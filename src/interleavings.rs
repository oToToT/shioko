//! The real code of what connections share, under thousands of schedules of
//! their threads: shuttle (https://github.com/awslabs/shuttle) runs each
//! test again and again, choosing at every lock, wait and atomic which
//! thread goes on (PCT, which finds any bug of a few steps with a known
//! probability, then at random), and reports a deadlock as a failure.
//!
//! Only in the build of shuttle/ (`tools/shuttle.sh`), where src/sync.rs
//! hands out shuttle's locks and threads; in any other build these locks
//! would block for real and the tests would hang instead of failing. The
//! schedules come from a seed (SHUTTLE_SEED, 0 by default), so a failure
//! can be run again; SHUTTLE_ITERATIONS sets how many of each kind.
//!
//! The threads are those of a tunnel (two pumps over one TlsStream, which
//! is also read, written and shut down from both), and those of the slots:
//! accept loops waiting for room, connections giving theirs back, and a
//! stop waiting for the last of them.

use crate::config::Config;
use crate::http::proxy::{self, Connect, Context, Timeouts};
use crate::log::Log;
use crate::server::{Reserved, Server};
use crate::stream::Stream;
use crate::sync::{Arc, Condvar, Mutex, thread};
use crate::tls::conn::{Identity, Served, TlsStream};
use crate::tls::peer::Peer;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

/// Runs `test` under PCT schedules, then under random ones.
fn every_schedule(test: impl Fn() + Send + Sync + 'static) {
    let iterations = usize::try_from(setting("SHUTTLE_ITERATIONS", 300)).unwrap();
    let seed = setting("SHUTTLE_SEED", 0);
    let mut config = shuttle::Config::new();
    // The handshake's cryptography needs more than shuttle's 32 KiB.
    config.stack_size = 1 << 20;
    let test = std::sync::Arc::new(test);
    let pct = std::sync::Arc::clone(&test);
    let runs = shuttle::Runner::new(shuttle::scheduler::PctScheduler::new_from_seed(seed, 3, iterations), config.clone()).run(move || pct());
    assert_eq!(runs, iterations);
    let runs = shuttle::Runner::new(shuttle::scheduler::RandomScheduler::new_from_seed(seed, iterations), config).run(move || test());
    assert_eq!(runs, iterations);
}

struct Quiet;

impl Log for Quiet {
    fn access(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

/// An upstream connection: it answers with `answer`, `piece` bytes at a
/// time, then ends, or if `held` stays open until it is shut down. What is
/// written to it is kept.
#[derive(Clone)]
struct Pipe(Arc<(Mutex<PipeState>, Condvar)>);

struct PipeState {
    answer: Vec<u8>,
    at: usize,
    piece: usize,
    held: bool,
    shut: bool,
    got: Vec<u8>,
}

impl Pipe {
    fn new(answer: &[u8], piece: usize, held: bool) -> Pipe {
        let state = PipeState { answer: answer.to_vec(), at: 0, piece, held, shut: false, got: Vec::new() };
        Pipe(Arc::new((Mutex::new(state), Condvar::new())))
    }

    fn got(&self) -> Vec<u8> {
        self.0.0.lock().unwrap().got.clone()
    }
}

impl Stream for Pipe {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.0.0.lock().unwrap();
        while state.held && !state.shut && state.at == state.answer.len() {
            state = self.0.1.wait(state).unwrap();
        }
        let n = buf.len().min(state.piece).min(state.answer.len() - state.at);
        buf[..n].copy_from_slice(&state.answer[state.at..state.at + n]);
        state.at += n;
        Ok(n)
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut state = self.0.0.lock().unwrap();
        if state.shut {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        state.got.extend_from_slice(buf);
        Ok(())
    }

    fn set_read_timeout(&self, _: Duration) {}

    fn shutdown(&self) {
        self.0.0.lock().unwrap().shut = true;
        self.0.1.notify_all();
    }

    fn finish(&self) {
        self.shutdown();
    }
}

/// Connects to the one upstream pipe.
struct Upstream(Pipe);

impl Connect for Upstream {
    type Upstream = Pipe;

    fn connect(&self, _: &str) -> Result<Pipe, u16> {
        Ok(self.0.clone())
    }
}

fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let text = "[site.test]\nupstream = 127.0.0.1:1\nwebsocket = yes\ncert = /chain.pem\nkey = /key.pem\n";
        Config::parse(text, &|_| Ok(String::new())).unwrap()
    })
}

fn identities() -> &'static [Option<std::sync::Arc<Identity>>] {
    static IDENTITIES: OnceLock<Vec<Option<std::sync::Arc<Identity>>>> = OnceLock::new();
    IDENTITIES.get_or_init(|| {
        // The manifest is shuttle/'s.
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/certs");
        let identity = Identity::load(&certs.join("site.test.chain.pem"), &certs.join("site.test.key")).unwrap();
        vec![Some(std::sync::Arc::new(identity))]
    })
}

const UPGRADE: &[u8] = b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
const SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
const KEY_UPDATE_REQUESTED: &[u8] = &[24, 0, 0, 1, 1];

/// What came after the head of a message.
fn after_head(bytes: &[u8]) -> &[u8] {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").expect("a head") + 4;
    &bytes[end..]
}

/// A WebSocket connection over TLS, with the client and the upstream as
/// given, served to its end. Returns what the client got (the 101 and the
/// data after it), the alert the server ended with, and what the upstream
/// got after the request head.
fn tunnel(client: Peer, upstream: Pipe) -> (Vec<u8>, Option<u8>, Vec<u8>) {
    let served = Served { config: config(), identities: identities(), peer: "192.0.2.1".parse().unwrap(), timeout: Duration::from_secs(60) };
    let (tls, site) = TlsStream::accept(client.clone(), &served, &Quiet).expect("the handshake succeeds");
    let connect = Upstream(upstream.clone());
    let context = Context {
        config: config(),
        connect: &connect,
        log: &Quiet,
        peer: served.peer,
        tls_site: Some(site),
        acme: Path::new("/nonexistent"),
        clock: || 784_111_777,
        timeouts: Timeouts::STANDARD,
        interruptible: &|_| true,
    };
    proxy::serve(&tls, &context);
    drop(tls);
    let (data, alert) = client.check();
    assert!(data.starts_with(b"HTTP/1.1 101 "), "the client got {:?}", String::from_utf8_lossy(&data));
    (after_head(&data).to_vec(), alert, after_head(&upstream.got()).to_vec())
}

fn records(records: &[(u8, &[u8])]) -> Vec<(u8, Vec<u8>)> {
    records.iter().map(|&(content_type, content)| (content_type, content.to_vec())).collect()
}

/// The upstream ends first while the client stays: the pump that reads
/// the client is blocked in a read, and the shutdown of the other must
/// wake it. Everything the upstream sent reaches the client, then
/// close_notify.
#[test]
fn bug_a_tunnel_ending_at_both_ends_at_once_lost_its_close_notify() {
    every_schedule(|| {
        let client = Peer::held(records(&[(23, UPGRADE), (23, b"up 1"), (23, b"up 2")]), usize::MAX);
        let upstream = Pipe::new(&[SWITCHING, b"down 1down 2"].concat(), 5, false);
        let (down, alert, up) = tunnel(client, upstream);
        assert_eq!(down, b"down 1down 2");
        assert_eq!(alert, Some(0));
        assert!(b"up 1up 2".starts_with(&up), "the upstream got {up:?}");
    });
}

/// The client asks for a KeyUpdate while data flows down: the reading pump
/// sends ours while the other pump sends data, and every record must still
/// be under the keys of its place (Peer::check follows our KeyUpdate).
#[test]
fn a_tunnel_with_a_key_update_both_ways() {
    every_schedule(|| {
        let client = Peer::held(records(&[(23, UPGRADE), (23, b"up 1"), (22, KEY_UPDATE_REQUESTED), (23, b"up 2")]), usize::MAX);
        let upstream = Pipe::new(&[SWITCHING, b"down 1down 2down 3"].concat(), 6, false);
        let (down, alert, up) = tunnel(client, upstream);
        assert_eq!(down, b"down 1down 2down 3");
        // The shutdown says close_notify only if the write lock is free.
        assert!(matches!(alert, Some(0) | None), "the server ended with alert {alert:?}");
        assert!(b"up 1up 2".starts_with(&up), "the upstream got {up:?}");
    });
}

/// A stop while the slots are full: two connections (one in each pool,
/// each pool of one), an accept loop waiting for room, and the stop
/// waiting for the connections to end. When they have, the stop must
/// return; the accept loop takes the room and then waits in accept for a
/// connection that does not come, until the stop is over.
#[test]
fn bug_a_stop_slept_to_its_deadline_when_an_accept_loop_took_its_wakeup() {
    every_schedule(|| {
        let text = "[inside.test]\nupstream = 127.0.0.1:1\nallow = 10.0.0.0/8\n\n[outside.test]\nupstream = 127.0.0.1:2\n";
        let config = Config::parse(text, &|_| Ok(String::new())).unwrap();
        let server = Server::new(config, vec![None, None], PathBuf::new(), Box::new(Quiet), 1, 1);
        let closed = Arc::new((Mutex::new(false), Condvar::new()));
        let listener = {
            let (server, closed) = (Arc::clone(&server), Arc::clone(&closed));
            thread::spawn(move || {
                let mut connections = Vec::new();
                for peer in ["10.0.0.1", "192.0.2.1"] {
                    let peer = peer.parse().unwrap();
                    let reserved = Reserved::take(&server);
                    if let Some(slot) = reserved.admit(server.pool_of(peer, false), peer, "") {
                        connections.push(thread::spawn(move || {
                            thread::yield_now();
                            drop(slot);
                        }));
                    }
                }
                let reserved = Reserved::take(&server);
                let mut listening = closed.0.lock().unwrap();
                while !*listening {
                    listening = closed.1.wait(listening).unwrap();
                }
                drop(listening);
                drop(reserved);
                for connection in connections {
                    connection.join().unwrap();
                }
            })
        };
        assert_eq!(server.drain(Duration::from_secs(3600)), 0);
        *closed.0.lock().unwrap() = true;
        closed.1.notify_all();
        listener.join().unwrap();
        assert_eq!(server.used(), 0);
    });
}
