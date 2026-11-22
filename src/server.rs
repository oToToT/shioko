//! Listening, the cap on connections, and one thread per connection.
//!
//! An accept loop takes a slot before it accepts, so that when the server
//! is full new connections wait in the kernel's queue. The slot goes to the
//! thread that serves the connection and comes back when that thread ends,
//! however it ends. `spec/Server.tla` is the design this follows.

use crate::config::Config;
use crate::http::proxy::{self, Context, Tcp};
use crate::log::Log;
use crate::tls::conn::{self as tls, Identity, Served, TlsStream};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The most connections served at once.
pub const CONNECTIONS: usize = 512;
/// How long a write to a client may block.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long an accept loop rests after `accept` failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// What every connection shares.
pub struct Server {
    pub config: Config,
    /// The certificate and key of each site, in the order of the sites;
    /// `None` for a site served over plain HTTP.
    pub identities: Vec<Option<Identity>>,
    pub acme: PathBuf,
    pub log: Box<dyn Log + Send>,
    slots: Slots,
}

struct Slots {
    used: Mutex<usize>,
    freed: Condvar,
    cap: usize,
}

/// One of the server's connection slots. Dropping it gives the slot back.
pub struct Slot(Arc<Server>);

impl Server {
    pub fn new(
        config: Config,
        identities: Vec<Option<Identity>>,
        acme: PathBuf,
        log: Box<dyn Log + Send>,
        cap: usize,
    ) -> Arc<Server> {
        let slots = Slots { used: Mutex::new(0), freed: Condvar::new(), cap };
        Arc::new(Server { config, identities, acme, log, slots })
    }

    /// The number of slots taken.
    #[cfg(test)]
    pub fn used(&self) -> usize {
        *self.slots.used.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Slot {
    /// Takes a slot, waiting for one while the server is full.
    pub fn take(server: &Arc<Server>) -> Slot {
        let slots = &server.slots;
        // The count is a plain number that is always left consistent, so a
        // lock poisoned by a panic elsewhere can still be used.
        let mut used = slots.used.lock().unwrap_or_else(PoisonError::into_inner);
        while *used >= slots.cap {
            used = slots.freed.wait(used).unwrap_or_else(PoisonError::into_inner);
        }
        *used = used.saturating_add(1);
        Slot(Arc::clone(server))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let slots = &self.0.slots;
        let mut used = slots.used.lock().unwrap_or_else(PoisonError::into_inner);
        *used = used.saturating_sub(1);
        slots.freed.notify_one();
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// Serves one connection: plain HTTP, or HTTP over TLS.
fn connection(server: &Server, client: TcpStream, secure: bool) {
    let Ok(peer) = client.peer_addr() else {
        return;
    };
    let _ = client.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = client.set_nodelay(true);
    let context = |tls_site| Context {
        config: &server.config,
        connect: &Tcp,
        log: server.log.as_ref(),
        peer: peer.ip(),
        tls_site,
        acme: &server.acme,
        clock: now,
        timeouts: proxy::Timeouts::STANDARD,
    };
    if !secure {
        proxy::serve(&client, &context(None));
        return;
    }
    let served = Served {
        config: &server.config,
        identities: &server.identities,
        peer: peer.ip(),
        timeout: tls::HANDSHAKE_TIMEOUT,
    };
    if let Some((stream, site)) = TlsStream::accept(client, &served, server.log.as_ref()) {
        proxy::serve(&stream, &context(Some(site)));
    }
}

/// Accepts connections for ever, each served on a thread of its own;
/// `secure` connections speak TLS.
pub fn listen(server: &Arc<Server>, listener: &TcpListener, secure: bool) {
    loop {
        let slot = Slot::take(server);
        match listener.accept() {
            Ok((client, _)) => {
                let shared = Arc::clone(server);
                // The slot moves into the thread. If the thread cannot be
                // started, the closure is dropped and the slot with it.
                let started = std::thread::Builder::new().spawn(move || {
                    let _slot = slot;
                    connection(&shared, client, secure);
                });
                if let Err(error) = started {
                    server.log.error(&format!("cannot start a thread: {error}"));
                }
            }
            Err(error) => {
                drop(slot);
                server.log.error(&format!("accept failed: {error}"));
                std::thread::sleep(ACCEPT_PAUSE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::parse;
    use crate::log::testing::Kept;
    use std::io::{Read, Write};
    use std::net::Shutdown;

    /// Starts a server for `sites` on a free port and returns its address.
    fn start(sites: &str, cap: usize) -> (Arc<Server>, std::net::SocketAddr) {
        let config = parse(sites).unwrap();
        let identities = config.sites.iter().map(|_| None).collect();
        let server = Server::new(config, identities, "/nonexistent".into(), Box::new(Kept::default()), cap);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::clone(&server);
        std::thread::spawn(move || listen(&shared, &listener, false));
        (server, address)
    }

    /// An upstream that answers each connection with what `answer` makes of
    /// the request head it read.
    fn upstream(answer: impl Fn(&str, &mut TcpStream) + Send + 'static) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut connection in listener.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                answer(&String::from_utf8_lossy(&head), &mut connection);
            }
        });
        address
    }

    fn read_to_end(mut stream: &TcpStream) -> String {
        let mut text = Vec::new();
        let _ = stream.read_to_end(&mut text);
        String::from_utf8_lossy(&text).into_owned()
    }

    fn wait_until(what: impl Fn() -> bool) {
        for _ in 0..500 {
            if what() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("waited five seconds in vain");
    }

    #[test]
    fn a_request_goes_through_real_sockets() {
        let up = upstream(|head, connection| {
            assert!(head.starts_with("GET /hello HTTP/1.1\r\n"));
            assert!(head.contains("\r\nX-Real-IP: 127.0.0.1\r\n"));
            let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld");
        });
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"GET /hello HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n").unwrap();
        let received = read_to_end(&client);
        assert!(received.starts_with("HTTP/1.1 200 OK\r\n"), "{received:?}");
        assert!(received.ends_with("Connection: close\r\n\r\nworld"));
        // The slot of the connection comes back; the accept loop keeps one.
        wait_until(|| server.used() == 1);
    }

    #[test]
    fn an_upstream_that_refuses_connections_is_a_bad_gateway() {
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (_, address) = start(&format!("[site.test]\nupstream = {closed}\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n").unwrap();
        assert!(read_to_end(&client).starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    }

    #[test]
    fn a_websocket_tunnel_carries_bytes_both_ways_and_ends_as_one() {
        let up = upstream(|head, connection| {
            assert!(head.contains("\r\nConnection: upgrade\r\nUpgrade: websocket\r\n"));
            let _ = connection.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello",
            );
            // Echo until the client's side ends.
            let mut space = [0u8; 64];
            while let Ok(n) = connection.read(&mut space) {
                if n == 0 || connection.write_all(&space[..n]).is_err() {
                    break;
                }
            }
        });
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\nwebsocket = yes\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .unwrap();
        let mut received = Vec::new();
        let mut space = [0u8; 256];
        while !received.ends_with(b"hello") {
            let n = client.read(&mut space).unwrap();
            assert!(n > 0, "the tunnel ended early");
            received.extend_from_slice(&space[..n]);
        }
        assert!(received.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        for message in ["one", "two", "three"] {
            client.write_all(message.as_bytes()).unwrap();
            let mut echo = vec![0u8; message.len()];
            client.read_exact(&mut echo).unwrap();
            assert_eq!(echo, message.as_bytes());
        }
        // The client closes its side: the whole tunnel ends, both threads
        // stop and the slot comes back.
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(read_to_end(&client), "");
        wait_until(|| server.used() == 1);
    }

    #[test]
    fn no_more_connections_are_served_at_once_than_the_cap_allows() {
        let up = upstream(|_, connection| {
            let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        // Three slots, three connections: the accept loop then waits for a
        // slot before it accepts again.
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\n"), 3);
        let first = TcpStream::connect(address).unwrap();
        let second = TcpStream::connect(address).unwrap();
        let third = TcpStream::connect(address).unwrap();
        wait_until(|| server.used() == 3);
        // A fourth connection is made by the kernel but nobody serves it.
        let mut fourth = TcpStream::connect(address).unwrap();
        fourth.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n").unwrap();
        fourth.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut byte = [0u8; 1];
        assert!(fourth.read(&mut byte).is_err(), "the fourth connection was served");
        assert_eq!(server.used(), 3);
        // One of the first three goes away, and the fourth gets its turn.
        drop(first);
        fourth.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(read_to_end(&fourth).ends_with("\r\n\r\nok"));
        drop((second, third));
        wait_until(|| server.used() == 1);
    }

    #[test]
    fn a_slot_comes_back_however_its_holder_ends() {
        let (server, _) = start("[site.test]\nupstream = 127.0.0.1:9\n", 4);
        wait_until(|| server.used() == 1);
        let shared = Arc::clone(&server);
        let panicking = std::thread::spawn(move || {
            let _slot = Slot::take(&shared);
            assert_eq!(shared.used(), 2);
            panic!("a connection thread dies");
        });
        assert!(panicking.join().is_err());
        assert_eq!(server.used(), 1);
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use crate::config::tests::parse;
    use crate::log::testing::Kept;
    use crate::tls::client::{Client, Got};
    use crate::tls::{msgs, record};
    use std::io::{Read, Write};
    use std::path::Path;

    fn certs(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs").join(name)
    }

    /// An upstream that accepts a WebSocket upgrade and then echoes, also
    /// sending something of its own every so often.
    fn websocket_upstream() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut connection in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                        head.push(byte[0]);
                    }
                    let _ = connection.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    );
                    let mut space = [0u8; 4096];
                    while let Ok(n) = connection.read(&mut space) {
                        if n == 0 || connection.write_all(&space[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        address
    }

    fn tls_server(upstream: std::net::SocketAddr) -> (Arc<Server>, std::net::SocketAddr) {
        let config = parse(&format!(
            "[site.test]\nupstream = {upstream}\nwebsocket = yes\ncert = /certs/chain.pem\nkey = /certs/key.pem\n"
        ))
        .unwrap();
        let identity = Identity::load(&certs("site.test.chain.pem"), &certs("site.test.key")).unwrap();
        let server = Server::new(config, vec![Some(identity)], "/nonexistent".into(), Box::new(Kept::default()), 8);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::clone(&server);
        std::thread::spawn(move || listen(&shared, &listener, true));
        (server, address)
    }

    fn public() -> [u8; 65] {
        Identity::load(&certs("site.test.chain.pem"), &certs("site.test.key")).unwrap().key.public_key().unwrap()
    }

    /// Reads application data until `want` bytes have come, taking the
    /// server's KeyUpdates as they come.
    fn read_data(client: &mut Client, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < want {
            match client.get() {
                Got::Data(data) => got.extend(data),
                Got::Handshake(messages) if messages == vec![msgs::key_update(false)] => {
                    client.read.as_mut().unwrap().next();
                }
                other => panic!("expected data, got {other:?}"),
            }
        }
        got
    }

    /// A WebSocket tunnel over TLS: two threads share the TLS connection,
    /// one reading from the client, the other writing to it. The client
    /// asks for KeyUpdates in the middle; the writing thread must send ours
    /// before its next data, and every record must decrypt in order.
    #[test]
    fn a_websocket_tunnel_over_tls_with_key_updates() {
        let (server, address) = tls_server(websocket_upstream());
        let mut client = Client::handshake(address, "site.test", &public());
        client.send(record::APPLICATION_DATA, b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        let head = read_data(&mut client, 1);
        assert!(head.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"), "{}", String::from_utf8_lossy(&head));
        let mut expected = Vec::new();
        let mut received = Vec::new();
        for round in 0..20u8 {
            if round % 4 == 1 {
                client.send(record::HANDSHAKE, &msgs::key_update(true));
                client.write.as_mut().unwrap().next();
            }
            if round % 4 == 3 {
                client.send(record::HANDSHAKE, &msgs::key_update(false));
                client.write.as_mut().unwrap().next();
            }
            let message = vec![b'a' + round; 3000 + usize::from(round) * 997];
            client.send(record::APPLICATION_DATA, &message);
            expected.extend(&message);
            received.extend(read_data(&mut client, expected.len() - received.len()));
        }
        assert_eq!(received, expected);
        // The client closes: the tunnel ends, both threads stop, the slot
        // comes back.
        client.send(record::ALERT, &[1, 0]);
        loop {
            match client.get() {
                Got::Alert(0) | Got::End => break,
                Got::Data(_) | Got::Handshake(_) => {}
                other => panic!("{other:?}"),
            }
        }
        for _ in 0..500 {
            if server.used() == 1 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the tunnel's slot did not come back");
    }
}
