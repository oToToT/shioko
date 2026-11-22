//! The TLS server end to end, over loopback sockets, driven by the test
//! client.

use super::client::{Client, Got, SECRET, share};
use super::conn::{Identity, Served, TlsStream};
use super::msgs::tests::{Hello, alpn, key_shares, sni};
use super::{msgs, record};
use crate::config::Config;
use crate::crypto;
use crate::log::testing::Kept;
use crate::stream::Stream;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::Duration;

const X25519: u16 = 0x001d;
const SECP256R1: u16 = 0x0017;

fn certs(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/certs").join(name)
}

fn identity(name: &str) -> Identity {
    let key = if name == "tls.test" { "tls.test.key".to_string() } else { format!("{name}.key") };
    Identity::load(&certs(&format!("{name}.chain.pem")), &certs(&key)).unwrap()
}

fn public(name: &str) -> [u8; 65] {
    identity(name).key.public_key().unwrap()
}

struct World {
    config: Config,
    identities: Vec<Option<Identity>>,
    log: Kept,
    /// How each connection's reading ended: "end" after an orderly close,
    /// "error" otherwise.
    ends: std::sync::Mutex<Vec<&'static str>>,
}

fn world() -> &'static World {
    let config = crate::config::tests::parse(
        "[site.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\n\n\
         [tls.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\n\n\
         [plain.test]\nupstream = a:1\n\n\
         [locked.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\nallow = 10.0.0.0/8\n\n\
         [big.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\n",
    )
    .unwrap();
    // big.test sends a chain of more than 16 KB: its leaf and the CA forty
    // times over.
    let mut big = identity("site.test");
    let ca = big.chain[1].clone();
    big.chain.extend(std::iter::repeat_n(ca, 40));
    let identities = vec![Some(identity("site.test")), Some(identity("tls.test")), None, Some(identity("site.test")), Some(big)];
    Box::leak(Box::new(World { config, identities, log: Kept::default(), ends: std::sync::Mutex::new(Vec::new()) }))
}

/// A server that answers each connection with the handshake and then
/// echoes: what comes in goes back, `close` closes, `big N` sends N bytes.
fn server_with(timeout: Duration) -> (SocketAddr, &'static World) {
    let world = world();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let peer = tcp.peer_addr().unwrap().ip();
                let served = Served { config: &world.config, identities: &world.identities, peer, timeout };
                let Some((tls, _site)) = TlsStream::accept(tcp, &served, &world.log) else { return };
                let mut space = vec![0u8; 70_000];
                loop {
                    match tls.read(&mut space) {
                        Ok(0) => {
                            world.ends.lock().unwrap().push("end");
                            break;
                        }
                        Err(_) => {
                            world.ends.lock().unwrap().push("error");
                            break;
                        }
                        Ok(n) if &space[..n] == b"shutdown" => {
                            tls.shutdown();
                            return;
                        }
                        Ok(n) if &space[..n] == b"close" => {
                            tls.finish();
                            return;
                        }
                        Ok(n) if &space[..n] == b"slow read" => {
                            // How long does one read with a short timeout
                            // wait while records without data keep coming?
                            tls.set_read_timeout(Duration::from_millis(300));
                            let started = std::time::Instant::now();
                            let result = tls.read(&mut space);
                            let waited = started.elapsed().as_millis();
                            tls.set_read_timeout(Duration::from_secs(5));
                            let answer = match result {
                                Err(error) if crate::stream::timed_out(&error) => format!("timed out after {waited} ms"),
                                other => format!("{other:?}"),
                            };
                            let _ = tls.write_all(answer.as_bytes());
                        }
                        Ok(n) if space[..n].starts_with(b"big ") => {
                            let size: usize = std::str::from_utf8(&space[4..n]).unwrap().parse().unwrap();
                            let _ = tls.write_all(&vec![b'z'; size]);
                        }
                        Ok(n) => {
                            if tls.write_all(&space[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                tls.finish();
            });
        }
    });
    (address, world)
}

fn server() -> SocketAddr {
    server_with(Duration::from_secs(5)).0
}

fn hello(name: &str) -> Hello {
    Hello::new(name, &share())
}

/// Sends `hello` and returns the server's first answer.
fn first_answer(address: SocketAddr, hello: &Hello) -> (Client, Got) {
    let mut client = Client::connect(address);
    client.send_hello(hello);
    let got = client.get();
    (client, got)
}

fn alert_for(address: SocketAddr, hello: &Hello) -> Option<u8> {
    let (mut client, got) = first_answer(address, hello);
    match got {
        Got::Alert(code) => Some(code),
        Got::End => None,
        _ => client.alert(),
    }
}

/// The ServerHello as sent: our random, the client's session id, one
/// X25519 share.
fn server_hello_parts(hello: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let random = hello[6..38].to_vec();
    let id_length = usize::from(hello[38]);
    (random, hello[39..39 + id_length].to_vec())
}

#[test]
fn a_whole_handshake_and_data_both_ways() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    // EncryptedExtensions says we used the name and picked http/1.1.
    assert!(client.encrypted_extensions.windows(4).any(|w| w == [0, 0, 0, 0]));
    assert!(client.encrypted_extensions.ends_with(b"\x08http/1.1"));
    // The chain is the file's, leaf first.
    let chain = crate::pem::certificates(&std::fs::read_to_string(certs("site.test.chain.pem")).unwrap()).unwrap();
    assert!(client.certificate.windows(chain[0].len()).any(|w| w == chain[0]));
    assert!(client.certificate.windows(chain[1].len()).any(|w| w == chain[1]));
    for message in [&b"hello"[..], b"", b"second message"] {
        if message.is_empty() {
            continue;
        }
        client.send(record::APPLICATION_DATA, message);
        assert_eq!(client.get(), Got::Data(message.to_vec()));
    }
    // A clean close: the server says close_notify and nothing after.
    client.send(record::APPLICATION_DATA, b"close");
    assert_eq!(client.get(), Got::Alert(0));
    assert_eq!(client.get(), Got::End);
}

#[test]
fn both_sites_and_both_key_forms() {
    let address = server();
    for name in ["site.test", "TLS.test"] {
        let mut client = Client::handshake(address, name, &public(&name.to_ascii_lowercase()));
        client.send(record::APPLICATION_DATA, b"ping");
        assert_eq!(client.get(), Got::Data(b"ping".to_vec()));
    }
}

#[test]
fn without_alpn_none_is_chosen() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").without(16));
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    assert!(!client.encrypted_extensions.windows(8).any(|w| w == b"http/1.1"));
}

#[test]
fn a_hello_retry_request_and_then_the_handshake() {
    let address = server();
    let mut client = Client::connect(address);
    // Only a P-256 share, though X25519 is offered.
    let first = hello("site.test").set(51, key_shares(&[(SECP256R1, &[4u8; 65])]));
    client.send_hello(&first);
    let Got::Handshake(messages) = client.get() else { panic!("no HelloRetryRequest") };
    assert_eq!(messages.len(), 1, "the HelloRetryRequest is alone in its record");
    assert_eq!(&client.last_header[..3], &[22, 3, 3]);
    let retry = &messages[0];
    assert_eq!(server_hello_parts(retry).1, [0xab; 32], "the session id is echoed");
    assert_eq!(retry[6..38], crypto::sha256(b"HelloRetryRequest"));
    assert!(retry.ends_with(&[0, 51, 0, 2, 0, 0x1d]), "it asks for X25519");
    assert_eq!(client.get(), Got::Ccs);
    client.transcript.restart_with_message_hash();
    client.transcript.add(retry);
    // The second ClientHello brings the share.
    client.send_hello(&hello("site.test"));
    let Got::Handshake(messages) = client.get_past_ccs() else { panic!("no ServerHello") };
    client.take_server_hello(&messages[0]);
    client.take_flight(&public("site.test"));
    client.finish(true);
    client.send(record::APPLICATION_DATA, b"after a retry");
    assert_eq!(client.get(), Got::Data(b"after a retry".to_vec()));
}

#[test]
fn what_a_second_client_hello_may_not_do() {
    let address = server();
    let p256 = || hello("site.test").set(51, key_shares(&[(SECP256R1, &[4u8; 65])]));
    for (what, second) in [
        ("still no X25519 share", p256()),
        ("another site", hello("tls.test")),
        ("early data again", hello("site.test").set(42, vec![])),
        ("two shares", hello("site.test").set(51, key_shares(&[(X25519, &share()), (SECP256R1, &[4u8; 65])]))),
    ] {
        let mut client = Client::connect(address);
        client.send_hello(&p256());
        assert!(matches!(client.get(), Got::Handshake(_)), "{what}");
        client.send_hello(&second);
        assert_eq!(client.alert(), Some(47), "{what}: illegal_parameter");
    }
}

#[test]
fn refused_hellos_get_the_alert_of_the_plan() {
    let address = server();
    let cases: Vec<(&str, Hello, u8)> = vec![
        ("only TLS 1.2", hello("site.test").set(43, vec![2, 3, 3]), 70),
        ("no ChaCha20", Hello { suites: vec![0x1301], ..hello("site.test") }, 40),
        ("no X25519 at all", hello("site.test").set(10, vec![0, 2, 0, 0x17]).set(51, key_shares(&[(SECP256R1, &[4u8; 65])])), 40),
        ("no ECDSA", hello("site.test").set(13, vec![0, 2, 8, 4]), 40),
        ("no server_name", hello("site.test").without(0), 109),
        ("no key_share", hello("site.test").without(51), 109),
        ("a cookie", hello("site.test").set(44, vec![0, 1, 9]), 47),
        ("ALPN without http/1.1", hello("site.test").set(16, alpn(&["h2"])), 120),
        ("unknown site", hello("nowhere.test"), 112),
        ("site without a certificate", hello("plain.test"), 112),
        ("not on the allowlist", hello("locked.test"), 49),
        ("compression", Hello { compression: vec![1, 0], ..hello("site.test") }, 47),
    ];
    for (what, hello, alert) in cases {
        assert_eq!(alert_for(address, &hello), Some(alert), "{what}");
    }
    // A ClientHello that is not one, and records that are not TLS.
    let mut client = Client::connect(address);
    client.send(record::HANDSHAKE, &[1, 0, 0, 2, 3, 3]);
    assert_eq!(client.alert(), Some(50));
    let mut client = Client::connect(address);
    client.raw(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n");
    assert_eq!(client.alert(), Some(10));
    // A plain-HTTP site on the allowlist is still no TLS site.
    assert_eq!(alert_for(address, &hello("plain.test")), Some(112));
    let log = world().log.0.lock().unwrap().clone();
    let _ = log;
}

#[test]
fn a_wrong_finished_is_decrypt_error() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    client.finish(false);
    // The server's alert is under its application keys now.
    assert_eq!(client.alert(), Some(51));
}

#[test]
fn data_before_finished_is_refused() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    client.read_application();
    client.use_handshake_keys();
    client.send(record::APPLICATION_DATA, b"too early");
    assert_eq!(client.alert(), Some(10));
}

#[test]
fn key_updates_from_the_client() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    // Not requested: we switch our write keys, the server its read keys.
    client.send(record::HANDSHAKE, &msgs::key_update(false));
    client.write.as_mut().unwrap().next();
    client.send(record::APPLICATION_DATA, b"one");
    assert_eq!(client.get(), Got::Data(b"one".to_vec()));
    // Requested: the server's next record is its own KeyUpdate, and after
    // it come records under its next keys.
    client.send(record::HANDSHAKE, &msgs::key_update(true));
    client.write.as_mut().unwrap().next();
    client.send(record::APPLICATION_DATA, b"two");
    assert_eq!(client.get(), Got::Handshake(vec![msgs::key_update(false)]));
    client.read.as_mut().unwrap().next();
    assert_eq!(client.get(), Got::Data(b"two".to_vec()));
    // A KeyUpdate that is neither is refused.
    client.send(record::HANDSHAKE, &[24, 0, 0, 1, 7]);
    assert_eq!(client.alert(), Some(47));
}

#[test]
fn records_under_old_keys_are_bad_record_mac() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::HANDSHAKE, &msgs::key_update(false));
    // We do not switch: the next record is under the old keys.
    client.send(record::APPLICATION_DATA, b"old");
    assert_eq!(client.alert(), Some(20));
}

#[test]
fn early_data_is_skipped_up_to_a_limit() {
    let address = server();
    let garbage = |size: usize| {
        let mut record = vec![23, 3, 3];
        record.extend_from_slice(&u16::try_from(size).unwrap().to_be_bytes());
        record.extend(vec![0x5a; size]);
        record
    };
    // Skipped: the handshake goes on as if nothing had come.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").set(42, vec![]));
    for _ in 0..3 {
        client.raw(&garbage(1000));
    }
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    client.finish(true);
    client.send(record::APPLICATION_DATA, b"after early data");
    assert_eq!(client.get(), Got::Data(b"after early data".to_vec()));
    // Too much of it.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").set(42, vec![]));
    for _ in 0..2 {
        client.raw(&garbage(16_000));
    }
    client.through_flight(&public("site.test"));
    assert_eq!(client.alert(), Some(10));
    // Without an offer of early data, the same record is bad_record_mac.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.raw(&garbage(100));
    client.through_flight(&public("site.test"));
    assert_eq!(client.alert(), Some(20));
    // After a HelloRetryRequest, early data shows as application data
    // without encryption, and is skipped too.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").set(42, vec![]).set(51, key_shares(&[(SECP256R1, &[4u8; 65])])));
    let Got::Handshake(m) = client.get() else { panic!() };
    client.raw(&garbage(500));
    client.transcript.restart_with_message_hash();
    client.transcript.add(&m[0]);
    client.send_hello(&hello("site.test"));
    let Got::Handshake(m) = client.get_past_ccs() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    client.finish(true);
    client.send(record::APPLICATION_DATA, b"ok");
    assert_eq!(client.get(), Got::Data(b"ok".to_vec()));
}

#[test]
fn a_client_hello_in_pieces_and_how_not_to() {
    let address = server();
    let bytes = hello("site.test").bytes();
    // In three records: fine.
    let mut client = Client::connect(address);
    client.transcript.add(&bytes);
    for piece in [&bytes[..3], &bytes[3..50], &bytes[50..]] {
        client.send(record::HANDSHAKE, piece);
    }
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    // Something between the pieces: refused.
    let mut client = Client::connect(address);
    client.send(record::HANDSHAKE, &bytes[..50]);
    client.send(record::CHANGE_CIPHER_SPEC, &[1]);
    assert_eq!(client.alert(), Some(10));
    // Something after the message in its record: refused.
    let mut client = Client::connect(address);
    let mut more = bytes.clone();
    more.extend_from_slice(&[20, 0, 0, 0]);
    client.send(record::HANDSHAKE, &more);
    assert_eq!(client.alert(), Some(10));
    // An empty handshake record: refused.
    let mut client = Client::connect(address);
    client.send(record::HANDSHAKE, &[]);
    assert_eq!(client.alert(), Some(10));
}

#[test]
fn change_cipher_spec_only_where_it_belongs() {
    let address = server();
    // Before the ClientHello.
    let mut client = Client::connect(address);
    client.send(record::CHANGE_CIPHER_SPEC, &[1]);
    assert_eq!(client.alert(), Some(10));
    // During the handshake it is dropped, also more than once.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.send(record::CHANGE_CIPHER_SPEC, &[1]);
    client.send(record::CHANGE_CIPHER_SPEC, &[1]);
    let Got::Handshake(m) = client.get() else { panic!() };
    client.take_server_hello(&m[0]);
    client.take_flight(&public("site.test"));
    client.finish(true);
    // After the client Finished it is refused.
    let write = client.write.take();
    client.send(record::CHANGE_CIPHER_SPEC, &[1]);
    client.write = write;
    assert_eq!(client.alert(), Some(10));
    // One that is not the single byte 1 is refused.
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.send(record::CHANGE_CIPHER_SPEC, &[2]);
    client.through_flight(&public("site.test"));
    assert_eq!(client.alert(), Some(10));
}

#[test]
fn large_data_goes_in_records_of_16k_at_most() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::APPLICATION_DATA, b"big 40000");
    let mut got = Vec::new();
    while got.len() < 40_000 {
        let Got::Data(data) = client.get() else { panic!() };
        assert!(data.len() <= 16_384);
        got.extend(data);
    }
    assert_eq!(got, vec![b'z'; 40_000]);
    // A record over the limit from the client is refused.
    let mut over = vec![b'x'; 16_385];
    let keys = client.write.as_mut().unwrap();
    over.push(23);
    let length = u16::try_from(over.len() + 16).unwrap();
    let mut header = vec![23, 3, 3];
    header.extend_from_slice(&length.to_be_bytes());
    let sealed = crypto::aead_seal(&keys.keys.key, &keys.keys.nonce(keys.sequence), &header, &over).unwrap();
    header.extend(sealed);
    client.raw(&header);
    assert_eq!(client.alert(), Some(22));
}

#[test]
fn close_notify_from_the_client_is_answered() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::ALERT, &[1, 0]);
    assert_eq!(client.get(), Got::Alert(0));
    assert_eq!(client.get(), Got::End);
}

#[test]
fn other_alerts_end_the_connection_and_are_logged() {
    let (address, world) = server_with(Duration::from_secs(5));
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::ALERT, &[2, 48]);
    assert_eq!(client.get(), Got::End);
    std::thread::sleep(Duration::from_millis(100));
    let log = world.log.0.lock().unwrap().clone();
    assert!(log.iter().any(|line| line.ends_with("tls: received unknown_ca")), "{log:?}");
}

#[test]
fn the_handshake_has_a_deadline() {
    let (address, _) = server_with(Duration::from_millis(200));
    let mut client = Client::connect(address);
    let bytes = hello("site.test").bytes();
    client.send(record::HANDSHAKE, &bytes[..20]);
    // The rest never comes: after the deadline, close_notify.
    assert_eq!(client.alert(), Some(0));
}

#[test]
fn an_all_zero_share_is_illegal() {
    let address = server();
    assert_eq!(alert_for(address, &Hello::new("site.test", &[0u8; 32])), Some(47));
}

#[test]
fn sni_is_matched_without_case_and_exactly() {
    let address = server();
    assert_eq!(alert_for(address, &hello("site.test.").set(0, sni("site.test."))), Some(112));
    let _ = SECRET;
}

/// Bug (found in review): a read on a TLS connection went on reading until
/// a record brought data, each transport read with the full timeout. A
/// client sending a KeyUpdate or an empty record now and then kept that
/// read waiting for ever, past every deadline the proxy had set (the slow
/// head fixed in M2, now over TLS). The timeout is now a budget for the
/// whole read.
#[test]
fn bug_records_without_data_kept_a_read_waiting() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::APPLICATION_DATA, b"slow read");
    let sender = std::thread::spawn({
        let started = std::time::Instant::now();
        let tcp = client.tcp.try_clone().unwrap();
        let mut keys = client.write.take().unwrap();
        move || {
            // Records without data, every 50 ms, for a second.
            while started.elapsed() < Duration::from_secs(1) {
                let record = record::seal(&keys.keys, keys.sequence, record::APPLICATION_DATA, b"").unwrap();
                keys.sequence += 1;
                if tcp.write_all(&record).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            keys
        }
    });
    let Got::Data(answer) = client.get() else { panic!("no answer") };
    let answer = String::from_utf8(answer).unwrap();
    client.write = Some(sender.join().unwrap());
    let waited: u64 = answer.strip_prefix("timed out after ").and_then(|a| a.strip_suffix(" ms")).and_then(|a| a.parse().ok()).unwrap_or_else(|| panic!("{answer}"));
    assert!(waited < 600, "the read waited {waited} ms");
}

#[test]
fn every_server_random_is_new() {
    let address = server();
    let mut randoms = Vec::new();
    for _ in 0..4 {
        let (_, got) = first_answer(address, &hello("site.test"));
        let Got::Handshake(messages) = got else { panic!() };
        let (random, session_id) = server_hello_parts(&messages[0]);
        assert_eq!(session_id, [0xab; 32], "the session id is echoed");
        assert_ne!(random, [7u8; 32], "the client's random");
        assert_ne!(random, crypto::sha256(b"HelloRetryRequest"));
        randoms.push(random);
    }
    randoms.sort();
    randoms.dedup();
    assert_eq!(randoms.len(), 4);
}

#[test]
fn a_second_client_hello_without_our_suite_fails() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").set(51, key_shares(&[(SECP256R1, &[4u8; 65])])));
    assert!(matches!(client.get(), Got::Handshake(_)));
    client.send_hello(&Hello { suites: vec![0x1301], ..hello("site.test") });
    assert_eq!(client.alert(), Some(40));
}

/// Handshake messages a server never expects are refused wherever they
/// come: first, under the handshake keys, after the handshake.
#[test]
fn other_handshake_messages_are_unexpected() {
    let address = server();
    let certificate = [11, 0, 0, 4, 0, 0, 0, 0];
    let mut client = Client::connect(address);
    client.send(record::HANDSHAKE, &certificate);
    assert_eq!(client.alert(), Some(10));
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.through_flight(&public("site.test"));
    client.use_handshake_keys();
    client.send(record::HANDSHAKE, &[5, 0, 0, 0]);
    assert_eq!(client.alert(), Some(10));
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::HANDSHAKE, &certificate);
    assert_eq!(client.alert(), Some(10));
    // A ClientHello once the handshake is done.
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::HANDSHAKE, &hello("site.test").bytes());
    assert_eq!(client.alert(), Some(10));
}

#[test]
fn a_finished_wrong_in_its_last_byte_is_decrypt_error() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.through_flight(&public("site.test"));
    // finish(false) flips the first byte; flip the last by hand.
    client.finish_flipping_last_byte();
    assert_eq!(client.alert(), Some(51));
}

#[test]
fn signature_algorithms_cert_is_ignored() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test").set(50, vec![0, 2, 8, 9]));
    client.through_flight(&public("site.test"));
    let _ = client;
}

#[test]
fn a_key_that_does_not_belong_to_the_certificate_is_refused() {
    let error = Identity::load(&certs("site.test.chain.pem"), &certs("tls.test.key")).err().unwrap();
    assert!(error.ends_with(&format!("the key does not belong to the certificate in {}", certs("site.test.chain.pem").display())), "{error}");
    let error = Identity::load(&certs("site.test.chain.pem"), &certs("rsa.key")).err().unwrap();
    assert!(error.contains("only ECDSA P-256 keys are supported"), "{error}");
    assert!(Identity::load(&certs("missing.pem"), &certs("site.test.key")).is_err());
}

/// Bug (found in review): a plaintext alert that came after we had
/// switched to the handshake keys was refused unread, and so never logged,
/// though it tells why the client gave up (for example it could not use
/// our ServerHello).
#[test]
fn bug_plaintext_alert_after_our_keys_was_not_logged() {
    let (address, world) = server_with(Duration::from_secs(5));
    let mut client = Client::connect(address);
    client.send_hello(&hello("site.test"));
    client.through_flight(&public("site.test"));
    client.send(record::ALERT, &[2, 42]);
    assert_eq!(client.get(), Got::End);
    std::thread::sleep(Duration::from_millis(100));
    let log = world.log.0.lock().unwrap().clone();
    assert!(log.iter().any(|line| line.ends_with("tls: received bad_certificate")), "{log:?}");
}

/// How the server's read of the next connection ended.
fn how_it_ended(world: &World, before: usize) -> &'static str {
    for _ in 0..200 {
        if let Some(end) = world.ends.lock().unwrap().get(before) {
            return end;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the server's read did not end");
}

/// Bug (found in review): after an error alert, a fatal error of ours or
/// a connection cut off without close_notify, a read reported an orderly
/// end, just as after close_notify; a cut-off WebSocket looked closed on
/// purpose to the upstream.
#[test]
fn bug_error_alerts_looked_like_a_clean_close() {
    let (address, world) = server_with(Duration::from_secs(5));
    let ends = |world: &World| world.ends.lock().unwrap().len();
    let before = ends(world);
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::ALERT, &[1, 0]);
    assert_eq!(how_it_ended(world, before), "end");
    // These test the same server one after the other.
    for how in ["error alert", "cut off", "bad record"] {
        let before = ends(world);
        let mut client = Client::handshake(address, "site.test", &public("site.test"));
        match how {
            "error alert" => client.send(record::ALERT, &[2, 80]),
            "cut off" => client.tcp.shutdown(std::net::Shutdown::Both).unwrap(),
            _ => client.raw(&[23, 3, 3, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
        }
        assert_eq!(how_it_ended(world, before), "error", "{how}");
    }
}

/// Bug (found in review): ending a connection at once (a timeout, the end
/// of a tunnel) sent no close_notify, though the connection could still
/// carry one.
#[test]
fn bug_close_notify_was_missing_on_shutdown() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::APPLICATION_DATA, b"shutdown");
    assert_eq!(client.get(), Got::Alert(0));
    assert_eq!(client.get(), Got::End);
}

/// Bug (found in review): an empty alert got decode_error rather than the
/// unexpected_message section 5.4 asks for, and alerts that were not two
/// bytes were not logged.
#[test]
fn bug_empty_alert_got_the_wrong_alert() {
    let (address, world) = server_with(Duration::from_secs(5));
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::ALERT, &[]);
    assert_eq!(client.alert(), Some(10));
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.send(record::ALERT, &[2, 40, 0]);
    assert_eq!(client.alert(), Some(50));
    std::thread::sleep(Duration::from_millis(100));
    let log = world.log.0.lock().unwrap().clone();
    assert!(log.iter().any(|l| l.ends_with("tls: received an empty alert")), "{log:?}");
    assert!(log.iter().any(|l| l.ends_with("tls: received a malformed alert")), "{log:?}");
}

/// What becomes of the alerts a client may send: a warning or an unknown
/// alert ends the connection with nothing said; close_notify, at any
/// level, is answered with ours.
#[test]
fn alerts_from_the_client() {
    let address = server();
    for (alert, answer) in [([1u8, 48u8], None), ([2, 255], None), ([2, 0], Some(0)), ([1, 0], Some(0))] {
        let mut client = Client::handshake(address, "site.test", &public("site.test"));
        client.send(record::ALERT, &alert);
        let got = client.get();
        match answer {
            Some(code) => {
                assert_eq!(got, Got::Alert(code), "{alert:?}");
                assert_eq!(client.get(), Got::End);
            }
            None => assert_eq!(got, Got::End, "{alert:?}"),
        }
    }
}

/// A record under the next keys is refused until a KeyUpdate says the
/// keys change.
#[test]
fn next_keys_only_after_a_key_update() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.write.as_mut().unwrap().next();
    client.send(record::APPLICATION_DATA, b"too soon");
    assert_eq!(client.alert(), Some(20));
}

/// A chain of more than 16 KB goes out in records of at most 16 KB, one
/// after the other, and the handshake completes.
#[test]
fn a_flight_larger_than_a_record() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&hello("big.test"));
    client.through_flight(&public("site.test"));
    let handshake_records = client.sizes.iter().filter(|&&size| size == record::MAX_PLAINTEXT).count();
    assert!(handshake_records >= 1, "{:?}", client.sizes);
    client.finish(true);
    client.send(record::APPLICATION_DATA, b"a large chain");
    assert_eq!(client.get(), Got::Data(b"a large chain".to_vec()));
}

/// Our unencrypted records say 03 03 for their version; the dummy
/// ChangeCipherSpec follows the ServerHello; an empty session id is
/// echoed as empty; an empty list of key shares asks for a retry.
#[test]
fn what_our_first_records_look_like() {
    let address = server();
    let mut client = Client::connect(address);
    client.send_hello(&Hello { session_id: vec![], ..hello("site.test") });
    let Got::Handshake(messages) = client.get() else { panic!() };
    assert_eq!(&client.last_header[..3], &[22, 3, 3]);
    assert_eq!(server_hello_parts(&messages[0]).1, Vec::<u8>::new());
    assert_eq!(client.get(), Got::Ccs);
    assert_eq!(&client.last_header[..5], &[20, 3, 3, 0, 1]);
    let (_, got) = first_answer(address, &hello("site.test").set(51, key_shares(&[])));
    let Got::Handshake(messages) = got else { panic!() };
    assert_eq!(messages[0][6..38], crypto::sha256(b"HelloRetryRequest"));
}

/// Bug (found in review): any close_notify marked the connection as ended
/// in order, before the state machine had judged it. An unencrypted one
/// after the handshake is refused, yet seven forged bytes from anyone on
/// the path made a cut-off connection read as closed on purpose.
#[test]
fn bug_injected_close_notify_looked_like_an_orderly_end() {
    let (address, world) = server_with(Duration::from_secs(5));
    let before = world.ends.lock().unwrap().len();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.raw(&[21, 3, 3, 0, 2, 1, 0]);
    assert_eq!(client.alert(), Some(10));
    assert_eq!(how_it_ended(world, before), "error");
}

/// A client whose stream ends without close_notify is answered with ours.
#[test]
fn the_end_of_the_client_stream_is_answered() {
    let address = server();
    let mut client = Client::handshake(address, "site.test", &public("site.test"));
    client.tcp.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(client.get(), Got::Alert(0));
    assert_eq!(client.get(), Got::End);
}

/// The alerts we send are logged with their names.
#[test]
fn sent_alerts_are_logged() {
    let (address, world) = server_with(Duration::from_secs(5));
    assert_eq!(alert_for(address, &hello("nowhere.test")), Some(112));
    std::thread::sleep(Duration::from_millis(100));
    let log = world.log.0.lock().unwrap().clone();
    assert!(log.iter().any(|l| l.ends_with("tls: sent unrecognized_name")), "{log:?}");
}

/// Bug (found by tlsfuzzer): a client that cannot read our ServerHello has
/// no keys, so its alert comes unencrypted. We answered it with
/// unexpected_message instead of closing, as after any other alert.
#[test]
fn bug_unencrypted_alert_during_the_handshake_was_answered() {
    let address = server();
    for alert in [[2, 40], [1, 0]] {
        let mut client = Client::connect(address);
        client.send_hello(&hello("site.test"));
        client.through_flight(&public("site.test"));
        client.send(record::ALERT, &alert);
        assert_eq!(client.get(), Got::End, "{alert:?}");
    }
}

/// Bug (found by tlsfuzzer): handshake messages were limited to 64 KB, so a
/// ClientHello with its extensions at their largest, which is valid, got
/// decode_error. The limit is now the longest ClientHello there can be.
#[test]
fn bug_the_largest_client_hellos_were_refused() {
    let address = server();
    let mut big = hello("site.test");
    let extensions = big.extensions.as_mut().unwrap();
    let used: usize = extensions.iter().map(|(_, data)| 4 + data.len()).sum();
    extensions.push((0x4444, vec![0; 65535 - used - 4]));
    big.suites = [0x1303].into_iter().chain(std::iter::repeat_n(0x0a0a, 32766)).collect();
    assert!(big.bytes().len() > 131_000);
    let (_, got) = first_answer(address, &big);
    assert!(matches!(got, Got::Handshake(ref m) if m[0][0] == msgs::SERVER_HELLO), "{got:?}");
}
