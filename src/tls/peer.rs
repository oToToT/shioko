//! A TLS client, as the transport of a TlsStream under test, for the fuzz
//! targets (fuzz/) and the tests of interleavings (src/interleavings.rs):
//! it gets the server through a real handshake, then sends records of the
//! test's choosing sealed under its keys, so that what comes after the
//! handshake can be reached: records, key updates, alerts, HTTP over TLS.
//! It also checks what the server sends back.
//!
//! It runs in the thread that reads: the server reads our ClientHello,
//! writes its flight, and when it reads again we take the flight from what
//! it wrote and answer with our Finished and the planned records.

use super::keys::{self, Secret, TrafficKeys, Transcript};
use super::msgs;
use super::record::{self, Opened, Record};
use super::wire::Reader;
use crate::crypto;
use crate::stream::Stream;
use crate::sync::{Arc, Condvar, Mutex};
use std::io;
use std::time::Duration;

const SECRET: [u8; 32] = [0x42; 32];
const OUTPUT_LIMIT: usize = 1 << 20;

/// In the fuzzer's records, this content type means: these bytes as they
/// are, not sealed.
pub const RAW: u8 = 0xff;

/// A handle on the client; clones share it, so that the test can check
/// what the server sent after the server is done with its stream.
#[derive(Clone)]
pub struct Peer(Arc<(Mutex<State>, Condvar)>);

struct State {
    /// Once its records are read, the connection stays open (a read waits)
    /// until the server shuts it down; otherwise it ends there.
    held: bool,
    /// The server shut the connection down: reads end, writes fail.
    shut: bool,
    input: Vec<u8>,
    at: usize,
    piece: usize,
    output: Vec<u8>,
    transcript: Transcript,
    /// The fuzzer's records, until the handshake gives us keys to seal them.
    planned: Vec<(u8, Vec<u8>)>,
    /// Once the handshake is done: the server's application secret and
    /// where its records under it begin.
    reading: Option<(Secret, usize)>,
}

impl Peer {
    /// A client that will send `records` once the handshake is done, the
    /// server's reads getting at most `piece` bytes each, and then end.
    pub fn new(records: Vec<(u8, Vec<u8>)>, piece: usize) -> Peer {
        Peer::with(records, piece, false)
    }

    /// The same, but it then keeps the connection open until the server
    /// shuts it down.
    pub fn held(records: Vec<(u8, Vec<u8>)>, piece: usize) -> Peer {
        Peer::with(records, piece, true)
    }

    fn with(records: Vec<(u8, Vec<u8>)>, piece: usize, held: bool) -> Peer {
        let hello = client_hello(&crypto::x25519_public(&SECRET));
        let mut transcript = Transcript::default();
        transcript.add(&hello);
        Peer(Arc::new((Mutex::new(State {
            held,
            shut: false,
            input: record::plain(record::HANDSHAKE, &hello),
            at: 0,
            piece: piece.max(1),
            output: Vec::new(),
            transcript,
            planned: records,
            reading: None,
        }), Condvar::new())))
    }

    fn state(&self) -> crate::sync::MutexGuard<'_, State> {
        self.0.0.lock().unwrap()
    }

    /// The fuzzer's part of the input: records, each a content type, a
    /// length in two bytes and the content; a cut-off one takes what is
    /// left.
    pub fn records(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut records = Vec::new();
        while let Some((&content_type, rest)) = data.split_first() {
            let (length, rest) = rest.split_at_checked(2).unwrap_or((&[0, 0], rest));
            let n = usize::from(u16::from_be_bytes([length[0], length[1]])).min(rest.len());
            records.push((content_type, rest[..n].to_vec()));
            data = &rest[n..];
        }
        records
    }

    /// What the server sent after the handshake: every record must open
    /// under its keys in turn (following its KeyUpdates), hold at most
    /// 16 KB, and none may come after an alert. Returns the application
    /// data, and the alert the server ended with, if it did.
    pub fn check(&self) -> (Vec<u8>, Option<u8>) {
        let state = self.state();
        let mut data = Vec::new();
        let mut alert = None;
        let Some((secret, from)) = state.reading else { return (data, alert) };
        let mut keys = Keys::new(secret);
        let mut partial = Vec::new();
        for record in split(&state.output[from..]).expect("the server's records are whole") {
            assert!(alert.is_none(), "the server sent a record after an alert");
            assert_eq!(record.content_type, record::APPLICATION_DATA, "a record not protected after the handshake");
            let Opened::Content(content_type, content) = record::open(&keys.keys, keys.sequence, &record) else {
                panic!("a record of the server's does not open under its keys");
            };
            keys.sequence += 1;
            assert!(content.len() <= record::MAX_PLAINTEXT, "a record of {} bytes", content.len());
            match content_type {
                record::ALERT => alert = Some(*content.get(1).unwrap_or(&255)),
                record::HANDSHAKE => {
                    partial.extend(content);
                    for message in messages(&mut partial) {
                        assert_eq!(message[0], msgs::KEY_UPDATE, "the server sent handshake message {}", message[0]);
                        keys.next();
                    }
                }
                record::APPLICATION_DATA => data.extend(content),
                other => panic!("the server sent content type {other}"),
            }
        }
        (data, alert)
    }
}

impl Stream for Peer {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state();
        if state.at == state.input.len() && state.reading.is_none() {
            state.answer_flight();
        }
        while state.held && !state.shut && state.at == state.input.len() {
            state = self.0.1.wait(state).unwrap();
        }
        let State { input, at, piece, .. } = &mut *state;
        let n = buf.len().min(*piece).min(input.len() - *at);
        buf[..n].copy_from_slice(&input[*at..*at + n]);
        *at += n;
        Ok(n)
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut state = self.state();
        if state.shut {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if state.output.len() + buf.len() > OUTPUT_LIMIT {
            return Err(io::ErrorKind::WriteZero.into());
        }
        state.output.extend_from_slice(buf);
        Ok(())
    }

    fn set_read_timeout(&self, _: Duration) {}

    fn shutdown(&self) {
        self.state().shut = true;
        self.0.1.notify_all();
    }

    fn finish(&self) {
        self.shutdown();
    }
}

impl State {
    /// The server has read our ClientHello and wants more: by now it has
    /// sent ServerHello and its flight, which it must have done right. We
    /// send our Finished, then the fuzzer's records.
    fn answer_flight(&mut self) {
        let records = split(&self.output).expect("the server's flight is whole records");
        let mut records = records.into_iter().filter(|r| r.content_type != record::CHANGE_CIPHER_SPEC);
        let hello = records.next().expect("a ServerHello");
        assert_eq!(hello.content_type, record::HANDSHAKE, "the server answered a good ClientHello with {hello:?}");
        self.transcript.add(&hello.payload);
        let shared = crypto::x25519(&SECRET, &server_share(&hello.payload)).expect("a good X25519 share");
        let secrets = keys::handshake_secrets(&shared, &self.transcript.hash());
        let mut server = Keys::new(secrets.server);
        let mut partial = Vec::new();
        let mut flight = Vec::new();
        for record in records {
            let Opened::Content(record::HANDSHAKE, content) = record::open(&server.keys, server.sequence, &record) else {
                panic!("a record of the flight does not open as handshake");
            };
            server.sequence += 1;
            partial.extend(content);
            flight.extend(messages(&mut partial));
        }
        let kinds: Vec<u8> = flight.iter().map(|m| m[0]).collect();
        assert_eq!(kinds, [msgs::ENCRYPTED_EXTENSIONS, msgs::CERTIFICATE, msgs::CERTIFICATE_VERIFY, msgs::FINISHED]);
        for message in &flight[..3] {
            self.transcript.add(message);
        }
        assert_eq!(flight[3][4..], keys::verify_data(&secrets.server, &self.transcript.hash()), "the server Finished");
        self.transcript.add(&flight[3]);
        let hash = self.transcript.hash();
        let (client_ap, server_ap) = keys::application_secrets(&secrets.master, &hash);
        let finished = msgs::finished(&keys::verify_data(&secrets.client, &hash));
        let mut write = Keys::new(secrets.client);
        self.input.extend(write.seal(record::HANDSHAKE, &finished));
        let mut write = Keys::new(client_ap);
        let mut partial = Vec::new();
        for (content_type, content) in std::mem::take(&mut self.planned) {
            if content_type == RAW {
                self.input.extend(content);
                continue;
            }
            self.input.extend(write.seal(content_type, &content));
            // A KeyUpdate of ours: the server reads with the next keys.
            if content_type == record::HANDSHAKE {
                partial.extend(content);
                for message in messages(&mut partial) {
                    if message[0] == msgs::KEY_UPDATE {
                        write.next();
                    }
                }
            }
        }
        self.reading = Some((server_ap, self.output.len()));
    }
}

struct Keys {
    secret: Secret,
    keys: TrafficKeys,
    sequence: u64,
}

impl Keys {
    fn new(secret: Secret) -> Keys {
        Keys { secret, keys: TrafficKeys::new(&secret), sequence: 0 }
    }

    fn next(&mut self) {
        *self = Keys::new(keys::next_secret(&self.secret));
    }

    fn seal(&mut self, content_type: u8, content: &[u8]) -> Vec<u8> {
        let sealed = record::seal(&self.keys, self.sequence, content_type, content).unwrap();
        self.sequence += 1;
        sealed
    }
}

/// The records in `bytes`, or None if the last one is cut off.
fn split(mut bytes: &[u8]) -> Option<Vec<Record>> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        let header: [u8; 5] = bytes.get(..5)?.try_into().unwrap();
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload = bytes.get(5..5 + length)?.to_vec();
        records.push(Record { content_type: header[0], header, payload });
        bytes = &bytes[5 + length..];
    }
    Some(records)
}

/// The whole handshake messages at the start of `partial`, taken out of it.
fn messages(partial: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    loop {
        let mut r = Reader::new(partial);
        let (Some(_), Some(body)) = (r.u8(), r.vec24()) else { break };
        let whole = 4 + body.rest().len();
        messages.push(partial.drain(..whole).collect());
    }
    messages
}

/// The X25519 share of a ServerHello.
fn server_share(hello: &[u8]) -> [u8; 32] {
    let mut r = Reader::new(&hello[4 + 2 + 32..]);
    r.vec8().unwrap();
    r.u16().unwrap();
    r.u8().unwrap();
    let mut extensions = r.vec16().unwrap();
    while !extensions.is_empty() {
        let kind = extensions.u16().unwrap();
        let mut data = extensions.vec16().unwrap();
        if kind == 51 {
            assert_eq!(data.u16(), Some(msgs::X25519));
            return data.vec16().unwrap().rest().try_into().unwrap();
        }
    }
    panic!("a ServerHello without a key share");
}

/// An ordinary ClientHello for site.test: X25519 only, so no
/// HelloRetryRequest, both suites, ECDSA P-256, ALPN http/1.1.
fn client_hello(share: &[u8; 32]) -> Vec<u8> {
    fn vec(width: usize, data: &[u8]) -> Vec<u8> {
        [&data.len().to_be_bytes()[8 - width..], data].concat()
    }
    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        [&kind.to_be_bytes()[..], &vec(2, data)].concat()
    }
    let extensions = [
        extension(0, &vec(2, &[&[0][..], &vec(2, b"site.test")].concat())),
        extension(43, &vec(1, &[3, 4])),
        extension(10, &vec(2, &msgs::X25519.to_be_bytes())),
        extension(13, &vec(2, &[4, 3])),
        extension(51, &vec(2, &[&msgs::X25519.to_be_bytes()[..], &vec(2, share)].concat())),
        extension(16, &vec(2, &vec(1, b"http/1.1"))),
    ]
    .concat();
    let body = [&[3, 3][..], &[7; 32], &vec(1, &[0; 32]), &vec(2, &[0x13, 0x03, 0x13, 0x01]), &vec(1, &[0]), &vec(2, &extensions)]
        .concat();
    [&[msgs::CLIENT_HELLO][..], &vec(3, &body)].concat()
}
