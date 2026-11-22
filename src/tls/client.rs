//! A TLS 1.3 client for tests: it does what a well-behaved client does, and
//! lets a test do what a badly behaved one would.

use super::keys::{self, Secret, TrafficKeys, Transcript};
use super::msgs::{self, tests::Hello};
use super::record::{self, Opened};
use super::wire::Reader;
use crate::crypto;
use crate::stream::Buffer;
use std::net::TcpStream;
use std::time::Duration;

/// What the server sent, one record's worth.
#[derive(Debug, PartialEq, Eq)]
pub enum Got {
    /// Handshake messages, each with its header.
    Handshake(Vec<Vec<u8>>),
    Data(Vec<u8>),
    Ccs,
    /// An alert: its description.
    Alert(u8),
    /// The connection ended.
    End,
    /// A record that did not decrypt under the keys we expected.
    Undecryptable,
}

pub struct Keys {
    pub secret: Secret,
    pub keys: TrafficKeys,
    pub sequence: u64,
}

impl Keys {
    fn new(secret: Secret) -> Keys {
        Keys { secret, keys: TrafficKeys::new(&secret), sequence: 0 }
    }

    pub fn next(&mut self) {
        *self = Keys::new(keys::next_secret(&self.secret));
    }
}

pub struct Client {
    pub tcp: TcpStream,
    buffer: Buffer,
    pub transcript: Transcript,
    pub read: Option<Keys>,
    pub write: Option<Keys>,
    secret: [u8; 32],
    /// The handshake secrets and the master secret, once known.
    client_handshake: Secret,
    master: Secret,
    /// What the server's flight held.
    pub encrypted_extensions: Vec<u8>,
    pub certificate: Vec<u8>,
    /// The header of the last record received.
    pub last_header: [u8; 5],
    /// The sizes of the records received, content only.
    pub sizes: Vec<usize>,
    /// Handshake bytes of a message not yet complete.
    partial: Vec<u8>,
    /// The ML-KEM decapsulation key, if we offered X25519MLKEM768.
    pub kem_private: Option<Vec<u8>>,
    /// The group the ServerHello chose.
    pub group: u16,
}

/// An X25519MLKEM768 share (ML-KEM encapsulation key, then our X25519
/// share) and the decapsulation key that goes with it.
pub fn hybrid_share() -> (Vec<u8>, Vec<u8>) {
    let (public, private) = crypto::mlkem768_key_pair([7; 64]);
    ([&public[..], &share()].concat(), private)
}

/// The client's X25519 secret in every test.
pub const SECRET: [u8; 32] = [0x42; 32];

pub fn share() -> [u8; 32] {
    crypto::x25519_public(&SECRET)
}

impl Client {
    pub fn connect(address: std::net::SocketAddr) -> Client {
        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Client {
            tcp,
            buffer: Buffer::new(),
            transcript: Transcript::default(),
            read: None,
            write: None,
            secret: SECRET,
            client_handshake: [0; 32],
            master: [0; 32],
            encrypted_extensions: Vec::new(),
            certificate: Vec::new(),
            last_header: [0; 5],
            sizes: Vec::new(),
            partial: Vec::new(),
            kem_private: None,
            group: 0,
        }
    }

    pub fn raw(&self, bytes: &[u8]) {
        use std::io::Write;
        let _ = (&self.tcp).write_all(bytes);
    }

    /// Sends content in records, sealed if we have write keys, split as a
    /// record may carry at most 16 KB. Empty content is one empty record.
    pub fn send(&mut self, content_type: u8, content: &[u8]) {
        let pieces: Vec<&[u8]> = if content.is_empty() { vec![content] } else { content.chunks(record::MAX_PLAINTEXT).collect() };
        for piece in pieces {
            let bytes = match &mut self.write {
                Some(keys) => {
                    let sealed = record::seal(&keys.keys, keys.sequence, content_type, piece).unwrap();
                    keys.sequence += 1;
                    sealed
                }
                None => record::plain(content_type, piece),
            };
            self.raw(&bytes);
        }
    }

    pub fn send_hello(&mut self, hello: &Hello) {
        let bytes = hello.bytes();
        self.transcript.add(&bytes);
        self.send(record::HANDSHAKE, &bytes);
    }

    /// The next record from the server; handshake messages split over
    /// several records come whole, once their last piece has.
    pub fn get(&mut self) -> Got {
        loop {
            match self.get_one() {
                Got::Handshake(messages) if messages.is_empty() => {}
                other => return other,
            }
        }
    }

    fn get_one(&mut self) -> Got {
        let record = match record::read(&mut self.buffer, &self.tcp) {
            Ok(record) => record,
            Err(_) => return Got::End,
        };
        self.last_header = record.header;
        let (content_type, content) = match (&mut self.read, record.content_type) {
            (Some(keys), record::APPLICATION_DATA) => match record::open(&keys.keys, keys.sequence, &record) {
                Opened::Content(t, c) => {
                    keys.sequence += 1;
                    (t, c)
                }
                _ => return Got::Undecryptable,
            },
            _ => (record.content_type, record.payload),
        };
        self.sizes.push(content.len());
        assert!(content.len() <= record::MAX_PLAINTEXT, "a record of {} bytes", content.len());
        match content_type {
            record::CHANGE_CIPHER_SPEC => {
                assert_eq!(content, [1], "the ChangeCipherSpec is the single byte 1");
                Got::Ccs
            }
            record::ALERT => Got::Alert(*content.get(1).unwrap_or(&255)),
            record::APPLICATION_DATA => Got::Data(content),
            _ => {
                self.partial.extend(content);
                let mut messages = Vec::new();
                loop {
                    let mut r = Reader::new(&self.partial);
                    let Some(_) = r.u8() else { break };
                    let Some(body) = r.vec24() else { break };
                    let whole = 4 + body.rest().len();
                    messages.push(self.partial.drain(..whole).collect());
                }
                Got::Handshake(messages)
            }
        }
    }

    /// The next record that is not the dummy ChangeCipherSpec.
    pub fn get_past_ccs(&mut self) -> Got {
        loop {
            match self.get() {
                Got::Ccs => {}
                other => return other,
            }
        }
    }

    /// The alert the server ends with, past anything else it sends.
    pub fn alert(&mut self) -> Option<u8> {
        loop {
            match self.get() {
                Got::Alert(code) => return Some(code),
                Got::End => return None,
                _ => {}
            }
        }
    }

    /// Takes a ServerHello: keys for the rest of the handshake.
    pub fn take_server_hello(&mut self, hello: &[u8]) {
        self.transcript.add(hello);
        let (group, theirs) = key_share(hello);
        self.group = group;
        let x25519 = |public: &[u8]| crypto::x25519(&self.secret, public.try_into().unwrap()).unwrap();
        let shared = if group == msgs::X25519MLKEM768 {
            let (ciphertext, public) = theirs.split_at(crypto::MLKEM768_CIPHERTEXT_LEN);
            let private = self.kem_private.as_ref().expect("we offered no X25519MLKEM768");
            [crypto::mlkem768_decapsulate(private, ciphertext.try_into().unwrap()), x25519(public)].concat()
        } else {
            assert_eq!(group, msgs::X25519);
            x25519(&theirs).to_vec()
        };
        let secrets = keys::handshake_secrets(&shared, &self.transcript.hash());
        self.read = Some(Keys::new(secrets.server));
        self.write = None;
        self.client_handshake = secrets.client;
        self.master = secrets.master;
    }

    /// Reads the server's flight and checks it: the signature with
    /// `public`, the Finished with our keys. Then we switch to application
    /// keys for reading; `finish` sends our Finished.
    pub fn take_flight(&mut self, public: &[u8; 65]) {
        let mut messages: Vec<Vec<u8>> = Vec::new();
        while messages.len() < 4 {
            match self.get() {
                // The dummy ChangeCipherSpec comes before the flight, never
                // in the middle of it.
                Got::Ccs if messages.is_empty() => {}
                Got::Handshake(more) => messages.extend(more),
                other => panic!("expected the flight, got {other:?}"),
            }
        }
        let [ee, certificate, verify, finished] = <[Vec<u8>; 4]>::try_from(messages).unwrap();
        assert_eq!(ee[0], msgs::ENCRYPTED_EXTENSIONS);
        self.transcript.add(&ee);
        self.transcript.add(&certificate);
        let signed = msgs::signed_content(&self.transcript.hash());
        assert_eq!(&verify[..6], &[msgs::CERTIFICATE_VERIFY, 0, 0, u8::try_from(verify.len() - 4).unwrap(), 4, 3]);
        assert!(crypto::verify(public, &signed, &verify[8..]), "the CertificateVerify does not verify");
        self.transcript.add(&verify);
        let server_secret = self.read.as_ref().unwrap().secret;
        assert_eq!(finished[4..], keys::verify_data(&server_secret, &self.transcript.hash()), "the server Finished is wrong");
        self.transcript.add(&finished);
        self.encrypted_extensions = ee;
        self.certificate = certificate;
    }

    /// Sends our Finished (correct, or not) and switches to application
    /// keys.
    pub fn finish(&mut self, correct: bool) {
        self.finish_with(if correct { None } else { Some(0) });
    }

    pub fn finish_flipping_last_byte(&mut self) {
        self.finish_with(Some(31));
    }

    fn finish_with(&mut self, flip: Option<usize>) {
        let hash = self.transcript.hash();
        let (client_ap, server_ap) = keys::application_secrets(&self.master, &hash);
        let mut verify = keys::verify_data(&self.client_handshake, &hash);
        if let Some(at) = flip {
            verify[at] ^= 1;
        }
        self.write = Some(Keys::new(self.client_handshake));
        self.send(record::HANDSHAKE, &msgs::finished(&verify));
        self.read = Some(Keys::new(server_ap));
        self.write = Some(Keys::new(client_ap));
    }

    /// Reads from now on with the server's application keys, as after its
    /// Finished, without sending ours.
    pub fn read_application(&mut self) {
        let (_, server_ap) = keys::application_secrets(&self.master, &self.transcript.hash());
        self.read = Some(Keys::new(server_ap));
    }

    /// Takes the ServerHello and the flight, as far as reading under the
    /// server's application keys.
    pub fn through_flight(&mut self, public: &[u8; 65]) {
        match self.get_past_ccs() {
            Got::Handshake(messages) => self.take_server_hello(&messages[0]),
            other => panic!("expected ServerHello, got {other:?}"),
        }
        self.take_flight(public);
        self.read_application();
    }

    /// Writes as the client's handshake keys would, for tests that send
    /// something other than Finished at that point.
    pub fn use_handshake_keys(&mut self) {
        self.write = Some(Keys::new(self.client_handshake));
    }

    /// A whole handshake with an ordinary ClientHello for `name`.
    pub fn handshake(address: std::net::SocketAddr, name: &str, public: &[u8; 65]) -> Client {
        let mut client = Client::connect(address);
        client.send_hello(&Hello::new(name, &share()));
        match client.get() {
            Got::Handshake(messages) => client.take_server_hello(&messages[0]),
            other => panic!("expected ServerHello, got {other:?}"),
        }
        client.take_flight(public);
        client.finish(true);
        client
    }
}

/// The group and the key share of a ServerHello.
pub fn key_share(hello: &[u8]) -> (u16, Vec<u8>) {
    let mut r = Reader::new(&hello[4 + 2 + 32..]);
    r.vec8().unwrap();
    r.u16().unwrap();
    r.u8().unwrap();
    let mut extensions = r.vec16().unwrap();
    while !extensions.is_empty() {
        let kind = extensions.u16().unwrap();
        let mut data = extensions.vec16().unwrap();
        if kind == 51 {
            let group = data.u16().unwrap();
            return (group, data.vec16().unwrap().rest().to_vec());
        }
    }
    panic!("a ServerHello without a key share");
}
