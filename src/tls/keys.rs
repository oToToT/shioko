//! The TLS 1.3 key schedule (RFC 8446 section 7) for SHA-256, and the
//! transcript hash.

use crate::crypto::{self, HASH_LEN, KEY_LEN, NONCE_LEN, Sha256};

pub type Secret = [u8; HASH_LEN];

/// Overwrites a secret. Best effort: without `unsafe` the compiler is
/// allowed to drop the write, and `black_box` only discourages that.
pub fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// HKDF-Expand-Label of RFC 8446 section 7.1.
pub fn expand_label(secret: &Secret, label: &str, context: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    info.extend_from_slice(&u16::try_from(out.len()).unwrap_or(0).to_be_bytes());
    info.push(u8::try_from(6 + label.len()).unwrap_or(0));
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(u8::try_from(context.len()).unwrap_or(0));
    info.extend_from_slice(context);
    // Our outputs are at most 32 bytes, far below the limit of HKDF.
    let _ = crypto::hkdf_expand(secret, &info, out);
}

/// Derive-Secret of RFC 8446 section 7.1, given the transcript hash.
pub fn derive_secret(secret: &Secret, label: &str, transcript: &[u8; HASH_LEN]) -> Secret {
    let mut out = [0u8; HASH_LEN];
    expand_label(secret, label, transcript, &mut out);
    out
}

/// The secrets of a handshake, from the shared X25519 secret and the
/// transcript up to ServerHello.
pub struct HandshakeSecrets {
    pub client: Secret,
    pub server: Secret,
    /// Where the application secrets come from.
    pub master: Secret,
}

impl Drop for HandshakeSecrets {
    fn drop(&mut self) {
        wipe(&mut self.client);
        wipe(&mut self.server);
        wipe(&mut self.master);
    }
}

pub fn handshake_secrets(shared: &[u8; 32], transcript: &[u8; HASH_LEN]) -> HandshakeSecrets {
    // Without a PSK the early secret is Extract(0, 0).
    let empty_hash = crypto::sha256(b"");
    let mut early = crypto::hkdf_extract(&[0u8; HASH_LEN], &[0u8; HASH_LEN]);
    let mut salt = derive_secret(&early, "derived", &empty_hash);
    let mut handshake = crypto::hkdf_extract(&salt, shared);
    let client = derive_secret(&handshake, "c hs traffic", transcript);
    let server = derive_secret(&handshake, "s hs traffic", transcript);
    let mut master_salt = derive_secret(&handshake, "derived", &empty_hash);
    let master = crypto::hkdf_extract(&master_salt, &[0u8; HASH_LEN]);
    for secret in [&mut early, &mut salt, &mut handshake, &mut master_salt] {
        wipe(secret);
    }
    HandshakeSecrets { client, server, master }
}

/// The first application traffic secrets, client then server, from the
/// transcript up to the server Finished.
pub fn application_secrets(master: &Secret, transcript: &[u8; HASH_LEN]) -> (Secret, Secret) {
    (derive_secret(master, "c ap traffic", transcript), derive_secret(master, "s ap traffic", transcript))
}

/// The secret of the next generation, after a KeyUpdate.
pub fn next_secret(secret: &Secret) -> Secret {
    let mut out = [0u8; HASH_LEN];
    expand_label(secret, "traffic upd", &[], &mut out);
    out
}

/// The key and IV for ChaCha20-Poly1305 made from a traffic secret.
#[derive(Clone)]
pub struct TrafficKeys {
    pub key: [u8; KEY_LEN],
    pub iv: [u8; NONCE_LEN],
}

impl TrafficKeys {
    pub fn new(secret: &Secret) -> TrafficKeys {
        let mut keys = TrafficKeys { key: [0; KEY_LEN], iv: [0; NONCE_LEN] };
        expand_label(secret, "key", &[], &mut keys.key);
        expand_label(secret, "iv", &[], &mut keys.iv);
        keys
    }

    /// The nonce of the record with this sequence number (section 5.3).
    pub fn nonce(&self, sequence: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        for (byte, s) in nonce.iter_mut().skip(NONCE_LEN - 8).zip(sequence.to_be_bytes()) {
            *byte ^= s;
        }
        nonce
    }
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.iv);
    }
}

/// The verify_data of a Finished message (section 4.4.4).
pub fn verify_data(secret: &Secret, transcript: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut key = [0u8; HASH_LEN];
    expand_label(secret, "finished", &[], &mut key);
    crypto::hmac_sha256(&key, &[transcript])
}

/// The running hash of the handshake messages.
#[derive(Clone)]
pub struct Transcript(Sha256);

impl Default for Transcript {
    fn default() -> Transcript {
        Transcript(Sha256::new())
    }
}

impl Transcript {
    pub fn add(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.0.finish()
    }

    /// After a HelloRetryRequest the first ClientHello is replaced by a
    /// message_hash message holding its hash (section 4.4.1).
    pub fn restart_with_message_hash(&mut self) {
        let hash = self.hash();
        *self = Transcript::default();
        self.add(&[254, 0, 0, HASH_LEN as u8]);
        self.add(&hash);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const RFC8448: &str = include_str!("../../tests/vectors/rfc8448.txt");

    /// A value of the RFC 8448 traces: the section, the step's title, which
    /// occurrence of that title, and the value's name.
    pub fn trace(section: &str, step: &str, occurrence: usize, name: &str) -> Vec<u8> {
        let occurrence = occurrence.to_string();
        let line = RFC8448
            .lines()
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .find(|f| f.len() == 5 && f[0] == section && f[1] == step && f[2] == occurrence && f[3] == name)
            .unwrap_or_else(|| panic!("no {section} {step} {name}"));
        (0..line[4].len()).step_by(2).map(|i| u8::from_str_radix(&line[4][i..i + 2], 16).unwrap()).collect()
    }

    fn secret(bytes: Vec<u8>) -> Secret {
        bytes.try_into().unwrap()
    }

    fn message(section: &str, who: &str, name: &str, occurrence: usize) -> Vec<u8> {
        trace(section, &format!("{{{who}}}  construct a{} {name} handshake message:", if name.starts_with(['A', 'E']) { "n" } else { "" }), occurrence, name)
    }

    #[test]
    fn the_simple_handshake_of_rfc8448() {
        let s = "3";
        let client_hello = message(s, "client", "ClientHello", 1);
        let server_hello = message(s, "server", "ServerHello", 1);
        let client_public: [u8; 32] = trace(s, "{client}  create an ephemeral x25519 key pair:", 1, "public key").try_into().unwrap();
        let server_private: [u8; 32] = trace(s, "{server}  create an ephemeral x25519 key pair:", 1, "private key").try_into().unwrap();
        let shared = crypto::x25519(&server_private, &client_public).unwrap();
        assert_eq!(shared.to_vec(), trace(s, "{server}  extract secret \"handshake\":", 1, "IKM"));

        let mut transcript = Transcript::default();
        transcript.add(&client_hello);
        transcript.add(&server_hello);
        let hash = transcript.hash();
        assert_eq!(hash.to_vec(), trace(s, "{server}  derive secret \"tls13 c hs traffic\":", 1, "hash"));
        let secrets = handshake_secrets(&shared, &hash);
        assert_eq!(secrets.client.to_vec(), trace(s, "{server}  derive secret \"tls13 c hs traffic\":", 1, "expanded"));
        assert_eq!(secrets.server.to_vec(), trace(s, "{server}  derive secret \"tls13 s hs traffic\":", 1, "expanded"));
        assert_eq!(secrets.master.to_vec(), trace(s, "{server}  extract secret \"master\":", 1, "secret"));

        // Keys are expanded the same way whatever their length; the trace
        // uses AES-128, so 16 bytes.
        let step = "{server}  derive write traffic keys for handshake data:";
        let mut key = [0u8; 16];
        expand_label(&secrets.server, "key", &[], &mut key);
        assert_eq!(key.to_vec(), trace(s, step, 1, "key expanded"));
        assert_eq!(TrafficKeys::new(&secrets.server).iv.to_vec(), trace(s, step, 1, "iv expanded"));

        for name in ["EncryptedExtensions", "Certificate", "CertificateVerify"] {
            transcript.add(&message(s, "server", name, 1));
        }
        let finished = message(s, "server", "Finished", 1);
        assert_eq!(verify_data(&secrets.server, &transcript.hash()).to_vec(), finished[4..]);
        transcript.add(&finished);

        let (client_ap, server_ap) = application_secrets(&secrets.master, &transcript.hash());
        assert_eq!(client_ap.to_vec(), trace(s, "{server}  derive secret \"tls13 c ap traffic\":", 1, "expanded"));
        assert_eq!(server_ap.to_vec(), trace(s, "{server}  derive secret \"tls13 s ap traffic\":", 1, "expanded"));
        let step = "{server}  derive write traffic keys for application data:";
        assert_eq!(TrafficKeys::new(&server_ap).iv.to_vec(), trace(s, step, 1, "iv expanded"));

        // The client's Finished, as the server checks it.
        let client_finished = message(s, "client", "Finished", 1);
        assert_eq!(verify_data(&secrets.client, &transcript.hash()).to_vec(), client_finished[4..]);
    }

    #[test]
    fn the_hello_retry_request_of_rfc8448() {
        let s = "5";
        let mut transcript = Transcript::default();
        transcript.add(&message(s, "client", "ClientHello", 1));
        transcript.restart_with_message_hash();
        transcript.add(&message(s, "server", "ServerHello", 1));
        transcript.add(&message(s, "client", "ClientHello", 2));
        transcript.add(&message(s, "server", "ServerHello", 2));
        let hash = transcript.hash();
        assert_eq!(hash.to_vec(), trace(s, "{server}  derive secret \"tls13 c hs traffic\":", 1, "hash"));
        let shared = secret(trace(s, "{server}  extract secret \"handshake\":", 1, "IKM"));
        let secrets = handshake_secrets(&shared, &hash);
        assert_eq!(secrets.server.to_vec(), trace(s, "{server}  derive secret \"tls13 s hs traffic\":", 1, "expanded"));
        for name in ["EncryptedExtensions", "Certificate", "CertificateVerify"] {
            transcript.add(&message(s, "server", name, 1));
        }
        let finished = message(s, "server", "Finished", 1);
        assert_eq!(verify_data(&secrets.server, &transcript.hash()).to_vec(), finished[4..]);
    }

    /// The next-generation secret, worked out by hand from RFC 8446
    /// section 7.2 rather than through `expand_label`.
    #[test]
    fn the_next_generation_by_hand() {
        let secret = [3u8; 32];
        let mut info = vec![0, 32, 17];
        info.extend_from_slice(b"tls13 traffic upd");
        info.push(0);
        let mut expected = [0u8; 32];
        crypto::hkdf_expand(&secret, &info, &mut expected).unwrap();
        assert_eq!(next_secret(&secret), expected);
    }

    /// Bug (found in review): the handshake and master secrets, and the
    /// secrets in between, were never overwritten.
    #[test]
    fn bug_handshake_secrets_were_never_wiped() {
        assert!(std::mem::needs_drop::<HandshakeSecrets>());
        let mut secret = [7u8; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0; 32]);
    }

    #[test]
    fn the_next_generation_and_the_nonce() {
        // Each generation differs from the last, and the nonce is the IV
        // with the sequence number folded into its last eight bytes.
        let first = [7u8; 32];
        let second = next_secret(&first);
        assert_ne!(first, second);
        assert_ne!(second, next_secret(&second));
        let keys = TrafficKeys::new(&first);
        assert_eq!(keys.nonce(0), keys.iv);
        let mut expected = keys.iv;
        expected[11] ^= 1;
        expected[4] ^= 0x80;
        assert_eq!(keys.nonce(0x8000_0000_0000_0001), expected);
    }
}
