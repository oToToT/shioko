//! Handshake messages (RFC 8446 section 4): reading the ClientHello and the
//! client's other messages, and writing ours.

use super::fsm::Alert;
use super::wire::{Reader, Writer};
use crate::crypto::HASH_LEN;

pub const CLIENT_HELLO: u8 = 1;
pub const SERVER_HELLO: u8 = 2;
pub const ENCRYPTED_EXTENSIONS: u8 = 8;
pub const CERTIFICATE: u8 = 11;
pub const CERTIFICATE_VERIFY: u8 = 15;
pub const FINISHED: u8 = 20;
pub const KEY_UPDATE: u8 = 24;

const TLS13: u16 = 0x0304;
const CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const X25519: u16 = 0x001d;
const ECDSA_P256_SHA256: u16 = 0x0403;
const HTTP11: &[u8] = b"http/1.1";

const SERVER_NAME: u16 = 0;
const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const PADDING: u16 = 21;
const PRE_SHARED_KEY: u16 = 41;
const EARLY_DATA: u16 = 42;
const SUPPORTED_VERSIONS: u16 = 43;
const COOKIE: u16 = 44;
const PSK_KEY_EXCHANGE_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;

/// The random of a HelloRetryRequest: SHA-256 of "HelloRetryRequest"
/// (section 4.1.3).
const RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The longest handshake message we take from a client: the longest
/// ClientHello there can be, with every vector at its largest (version,
/// random, session id, cipher suites, compression methods, extensions).
pub const MESSAGE_LIMIT: usize = 2 + 32 + (1 + 32) + (2 + 65534) + (1 + 255) + (2 + 65535);

/// What we need of a ClientHello we can serve.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub session_id: &'a [u8],
    /// The host name of server_name.
    pub server_name: &'a [u8],
    /// The X25519 key share, if the client sent one.
    pub share: Option<[u8; 32]>,
    /// How many key shares the client sent.
    pub shares: usize,
    /// The client offers early data.
    pub early: bool,
    /// The client offers ALPN (and http/1.1 is among what it offers).
    pub alpn: bool,
    /// What a second ClientHello must repeat of this one (section 4.1.2):
    /// all of it, extensions in order, but the key shares, early_data,
    /// pre_shared_key and padding.
    pub kept: Vec<u8>,
}

fn u16s_bytes(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// A non-empty list of two-byte values that fills `list`.
fn u16s(mut list: Reader<'_>) -> Option<Vec<u16>> {
    if list.is_empty() || !list.rest().len().is_multiple_of(2) {
        return None;
    }
    let mut values = Vec::new();
    while !list.is_empty() {
        values.push(list.u16()?);
    }
    Some(values)
}

/// The contents of an extension as `read` decodes them, if it is there.
/// `read` must take all of it.
fn extension<'a, T>(data: Option<Reader<'a>>, read: impl FnOnce(&mut Reader<'a>) -> Option<T>) -> Result<Option<T>, Alert> {
    let Some(mut data) = data else { return Ok(None) };
    read(&mut data).filter(|_| data.is_empty()).map(Some).ok_or(Alert::DecodeError)
}

/// Reads and checks a ClientHello: the whole handshake message, header
/// included. The error is the alert that refuses it. What is checked, and
/// in this order:
///
/// 1. it parses, the contents of the extensions we read included
///    (`decode_error`);
/// 2. it offers TLS 1.3 (`protocol_version`);
/// 3. compression is exactly "none", no extension is repeated, a cookie is
///    not sent, `pre_shared_key` comes last, server_name holds one host
///    name, no key share is empty (`illegal_parameter`), and `pre_shared_key` has
///    `psk_key_exchange_modes` with it (`missing_extension`);
/// 4. `signature_algorithms`, `supported_groups`, `key_share` and
///    `server_name` are there (`missing_extension`);
/// 5. it offers our cipher suite, group and signature scheme
///    (`handshake_failure`);
/// 6. its key shares are well formed (`illegal_parameter`);
/// 7. if it offers ALPN, it offers http/1.1 (`no_application_protocol`).
pub fn client_hello(message: &[u8]) -> Result<ClientHello<'_>, Alert> {
    let decode_error = Alert::DecodeError;
    let mut r = Reader::new(message);
    if r.u8() != Some(CLIENT_HELLO) {
        return Err(Alert::UnexpectedMessage);
    }
    let mut body = r.vec24().ok_or(decode_error)?;
    r.end().ok_or(decode_error)?;
    let legacy_version = body.u16().ok_or(decode_error)?;
    let random = body.bytes(32).ok_or(decode_error)?;
    let session_id = body.vec8().map(Reader::rest).filter(|id| id.len() <= 32).ok_or(decode_error)?;
    let suites = body.vec16().and_then(u16s).ok_or(decode_error)?;
    let compression = body.vec8().map(Reader::rest).filter(|c| !c.is_empty()).ok_or(decode_error)?;
    // Without extensions there is no supported_versions: a client of TLS
    // 1.2 or older.
    if body.is_empty() {
        return Err(Alert::ProtocolVersion);
    }
    let mut extensions = body.vec16().ok_or(decode_error)?;
    body.end().ok_or(decode_error)?;
    let mut found: Vec<(u16, Reader<'_>)> = Vec::new();
    let (mut repeated, mut psk_last) = (false, true);
    while !extensions.is_empty() {
        let kind = extensions.u16().ok_or(decode_error)?;
        let data = extensions.vec16().ok_or(decode_error)?;
        repeated |= found.iter().any(|(k, _)| *k == kind);
        psk_last &= !found.iter().any(|(k, _)| *k == PRE_SHARED_KEY);
        found.push((kind, data));
    }
    let get = |kind: u16| found.iter().find(|(k, _)| *k == kind).map(|(_, data)| *data);

    // 1. The contents of the extensions we read.
    let versions = extension(get(SUPPORTED_VERSIONS), |data| data.vec8().and_then(u16s))?;
    let signatures = extension(get(SIGNATURE_ALGORITHMS), |data| data.vec16().and_then(u16s))?;
    let groups = extension(get(SUPPORTED_GROUPS), |data| data.vec16().and_then(u16s))?;
    let shares = extension(get(KEY_SHARE), |data| {
        let mut entries = data.vec16()?;
        let mut list = Vec::new();
        while !entries.is_empty() {
            let group = entries.u16()?;
            list.push((group, entries.vec16()?.rest()));
        }
        Some(list)
    })?;
    // The host name, and whether there was more than one.
    let server_name = extension(get(SERVER_NAME), |data| {
        let mut list = data.vec16()?;
        let mut name: Option<&[u8]> = None;
        let mut two = false;
        while !list.is_empty() {
            let kind = list.u8()?;
            let entry = list.vec16()?.rest();
            if kind == 0 {
                two |= name.is_some();
                name = Some(entry);
            }
        }
        Some((name.filter(|n| !n.is_empty())?, two))
    })?;
    // Whether the ALPN list holds http/1.1.
    let alpn = extension(get(ALPN), |data| {
        let mut protocols = data.vec16().filter(|p| !p.is_empty())?;
        let mut http11 = false;
        while !protocols.is_empty() {
            http11 |= protocols.vec8().filter(|n| !n.is_empty())?.rest() == HTTP11;
        }
        Some(http11)
    })?;
    let early = extension(get(EARLY_DATA), |_| Some(()))?.is_some();

    // 2. The version. A legacy_version of SSL 3.0 or older is refused
    // whatever else is offered (appendix D.5).
    if !versions.is_some_and(|v| v.contains(&TLS13)) || legacy_version <= 0x0300 {
        return Err(Alert::ProtocolVersion);
    }

    // 3. What may not be there, or not like this.
    let two_names = server_name.is_some_and(|(_, two)| two);
    // key_exchange<1..2^16-1>: an empty one is a bad value, for any group.
    let empty_share = shares.as_ref().is_some_and(|s| s.iter().any(|(_, key)| key.is_empty()));
    if compression != [0] || repeated || get(COOKIE).is_some() || !psk_last || two_names || empty_share {
        return Err(Alert::IllegalParameter);
    }
    if get(PRE_SHARED_KEY).is_some() && get(PSK_KEY_EXCHANGE_MODES).is_none() {
        return Err(Alert::MissingExtension);
    }

    // 4. What must be there.
    let (Some(signatures), Some(groups), Some(shares), Some((server_name, _))) = (signatures, groups, shares, server_name) else {
        return Err(Alert::MissingExtension);
    };

    // 5. What we can do.
    if !suites.contains(&CHACHA20_POLY1305_SHA256) || !signatures.contains(&ECDSA_P256_SHA256) || !groups.contains(&X25519) {
        return Err(Alert::HandshakeFailure);
    }

    // 6. The key shares: one per group at most, only for offered groups.
    let mut share = None;
    for (index, (group, key)) in shares.iter().enumerate() {
        let again = shares.iter().take(index).any(|(g, _)| g == group);
        if again || !groups.contains(group) {
            return Err(Alert::IllegalParameter);
        }
        if *group == X25519 {
            share = Some(<[u8; 32]>::try_from(*key).map_err(|_| Alert::IllegalParameter)?);
        }
    }

    // 7. ALPN.
    if alpn == Some(false) {
        return Err(Alert::NoApplicationProtocol);
    }

    // Each part with its length, so that no two ClientHellos keep the same.
    let mut kept = Vec::new();
    let mut keep = |part: &[u8]| {
        kept.extend(u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        kept.extend(part);
    };
    for part in [&legacy_version.to_be_bytes()[..], random, session_id, &u16s_bytes(&suites), compression] {
        keep(part);
    }
    for (kind, data) in found.iter().filter(|(k, _)| ![KEY_SHARE, EARLY_DATA, PRE_SHARED_KEY, PADDING].contains(k)) {
        keep(&kind.to_be_bytes());
        keep(data.rest());
    }
    Ok(ClientHello { session_id, server_name, share, shares: shares.len(), early, alpn: alpn.is_some(), kept })
}

/// A handshake message: its type, its length, its body.
fn message(kind: u8, body: impl FnOnce(&mut Writer) -> &mut Writer) -> Vec<u8> {
    let mut w = Writer::default();
    w.u8(kind).vec(3, body);
    w.bytes
}

fn hello(random: &[u8; 32], session_id: &[u8], key_share: impl FnOnce(&mut Writer) -> &mut Writer) -> Vec<u8> {
    message(SERVER_HELLO, |w| {
        w.u16(0x0303).raw(random).vec(1, |w| w.raw(session_id));
        w.u16(CHACHA20_POLY1305_SHA256).u8(0).vec(2, |w| {
            w.u16(SUPPORTED_VERSIONS).vec(2, |w| w.u16(TLS13));
            w.u16(KEY_SHARE).vec(2, key_share)
        })
    })
}

pub fn server_hello(random: &[u8; 32], session_id: &[u8], public: &[u8; 32]) -> Vec<u8> {
    hello(random, session_id, |w| w.u16(X25519).vec(2, |w| w.raw(public)))
}

pub fn hello_retry_request(session_id: &[u8]) -> Vec<u8> {
    hello(&RETRY_RANDOM, session_id, |w| w.u16(X25519))
}

/// EncryptedExtensions: an empty server_name to say we used it, and the
/// protocol if the client offered ALPN.
pub fn encrypted_extensions(alpn: bool) -> Vec<u8> {
    message(ENCRYPTED_EXTENSIONS, |w| {
        w.vec(2, |w| {
            w.u16(SERVER_NAME).u16(0);
            if alpn {
                w.u16(ALPN).vec(2, |w| w.vec(2, |w| w.vec(1, |w| w.raw(HTTP11))));
            }
            w
        })
    })
}

pub fn certificate(chain: &[Vec<u8>]) -> Vec<u8> {
    message(CERTIFICATE, |w| {
        w.u8(0).vec(3, |w| {
            for der in chain {
                w.vec(3, |w| w.raw(der)).u16(0);
            }
            w
        })
    })
}

/// What CertificateVerify signs (section 4.4.3).
pub fn signed_content(transcript: &[u8; HASH_LEN]) -> Vec<u8> {
    [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", transcript].concat()
}

pub fn certificate_verify(signature: &[u8]) -> Vec<u8> {
    message(CERTIFICATE_VERIFY, |w| w.u16(ECDSA_P256_SHA256).vec(2, |w| w.raw(signature)))
}

pub fn finished(verify_data: &[u8; HASH_LEN]) -> Vec<u8> {
    message(FINISHED, |w| w.raw(verify_data))
}

pub fn key_update(requested: bool) -> Vec<u8> {
    message(KEY_UPDATE, |w| w.u8(u8::from(requested)))
}

/// The verify_data of a client Finished, if the message is one.
pub fn client_finished(message: &[u8]) -> Option<&[u8]> {
    let verify_data = message.strip_prefix(&[FINISHED, 0, 0, HASH_LEN as u8])?;
    (verify_data.len() == HASH_LEN).then_some(verify_data)
}

/// A KeyUpdate: whether the client asks for ours. Anything but 0 and 1 is
/// refused (section 4.6.3).
pub fn client_key_update(message: &[u8]) -> Result<bool, Alert> {
    match message {
        [KEY_UPDATE, 0, 0, 1, 0] => Ok(false),
        [KEY_UPDATE, 0, 0, 1, 1] => Ok(true),
        [KEY_UPDATE, 0, 0, 1, _] => Err(Alert::IllegalParameter),
        _ => Err(Alert::DecodeError),
    }
}

/// An alert record's payload.
pub fn alert(alert: Alert) -> [u8; 2] {
    let level = if alert == Alert::CloseNotify { 1 } else { 2 };
    [level, alert.code()]
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tls::keys::tests::trace;

    /// The parts of a ClientHello a test may want to change.
    #[derive(Clone)]
    pub struct Hello {
        pub version: Vec<u8>,
        pub session_id: Vec<u8>,
        pub suites: Vec<u16>,
        pub compression: Vec<u8>,
        /// (type, data) in order; `None` for no extensions block at all.
        pub extensions: Option<Vec<(u16, Vec<u8>)>>,
    }

    pub fn u16s(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn vec16(data: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    pub fn sni(name: &str) -> Vec<u8> {
        let mut entry = vec![0u8];
        entry.extend(vec16(name.as_bytes()));
        vec16(&entry)
    }

    pub fn key_shares(shares: &[(u16, &[u8])]) -> Vec<u8> {
        let entries: Vec<u8> = shares.iter().flat_map(|(group, key)| [group.to_be_bytes().to_vec(), vec16(key)].concat()).collect();
        vec16(&entries)
    }

    pub fn alpn(protocols: &[&str]) -> Vec<u8> {
        let list: Vec<u8> = protocols.iter().flat_map(|p| [vec![u8::try_from(p.len()).unwrap()], p.as_bytes().to_vec()].concat()).collect();
        vec16(&list)
    }

    impl Hello {
        /// What a modern client sends, with this X25519 key share.
        pub fn new(name: &str, share: &[u8; 32]) -> Hello {
            Hello {
                version: vec![3, 3],
                session_id: vec![0xab; 32],
                suites: vec![0x1301, 0x1303, 0x1302],
                compression: vec![0],
                extensions: Some(vec![
                    (SERVER_NAME, sni(name)),
                    (SUPPORTED_GROUPS, vec16(&u16s(&[X25519, 0x0017]))),
                    (SIGNATURE_ALGORITHMS, vec16(&u16s(&[0x0804, ECDSA_P256_SHA256]))),
                    (ALPN, alpn(&["h2", "http/1.1"])),
                    (SUPPORTED_VERSIONS, [vec![4], u16s(&[TLS13, 0x0303])].concat()),
                    (KEY_SHARE, key_shares(&[(X25519, share)])),
                ]),
            }
        }

        pub fn set(mut self, kind: u16, data: Vec<u8>) -> Hello {
            let extensions = self.extensions.as_mut().unwrap();
            match extensions.iter_mut().find(|(k, _)| *k == kind) {
                Some(entry) => entry.1 = data,
                None => extensions.push((kind, data)),
            }
            self
        }

        pub fn without(mut self, kind: u16) -> Hello {
            self.extensions.as_mut().unwrap().retain(|(k, _)| *k != kind);
            self
        }

        pub fn bytes(&self) -> Vec<u8> {
            let mut body = self.version.clone();
            body.extend([7u8; 32]);
            body.push(u8::try_from(self.session_id.len()).unwrap());
            body.extend(&self.session_id);
            body.extend(vec16(&u16s(&self.suites)));
            body.push(u8::try_from(self.compression.len()).unwrap());
            body.extend(&self.compression);
            if let Some(extensions) = &self.extensions {
                let all: Vec<u8> = extensions.iter().flat_map(|(k, d)| [k.to_be_bytes().to_vec(), vec16(d)].concat()).collect();
                body.extend(vec16(&all));
            }
            let mut message = vec![CLIENT_HELLO];
            message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
            message.extend(body);
            message
        }
    }

    const SHARE: [u8; 32] = [5u8; 32];

    fn check(hello: &Hello) -> Result<ClientHello<'static>, Alert> {
        let bytes: &'static [u8] = Box::leak(hello.bytes().into_boxed_slice());
        client_hello(bytes)
    }

    #[test]
    fn a_modern_client_hello() {
        let parsed = check(&Hello::new("site.test", &SHARE)).unwrap();
        assert_eq!(parsed.server_name, b"site.test");
        assert_eq!(parsed.share, Some(SHARE));
        assert_eq!((parsed.shares, parsed.early, parsed.alpn), (1, false, true));
        assert_eq!(parsed.session_id, [0xab; 32]);
    }

    #[test]
    fn the_client_hello_of_rfc8448() {
        let message = trace("3", "{client}  construct a ClientHello handshake message:", 1, "ClientHello");
        let parsed = client_hello(&message).unwrap();
        assert_eq!(parsed.server_name, b"server");
        assert!(parsed.share.is_some());
        assert!(!parsed.alpn && !parsed.early);
        // In the HelloRetryRequest trace the client offers X25519 first.
        // That trace's server sent a cookie, which the second ClientHello
        // returns; we never send one, so a cookie is refused.
        let step = "{client}  construct a ClientHello handshake message:";
        let first = trace("5", step, 1, "ClientHello");
        assert!(client_hello(&first).unwrap().share.is_some());
        let second = trace("5", step, 2, "ClientHello");
        assert_eq!(client_hello(&second), Err(Alert::IllegalParameter));
    }

    #[test]
    fn what_is_refused_and_with_which_alert() {
        let ok = || Hello::new("site.test", &SHARE);
        let cases: Vec<(&str, Hello, Alert)> = vec![
            ("TLS 1.2 client: no extensions", Hello { extensions: None, ..ok() }, Alert::ProtocolVersion),
            ("no supported_versions", ok().without(SUPPORTED_VERSIONS), Alert::ProtocolVersion),
            ("only TLS 1.2", ok().set(SUPPORTED_VERSIONS, [vec![2], u16s(&[0x0303])].concat()), Alert::ProtocolVersion),
            ("compression", Hello { compression: vec![1, 0], ..ok() }, Alert::IllegalParameter),
            ("no compression method", Hello { compression: vec![], ..ok() }, Alert::DecodeError),
            ("a cookie", ok().set(COOKIE, vec16(b"c")), Alert::IllegalParameter),
            ("repeated extension", { let mut h = ok(); h.extensions.as_mut().unwrap().push((SIGNATURE_ALGORITHMS, vec16(&u16s(&[0x0403])))); h }, Alert::IllegalParameter),
            ("pre_shared_key not last", { let mut h = ok().set(PSK_KEY_EXCHANGE_MODES, vec![1, 1]); h.extensions.as_mut().unwrap().insert(0, (PRE_SHARED_KEY, vec![0, 0])); h }, Alert::IllegalParameter),
            ("pre_shared_key without modes", ok().set(PRE_SHARED_KEY, vec![0, 0]), Alert::MissingExtension),
            ("no signature_algorithms", ok().without(SIGNATURE_ALGORITHMS), Alert::MissingExtension),
            ("no supported_groups", ok().without(SUPPORTED_GROUPS), Alert::MissingExtension),
            ("no key_share", ok().without(KEY_SHARE), Alert::MissingExtension),
            ("no server_name", ok().without(SERVER_NAME), Alert::MissingExtension),
            ("no ChaCha20", Hello { suites: vec![0x1301, 0x1302], ..ok() }, Alert::HandshakeFailure),
            ("no ECDSA P-256", ok().set(SIGNATURE_ALGORITHMS, vec16(&u16s(&[0x0804, 0x0805]))), Alert::HandshakeFailure),
            ("no X25519", ok().set(SUPPORTED_GROUPS, vec16(&u16s(&[0x0017]))).set(KEY_SHARE, key_shares(&[])), Alert::HandshakeFailure),
            ("short X25519 share", ok().set(KEY_SHARE, key_shares(&[(X25519, &[1u8; 31])])), Alert::IllegalParameter),
            ("two X25519 shares", ok().set(KEY_SHARE, key_shares(&[(X25519, &SHARE), (X25519, &SHARE)])), Alert::IllegalParameter),
            ("share for a group not offered", ok().set(KEY_SHARE, key_shares(&[(X25519, &SHARE), (0x0018, &[4u8; 97])])), Alert::IllegalParameter),
            ("ALPN without http/1.1", ok().set(ALPN, alpn(&["h2"])), Alert::NoApplicationProtocol),
            ("empty ALPN name", ok().set(ALPN, alpn(&["", "http/1.1"])), Alert::DecodeError),
            ("two host names", ok().set(SERVER_NAME, vec16(&[sni("a")[2..].to_vec(), sni("b")[2..].to_vec()].concat())), Alert::IllegalParameter),
            ("empty host name", ok().set(SERVER_NAME, sni("")), Alert::DecodeError),
            ("early_data with contents", ok().set(EARLY_DATA, vec![0]), Alert::DecodeError),
            ("odd cipher suites", Hello { suites: vec![], ..ok() }, Alert::DecodeError),
            ("session id too long", Hello { session_id: vec![0; 33], ..ok() }, Alert::DecodeError),
        ];
        for (what, hello, alert) in cases {
            assert_eq!(check(&hello).err(), Some(alert), "{what}");
        }
        // Bytes after the extensions, or a length that runs past the end.
        let mut longer = ok().bytes();
        longer.push(0);
        assert_eq!(client_hello(&longer).err(), Some(Alert::DecodeError));
        for cut in 4..ok().bytes().len() {
            let mut cut_short = ok().bytes()[..cut].to_vec();
            let length = u32::try_from(cut - 4).unwrap().to_be_bytes();
            cut_short[1..4].copy_from_slice(&length[1..]);
            assert!(client_hello(&cut_short).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn what_a_client_hello_may_offer() {
        // No X25519 share: served after a HelloRetryRequest.
        let retry = check(&Hello::new("site.test", &SHARE).set(KEY_SHARE, key_shares(&[(0x0017, &[4u8; 65])]))).unwrap();
        assert_eq!((retry.share, retry.shares), (None, 1));
        let early = check(&Hello::new("site.test", &SHARE).set(EARLY_DATA, vec![])).unwrap();
        assert!(early.early);
        let no_alpn = check(&Hello::new("site.test", &SHARE).without(ALPN)).unwrap();
        assert!(!no_alpn.alpn);
        // A PSK is ignored: served with a full handshake.
        let psk = Hello::new("site.test", &SHARE).set(PSK_KEY_EXCHANGE_MODES, vec![1, 1]).set(PRE_SHARED_KEY, vec![0, 0]);
        assert!(check(&psk).is_ok());
        // Unknown extensions and a TLS 1.0 record version are fine.
        assert!(check(&Hello::new("site.test", &SHARE).set(0x7777, vec![1, 2, 3])).is_ok());
        assert!(check(&Hello { version: vec![3, 1], ..Hello::new("site.test", &SHARE) }).is_ok());
    }

    /// Mutated ClientHellos never make the parser panic, and what it
    /// accepts is always a hello we can serve.
    #[test]
    fn mutated_client_hellos() {
        let mut noise = crate::stream::testing::Noise::new(1);
        let base = Hello::new("site.test", &SHARE).set(EARLY_DATA, vec![]).bytes();
        let mut accepted = 0;
        for _ in 0..200_000 {
            let input = noise.mutate(&base);
            if let Ok(hello) = client_hello(&input) {
                accepted += 1;
                assert!(!hello.server_name.is_empty() && hello.session_id.len() <= 32);
            }
        }
        // Some mutations leave a valid hello (a changed random, say).
        assert!(accepted > 0);
    }

    /// Bug (found in review): a repeated extension was refused with
    /// illegal_parameter before the version was looked at, so a client
    /// that does not speak TLS 1.3 could be told the wrong thing.
    #[test]
    fn bug_repeated_extension_hid_the_version() {
        let mut hello = Hello::new("site.test", &SHARE).set(SUPPORTED_VERSIONS, [vec![2], u16s(&[0x0303])].concat());
        hello.extensions.as_mut().unwrap().push((0x7777, vec![]));
        hello.extensions.as_mut().unwrap().push((0x7777, vec![]));
        assert_eq!(check(&hello).err(), Some(Alert::ProtocolVersion));
    }

    /// Bug (found in review): the contents of some extensions were decoded
    /// only after other checks, so a malformed hello could get another
    /// alert than decode_error.
    #[test]
    fn bug_extension_contents_were_decoded_after_other_checks() {
        let ok = || Hello::new("site.test", &SHARE);
        for (what, hello) in [
            ("bad ALPN, no ChaCha20", Hello { suites: vec![0x1301], ..ok().set(ALPN, vec![0, 3, 0, 1, 2]) }),
            ("cookie, bad key_share", ok().set(COOKIE, vec![0, 1, 9]).set(KEY_SHARE, vec![0, 5, 0])),
            ("no server_name, bad supported_groups", ok().without(SERVER_NAME).set(SUPPORTED_GROUPS, vec![0, 3, 0, 0x1d, 0])),
        ] {
            assert_eq!(check(&hello).err(), Some(Alert::DecodeError), "{what}");
        }
    }

    /// Bug (found in review): supported_versions, signature_algorithms and
    /// supported_groups took bytes after their list.
    #[test]
    fn bug_trailing_bytes_in_list_extensions_were_accepted() {
        let ok = || Hello::new("site.test", &SHARE);
        let with_more = |mut data: Vec<u8>| {
            data.push(0);
            data
        };
        for (kind, data) in [
            (SUPPORTED_VERSIONS, with_more([vec![2], u16s(&[TLS13])].concat())),
            (SIGNATURE_ALGORITHMS, with_more(vec16(&u16s(&[ECDSA_P256_SHA256])))),
            (SUPPORTED_GROUPS, with_more(vec16(&u16s(&[X25519])))),
        ] {
            assert_eq!(check(&ok().set(kind, data)).err(), Some(Alert::DecodeError), "extension {kind}");
        }
    }

    /// Bug (found in review): a key share with no key bytes was taken for
    /// groups other than X25519; key_exchange may not be empty. It is
    /// refused with illegal_parameter (tlsfuzzer's expectation), also for a
    /// group we do not support and before we look for a group in common.
    #[test]
    fn bug_empty_key_share_was_accepted() {
        let hello = Hello::new("site.test", &SHARE).set(KEY_SHARE, key_shares(&[(0x0017, &[]), (X25519, &SHARE)]));
        assert_eq!(check(&hello).err(), Some(Alert::IllegalParameter));
        let x25519 = Hello::new("site.test", &SHARE).set(KEY_SHARE, key_shares(&[(X25519, &[])]));
        assert_eq!(check(&x25519).err(), Some(Alert::IllegalParameter));
        let ffdhe = Hello::new("site.test", &SHARE)
            .set(SUPPORTED_GROUPS, vec16(&u16s(&[0x0100])))
            .set(KEY_SHARE, key_shares(&[(0x0100, &[])]));
        assert_eq!(check(&ffdhe).err(), Some(Alert::IllegalParameter));
    }

    /// Bug (found in review): a ClientHello with legacy_version 0x0300
    /// (SSL 3.0) was served if it offered TLS 1.3 among its versions.
    #[test]
    fn bug_ssl3_legacy_version_was_served() {
        for version in [[3, 0], [2, 0], [0, 0]] {
            let hello = Hello { version: version.to_vec(), ..Hello::new("site.test", &SHARE) };
            assert_eq!(check(&hello).err(), Some(Alert::ProtocolVersion), "{version:?}");
        }
        assert!(check(&Hello { version: vec![3, 1], ..Hello::new("site.test", &SHARE) }).is_ok());
    }

    #[test]
    fn bytes_past_the_extensions_or_an_extension() {
        let bytes = Hello::new("site.test", &SHARE).bytes();
        // A byte after the extensions block, the lengths fixed up.
        let mut longer = bytes.clone();
        longer.push(0);
        let body = u32::try_from(longer.len() - 4).unwrap().to_be_bytes();
        longer[1..4].copy_from_slice(&body[1..]);
        assert_eq!(client_hello(&longer).err(), Some(Alert::DecodeError));
        // An extension whose length runs past the block.
        let mut hello = Hello::new("site.test", &SHARE);
        hello.extensions.as_mut().unwrap().push((0x7777, vec![]));
        let mut bytes = hello.bytes();
        let at = bytes.len() - 1;
        bytes[at] = 5;
        assert_eq!(client_hello(&bytes).err(), Some(Alert::DecodeError));
    }

    #[test]
    fn unknown_values_are_ignored() {
        // GREASE values (RFC 8701) in the suites, versions and groups, an
        // unknown extension, and extensions that only clients send.
        let hello = Hello { suites: vec![0x0a0a, 0x1303], ..Hello::new("site.test", &SHARE) }
            .set(SUPPORTED_VERSIONS, [vec![4], u16s(&[0x1a1a, TLS13])].concat())
            .set(SUPPORTED_GROUPS, vec16(&u16s(&[0x2a2a, X25519])))
            .set(17, vec![0, 0])
            .set(0x7a7a, vec![]);
        assert!(check(&hello).is_ok());
    }

    /// Our ServerHello and HelloRetryRequest, read back field by field.
    #[test]
    fn our_hellos_field_by_field() {
        for session_id in [&[][..], &[9][..], &[9; 32][..]] {
            for retry in [false, true] {
                let bytes = if retry { hello_retry_request(session_id) } else { server_hello(&[1; 32], session_id, &[3; 32]) };
                let mut r = Reader::new(&bytes);
                assert_eq!(r.u8(), Some(SERVER_HELLO));
                let mut body = r.vec24().unwrap();
                assert!(r.end().is_some());
                assert_eq!(body.u16(), Some(0x0303));
                let random = body.bytes(32).unwrap();
                assert_eq!(random == RETRY_RANDOM, retry);
                assert_eq!(body.vec8().unwrap().rest(), session_id);
                assert_eq!(body.u16(), Some(CHACHA20_POLY1305_SHA256));
                assert_eq!(body.u8(), Some(0));
                let mut extensions = body.vec16().unwrap();
                assert!(body.end().is_some());
                let mut seen = Vec::new();
                while !extensions.is_empty() {
                    let kind = extensions.u16().unwrap();
                    let data = extensions.vec16().unwrap().rest();
                    match kind {
                        SUPPORTED_VERSIONS => assert_eq!(data, [3, 4]),
                        KEY_SHARE if retry => assert_eq!(data, [0, 0x1d]),
                        KEY_SHARE => assert_eq!(data, [[0, 0x1d, 0, 32].as_slice(), &[3; 32]].concat()),
                        other => panic!("extension {other}"),
                    }
                    seen.push(kind);
                }
                assert_eq!(seen, [SUPPORTED_VERSIONS, KEY_SHARE]);
            }
        }
    }

    #[test]
    fn our_messages_are_well_formed() {
        let sh = server_hello(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(&sh[..4], &[SERVER_HELLO, 0, 0, u8::try_from(sh.len() - 4).unwrap()]);
        assert_eq!(&sh[4..6], &[3, 3]);
        let hrr = hello_retry_request(&[2; 32]);
        assert_eq!(&hrr[6..38], &RETRY_RANDOM);
        assert!(hrr.ends_with(&[0, 51, 0, 2, 0, 0x1d]));
        assert_eq!(&RETRY_RANDOM, &crate::crypto::sha256(b"HelloRetryRequest"));
        assert_eq!(encrypted_extensions(false), [8, 0, 0, 6, 0, 4, 0, 0, 0, 0]);
        let ee = encrypted_extensions(true);
        assert_eq!(ee, [&[8, 0, 0, 21, 0, 19, 0, 0, 0, 0, 0, 16, 0, 11, 0, 9, 8][..], b"http/1.1"].concat());
        let cert = certificate(&[vec![0x30, 1, 2], vec![0x30, 3]]);
        assert_eq!(cert, [11, 0, 0, 19, 0, 0, 0, 15, 0, 0, 3, 0x30, 1, 2, 0, 0, 0, 0, 2, 0x30, 3, 0, 0]);
        assert_eq!(key_update(false), [24, 0, 0, 1, 0]);
        assert_eq!(client_key_update(&key_update(true)), Ok(true));
        assert_eq!(client_key_update(&[24, 0, 0, 1, 2]), Err(Alert::IllegalParameter));
        assert_eq!(client_key_update(&[24, 0, 0, 2, 0, 0]), Err(Alert::DecodeError));
        assert_eq!(client_finished(&finished(&[9; 32])), Some(&[9u8; 32][..]));
        assert_eq!(client_finished(&[20, 0, 0, 1, 0]), None);
        assert_eq!(alert(Alert::CloseNotify), [1, 0]);
        assert_eq!(alert(Alert::BadRecordMac), [2, 20]);
        assert_eq!(signed_content(&[0; 32]).len(), 64 + 34 + 32);
    }
}
