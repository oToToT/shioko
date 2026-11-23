//! Reading the certificate chain and the private key of a site from PEM
//! files: base64, PEM blocks, and just enough DER to find the P-256 private
//! key. Certificates are not parsed; they are sent as they are.

/// Decodes standard base64 (RFC 4648), padding required. Line breaks and
/// other whitespace between characters are ignored.
pub fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut quad = [0u8; 4];
    let mut filled = 0usize;
    let mut padding = 0usize;
    for byte in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 0,
            _ => return None,
        };
        // Nothing but padding may follow padding.
        if byte == b'=' {
            padding += 1;
        } else if padding > 0 {
            return None;
        }
        *quad.get_mut(filled)? = value;
        filled += 1;
        if filled == 4 {
            let [a, b, c, d] = quad;
            out.extend_from_slice(&[a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d]);
            out.truncate(out.len().checked_sub(padding)?);
            filled = 0;
        }
    }
    (filled == 0 && padding <= 2).then_some(out)
}

/// The decoded contents of every PEM block with this label, in order.
pub fn blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once(&begin) {
        let (body, next) = after.split_once(&end).ok_or(format!("a {label} block has no end"))?;
        found.push(base64(body).ok_or(format!("a {label} block is not valid base64"))?);
        rest = next;
    }
    Ok(found)
}

/// One DER element: its tag and its contents.
fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let (digits, rest) = rest.split_at_checked(count)?;
        let length = digits.iter().fold(0usize, |n, &d| n << 8 | usize::from(d));
        (length, rest)
    };
    let (contents, rest) = rest.split_at_checked(length)?;
    Some((tag, contents, rest))
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OBJECT: u8 = 0x06;
/// The object identifiers id-ecPublicKey and prime256v1 (RFC 5480).
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The private scalar of an ECPrivateKey (SEC1, RFC 5915). If it names its
/// curve, the curve must be P-256.
fn sec1(der: &[u8]) -> Result<[u8; 32], String> {
    let bad = || "the key is not an EC private key".to_string();
    let Some((SEQUENCE, body, [])) = element(der) else { return Err(bad()) };
    let Some((INTEGER, [1], body)) = element(body) else { return Err(bad()) };
    let Some((OCTET_STRING, scalar, mut rest)) = element(body) else { return Err(bad()) };
    while !rest.is_empty() {
        let (tag, contents, after) = element(rest).ok_or_else(bad)?;
        // [0] parameters: the curve.
        if tag == 0xa0 {
            let Some((OBJECT, oid, [])) = element(contents) else { return Err(bad()) };
            if oid != P256 {
                return Err("the key is not on the P-256 curve".into());
            }
        }
        rest = after;
    }
    scalar.try_into().map_err(|_| "the key is not on the P-256 curve".to_string())
}

/// The private scalar of a PrivateKeyInfo (PKCS#8, RFC 5208) holding a
/// P-256 key.
fn pkcs8(der: &[u8]) -> Result<[u8; 32], String> {
    let bad = || "the key is not a PKCS#8 private key".to_string();
    let Some((SEQUENCE, body, [])) = element(der) else { return Err(bad()) };
    let Some((INTEGER, [0], body)) = element(body) else { return Err(bad()) };
    let Some((SEQUENCE, algorithm, body)) = element(body) else { return Err(bad()) };
    let Some((OBJECT, kind, parameters)) = element(algorithm) else { return Err(bad()) };
    if kind != EC_PUBLIC_KEY {
        return Err("the key is not an EC key (only ECDSA P-256 keys are supported)".into());
    }
    let Some((OBJECT, curve, [])) = element(parameters) else { return Err(bad()) };
    if curve != P256 {
        return Err("the key is not on the P-256 curve".into());
    }
    let Some((OCTET_STRING, inner, _attributes)) = element(body) else { return Err(bad()) };
    sec1(inner)
}

/// The P-256 private scalar of a PEM key file, in either form.
pub fn private_key(text: &str) -> Result<[u8; 32], String> {
    if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err("the key is encrypted".into());
    }
    match (blocks(text, "PRIVATE KEY")?.as_slice(), blocks(text, "EC PRIVATE KEY")?.as_slice()) {
        ([der], []) => pkcs8(der),
        ([], [der]) => sec1(der),
        ([], []) => Err("no private key found".into()),
        _ => Err("more than one private key found".into()),
    }
}

/// The certificates of a PEM chain file, leaf first, as DER.
pub fn certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let chain = blocks(text, "CERTIFICATE")?;
    if chain.is_empty() { Err("no certificate found".into()) } else { Ok(chain) }
}

/// Input lengths of the proofs: CI's, and `tools/prove.sh big`'s.
#[cfg(kani)]
const PROVED: usize = if cfg!(feature = "kani-big") { 16 } else { 8 };

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Reading a DER element never panics, and what it gives back lies
    /// within the input.
    #[kani::proof]
    #[cfg_attr(not(feature = "kani-big"), kani::unwind(10))]
    #[cfg_attr(feature = "kani-big", kani::unwind(18))]
    fn der_element_is_sound() {
        let bytes: [u8; PROVED] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= PROVED);
        if let Some((_, contents, rest)) = element(&bytes[..len]) {
            assert!(contents.len() + rest.len() + 2 <= len);
        }
    }
}

#[cfg(kani)]
mod base64_proofs {
    use super::*;

    /// Base64 of any eight (sixteen) bytes of text decodes without
    /// panicking, and to at most three bytes for every four characters.
    #[kani::proof]
    #[cfg_attr(not(feature = "kani-big"), kani::unwind(10))]
    #[cfg_attr(feature = "kani-big", kani::unwind(18))]
    fn base64_is_sound() {
        let bytes: [u8; PROVED] = kani::any();
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if let Some(decoded) = base64(text) {
                assert!(decoded.len() <= PROVED / 4 * 3);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/certs/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn base64_rfc4648() {
        for (text, plain) in [("", ""), ("Zg==", "f"), ("Zm8=", "fo"), ("Zm9v", "foo"), ("Zm9vYg==", "foob"), ("Zm9vYmE=", "fooba"), ("Zm9vYmFy", "foobar")] {
            assert_eq!(base64(text).unwrap(), plain.as_bytes(), "{text}");
        }
        assert_eq!(base64("Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        for bad in ["Zg", "Zg=", "Z===", "Zm9v!", "Zg==Zg==", "Z=g=", "===="] {
            assert_eq!(base64(bad), None, "{bad}");
        }
    }

    #[test]
    fn chains_come_leaf_first() {
        let chain = certificates(&file("site.test.chain.pem")).unwrap();
        assert_eq!(chain.len(), 2);
        let ca = certificates(&file("ca.pem")).unwrap();
        assert_eq!(chain[1], ca[0]);
        assert!(chain.iter().all(|der| der[0] == 0x30));
        assert_eq!(certificates("nothing here"), Err("no certificate found".into()));
        assert!(certificates("-----BEGIN CERTIFICATE-----\nZg==\n").is_err());
    }

    #[test]
    fn both_key_forms_are_read() {
        assert!(private_key(&file("site.test.key")).is_ok());
        assert!(private_key(&file("tls.test.key")).is_ok());
        // The CA key is a P-256 key too.
        assert!(private_key(&file("ca.key")).is_ok());
    }

    #[test]
    fn keys_we_cannot_use_are_refused() {
        assert_eq!(private_key(&file("rsa.key")), Err("the key is not an EC key (only ECDSA P-256 keys are supported)".into()));
        assert_eq!(private_key(&file("p384.key")), Err("the key is not on the P-256 curve".into()));
        assert_eq!(private_key(&file("encrypted.key")), Err("the key is encrypted".into()));
        assert_eq!(private_key(&file("site.test.chain.pem")), Err("no private key found".into()));
        let two = format!("{}{}", file("site.test.key"), file("site.test.key"));
        assert_eq!(private_key(&two), Err("more than one private key found".into()));
    }

    /// Mutated key files never make the reader panic.
    #[test]
    fn mutated_keys() {
        let mut noise = crate::stream::testing::Noise::new(4);
        for name in ["site.test.key", "tls.test.key"] {
            let text = file(name);
            let der = blocks(&text, if name.starts_with("tls") { "EC PRIVATE KEY" } else { "PRIVATE KEY" }).unwrap().remove(0);
            for _ in 0..50_000 {
                let mutated = noise.mutate(&der);
                let _ = (pkcs8(&mutated), sec1(&mutated));
                let _ = private_key(&String::from_utf8_lossy(&noise.mutate(text.as_bytes())));
            }
        }
    }

    #[test]
    fn der_lengths() {
        assert_eq!(element(&[0x04, 0x02, 1, 2, 9]), Some((0x04, &[1u8, 2][..], &[9u8][..])));
        assert_eq!(element(&[0x04, 0x81, 0x01, 7]), Some((0x04, &[7u8][..], &[][..])));
        assert_eq!(element(&[0x04, 0x82, 0x00, 0x01, 7]), Some((0x04, &[7u8][..], &[][..])));
        assert_eq!(element(&[0x04, 0x03, 1, 2]), None);
        assert_eq!(element(&[0x04, 0x80]), None);
        assert_eq!(element(&[0x04, 0x85, 0, 0, 0, 0, 1]), None);
        assert_eq!(element(&[0x04]), None);
    }
}
