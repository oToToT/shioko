//! Cryptographic primitives. This is the only module that uses libcrux.
//!
//! SHA-256, ChaCha20-Poly1305, X25519 and P-256 ECDSA come from libcrux
//! (Rust compiled from the formally verified HACL* library). HMAC and HKDF
//! are written here on top of the verified SHA-256, to avoid the extra
//! dependencies the libcrux versions bring in.

use libcrux_sha2::Digest;
use std::io::Read;

pub const HASH_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// SHA-256 block size in bytes.
const BLOCK_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub struct Error;

/// Fill `buf` from the kernel's random number generator.
pub fn random(buf: &mut [u8]) -> Result<(), Error> {
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).map_err(|_| Error)
}

/// Compare two byte strings without an early exit on the first difference.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    a.len() == b.len() && std::hint::black_box(diff) == 0
}

// ---------------------------------------------------------------- SHA-256

pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    libcrux_sha2::sha256(data)
}

/// Incremental SHA-256. `finish` does not consume the state, so a running
/// transcript hash can be read at any point and then extended.
#[derive(Clone)]
pub struct Sha256(libcrux_sha2::Sha256);

impl Sha256 {
    pub fn new() -> Self {
        Sha256(libcrux_sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(&self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        self.0.finish(&mut out);
        out
    }
}

// ------------------------------------------------------- HMAC (RFC 2104)

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block.iter_mut().zip(sha256(key)).for_each(|(b, k)| *b = k);
    } else {
        block.iter_mut().zip(key).for_each(|(b, k)| *b = *k);
    }

    let mut inner = Sha256::new();
    inner.update(&block.map(|b| b ^ 0x36));
    parts.iter().for_each(|part| inner.update(part));

    let mut outer = Sha256::new();
    outer.update(&block.map(|b| b ^ 0x5c));
    outer.update(&inner.finish());
    outer.finish()
}

// ------------------------------------------------------- HKDF (RFC 5869)

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    hmac_sha256(salt, &[ikm])
}

/// Fill `out` with output keying material. Fails if `out` is longer than
/// RFC 5869 allows (255 hash lengths).
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() > 255 * HASH_LEN {
        return Err(Error);
    }
    let mut previous: &[u8] = &[];
    let mut block;
    for (counter, chunk) in (1u8..=255).zip(out.chunks_mut(HASH_LEN)) {
        block = hmac_sha256(prk, &[previous, info, &[counter]]);
        chunk.iter_mut().zip(block).for_each(|(o, b)| *o = b);
        previous = &block;
    }
    Ok(())
}

// --------------------------------------------- ChaCha20-Poly1305 (RFC 8439)

/// Encrypt `plaintext`; returns ciphertext followed by the 16-byte tag.
pub fn aead_seal(
    key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; plaintext.len().checked_add(TAG_LEN).ok_or(Error)?];
    libcrux_chacha20poly1305::encrypt(key, plaintext, &mut out, aad, nonce).map_err(|_| Error)?;
    Ok(out)
}

/// Verify and decrypt `ciphertext` (ciphertext followed by the tag).
pub fn aead_open(
    key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; ciphertext.len().checked_sub(TAG_LEN).ok_or(Error)?];
    libcrux_chacha20poly1305::decrypt(key, &mut out, ciphertext, aad, nonce).map_err(|_| Error)?;
    Ok(out)
}

// ------------------------------------------------------- X25519 (RFC 7748)

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let mut public = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public, secret);
    public
}

/// Diffie-Hellman. Fails if the result is all zero (a low-order peer key).
pub fn x25519(secret: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut shared = [0u8; 32];
    libcrux_curve25519::ecdh(&mut shared, peer_public, secret).map_err(|_| Error)?;
    Ok(shared)
}

// ------------------------------------------------- ECDSA P-256 with SHA-256

pub struct SigningKey(libcrux_ecdsa::p256::PrivateKey);

impl SigningKey {
    /// Fails unless 0 < scalar < the order of the curve.
    pub fn from_bytes(scalar: &[u8; 32]) -> Result<Self, Error> {
        libcrux_ecdsa::p256::PrivateKey::try_from(scalar).map(SigningKey).map_err(|_| Error)
    }

    /// The public key as an uncompressed point: 0x04, X, Y.
    pub fn public_key(&self) -> Result<[u8; 65], Error> {
        let point = self.0.public_key().map_err(|_| Error)?;
        let mut out = [0x04u8; 65];
        out.iter_mut().skip(1).zip(point.0).for_each(|(o, p)| *o = p);
        Ok(out)
    }

    /// Sign `message` with a fresh random nonce; returns the DER signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // A random 32-byte value is a valid nonce except with probability
        // about 2^-32; rejecting and retrying keeps the nonce uniform.
        for _ in 0..8 {
            let mut nonce = [0u8; 32];
            random(&mut nonce)?;
            if let Some(raw) = self.sign_with_nonce(message, &nonce) {
                let signature = libcrux_ecdsa::p256::Signature::from_bytes(raw);
                return Ok(signature.to_der().as_bytes().to_vec());
            }
        }
        Err(Error)
    }

    /// Raw signature (r followed by s), or `None` if the nonce is out of range.
    fn sign_with_nonce(&self, message: &[u8], nonce: &[u8; 32]) -> Option<[u8; 64]> {
        let len = u32::try_from(message.len()).ok()?;
        let key: &[u8; 32] = self.0.as_ref();
        let mut raw = [0u8; 64];
        libcrux_p256::ecdsa_sign_p256_sha2(&mut raw, len, message, key, nonce).then_some(raw)
    }
}

/// Checks a DER ECDSA P-256 signature over `message`. Only tests need it:
/// a server never verifies a signature.
#[cfg(test)]
pub fn verify(public: &[u8; 65], message: &[u8], der: &[u8]) -> bool {
    use libcrux_ecdsa::p256::{PublicKey, Signature};
    let (Some(point), Ok(signature)) = (public.get(1..), Signature::from_der(der)) else {
        return false;
    };
    let Ok(public) = PublicKey::try_from(point) else {
        return false;
    };
    libcrux_ecdsa::p256::verify(libcrux_sha2::Algorithm::Sha256, message, &signature, &public).is_ok()
}

// Proofs, checked by Kani (tools/prove.sh). Each holds for every input
// within the stated bounds, not just for the ones a test happens to try.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `ct_eq` gives the same answer as `==`, for all byte strings of up to
    /// four bytes each.
    #[kani::proof]
    #[kani::unwind(6)]
    fn ct_eq_is_equality() {
        let a: [u8; 4] = kani::any();
        let b: [u8; 4] = kani::any();
        let (a_len, b_len): (usize, usize) = kani::any();
        kani::assume(a_len <= 4 && b_len <= 4);
        let (a, b) = (&a[..a_len], &b[..b_len]);
        assert_eq!(ct_eq(a, b), a == b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(s.len().is_multiple_of(2), "odd hex length");
        s.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    /// Wycheproof vectors converted by tools/wycheproof.py: one test per
    /// line, `name id result key=hex ...`.
    fn vectors(file: &str) -> Vec<(String, bool, std::collections::HashMap<String, Vec<u8>>)> {
        let path = format!("{}/tests/vectors/{file}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(path).unwrap();
        text.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|line| {
                let mut words = line.split(' ');
                let id = words.next().unwrap().to_string();
                let valid = match words.next().unwrap() {
                    "valid" => true,
                    "invalid" => false,
                    other => panic!("unexpected result {other}"),
                };
                let fields = words
                    .map(|w| {
                        let (k, v) = w.split_once('=').unwrap();
                        (k.to_string(), hex(v))
                    })
                    .collect();
                (id, valid, fields)
            })
            .collect()
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn sha256_incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 128, 999, 1000] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            let early = h.finish();
            assert_eq!(early, sha256(&data[..split]));
            let mut fork = h.clone();
            h.update(&data[split..]);
            assert_eq!(h.finish(), sha256(&data));
            fork.update(b"x");
            assert_ne!(fork.finish(), h.finish());
        }
    }

    #[test]
    fn hmac_rfc4231() {
        // Test cases 1, 2, 3, 4, 6 and 7.
        let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger \
                  than block-size data. The key needs to be hashed before being \
                  used by the HMAC algorithm."
                    .to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, data, want) in cases {
            assert_eq!(hmac_sha256(&key, &[&data]).to_vec(), hex(want));
            // Splitting the message across parts must not change the result.
            let (a, b) = data.split_at(data.len() / 2);
            assert_eq!(hmac_sha256(&key, &[a, b]).to_vec(), hex(want));
        }
    }

    #[test]
    fn hkdf_rfc5869() {
        // Test cases 1, 2 and 3: (ikm, salt, info, prk, okm).
        let cases = [
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                 404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                 d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (ikm, salt, info, prk, okm) in cases {
            let got_prk = hkdf_extract(&hex(salt), &hex(ikm));
            assert_eq!(got_prk.to_vec(), hex(prk));
            let mut got_okm = vec![0u8; hex(okm).len()];
            hkdf_expand(&got_prk, &hex(info), &mut got_okm).unwrap();
            assert_eq!(got_okm, hex(okm));
        }
    }

    #[test]
    fn hkdf_expand_length_limits() {
        let prk = [7u8; 32];
        let mut max = vec![0u8; 255 * 32];
        assert!(hkdf_expand(&prk, b"", &mut max).is_ok());
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert_eq!(hkdf_expand(&prk, b"", &mut too_long), Err(Error));
        // A shorter output is a prefix of a longer one.
        let mut short = [0u8; 40];
        hkdf_expand(&prk, b"", &mut short).unwrap();
        assert_eq!(short[..], max[..40]);
        assert!(hkdf_expand(&prk, b"", &mut []).is_ok());
    }

    #[test]
    fn aead_rfc8439() {
        let key = arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = arr("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";
        let want = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116\
             1ae10b594f09e26a7e902ecbd0600691",
        );
        let sealed = aead_seal(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(sealed, want);
        assert_eq!(aead_open(&key, &nonce, &aad, &sealed).unwrap(), plaintext);

        // Any single flipped bit, in the ciphertext, tag or AAD, must fail.
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(aead_open(&key, &nonce, &aad, &bad), Err(Error));
        }
        assert_eq!(aead_open(&key, &nonce, b"other", &sealed), Err(Error));
        assert_eq!(aead_open(&key, &nonce, &aad, &sealed[..15]), Err(Error));
        assert_eq!(aead_open(&key, &nonce, &aad, &[]), Err(Error));
    }

    #[test]
    fn x25519_rfc7748() {
        // Section 5.2 test vectors.
        let out = x25519(
            &arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            &arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        );
        assert_eq!(
            out.unwrap().to_vec(),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        let out = x25519(
            &arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            &arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        );
        assert_eq!(
            out.unwrap().to_vec(),
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );

        // Section 6.1 Diffie-Hellman example.
        let a = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519_public(&a);
        let b_pub = x25519_public(&b);
        assert_eq!(
            a_pub.to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b_pub.to_vec(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &b_pub).unwrap().to_vec(), shared);
        assert_eq!(x25519(&b, &a_pub).unwrap().to_vec(), shared);

        // A low-order peer key gives an all-zero secret and must be refused.
        assert_eq!(x25519(&a, &[0u8; 32]), Err(Error));
    }

    // RFC 6979 appendix A.2.5: P-256 key pair and the SHA-256 signature of
    // "sample" with its deterministic nonce.
    const RFC6979_KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const RFC6979_PUB: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                               7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    #[test]
    fn ecdsa_rfc6979_known_answer() {
        let key = SigningKey::from_bytes(&arr(RFC6979_KEY)).unwrap();
        let public = key.public_key().unwrap();
        assert_eq!(public[0], 0x04);
        assert_eq!(public[1..].to_vec(), hex(RFC6979_PUB));

        let nonce = arr("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
        let raw = key.sign_with_nonce(b"sample", &nonce).unwrap();
        assert_eq!(
            raw.to_vec(),
            hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                 f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
        );
    }

    #[test]
    fn ecdsa_sign_verifies_and_is_randomised() {
        use libcrux_ecdsa::p256::{PublicKey, Signature, verify};
        let key = SigningKey::from_bytes(&arr(RFC6979_KEY)).unwrap();
        let public = PublicKey::try_from(&key.public_key().unwrap()[1..]).unwrap();
        let message = b"TLS 1.3, server CertificateVerify";

        let first = key.sign(message).unwrap();
        let second = key.sign(message).unwrap();
        assert_ne!(first, second, "two signatures used the same nonce");
        for der in [&first, &second] {
            assert_eq!(der[0], 0x30, "not a DER SEQUENCE");
            let signature = Signature::from_der(der).unwrap();
            let hash = libcrux_sha2::Algorithm::Sha256;
            assert!(verify(hash, message, &signature, &public).is_ok());
            assert!(verify(hash, b"another message", &signature, &public).is_err());
        }
    }

    #[test]
    fn ecdsa_rejects_out_of_range_scalars() {
        // The order of the P-256 group.
        let n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        assert!(SigningKey::from_bytes(&[0u8; 32]).is_err());
        assert!(SigningKey::from_bytes(&arr(n)).is_err());
        assert!(SigningKey::from_bytes(&[0xff; 32]).is_err());

        let key = SigningKey::from_bytes(&arr(RFC6979_KEY)).unwrap();
        assert!(key.sign_with_nonce(b"m", &[0u8; 32]).is_none());
        assert!(key.sign_with_nonce(b"m", &arr(n)).is_none());
    }

    #[test]
    fn ct_eq_behaviour() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"\x00", b"\x80"));
    }

    #[test]
    fn random_fills_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random(&mut a).unwrap();
        random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn wycheproof_hmac_sha256() {
        let tests = vectors("hmac_sha256.txt");
        assert!(tests.len() > 100);
        for (id, valid, f) in tests {
            let mac = hmac_sha256(&f["key"], &[&f["msg"]]);
            // Wycheproof includes truncated tags; compare the prefix.
            let tag = &f["tag"];
            assert_eq!(ct_eq(&mac[..tag.len()], tag), valid, "{id}");
        }
    }

    #[test]
    fn wycheproof_hkdf_sha256() {
        let tests = vectors("hkdf_sha256.txt");
        assert!(tests.len() > 50);
        for (id, valid, f) in tests {
            let prk = hkdf_extract(&f["salt"], &f["ikm"]);
            let mut okm = vec![0u8; f["size"].iter().fold(0usize, |n, b| n << 8 | *b as usize)];
            let result = hkdf_expand(&prk, &f["info"], &mut okm);
            assert_eq!(result.is_ok(), valid, "{id}");
            if valid {
                assert_eq!(okm, f["okm"], "{id}");
            }
        }
    }

    #[test]
    fn wycheproof_chacha20_poly1305() {
        let tests = vectors("chacha20_poly1305.txt");
        assert!(tests.len() > 200);
        for (id, valid, f) in tests {
            let (Ok(key), Ok(nonce)) = (f["key"].as_slice().try_into(), f["iv"].as_slice().try_into())
            else {
                // Wrong key or nonce sizes cannot be expressed in our API.
                assert!(!valid, "{id}");
                continue;
            };
            let sealed = [f["ct"].as_slice(), f["tag"].as_slice()].concat();
            let opened = aead_open(key, nonce, &f["aad"], &sealed);
            assert_eq!(opened.is_ok(), valid, "{id}");
            if valid {
                assert_eq!(opened.unwrap(), f["msg"], "{id}");
                assert_eq!(aead_seal(key, nonce, &f["aad"], &f["msg"]).unwrap(), sealed, "{id}");
            }
        }
    }

    #[test]
    fn wycheproof_x25519() {
        let tests = vectors("x25519.txt");
        assert!(tests.len() > 400);
        for (id, _valid, f) in tests {
            let secret: [u8; 32] = f["private"].as_slice().try_into().unwrap();
            let public: [u8; 32] = f["public"].as_slice().try_into().unwrap();
            // Every vector has a defined shared secret; the only ones we must
            // refuse are those where it is all zero.
            let zero = f["shared"].iter().all(|b| *b == 0);
            match x25519(&secret, &public) {
                Ok(shared) => {
                    assert!(!zero, "{id}");
                    assert_eq!(shared.to_vec(), f["shared"], "{id}");
                }
                Err(Error) => assert!(zero, "{id}"),
            }
        }
    }
}
