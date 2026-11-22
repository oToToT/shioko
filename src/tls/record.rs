//! The record layer (RFC 8446 section 5): framing, and protection with
//! ChaCha20-Poly1305.

use super::fsm::Alert;
use super::keys::TrafficKeys;
use crate::crypto::{self, TAG_LEN};
use crate::stream::{self, Buffer, Stream};

pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;

/// The most plaintext one record may carry.
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// The most a protected record may carry: plaintext, the content type, and
/// at most 255 bytes of padding and tag together (section 5.2).
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;

/// One record as it arrived.
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub content_type: u8,
    /// The five bytes of the header, which are the additional data of a
    /// protected record.
    pub header: [u8; 5],
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The stream ended between records.
    End,
    /// The stream ended or failed inside a record.
    Cut,
    /// Nothing came in time.
    Timeout,
    /// The record is refused with this alert.
    Refused(Alert),
}

/// Waits until `n` bytes are pending.
fn need(buffer: &mut Buffer, from: &impl Stream, n: usize) -> Result<(), ReadError> {
    let had = buffer.pending().len();
    match buffer.need(from, n) {
        Ok(true) => Ok(()),
        Ok(false) if had == 0 && buffer.pending().is_empty() => Err(ReadError::End),
        Ok(false) => Err(ReadError::Cut),
        Err(error) if stream::timed_out(&error) => Err(ReadError::Timeout),
        Err(_) => Err(ReadError::Cut),
    }
}

/// Reads one record. On a timeout nothing is consumed: what was read of a
/// record stays in the buffer, and the next call goes on from there.
pub fn read(buffer: &mut Buffer, from: &impl Stream) -> Result<Record, ReadError> {
    need(buffer, from, 5)?;
    let mut header = [0u8; 5];
    for (to, from) in header.iter_mut().zip(buffer.pending()) {
        *to = *from;
    }
    // The version is ignored for all purposes (section 5.1). An unknown
    // content type is refused, which also refuses an SSL 2.0 hello and
    // other protocols (section 5, appendix D.5).
    let [content_type, _major, _minor, high, low] = header;
    if !matches!(content_type, CHANGE_CIPHER_SPEC | ALERT | HANDSHAKE | APPLICATION_DATA) {
        return Err(ReadError::Refused(Alert::UnexpectedMessage));
    }
    // Only a protected record may be longer than 2^14 bytes; records of the
    // other types are never protected.
    let length = usize::from(u16::from_be_bytes([high, low]));
    let limit = if content_type == APPLICATION_DATA { MAX_CIPHERTEXT } else { MAX_PLAINTEXT };
    if length > limit {
        return Err(ReadError::Refused(Alert::RecordOverflow));
    }
    need(buffer, from, 5 + length).map_err(|error| match error {
        ReadError::End => ReadError::Cut,
        other => other,
    })?;
    let mut whole = buffer.take_exactly(5 + length).ok_or(ReadError::Cut)?;
    let payload = whole.split_off(5);
    Ok(Record { content_type, header, payload })
}

/// A record whose payload goes as it is.
pub fn plain(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut record = vec![content_type, 3, 3];
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    record
}

/// A protected record carrying `content` of this type.
pub fn seal(keys: &TrafficKeys, sequence: u64, content_type: u8, content: &[u8]) -> Result<Vec<u8>, crypto::Error> {
    let mut inner = Vec::with_capacity(content.len() + 1);
    inner.extend_from_slice(content);
    inner.push(content_type);
    let length = inner.len().checked_add(TAG_LEN).ok_or(crypto::Error)?;
    let length = u16::try_from(length).map_err(|_| crypto::Error)?;
    let mut header = vec![APPLICATION_DATA, 3, 3];
    header.extend_from_slice(&length.to_be_bytes());
    let sealed = crypto::aead_seal(&keys.key, &keys.nonce(sequence), &header, &inner)?;
    header.extend_from_slice(&sealed);
    Ok(header)
}

/// What a protected record held.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// The inner content type and the content.
    Content(u8, Vec<u8>),
    /// It does not decrypt under these keys.
    Undecryptable,
    /// It decrypts but is not a valid record.
    Refused(Alert),
}

/// Opens a protected record: decrypts it, then strips the padding to find
/// the content type (section 5.4).
pub fn open(keys: &TrafficKeys, sequence: u64, record: &Record) -> Opened {
    let Ok(mut inner) = crypto::aead_open(&keys.key, &keys.nonce(sequence), &record.header, &record.payload) else {
        return Opened::Undecryptable;
    };
    // Padding counts towards the limit: content, type and zeros together
    // are at most 2^14 + 1 bytes (section 5.4).
    if inner.len() > MAX_PLAINTEXT + 1 {
        return Opened::Refused(Alert::RecordOverflow);
    }
    while inner.last() == Some(&0) {
        inner.pop();
    }
    let Some(content_type) = inner.pop() else {
        // All padding and no content type.
        return Opened::Refused(Alert::UnexpectedMessage);
    };
    Opened::Content(content_type, inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::testing::{Script, Step};

    fn keys() -> TrafficKeys {
        TrafficKeys::new(&[9u8; 32])
    }

    fn record_of(bytes: Vec<u8>) -> Record {
        read(&mut Buffer::new(), &Script::new(vec![Step::Data(bytes)])).unwrap()
    }

    #[test]
    fn sealed_records_open_with_the_same_keys_and_sequence_only() {
        let sealed = seal(&keys(), 7, HANDSHAKE, b"hello").unwrap();
        assert_eq!(&sealed[..3], &[APPLICATION_DATA, 3, 3]);
        let record = record_of(sealed.clone());
        assert_eq!(open(&keys(), 7, &record), Opened::Content(HANDSHAKE, b"hello".to_vec()));
        assert_eq!(open(&keys(), 8, &record), Opened::Undecryptable);
        assert_eq!(open(&TrafficKeys::new(&[8u8; 32]), 7, &record), Opened::Undecryptable);
        // The header is authenticated too.
        let mut changed = sealed;
        changed[2] = 1;
        assert_eq!(open(&keys(), 7, &record_of(changed)), Opened::Undecryptable);
    }

    /// Builds a protected record from an inner plaintext as given, padding
    /// included.
    fn sealed_inner(inner: &[u8]) -> Record {
        let length = u16::try_from(inner.len() + TAG_LEN).unwrap();
        let mut header = vec![APPLICATION_DATA, 3, 3];
        header.extend_from_slice(&length.to_be_bytes());
        let mut bytes = header.clone();
        bytes.extend(crypto::aead_seal(&keys().key, &keys().nonce(0), &header, inner).unwrap());
        record_of(bytes)
    }

    #[test]
    fn padding_is_stripped_and_content_must_have_a_type() {
        assert_eq!(open(&keys(), 0, &sealed_inner(b"ab\x17\0\0\0")), Opened::Content(23, b"ab".to_vec()));
        assert_eq!(open(&keys(), 0, &sealed_inner(b"\x16")), Opened::Content(22, vec![]));
        assert_eq!(open(&keys(), 0, &sealed_inner(b"\0\0\0")), Opened::Refused(Alert::UnexpectedMessage));
        assert_eq!(open(&keys(), 0, &sealed_inner(b"")), Opened::Refused(Alert::UnexpectedMessage));
        // At most 2^14 bytes of content and type.
        let mut most = vec![b'x'; MAX_PLAINTEXT];
        most.push(23);
        assert!(matches!(open(&keys(), 0, &sealed_inner(&most)), Opened::Content(23, _)));
        let mut over = vec![b'x'; MAX_PLAINTEXT + 1];
        over.push(23);
        assert_eq!(open(&keys(), 0, &sealed_inner(&over)), Opened::Refused(Alert::RecordOverflow));
    }

    #[test]
    fn records_are_framed_and_checked() {
        let read_all = |bytes: Vec<u8>| read(&mut Buffer::new(), &Script::new(vec![Step::Data(bytes), Step::End]));
        assert_eq!(read_all(plain(HANDSHAKE, b"abc")).unwrap().payload, b"abc");
        // The version is ignored.
        for version in [[3, 1], [3, 3], [2, 0], [4, 4], [0, 0]] {
            assert!(read_all(vec![22, version[0], version[1], 0, 1, 9]).is_ok(), "{version:?}");
        }
        assert_eq!(read_all(vec![24, 3, 3, 0, 1, 9]), Err(ReadError::Refused(Alert::UnexpectedMessage)));
        // An SSL 2.0 hello.
        assert_eq!(read_all(vec![0x80, 0x2e, 1, 3, 1]), Err(ReadError::Refused(Alert::UnexpectedMessage)));
        let mut big = vec![23, 3, 3];
        big.extend_from_slice(&u16::try_from(MAX_CIPHERTEXT + 1).unwrap().to_be_bytes());
        assert_eq!(read_all(big), Err(ReadError::Refused(Alert::RecordOverflow)));
        assert_eq!(read_all(vec![]), Err(ReadError::End));
        assert_eq!(read_all(vec![22, 3]), Err(ReadError::Cut));
        assert_eq!(read_all(vec![22, 3, 3, 0, 5, 1]), Err(ReadError::Cut));
        let stalls = Script::new(vec![Step::Data(vec![22, 3, 3, 0, 5, 1]), Step::Timeout]);
        assert_eq!(read(&mut Buffer::new(), &stalls), Err(ReadError::Timeout));
    }

    /// Bug (found in review before it ran): a read timeout in the middle
    /// of a record dropped the bytes already read, so the next read began
    /// inside the record. A tunnel reads with a timeout to notice idleness,
    /// so this would have broken any quiet WebSocket. Now nothing is lost.
    #[test]
    fn bug_timeout_inside_a_record_lost_its_bytes() {
        let bytes = plain(HANDSHAKE, b"hello");
        for cut in 1..bytes.len() {
            let stream = Script::new(vec![Step::Data(bytes[..cut].to_vec()), Step::Timeout, Step::Data(bytes[cut..].to_vec())]);
            let mut buffer = Buffer::new();
            assert_eq!(read(&mut buffer, &stream), Err(ReadError::Timeout), "cut at {cut}");
            assert_eq!(read(&mut buffer, &stream).unwrap().payload, b"hello", "cut at {cut}");
        }
    }

    /// Mutated records never make reading or opening panic.
    #[test]
    fn mutated_records() {
        let mut noise = crate::stream::testing::Noise::new(2);
        let mut base = plain(HANDSHAKE, b"some handshake bytes");
        base.extend(seal(&keys(), 0, APPLICATION_DATA, b"some data").unwrap());
        for _ in 0..100_000 {
            let input = noise.mutate(&base);
            let stream = Script::new(vec![Step::Data(input), Step::End]);
            let mut buffer = Buffer::new();
            while let Ok(record) = read(&mut buffer, &stream) {
                let _ = open(&keys(), 0, &record);
            }
        }
    }

    /// Bug (found in review): an unknown record type got decode_error; the
    /// RFC asks for unexpected_message (section 5).
    #[test]
    fn bug_unknown_record_type_got_decode_error() {
        let stream = Script::new(vec![Step::Data(vec![99, 3, 3, 0, 1, 0]), Step::End]);
        assert_eq!(read(&mut Buffer::new(), &stream), Err(ReadError::Refused(Alert::UnexpectedMessage)));
    }

    /// Bug (found in review): a record whose version did not start with 3
    /// was refused, though the version is to be ignored (section 5.1).
    #[test]
    fn bug_record_version_was_not_ignored() {
        for version in [[2, 0], [4, 0], [0xff, 0xff]] {
            let stream = Script::new(vec![Step::Data(vec![22, version[0], version[1], 0, 1, 7]), Step::End]);
            assert_eq!(read(&mut Buffer::new(), &stream).unwrap().payload, [7], "{version:?}");
        }
    }

    /// Bug (found in review): an unprotected record of more than 2^14
    /// bytes was taken, as the limit for protected ones applied to all.
    #[test]
    fn bug_unprotected_record_could_exceed_2_14() {
        for content_type in [HANDSHAKE, ALERT, CHANGE_CIPHER_SPEC] {
            let mut bytes = vec![content_type, 3, 3];
            bytes.extend_from_slice(&u16::try_from(MAX_PLAINTEXT + 1).unwrap().to_be_bytes());
            bytes.extend(vec![0u8; MAX_PLAINTEXT + 1]);
            let stream = Script::new(vec![Step::Data(bytes), Step::End]);
            assert_eq!(read(&mut Buffer::new(), &stream), Err(ReadError::Refused(Alert::RecordOverflow)));
        }
        let mut bytes = vec![HANDSHAKE, 3, 3];
        bytes.extend_from_slice(&u16::try_from(MAX_PLAINTEXT).unwrap().to_be_bytes());
        bytes.extend(vec![0u8; MAX_PLAINTEXT]);
        assert!(read(&mut Buffer::new(), &Script::new(vec![Step::Data(bytes)])).is_ok());
    }

    /// Bug (found in review): padding did not count towards the size
    /// limit, so up to 2^14 + 240 bytes of inner plaintext were taken.
    #[test]
    fn bug_padding_did_not_count_towards_the_limit() {
        let mut inner = vec![b'x'; MAX_PLAINTEXT];
        inner.push(23);
        inner.push(0);
        assert_eq!(open(&keys(), 0, &sealed_inner(&inner)), Opened::Refused(Alert::RecordOverflow));
    }

    /// A sealed record is the header, the content, its type and the tag:
    /// we send no padding.
    #[test]
    fn our_records_have_no_padding() {
        let sealed = seal(&keys(), 0, APPLICATION_DATA, b"12345").unwrap();
        assert_eq!(sealed.len(), 5 + 5 + 1 + TAG_LEN);
        assert_eq!(&sealed[3..5], &[0, 5 + 1 + 16]);
        let plain = crypto::aead_open(&keys().key, &keys().nonce(0), &sealed[..5], &sealed[5..]).unwrap();
        assert_eq!(plain, b"12345\x17");
    }

    #[test]
    fn records_arrive_whole_however_the_reads_fall() {
        let mut bytes = plain(HANDSHAKE, b"first");
        bytes.extend(seal(&keys(), 0, APPLICATION_DATA, b"second").unwrap());
        for cut in 1..bytes.len() {
            let stream = Script::new(vec![Step::Data(bytes[..cut].to_vec()), Step::Data(bytes[cut..].to_vec()), Step::End]);
            let mut buffer = Buffer::new();
            assert_eq!(read(&mut buffer, &stream).unwrap().payload, b"first");
            let second = read(&mut buffer, &stream).unwrap();
            assert_eq!(open(&keys(), 0, &second), Opened::Content(APPLICATION_DATA, b"second".to_vec()));
            assert_eq!(read(&mut buffer, &stream), Err(ReadError::End));
        }
    }
}
