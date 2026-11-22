//! Copying message bodies from one stream to another.
//!
//! A body is copied through the `Buffer` of the stream it comes from, so
//! that bytes already read behind the head are used first and bytes behind
//! the body are left for whoever reads next.

use super::parse::{self, FieldsError, HEAD_LIMIT};
use crate::stream::{self, Buffer, LineError, Stream};

/// The longest chunk-size line we read, extensions included.
const CHUNK_LINE_LIMIT: usize = 4096;
/// How much is copied at a time.
const COPY_SIZE: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum CopyError {
    /// The source ended early or failed.
    Source,
    /// The source sent nothing in time.
    SourceTimeout,
    /// The body is not what its framing says.
    Malformed,
    /// The body is larger than allowed.
    TooLarge,
    /// Writing failed.
    Sink,
}

fn source_failed(buffer: &Buffer) -> CopyError {
    if buffer.timed_out() { CopyError::SourceTimeout } else { CopyError::Source }
}

/// `Buffer::read`, failing as a copy fails. `Ok(0)` is the end of the source.
fn read(buffer: &mut Buffer, from: &impl Stream, space: &mut [u8]) -> Result<usize, CopyError> {
    buffer.read(from, space).map_err(|error| {
        if stream::timed_out(&error) { CopyError::SourceTimeout } else { CopyError::Source }
    })
}

fn write(to: &impl Stream, bytes: &[u8]) -> Result<(), CopyError> {
    to.write_all(bytes).map_err(|_| CopyError::Sink)
}

/// Copies exactly `length` bytes.
pub fn copy_length(
    buffer: &mut Buffer,
    from: &impl Stream,
    to: &impl Stream,
    mut length: u64,
) -> Result<(), CopyError> {
    let mut space = vec![0u8; COPY_SIZE];
    while length > 0 {
        let want = usize::try_from(length).unwrap_or(COPY_SIZE).min(COPY_SIZE);
        let piece = space.get_mut(..want).unwrap_or(&mut []);
        let n = read(buffer, from, piece)?;
        if n == 0 {
            return Err(CopyError::Source);
        }
        write(to, piece.get(..n).unwrap_or(&[]))?;
        length = length.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok(())
}

fn line(buffer: &mut Buffer, from: &impl Stream, limit: usize) -> Result<Vec<u8>, CopyError> {
    buffer.line(from, limit).map_err(|error| match error {
        LineError::End | LineError::Cut => source_failed(buffer),
        LineError::TooLong | LineError::Bare => CopyError::Malformed,
    })
}

/// Copies a chunked body of at most `limit` bytes. With `rechunk` the body
/// is written chunked again, otherwise as plain bytes. Chunk extensions are
/// ignored and trailers are read and dropped.
///
/// The end of the body is written only once the source's own end has been
/// read, so a body that is cut short is never passed on as complete.
pub fn copy_chunked(
    buffer: &mut Buffer,
    from: &impl Stream,
    to: &impl Stream,
    limit: u64,
    rechunk: bool,
) -> Result<(), CopyError> {
    let mut total = 0u64;
    loop {
        let size_line = line(buffer, from, CHUNK_LINE_LIMIT)?;
        let size = parse::chunk_size(&size_line).ok_or(CopyError::Malformed)?;
        if size == 0 {
            parse::read_fields(buffer, from, HEAD_LIMIT).map_err(|error| match error {
                FieldsError::Gone => source_failed(buffer),
                _ => CopyError::Malformed,
            })?;
            return if rechunk { write(to, b"0\r\n\r\n") } else { Ok(()) };
        }
        total = total.checked_add(size).filter(|&total| total <= limit).ok_or(CopyError::TooLarge)?;
        if rechunk {
            write(to, format!("{size:x}\r\n").as_bytes())?;
        }
        copy_length(buffer, from, to, size)?;
        if !line(buffer, from, 0)?.is_empty() {
            return Err(CopyError::Malformed);
        }
        if rechunk {
            write(to, b"\r\n")?;
        }
    }
}

/// Copies until the source closes. With `rechunk` the bytes are written as
/// chunks, and the end is marked only when the source closed by itself.
pub fn copy_to_end(
    buffer: &mut Buffer,
    from: &impl Stream,
    to: &impl Stream,
    rechunk: bool,
) -> Result<(), CopyError> {
    let mut space = vec![0u8; COPY_SIZE];
    loop {
        let n = read(buffer, from, &mut space)?;
        let piece = space.get(..n).unwrap_or(&[]);
        if !rechunk {
            write(to, piece)?;
        } else if n == 0 {
            write(to, b"0\r\n\r\n")?;
        } else {
            write(to, format!("{n:x}\r\n").as_bytes())?;
            write(to, piece)?;
            write(to, b"\r\n")?;
        }
        if n == 0 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::testing::{Script, Step};

    /// Feeds `text` to the copy split at every position in turn, and checks
    /// the result is the same each time.
    fn every_split(
        text: &[u8],
        copy: impl Fn(&mut Buffer, &Script, &Script) -> Result<(), CopyError>,
    ) -> (Result<(), CopyError>, Vec<u8>, Vec<u8>) {
        let mut outcome = None;
        for cut in 0..=text.len() {
            let from = Script::new(vec![
                Step::Data(text[..cut].to_vec()),
                Step::Data(text[cut..].to_vec()),
                Step::End,
            ]);
            let to = Script::default();
            let mut buffer = Buffer::new();
            let result = copy(&mut buffer, &from, &to);
            let mut rest = buffer.take();
            let mut space = [0u8; 64];
            while let Ok(n) = from.read(&mut space)
                && n > 0
            {
                rest.extend_from_slice(&space[..n]);
            }
            let this = (result, to.written(), rest);
            if let Some(previous) = &outcome {
                assert_eq!(previous, &this, "cut at {cut}");
            }
            outcome = Some(this);
        }
        outcome.unwrap()
    }

    #[test]
    fn a_length_is_copied_exactly_and_the_rest_left_alone() {
        let (result, written, rest) =
            every_split(b"12345NEXT", |b, from, to| copy_length(b, from, to, 5));
        assert_eq!((result, written.as_slice(), rest.as_slice()), (Ok(()), &b"12345"[..], &b"NEXT"[..]));
        let (result, written, _) = every_split(b"123", |b, from, to| copy_length(b, from, to, 5));
        assert_eq!((result, written.as_slice()), (Err(CopyError::Source), &b"123"[..]));
        let (result, written, rest) = every_split(b"NEXT", |b, from, to| copy_length(b, from, to, 0));
        assert_eq!((result, written.len(), rest.as_slice()), (Ok(()), 0, &b"NEXT"[..]));
    }

    #[test]
    fn chunks_are_decoded_and_the_rest_left_alone() {
        let body = b"3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nTrailer: x\r\n\r\nNEXT";
        let (result, written, rest) =
            every_split(body, |b, from, to| copy_chunked(b, from, to, 5, false));
        assert_eq!((result, written.as_slice(), rest.as_slice()), (Ok(()), &b"abcde"[..], &b"NEXT"[..]));
        let (result, written, rest) =
            every_split(body, |b, from, to| copy_chunked(b, from, to, 5, true));
        assert_eq!(result, Ok(()));
        assert_eq!(written, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
        assert_eq!(rest, b"NEXT");
    }

    #[test]
    fn a_cut_chunked_body_is_never_ended() {
        let whole = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        for cut in 0..whole.len() {
            let from = Script::new(vec![Step::Data(whole[..cut].to_vec()), Step::End]);
            let to = Script::default();
            let result = copy_chunked(&mut Buffer::new(), &from, &to, 100, true);
            assert_eq!(result, Err(CopyError::Source), "cut at {cut}");
            assert!(!to.written().ends_with(b"0\r\n\r\n"), "cut at {cut}");
        }
    }

    #[test]
    fn malformed_chunks() {
        for body in [
            "x\r\nabc\r\n0\r\n\r\n",
            "3\r\nabcd\r\n0\r\n\r\n",
            "3\r\nab\r\n0\r\n\r\n",
            "3\nabc\n0\n\n",
            "3\r\nabc\r\n0\r\nbad trailer\r\n\r\n",
            "-3\r\nabc\r\n0\r\n\r\n",
            "3 \r\nabc\r\n0\r\n\r\n",
        ] {
            let from = Script::new(vec![Step::Data(body.as_bytes().to_vec()), Step::End]);
            let result = copy_chunked(&mut Buffer::new(), &from, &Script::default(), 100, true);
            assert_eq!(result, Err(CopyError::Malformed), "{body:?}");
        }
    }

    #[test]
    fn a_chunked_body_over_the_limit_is_refused_before_it_is_copied() {
        let from = Script::new(vec![Step::Data(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec())]);
        let to = Script::default();
        let result = copy_chunked(&mut Buffer::new(), &from, &to, 5, true);
        assert_eq!(result, Err(CopyError::TooLarge));
        assert_eq!(to.written(), b"3\r\nabc\r\n");
        // A size that overflows the total is refused the same way.
        let from = Script::new(vec![Step::Data(b"1\r\na\r\nffffffffffffffff\r\n".to_vec())]);
        let result = copy_chunked(&mut Buffer::new(), &from, &Script::default(), u64::MAX, true);
        assert_eq!(result, Err(CopyError::TooLarge));
    }

    #[test]
    fn copying_to_the_end() {
        let (result, written, _) = every_split(b"abcde", |b, from, to| copy_to_end(b, from, to, false));
        assert_eq!((result, written.as_slice()), (Ok(()), &b"abcde"[..]));
        // Chunked again: however the pieces fall, they decode to the same.
        for cut in 0..=5 {
            let from = Script::new(vec![
                Step::Data(b"abcde"[..cut].to_vec()),
                Step::Data(b"abcde"[cut..].to_vec()),
                Step::End,
            ]);
            let to = Script::default();
            copy_to_end(&mut Buffer::new(), &from, &to, true).unwrap();
            let again = Script::new(vec![Step::Data(to.written()), Step::End]);
            let plain = Script::default();
            copy_chunked(&mut Buffer::new(), &again, &plain, 100, false).unwrap();
            assert_eq!(plain.written(), b"abcde");
        }
    }

    #[test]
    fn a_source_that_stalls_is_not_taken_for_one_that_ended() {
        let from = Script::new(vec![Step::Data(b"abc".to_vec()), Step::Timeout]);
        let to = Script::default();
        assert_eq!(copy_to_end(&mut Buffer::new(), &from, &to, true), Err(CopyError::SourceTimeout));
        assert_eq!(to.written(), b"3\r\nabc\r\n");
        let from = Script::new(vec![Step::Data(b"abc".to_vec()), Step::Timeout]);
        assert_eq!(copy_length(&mut Buffer::new(), &from, &Script::default(), 5), Err(CopyError::SourceTimeout));
    }

    #[test]
    fn a_failing_sink_is_reported() {
        let from = Script::new(vec![Step::Data(b"abcde".to_vec())]);
        let to = Script::default().failing_after(2);
        assert_eq!(copy_length(&mut Buffer::new(), &from, &to, 5), Err(CopyError::Sink));
    }
}
