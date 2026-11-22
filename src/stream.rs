//! Byte streams as the proxy sees them, and the buffer it reads them through.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

/// A two-way byte stream. All methods take `&self`, so the two threads of a
/// tunnel can share one stream: one reads while the other writes.
pub trait Stream: Sync {
    /// Reads some bytes. `Ok(0)` is the end of the stream.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all(&self, buf: &[u8]) -> io::Result<()>;
    /// How long a read may wait from now on.
    fn set_read_timeout(&self, timeout: Duration);
    /// Ends both directions at once. Reads and writes blocked in another
    /// thread return.
    fn shutdown(&self);
    /// Ends the stream in an orderly way after a last write: closes our side
    /// and gives the peer a moment to read what we sent.
    fn finish(&self);
}

/// A read that failed only because nothing came in time.
pub fn timed_out(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

impl Stream for TcpStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stream: &TcpStream = self;
        Read::read(&mut stream, buf)
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut stream: &TcpStream = self;
        Write::write_all(&mut stream, buf)
    }

    fn set_read_timeout(&self, timeout: Duration) {
        // Fails only for a zero duration, which we never pass.
        let _ = TcpStream::set_read_timeout(self, Some(timeout));
    }

    fn shutdown(&self) {
        let _ = TcpStream::shutdown(self, Shutdown::Both);
    }

    fn finish(&self) {
        // Closing a socket that still has unread input makes the kernel
        // reset the connection, which can destroy our last response before
        // the peer has read it. So close our side only, and read what is
        // left for a short while.
        let _ = TcpStream::shutdown(self, Shutdown::Write);
        Stream::set_read_timeout(self, LINGER);
        let mut scratch = [0u8; 1024];
        let mut left = LINGER_BYTES;
        while left > 0 {
            match Stream::read(self, &mut scratch) {
                Ok(n) if n > 0 => left = left.saturating_sub(n),
                _ => break,
            }
        }
        Stream::shutdown(self);
    }
}

const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 64 * 1024;

/// How much one read asks for.
const READ_SIZE: usize = 16 * 1024;

/// What can go wrong reading a line.
#[derive(Debug, PartialEq, Eq)]
pub enum LineError {
    /// The stream ended before the first byte of the line.
    End,
    /// The stream ended or failed in the middle of the line.
    Cut,
    /// No line end within the limit.
    TooLong,
    /// A CR or LF that is not part of a CRLF line end.
    Bare,
}

/// Bytes read from a stream and not yet used. Everything the proxy reads
/// goes through one of these per stream, so that what one step reads too
/// much is there for the next step.
#[derive(Default)]
pub struct Buffer {
    data: Vec<u8>,
    start: usize,
    timed_out: bool,
    /// When set, the reads `line` makes must all be done by then.
    deadline: Option<Instant>,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer::default()
    }

    /// The bytes read and not yet used.
    pub fn pending(&self) -> &[u8] {
        self.data.get(self.start..).unwrap_or(&[])
    }

    fn consume(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.data.len());
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    /// Takes everything read and not yet used.
    pub fn take(&mut self) -> Vec<u8> {
        let rest = self.pending().to_vec();
        self.consume(rest.len());
        rest
    }

    /// From now on the reads made by `line` must be done by `deadline`, so
    /// that a peer cannot keep a line open by sending it slowly. `None`
    /// lifts the limit; reads then wait as long as the stream's own timeout.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    /// One read from the stream, added to the pending bytes.
    fn fill(&mut self, stream: &impl Stream) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.timed_out = true;
                return Err(io::ErrorKind::TimedOut.into());
            }
            stream.set_read_timeout(left);
        }
        let old = self.data.len();
        self.data.resize(old.saturating_add(READ_SIZE), 0);
        let result = match self.data.get_mut(old..) {
            Some(space) => stream.read(space),
            None => Ok(0),
        };
        self.data.truncate(old.saturating_add(*result.as_ref().unwrap_or(&0)));
        self.timed_out = result.as_ref().is_err_and(timed_out);
        result
    }

    /// The last read made for `line` failed because nothing came in time.
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// Reads from the stream until at least `n` bytes are pending, without
    /// consuming any. `Ok(false)`: the stream ended first. On an error, or
    /// a timeout, what was read stays pending for the next call.
    pub fn need(&mut self, stream: &impl Stream, n: usize) -> io::Result<bool> {
        while self.pending().len() < n {
            if self.fill(stream)? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Takes the first `n` pending bytes, or none if fewer are pending.
    pub fn take_exactly(&mut self, n: usize) -> Option<Vec<u8>> {
        let taken = self.pending().get(..n)?.to_vec();
        self.consume(n);
        Some(taken)
    }

    /// Reads at most `out.len()` bytes: pending ones first, and from the
    /// stream only when none are pending. `Ok(0)` is the end of the stream.
    pub fn read(&mut self, stream: &impl Stream, out: &mut [u8]) -> io::Result<usize> {
        if self.pending().is_empty() {
            return stream.read(out);
        }
        let n = self.pending().len().min(out.len());
        for (to, from) in out.iter_mut().zip(self.pending()) {
            *to = *from;
        }
        self.consume(n);
        Ok(n)
    }

    /// Reads one line of at most `limit` bytes and returns it without its
    /// CRLF. The bytes after the line stay pending.
    pub fn line(&mut self, stream: &impl Stream, limit: usize) -> Result<Vec<u8>, LineError> {
        loop {
            if let Some(end) = self.pending().iter().position(|&b| b == b'\n') {
                let with_cr = self.pending().get(..end).unwrap_or(&[]);
                let Some((&b'\r', line)) = with_cr.split_last() else {
                    return Err(LineError::Bare);
                };
                if line.len() > limit {
                    return Err(LineError::TooLong);
                }
                if line.contains(&b'\r') {
                    return Err(LineError::Bare);
                }
                let line = line.to_vec();
                self.consume(end.saturating_add(1));
                return Ok(line);
            }
            // A line end takes two bytes more than the line.
            if self.pending().len() > limit.saturating_add(1) {
                return Err(LineError::TooLong);
            }
            let nothing_yet = self.pending().is_empty();
            match self.fill(stream) {
                Ok(n) if n > 0 => {}
                Ok(_) if nothing_yet => return Err(LineError::End),
                Err(_) if nothing_yet => return Err(LineError::End),
                _ => return Err(LineError::Cut),
            }
        }
    }
}

#[cfg(test)]
pub mod testing {
    //! A stream that plays back a script, for tests.

    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// What one call of `read` gives.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Step {
        Data(Vec<u8>),
        /// The peer closed its side.
        End,
        /// Nothing comes in time.
        Timeout,
        /// The peer waits for our "100 Continue" before it sends this.
        AfterContinue(Vec<u8>),
        /// The read takes this long and then gives the bytes.
        Slow(Duration, Vec<u8>),
    }

    #[derive(Default)]
    struct Inner {
        steps: VecDeque<Step>,
        written: Vec<u8>,
        /// Writes fail once this many bytes have been written.
        write_limit: Option<usize>,
        shut: bool,
        /// How many bytes had been written when `read` was first called.
        written_at_first_read: Option<usize>,
        /// A read was made for bytes the peer was still holding back.
        read_before_continue: bool,
    }

    /// Plays back `steps` to the reader and records what is written. When
    /// the script runs out, reads time out.
    #[derive(Default)]
    pub struct Script(Mutex<Inner>);

    impl Script {
        pub fn new(steps: Vec<Step>) -> Script {
            // A read never returns no data; that would mean the end.
            let steps = steps.into_iter().filter(|s| *s != Step::Data(vec![])).collect();
            Script(Mutex::new(Inner { steps, ..Inner::default() }))
        }

        pub fn failing_after(self, bytes: usize) -> Script {
            self.0.lock().unwrap().write_limit = Some(bytes);
            self
        }

        pub fn written(&self) -> Vec<u8> {
            self.0.lock().unwrap().written.clone()
        }

        pub fn written_at_first_read(&self) -> Option<usize> {
            self.0.lock().unwrap().written_at_first_read
        }

        pub fn read_before_continue(&self) -> bool {
            self.0.lock().unwrap().read_before_continue
        }

        pub fn was_shut(&self) -> bool {
            self.0.lock().unwrap().shut
        }
    }

    impl Stream for Script {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inner = self.0.lock().unwrap();
            if inner.written_at_first_read.is_none() {
                inner.written_at_first_read = Some(inner.written.len());
            }
            if inner.shut {
                return Ok(0);
            }
            let step = match inner.steps.pop_front() {
                Some(Step::AfterContinue(data)) => {
                    if !contains(&inner.written, b"100 Continue") {
                        inner.read_before_continue = true;
                        inner.steps.push_front(Step::AfterContinue(data));
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    Step::Data(data)
                }
                Some(Step::Slow(pause, data)) => {
                    drop(inner);
                    std::thread::sleep(pause);
                    inner = self.0.lock().unwrap();
                    Step::Data(data)
                }
                Some(step) => step,
                None => Step::Timeout,
            };
            match step {
                Step::Data(data) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        inner.steps.push_front(Step::Data(data[n..].to_vec()));
                    }
                    Ok(n)
                }
                Step::End => {
                    inner.steps.push_front(Step::End);
                    Ok(0)
                }
                _ => Err(io::ErrorKind::TimedOut.into()),
            }
        }

        fn write_all(&self, buf: &[u8]) -> io::Result<()> {
            let mut inner = self.0.lock().unwrap();
            if inner.shut {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if let Some(limit) = inner.write_limit
                && inner.written.len() + buf.len() > limit
            {
                let room = limit - inner.written.len();
                inner.written.extend_from_slice(&buf[..room]);
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            inner.written.extend_from_slice(buf);
            Ok(())
        }

        fn set_read_timeout(&self, _: Duration) {}

        fn shutdown(&self) {
            self.0.lock().unwrap().shut = true;
        }

        fn finish(&self) {
            self.0.lock().unwrap().shut = true;
        }
    }

    impl Stream for std::sync::Arc<Script> {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            Script::read(self, buf)
        }
        fn write_all(&self, buf: &[u8]) -> io::Result<()> {
            Script::write_all(self, buf)
        }
        fn set_read_timeout(&self, _: Duration) {}
        fn shutdown(&self) {
            Script::shutdown(self);
        }
        fn finish(&self) {
            Script::finish(self);
        }
    }


    /// A small deterministic generator of test inputs (xorshift).
    pub struct Noise(u64);
    
    impl Noise {
        pub fn new(seed: u64) -> Noise {
            Noise(seed | 1)
        }
    
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    
        pub fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
        }
    
        /// `input` with a few random changes: bytes flipped, set, inserted or
        /// removed, or the end cut off.
        pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
            let mut out = input.to_vec();
            for _ in 0..=self.below(4) {
                let at = self.below(out.len() + 1);
                match self.below(5) {
                    0 if at < out.len() => out[at] ^= 1 << self.below(8),
                    1 if at < out.len() => out[at] = self.next() as u8,
                    2 => out.insert(at, self.next() as u8),
                    3 if at < out.len() => {
                        out.remove(at);
                    }
                    _ => out.truncate(at),
                }
            }
            out
        }
    }

    pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Script, Step};
    use super::*;

    fn data(text: &str) -> Step {
        Step::Data(text.as_bytes().to_vec())
    }

    #[test]
    fn lines_come_out_whole_however_the_reads_fall() {
        let text = "first\r\nsecond line\r\n\r\nrest";
        for cut in 1..text.len() {
            let stream = Script::new(vec![data(&text[..cut]), data(&text[cut..]), Step::End]);
            let mut buffer = Buffer::new();
            assert_eq!(buffer.line(&stream, 100).unwrap(), b"first");
            assert_eq!(buffer.line(&stream, 100).unwrap(), b"second line");
            assert_eq!(buffer.line(&stream, 100).unwrap(), b"");
            assert_eq!(buffer.line(&stream, 100), Err(LineError::Cut));
        }
    }

    #[test]
    fn bare_cr_or_lf_is_refused() {
        for text in ["a\nb\r\n", "a\rb\r\n", "\n"] {
            let stream = Script::new(vec![data(text)]);
            assert_eq!(Buffer::new().line(&stream, 100), Err(LineError::Bare), "{text:?}");
        }
    }

    #[test]
    fn line_limit() {
        let stream = Script::new(vec![data("12345\r\n")]);
        assert_eq!(Buffer::new().line(&stream, 5).unwrap(), b"12345");
        let stream = Script::new(vec![data("123456\r\n")]);
        assert_eq!(Buffer::new().line(&stream, 5), Err(LineError::TooLong));
        // No line end in sight: give up without reading for ever.
        let stream = Script::new(vec![data("1234567"), data("89")]);
        assert_eq!(Buffer::new().line(&stream, 5), Err(LineError::TooLong));
    }

    #[test]
    fn end_before_any_byte_is_told_apart() {
        let stream = Script::new(vec![Step::End]);
        assert_eq!(Buffer::new().line(&stream, 5), Err(LineError::End));
        let stream = Script::new(vec![Step::Timeout]);
        assert_eq!(Buffer::new().line(&stream, 5), Err(LineError::End));
        let stream = Script::new(vec![data("ab"), Step::Timeout]);
        assert_eq!(Buffer::new().line(&stream, 5), Err(LineError::Cut));
    }

    #[test]
    fn read_gives_pending_bytes_first_and_only_those() {
        let stream = Script::new(vec![data("line\r\nabc"), data("def"), Step::End]);
        let mut buffer = Buffer::new();
        buffer.line(&stream, 100).unwrap();
        let mut out = [0u8; 2];
        assert_eq!(buffer.read(&stream, &mut out).unwrap(), 2);
        assert_eq!(&out, b"ab");
        let mut out = [0u8; 10];
        assert_eq!(buffer.read(&stream, &mut out).unwrap(), 1);
        assert_eq!(buffer.read(&stream, &mut out).unwrap(), 3);
        assert_eq!(&out[..3], b"def");
        assert_eq!(buffer.read(&stream, &mut out).unwrap(), 0);
    }

    #[test]
    fn a_line_sent_slowly_runs_into_the_deadline() {
        let slow = |text: &str| Step::Slow(Duration::from_millis(30), text.as_bytes().to_vec());
        let steps = || vec![slow("GET "), slow("/ HTTP/1.1"), slow("\r\n")];
        // Each read is quick enough on its own; together they are too slow.
        let stream = Script::new(steps());
        let mut buffer = Buffer::new();
        buffer.set_deadline(Some(Instant::now() + Duration::from_millis(50)));
        assert_eq!(buffer.line(&stream, 100), Err(LineError::Cut));
        assert!(buffer.timed_out());
        // Without a deadline the same line arrives.
        let stream = Script::new(steps());
        assert_eq!(Buffer::new().line(&stream, 100).unwrap(), b"GET / HTTP/1.1");
    }

    #[test]
    fn take_hands_over_what_is_pending() {
        let stream = Script::new(vec![data("head\r\nraw bytes")]);
        let mut buffer = Buffer::new();
        buffer.line(&stream, 100).unwrap();
        assert_eq!(buffer.take(), b"raw bytes");
        assert!(buffer.pending().is_empty());
    }
}
