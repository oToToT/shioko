//! Reading HTTP/1.1 heads: from bytes to what the state machine and the
//! framing rules are given.
//!
//! Parsing is strict. A head that can be read in two ways is how request
//! smuggling starts, so anything unusual is refused rather than repaired.

use super::fsm::{Coding, Length, Version};
use crate::stream::{Buffer, LineError, Stream};

/// The longest request line or status line we read.
pub const LINE_LIMIT: usize = 8192;
/// The most bytes a head may have.
pub const HEAD_LIMIT: usize = 16 * 1024;
/// The most fields a head may have.
pub const FIELD_LIMIT: usize = 100;
/// The longest method we take for one.
pub const METHOD_LIMIT: usize = 32;
/// The most empty lines we skip before a request line.
const EMPTY_LINES: usize = 4;

/// A token as RFC 9110 defines it: one or more of the characters allowed in
/// method and field names (`tchar`).
pub fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| is_tchar(b))
}

// The character classes are `matches!`, not searches of a string: a search
// is a loop, which the Kani proofs would have to unroll for every byte.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
}

fn is_visible(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}

/// What a field value, reason phrase, quoted string or chunk extension may
/// hold: visible characters, spaces, tabs and bytes above ASCII.
fn is_text(byte: u8) -> bool {
    byte == b'\t' || byte == b' ' || is_visible(byte) || byte >= 0x80
}

/// Removes spaces and tabs from both ends.
fn trim(mut bytes: &[u8]) -> &[u8] {
    while let Some((&(b' ' | b'\t'), rest)) = bytes.split_first() {
        bytes = rest;
    }
    while let Some((&(b' ' | b'\t'), rest)) = bytes.split_last() {
        bytes = rest;
    }
    bytes
}

fn version(bytes: &[u8]) -> Option<Version> {
    match bytes.strip_prefix(b"HTTP/1.")? {
        [b'0'] => Some(Version::V10),
        [minor] if minor.is_ascii_digit() => Some(Version::V11),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RequestLine<'a> {
    pub method: &'a [u8],
    pub target: &'a [u8],
    pub version: Version,
}

/// Takes a request line apart, or says which status refuses it.
///
/// The target must be in origin form and hold only visible ASCII
/// characters; `*` is refused, even with OPTIONS, as nginx refuses it. Some of those may not appear in a URI (`|`,
/// `^`, `[`, `{`, ...), but browsers send them unencoded, so they are
/// accepted and passed on as received. CONNECT is refused whatever its
/// target. A method that is too long is refused later, once the fields are
/// read (`METHOD_LIMIT`).
pub fn request_line(line: &[u8]) -> Result<RequestLine<'_>, u16> {
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(protocol), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(400);
    };
    if !is_token(method) || method == b"CONNECT" {
        return Err(400);
    }
    if target.first() != Some(&b'/') || !target.iter().all(|&b| is_visible(b)) {
        return Err(400);
    }
    let version = version(protocol).ok_or(400u16)?;
    Ok(RequestLine { method, target, version })
}

#[derive(Debug, PartialEq, Eq)]
pub struct StatusLine<'a> {
    pub version: Version,
    pub status: u16,
    pub reason: &'a [u8],
}

/// Takes a status line apart. The status must be three digits from 100 to
/// 599.
pub fn status_line(line: &[u8]) -> Option<StatusLine<'_>> {
    let (protocol, rest) = line.split_at_checked(8)?;
    let rest = rest.strip_prefix(b" ")?;
    let (digits, reason) = rest.split_at_checked(3)?;
    let reason = match reason {
        [] => reason,
        [b' ', text @ ..] => text,
        _ => return None,
    };
    let status = u16::try_from(decimal(digits)?).ok()?;
    ((100..=599).contains(&status) && reason.iter().all(|&b| is_text(b)))
        .then_some(StatusLine { version: version(protocol)?, status, reason })
}

/// Takes a field line apart into name and value. The name must be a token
/// directly followed by the colon; the value loses the spaces and tabs
/// around it and may hold no control character.
pub fn field_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    let (name, rest) = line.split_at_checked(colon)?;
    let value = trim(rest.get(1..)?);
    (is_token(name) && value.iter().all(|&b| is_text(b))).then_some((name, value))
}

/// A quoted string: visible characters, spaces and tabs between double
/// quotes, with backslash escapes.
fn is_quoted(bytes: &[u8]) -> bool {
    let [b'"', inner @ .., b'"'] = bytes else {
        return false;
    };
    let mut escaped = false;
    for &byte in inner {
        if !is_text(byte) || (byte == b'"' && !escaped) {
            return false;
        }
        escaped = byte == b'\\' && !escaped;
    }
    !escaped
}

/// The number one or more digits in base `radix` spell, if it fits a `u64`.
/// Leading zeros are allowed, any number of them.
fn number(digits: &[u8], radix: u32) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |number, &byte| {
        number.checked_mul(u64::from(radix))?.checked_add(u64::from(char::from(byte).to_digit(radix)?))
    })
}

/// A decimal number that fits a `u64`, and nothing else.
pub fn decimal(bytes: &[u8]) -> Option<u64> {
    number(bytes, 10)
}

/// The size at the start of a chunk: hexadecimal digits, then nothing or a
/// chunk extension, which is ignored. Spaces and tabs may come before the
/// `;` of an extension, but not at the end of a line without one.
pub fn chunk_size(line: &[u8]) -> Option<u64> {
    let (digits, rest) = line.split_at_checked(line.iter().take_while(|b| b.is_ascii_hexdigit()).count())?;
    let size = number(digits, 16)?;
    let extension = rest.iter().position(|&b| b != b' ' && b != b'\t').and_then(|at| rest.get(at..));
    match extension {
        None if rest.is_empty() => Some(size),
        Some([b';', more @ ..]) if more.iter().all(|&b| is_text(b)) => Some(size),
        _ => None,
    }
}

/// What the `Host` field names, without the port: a host name (`reg-name`),
/// an IPv4 address, or an IP literal in brackets, then optionally a colon
/// and a port of at most five digits, which may be empty. An empty name is
/// refused: there is nothing to route by.
pub fn host(value: &[u8]) -> Option<&[u8]> {
    let (name, rest) = if value.first() == Some(&b'[') {
        let end = value.iter().position(|&b| b == b']')?;
        let (literal, rest) = value.split_at_checked(end.checked_add(1)?)?;
        let inside = literal.get(1..end)?;
        let ok = !inside.is_empty() && inside.iter().all(|&b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        (ok.then_some(literal)?, rest)
    } else {
        let end = value.iter().position(|&b| b == b':').unwrap_or(value.len());
        let (name, rest) = value.split_at_checked(end)?;
        let mut bytes = name.iter();
        while let Some(&byte) = bytes.next() {
            // RFC 3986 `reg-name`: unreserved, sub-delims and percent escapes.
            let ok = if byte == b'%' {
                bytes.next().is_some_and(u8::is_ascii_hexdigit) && bytes.next().is_some_and(u8::is_ascii_hexdigit)
            } else {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
            };
            if !ok {
                return None;
            }
        }
        (name, rest)
    };
    let port_ok = match rest {
        [] => true,
        [b':', port @ ..] => port.len() <= 5 && port.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    (!name.is_empty() && port_ok).then_some(name)
}

/// The fields of a head, in the order received, names as received.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields(pub Vec<(Vec<u8>, Vec<u8>)>);

impl Fields {
    /// The values of every field with this name, compared without case.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.0
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, value)| value.as_slice())
    }

    /// The value of the field with this name, if there is exactly one.
    pub fn one<'a>(&'a self, name: &'a str) -> Option<&'a [u8]> {
        let mut values = self.all(name);
        values.next().filter(|_| values.next().is_none())
    }

    /// The elements of a field whose value is a comma-separated list, over
    /// all fields with this name, in lower case, empty elements left out.
    pub fn list(&self, name: &str) -> Vec<Vec<u8>> {
        self.all(name)
            .flat_map(|value| value.split(|&b| b == b','))
            .map(|element| trim(element).to_ascii_lowercase())
            .filter(|element| !element.is_empty())
            .collect()
    }

    /// Whether that list holds this element, given in lower case.
    pub fn has(&self, name: &str, element: &str) -> bool {
        self.list(name).iter().any(|e| e == element.as_bytes())
    }

    /// What the head says about `Content-Length`, and the length if it is
    /// clear.
    pub fn length(&self) -> (Length, u64) {
        match (self.all("content-length").next(), self.one("content-length").and_then(decimal)) {
            (None, _) => (Length::None, 0),
            (_, Some(length)) => (Length::One, length),
            _ => (Length::Bad, 0),
        }
    }

    /// What the head says about `Transfer-Encoding`. Each coding is a token
    /// with optional parameters (`gzip;level=1`); `chunked` takes none.
    pub fn coding(&self) -> Coding {
        let mut values = self.all("transfer-encoding").peekable();
        if values.peek().is_none() {
            return Coding::None;
        }
        let mut codings = 0usize;
        let mut last_is_chunked = false;
        for element in values.flat_map(|value| value.split(|&b| b == b',')) {
            let mut parts = element.split(|&b| b == b';');
            let name = trim(parts.next().unwrap_or(&[]));
            let parameters_ok = parts.all(|parameter| {
                let mut sides = parameter.splitn(2, |&b| b == b'=');
                let (key, value) = (trim(sides.next().unwrap_or(&[])), trim(sides.next().unwrap_or(&[])));
                is_token(key) && (is_token(value) || is_quoted(value))
            });
            let chunked = name.eq_ignore_ascii_case(b"chunked");
            // "chunked" may come once, without parameters, and nothing may
            // follow it.
            if !is_token(name) || !parameters_ok || last_is_chunked || (chunked && element.contains(&b';')) {
                return Coding::Bad;
            }
            last_is_chunked = chunked;
            codings = codings.saturating_add(1);
        }
        match (last_is_chunked, codings) {
            (true, 1) => Coding::Chunked,
            (true, _) => Coding::Other,
            _ => Coding::Bad,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FieldsError {
    /// The stream ended or failed.
    Gone,
    /// More bytes or more fields than a head may have.
    TooLarge,
    Malformed,
}

/// Reads field lines up to and including the empty line that ends them,
/// using at most `room` bytes.
pub fn read_fields(
    buffer: &mut Buffer,
    stream: &impl Stream,
    mut room: usize,
) -> Result<Fields, FieldsError> {
    let mut fields = Fields::default();
    loop {
        let line = buffer.line(stream, room).map_err(|error| match error {
            LineError::End | LineError::Cut => FieldsError::Gone,
            LineError::TooLong => FieldsError::TooLarge,
            LineError::Bare => FieldsError::Malformed,
        })?;
        if line.is_empty() {
            return Ok(fields);
        }
        room = room.saturating_sub(line.len().saturating_add(2));
        if fields.0.len() == FIELD_LIMIT {
            return Err(FieldsError::TooLarge);
        }
        let (name, value) = field_line(&line).ok_or(FieldsError::Malformed)?;
        fields.0.push((name.to_vec(), value.to_vec()));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub version: Version,
    pub fields: Fields,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    /// The client sent nothing more.
    End,
    /// The stream ended or failed inside a head.
    Gone,
    /// The head is refused with this status; `head` says the request line
    /// was read and its method is HEAD, so the answer must have no body.
    Status(u16, bool),
}

/// Reads one request head.
pub fn read_request(buffer: &mut Buffer, stream: &impl Stream) -> Result<Request, RequestError> {
    let mut skipped = 0usize;
    let line = loop {
        let line = buffer.line(stream, LINE_LIMIT).map_err(|error| {
            // A line that is refused is still there to see whether it is HEAD.
            let head = buffer.pending().starts_with(b"HEAD ");
            match error {
                LineError::End => RequestError::End,
                LineError::Cut => RequestError::Gone,
                LineError::TooLong => RequestError::Status(414, head),
                LineError::Bare => RequestError::Status(400, head),
            }
        })?;
        if !line.is_empty() {
            break line;
        }
        skipped = skipped.saturating_add(1);
        if skipped > EMPTY_LINES {
            return Err(RequestError::Status(400, false));
        }
    };
    let head = line.starts_with(b"HEAD ");
    let RequestLine { method, target, version } =
        request_line(&line).map_err(|status| RequestError::Status(status, head))?;
    let room = HEAD_LIMIT.saturating_sub(line.len());
    let fields = read_fields(buffer, stream, room).map_err(|error| match error {
        FieldsError::Gone => RequestError::Gone,
        FieldsError::TooLarge => RequestError::Status(431, head),
        FieldsError::Malformed => RequestError::Status(400, head),
    })?;
    Ok(Request { method: method.to_vec(), target: target.to_vec(), version, fields })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub version: Version,
    pub status: u16,
    pub reason: Vec<u8>,
    pub fields: Fields,
}

/// Reads one response head from an upstream. The error is the status our
/// client gets instead: 504 if the upstream was too slow, 502 otherwise.
pub fn read_response(buffer: &mut Buffer, stream: &impl Stream) -> Result<Response, u16> {
    let failed = |buffer: &Buffer| if buffer.timed_out() { 504u16 } else { 502u16 };
    let line = buffer.line(stream, LINE_LIMIT).map_err(|_| failed(buffer))?;
    let StatusLine { version, status, reason } = status_line(&line).ok_or(502u16)?;
    let room = HEAD_LIMIT.saturating_sub(line.len());
    let fields = read_fields(buffer, stream, room).map_err(|error| match error {
        FieldsError::Gone => failed(buffer),
        _ => 502,
    })?;
    Ok(Response { version, status, reason: reason.to_vec(), fields })
}

// Proofs, checked by Kani (tools/prove.sh): each holds for every input up
// to the stated length.
#[cfg(kani)]
mod proofs {
    use super::*;

    const N: usize = 12;

    fn any_bytes<const L: usize>() -> ([u8; L], usize) {
        let bytes: [u8; L] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= L);
        (bytes, len)
    }

    /// A request line is never taken apart wrongly: what comes out has a
    /// token for a method and a target that is in origin form or `*`, free
    /// of spaces and control characters. And nothing panics.
    #[kani::proof]
    #[kani::unwind(14)]
    fn request_line_is_sound() {
        let (bytes, len) = any_bytes::<N>();
        if let Ok(parsed) = request_line(&bytes[..len]) {
            assert!(is_token(parsed.method));
            assert!(parsed.target[0] == b'/');
            assert!(parsed.target.iter().all(|&b| b > b' ' && b < 0x7f));
            assert!(parsed.method.len() + parsed.target.len() + 10 == len);
        }
    }

    /// A field line that is accepted has a token for a name, the colon
    /// directly after it, and no control character in its value.
    #[kani::proof]
    #[kani::unwind(14)]
    fn field_line_is_sound() {
        let (bytes, len) = any_bytes::<N>();
        if let Some((name, value)) = field_line(&bytes[..len]) {
            assert!(is_token(name));
            assert!(bytes[name.len()] == b':');
            assert!(value.iter().all(|&b| b == b'\t' || b >= b' ' && b != 0x7f));
            assert!(value.first() != Some(&b' ') && value.last() != Some(&b' '));
        }
    }

    /// A status line that is accepted has a status from 100 to 599.
    #[kani::proof]
    #[kani::unwind(16)]
    fn status_line_is_sound() {
        let (bytes, len) = any_bytes::<14>();
        if let Some(parsed) = status_line(&bytes[..len]) {
            assert!((100..=599).contains(&parsed.status));
            assert!(bytes[8] == b' ');
        }
    }

    /// Only digits make a decimal number, and its value is right.
    #[kani::proof]
    #[kani::unwind(6)]
    fn decimal_is_exact() {
        let (bytes, len) = any_bytes::<4>();
        let digits = &bytes[..len];
        match decimal(digits) {
            Some(number) => {
                assert!(len > 0 && digits.iter().all(u8::is_ascii_digit));
                let expected = digits.iter().fold(0u64, |n, d| n * 10 + u64::from(d - b'0'));
                assert!(number == expected);
            }
            None => {
                assert!(len == 0 || !digits.iter().all(u8::is_ascii_digit));
            }
        }
    }

    /// A chunk size never overflows and never panics, whatever the line.
    #[kani::proof]
    #[kani::unwind(20)]
    fn chunk_size_is_sound() {
        let (bytes, len) = any_bytes::<18>();
        if let Some(size) = chunk_size(&bytes[..len]) {
            assert!(len > 0 && bytes[0].is_ascii_hexdigit());
            if len == 1 {
                assert!(size < 16);
            }
        }
    }

    /// A host that is accepted is a name or a bracketed IP literal: never
    /// a slash, an at sign, a question mark, a space or a control
    /// character, nothing that could change where a request is routed.
    #[kani::proof]
    #[kani::unwind(14)]
    fn host_is_sound() {
        let (bytes, len) = any_bytes::<N>();
        if let Some(name) = host(&bytes[..len]) {
            assert!(!name.is_empty());
            assert!(name.iter().all(|&b| b > b' ' && b < 0x7f && !matches!(b, b'/' | b'@' | b'?' | b'#' | b'\\')));
            assert!(name[0] == b'[' || !name.contains(&b':'));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::testing::{Script, Step};

    fn fields(lines: &[&str]) -> Fields {
        Fields(
            lines
                .iter()
                .map(|line| {
                    let (name, value) = field_line(line.as_bytes()).unwrap();
                    (name.to_vec(), value.to_vec())
                })
                .collect(),
        )
    }

    #[test]
    fn request_lines() {
        let ok = |line: &str| request_line(line.as_bytes()).map(|l| l.version);
        assert_eq!(ok("GET / HTTP/1.1"), Ok(Version::V11));
        assert_eq!(ok("GET /a?b=c HTTP/1.0"), Ok(Version::V10));
        assert_eq!(ok("GET / HTTP/1.2"), Ok(Version::V11));
        assert_eq!(ok("OPTIONS * HTTP/1.1"), Err(400));
        // The target form.
        assert_eq!(ok("GET * HTTP/1.1"), Err(400));
        assert_eq!(ok("GET http://example.org/ HTTP/1.1"), Err(400));
        assert_eq!(ok("CONNECT example.org:443 HTTP/1.1"), Err(400));
        assert_eq!(ok("CONNECT / HTTP/1.1"), Err(400));
        assert_eq!(ok("GET /\u{7f} HTTP/1.1"), Err(400));
        assert_eq!(ok("GET /caf\u{e9} HTTP/1.1"), Err(400));
        // The shape of the line.
        assert_eq!(ok("GET  / HTTP/1.1"), Err(400));
        assert_eq!(ok("GET / HTTP/1.1 "), Err(400));
        assert_eq!(ok("GET /a b HTTP/1.1"), Err(400));
        assert_eq!(ok("GET\t/ HTTP/1.1"), Err(400));
        assert_eq!(ok(" GET / HTTP/1.1"), Err(400));
        assert_eq!(ok("GET /"), Err(400));
        assert_eq!(ok("G(T / HTTP/1.1"), Err(400));
        // The version.
        for version in ["HTTP/2.0", "HTTP/1", "HTTP/1.", "HTTP/1.10", "http/1.1", "HTTP/0.9"] {
            assert_eq!(ok(&format!("GET / {version}")), Err(400), "{version}");
        }
        // Characters a URI may not hold but browsers send as they are.
        for target in ["/a|b", "/a^b", "/a[0]", "/a{b}", "/a`b", "/a\\b", "/a\"b"] {
            assert_eq!(ok(&format!("GET {target} HTTP/1.1")), Ok(Version::V11), "{target}");
        }
        // A long method is taken apart here and refused once the fields
        // are read.
        assert_eq!(ok(&format!("{} / HTTP/1.1", "M".repeat(33))), Ok(Version::V11));
    }

    #[test]
    fn status_lines() {
        let ok = |line: &str| status_line(line.as_bytes()).map(|l| (l.status, l.reason.to_vec()));
        assert_eq!(ok("HTTP/1.1 200 OK"), Some((200, b"OK".to_vec())));
        assert_eq!(ok("HTTP/1.1 200 "), Some((200, vec![])));
        assert_eq!(ok("HTTP/1.1 200"), Some((200, vec![])));
        assert_eq!(ok("HTTP/1.0 404 Not Found"), Some((404, b"Not Found".to_vec())));
        for bad in [
            "HTTP/1.1  200 OK",
            "HTTP/1.1 20 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 099 Low",
            "HTTP/1.1 600 High",
            "HTTP/1.1 2x0 OK",
            "HTTP/2.0 200 OK",
            "HTTP/1.1 200OK",
            "HTTP/1.1 200 O\u{1}K",
            "200 OK",
            "",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn field_lines() {
        let ok = |line: &str| {
            field_line(line.as_bytes()).map(|(n, v)| {
                (String::from_utf8(n.to_vec()).unwrap(), String::from_utf8_lossy(v).into_owned())
            })
        };
        assert_eq!(ok("Host: example.org"), Some(("Host".into(), "example.org".into())));
        assert_eq!(ok("X:\t a  b \t"), Some(("X".into(), "a  b".into())));
        assert_eq!(ok("Empty:"), Some(("Empty".into(), "".into())));
        assert_eq!(ok("A: b: c"), Some(("A".into(), "b: c".into())));
        for bad in [
            "Host : example.org", // whitespace before the colon
            " Host: x",           // a folded line
            "\tcontinued",
            ": no name",
            "No colon",
            "Na me: x",
            "X: a\u{0}b",
            "X: a\u{b}b",
            "X: \u{7f}",
            "X\u{e9}: y",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
        // Bytes above ASCII are allowed in a value.
        assert!(field_line(b"X: caf\xc3\xa9").is_some());
    }

    #[test]
    fn content_length_classes() {
        assert_eq!(fields(&["A: b"]).length(), (Length::None, 0));
        assert_eq!(fields(&["Content-Length: 0"]).length(), (Length::One, 0));
        assert_eq!(fields(&["content-LENGTH: 42"]).length(), (Length::One, 42));
        assert_eq!(
            fields(&["Content-Length: 18446744073709551615"]).length(),
            (Length::One, u64::MAX)
        );
        assert_eq!(fields(&["Content-Length: 000000000000000000000042"]).length(), (Length::One, 42));
        for bad in [
            vec!["Content-Length: 42", "Content-Length: 42"],
            vec!["Content-Length: 42", "Content-Length: 43"],
            vec!["Content-Length: 42, 42"],
            vec!["Content-Length: +42"],
            vec!["Content-Length: 0x2a"],
            vec!["Content-Length: 4 2"],
            vec!["Content-Length:"],
            vec!["Content-Length: -1"],
            vec!["Content-Length: 18446744073709551616"],
            vec!["Content-Length: 99999999999999999999"],
        ] {
            assert_eq!(fields(&bad).length().0, Length::Bad, "{bad:?}");
        }
    }

    #[test]
    fn transfer_encoding_classes() {
        let class = |lines: &[&str]| fields(lines).coding();
        assert_eq!(class(&["A: b"]), Coding::None);
        assert_eq!(class(&["Transfer-Encoding: chunked"]), Coding::Chunked);
        assert_eq!(class(&["transfer-encoding: CHUNKED"]), Coding::Chunked);
        assert_eq!(class(&["Transfer-Encoding: gzip, chunked"]), Coding::Other);
        assert_eq!(class(&["Transfer-Encoding: gzip", "Transfer-Encoding: chunked"]), Coding::Other);
        assert_eq!(class(&["Transfer-Encoding: gzip;level=1, chunked"]), Coding::Other);
        assert_eq!(class(&["Transfer-Encoding: x ; a=\"b;c\\\"\" , chunked"]), Coding::Bad);
        assert_eq!(class(&["Transfer-Encoding: x ; a=\"b c\" , chunked"]), Coding::Other);
        for bad in [
            vec!["Transfer-Encoding: gzip"],
            vec!["Transfer-Encoding: chunked, gzip"],
            vec!["Transfer-Encoding: chunked, chunked"],
            vec!["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"],
            vec!["Transfer-Encoding: chunked,"],
            vec!["Transfer-Encoding: , chunked"],
            vec!["Transfer-Encoding:"],
            vec!["Transfer-Encoding: chunked;q=1"],
            vec!["Transfer-Encoding: gzip;level, chunked"],
            vec!["Transfer-Encoding: gzip;=1, chunked"],
            vec!["Transfer-Encoding: gzip;a=\"open, chunked"],
            vec!["Transfer-Encoding: xchunked"],
            vec!["Transfer-Encoding: chunked x"],
        ] {
            assert_eq!(class(&bad), Coding::Bad, "{bad:?}");
        }
    }

    #[test]
    fn chunk_sizes() {
        assert_eq!(chunk_size(b"0"), Some(0));
        assert_eq!(chunk_size(b"1a"), Some(26));
        assert_eq!(chunk_size(b"FF"), Some(255));
        assert_eq!(chunk_size(b"ffffffffffffffff"), Some(u64::MAX));
        assert_eq!(chunk_size(b"5;name=value"), Some(5));
        assert_eq!(chunk_size(b"5;"), Some(5));
        assert_eq!(chunk_size(b"5 ;x"), Some(5));
        assert_eq!(chunk_size(b"5\t ; x = \"caf\xc3\xa9\""), Some(5));
        assert_eq!(chunk_size(b"00000000000000000005"), Some(5));
        for bad in ["", "g", "-1", "+1", "0x5", " 5", "5 ", "5 x", "10000000000000000", ";x", "5;\u{1}"] {
            assert_eq!(chunk_size(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn hosts() {
        let name = |value: &str| host(value.as_bytes()).map(|n| String::from_utf8(n.to_vec()).unwrap());
        assert_eq!(name("example.org"), Some("example.org".into()));
        assert_eq!(name("example.org:8080"), Some("example.org".into()));
        assert_eq!(name("10.0.0.1:80"), Some("10.0.0.1".into()));
        assert_eq!(name("[::1]"), Some("[::1]".into()));
        assert_eq!(name("[2001:db8::1]:443"), Some("[2001:db8::1]".into()));
        assert_eq!(name("a:"), Some("a".into()));
        assert_eq!(name("under_score.test"), Some("under_score.test".into()));
        assert_eq!(name("caf%C3%A9.test"), Some("caf%C3%A9.test".into()));
        for bad in ["", ":80", "a:b", "a:123456", "a:1:2", "a b", "a/b", "user@a", "[]", "[::1", "[::1]x", "[g::]", "a%2", "a%zz", "a?b", "a#b"] {
            assert_eq!(name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn lists() {
        let f = fields(&["Connection: Keep-Alive , Upgrade", "connection: close,,"]);
        assert_eq!(f.list("connection"), vec![b"keep-alive".to_vec(), b"upgrade".to_vec(), b"close".to_vec()]);
        assert_eq!(f.one("connection"), None);
        assert_eq!(fields(&["A: b"]).one("a"), Some(&b"b"[..]));
    }

    fn request(text: &str) -> Result<Request, RequestError> {
        let stream = Script::new(vec![Step::Data(text.as_bytes().to_vec()), Step::End]);
        read_request(&mut Buffer::new(), &stream)
    }

    /// Mutated request and response heads never make the parsers panic,
    /// and what they accept has a usable framing class.
    #[test]
    fn mutated_heads() {
        let mut noise = crate::stream::testing::Noise::new(3);
        let request = b"POST /a?b HTTP/1.1\r\nHost: site.test:80\r\nContent-Length: 12\r\nTransfer-Encoding: gzip, chunked\r\nX: y\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        for _ in 0..100_000 {
            let input = noise.mutate(request);
            if let Ok(parsed) = read_request(&mut Buffer::new(), &Script::new(vec![Step::Data(input), Step::End])) {
                let _ = (parsed.fields.length(), parsed.fields.coding(), parsed.fields.one("host").map(host));
            }
            let input = noise.mutate(response);
            if let Ok(parsed) = read_response(&mut Buffer::new(), &Script::new(vec![Step::Data(input), Step::End])) {
                assert!((100..=599).contains(&parsed.status));
                let _ = (parsed.fields.length(), parsed.fields.coding());
            }
            let input = noise.mutate(b"1a;name=\"value\"");
            let _ = chunk_size(&input);
        }
    }

    #[test]
    fn request_heads() {
        let r = request("GET /x HTTP/1.1\r\nHost: a\r\nX: y\r\n\r\nbody").unwrap();
        assert_eq!((r.method.as_slice(), r.target.as_slice()), (&b"GET"[..], &b"/x"[..]));
        assert_eq!(r.fields.0.len(), 2);
        // Empty lines before the request line are skipped, a few of them.
        assert!(request("\r\n\r\nGET / HTTP/1.1\r\n\r\n").is_ok());
        assert_eq!(request(&format!("{}GET / HTTP/1.1\r\n\r\n", "\r\n".repeat(5))), Err(RequestError::Status(400, false)));
        assert_eq!(request(""), Err(RequestError::End));
        assert_eq!(request("\r\n"), Err(RequestError::End));
        assert_eq!(request("GET / HT"), Err(RequestError::Gone));
        assert_eq!(request("GET / HTTP/1.1\r\nHost: a\r\n"), Err(RequestError::Gone));
        assert_eq!(request("GET / HTTP/1.1\nHost: a\n\n"), Err(RequestError::Status(400, false)));
        assert_eq!(request("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n"), Err(RequestError::Status(400, false)));
        assert_eq!(request("GET / HTTP/1.1\r\n folded\r\n\r\n"), Err(RequestError::Status(400, false)));
    }

    #[test]
    fn request_head_limits() {
        let line = |target_len: usize| format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(target_len));
        // "GET /" and " HTTP/1.1" take 14 bytes of the line.
        assert!(request(&line(LINE_LIMIT - 14)).is_ok());
        assert_eq!(request(&line(LINE_LIMIT - 13)), Err(RequestError::Status(414, false)));
        let with_fields = |n: usize| format!("GET / HTTP/1.1\r\n{}\r\n", "A: b\r\n".repeat(n));
        assert!(request(&with_fields(FIELD_LIMIT)).is_ok());
        assert_eq!(request(&with_fields(FIELD_LIMIT + 1)), Err(RequestError::Status(431, false)));
        let big = format!("GET / HTTP/1.1\r\nA: {}\r\nB: {}\r\n\r\n", "x".repeat(8000), "y".repeat(8400));
        assert_eq!(request(&big), Err(RequestError::Status(431, false)));
    }

    #[test]
    fn response_heads() {
        let read = |steps: Vec<Step>| read_response(&mut Buffer::new(), &Script::new(steps));
        let data = |text: &str| Step::Data(text.as_bytes().to_vec());
        let r = read(vec![data("HTTP/1.1 204 No Content\r\nA: b\r\n\r\n")]).unwrap();
        assert_eq!((r.status, r.reason.as_slice()), (204, &b"No Content"[..]));
        assert_eq!(read(vec![Step::End]), Err(502));
        assert_eq!(read(vec![Step::Timeout]), Err(504));
        assert_eq!(read(vec![data("HTTP/1.1 200 OK\r\nA: b\r\n"), Step::Timeout]), Err(504));
        assert_eq!(read(vec![data("HTTP/1.1 200 OK\r\nA: b\r\n"), Step::End]), Err(502));
        assert_eq!(read(vec![data("HTTP/1.1 200 OK\r\nA : b\r\n\r\n")]), Err(502));
        assert_eq!(read(vec![data("HTTP/1.1 200 OK\nA: b\n\n")]), Err(502));
        assert_eq!(read(vec![data("garbage\r\n\r\n")]), Err(502));
    }
}
