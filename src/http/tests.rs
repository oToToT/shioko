//! The proxy as a whole, run against scripted streams.
//!
//! The first part is a harness: a description of what a client sends and
//! what its upstreams answer, turned into real bytes and played to
//! `proxy::serve` with the reads split in every way that matters. The
//! second part states, one test each, what must hold of every such run.
//! These are the properties `spec/rfc/*.req` cites by name.

use super::fsm::Version;
use super::proxy::{self, Connect, Context, Timeouts};
use crate::config::{Config, Site};
use crate::log::testing::Kept;
use crate::stream::testing::{Script, Step, contains};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------ the harness

/// How a body is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    None,
    /// A stated length of this many bytes.
    Length(usize),
    /// Two chunks of these sizes (a size of zero leaves the chunk out).
    Chunked(usize, usize),
    /// Bytes until the connection closes (responses only).
    ToEnd(usize),
}

impl Body {
    fn size(self) -> usize {
        match self {
            Body::None => 0,
            Body::Length(n) | Body::ToEnd(n) => n,
            Body::Chunked(a, b) => a + b,
        }
    }

    /// The bytes of the body itself: `size` copies of `letter`.
    fn payload(self, letter: u8) -> Vec<u8> {
        vec![letter; self.size()]
    }

    /// The body as it goes over the wire.
    fn encoded(self, letter: u8) -> Vec<u8> {
        match self {
            Body::Chunked(a, b) => {
                let mut bytes = Vec::new();
                for size in [a, b].into_iter().filter(|&n| n > 0) {
                    bytes.extend_from_slice(format!("{size:x}\r\n").as_bytes());
                    bytes.extend(std::iter::repeat_n(letter, size));
                    bytes.extend_from_slice(b"\r\n");
                }
                bytes.extend_from_slice(b"0\r\n\r\n");
                bytes
            }
            other => other.payload(letter),
        }
    }
}

/// What the client sends for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ask {
    method: &'static str,
    version: Version,
    host: &'static str,
    close: bool,
    body: Body,
    /// "Expect: 100-continue", and the client holds its body back for it.
    expect: bool,
    upgrade: bool,
    /// The head is not HTTP at all.
    garbage: bool,
}

const GET: Ask = Ask {
    method: "GET",
    version: Version::V11,
    host: "site.test",
    close: false,
    body: Body::None,
    expect: false,
    upgrade: false,
    garbage: false,
};

impl Ask {
    fn head(self, number: usize) -> Vec<u8> {
        if self.garbage {
            return b"\x16\x03\x01 not http\r\n\r\n".to_vec();
        }
        let version = if self.version == Version::V10 { "1.0" } else { "1.1" };
        let mut head = format!(
            "{} /r{number} HTTP/{version}\r\nHost: {}\r\nX-Mark: {number}\r\n",
            self.method, self.host
        );
        match self.body {
            Body::Length(n) => head.push_str(&format!("Content-Length: {n}\r\n")),
            Body::Chunked(..) => head.push_str("Transfer-Encoding: chunked\r\n"),
            _ => {}
        }
        if self.close {
            head.push_str("Connection: close\r\n");
        }
        if self.expect {
            head.push_str("Expect: 100-continue\r\n");
        }
        if self.upgrade {
            head.push_str("Upgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: k\r\n");
        }
        head.push_str("\r\n");
        head.into_bytes()
    }

    fn letter(number: usize) -> u8 {
        b'A' + u8::try_from(number).unwrap()
    }

    /// Whether the proxy forwards this request at all.
    fn accepted(self) -> bool {
        !self.garbage && self.host == "site.test" && self.body.size() <= MAX_BODY
    }

    /// The status of our own answer to a request we do not forward.
    fn refusal(self) -> u16 {
        if self.garbage {
            400
        } else if self.host == "tls.test" {
            301
        } else if self.host != "site.test" {
            404
        } else {
            413
        }
    }

    fn is_upgrade(self) -> bool {
        self.upgrade && self.version == Version::V11 && self.method == "GET"
    }

    /// The request exactly as its upstream must receive it.
    fn upstream_bytes(self, number: usize) -> Vec<u8> {
        let via = if self.version == Version::V10 { "1.0" } else { "1.1" };
        let mut head = format!("{} /r{number} HTTP/1.1\r\nX-Mark: {number}\r\n", self.method);
        if self.is_upgrade() {
            head.push_str("Sec-WebSocket-Key: k\r\n");
        }
        head.push_str(&format!(
            "Host: site.test\r\nX-Real-IP: 192.0.2.7\r\nX-Forwarded-For: 192.0.2.7\r\n\
             X-Forwarded-Proto: http\r\nVia: {via} shioko\r\n"
        ));
        match self.body {
            Body::Length(n) => head.push_str(&format!("Content-Length: {n}\r\n")),
            Body::Chunked(..) => head.push_str("Transfer-Encoding: chunked\r\n"),
            _ => {}
        }
        head.push_str(if self.is_upgrade() {
            "Connection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        } else {
            "Connection: close\r\n\r\n"
        });
        let mut bytes = head.into_bytes();
        bytes.extend(self.body.encoded(Ask::letter(number)));
        bytes
    }
}

/// What the upstream does for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    /// A final response, perhaps after a 103.
    Final { status: u16, body: Body, interim: bool },
    /// A 101 that accepts the upgrade, followed by this many raw bytes.
    Switch(usize),
    /// Something that is not an HTTP response.
    Garbage,
    /// The connection cannot be made; the client gets this status.
    Unreachable(u16),
}

const OK: Reply = Reply::Final { status: 200, body: Body::Length(4), interim: false };

impl Reply {
    fn letter(number: usize) -> u8 {
        b'a' + u8::try_from(number).unwrap()
    }

    fn bytes(self, number: usize) -> Vec<u8> {
        match self {
            Reply::Final { status, body, interim } => {
                let mut head = String::new();
                if interim {
                    head.push_str(&format!("HTTP/1.1 103 Early Hints\r\nX-Hint: {number}\r\n\r\n"));
                }
                head.push_str(&format!("HTTP/1.1 {status} Fine\r\nX-Mark: {number}\r\n"));
                match body {
                    Body::Length(n) => head.push_str(&format!("Content-Length: {n}\r\n")),
                    Body::Chunked(..) => head.push_str("Transfer-Encoding: chunked\r\n"),
                    _ => {}
                }
                head.push_str("Connection: close\r\nKeep-Alive: timeout=5\r\n\r\n");
                let mut bytes = head.into_bytes();
                bytes.extend(body.encoded(Reply::letter(number)));
                bytes
            }
            Reply::Switch(raw) => {
                let mut bytes = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                                  Connection: Upgrade\r\nSec-WebSocket-Accept: a\r\n\r\n"
                    .to_vec();
                bytes.extend(std::iter::repeat_n(Reply::letter(number), raw));
                bytes
            }
            Reply::Garbage => b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(),
            Reply::Unreachable(_) => Vec::new(),
        }
    }
}

/// One exchange: what is asked and what the upstream does about it.
type Exchange = (Ask, Reply);

/// How the bytes of a stream are handed to the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Feed {
    /// All in one read, then the peer's side ends.
    Whole,
    /// One byte per read.
    Bytes,
    /// Two reads, split at this offset.
    Split(usize),
    /// Only this many bytes, then the peer's side ends.
    CutEnd(usize),
    /// Only this many bytes, then nothing comes any more.
    CutStall(usize),
}

impl Feed {
    fn steps(self, bytes: &[u8]) -> Vec<Step> {
        let data = |piece: &[u8]| Step::Data(piece.to_vec());
        let at = |offset: usize| offset.min(bytes.len());
        match self {
            Feed::Whole => vec![data(bytes), Step::End],
            Feed::Bytes => bytes.iter().map(|b| data(&[*b])).chain([Step::End]).collect(),
            Feed::Split(n) => vec![data(&bytes[..at(n)]), data(&bytes[at(n)..]), Step::End],
            Feed::CutEnd(n) => vec![data(&bytes[..at(n)]), Step::End],
            Feed::CutStall(n) => vec![data(&bytes[..at(n)]), Step::Timeout],
        }
    }
}

const MAX_BODY: usize = 6;
const PEER: &str = "192.0.2.7";

fn config() -> Config {
    let site = |name: &str, websocket: bool, cert: bool| Site {
        name: name.to_string(),
        upstream: "upstream.test:1".to_string(),
        cert: cert.then(|| "/chain.pem".into()),
        key: cert.then(|| "/key.pem".into()),
        websocket,
        allow: None,
        max_body: MAX_BODY as u64,
    };
    let mut locked = site("locked.test", false, false);
    locked.allow = Some(vec![crate::net::Range::parse("10.0.0.0/8").unwrap()]);
    Config { sites: vec![site("site.test", true, false), site("tls.test", false, true), locked] }
}

/// Hands out scripted upstreams in order and keeps them for inspection.
#[derive(Default)]
struct Upstreams {
    scripts: Mutex<VecDeque<Result<Vec<Step>, u16>>>,
    made: Mutex<Vec<Arc<Script>>>,
    /// Writes to the upstreams fail after this many bytes.
    write_limit: Option<usize>,
}

impl Connect for Upstreams {
    type Upstream = Arc<Script>;

    fn connect(&self, address: &str) -> Result<Arc<Script>, u16> {
        assert_eq!(address, "upstream.test:1");
        let steps = self.scripts.lock().unwrap().pop_front().unwrap_or(Ok(vec![Step::End]))?;
        let script = match self.write_limit {
            Some(limit) => Script::new(steps).failing_after(limit),
            None => Script::new(steps),
        };
        let script = Arc::new(script);
        self.made.lock().unwrap().push(Arc::clone(&script));
        Ok(script)
    }
}

/// One response as the client received it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Seen {
    status: u16,
    head: String,
    body: Vec<u8>,
    /// The client can tell the response is over without the connection
    /// closing.
    ended: bool,
}

impl Seen {
    fn has(&self, line: &str) -> bool {
        self.head.split("\r\n").any(|l| l.eq_ignore_ascii_case(line))
    }

    fn mark(&self) -> Option<usize> {
        self.head.split("\r\n").find_map(|l| l.strip_prefix("X-Mark: ")?.parse().ok())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads what the client received the way a client would. `methods` are the
/// methods of the requests it sent, in order.
fn responses(mut bytes: &[u8], methods: &[&str]) -> Vec<Seen> {
    let mut seen = Vec::new();
    let mut finals = 0;
    while let Some(end) = find(bytes, b"\r\n\r\n") {
        let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
        bytes = &bytes[end + 4..];
        let status: u16 = head[9..12].parse().unwrap();
        assert!(head.starts_with("HTTP/1.1 "), "{head}");
        let mut one = Seen { status, head, ..Seen::default() };
        if status == 101 {
            one.body = bytes.to_vec();
            seen.push(one);
            return seen;
        }
        if status < 200 {
            one.ended = true;
            seen.push(one);
            continue;
        }
        let method = methods.get(finals).copied().unwrap_or("GET");
        finals += 1;
        let length = one.head.split("\r\n").find_map(|l| l.strip_prefix("Content-Length: "));
        if method == "HEAD" || status == 204 || status == 304 {
            one.ended = true;
        } else if one.has("Transfer-Encoding: chunked") {
            while let Some(line_end) = find(bytes, b"\r\n") {
                let size = usize::from_str_radix(std::str::from_utf8(&bytes[..line_end]).unwrap(), 16).unwrap();
                let rest = &bytes[line_end + 2..];
                if rest.len() < size + 2 {
                    one.body.extend_from_slice(&rest[..size.min(rest.len())]);
                    bytes = &[];
                    break;
                }
                one.body.extend_from_slice(&rest[..size]);
                assert_eq!(&rest[size..size + 2], b"\r\n");
                bytes = &rest[size + 2..];
                if size == 0 {
                    one.ended = true;
                    break;
                }
            }
        } else if let Some(length) = length {
            let length: usize = length.parse().unwrap();
            let have = length.min(bytes.len());
            one.body = bytes[..have].to_vec();
            one.ended = have == length;
            bytes = &bytes[have..];
        } else {
            one.body = bytes.to_vec();
            bytes = &[];
        }
        let over = !one.ended;
        seen.push(one);
        if over {
            break;
        }
    }
    assert!(bytes.is_empty() || !seen.last().is_some_and(|s| s.ended), "bytes after the last response");
    seen
}

/// Everything about one run of the proxy.
struct Run {
    exchanges: Vec<Exchange>,
    client_feed: Feed,
    upstream_feed: Feed,
    client: Script,
    upstreams: Vec<Arc<Script>>,
    log: Vec<String>,
}

impl Run {
    fn seen(&self) -> Vec<Seen> {
        let methods: Vec<&str> = self.exchanges.iter().map(|(ask, _)| ask.method).collect();
        responses(&self.client.written(), &methods)
    }

    fn finals(&self) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.status >= 200 || s.status == 101).collect()
    }

    /// The requests the proxy should get to, given that nothing is cut:
    /// each one is reached only if the exchange before left the connection
    /// open and at a message boundary.
    fn reached(&self) -> usize {
        let mut reached = 0;
        for exchange in &self.exchanges {
            reached += 1;
            if !kept(*exchange) {
                break;
            }
        }
        reached
    }

    /// The exchanges that get an upstream connection, with their numbers.
    fn forwarded(&self) -> Vec<(usize, Ask, Reply)> {
        self.exchanges
            .iter()
            .enumerate()
            .take(self.reached())
            .filter(|(_, (ask, reply))| ask.accepted() && !matches!(reply, Reply::Unreachable(_)))
            .map(|(number, (ask, reply))| (number, *ask, *reply))
            .collect()
    }
}

fn client_bytes(exchanges: &[Exchange], tail: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (number, (ask, _)) in exchanges.iter().enumerate() {
        bytes.extend(ask.head(number));
        if !ask.garbage {
            bytes.extend(ask.body.encoded(Ask::letter(number)));
        }
    }
    bytes.extend_from_slice(tail);
    bytes
}

/// Plays `exchanges` to the proxy. `client_feed` says how the client's
/// bytes arrive, `upstream_feed` how the first upstream's do; the other
/// upstreams answer in one piece.
fn run(exchanges: &[Exchange], tail: &[u8], client_feed: Feed, upstream_feed: Feed) -> Run {
    let mut client_steps = Vec::new();
    let patient = exchanges.iter().any(|(ask, _)| ask.expect);
    if patient && client_feed == Feed::Whole {
        // A client that waits for "100 Continue" sends each body only once
        // it has seen it.
        for (number, (ask, _)) in exchanges.iter().enumerate() {
            client_steps.push(Step::Data(ask.head(number)));
            let body = ask.body.encoded(Ask::letter(number));
            client_steps.push(if ask.expect { Step::AfterContinue(body) } else { Step::Data(body) });
        }
        client_steps.push(Step::Data(tail.to_vec()));
        client_steps.push(Step::End);
    } else {
        client_steps = client_feed.steps(&client_bytes(exchanges, tail));
    }
    let client = Script::new(client_steps);
    let upstreams = Upstreams::default();
    let mut first = true;
    for (number, (ask, reply)) in exchanges.iter().enumerate() {
        if !ask.accepted() {
            continue;
        }
        let script = match reply {
            Reply::Unreachable(status) => Err(*status),
            reply => {
                let feed = if first { upstream_feed } else { Feed::Whole };
                first = false;
                Ok(feed.steps(&reply.bytes(number)))
            }
        };
        upstreams.scripts.lock().unwrap().push_back(script);
    }
    let config = config();
    let log = Kept::default();
    let peer: IpAddr = PEER.parse().unwrap();
    let context = Context {
        config: &config,
        connect: &upstreams,
        log: &log,
        peer,
        tls_site: None,
        acme: Path::new("/nonexistent"),
        clock: || 0,
        timeouts: Timeouts::STANDARD,
    };
    proxy::serve(&client, &context);
    Run {
        exchanges: exchanges.to_vec(),
        client_feed,
        upstream_feed,
        client,
        upstreams: upstreams.made.into_inner().unwrap(),
        log: log.0.into_inner().unwrap(),
    }
}

/// The shapes of request and response the sweeps combine.
fn asks() -> Vec<Ask> {
    vec![
        GET,
        Ask { close: true, ..GET },
        Ask { version: Version::V10, ..GET },
        Ask { method: "HEAD", ..GET },
        Ask { method: "POST", body: Body::Length(3), ..GET },
        Ask { method: "POST", body: Body::Length(0), ..GET },
        Ask { method: "POST", body: Body::Chunked(2, 1), ..GET },
        Ask { method: "POST", body: Body::Chunked(0, 0), ..GET },
        Ask { method: "PUT", body: Body::Length(3), expect: true, ..GET },
        Ask { method: "PUT", body: Body::Chunked(1, 2), expect: true, ..GET },
        Ask { method: "POST", body: Body::Length(3), version: Version::V10, ..GET },
        Ask { method: "POST", body: Body::Length(MAX_BODY + 1), ..GET },
        Ask { host: "unknown.test", ..GET },
        Ask { host: "tls.test", ..GET },
        Ask { garbage: true, ..GET },
    ]
}

fn replies() -> Vec<Reply> {
    let reply = |status, body, interim| Reply::Final { status, body, interim };
    vec![
        OK,
        reply(200, Body::Length(0), false),
        reply(200, Body::Chunked(3, 1), false),
        reply(200, Body::Chunked(0, 0), false),
        reply(200, Body::ToEnd(4), false),
        reply(204, Body::None, false),
        reply(304, Body::None, false),
        reply(404, Body::Length(2), true),
        reply(200, Body::Chunked(2, 2), true),
        Reply::Garbage,
        Reply::Unreachable(502),
        Reply::Unreachable(504),
    ]
}

/// The first exchange leaves the connection open for a second one.
fn kept((ask, reply): Exchange) -> bool {
    ask.accepted() && ask.version == Version::V11 && !ask.close && matches!(reply, Reply::Final { .. })
}

/// Every single exchange, and every pair of exchanges on one connection
/// whose first leaves the connection open.
fn scenarios() -> Vec<Vec<Exchange>> {
    let mut all = Vec::new();
    for ask in asks() {
        for reply in replies() {
            all.push(vec![(ask, reply)]);
        }
    }
    let seconds = [
        (GET, OK),
        (Ask { method: "POST", body: Body::Length(3), ..GET }, Reply::Final { status: 200, body: Body::Chunked(3, 1), interim: false }),
        (Ask { method: "POST", body: Body::Chunked(2, 1), close: true, ..GET }, Reply::Final { status: 200, body: Body::ToEnd(4), interim: false }),
        (Ask { garbage: true, ..GET }, OK),
    ];
    for ask in asks() {
        for reply in replies() {
            for second in seconds {
                if kept((ask, reply)) {
                    all.push(vec![(ask, reply), second]);
                }
            }
        }
    }
    all
}

/// Runs every scenario with the reads falling in every way: whole, byte by
/// byte, and split once at every offset of the client's and of the first
/// upstream's stream. Nothing is cut short.
fn every_run(mut check: impl FnMut(&Run)) {
    for exchanges in scenarios() {
        let client_len = client_bytes(&exchanges, b"").len();
        let upstream_len = exchanges
            .iter()
            .enumerate()
            .find(|(_, (ask, _))| ask.accepted())
            .map_or(0, |(number, (_, reply))| reply.bytes(number).len());
        let mut feeds = vec![(Feed::Whole, Feed::Whole), (Feed::Bytes, Feed::Bytes)];
        feeds.extend((1..client_len).map(|n| (Feed::Split(n), Feed::Whole)));
        feeds.extend((1..upstream_len).map(|n| (Feed::Whole, Feed::Split(n))));
        for (client_feed, upstream_feed) in feeds {
            check(&run(&exchanges, b"", client_feed, upstream_feed));
        }
    }
}

/// Runs every scenario with one of its streams stopping at every offset:
/// the client's or the first upstream's, by ending or by going silent.
fn every_cut_run(mut check: impl FnMut(&Run)) {
    for exchanges in scenarios() {
        let client_len = client_bytes(&exchanges, b"").len();
        let upstream_len = exchanges
            .iter()
            .enumerate()
            .find(|(_, (ask, _))| ask.accepted())
            .map_or(0, |(number, (_, reply))| reply.bytes(number).len());
        for n in 0..client_len {
            check(&run(&exchanges, b"", Feed::CutEnd(n), Feed::Whole));
            check(&run(&exchanges, b"", Feed::CutStall(n), Feed::Whole));
        }
        for n in 0..upstream_len {
            check(&run(&exchanges, b"", Feed::Whole, Feed::CutEnd(n)));
            check(&run(&exchanges, b"", Feed::Whole, Feed::CutStall(n)));
        }
    }
}

fn describe(run: &Run) -> String {
    format!("{:?} client {:?} upstream {:?}", run.exchanges, run.client_feed, run.upstream_feed)
}

// --------------------------------------------- what holds of every run

/// An upstream receives exactly the client's own request and nothing else:
/// its head, written by us, then its body to the last byte, and no byte of
/// another request.
#[test]
fn request_intact() {
    every_run(|run| {
        let forwarded = run.forwarded();
        assert_eq!(run.upstreams.len(), forwarded.len(), "{}", describe(run));
        for (upstream, (number, ask, _)) in run.upstreams.iter().zip(forwarded) {
            assert_eq!(
                String::from_utf8_lossy(&upstream.written()),
                String::from_utf8_lossy(&ask.upstream_bytes(number)),
                "{}",
                describe(run)
            );
        }
    });
    every_cut_run(|run| {
        let numbers: Vec<usize> =
            run.exchanges.iter().enumerate().filter(|(_, (a, _))| a.accepted()).map(|(n, _)| n).collect();
        for (upstream, number) in run.upstreams.iter().zip(numbers) {
            let whole = run.exchanges[number].0.upstream_bytes(number);
            assert!(whole.starts_with(&upstream.written()), "{}", describe(run));
        }
    });
}

/// A request head is looked for only where one starts. With two requests
/// sent back to back, bodies included, the second is found whole however
/// the reads fall.
#[test]
fn head_at_boundary() {
    let first = Ask { method: "POST", body: Body::Chunked(2, 1), ..GET };
    let second = Ask { method: "POST", body: Body::Length(3), ..GET };
    let exchanges = [(first, OK), (second, OK)];
    let length = client_bytes(&exchanges, b"").len();
    for feed in (1..length).map(Feed::Split).chain([Feed::Whole, Feed::Bytes]) {
        let run = run(&exchanges, b"", feed, Feed::Whole);
        assert_eq!(run.upstreams.len(), 2, "{feed:?}");
        assert_eq!(run.upstreams[1].written(), second.upstream_bytes(1), "{feed:?}");
        assert_eq!(run.finals().iter().map(|s| s.status).collect::<Vec<_>>(), [200, 200]);
    }
}

/// The upstream is asked for its response only after it has the whole
/// request.
#[test]
fn response_after_request() {
    every_run(|run| {
        for (upstream, (number, ask, _)) in run.upstreams.iter().zip(run.forwarded()) {
            let whole = ask.upstream_bytes(number).len();
            assert_eq!(upstream.written_at_first_read(), Some(whole), "{}", describe(run));
        }
    });
    every_cut_run(|run| {
        let numbers: Vec<usize> =
            run.exchanges.iter().enumerate().filter(|(_, (a, _))| a.accepted()).map(|(n, _)| n).collect();
        for (upstream, number) in run.upstreams.iter().zip(numbers) {
            if let Some(at) = upstream.written_at_first_read() {
                assert_eq!(at, run.exchanges[number].0.upstream_bytes(number).len(), "{}", describe(run));
            }
        }
    });
}

/// Nothing of a refused request is forwarded: no upstream connection is
/// made for it, and its client is not asked to send the body.
#[test]
fn refused_never_forwarded() {
    let refused = |run: &Run| {
        let (first, _) = run.exchanges[0];
        if !first.accepted() {
            assert!(run.upstreams.is_empty(), "{}", describe(run));
            assert!(!contains(&run.client.written(), b"100 Continue"), "{}", describe(run));
        }
    };
    every_run(refused);
    every_cut_run(refused);
    // Also when the request asks for "100 Continue".
    for ask in [
        Ask { method: "PUT", body: Body::Length(3), expect: true, host: "unknown.test", ..GET },
        Ask { method: "PUT", body: Body::Length(MAX_BODY + 1), expect: true, ..GET },
        Ask { method: "PUT", body: Body::Length(3), expect: true, host: "tls.test", ..GET },
    ] {
        let run = run(&[(ask, OK)], b"", Feed::Whole, Feed::Whole);
        assert!(run.upstreams.is_empty());
        assert!(!contains(&run.client.written(), b"100 Continue"));
        assert_eq!(run.finals()[0].status, ask.refusal());
    }
}

/// "100 Continue" goes out before we wait for a body whose client expects
/// it, only once the upstream is connected, and for no other request.
#[test]
fn continue_in_time() {
    every_run(|run| {
        assert!(!run.client.read_before_continue(), "{}", describe(run));
        let expected = run
            .exchanges
            .iter()
            .take(run.reached())
            .filter(|(ask, reply)| ask.expect && ask.accepted() && !matches!(reply, Reply::Unreachable(_)))
            .count();
        let sent = run.seen().iter().filter(|s| s.status == 100).count();
        assert_eq!(sent, expected, "{}", describe(run));
    });
    // If the upstream cannot be reached, the client is told so and is never
    // asked for the body.
    let ask = Ask { method: "PUT", body: Body::Length(3), expect: true, ..GET };
    let run = run(&[(ask, Reply::Unreachable(502))], b"", Feed::Whole, Feed::Whole);
    assert_eq!(run.seen().iter().map(|s| s.status).collect::<Vec<_>>(), [502]);
}

/// An HTTP/1.0 client is never sent a 1xx response.
#[test]
fn no_interim_to_http10() {
    let check = |run: &Run| {
        let finals = run.finals().len();
        for (number, seen) in run.seen().iter().enumerate() {
            if seen.status < 200 && seen.status != 101 {
                // The interim responses of an exchange come before its
                // final one, so the exchange is the one not yet answered.
                let answered = run.seen()[..number].iter().filter(|s| s.status >= 200).count();
                let (ask, _) = run.exchanges[answered.min(finals)];
                assert_eq!(ask.version, Version::V11, "{}", describe(run));
            }
        }
    };
    every_run(check);
    let old = Ask { version: Version::V10, method: "POST", body: Body::Length(3), expect: true, ..GET };
    let hinted = Reply::Final { status: 200, body: Body::Length(4), interim: true };
    let run = run(&[(old, hinted)], b"", Feed::Bytes, Feed::Bytes);
    assert_eq!(run.seen().iter().map(|s| s.status).collect::<Vec<_>>(), [200]);
    assert_eq!(run.upstreams[0].written(), old.upstream_bytes(0));
}

/// Responses reach the client in the order of the requests, one after the
/// other.
#[test]
fn responses_in_order() {
    let check = |run: &Run| {
        let marks: Vec<usize> = run.seen().iter().filter_map(Seen::mark).collect();
        assert!(marks.is_sorted(), "{}", describe(run));
        let hints = run.seen().iter().filter(|s| s.status == 103).count();
        // Each exchange contributes its interim response at most once and
        // its final response at most once.
        let mut dedup = marks.clone();
        dedup.dedup();
        assert!(marks.len() <= dedup.len() + hints, "{}", describe(run));
    };
    every_run(check);
    every_cut_run(check);
}

/// One final response per request: never more responses than requests,
/// nothing after an error response, and nothing after a response that only
/// closing ends.
#[test]
fn one_final_response() {
    let check = |run: &Run| {
        let finals = run.finals();
        assert!(finals.len() <= run.exchanges.len(), "{}", describe(run));
        if let Some(early) = finals.iter().rev().skip(1).find(|s| !s.ended || s.has("Connection: close")) {
            panic!("a response after {early:?}: {}", describe(run));
        }
    };
    every_run(check);
    every_cut_run(check);
}

/// What the client receives of a response is what that request's upstream
/// sent: the same status, the same body bytes in order, none missing in
/// between, and nothing that was not part of the response.
#[test]
fn response_intact() {
    every_run(|run| {
        let finals = run.finals();
        for (seen, (number, ask, reply)) in finals.iter().zip(
            run.exchanges.iter().enumerate().take(run.reached()).map(|(n, (a, r))| (n, *a, *r)),
        ) {
            let (status, body) = match reply {
                _ if !ask.accepted() => (ask.refusal(), None),
                Reply::Final { status, body, .. } => (status, Some(body)),
                Reply::Unreachable(status) => (status, None),
                _ => (502, None),
            };
            assert_eq!(seen.status, status, "{}", describe(run));
            if let Some(body) = body {
                let payload = if ask.method == "HEAD" { vec![] } else { body.payload(Reply::letter(number)) };
                assert_eq!(seen.body, payload, "{}", describe(run));
                assert_eq!(seen.mark(), Some(number), "{}", describe(run));
            }
        }
        assert_eq!(finals.len(), run.reached(), "{}", describe(run));
    });
    every_cut_run(|run| {
        for seen in run.finals() {
            let Some(number) = seen.mark() else { continue };
            let (_, reply) = run.exchanges[number];
            if let Reply::Final { body, .. } = reply {
                assert!(body.payload(Reply::letter(number)).starts_with(&seen.body), "{}", describe(run));
            }
        }
    });
}

/// A response to the client is marked as ended only when the upstream's
/// body is known to be complete, so a response that was cut off looks cut
/// off.
#[test]
fn end_only_when_whole() {
    every_cut_run(|run| {
        if run.client_feed != Feed::Whole {
            return;
        }
        let Some((number, ask, reply)) = run.forwarded().into_iter().next() else { return };
        let Reply::Final { body, .. } = reply else { return };
        let whole = reply.bytes(number).len();
        let (Feed::CutEnd(cut) | Feed::CutStall(cut)) = run.upstream_feed else { return };
        let Some(seen) = run.finals().into_iter().find(|s| s.mark() == Some(number)) else { return };
        if ask.method == "HEAD" || matches!(seen.status, 204 | 304) || ask.version == Version::V10 {
            return;
        }
        // A body that runs to the end of the connection is complete
        // whenever the upstream closes; one that stalls is not.
        let complete = match body {
            Body::ToEnd(_) => run.upstream_feed == Feed::CutEnd(cut),
            _ => cut == whole,
        };
        assert_eq!(seen.ended, complete, "{seen:?} {}", describe(run));
    });
}

/// The next request is read only at a message boundary on both streams:
/// exactly the requests are reached whose predecessors were forwarded whole
/// and answered with a response the client can tell the end of.
#[test]
fn next_request_at_boundary() {
    every_run(|run| {
        assert_eq!(run.finals().len(), run.reached(), "{}", describe(run));
        assert_eq!(run.upstreams.len(), run.forwarded().len(), "{}", describe(run));
        for seen in run.finals().iter().rev().skip(1) {
            assert!(seen.ended, "{}", describe(run));
        }
    });
    every_cut_run(|run| {
        // However a stream is cut, a later request is served only if the
        // response before it was complete.
        for seen in run.finals().iter().rev().skip(1) {
            assert!(seen.ended, "{}", describe(run));
        }
        assert!(run.upstreams.len() <= run.finals().len() + 1, "{}", describe(run));
    });
}

/// After "Connection: close", from either side, no further request is
/// read; and the client is told "close" exactly when we will close.
#[test]
fn close_honoured() {
    every_run(|run| {
        let finals = run.finals();
        for (index, (seen, (ask, _))) in finals.iter().zip(&run.exchanges).enumerate() {
            let last = index + 1 == run.reached();
            let asked_to_close = ask.close || ask.version == Version::V10;
            if asked_to_close || seen.has("Connection: close") {
                assert_eq!(index + 1, finals.len(), "{}", describe(run));
            }
            if asked_to_close || !ask.accepted() {
                assert!(seen.has("Connection: close"), "{}", describe(run));
            }
            if !last {
                assert!(!seen.has("Connection: close"), "{}", describe(run));
            }
            assert!(!seen.has("Keep-Alive: timeout=5"), "{}", describe(run));
        }
    });
}

/// Every request that was read gets its final response, unless the client
/// itself went away.
#[test]
fn every_request_answered() {
    every_run(|run| {
        assert_eq!(run.finals().len(), run.reached(), "{}", describe(run));
        assert!(run.client.was_shut(), "{}", describe(run));
        // One line in the log for each of them.
        assert_eq!(run.log.len(), run.reached(), "{:?} {}", run.log, describe(run));
    });
    // When an upstream stops in the middle of anything, the client still
    // gets one response for every request that was read.
    every_cut_run(|run| {
        if run.client_feed == Feed::Whole {
            assert!(run.finals().len() >= run.upstreams.len(), "{}", describe(run));
            assert!(!run.finals().is_empty(), "{}", describe(run));
        }
    });
}

// ----------------------------------------------------------------- tunnels

const UPGRADE: Ask = Ask { upgrade: true, ..GET };

/// A tunnel is opened only for an upgrade request that the upstream answers
/// with 101; bytes already read from either side go into it first, in
/// order; and no HTTP message follows it.
#[test]
fn tunnel_rules() {
    let raw = b"RAW-FROM-CLIENT";
    let length = client_bytes(&[(UPGRADE, Reply::Switch(5))], raw).len();
    for feed in (1..length).map(Feed::Split).chain([Feed::Whole, Feed::Bytes]) {
        for upstream_feed in [Feed::Whole, Feed::Bytes, Feed::Split(40)] {
            let run = run(&[(UPGRADE, Reply::Switch(5)), (GET, OK)], raw, feed, upstream_feed);
            assert_eq!(run.upstreams.len(), 1, "{feed:?}");
            let sent = run.upstreams[0].written();
            let head = UPGRADE.upstream_bytes(0);
            assert!(sent.starts_with(&head), "{}", String::from_utf8_lossy(&sent));
            // What follows the head is what the client sent after its
            // request, untouched, also where it looks like HTTP; a prefix
            // of it at least, as the tunnel may end as soon as the
            // upstream's side does.
            let after_head = client_bytes(&[(UPGRADE, OK), (GET, OK)], raw);
            assert!(after_head[UPGRADE.head(0).len()..].starts_with(&sent[head.len()..]), "{feed:?}");
            let seen = run.seen();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].status, 101);
            assert!(seen[0].has("Upgrade: websocket") && seen[0].has("Connection: upgrade"));
            assert!(seen[0].has("Sec-WebSocket-Accept: a"));
            assert!(b"aaaaa".starts_with(&seen[0].body), "{feed:?}");
            assert!(run.client.was_shut() && run.upstreams[0].was_shut());
        }
    }
    // With the upstream's bytes in one piece, all of them arrive.
    let run = run(&[(UPGRADE, Reply::Switch(5))], raw, Feed::Whole, Feed::Whole);
    assert_eq!(run.seen()[0].body, b"aaaaa");
}

#[test]
fn a_101_nobody_asked_for_is_a_bad_gateway() {
    let run = run(&[(GET, Reply::Switch(3))], b"", Feed::Whole, Feed::Whole);
    assert_eq!(run.finals().iter().map(|s| s.status).collect::<Vec<_>>(), [502]);
    assert!(!contains(&run.client.written(), b"aaa"));
}

#[test]
fn an_upgrade_the_upstream_declines_is_an_ordinary_exchange() {
    let run = run(&[(UPGRADE, OK), (GET, OK)], b"", Feed::Whole, Feed::Whole);
    assert_eq!(run.finals().iter().map(|s| s.status).collect::<Vec<_>>(), [200, 200]);
    assert!(!run.finals()[0].has("Upgrade: websocket"));
}

#[test]
fn what_is_not_a_websocket_upgrade_is_not_forwarded_as_one() {
    for ask in [
        Ask { version: Version::V10, ..UPGRADE },
        Ask { method: "POST", ..UPGRADE },
        Ask { method: "POST", body: Body::Length(2), ..UPGRADE },
        Ask { expect: true, ..UPGRADE },
    ] {
        let run = run(&[(ask, Reply::Switch(3))], b"", Feed::Whole, Feed::Whole);
        let sent = String::from_utf8(run.upstreams[0].written()).unwrap();
        assert!(sent.contains("\r\nConnection: close\r\n"), "{ask:?}");
        assert!(!sent.to_ascii_lowercase().contains("upgrade"), "{ask:?}");
        // The upstream answered 101 to a request that did not ask for it.
        assert_eq!(run.finals()[0].status, 502, "{ask:?}");
    }
}

// ------------------------------------------------- particular behaviours

/// One conversation spelled out byte for byte.
struct Talk {
    peer: &'static str,
    /// The connection came in over TLS for this site.
    tls: Option<&'static str>,
    acme: std::path::PathBuf,
    /// Writes to the upstream fail after this many bytes.
    upstream_write_limit: Option<usize>,
    timeouts: Timeouts,
}

impl Default for Talk {
    fn default() -> Self {
        Talk {
            peer: PEER,
            tls: None,
            acme: "/nonexistent".into(),
            upstream_write_limit: None,
            timeouts: Timeouts::STANDARD,
        }
    }
}

impl Talk {
    /// Sends `request` and lets each upstream connection answer with the
    /// next of `replies`. Returns what the client received, what each
    /// upstream received, and the log.
    fn steps(&self, client: Vec<Step>, replies: Vec<Vec<Step>>) -> (String, Vec<String>, Vec<String>) {
        let client = Script::new(client);
        let upstreams = Upstreams { write_limit: self.upstream_write_limit, ..Upstreams::default() };
        upstreams.scripts.lock().unwrap().extend(replies.into_iter().map(Ok));
        let config = config();
        let log = Kept::default();
        let context = Context {
            config: &config,
            connect: &upstreams,
            log: &log,
            peer: self.peer.parse().unwrap(),
            tls_site: self.tls.map(|name| config.site(name.as_bytes()).unwrap()),
            acme: &self.acme,
            clock: || 784_111_777,
            timeouts: self.timeouts,
        };
        proxy::serve(&client, &context);
        let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
        let sent = upstreams.made.lock().unwrap().iter().map(|u| text(u.written())).collect();
        (text(client.written()), sent, log.0.into_inner().unwrap())
    }

    fn go(&self, request: &str, replies: &[&str]) -> (String, Vec<String>) {
        let data = |text: &str| vec![Step::Data(text.as_bytes().to_vec()), Step::End];
        let (received, sent, _) = self.steps(data(request), replies.iter().map(|r| data(r)).collect());
        (received, sent)
    }

    /// The status of the first response to `request`.
    fn status(&self, request: &str) -> u16 {
        let (received, _) = self.go(request, &["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]);
        received[9..12].parse().unwrap()
    }
}

const PLAIN_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

#[test]
fn the_request_head_is_written_by_us() {
    let request = "POST /path?q=1 HTTP/1.1\r\n\
                   hOsT: SITE.test:80\r\n\
                   User-Agent: test\r\n\
                   Connection: X-Secret, close\r\n\
                   X-Secret: hidden\r\n\
                   Keep-Alive: timeout=5\r\n\
                   Proxy-Connection: keep-alive\r\n\
                   TE: trailers\r\n\
                   Trailer: X-Sum\r\n\
                   Upgrade: h2c\r\n\
                   Expect: something-else\r\n\
                   X-Real-IP: 6.6.6.6\r\n\
                   X-Forwarded-Proto: https\r\n\
                   X-Forwarded-For: 1.1.1.1\r\n\
                   x-forwarded-for: 2.2.2.2\r\n\
                   Via: 1.0 fred,\r\n\
                   via:\r\n\
                   Cookie: a=b\r\n\
                   Content-Length: 2\r\n\
                   \r\nhi";
    let (_, sent) = Talk::default().go(request, &[PLAIN_OK]);
    assert_eq!(
        sent[0],
        "POST /path?q=1 HTTP/1.1\r\n\
         User-Agent: test\r\n\
         Cookie: a=b\r\n\
         Host: SITE.test:80\r\n\
         X-Real-IP: 192.0.2.7\r\n\
         X-Forwarded-For: 1.1.1.1, 2.2.2.2, 192.0.2.7\r\n\
         X-Forwarded-Proto: http\r\n\
         Via: 1.0 fred, 1.1 shioko\r\n\
         Content-Length: 2\r\n\
         Connection: close\r\n\
         \r\nhi"
    );
}

#[test]
fn the_response_head_is_written_by_us() {
    let reply = "HTTP/1.0 200 All Good\r\n\
                 Server: app\r\n\
                 Connection: X-Internal\r\n\
                 X-Internal: 1\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Upgrade: h2c\r\n\
                 Via: 1.1 inner\r\n\
                 Set-Cookie: a=b\r\n\
                 Content-Length: 2\r\n\
                 \r\nok";
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", &[reply]);
    assert_eq!(
        received,
        "HTTP/1.1 200 All Good\r\n\
         Server: app\r\n\
         Via: 1.1 inner\r\n\
         Set-Cookie: a=b\r\n\
         Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n\
         Content-Length: 2\r\n\
         \r\nok"
    );
    // A date the upstream gave is left alone.
    let reply = "HTTP/1.1 200 OK\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n";
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", &[reply]);
    assert_eq!(received.matches("Date:").count(), 1);
    assert!(received.contains("Date: Thu, 01 Jan 1970"));
}

#[test]
fn a_response_without_a_length_is_chunked_for_http11_and_closed_for_http10() {
    let reply = "HTTP/1.1 200 OK\r\n\r\nto the end";
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", &[reply]);
    assert!(received.contains("\r\nTransfer-Encoding: chunked\r\n"));
    assert!(received.ends_with("\r\n\r\na\r\nto the end\r\n0\r\n\r\n"), "{received:?}");
    assert!(!received.contains("Connection: close"));
    let (received, _) = Talk::default().go("GET / HTTP/1.0\r\nHost: site.test\r\n\r\n", &[reply]);
    assert!(received.ends_with("Connection: close\r\n\r\nto the end"), "{received:?}");
    // A chunked response for an HTTP/1.0 client loses its chunking.
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let (received, _) = Talk::default().go("GET / HTTP/1.0\r\nHost: site.test\r\n\r\n", &[chunked]);
    assert!(received.ends_with("Connection: close\r\n\r\nabc"), "{received:?}");
    assert!(!received.contains("Transfer-Encoding"));
}

#[test]
fn responses_without_a_body() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    let head = "HEAD / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    // HEAD: the length the body would have is passed on, no body is read.
    let (received, _) = Talk::default().go(head, &["HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"]);
    assert!(received.ends_with("Content-Length: 500\r\n\r\n"), "{received:?}");
    let (received, _) = Talk::default().go(get, &["HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\nETag: \"x\"\r\n\r\n"]);
    assert!(received.contains("Content-Length: 500\r\n") && received.contains("ETag: \"x\"\r\n"));
    // 204 never carries a length, whatever the upstream wrote.
    let (received, _) = Talk::default().go(get, &["HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"]);
    assert!(!received.contains("Content-Length") && !received.contains("Transfer-Encoding"));
}

#[test]
fn requests_we_refuse_and_why() {
    let host = "Host: site.test\r\n";
    let cases: Vec<(String, u16)> = vec![
        // Host.
        ("GET / HTTP/1.1\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nHost: site.test\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\nHost: site.test/x\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\nHost: user@site.test\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\nHost:\r\n\r\n".into(), 400),
        ("GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n".into(), 404),
        ("GET / HTTP/1.1\r\nHost: locked.test\r\n\r\n".into(), 403),
        // How the body is delimited.
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: 1\r\nContent-Length: 1\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: 1, 1\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: one\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: -1\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: gzip\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked, gzip\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked, chunked\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked,\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: gzip, chunked\r\n\r\n"), 501),
        (format!("POST / HTTP/1.0\r\n{host}Transfer-Encoding: chunked\r\n\r\n"), 400),
        (format!("POST / HTTP/1.1\r\n{host}Content-Length: 7\r\n\r\n1234567"), 413),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\r\n7\r\n1234567\r\n0\r\n\r\n"), 413),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\r\nzz\r\n"), 400),
        (format!("TRACE / HTTP/1.1\r\n{host}Content-Length: 1\r\n\r\nx"), 400),
        (format!("TRACE / HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), 400),
        (format!("CONNECT / HTTP/1.1\r\n{host}\r\n"), 400),
        // Without a usable Host the answer is 400, whatever else is wrong.
        ("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".into(), 400),
        (format!("{} / HTTP/1.1\r\n\r\n", "M".repeat(33)), 400),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: gzip;level=1, chunked\r\n\r\n"), 501),
        (format!("POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked;x=1\r\n\r\n"), 400),
        // The request line.
        (format!("GET http://site.test/ HTTP/1.1\r\n{host}\r\n"), 400),
        (format!("CONNECT site.test:443 HTTP/1.1\r\n{host}\r\n"), 400),
        (format!("GET * HTTP/1.1\r\n{host}\r\n"), 400),
        (format!("GET / HTTP/2.0\r\n{host}\r\n"), 400),
        (format!("GET /a b HTTP/1.1\r\n{host}\r\n"), 400),
        (format!("{} / HTTP/1.1\r\n{host}\r\n", "M".repeat(33)), 501),
        (format!("GET /{} HTTP/1.1\r\n{host}\r\n", "a".repeat(8192)), 414),
        // The fields.
        (format!("GET / HTTP/1.1\r\n{host}{}\r\n", "A: b\r\n".repeat(100)), 431),
        (format!("GET / HTTP/1.1\r\n{host}A: {}\r\nB: {}\r\n\r\n", "x".repeat(8000), "y".repeat(8400)), 431),
        (format!("GET / HTTP/1.1\r\n{host}A : b\r\n\r\n"), 400),
        (format!("GET / HTTP/1.1\r\n{host}A: b\r\n folded\r\n\r\n"), 400),
        (format!("GET / HTTP/1.1\n{host}\n"), 400),
        (format!("GET / HTTP/1.1\r\n{host}A: b\rc\r\n\r\n"), 400),
        (format!("GET / HTTP/1.1\r\n{host}A: b\u{0}c\r\n\r\n"), 400),
        // A request that has been through us eight times is in a loop.
        (format!("GET / HTTP/1.1\r\n{host}{}\r\n", "Via: 1.1 shioko\r\n".repeat(8)), 400),
        (format!("GET / HTTP/1.1\r\n{host}Via: {}\r\n\r\n", ["1.1 shioko"; 8].join(", ")), 400),
    ];
    for (request, status) in cases {
        let (received, sent) = Talk::default().go(&request, &[PLAIN_OK]);
        let shown = &request[..request.len().min(70)];
        assert_eq!(received[9..12].parse::<u16>().unwrap(), status, "{shown:?}");
        assert!(received.contains("\r\nConnection: close\r\n"), "{shown:?}");
        assert_eq!(received.matches("HTTP/1.1 ").count(), 1, "{shown:?}");
        // Only a chunked body that turns out too large or malformed gets as
        // far as an upstream, and that upstream is given no complete
        // request. Every other refusal happens before any upstream.
        let late = request.contains("chunked\r\n\r\n7\r\n") || request.contains("chunked\r\n\r\nzz");
        assert_eq!(sent.is_empty(), !late, "{shown:?}");
        if late {
            assert!(!sent[0].ends_with("0\r\n\r\n"), "{shown:?}");
        }
    }
    // What is still fine.
    for request in [
        format!("GET / HTTP/1.1\r\n{host}{}\r\n", "A: b\r\n".repeat(99)),
        format!("GET / HTTP/1.1\r\n{host}{}\r\n", "Via: 1.1 shioko\r\n".repeat(7)),
        format!("\r\nGET / HTTP/1.1\r\n{host}\r\n"),
        format!("OPTIONS * HTTP/1.1\r\n{host}\r\n"),
        format!("GET / HTTP/1.2\r\n{host}\r\n"),
        "GET / HTTP/1.1\r\nHOST: Site.Test:8080\r\n\r\n".to_string(),
        "GET / HTTP/1.1\r\nHost: site.test:\r\n\r\n".to_string(),
        format!("TRACE / HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n"),
        format!("POST / HTTP/1.1\r\n{host}Content-Length: 000000000000000000000002\r\n\r\nhi"),
        format!("GET /a|b^c[0]{{d}} HTTP/1.1\r\n{host}\r\n"),
    ] {
        assert_eq!(Talk::default().status(&request), 200, "{:?}", &request[..request.len().min(60)]);
    }
}

#[test]
fn the_allowlist_of_a_plain_site() {
    let request = "GET / HTTP/1.1\r\nHost: locked.test\r\n\r\n";
    assert_eq!(Talk::default().status(request), 403);
    assert_eq!(Talk { peer: "10.1.2.3", ..Talk::default() }.status(request), 200);
    assert_eq!(Talk { peer: "::ffff:10.1.2.3", ..Talk::default() }.status(request), 200);
}

#[test]
fn an_error_answer_to_head_has_no_body() {
    let (received, _) = Talk::default().go("HEAD / HTTP/1.1\r\nHost: unknown.test\r\n\r\n", &[]);
    assert!(received.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(received.ends_with("Content-Length: 14\r\nConnection: close\r\n\r\n"), "{received:?}");
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n", &[]);
    assert!(received.ends_with("\r\n\r\n404 Not Found\n"));
    assert!(received.contains("\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Type: text/plain\r\n"));
}

#[test]
fn a_site_with_a_certificate_is_redirected_to_https() {
    let (received, sent) = Talk::default().go("GET /a/b?c=d HTTP/1.1\r\nHost: TLS.test:80\r\n\r\n", &[]);
    assert!(received.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{received:?}");
    assert!(received.contains("\r\nLocation: https://tls.test/a/b?c=d\r\n"));
    assert!(received.contains("\r\nConnection: close\r\n"));
    assert!(sent.is_empty());
    // The location is built from the configured name and the path, and is
    // always a valid URI: what a URI may not hold is percent-encoded.
    for (target, location) in [
        ("/a\"b", "/a%22b"),
        ("/a<b>", "/a%3Cb%3E"),
        ("/a\\b", "/a%5Cb"),
        ("/a{b}|^`", "/a%7Bb%7D%7C%5E%60"),
        ("/a[0]#x", "/a%5B0%5D%23x"),
        ("/%zz%4", "/%25zz%254"),
        ("/ok%2F%20?q=1&r=a:b@c", "/ok%2F%20?q=1&r=a:b@c"),
    ] {
        let request = format!("GET {target} HTTP/1.1\r\nHost: tls.test\r\n\r\n");
        let (received, _) = Talk::default().go(&request, &[]);
        assert!(received.contains(&format!("\r\nLocation: https://tls.test{location}\r\n")), "{target}: {received:?}");
    }
    assert_eq!(Talk::default().status("OPTIONS * HTTP/1.1\r\nHost: tls.test\r\n\r\n"), 400);
    let long = format!("/{}", "a".repeat(8000));
    let (received, _) = Talk::default().go(&format!("GET {long} HTTP/1.1\r\nHost: tls.test\r\n\r\n"), &[]);
    assert!(received.contains(&format!("\r\nLocation: https://tls.test{long}\r\n")));
    // The redirect is for everyone; the allowlist is applied on port 443.
    assert_eq!(Talk { peer: "203.0.113.1", ..Talk::default() }.status("GET / HTTP/1.1\r\nHost: tls.test\r\n\r\n"), 301);
}

#[test]
fn acme_tokens_are_served_from_the_directory_for_any_host() {
    let directory = std::env::temp_dir().join(format!("shioko-acme-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("tok-EN_1"), "tok-EN_1.thumbprint").unwrap();
    std::fs::write(directory.join("huge"), vec![b'x'; 5000]).unwrap();
    std::fs::create_dir_all(directory.join("folder")).unwrap();
    let talk = Talk { acme: directory.clone(), ..Talk::default() };
    let path = "/.well-known/acme-challenge";
    for host in ["mail.example.org", "tls.test", "site.test"] {
        let (received, sent) = talk.go(&format!("GET {path}/tok-EN_1 HTTP/1.1\r\nHost: {host}\r\n\r\n"), &[]);
        assert!(received.starts_with("HTTP/1.1 200 OK\r\n"), "{received:?}");
        assert!(received.contains("\r\nContent-Type: application/octet-stream\r\nContent-Length: 19\r\n"));
        assert!(received.ends_with("\r\nConnection: close\r\n\r\ntok-EN_1.thumbprint"));
        assert!(sent.is_empty());
    }
    let (received, _) = talk.go(&format!("HEAD {path}/tok-EN_1 HTTP/1.1\r\nHost: x.test\r\n\r\n"), &[]);
    assert!(received.ends_with("Content-Length: 19\r\nConnection: close\r\n\r\n"));
    // Conditional and range headers change nothing.
    let conditional = format!(
        "GET {path}/tok-EN_1 HTTP/1.1\r\nHost: x.test\r\nIf-None-Match: *\r\nIf-Range: \"x\"\r\nRange: bytes=0-1\r\n\r\n"
    );
    assert!(talk.go(&conditional, &[]).0.ends_with("tok-EN_1.thumbprint"));
    // Only a file directly in the directory, with a name that is a token.
    for (token, status) in [("missing", 404), ("huge", 404), ("folder", 404)] {
        assert_eq!(talk.status(&format!("GET {path}/{token} HTTP/1.1\r\nHost: x.test\r\n\r\n")), status, "{token}");
    }
    for target in [
        format!("{path}/"),
        format!("{path}/..%2ftok-EN_1"),
        format!("{path}/../acme/tok-EN_1"),
        format!("{path}/tok-EN_1?x"),
        format!("{path}/{}", "a".repeat(129)),
        format!("{path}/tok.EN"),
    ] {
        // Not a token request: it is routed like any other, here to a host
        // nobody serves.
        assert_eq!(talk.status(&format!("GET {target} HTTP/1.1\r\nHost: x.test\r\n\r\n")), 404, "{target}");
    }
    assert_eq!(talk.status(&format!("POST {path}/tok-EN_1 HTTP/1.1\r\nHost: x.test\r\n\r\n")), 404);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn on_a_tls_connection_the_host_must_be_the_site_of_the_handshake() {
    let talk = Talk { tls: Some("site.test"), ..Talk::default() };
    assert_eq!(talk.status("GET / HTTP/1.1\r\nHost: tls.test\r\n\r\n"), 421);
    assert_eq!(talk.status("GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n"), 421);
    let (_, sent) = talk.go("GET /.well-known/acme-challenge/x HTTP/1.1\r\nHost: SITE.test:443\r\n\r\n", &[PLAIN_OK]);
    assert!(sent[0].starts_with("GET /.well-known/acme-challenge/x HTTP/1.1\r\n"));
    assert!(sent[0].contains("\r\nX-Forwarded-Proto: https\r\n"));
    // A site with a certificate is served here, not redirected.
    let talk = Talk { tls: Some("tls.test"), ..Talk::default() };
    assert_eq!(talk.status("GET / HTTP/1.1\r\nHost: tls.test\r\n\r\n"), 200);
}

#[test]
fn upstream_responses_we_refuse() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    for reply in [
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: two\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad Field: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA : b\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA: b\r\n folded\r\n\r\n",
        "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        "HTTP/1.1 099 Low\r\n\r\n",
        "HTTP/1.1 600 High\r\n\r\n",
        "HTTP/2 200 OK\r\n\r\n",
        "ICY 200 OK\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        "",
    ] {
        let (received, _) = Talk::default().go(get, &[reply]);
        assert!(received.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{reply:?} gave {received:?}");
        assert_eq!(received.matches("HTTP/1.1 ").count(), 1);
    }
    // An upgrade that the upstream accepts without saying to what.
    let upgrade = "GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    for reply in [
        "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
    ] {
        assert!(Talk::default().go(upgrade, &[reply]).0.starts_with("HTTP/1.1 502 "), "{reply:?}");
    }
}

#[test]
fn an_upstream_that_is_slow_is_a_gateway_timeout() {
    let get = vec![Step::Data(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n".to_vec()), Step::End];
    let (received, _, log) = Talk::default().steps(get.clone(), vec![vec![Step::Timeout]]);
    assert!(received.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"), "{received:?}");
    assert!(log[0].ends_with("ms") && log[0].contains(" 504 "), "{log:?}");
    // Once the response has begun, all that is left is to stop.
    let slow = vec![Step::Data(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab".to_vec()), Step::Timeout];
    let (received, _, _) = Talk::default().steps(get, vec![slow]);
    assert!(received.ends_with("Content-Length: 4\r\n\r\nab"), "{received:?}");
}

#[test]
fn an_upstream_that_stops_reading_is_a_bad_gateway() {
    let request = "POST / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 5\r\n\r\nhello";
    let whole = Talk::default().go(request, &[PLAIN_OK]).1[0].len();
    for limit in [0, 10, whole - 5, whole - 1] {
        let talk = Talk { upstream_write_limit: Some(limit), ..Talk::default() };
        let (received, sent) = talk.go(request, &[PLAIN_OK]);
        assert!(received.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "limit {limit}: {received:?}");
        assert_eq!(sent[0].len(), limit);
    }
}

#[test]
fn the_log_has_one_line_per_request_and_cannot_be_forged() {
    let request = "GET /a%0d%0a\"x HTTP/1.1\r\nHost: site.test\r\n\r\nGET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n";
    let data = |text: &str| vec![Step::Data(text.as_bytes().to_vec()), Step::End];
    let (_, _, log) = Talk::default().steps(data(request), vec![data(PLAIN_OK)]);
    assert_eq!(log.len(), 2);
    assert!(log[0].starts_with("192.0.2.7 site.test \"GET /a%0d%0a\\x22x\" 200 "), "{log:?}");
    assert!(log[1].starts_with("192.0.2.7 unknown.test \"GET /\" 404 "), "{log:?}");
    // A request that is not HTTP is logged without anything of its own.
    let (_, _, log) = Talk::default().steps(data("\x01\x02\r\n\r\n"), vec![]);
    assert!(log[0].starts_with("192.0.2.7 - \"- -\" 400 "), "{log:?}");
}

#[test]
fn chunk_extensions_and_trailers_are_dropped() {
    let request = "POST / HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                   3;name=value\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n";
    let reply = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                 2;x\r\nok\r\n0\r\nX-Sum: 2\r\n\r\n";
    let (received, sent) = Talk::default().go(request, &[reply]);
    assert!(sent[0].ends_with("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), "{:?}", sent[0]);
    assert!(received.ends_with("Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"), "{received:?}");
    assert!(!sent[0].contains("X-Sum") && !received.contains("X-Sum"));
}

/// A HEAD request that is refused while its head is read still gets an
/// answer without a body.
#[test]
fn a_refused_head_request_gets_no_body() {
    for request in [
        format!("HEAD / HTTP/1.1\r\nHost: site.test\r\n{}\r\n", "A: b\r\n".repeat(101)),
        "HEAD / HTTP/1.1\r\nHost: site.test\r\nA : b\r\n\r\n".to_string(),
        "HEAD http://site.test/ HTTP/1.1\r\nHost: site.test\r\n\r\n".to_string(),
        format!("HEAD /{} HTTP/1.1\r\nHost: site.test\r\n\r\n", "a".repeat(8200)),
        "HEAD /a\rb HTTP/1.1\r\nHost: site.test\r\n\r\n".to_string(),
    ] {
        let (received, _) = Talk::default().go(&request, &[]);
        assert!(received.ends_with("Connection: close\r\n\r\n"), "{received:?}");
    }
}

/// Each response is dated when it is written, not when the connection
/// started.
#[test]
fn every_response_is_dated_when_it_is_written() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);
    let client = Script::new(vec![Step::Data(
        b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\nGET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n".to_vec(),
    )]);
    let upstreams = Upstreams::default();
    upstreams.scripts.lock().unwrap().push_back(Ok(vec![Step::Data(PLAIN_OK.as_bytes().to_vec())]));
    let config = config();
    let log = Kept::default();
    let context = Context {
        config: &config,
        connect: &upstreams,
        log: &log,
        peer: PEER.parse().unwrap(),
        tls_site: None,
        acme: Path::new("/nonexistent"),
        // Every reading of the clock is a day later than the one before.
        clock: || NOW.fetch_add(86_400, Ordering::Relaxed),
        timeouts: Timeouts::STANDARD,
    };
    proxy::serve(&client, &context);
    let received = String::from_utf8(client.written()).unwrap();
    assert!(received.contains("Date: Thu, 01 Jan 1970"), "{received}");
    assert!(received.contains("Date: Fri, 02 Jan 1970"), "{received}");
}

/// Octets that are not ASCII pass through fields and reason phrases
/// unchanged, in both directions.
#[test]
fn octets_pass_through_as_they_are() {
    let request = b"GET / HTTP/1.1\r\nHost: site.test\r\nX: \xff\xfe caf\xc3\xa9\r\n\r\n";
    let client = vec![Step::Data(request.to_vec()), Step::End];
    let reply = b"HTTP/1.1 200 \x80\xc3\xa9\r\nY: \xfe\r\nContent-Length: 0\r\n\r\n";
    let script = Script::new(client);
    let upstreams = Upstreams::default();
    upstreams.scripts.lock().unwrap().push_back(Ok(vec![Step::Data(reply.to_vec())]));
    let config = config();
    let log = Kept::default();
    let context = Context {
        config: &config,
        connect: &upstreams,
        log: &log,
        peer: PEER.parse().unwrap(),
        tls_site: None,
        acme: Path::new("/nonexistent"),
        clock: || 0,
        timeouts: Timeouts::STANDARD,
    };
    proxy::serve(&script, &context);
    let sent = upstreams.made.lock().unwrap()[0].written();
    assert!(contains(&sent, b"\r\nX: \xff\xfe caf\xc3\xa9\r\n"));
    let received = script.written();
    assert!(received.starts_with(b"HTTP/1.1 200 \x80\xc3\xa9\r\nY: \xfe\r\n"));
}

#[test]
fn an_empty_reason_phrase_keeps_its_space() {
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", &["HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"]);
    assert!(received.starts_with("HTTP/1.1 200 \r\n"), "{received:?}");
}

/// Status codes we do not know are passed on as they are, interim ones
/// included.
#[test]
fn unknown_status_codes_are_relayed() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    for (reply, start) in [
        ("HTTP/1.1 299 Odd\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 299 Odd\r\n"),
        ("HTTP/1.1 599 Odd\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 599 Odd\r\n"),
        ("HTTP/1.1 150 Odd\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 150 Odd\r\n"),
        ("HTTP/1.2 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", "HTTP/1.1 200 OK\r\n"),
    ] {
        let (received, _) = Talk::default().go(get, &[reply]);
        assert!(received.starts_with(start), "{reply:?} gave {received:?}");
    }
    let (received, _) = Talk::default().go(get, &["HTTP/1.2 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"]);
    assert!(received.ends_with("\r\n\r\n2\r\nok\r\n0\r\n\r\n"));
}

/// Interim and bodiless responses lose the fields that would say how a body
/// is framed; interim ones get a Date like any other.
#[test]
fn interim_and_bodiless_responses_carry_no_framing() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    let (received, _) = Talk::default().go(
        get,
        &["HTTP/1.1 103 Hints\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nLink: </a>\r\n\r\nHTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"],
    );
    let (interim, last) = received.split_once("\r\n\r\n").unwrap();
    assert!(interim.starts_with("HTTP/1.1 103 Hints\r\nLink: </a>\r\nDate: "), "{interim:?}");
    assert!(!interim.contains("Content-Length") && !interim.contains("Transfer-Encoding"));
    assert!(last.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(!last.contains("Content-Length") && !last.contains("Transfer-Encoding"), "{last:?}");
    // Our own 100 Continue has no fields at all.
    let put = "PUT / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi";
    let (received, _) = Talk::default().go(put, &[PLAIN_OK]);
    assert!(received.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"), "{received:?}");
}

/// "100 Continue" is sent only for a request that has a body to wait for,
/// and Expect is read as a list.
#[test]
fn continue_only_for_a_body() {
    let host = "Host: site.test\r\n";
    for (request, continues) in [
        (format!("GET / HTTP/1.1\r\n{host}Expect: 100-continue\r\n\r\n"), false),
        (format!("PUT / HTTP/1.1\r\n{host}Content-Length: 0\r\nExpect: 100-continue\r\n\r\n"), false),
        (format!("PUT / HTTP/1.1\r\n{host}Content-Length: 2\r\nExpect: 100-Continue, \r\n\r\nhi"), true),
        (format!("PUT / HTTP/1.1\r\n{host}Content-Length: 2\r\nExpect: something-else\r\n\r\nhi"), false),
    ] {
        let (received, sent) = Talk::default().go(&request, &[PLAIN_OK]);
        assert_eq!(received.contains("100 Continue"), continues, "{request:?}");
        assert!(!sent[0].to_ascii_lowercase().contains("expect"), "{request:?}");
    }
}

/// What makes a request a WebSocket upgrade, and what does not.
#[test]
fn which_requests_are_upgrades() {
    let switch = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
    for (request, upgrade) in [
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n", true),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: h2c, websocket\r\nConnection: keep-alive, upgrade\r\n\r\n", true),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket,\r\nConnection: upgrade\r\n\r\n", true),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\n\r\n", false),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: h2c\r\nConnection: upgrade\r\n\r\n", false),
        ("GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: upgrade\r\nExpect: 100-continue\r\n\r\n", false),
    ] {
        let (received, sent) = Talk::default().go(request, &[switch]);
        assert_eq!(received.starts_with("HTTP/1.1 101 "), upgrade, "{request:?}: {received:?}");
        assert_eq!(sent[0].contains("\r\nUpgrade: websocket\r\n"), upgrade, "{request:?}");
    }
    // A site without websocket never gets an upgrade request.
    let talk = Talk { tls: Some("tls.test"), ..Talk::default() };
    let (received, sent) = talk.go("GET / HTTP/1.1\r\nHost: tls.test\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n", &[switch]);
    assert!(sent[0].ends_with("\r\nConnection: close\r\n\r\n") && !sent[0].contains("Upgrade"), "{:?}", sent[0]);
    assert!(received.starts_with("HTTP/1.1 502 "));
}

/// X-Forwarded-For never gets empty elements, however the client wrote
/// its own.
#[test]
fn forwarded_for_has_no_empty_elements() {
    for (fields, expected) in [
        ("X-Forwarded-For:\r\n", "192.0.2.7"),
        ("X-Forwarded-For: 1.1.1.1,\r\n", "1.1.1.1, 192.0.2.7"),
        ("X-Forwarded-For: , 1.1.1.1 ,, 2.2.2.2\r\n", "1.1.1.1, 2.2.2.2, 192.0.2.7"),
    ] {
        let (_, sent) = Talk::default().go(&format!("GET / HTTP/1.1\r\nHost: site.test\r\n{fields}\r\n"), &[PLAIN_OK]);
        assert!(sent[0].contains(&format!("\r\nX-Forwarded-For: {expected}\r\n")), "{fields:?}: {:?}", sent[0]);
    }
}

/// The fields we have no business with go to the upstream and back
/// unchanged and in order: routing, authentication, conditions, ranges.
#[test]
fn end_to_end_fields_are_passed_on_unchanged() {
    let fields = "From: a@example.org\r\nReferer: /back\r\nAuthorization: Basic eA==\r\nContent-Range: bytes 0-1/2\r\n\
                  If-Match: \"a\"\r\nIf-None-Match: *\r\nIf-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n\
                  If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nIf-Range: \"a\"\r\nRange: bytes=0-1\r\n\
                  Max-Forwards: 0\r\n";
    for method in ["GET", "OPTIONS", "TRACE", "DELETE"] {
        let (_, sent) = Talk::default().go(&format!("{method} / HTTP/1.1\r\nHost: site.test\r\n{fields}\r\n"), &[PLAIN_OK]);
        assert!(sent[0].starts_with(&format!("{method} / HTTP/1.1\r\n{fields}Host: site.test\r\n")), "{method}: {:?}", sent[0]);
    }
    let reply = "HTTP/1.1 206 Partial Content\r\nAllow: GET, HEAD\r\nWWW-Authenticate: Basic realm=\"a\"\r\n\
                 WWW-Authenticate: Bearer\r\nContent-Range: bytes 0-1/10\r\nExpect: nonsense\r\nContent-Length: 2\r\n\r\nok";
    let (received, _) = Talk::default().go("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", &[reply]);
    assert!(received.starts_with(
        "HTTP/1.1 206 Partial Content\r\nAllow: GET, HEAD\r\nWWW-Authenticate: Basic realm=\"a\"\r\n\
         WWW-Authenticate: Bearer\r\nContent-Range: bytes 0-1/10\r\nDate: "
    ), "{received:?}");
    assert!(!received.contains("Expect"));
    // Conditions do not change our own answers.
    let conditional = "If-None-Match: *\r\nIf-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nIf-Range: \"x\"\r\nRange: bytes=0-1\r\n";
    assert_eq!(Talk::default().status(&format!("GET / HTTP/1.1\r\nHost: tls.test\r\n{conditional}\r\n")), 301);
    assert_eq!(Talk::default().status(&format!("GET / HTTP/1.1\r\nHost: unknown.test\r\n{conditional}\r\n")), 404);
}

/// An upstream response head that is too large is refused.
#[test]
fn upstream_head_limits() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    let long_line = format!("HTTP/1.1 200 {}\r\n\r\n", "x".repeat(8200));
    let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "A: b\r\n".repeat(101));
    let big = format!("HTTP/1.1 200 OK\r\nA: {}\r\nB: {}\r\n\r\n", "x".repeat(8000), "y".repeat(8400));
    for reply in [long_line, many, big] {
        let (received, _) = Talk::default().go(get, &[&reply]);
        assert!(received.starts_with("HTTP/1.1 502 "), "{:?}", &received[..40.min(received.len())]);
    }
}

/// A bare CR in an upstream's status line or fields is refused with 502;
/// one in a chunk or trailer line, after the response has begun, cuts the
/// response off.
#[test]
fn bare_cr_from_upstreams() {
    let get = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";
    for reply in ["HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 200 OK\r\nA: b\rc\r\nContent-Length: 0\r\n\r\n"] {
        assert!(Talk::default().go(get, &[reply]).0.starts_with("HTTP/1.1 502 "), "{reply:?}");
    }
    for reply in [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX: a\rb\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\r\nok\r\n0\r\n\r\n",
    ] {
        let (received, _) = Talk::default().go(get, &[reply]);
        assert!(received.starts_with("HTTP/1.1 200 OK\r\n"), "{reply:?}");
        assert!(!received.ends_with("0\r\n\r\n"), "{reply:?} gave {received:?}");
    }
}

/// When an exchange is over, its upstream connection is closed at once and
/// never read again, whatever the upstream sent or said in Connection.
#[test]
fn an_upstream_is_closed_when_its_exchange_ends() {
    for reply in [
        "garbage\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nokHTTP/1.1 200 OK\r\n\r\n",
    ] {
        let client = Script::new(vec![Step::Data(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n".to_vec())]);
        let upstreams = Upstreams::default();
        upstreams.scripts.lock().unwrap().push_back(Ok(vec![Step::Data(reply.as_bytes().to_vec())]));
        let config = config();
        let log = Kept::default();
        let context = Context {
            config: &config,
            connect: &upstreams,
            log: &log,
            peer: PEER.parse().unwrap(),
            tls_site: None,
            acme: Path::new("/nonexistent"),
            clock: || 0,
            timeouts: Timeouts::STANDARD,
        };
        proxy::serve(&client, &context);
        assert!(upstreams.made.lock().unwrap()[0].was_shut(), "{reply:?}");
        assert_eq!(String::from_utf8(client.written()).unwrap().matches("HTTP/1.1 ").count(), 1, "{reply:?}");
    }
    // Two requests on one client connection get two upstream connections,
    // one request each, though the upstream did not ask to close.
    let two = "GET /1 HTTP/1.1\r\nHost: site.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: site.test\r\n\r\n";
    let plain = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (received, sent) = Talk::default().go(two, &[plain, plain]);
    assert_eq!(sent.len(), 2);
    assert!(sent[0].starts_with("GET /1 ") && !sent[0].contains("GET /2"));
    assert!(sent[1].starts_with("GET /2 ") && !sent[1].contains("GET /1"));
    assert_eq!(received.matches("HTTP/1.1 200 OK").count(), 2);
}

#[test]
fn http10_keep_alive_is_not_kept() {
    let request = "GET /1 HTTP/1.0\r\nHost: site.test\r\nConnection: keep-alive\r\n\r\nGET /2 HTTP/1.0\r\nHost: site.test\r\n\r\n";
    let (received, sent) = Talk::default().go(request, &[PLAIN_OK, PLAIN_OK]);
    assert_eq!(sent.len(), 1);
    assert!(received.contains("\r\nConnection: close\r\n") && !received.contains("Keep-Alive"));
}

#[test]
fn a_long_target_is_forwarded_whole() {
    let target = format!("/{}", "a".repeat(8000));
    let (_, sent) = Talk::default().go(&format!("GET {target} HTTP/1.1\r\nHost: site.test\r\n\r\n"), &[PLAIN_OK]);
    assert!(sent[0].starts_with(&format!("GET {target} HTTP/1.1\r\n")));
}

/// On a TLS connection every request is checked against the site of the
/// handshake, not only the first.
#[test]
fn every_request_on_a_tls_connection_is_checked() {
    let talk = Talk { tls: Some("site.test"), ..Talk::default() };
    let (received, sent) = talk.go(
        "GET / HTTP/1.1\r\nHost: site.test\r\n\r\nGET / HTTP/1.1\r\nHost: tls.test\r\n\r\n",
        &["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"],
    );
    assert_eq!(sent.len(), 1);
    let statuses: Vec<&str> = received.match_indices("HTTP/1.1 ").map(|(at, _)| &received[at + 9..at + 12]).collect();
    assert_eq!(statuses, ["200", "421"]);
}

/// Everything the proxy writes, to an upstream or to the client, passes our
/// own strict parser, which refuses anything the grammar does not allow
/// (bare CR or LF, folded or malformed fields, ambiguous framing). Raw
/// tunnel bytes and bodies are not heads and are left out.
#[test]
fn generated_messages_parse_strictly() {
    use super::parse;
    use crate::stream::Buffer;
    let check = |run: &Run| {
        for (upstream, (number, ask, _)) in run.upstreams.iter().zip(run.forwarded()) {
            let stream = Script::new(vec![Step::Data(upstream.written()), Step::End]);
            let request = parse::read_request(&mut Buffer::new(), &stream);
            let request = request.unwrap_or_else(|e| panic!("request {number}: {e:?} {}", describe(run)));
            assert!(!ask.accepted() || request.fields.length().0 != super::fsm::Length::Bad);
        }
        for seen in run.seen() {
            let bytes = format!("{}\r\n\r\n", seen.head).into_bytes();
            let stream = Script::new(vec![Step::Data(bytes), Step::End]);
            let response = parse::read_response(&mut Buffer::new(), &stream)
                .unwrap_or_else(|e| panic!("response {}: {e} {}", seen.status, describe(run)));
            assert_eq!(response.status, seen.status, "{}", describe(run));
            let (length, _) = response.fields.length();
            let framing = super::fsm::response_framing(response.version, false, length, response.fields.coding());
            assert_ne!(framing, super::fsm::Framing::Reject, "{}", describe(run));
        }
    };
    every_run(check);
}

/// However a conversation ends, every upstream connection is closed by the
/// time the client connection is.
#[test]
fn upstreams_are_always_closed() {
    let check = |run: &Run| {
        for upstream in &run.upstreams {
            assert!(upstream.was_shut(), "{}", describe(run));
        }
    };
    every_run(check);
    every_cut_run(check);
}

// --------------------------------------------------------- bugs found
//
// Every bug found in review has a test here that reproduces what was
// reported, so that it cannot come back unnoticed. Each says what the bug
// was. Most of the behaviour is also covered by the broader tests above.

const GET_SITE: &str = "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n";

/// Bug: `CONNECT /x` passed the request-line check (only the authority form
/// was refused) and was forwarded to the upstream.
#[test]
fn bug_connect_with_a_path_was_forwarded() {
    let (received, sent) = Talk::default().go("CONNECT /x HTTP/1.1\r\nHost: site.test\r\n\r\n", &[PLAIN_OK]);
    assert!(received.starts_with("HTTP/1.1 400 "));
    assert!(sent.is_empty());
}

/// Bug: a HEAD request refused while its head was read (431, a bad field,
/// a too long line) got an error response with a body.
#[test]
fn bug_refused_head_request_got_a_body() {
    let request = format!("HEAD / HTTP/1.1\r\nHost: site.test\r\n{}\r\n", "A: b\r\n".repeat(101));
    let (received, _) = Talk::default().go(&request, &[]);
    assert!(received.starts_with("HTTP/1.1 431 "));
    assert!(received.ends_with("\r\n\r\n"), "{received:?}");
}

/// Bug: the Date of every response on a connection was the time the
/// connection was accepted.
#[test]
fn bug_date_was_taken_once_per_connection() {
    // Shown with a clock that moves a day per reading, in
    // `every_response_is_dated_when_it_is_written`; here the plainest case:
    // two responses on one connection carry two different dates.
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(1_000_000_000);
    let client = Script::new(vec![Step::Data(format!("{GET_SITE}{GET_SITE}").into_bytes())]);
    let upstreams = Upstreams::default();
    for _ in 0..2 {
        upstreams.scripts.lock().unwrap().push_back(Ok(vec![Step::Data(PLAIN_OK.as_bytes().to_vec())]));
    }
    let config = config();
    let log = Kept::default();
    let context = Context {
        config: &config,
        connect: &upstreams,
        log: &log,
        peer: PEER.parse().unwrap(),
        tls_site: None,
        acme: Path::new("/nonexistent"),
        clock: || NOW.fetch_add(3_600, Ordering::Relaxed),
        timeouts: Timeouts::STANDARD,
    };
    proxy::serve(&client, &context);
    let received = String::from_utf8(client.written()).unwrap();
    let dates: Vec<&str> = received.lines().filter(|l| l.starts_with("Date: ")).collect();
    assert_eq!(dates.len(), 2);
    assert_ne!(dates[0], dates[1]);
}

/// Bug: an exchange's upstream connection stayed open until the client
/// connection ended.
#[test]
fn bug_upstream_stayed_open_after_its_exchange() {
    let client = Script::new(vec![Step::Data(GET_SITE.as_bytes().to_vec()), Step::Timeout]);
    let upstreams = Upstreams::default();
    upstreams.scripts.lock().unwrap().push_back(Ok(vec![Step::Data(PLAIN_OK.as_bytes().to_vec())]));
    let config = config();
    let log = Kept::default();
    let context = Context {
        config: &config,
        connect: &upstreams,
        log: &log,
        peer: PEER.parse().unwrap(),
        tls_site: None,
        acme: Path::new("/nonexistent"),
        clock: || 0,
        timeouts: Timeouts::STANDARD,
    };
    // The client keeps its connection, and the upstream must already be
    // closed when the proxy goes back to waiting for the next request:
    // the scripted client times out there, which ends the run, and by then
    // the upstream must have been shut by the proxy itself.
    proxy::serve(&client, &context);
    assert!(upstreams.made.lock().unwrap()[0].was_shut());
}

/// Bug: `Upgrade` and `Expect` were compared as whole values, so
/// `Upgrade: h2c, websocket` was no upgrade and `Expect: 100-continue,`
/// got no 100.
#[test]
fn bug_upgrade_and_expect_were_not_read_as_lists() {
    let switch = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
    let upgrade = "GET / HTTP/1.1\r\nHost: site.test\r\nUpgrade: h2c, websocket\r\nConnection: upgrade\r\n\r\n";
    assert!(Talk::default().go(upgrade, &[switch]).0.starts_with("HTTP/1.1 101 "));
    let put = "PUT / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 2\r\nExpect: 100-continue,\r\n\r\nhi";
    assert!(Talk::default().go(put, &[PLAIN_OK]).0.starts_with("HTTP/1.1 100 Continue\r\n"));
}

/// Bug: an empty or trailing-comma X-Forwarded-For or Via from the client
/// produced empty list elements in what we sent upstream.
#[test]
fn bug_empty_list_elements_in_forwarding_fields() {
    let request = "GET / HTTP/1.1\r\nHost: site.test\r\nX-Forwarded-For: 1.1.1.1,\r\nVia:\r\nVia: 1.0 a,\r\n\r\n";
    let (_, sent) = Talk::default().go(request, &[PLAIN_OK]);
    assert!(sent[0].contains("\r\nX-Forwarded-For: 1.1.1.1, 192.0.2.7\r\n"), "{:?}", sent[0]);
    assert!(sent[0].contains("\r\nVia: 1.0 a, 1.1 shioko\r\n"), "{:?}", sent[0]);
    assert_eq!(sent[0].matches("Via:").count(), 1);
}

/// Bug: a Content-Length of more than 19 digits was refused, also a valid
/// one with leading zeros.
#[test]
fn bug_long_content_length_was_refused() {
    let request = "POST / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 000000000000000000000003\r\n\r\nabc";
    let (received, sent) = Talk::default().go(request, &[PLAIN_OK]);
    assert!(received.starts_with("HTTP/1.1 200 "));
    assert!(sent[0].ends_with("Content-Length: 3\r\nConnection: close\r\n\r\nabc"), "{:?}", sent[0]);
}

/// Bug: valid Host values were refused with 400: an IP literal, an empty
/// port, an underscore.
#[test]
fn bug_valid_host_forms_were_refused() {
    for host in ["[::1]", "[::1]:80", "unknown.test:", "under_score.test"] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        // None of these is a configured site: the answer is 404, not 400.
        assert_eq!(Talk::default().status(&request), 404, "{host}");
    }
    assert_eq!(Talk::default().status("GET / HTTP/1.1\r\nHost: site.test:\r\n\r\n"), 200);
}

/// Bug: `Expect: 100-continue` on a request with `Content-Length: 0` got a
/// 100, and TRACE with `Content-Length: 0` was refused.
#[test]
fn bug_zero_length_was_taken_for_a_body() {
    let put = "PUT / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n";
    assert!(!Talk::default().go(put, &[PLAIN_OK]).0.contains("100 Continue"));
    assert_eq!(Talk::default().status("TRACE / HTTP/1.1\r\nHost: site.test\r\nContent-Length: 0\r\n\r\n"), 200);
}

/// Bug: a request without Host was answered 501 rather than 400 when it
/// also had an unsupported coding or a too long method.
#[test]
fn bug_missing_host_lost_to_501() {
    let coding = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    assert_eq!(Talk::default().status(coding), 400);
    let method = format!("{} / HTTP/1.1\r\n\r\n", "M".repeat(40));
    assert_eq!(Talk::default().status(&method), 400);
}

/// Bug: a chunk extension with a space before its `;` was refused.
#[test]
fn bug_chunk_extension_with_space_was_refused() {
    let request = "POST / HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: chunked\r\n\r\n2 ;x=\"é\"\r\nhi\r\n0\r\n\r\n";
    let (received, sent) = Talk::default().go(request, &[PLAIN_OK]);
    assert!(received.starts_with("HTTP/1.1 200 "), "{received:?}");
    assert!(sent[0].ends_with("\r\n\r\n2\r\nhi\r\n0\r\n\r\n"), "{:?}", sent[0]);
}

/// Bug: `Transfer-Encoding: gzip;level=1, chunked` was a 400 rather than
/// the 501 of a coding we do not implement.
#[test]
fn bug_coding_parameters_were_malformed() {
    let request = "POST / HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: gzip;level=1, chunked\r\n\r\n";
    assert_eq!(Talk::default().status(request), 501);
}

/// Bug: an upstream response's Expect field was passed to the client.
#[test]
fn bug_expect_was_relayed_in_responses() {
    let reply = "HTTP/1.1 200 OK\r\nExpect: x\r\nContent-Length: 0\r\n\r\n";
    assert!(!Talk::default().go(GET_SITE, &[reply]).0.contains("Expect"));
}

/// Bug: a relayed 1xx without Date was passed on without one.
#[test]
fn bug_interim_response_had_no_date() {
    let reply = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (received, _) = Talk::default().go(GET_SITE, &[reply]);
    let interim = received.split("\r\n\r\n").next().unwrap();
    assert!(interim.contains("\r\nDate: "), "{interim:?}");
}

/// Bug: the redirect answered 400 to targets holding characters a URI may
/// not, such as `|`, which browsers send unencoded.
#[test]
fn bug_redirect_refused_what_browsers_send() {
    let (received, _) = Talk::default().go("GET /a|b HTTP/1.1\r\nHost: tls.test\r\n\r\n", &[]);
    assert!(received.contains("\r\nLocation: https://tls.test/a%7Cb\r\n"), "{received:?}");
}

/// Bug: the request-head timeout applied to each read, not to the head, so
/// a client sending a byte now and then could hold a connection for ever.
#[test]
fn bug_slow_head_was_never_cut_off() {
    use std::time::Duration;
    let slow = |text: &str| Step::Slow(Duration::from_millis(40), text.as_bytes().to_vec());
    let timeouts = Timeouts { head: Duration::from_millis(100), keep_alive: Duration::from_millis(100) };
    let talk = Talk { timeouts, ..Talk::default() };
    // Each piece comes well within the limit; the head as a whole does not.
    let pieces = ["GET / ", "HTTP/1.1\r\n", "Host: ", "site.test", "\r\n", "\r\n"];
    let (received, sent, _) = talk.steps(pieces.iter().map(|p| slow(p)).collect(), vec![]);
    assert!(sent.is_empty(), "the request was served");
    assert_eq!(received, "");
    // The same for the next request on a kept connection.
    let mut steps = vec![Step::Data(GET_SITE.as_bytes().to_vec())];
    steps.extend(pieces.iter().map(|p| slow(p)));
    let (received, sent, _) = talk.steps(steps, vec![vec![Step::Data(PLAIN_OK.as_bytes().to_vec())]]);
    assert_eq!(sent.len(), 1);
    assert_eq!(received.matches("HTTP/1.1 200 ").count(), 1);
    // Quick enough, it is served.
    let quick = Talk { timeouts: Timeouts { head: Duration::from_secs(5), keep_alive: Duration::from_secs(5) }, ..Talk::default() };
    let (_, sent, _) = quick.steps(pieces.iter().map(|p| slow(p)).collect(), vec![vec![Step::Data(PLAIN_OK.as_bytes().to_vec())]]);
    assert_eq!(sent.len(), 1);
}

/// Bug: an upstream at 0.0.0.0 port 80 was allowed, which on Linux is this
/// host, and every request would have come back to shioko.
#[test]
fn bug_unspecified_address_upstream_was_allowed() {
    let error = crate::config::tests::parse("[a]\nupstream = 0.0.0.0:80\n").unwrap_err();
    assert!(error.contains("is shioko itself"), "{error}");
}

/// Bug: only the first response of each run was checked against our own
/// strict parser (a mistake in a test, found in review).
#[test]
fn bug_every_generated_response_parses() {
    let run = run(&[(GET, OK), (GET, OK)], b"", Feed::Whole, Feed::Whole);
    assert_eq!(run.seen().len(), 2);
    for seen in run.seen() {
        let bytes = format!("{}\r\n\r\n", seen.head).into_bytes();
        let stream = Script::new(vec![Step::Data(bytes), Step::End]);
        assert!(super::parse::read_response(&mut crate::stream::Buffer::new(), &stream).is_ok());
    }
}
