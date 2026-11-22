//! Serving one client connection: the code that carries out what the state
//! machine in `fsm` asks for.
//!
//! One thread serves a connection. It asks the state machine what to do,
//! does it, and tells the state machine what came of it, until the machine
//! has nothing more to ask. A tunnel adds a second thread for its duration.

use super::body::{self, CopyError};
use super::fsm::{self, Action, Event, Framing, Length, Phase, Version};
use super::own::{self, Content};
use super::parse::{self, Fields, Request, RequestError, Response};
use crate::config::{Config, Site};
use crate::log::{self, Log};
use crate::net;
use crate::stream::{self, Buffer, Stream};
use crate::sync::{self, atomic::AtomicU64, atomic::Ordering};
use std::collections::VecDeque;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long the client may take over a request head, and over a pause in
/// a body.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// The first request head on a connection must arrive whole within
    /// this.
    pub head: Duration,
    /// The next request head on a kept connection must arrive whole within
    /// this, counted from the end of the response before.
    pub keep_alive: Duration,
    /// Each `body_step` bytes of a request body must arrive within this, so
    /// that a body cannot hold a connection by trickling in.
    pub body: Duration,
    pub body_step: usize,
}

impl Timeouts {
    /// A request body must keep up 64 KiB a minute, about 1 KB/s.
    pub const STANDARD: Timeouts = Timeouts {
        head: Duration::from_secs(60),
        keep_alive: Duration::from_secs(75),
        body: Duration::from_secs(60),
        body_step: 64 * 1024,
    };
}
/// How long connecting to an upstream may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an upstream may stay silent, and how long a write to it may
/// block.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a tunnel may carry nothing in either direction.
const TUNNEL_IDLE: Duration = Duration::from_secs(60);
/// A request that has passed through shioko this often is going in circles.
const LOOP_LIMIT: usize = 8;
/// Where ACME tokens are asked for.
const ACME_PREFIX: &[u8] = b"/.well-known/acme-challenge/";
/// The largest ACME token file we serve.
const TOKEN_LIMIT: u64 = 4096;

/// Opens connections to upstreams.
pub trait Connect: Sync {
    type Upstream: Stream;
    /// Connects to `host:port`. The error is the status the client gets
    /// instead: 504 if it took too long, 502 otherwise.
    fn connect(&self, address: &str) -> Result<Self::Upstream, u16>;
}

/// Plain TCP, which is what upstreams speak.
pub struct Tcp;

impl Connect for Tcp {
    type Upstream = TcpStream;

    fn connect(&self, address: &str) -> Result<TcpStream, u16> {
        let mut status = 502;
        for candidate in address.to_socket_addrs().map_err(|_| 502u16)? {
            match TcpStream::connect_timeout(&candidate, CONNECT_TIMEOUT) {
                Ok(upstream) => {
                    let _ = upstream.set_write_timeout(Some(UPSTREAM_TIMEOUT));
                    let _ = upstream.set_nodelay(true);
                    return Ok(upstream);
                }
                Err(error) if stream::timed_out(&error) => status = 504,
                Err(_) => {}
            }
        }
        Err(status)
    }
}

/// What serving a connection needs to know about its surroundings.
pub struct Context<'a, K: Connect> {
    pub config: &'a Config,
    pub connect: &'a K,
    pub log: &'a dyn Log,
    /// The client's address.
    pub peer: IpAddr,
    /// On a TLS connection, the site the handshake settled on. On port 80,
    /// nothing.
    pub tls_site: Option<&'a Site>,
    /// The directory ACME tokens are read from.
    pub acme: &'a Path,
    /// The time, in seconds since 1970. Asked for each response.
    pub clock: fn() -> u64,
    pub timeouts: Timeouts,
    /// Told when the connection may be cut by the server stopping (`true`:
    /// it waits for a request head, or becomes a tunnel) and when no longer
    /// (`false`: a request has come). Given `true`, it answers `false` if
    /// the server is stopping already: the connection is then ended
    /// instead.
    pub interruptible: &'a dyn Fn(bool) -> bool,
}

/// One request and what we have learnt about it so far.
struct Exchange<'a, U> {
    started: Instant,
    request: Option<Request>,
    site: Option<&'a Site>,
    /// How the request body is delimited, and its length if stated.
    framing: Framing,
    length: u64,
    /// The client waits for "100 Continue" before it sends the body.
    expect: bool,
    /// The request is a WebSocket upgrade that the site allows.
    upgrade: bool,
    /// What an own answer carries besides its status.
    content: Content,
    upstream: Option<U>,
    /// What was read from the upstream and not yet used.
    pending: Buffer,
    response: Option<Response>,
    /// How the response body is delimited by the upstream and towards the
    /// client.
    response_framing: Framing,
    client_framing: Framing,
    /// The status that goes into the log.
    status: u16,
    /// The request was refused while its head was read, and it is HEAD.
    refused_head: bool,
}

impl<U> Exchange<'_, U> {
    fn new() -> Self {
        Exchange {
            started: Instant::now(),
            request: None,
            site: None,
            framing: Framing::Empty,
            length: 0,
            expect: false,
            upgrade: false,
            content: Content::Text,
            upstream: None,
            pending: Buffer::new(),
            response: None,
            response_framing: Framing::Empty,
            client_framing: Framing::Empty,
            status: 0,
            refused_head: false,
        }
    }

    fn version(&self) -> Version {
        self.request.as_ref().map_or(Version::V11, |r| r.version)
    }

    fn is_head(&self) -> bool {
        self.refused_head || self.request.as_ref().is_some_and(|r| r.method == b"HEAD")
    }
}

/// Serves one client connection to its end.
pub fn serve<'a, C: Stream, K: Connect>(client: &C, context: &Context<'a, K>) {
    let mut input = Buffer::new();
    let (mut state, actions) = fsm::start();
    let mut todo: VecDeque<Action> = actions.into();
    let mut exchange: Exchange<'a, K::Upstream> = Exchange::new();
    let mut first = true;
    let mut gone = false;

    while let Some(action) = todo.pop_front() {
        let event = match action {
            Action::ReadHead => {
                // The upstream connection of the exchange before goes with
                // it, and so does whatever was read from it and not used.
                exchange = Exchange::new();
                if !(context.interruptible)(true) {
                    // The server is stopping: no more requests.
                    break;
                }
                let limit = if first { context.timeouts.head } else { context.timeouts.keep_alive };
                first = false;
                input.set_deadline(Some(Instant::now() + limit));
                let event = read_head(client, &mut input, context, &mut exchange);
                input.set_deadline(None);
                (context.interruptible)(false);
                Some(event)
            }
            Action::Connect => Some(connect(context, &mut exchange).unwrap_or_else(Event::Fail)),
            Action::Forward => Some(forward(client, &mut input, context, &mut exchange)),
            Action::ReadResponse => Some(read_response(&mut exchange).unwrap_or_else(Event::Fail)),
            Action::Interim => pass_interim(client, context, &mut exchange),
            Action::Respond { keep } => Some(respond(client, context, &mut exchange, keep)),
            Action::Error(status) => {
                answer(client, context, &mut exchange, status);
                None
            }
            Action::Tunnel => Some(tunnel(client, &mut input, context, &mut exchange)),
        };
        if let Some(event) = event {
            gone = event == Event::Gone;
            let (next, actions) = fsm::step(state, event);
            state = next;
            todo = actions.into();
            // An exchange that is over has no more use for its upstream:
            // nothing more is read from it.
            if matches!(state.phase, Phase::Idle | Phase::Closed)
                && let Some(upstream) = exchange.upstream.take()
            {
                upstream.shutdown();
            }
        }
    }

    if gone {
        client.shutdown();
    } else {
        client.finish();
    }
}

/// The token of an ACME challenge request, if this is one.
fn acme_token(request: &Request) -> Option<&[u8]> {
    let token = request.target.strip_prefix(ACME_PREFIX)?;
    let method_ok = request.method == b"GET" || request.method == b"HEAD";
    let token_ok = (1..=128).contains(&token.len())
        && token.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    (method_ok && token_ok).then_some(token)
}

/// A request target made fit to be the path and query of a URI: every byte
/// that may not appear there as it stands (RFC 3986: unreserved,
/// sub-delims, ":", "@", "/", "?") is percent-encoded, and so is a `%` that
/// does not begin a valid escape.
fn uri_path(target: &[u8]) -> String {
    let mut path = String::with_capacity(target.len());
    for (at, &byte) in target.iter().enumerate() {
        let escape = byte == b'%'
            && target.get(at.saturating_add(1)..at.saturating_add(3)).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
        if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte) || escape {
            path.push(char::from(byte));
        } else {
            path.push_str(&format!("%{byte:02X}"));
        }
    }
    path
}

/// Reads a request head and decides what becomes of the request.
fn read_head<'a, C: Stream, K: Connect>(
    client: &C,
    input: &mut Buffer,
    context: &Context<'a, K>,
    exchange: &mut Exchange<'a, K::Upstream>,
) -> Event {
    let request = match parse::read_request(input, client) {
        Ok(request) => request,
        Err(RequestError::End | RequestError::Gone) => return Event::Gone,
        Err(RequestError::Status(status, head)) => {
            exchange.refused_head = head;
            return Event::Fail(status);
        }
    };
    exchange.started = Instant::now();
    client.set_read_timeout(context.timeouts.head);
    let event = judge(&request, context, exchange).unwrap_or_else(Event::Fail);
    exchange.request = Some(request);
    event
}

/// Checks a request head and finds its site. The error is the status of our
/// own answer.
fn judge<'a, K: Connect>(
    request: &Request,
    context: &Context<'a, K>,
    exchange: &mut Exchange<'a, K::Upstream>,
) -> Result<Event, u16> {
    let fields = &request.fields;

    // A head that leaves doubt about where its body ends is refused first,
    // whatever else it says, and so is one without a usable Host. What is
    // merely not supported comes after.
    let (length_class, length) = fields.length();
    let framing = fsm::request_framing(request.version, length_class, fields.coding());
    if framing == Framing::Reject {
        return Err(400);
    }
    let name = fields.one("host").and_then(parse::host).ok_or(400u16)?;
    let through_us = fields.list("via").iter().filter(|via| via.ends_with(b" shioko")).count();
    if through_us >= LOOP_LIMIT {
        return Err(400);
    }
    if framing == Framing::Unsupported || request.method.len() > parse::METHOD_LIMIT {
        return Err(501);
    }
    // TRACE is refused, as nginx refuses it: it would echo the request,
    // credentials and all, back to whatever page sent it.
    if request.method == b"TRACE" {
        return Err(405);
    }
    let has_body = framing == Framing::Chunked || (framing == Framing::Length && length > 0);

    let site = match context.tls_site {
        // The handshake chose the site, and with it the allowlist that was
        // applied. A request for another name does not belong here.
        Some(site) if name.eq_ignore_ascii_case(site.name.as_bytes()) => site,
        Some(_) => return Err(421),
        None => {
            if let Some(token) = acme_token(request) {
                let path = context.acme.join(String::from_utf8_lossy(token).as_ref());
                let small = std::fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() <= TOKEN_LIMIT);
                let token = small.then(|| std::fs::read(&path).ok()).flatten().ok_or(404u16)?;
                exchange.content = Content::Token(token);
                return Err(200);
            }
            let site = context.config.site(name).ok_or(404u16)?;
            if site.cert.is_some() {
                // The site is served over HTTPS only. The location is built
                // from the configured name, never from what the client sent
                // as Host, and from a target that is a path, encoded where
                // it holds what a URI may not.
                if request.target.first() != Some(&b'/') {
                    return Err(400);
                }
                exchange.content = Content::Redirect(format!("https://{}{}", site.name, uri_path(&request.target)));
                return Err(301);
            }
            if !site.allows(context.peer) {
                return Err(403);
            }
            site
        }
    };
    if framing == Framing::Length && length > site.max_body {
        return Err(413);
    }

    let modern = request.version == Version::V11;
    let expects = fields.has("expect", "100-continue");
    exchange.upgrade = site.websocket
        && modern
        && request.method == b"GET"
        && framing == Framing::Empty
        && fields.has("upgrade", "websocket")
        && fields.has("connection", "upgrade")
        && !expects;

    exchange.site = Some(site);
    exchange.framing = framing;
    exchange.length = length;
    exchange.expect = expects && modern && has_body;
    let keep = modern && !fields.has("connection", "close");
    Ok(if exchange.upgrade { Event::Upgrade { keep } } else { Event::Request { keep } })
}

/// Connects to the site's upstream. The error is the status of our answer.
fn connect<K: Connect>(context: &Context<'_, K>, exchange: &mut Exchange<'_, K::Upstream>) -> Result<Event, u16> {
    let site = exchange.site.ok_or(502u16)?;
    let upstream = context.connect.connect(&site.upstream)?;
    upstream.set_read_timeout(UPSTREAM_TIMEOUT);
    exchange.upstream = Some(upstream);
    Ok(Event::Connected)
}

/// Fields that concern one connection only and are never passed on.
const HOP_BY_HOP: [&str; 7] =
    ["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];

fn push_field(head: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    for part in [name, b": ", value, b"\r\n"] {
        head.extend_from_slice(part);
    }
}

/// Copies the fields that are passed on: all but the hop-by-hop ones, the
/// ones the peer named in `Connection`, and the ones in `ours`, which we
/// write ourselves.
fn pass_fields(head: &mut Vec<u8>, fields: &Fields, ours: &[&str]) {
    let named = fields.list("connection");
    for (name, value) in &fields.0 {
        let dropped = HOP_BY_HOP.iter().chain(ours).any(|hop| name.eq_ignore_ascii_case(hop.as_bytes()))
            || named.iter().any(|option| name.eq_ignore_ascii_case(option));
        if !dropped {
            push_field(head, name, value);
        }
    }
}

/// The non-empty elements of every field with this name, keeping their case,
/// then `last`, as one list.
fn list_with(fields: &Fields, name: &str, last: &[u8]) -> Vec<u8> {
    let elements = fields.all(name).flat_map(|value| value.split(|&b| b == b','));
    let mut list: Vec<&[u8]> = elements.map(<[u8]>::trim_ascii).filter(|e| !e.is_empty()).collect();
    list.push(last);
    list.join(b", ".as_slice())
}

/// The request head as the upstream gets it. It is written by us from what
/// we understood, never copied.
fn upstream_head<K: Connect>(
    request: &Request,
    context: &Context<'_, K>,
    exchange: &Exchange<'_, K::Upstream>,
) -> Vec<u8> {
    let mut head = [request.method.as_slice(), b" ", &request.target, b" HTTP/1.1\r\n"].concat();
    pass_fields(
        &mut head,
        &request.fields,
        &["host", "content-length", "expect", "via", "x-real-ip", "x-forwarded-for", "x-forwarded-proto"],
    );

    let peer = net::canonical(context.peer).to_string();
    // The addresses the request came through so far, then the client's;
    // and the intermediaries it came through, then us. Empty list elements
    // are left out.
    let forwarded_for = list_with(&request.fields, "x-forwarded-for", peer.as_bytes());
    let scheme: &[u8] = if context.tls_site.is_some() { b"https" } else { b"http" };
    let us: &[u8] = if request.version == Version::V10 { b"1.0 shioko" } else { b"1.1 shioko" };
    let via = list_with(&request.fields, "via", us);

    push_field(&mut head, b"Host", request.fields.one("host").unwrap_or(b""));
    push_field(&mut head, b"X-Real-IP", peer.as_bytes());
    push_field(&mut head, b"X-Forwarded-For", &forwarded_for);
    push_field(&mut head, b"X-Forwarded-Proto", scheme);
    push_field(&mut head, b"Via", &via);
    match exchange.framing {
        Framing::Length => push_field(&mut head, b"Content-Length", exchange.length.to_string().as_bytes()),
        Framing::Chunked => push_field(&mut head, b"Transfer-Encoding", b"chunked"),
        _ => {}
    }
    head.extend_from_slice(if exchange.upgrade { UPGRADE } else { b"Connection: close\r\n\r\n" });
    head
}

/// The end of a head that asks for, or agrees to, a WebSocket upgrade.
const UPGRADE: &[u8] = b"Connection: upgrade\r\nUpgrade: websocket\r\n\r\n";

/// Sends the request to the upstream: "100 Continue" to a client that waits
/// for it, then the head, then the body.
fn forward<C: Stream, K: Connect>(
    client: &C,
    input: &mut Buffer,
    context: &Context<'_, K>,
    exchange: &mut Exchange<'_, K::Upstream>,
) -> Event {
    let (Some(request), Some(upstream), Some(site)) = (&exchange.request, &exchange.upstream, exchange.site) else {
        return Event::Fail(502);
    };
    if exchange.expect && client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
        return Event::Gone;
    }
    if upstream.write_all(&upstream_head(request, context, exchange)).is_err() {
        return Event::Fail(502);
    }
    input.set_pace(Some((context.timeouts.body_step, context.timeouts.body)));
    let copied = match exchange.framing {
        Framing::Length => body::copy_length(input, client, upstream, exchange.length),
        Framing::Chunked => body::copy_chunked(input, client, upstream, site.max_body, true),
        _ => Ok(()),
    };
    input.set_pace(None);
    match copied {
        Ok(()) => Event::Sent,
        Err(CopyError::Source | CopyError::SourceTimeout) => Event::Gone,
        Err(CopyError::Malformed) => Event::Fail(400),
        Err(CopyError::TooLarge) => Event::Fail(413),
        Err(CopyError::Sink) => Event::Fail(502),
    }
}

/// Reads a response head from the upstream and decides what it is. The
/// error is the status of our answer.
fn read_response<U: Stream>(exchange: &mut Exchange<'_, U>) -> Result<Event, u16> {
    let upstream = exchange.upstream.as_ref().ok_or(502u16)?;
    let response = parse::read_response(&mut exchange.pending, upstream)?;
    let (status, fields) = (response.status, &response.fields);
    let event = if status == 101 {
        if !(fields.has("upgrade", "websocket") && fields.has("connection", "upgrade")) {
            return Err(502);
        }
        Event::Switching
    } else if status < 200 {
        Event::Interim
    } else {
        let bodiless = exchange.is_head() || status == 204 || status == 304;
        let framing = fsm::response_framing(response.version, bodiless, fields.length().0, fields.coding());
        if framing == Framing::Reject {
            return Err(502);
        }
        exchange.response_framing = framing;
        exchange.client_framing = fsm::client_framing(framing, exchange.version());
        Event::Final { delimited: exchange.client_framing != Framing::Close }
    };
    exchange.response = Some(response);
    Ok(event)
}

/// A response head as the client gets it, without the fields that say how
/// the body is delimited or what becomes of the connection.
fn client_head(response: &Response, now: u64) -> Vec<u8> {
    let mut head = [format!("HTTP/1.1 {} ", response.status).as_bytes(), &response.reason, b"\r\n"].concat();
    pass_fields(&mut head, &response.fields, &["content-length", "expect"]);
    if response.fields.all("date").next().is_none() {
        push_field(&mut head, b"Date", own::http_date(now).as_bytes());
    }
    head
}

/// Passes a 1xx response on, unless the client speaks HTTP/1.0.
fn pass_interim<C: Stream, K: Connect>(
    client: &C,
    context: &Context<'_, K>,
    exchange: &mut Exchange<'_, K::Upstream>,
) -> Option<Event> {
    let response = exchange.response.take()?;
    if exchange.version() == Version::V10 {
        return None;
    }
    let mut head = client_head(&response, (context.clock)());
    head.extend_from_slice(b"\r\n");
    client.write_all(&head).is_err().then_some(Event::Gone)
}

fn log_access<K: Connect>(context: &Context<'_, K>, exchange: &Exchange<'_, K::Upstream>) {
    let (method, target, host) = match &exchange.request {
        Some(request) => (
            log::escape(&request.method),
            log::escape(&request.target),
            log::escape(request.fields.one("host").unwrap_or(b"-")),
        ),
        None => ("-".into(), "-".into(), "-".into()),
    };
    let (peer, status, millis) = (net::canonical(context.peer), exchange.status, exchange.started.elapsed().as_millis());
    context.log.access(&format!("{peer} {host} \"{method} {target}\" {status} {millis}ms"));
}

/// Sends the response to the client: head, then body.
fn respond<C: Stream, K: Connect>(
    client: &C,
    context: &Context<'_, K>,
    exchange: &mut Exchange<'_, K::Upstream>,
    keep: bool,
) -> Event {
    let (Some(response), Some(upstream)) = (&exchange.response, &exchange.upstream) else {
        return Event::Fail(502);
    };
    exchange.status = response.status;
    let (stated, length) = response.fields.length();
    let rechunk = exchange.client_framing == Framing::Chunked;
    let mut head = client_head(response, (context.clock)());
    if rechunk {
        push_field(&mut head, b"Transfer-Encoding", b"chunked");
    } else if stated == Length::One && response.status != 204 {
        // The length of the body, or, in answer to HEAD or with a 304, the
        // length it would have. A 204 states none (RFC 9110 8.6).
        push_field(&mut head, b"Content-Length", length.to_string().as_bytes());
    }
    if !keep {
        push_field(&mut head, b"Connection", b"close");
    }
    head.extend_from_slice(b"\r\n");
    let copied = client.write_all(&head).map_err(|_| CopyError::Sink).and_then(|()| {
        let pending = &mut exchange.pending;
        match exchange.response_framing {
            Framing::Length => body::copy_length(pending, upstream, client, length),
            Framing::Chunked => body::copy_chunked(pending, upstream, client, u64::MAX, rechunk),
            Framing::Close => body::copy_to_end(pending, upstream, client, rechunk),
            _ => Ok(()),
        }
    });
    log_access(context, exchange);
    match copied {
        Ok(()) => Event::Done,
        Err(CopyError::Sink) => Event::Gone,
        Err(CopyError::SourceTimeout) => Event::Fail(504),
        Err(_) => Event::Fail(502),
    }
}

/// Writes our own response. Whether it arrives no longer matters: the
/// connection is closed after it either way.
fn answer<C: Stream, K: Connect>(
    client: &C,
    context: &Context<'_, K>,
    exchange: &mut Exchange<'_, K::Upstream>,
    status: u16,
) {
    exchange.status = status;
    let _ = client.write_all(&own::response(status, &exchange.content, (context.clock)(), exchange.is_head()));
    log_access(context, exchange);
}

/// Shuts both streams down when it goes out of scope, however that happens.
struct ShutBoth<'a, A: Stream, B: Stream>(&'a A, &'a B);

impl<A: Stream, B: Stream> Drop for ShutBoth<'_, A, B> {
    fn drop(&mut self) {
        self.0.shutdown();
        self.1.shutdown();
    }
}

/// Copies from one stream to the other until the source ends, a write
/// fails, or nothing has moved in either direction for too long. Then both
/// streams are shut down, which is what stops the pump of the other
/// direction.
fn pump<A: Stream, B: Stream>(from: &A, to: &B, started: Instant, last: &AtomicU64) {
    // Dropped last, once both streams are shut down.
    #[cfg(feature = "record")]
    let _stopped = Stopped;
    let _shut = ShutBoth(from, to);
    let millis = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut space = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut space) {
            Ok(n) if n > 0 => {
                last.store(millis(), Ordering::Relaxed);
                record!("data");
                if to.write_all(space.get(..n).unwrap_or(&[])).is_err() {
                    record!("write_fails");
                    return;
                }
            }
            // Nothing came this way in time. That is the end only if
            // nothing went the other way either.
            Err(error) if stream::timed_out(&error) => {
                let quiet = millis().saturating_sub(last.load(Ordering::Relaxed));
                if u128::from(quiet) >= TUNNEL_IDLE.as_millis() {
                    record!("read_ends");
                    return;
                }
            }
            _ => {
                record!("read_ends");
                return;
            }
        }
    }
}

/// The step `Stop` of spec/Server.tla, recorded once a pump has shut both
/// streams down, also when it unwinds from a panic.
#[cfg(feature = "record")]
struct Stopped;

#[cfg(feature = "record")]
impl Drop for Stopped {
    fn drop(&mut self) {
        record!("stop");
    }
}

/// Passes the 101 on and then copies bytes both ways until either side is
/// done. Bytes already read from either side go first.
fn tunnel<C: Stream, K: Connect>(
    client: &C,
    input: &mut Buffer,
    context: &Context<'_, K>,
    exchange: &mut Exchange<'_, K::Upstream>,
) -> Event {
    let (Some(response), Some(upstream)) = (&exchange.response, &exchange.upstream) else {
        return Event::Gone;
    };
    // A tunnel lasts as long as its two ends want; a stopping server cuts
    // it, and does not start one.
    if !(context.interruptible)(true) {
        return Event::Gone;
    }
    exchange.status = 101;
    log_access(context, exchange);
    let mut head = client_head(response, (context.clock)());
    head.extend_from_slice(UPGRADE);
    let _shut = ShutBoth(client, upstream);
    let early = client
        .write_all(&head)
        .and_then(|()| client.write_all(&exchange.pending.take()))
        .and_then(|()| upstream.write_all(&input.take()));
    if early.is_err() {
        return Event::Done;
    }
    client.set_read_timeout(TUNNEL_IDLE);
    upstream.set_read_timeout(TUNNEL_IDLE);
    let started = Instant::now();
    let last = AtomicU64::new(0);
    record!("tunnel");
    #[cfg(feature = "record")]
    let me = crate::record::who();
    #[cfg(feature = "record")]
    crate::record::be(me.clone(), true);
    sync::thread::scope(|scope| {
        let down = sync::spawn_scoped(scope, || {
            #[cfg(feature = "record")]
            crate::record::be(me.replace(" up", " down"), true);
            pump(upstream, client, started, &last);
        });
        // Without a second thread there is no tunnel; the streams are shut
        // down when we return.
        if down.is_ok() {
            pump(client, upstream, started, &last);
        }
    });
    #[cfg(feature = "record")]
    crate::record::be(me, false);
    Event::Done
}
