//! The framing rules and the state machine of one client connection.
//!
//! These are the functions of `spec/Http.tla`, kept in step with it by the
//! test at the end: TLC prints each function for every input into
//! `tests/vectors/http_fsm.txt`, and the test replays that table.

/// The HTTP version a message declares. Anything above 1.1 counts as 1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V10,
    V11,
}

/// What a head says about `Content-Length`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// No such field.
    None,
    /// Exactly one field holding one plain decimal number.
    One,
    /// Anything else.
    Bad,
}

/// What a head says about `Transfer-Encoding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// No such field.
    None,
    /// Exactly `chunked`.
    Chunked,
    /// A well-formed list that ends in `chunked` after other codings.
    Other,
    /// Anything else.
    Bad,
}

/// How a message body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Empty,
    Length,
    Chunked,
    /// The body runs until the connection closes.
    Close,
    /// The head leaves doubt: 400 for a request, 502 for a response.
    Reject,
    /// The head is clear but names a coding we do not implement: 501.
    Unsupported,
}

pub fn request_framing(version: Version, length: Length, coding: Coding) -> Framing {
    match (coding, length, version) {
        (Coding::None, Length::None, _) => Framing::Empty,
        (Coding::None, Length::One, _) => Framing::Length,
        (Coding::Chunked, Length::None, Version::V11) => Framing::Chunked,
        (Coding::Other, Length::None, Version::V11) => Framing::Unsupported,
        _ => Framing::Reject,
    }
}

/// `bodiless`: the response cannot have a body, because it answers HEAD or
/// its status is 1xx, 204 or 304.
pub fn response_framing(version: Version, bodiless: bool, length: Length, coding: Coding) -> Framing {
    match request_framing(version, length, coding) {
        Framing::Reject | Framing::Unsupported => Framing::Reject,
        _ if bodiless => Framing::Empty,
        Framing::Chunked => Framing::Chunked,
        Framing::Length => Framing::Length,
        _ => Framing::Close,
    }
}

/// How we delimit a response towards the client.
pub fn client_framing(framing: Framing, version: Version) -> Framing {
    match (framing, version) {
        (Framing::Empty | Framing::Length, _) => framing,
        (_, Version::V11) => Framing::Chunked,
        (_, Version::V10) => Framing::Close,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for a request head from the client.
    Idle,
    /// Request accepted, connecting to the upstream.
    Connect,
    /// Sending the request, head and body, to the upstream.
    Forward,
    /// Waiting for the response head from the upstream.
    Response,
    /// Sending the response, head and body, to the client.
    Relay,
    /// After a 101: bytes pass both ways untouched.
    Tunnel,
    /// The connection is finished.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    /// The client connection may serve another request afterwards.
    pub keep: bool,
    /// The request asks for WebSocket and the site allows it.
    pub upgrade: bool,
}

impl State {
    const fn at(phase: Phase) -> State {
        State { phase, keep: false, upgrade: false }
    }
}

/// What came of the last action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A request head we will forward.
    Request { keep: bool },
    /// The same, asking for WebSocket on a site that allows it.
    Upgrade { keep: bool },
    /// The exchange ends here; the status is what the client should be told
    /// if it can still be told. Also used when we answer a request ourselves
    /// without an error (200, 301).
    Fail(u16),
    /// The client connection is lost.
    Gone,
    Connected,
    /// The whole request, head and body, is forwarded.
    Sent,
    /// The upstream sent a 1xx other than 101.
    Interim,
    /// The upstream sent 101.
    Switching,
    /// The upstream sent a final response head. `delimited`: the client will
    /// see where our response ends without the connection closing.
    Final { delimited: bool },
    /// The response body, or the tunnel, has finished.
    Done,
}

/// What the caller must do, in order. Only the last action of a list is
/// waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Read and check a request head.
    ReadHead,
    /// Open a new upstream connection.
    Connect,
    /// Send the request, head and body.
    Forward,
    /// Read a response head.
    ReadResponse,
    /// Pass the 1xx head to the client.
    Interim,
    /// Send the response, head and body; `keep` is what the client is told.
    Respond { keep: bool },
    /// Write our own response with this status, then close.
    Error(u16),
    /// Pass the 101 head, then run the tunnel.
    Tunnel,
}

/// What the caller starts a new connection with.
pub fn start() -> (State, Vec<Action>) {
    (State::at(Phase::Idle), vec![Action::ReadHead])
}

pub fn step(s: State, e: Event) -> (State, Vec<Action>) {
    let close = |actions| (State::at(Phase::Closed), actions);
    match (s.phase, e) {
        (Phase::Closed, _) => (s, vec![]),
        (_, Event::Gone) => close(vec![]),
        // Our own response is possible only while none has been started.
        (Phase::Idle | Phase::Connect | Phase::Forward | Phase::Response, Event::Fail(status)) => {
            close(vec![Action::Error(status)])
        }
        (_, Event::Fail(_)) => close(vec![]),
        (Phase::Idle, Event::Request { keep }) => {
            (State { phase: Phase::Connect, keep, upgrade: false }, vec![Action::Connect])
        }
        (Phase::Idle, Event::Upgrade { keep }) => {
            (State { phase: Phase::Connect, keep, upgrade: true }, vec![Action::Connect])
        }
        (Phase::Connect, Event::Connected) => {
            (State { phase: Phase::Forward, ..s }, vec![Action::Forward])
        }
        (Phase::Forward, Event::Sent) => {
            (State { phase: Phase::Response, ..s }, vec![Action::ReadResponse])
        }
        (Phase::Response, Event::Interim) => (s, vec![Action::Interim, Action::ReadResponse]),
        (Phase::Response, Event::Switching) if s.upgrade => {
            (State { phase: Phase::Tunnel, ..s }, vec![Action::Tunnel])
        }
        (Phase::Response, Event::Switching) => close(vec![Action::Error(502)]),
        (Phase::Response, Event::Final { delimited }) => {
            let keep = s.keep && delimited;
            (State { phase: Phase::Relay, keep, upgrade: s.upgrade }, vec![Action::Respond { keep }])
        }
        (Phase::Relay, Event::Done) if s.keep => (State::at(Phase::Idle), vec![Action::ReadHead]),
        _ => close(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = include_str!("../../tests/vectors/http_fsm.txt");

    fn version(word: &str) -> Version {
        match word {
            "1.0" => Version::V10,
            "1.1" => Version::V11,
            _ => panic!("version {word}"),
        }
    }

    fn length(word: &str) -> Length {
        match word {
            "none" => Length::None,
            "one" => Length::One,
            "bad" => Length::Bad,
            _ => panic!("length {word}"),
        }
    }

    fn coding(word: &str) -> Coding {
        match word {
            "none" => Coding::None,
            "chunked" => Coding::Chunked,
            "other" => Coding::Other,
            "bad" => Coding::Bad,
            _ => panic!("coding {word}"),
        }
    }

    fn framing(word: &str) -> Framing {
        match word {
            "empty" => Framing::Empty,
            "length" => Framing::Length,
            "chunked" => Framing::Chunked,
            "close" => Framing::Close,
            "reject" => Framing::Reject,
            "unsupported" => Framing::Unsupported,
            _ => panic!("framing {word}"),
        }
    }

    fn state(words: &[&str]) -> State {
        let phase = match words[0] {
            "idle" => Phase::Idle,
            "connect" => Phase::Connect,
            "forward" => Phase::Forward,
            "response" => Phase::Response,
            "relay" => Phase::Relay,
            "tunnel" => Phase::Tunnel,
            "closed" => Phase::Closed,
            other => panic!("phase {other}"),
        };
        State { phase, keep: words[1] == "keep", upgrade: words[2] == "upgrade" }
    }

    fn event(word: &str) -> Event {
        let (kind, detail) = word.split_once(':').unwrap();
        match kind {
            "request" => Event::Request { keep: detail == "keep" },
            "upgrade" => Event::Upgrade { keep: detail == "keep" },
            "fail" => Event::Fail(detail.parse().unwrap()),
            "gone" => Event::Gone,
            "connected" => Event::Connected,
            "sent" => Event::Sent,
            "interim" => Event::Interim,
            "switching" => Event::Switching,
            "final" => Event::Final { delimited: detail == "delimited" },
            "done" => Event::Done,
            other => panic!("event {other}"),
        }
    }

    fn action(word: &str) -> Action {
        let (kind, detail) = word.split_once(':').unwrap();
        match kind {
            "read_head" => Action::ReadHead,
            "connect" => Action::Connect,
            "forward" => Action::Forward,
            "read_response" => Action::ReadResponse,
            "interim" => Action::Interim,
            "respond" => Action::Respond { keep: detail == "keep" },
            "error" => Action::Error(detail.parse().unwrap()),
            "tunnel" => Action::Tunnel,
            other => panic!("action {other}"),
        }
    }

    fn result(words: &[&str]) -> (State, Vec<Action>) {
        (state(&words[..3]), words[3..].iter().map(|w| action(w)).collect())
    }

    /// Every function here gives, for every input, what the spec gives.
    #[test]
    fn same_as_the_spec_on_every_input() {
        let mut rows = 0;
        for line in TABLE.lines().filter(|l| !l.starts_with('#')) {
            let (input, output) = line.split_once(" => ").unwrap();
            let input: Vec<&str> = input.split(' ').collect();
            let output: Vec<&str> = output.split(' ').collect();
            match input[0] {
                "start" => assert_eq!(start(), result(&output), "{line}"),
                "step" => assert_eq!(
                    step(state(&input[1..4]), event(input[4])),
                    result(&output),
                    "{line}"
                ),
                "request_framing" => assert_eq!(
                    request_framing(version(input[1]), length(input[2]), coding(input[3])),
                    framing(output[0]),
                    "{line}"
                ),
                "response_framing" => assert_eq!(
                    response_framing(
                        version(input[1]),
                        input[2] == "bodiless",
                        length(input[3]),
                        coding(input[4])
                    ),
                    framing(output[0]),
                    "{line}"
                ),
                "client_framing" => assert_eq!(
                    client_framing(framing(input[1]), version(input[2])),
                    framing(output[0]),
                    "{line}"
                ),
                other => panic!("unknown function {other}"),
            }
            rows += 1;
        }
        assert_eq!(rows, 753);
    }
}
