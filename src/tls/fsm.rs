//! The TLS 1.3 server state machine of one connection.
//!
//! This is `Step` of `spec/Handshake.tla`, kept in step with it by the test
//! at the end: TLC prints the function for every state and event into
//! `tests/vectors/handshake_fsm.txt`, and the test replays that table.
//! Bytes and keys are the caller's business; an event already says what a
//! record turned out to be.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for the first ClientHello.
    Start,
    /// HelloRetryRequest sent, waiting for the second ClientHello.
    Retry,
    /// Our whole flight is sent, waiting for the client Finished.
    WaitFinished,
    /// Application data flows.
    Open,
    /// Nothing more is sent or accepted.
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    /// The start of a handshake message has arrived, the rest has not.
    pub partial: bool,
    /// The peer asked for a KeyUpdate and we have not sent ours yet.
    pub owed: bool,
    /// The client offered early data, which we skip.
    pub early: bool,
}

pub const START: State = State { phase: Phase::Start, partial: false, owed: false, early: false };
const CLOSED: State = State { phase: Phase::Closed, ..START };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alert {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    IllegalParameter,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InternalError,
    MissingExtension,
    UnrecognizedName,
    NoApplicationProtocol,
}

impl Alert {
    /// The alert's number on the wire (RFC 8446 section 6).
    pub fn code(self) -> u8 {
        match self {
            Alert::CloseNotify => 0,
            Alert::UnexpectedMessage => 10,
            Alert::BadRecordMac => 20,
            Alert::RecordOverflow => 22,
            Alert::HandshakeFailure => 40,
            Alert::IllegalParameter => 47,
            Alert::AccessDenied => 49,
            Alert::DecodeError => 50,
            Alert::DecryptError => 51,
            Alert::ProtocolVersion => 70,
            Alert::InternalError => 80,
            Alert::MissingExtension => 109,
            Alert::UnrecognizedName => 112,
            Alert::NoApplicationProtocol => 120,
        }
    }
}

/// What one record from the peer turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// The dummy ChangeCipherSpec of middlebox compatibility.
    Ccs,
    CloseNotify,
    /// Any other alert.
    Alert,
    Data,
    /// Handshake bytes that do not yet complete a message.
    Fragment,
    /// A ClientHello we can serve.
    Hello,
    /// A ClientHello we can serve once it brings an X25519 key share.
    HelloRetry,
    HelloEarly,
    HelloRetryEarly,
    /// A Finished message that verifies.
    Finished,
    FinishedBad,
    KeyUpdate,
    KeyUpdateRequest,
    /// Any other handshake message.
    Other,
}

impl Content {
    fn is_handshake(self) -> bool {
        !matches!(self, Content::Ccs | Content::CloseNotify | Content::Alert | Content::Data)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A record that arrived unencrypted.
    Plain(Content),
    /// A record that decrypted under the current read keys.
    Protected(Content),
    /// A record that does not decrypt under the current read keys.
    Undecryptable,
    /// A record or message we cannot use; the alert to send.
    Invalid(Alert),
    /// The transport failed: nothing more can be sent.
    Lost,
    /// The application wants to send data.
    Write,
    /// We end the connection: the application is done, a deadline passed,
    /// or the peer's stream ended.
    Close,
}

/// Which keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Handshake,
    Data,
    /// The next generation of the data keys (KeyUpdate).
    Next,
}

/// What we send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    ServerHello,
    Retry,
    Ccs,
    /// EncryptedExtensions, Certificate, CertificateVerify, Finished.
    Flight,
    KeyUpdate,
    Data,
}

/// Actions, in the order the caller must carry them out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Send(Kind),
    Alert(Alert),
    ReadKeys(Level),
    WriteKeys(Level),
    /// Hand the data to the application.
    Deliver,
    /// Drop the record and count its size against the early data allowance.
    Skip,
}

impl Action {
    /// The action puts something on the wire, or changes what goes on it,
    /// so it needs the write lock.
    pub fn needs_write_lock(self) -> bool {
        matches!(self, Action::Send(_) | Action::Alert(_) | Action::WriteKeys(_))
    }
}

type Result = (State, Vec<Action>);

fn go(s: State, phase: Phase, actions: Vec<Action>) -> Result {
    (State { phase, partial: false, ..s }, actions)
}

fn fail(alert: Alert) -> Result {
    (CLOSED, vec![Action::Alert(alert)])
}

/// Everything after ServerHello.
fn flight(first: Action, ccs: bool) -> Vec<Action> {
    let mut actions = vec![first];
    if ccs {
        actions.push(Action::Send(Kind::Ccs));
    }
    actions.extend([
        Action::WriteKeys(Level::Handshake),
        Action::ReadKeys(Level::Handshake),
        Action::Send(Kind::Flight),
        Action::WriteKeys(Level::Data),
    ]);
    actions
}

fn on_record(s: State, protected: bool, c: Content) -> Result {
    use Content as C;
    use Phase as P;
    // The first record that decrypts ends the skipping of early data.
    let t = if protected { State { early: false, ..s } } else { s };
    let have_read_keys = matches!(s.phase, P::WaitFinished | P::Open);
    if s.partial && !c.is_handshake() {
        // Nothing may come between the pieces of a handshake message.
        return fail(Alert::UnexpectedMessage);
    }
    if c == C::Ccs {
        // Dropped, but only unencrypted and only between the first
        // ClientHello and the client Finished.
        return if !protected && matches!(s.phase, P::Retry | P::WaitFinished) {
            (s, vec![])
        } else {
            fail(Alert::UnexpectedMessage)
        };
    }
    if s.early && s.phase == P::Retry && !protected && c == C::Data {
        // Early data sent before our HelloRetryRequest arrived.
        return (s, vec![Action::Skip]);
    }
    if protected != have_read_keys {
        return fail(Alert::UnexpectedMessage);
    }
    match (s.phase, c) {
        (_, C::Fragment) => (State { partial: true, ..t }, vec![]),
        (_, C::CloseNotify) => (CLOSED, vec![Action::Alert(Alert::CloseNotify)]),
        (_, C::Alert) => (CLOSED, vec![]),
        (P::Start, C::Hello | C::HelloEarly) => go(
            State { early: c == C::HelloEarly, ..s },
            P::WaitFinished,
            flight(Action::Send(Kind::ServerHello), true),
        ),
        (P::Start, C::HelloRetry | C::HelloRetryEarly) => go(
            State { early: c == C::HelloRetryEarly, ..s },
            P::Retry,
            vec![Action::Send(Kind::Retry), Action::Send(Kind::Ccs)],
        ),
        (P::Retry, C::Hello) => {
            go(State { early: false, ..s }, P::WaitFinished, flight(Action::Send(Kind::ServerHello), false))
        }
        // A second ClientHello must bring the key share and must not offer
        // early data again.
        (P::Retry, C::HelloRetry | C::HelloEarly | C::HelloRetryEarly) => fail(Alert::IllegalParameter),
        (P::WaitFinished, C::Finished) => go(t, P::Open, vec![Action::ReadKeys(Level::Data)]),
        (P::WaitFinished, C::FinishedBad) => fail(Alert::DecryptError),
        (P::Open, C::Data) => go(t, P::Open, vec![Action::Deliver]),
        (P::Open, C::KeyUpdate) => go(t, P::Open, vec![Action::ReadKeys(Level::Next)]),
        // Our own KeyUpdate goes out with the next write, not now, so that
        // reading never has to wait for writing.
        (P::Open, C::KeyUpdateRequest) => {
            go(State { owed: true, ..t }, P::Open, vec![Action::ReadKeys(Level::Next)])
        }
        _ => fail(Alert::UnexpectedMessage),
    }
}

pub fn step(s: State, e: Event) -> Result {
    if s.phase == Phase::Closed {
        return (s, vec![]);
    }
    match e {
        Event::Lost => (CLOSED, vec![]),
        Event::Close => (CLOSED, vec![Action::Alert(Alert::CloseNotify)]),
        Event::Invalid(alert) => fail(alert),
        Event::Undecryptable if s.early && s.phase == Phase::WaitFinished => (s, vec![Action::Skip]),
        Event::Undecryptable => fail(Alert::BadRecordMac),
        Event::Write if s.phase != Phase::Open => (s, vec![]),
        Event::Write if s.owed => (
            State { owed: false, ..s },
            vec![Action::Send(Kind::KeyUpdate), Action::WriteKeys(Level::Next), Action::Send(Kind::Data)],
        ),
        Event::Write => (s, vec![Action::Send(Kind::Data)]),
        Event::Plain(c) => on_record(s, false, c),
        Event::Protected(c) => on_record(s, true, c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = include_str!("../../tests/vectors/handshake_fsm.txt");

    fn state(words: &[&str]) -> State {
        let phase = match words[0] {
            "start" => Phase::Start,
            "retry" => Phase::Retry,
            "wait_finished" => Phase::WaitFinished,
            "open" => Phase::Open,
            "closed" => Phase::Closed,
            other => panic!("phase {other}"),
        };
        State { phase, partial: words[1] == "partial", owed: words[2] == "owed", early: words[3] == "skipping" }
    }

    fn alert(word: &str) -> Alert {
        match word {
            "close_notify" => Alert::CloseNotify,
            "unexpected_message" => Alert::UnexpectedMessage,
            "bad_record_mac" => Alert::BadRecordMac,
            "record_overflow" => Alert::RecordOverflow,
            "handshake_failure" => Alert::HandshakeFailure,
            "illegal_parameter" => Alert::IllegalParameter,
            "access_denied" => Alert::AccessDenied,
            "decode_error" => Alert::DecodeError,
            "decrypt_error" => Alert::DecryptError,
            "protocol_version" => Alert::ProtocolVersion,
            "internal_error" => Alert::InternalError,
            "missing_extension" => Alert::MissingExtension,
            "unrecognized_name" => Alert::UnrecognizedName,
            "no_application_protocol" => Alert::NoApplicationProtocol,
            other => panic!("alert {other}"),
        }
    }

    fn content(word: &str) -> Content {
        match word {
            "ccs" => Content::Ccs,
            "close_notify" => Content::CloseNotify,
            "alert" => Content::Alert,
            "data" => Content::Data,
            "fragment" => Content::Fragment,
            "hello" => Content::Hello,
            "hello_retry" => Content::HelloRetry,
            "hello_early" => Content::HelloEarly,
            "hello_retry_early" => Content::HelloRetryEarly,
            "finished" => Content::Finished,
            "finished_bad" => Content::FinishedBad,
            "key_update" => Content::KeyUpdate,
            "key_update_request" => Content::KeyUpdateRequest,
            "other" => Content::Other,
            other => panic!("content {other}"),
        }
    }

    fn event(word: &str) -> Event {
        let (kind, detail) = word.split_once(':').unwrap();
        match kind {
            "plain" => Event::Plain(content(detail)),
            "protected" => Event::Protected(content(detail)),
            "undecryptable" => Event::Undecryptable,
            "invalid" => Event::Invalid(alert(detail)),
            "lost" => Event::Lost,
            "write" => Event::Write,
            "close" => Event::Close,
            other => panic!("event {other}"),
        }
    }

    fn level(word: &str) -> Level {
        match word {
            "handshake" => Level::Handshake,
            "data" => Level::Data,
            "next" => Level::Next,
            other => panic!("level {other}"),
        }
    }

    fn action(word: &str) -> Action {
        let (kind, detail) = word.split_once(':').unwrap();
        match kind {
            "send" => Action::Send(match detail {
                "server_hello" => Kind::ServerHello,
                "retry" => Kind::Retry,
                "ccs" => Kind::Ccs,
                "flight" => Kind::Flight,
                "key_update" => Kind::KeyUpdate,
                "data" => Kind::Data,
                other => panic!("kind {other}"),
            }),
            "alert" => Action::Alert(alert(detail)),
            "read_keys" => Action::ReadKeys(level(detail)),
            "write_keys" => Action::WriteKeys(level(detail)),
            "deliver" => Action::Deliver,
            "skip" => Action::Skip,
            other => panic!("action {other}"),
        }
    }

    /// `step` gives, for every state and event, what the spec gives.
    #[test]
    fn same_as_the_spec_on_every_input() {
        let mut rows = 0;
        for line in TABLE.lines().filter(|l| !l.starts_with('#')) {
            let (input, output) = line.split_once(" => ").unwrap();
            let input: Vec<&str> = input.split(' ').collect();
            let output: Vec<&str> = output.split(' ').collect();
            let expected = (state(&output[..4]), output[4..].iter().map(|w| action(w)).collect::<Vec<_>>());
            match input[0] {
                "start" => assert_eq!((START, vec![]), expected, "{line}"),
                "step" => assert_eq!(step(state(&input[1..5]), event(input[5])), expected, "{line}"),
                other => panic!("unknown function {other}"),
            }
            rows += 1;
        }
        assert_eq!(rows, 1801);
    }

    #[test]
    fn alert_codes_are_distinct() {
        let all = [
            Alert::CloseNotify, Alert::UnexpectedMessage, Alert::BadRecordMac, Alert::RecordOverflow,
            Alert::HandshakeFailure, Alert::IllegalParameter, Alert::AccessDenied, Alert::DecodeError,
            Alert::DecryptError, Alert::ProtocolVersion, Alert::InternalError, Alert::MissingExtension,
            Alert::UnrecognizedName, Alert::NoApplicationProtocol,
        ];
        let mut codes: Vec<u8> = all.iter().map(|a| a.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }
}
