//! A TLS connection: the handshake, then a `Stream` the proxy reads and
//! writes through.
//!
//! The design is the one `spec/Handshake.tla` checks (part 2). The state
//! machine (`fsm`) decides; this code carries out its actions. Three locks:
//!
//! - `fsm`: the state machine's state, held only for one call of `step`;
//! - `reader`: what reading needs (read keys, buffers); only one thread
//!   reads at a time;
//! - `writer`: the write lock (write keys, sequence number). A thread that
//!   sends for the application takes it before calling `step`; a thread
//!   that handles a record from the peer calls `step` first and takes it
//!   only if an action needs it. Reading application data never does, so a
//!   writer blocked on a slow client cannot hold up the reader.
//!
//! The lock order is reader, then writer, then fsm; `fsm` is never held
//! while another lock is taken.

use super::fsm::{self, Action, Alert, Content, Event, Kind, Level, Phase, State};
use super::keys::{self, HandshakeSecrets, Secret, TrafficKeys, Transcript};
use super::msgs;
use super::record::{self, Opened, ReadError};
use crate::config::{Config, Site};
use crate::crypto::{self, HASH_LEN, SigningKey};
use crate::log::Log;
use crate::net;
use crate::pem;
use crate::stream::{Buffer, Stream};
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long a handshake may take, from the first byte to the client
/// Finished.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How much early data we skip before we give up on the connection.
const EARLY_DATA_LIMIT: usize = 16 * 1024;

/// A site's certificate chain and private key.
pub struct Identity {
    pub chain: Vec<Vec<u8>>,
    pub key: SigningKey,
}

impl Identity {
    /// Reads and checks a site's certificate chain and key. The key must be
    /// an ECDSA P-256 key, and its public key must be the one in the first
    /// certificate of the chain.
    pub fn load(cert: &Path, key: &Path) -> Result<Identity, String> {
        let read = |path: &Path| std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
        let chain = pem::certificates(&read(cert)?).map_err(|e| format!("{}: {e}", cert.display()))?;
        let scalar = pem::private_key(&read(key)?).map_err(|e| format!("{}: {e}", key.display()))?;
        let key_error = || format!("{}: the key is not a valid P-256 private key", key.display());
        let signing = SigningKey::from_bytes(&scalar).map_err(|_| key_error())?;
        let public = signing.public_key().map_err(|_| key_error())?;
        let leaf = chain.first().map(Vec::as_slice).unwrap_or(&[]);
        if !leaf.windows(public.len()).any(|w| w == public) {
            return Err(format!("{}: the key does not belong to the certificate in {}", key.display(), cert.display()));
        }
        Ok(Identity { chain, key: signing })
    }
}

/// What a handshake needs to know: the sites, their identities (in the
/// order of `config.sites`; `None` for a site without a certificate), and
/// the client's address.
pub struct Served<'a> {
    pub config: &'a Config,
    pub identities: &'a [Option<Identity>],
    pub peer: IpAddr,
    /// How long the handshake may take; `HANDSHAKE_TIMEOUT` but in tests.
    pub timeout: Duration,
}

impl<'a> Served<'a> {
    fn find(&self, name: &[u8]) -> Option<(&'a Site, &'a Identity)> {
        let index = self.config.sites.iter().position(|s| name.eq_ignore_ascii_case(s.name.as_bytes()))?;
        let site = self.config.sites.get(index)?;
        let identity = self.identities.get(index)?.as_ref()?;
        Some((site, identity))
    }
}

/// What the handshake keeps between its steps.
struct Handshake<'a> {
    transcript: Transcript,
    site: Option<(&'a Site, &'a Identity)>,
    session_id: Vec<u8>,
    alpn: bool,
    /// Our X25519 public key and the secret shared with the client.
    public: [u8; 32],
    shared: [u8; 32],
    secrets: Option<HandshakeSecrets>,
    /// The transcript hash up to our Finished, and the application secrets.
    finished_hash: [u8; HASH_LEN],
    client_application: Secret,
    server_application: Secret,
}

impl Drop for Handshake<'_> {
    fn drop(&mut self) {
        keys::wipe(&mut self.shared);
        keys::wipe(&mut self.client_application);
        keys::wipe(&mut self.server_application);
    }
}

/// One direction's keys.
struct Direction {
    secret: Secret,
    keys: Option<TrafficKeys>,
    sequence: u64,
}

impl Drop for Direction {
    fn drop(&mut self) {
        keys::wipe(&mut self.secret);
    }
}

impl Direction {
    fn none() -> Direction {
        Direction { secret: [0; HASH_LEN], keys: None, sequence: 0 }
    }

    fn switch(&mut self, secret: Secret) {
        self.keys = Some(TrafficKeys::new(&secret));
        self.secret = secret;
        self.sequence = 0;
    }

    fn next(&mut self) {
        self.switch(keys::next_secret(&self.secret));
    }

    /// The sequence number for this record, moving on to the next. A
    /// sequence number that would wrap ends the connection (section 5.3).
    fn take_sequence(&mut self) -> Option<u64> {
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1)?;
        Some(sequence)
    }
}

struct ReadSide {
    buffer: Buffer,
    keys: Direction,
    /// The pieces of an incomplete handshake message.
    message: Vec<u8>,
    /// Application data read and not yet handed out.
    plain: Vec<u8>,
    /// How much early data was skipped.
    skipped: usize,
}

struct WriteSide {
    keys: Direction,
    /// A write failed: the stream may hold half a record, and nothing more
    /// may be sent.
    dead: bool,
}

pub struct TlsStream<'a, S: Stream> {
    transport: S,
    fsm: Mutex<State>,
    reader: Mutex<ReadSide>,
    writer: Mutex<WriteSide>,
    /// How long one `read` may take in all, however many records without
    /// data come meanwhile.
    read_timeout: Mutex<Option<Duration>>,
    /// The client ended with close_notify. Otherwise a closed connection
    /// was cut off or failed, and reads say so instead of reporting an
    /// orderly end.
    clean_end: AtomicBool,
    log: &'a dyn Log,
    peer: IpAddr,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere never leaves these half updated in a way that
    // matters more than ending the connection, which the panic does anyway.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn alert_name(code: u8) -> String {
    let name = match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => return format!("alert {code}"),
    };
    name.to_string()
}

/// What reading one record came to.
enum Read {
    /// An event for the state machine, and the application data it carried.
    Event(Event, Vec<u8>),
    /// Nothing came in time.
    Timeout,
}

impl<'a, S: Stream> TlsStream<'a, S> {
    fn new(transport: S, log: &'a dyn Log, peer: IpAddr) -> Self {
        TlsStream {
            transport,
            fsm: Mutex::new(fsm::START),
            reader: Mutex::new(ReadSide {
                buffer: Buffer::new(),
                keys: Direction::none(),
                message: Vec::new(),
                plain: Vec::new(),
                skipped: 0,
            }),
            writer: Mutex::new(WriteSide { keys: Direction::none(), dead: false }),
            read_timeout: Mutex::new(None),
            clean_end: AtomicBool::new(false),
            log,
            peer,
        }
    }

    fn state(&self) -> State {
        *lock(&self.fsm)
    }

    fn step(&self, event: Event) -> Vec<Action> {
        let mut state = lock(&self.fsm);
        let (next, actions) = fsm::step(*state, event);
        *state = next;
        actions
    }

    fn note_alert(&self, sent: bool, code: u8) {
        if code != 0 {
            let who = if sent { "sent" } else { "received" };
            self.log.error(&format!("{} tls: {who} {}", net::canonical(self.peer), alert_name(code)));
        }
    }

    // ------------------------------------------------------------ reading

    /// Reads one record and says what it is.
    fn read_record<'s>(&self, reader: &mut ReadSide, hs: Option<&mut Handshake<'s>>, served: Option<&Served<'s>>) -> Read {
        let record = match record::read(&mut reader.buffer, &self.transport) {
            Ok(record) => record,
            Err(ReadError::Timeout) => return Read::Timeout,
            Err(ReadError::End | ReadError::Cut) => return Read::Event(Event::Close, Vec::new()),
            Err(ReadError::Refused(alert)) => return Read::Event(Event::Invalid(alert), Vec::new()),
        };
        let state = self.state();
        let size = record.payload.len();
        // Early data we did not accept is skipped, up to a limit.
        let skip = |reader: &mut ReadSide, event: Event| -> Read {
            reader.skipped = reader.skipped.saturating_add(size);
            if reader.skipped > EARLY_DATA_LIMIT {
                Read::Event(Event::Invalid(Alert::UnexpectedMessage), Vec::new())
            } else {
                Read::Event(event, Vec::new())
            }
        };
        let Some(keys) = &reader.keys.keys else {
            return match record.content_type {
                record::APPLICATION_DATA if state.early && state.phase == Phase::Retry => {
                    skip(reader, Event::Plain(Content::Data))
                }
                record::APPLICATION_DATA => Read::Event(Event::Plain(Content::Data), Vec::new()),
                _ => self.content(reader, hs, served, state, false, record.content_type, record.payload),
            };
        };
        match record.content_type {
            record::APPLICATION_DATA => {}
            // Only the dummy ChangeCipherSpec may come unencrypted now. An
            // unencrypted alert is refused too, but read so that it is
            // logged: it tells why the client gave up.
            record::CHANGE_CIPHER_SPEC | record::ALERT => {
                return self.content(reader, hs, served, state, false, record.content_type, record.payload);
            }
            _ => return Read::Event(Event::Plain(Content::Other), Vec::new()),
        }
        let opened = record::open(keys, reader.keys.sequence, &record);
        match opened {
            Opened::Undecryptable if state.early && state.phase == Phase::WaitFinished => {
                skip(reader, Event::Undecryptable)
            }
            Opened::Undecryptable => Read::Event(Event::Undecryptable, Vec::new()),
            Opened::Refused(alert) => Read::Event(Event::Invalid(alert), Vec::new()),
            Opened::Content(content_type, content) => {
                if reader.keys.take_sequence().is_none() {
                    return Read::Event(Event::Invalid(Alert::InternalError), Vec::new());
                }
                self.content(reader, hs, served, state, true, content_type, content)
            }
        }
    }

    /// What the content of a readable record is.
    #[allow(clippy::too_many_arguments)]
    fn content<'s>(
        &self,
        reader: &mut ReadSide,
        hs: Option<&mut Handshake<'s>>,
        served: Option<&Served<'s>>,
        state: State,
        protected: bool,
        content_type: u8,
        content: Vec<u8>,
    ) -> Read {
        let wrap = |c: Content| if protected { Event::Protected(c) } else { Event::Plain(c) };
        let event = match content_type {
            record::CHANGE_CIPHER_SPEC if content == [1] => wrap(Content::Ccs),
            record::ALERT => match content.as_slice() {
                [_, code] => {
                    self.note_alert(false, *code);
                    wrap(if *code == 0 { Content::CloseNotify } else { Content::Alert })
                }
                // An empty alert is refused like an empty handshake record
                // (section 5.4), anything else that is not two bytes as
                // malformed.
                [] => {
                    self.log.error(&format!("{} tls: received an empty alert", net::canonical(self.peer)));
                    Event::Invalid(Alert::UnexpectedMessage)
                }
                _ => {
                    self.log.error(&format!("{} tls: received a malformed alert", net::canonical(self.peer)));
                    Event::Invalid(Alert::DecodeError)
                }
            },
            record::APPLICATION_DATA => return Read::Event(wrap(Content::Data), content),
            record::HANDSHAKE => self.handshake(reader, hs, served, state, protected, &content),
            _ => Event::Invalid(Alert::UnexpectedMessage),
        };
        Read::Event(event, Vec::new())
    }

    /// Handshake bytes: put together into messages, which must end where
    /// their record ends.
    fn handshake<'s>(
        &self,
        reader: &mut ReadSide,
        hs: Option<&mut Handshake<'s>>,
        served: Option<&Served<'s>>,
        state: State,
        protected: bool,
        bytes: &[u8],
    ) -> Event {
        let wrap = |c: Content| if protected { Event::Protected(c) } else { Event::Plain(c) };
        if bytes.is_empty() {
            return Event::Invalid(Alert::UnexpectedMessage);
        }
        reader.message.extend_from_slice(bytes);
        let length = match reader.message.get(1..4) {
            Some(&[a, b, c]) => usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c),
            _ => return wrap(Content::Fragment),
        };
        if length > msgs::MESSAGE_LIMIT {
            return Event::Invalid(Alert::DecodeError);
        }
        let whole = length.saturating_add(4);
        if reader.message.len() < whole {
            return wrap(Content::Fragment);
        }
        if reader.message.len() > whole {
            // Something after the end of a message in the same record.
            return Event::Invalid(Alert::UnexpectedMessage);
        }
        let message = std::mem::take(&mut reader.message);
        match (message.first(), state.phase, hs, served) {
            (Some(&msgs::CLIENT_HELLO), Phase::Start | Phase::Retry, Some(hs), Some(served)) => {
                match self.client_hello(&message, state.phase, hs, served) {
                    Ok(content) => wrap(content),
                    Err(alert) => Event::Invalid(alert),
                }
            }
            (Some(&msgs::FINISHED), Phase::WaitFinished, Some(hs), _) => {
                let expected = hs.secrets.as_ref().map(|s| keys::verify_data(&s.client, &hs.finished_hash));
                match (msgs::client_finished(&message), expected) {
                    (Some(got), Some(expected)) if crypto::ct_eq(got, &expected) => wrap(Content::Finished),
                    (Some(_), _) => wrap(Content::FinishedBad),
                    (None, _) => Event::Invalid(Alert::DecodeError),
                }
            }
            (Some(&msgs::KEY_UPDATE), Phase::Open, _, _) => match msgs::client_key_update(&message) {
                Ok(false) => wrap(Content::KeyUpdate),
                Ok(true) => wrap(Content::KeyUpdateRequest),
                Err(alert) => Event::Invalid(alert),
            },
            _ => wrap(Content::Other),
        }
    }

    /// Checks a ClientHello and gets ready to answer it.
    fn client_hello<'s>(
        &self,
        message: &[u8],
        phase: Phase,
        hs: &mut Handshake<'s>,
        served: &Served<'s>,
    ) -> Result<Content, Alert> {
        let hello = msgs::client_hello(message)?;
        let found = served.find(hello.server_name).ok_or(Alert::UnrecognizedName)?;
        if !found.0.allows(served.peer) {
            return Err(Alert::AccessDenied);
        }
        if phase == Phase::Retry {
            // The second ClientHello is for the same site, and brings
            // exactly the one key share we asked for (section 4.1.2).
            let same = hs.site.is_some_and(|(site, _)| std::ptr::eq(site, found.0));
            if !same || hello.shares != 1 {
                return Err(Alert::IllegalParameter);
            }
        }
        hs.site = Some(found);
        hs.session_id = hello.session_id.to_vec();
        hs.alpn = hello.alpn;
        hs.transcript.add(message);
        let Some(share) = hello.share else {
            return Ok(if hello.early { Content::HelloRetryEarly } else { Content::HelloRetry });
        };
        let mut secret = [0u8; 32];
        crypto::random(&mut secret).map_err(|_| Alert::InternalError)?;
        hs.public = crypto::x25519_public(&secret);
        // An all-zero result means the client's share is a small-order
        // point (section 7.4.2).
        let shared = crypto::x25519(&secret, &share);
        keys::wipe(&mut secret);
        hs.shared = shared.map_err(|_| Alert::IllegalParameter)?;
        Ok(if hello.early { Content::HelloEarly } else { Content::Hello })
    }

    // ------------------------------------------------------- carrying out

    /// Carries out actions in order. Those that need the write lock take it
    /// when the first of them comes. `data` is what `Deliver` hands over,
    /// `out` what `Send(Data)` sends.
    fn carry_out<'g>(
        &'g self,
        actions: Vec<Action>,
        reader: &mut ReadSide,
        mut hs: Option<&mut Handshake<'_>>,
        data: Vec<u8>,
        mut writer: Option<MutexGuard<'g, WriteSide>>,
        out: &[u8],
    ) -> Result<(), ()> {
        let mut data = Some(data);
        for action in actions {
            if action.needs_write_lock() && writer.is_none() {
                writer = Some(lock(&self.writer));
            }
            match action {
                Action::ReadKeys(level) => {
                    let secret = match (level, hs.as_deref()) {
                        (Level::Handshake, Some(h)) => h.secrets.as_ref().map(|s| s.client),
                        (Level::Data, Some(h)) => Some(h.client_application),
                        (Level::Next, _) => None,
                        _ => return Err(()),
                    };
                    match secret {
                        Some(secret) => reader.keys.switch(secret),
                        None if level == Level::Next => reader.keys.next(),
                        None => return Err(()),
                    }
                }
                Action::Deliver => reader.plain.extend(data.take().unwrap_or_default()),
                Action::Skip => {}
                _ => {
                    let Some(w) = writer.as_mut() else { return Err(()) };
                    if w.dead {
                        // Nothing more goes out; what was still to send is
                        // dropped.
                        return Ok(());
                    }
                    match self.write_action(action, w, hs.as_deref_mut(), out) {
                        Ok(()) => {}
                        // Something of ours failed, not the transport: say
                        // so to the client, if it can still be said.
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            self.log.error(&format!("{} tls: internal error", net::canonical(self.peer)));
                            for alert in self.step(Event::Invalid(Alert::InternalError)) {
                                if self.write_action(alert, w, None, &[]).is_err() {
                                    break;
                                }
                            }
                            w.dead = true;
                            return Err(());
                        }
                        Err(_) => {
                            w.dead = true;
                            self.step(Event::Lost);
                            return Err(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Sends records, splitting content longer than a record may carry.
    fn send(&self, w: &mut WriteSide, content_type: u8, content: &[u8]) -> io::Result<()> {
        let mut pieces = content.chunks(record::MAX_PLAINTEXT).peekable();
        if pieces.peek().is_none() {
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(content.len() + 32);
        for piece in pieces {
            if w.keys.keys.is_none() {
                bytes.extend(record::plain(content_type, piece));
                continue;
            }
            let sequence = w.keys.take_sequence().ok_or(io::ErrorKind::InvalidData)?;
            let keys = w.keys.keys.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            let sealed = record::seal(keys, sequence, content_type, piece).map_err(|_| io::ErrorKind::InvalidData)?;
            bytes.extend(sealed);
        }
        self.transport.write_all(&bytes)
    }

    fn write_action(&self, action: Action, w: &mut WriteSide, hs: Option<&mut Handshake<'_>>, out: &[u8]) -> io::Result<()> {
        let internal = || io::Error::from(io::ErrorKind::InvalidData);
        match action {
            Action::Alert(alert) => {
                self.note_alert(true, alert.code());
                self.send(w, record::ALERT, &msgs::alert(alert))
            }
            Action::Send(Kind::Ccs) => self.transport.write_all(&record::plain(record::CHANGE_CIPHER_SPEC, &[1])),
            Action::Send(Kind::Data) => self.send(w, record::APPLICATION_DATA, out),
            Action::Send(Kind::KeyUpdate) => self.send(w, record::HANDSHAKE, &msgs::key_update(false)),
            Action::WriteKeys(Level::Next) => {
                w.keys.next();
                Ok(())
            }
            Action::Send(Kind::Retry) => {
                let hs = hs.ok_or_else(internal)?;
                hs.transcript.restart_with_message_hash();
                let retry = msgs::hello_retry_request(&hs.session_id);
                hs.transcript.add(&retry);
                self.send(w, record::HANDSHAKE, &retry)
            }
            Action::Send(Kind::ServerHello) => {
                let hs = hs.ok_or_else(internal)?;
                let mut random = [0u8; 32];
                crypto::random(&mut random).map_err(|_| internal())?;
                let hello = msgs::server_hello(&random, &hs.session_id, &hs.public);
                hs.transcript.add(&hello);
                hs.secrets = Some(keys::handshake_secrets(&hs.shared, &hs.transcript.hash()));
                // The shared secret has served its purpose (section 7.1).
                keys::wipe(&mut hs.shared);
                self.send(w, record::HANDSHAKE, &hello)
            }
            Action::WriteKeys(level) => {
                let hs = hs.ok_or_else(internal)?;
                let secret = match level {
                    Level::Handshake => hs.secrets.as_ref().map(|s| s.server).ok_or_else(internal)?,
                    _ => hs.server_application,
                };
                w.keys.switch(secret);
                Ok(())
            }
            Action::Send(Kind::Flight) => {
                let hs = hs.ok_or_else(internal)?;
                let (_, identity) = hs.site.ok_or_else(internal)?;
                let (server, master) = hs.secrets.as_ref().map(|s| (s.server, s.master)).ok_or_else(internal)?;
                let mut flight = msgs::encrypted_extensions(hs.alpn);
                hs.transcript.add(&flight);
                let certificate = msgs::certificate(&identity.chain);
                hs.transcript.add(&certificate);
                let signature = identity.key.sign(&msgs::signed_content(&hs.transcript.hash())).map_err(|_| internal())?;
                let verify = msgs::certificate_verify(&signature);
                hs.transcript.add(&verify);
                let finished = msgs::finished(&keys::verify_data(&server, &hs.transcript.hash()));
                hs.transcript.add(&finished);
                hs.finished_hash = hs.transcript.hash();
                (hs.client_application, hs.server_application) = keys::application_secrets(&master, &hs.finished_hash);
                // All that is still needed is the client's handshake secret,
                // to check its Finished (section 7.1).
                let (mut server, mut master) = (server, master);
                keys::wipe(&mut server);
                keys::wipe(&mut master);
                if let Some(secrets) = hs.secrets.as_mut() {
                    keys::wipe(&mut secrets.server);
                    keys::wipe(&mut secrets.master);
                }
                for message in [certificate, verify, finished] {
                    flight.extend(message);
                }
                self.send(w, record::HANDSHAKE, &flight)
            }
            _ => Err(internal()),
        }
    }

    /// Handles one record: reads it, lets the state machine decide, and
    /// carries out what it says. `Ok(false)`: nothing came in time.
    fn advance<'s>(&self, reader: &mut ReadSide, mut hs: Option<&mut Handshake<'s>>, served: Option<&Served<'s>>) -> Result<bool, ()> {
        let (event, data) = match self.read_record(reader, hs.as_deref_mut(), served) {
            Read::Timeout => return Ok(false),
            Read::Event(event, data) => (event, data),
        };
        let actions = self.step(event);
        // An orderly end is a close_notify the state machine accepted and
        // answers with ours; one it refused (unencrypted after the
        // handshake, or between the pieces of a message) is none.
        let peer_closed = matches!(event, Event::Plain(Content::CloseNotify) | Event::Protected(Content::CloseNotify));
        if peer_closed && actions == [Action::Alert(Alert::CloseNotify)] {
            self.clean_end.store(true, Ordering::Relaxed);
        }
        self.carry_out(actions, reader, hs, data, None, &[])?;
        Ok(true)
    }

    /// Runs the handshake as the server. `None` if it did not complete; the
    /// client has then been sent the alert that says why, if it could be.
    pub fn accept(transport: S, served: &Served<'a>, log: &'a dyn Log) -> Option<(Self, &'a Site)> {
        let tls = TlsStream::new(transport, log, served.peer);
        let mut hs = Handshake {
            transcript: Transcript::new(),
            site: None,
            session_id: Vec::new(),
            alpn: false,
            public: [0; 32],
            shared: [0; 32],
            secrets: None,
            finished_hash: [0; HASH_LEN],
            client_application: [0; HASH_LEN],
            server_application: [0; HASH_LEN],
        };
        let deadline = Instant::now() + served.timeout;
        {
            let mut reader = lock(&tls.reader);
            reader.buffer.set_deadline(Some(deadline));
            loop {
                match tls.state().phase {
                    Phase::Open => break,
                    Phase::Closed => {
                        drop(reader);
                        tls.transport.finish();
                        return None;
                    }
                    _ => {}
                }
                match tls.advance(&mut reader, Some(&mut hs), Some(served)) {
                    Ok(true) => {}
                    // The deadline passed.
                    Ok(false) => {
                        let actions = tls.step(Event::Close);
                        let _ = tls.carry_out(actions, &mut reader, Some(&mut hs), Vec::new(), None, &[]);
                    }
                    Err(()) => {
                        drop(reader);
                        tls.transport.shutdown();
                        return None;
                    }
                }
            }
            reader.buffer.set_deadline(None);
        }
        let site = hs.site.map(|(site, _)| site)?;
        Some((tls, site))
    }

    /// Hands out application data, reading records until some comes. The
    /// buffer's deadline bounds the whole of it.
    fn read_data(&self, reader: &mut ReadSide, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if !reader.plain.is_empty() {
                let n = reader.plain.len().min(buf.len());
                for (to, from) in buf.iter_mut().zip(reader.plain.drain(..n)) {
                    *to = from;
                }
                return Ok(n);
            }
            if self.state().phase == Phase::Closed {
                // Only close_notify is an orderly end; a connection cut off,
                // or ended by an error, is reported as such (section 6).
                return if self.clean_end.load(Ordering::Relaxed) {
                    Ok(0)
                } else {
                    Err(io::ErrorKind::ConnectionAborted.into())
                };
            }
            match self.advance(reader, None, None) {
                Ok(true) => {}
                Ok(false) => return Err(io::ErrorKind::TimedOut.into()),
                Err(()) => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
}

impl<S: Stream> Stream for TlsStream<'_, S> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = lock(&self.reader);
        let budget = *lock(&self.read_timeout);
        reader.buffer.set_deadline(budget.map(|timeout| Instant::now() + timeout));
        let result = self.read_data(&mut reader, buf);
        reader.buffer.set_deadline(None);
        result
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let writer = lock(&self.writer);
        if writer.dead {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let actions = self.step(Event::Write);
        if actions.is_empty() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // Writing never touches the reader's side; an empty one stands in.
        let mut nothing = ReadSide { buffer: Buffer::new(), keys: Direction::none(), message: Vec::new(), plain: Vec::new(), skipped: 0 };
        self.carry_out(actions, &mut nothing, None, Vec::new(), Some(writer), buf)
            .map_err(|()| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn set_read_timeout(&self, timeout: Duration) {
        *lock(&self.read_timeout) = Some(timeout);
        self.transport.set_read_timeout(timeout);
    }

    /// Ends the connection at once, saying close_notify first if the write
    /// lock is free: a thread blocked writing to a slow client must not
    /// keep us from shutting the transport down, which is what stops it.
    fn shutdown(&self) {
        match self.writer.try_lock() {
            Ok(writer) => {
                let actions = self.step(Event::Close);
                let mut nothing = ReadSide { buffer: Buffer::new(), keys: Direction::none(), message: Vec::new(), plain: Vec::new(), skipped: 0 };
                let _ = self.carry_out(actions, &mut nothing, None, Vec::new(), Some(writer), &[]);
            }
            Err(_) => {
                self.step(Event::Lost);
            }
        }
        self.transport.shutdown();
    }

    fn finish(&self) {
        let writer = lock(&self.writer);
        let actions = self.step(Event::Close);
        let mut nothing = ReadSide { buffer: Buffer::new(), keys: Direction::none(), message: Vec::new(), plain: Vec::new(), skipped: 0 };
        let _ = self.carry_out(actions, &mut nothing, None, Vec::new(), Some(writer), &[]);
        self.transport.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::testing::Kept;
    use crate::stream::testing::Script;

    fn open_stream(log: &Kept) -> TlsStream<'_, Script> {
        let tls = TlsStream::new(Script::default(), log, "192.0.2.1".parse().unwrap());
        *lock(&tls.fsm) = State { phase: Phase::Open, ..fsm::START };
        lock(&tls.writer).keys.switch([5; 32]);
        tls
    }

    #[test]
    fn an_empty_write_sends_nothing() {
        let log = Kept::default();
        let tls = open_stream(&log);
        tls.write_all(&[]).unwrap();
        assert!(tls.transport.written().is_empty());
        tls.write_all(b"x").unwrap();
        assert_eq!(tls.transport.written().len(), 5 + 1 + 1 + 16);
    }

    #[test]
    fn the_next_generation_starts_over() {
        let mut direction = Direction::none();
        direction.switch([5; 32]);
        direction.sequence = 9;
        direction.next();
        assert_eq!(direction.secret, keys::next_secret(&[5; 32]));
        assert_eq!(direction.keys.as_ref().unwrap().key, TrafficKeys::new(&keys::next_secret(&[5; 32])).key);
        assert_eq!(direction.sequence, 0);
    }

    #[test]
    fn sequence_numbers_do_not_wrap() {
        let mut direction = Direction::none();
        direction.sequence = u64::MAX - 1;
        assert_eq!(direction.take_sequence(), Some(u64::MAX - 1));
        assert_eq!(direction.take_sequence(), None);
        assert!(std::mem::needs_drop::<Direction>());
    }

    /// Bug (found in review): the server's handshake secret and the master
    /// secret lived on until the end of the handshake, after the
    /// application secrets had been made from them.
    #[test]
    fn bug_master_secret_outlived_its_use() {
        let config = crate::config::tests::parse("[site.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\n").unwrap();
        let certs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs");
        let identity = Identity::load(&certs.join("site.test.chain.pem"), &certs.join("site.test.key")).unwrap();
        let log = Kept::default();
        let tls = open_stream(&log);
        let mut hs = Handshake {
            transcript: Transcript::new(),
            site: Some((&config.sites[0], &identity)),
            session_id: Vec::new(),
            alpn: false,
            public: [0; 32],
            shared: [0; 32],
            secrets: Some(keys::handshake_secrets(&[1; 32], &[2; 32])),
            finished_hash: [0; HASH_LEN],
            client_application: [0; HASH_LEN],
            server_application: [0; HASH_LEN],
        };
        let mut writer = lock(&tls.writer);
        tls.write_action(Action::Send(Kind::Flight), &mut writer, Some(&mut hs), &[]).unwrap();
        let secrets = hs.secrets.as_ref().unwrap();
        assert_eq!((secrets.server, secrets.master), ([0; 32], [0; 32]));
        assert_ne!(secrets.client, [0; 32], "still needed for the client Finished");
        assert_ne!(hs.client_application, [0; 32]);
    }

    /// Bug (found in review): a failure of our own while sending (here the
    /// write sequence number running out) ended the connection silently,
    /// unlogged, as if the transport had failed.
    #[test]
    fn bug_internal_failures_ended_silently() {
        let log = Kept::default();
        let tls = open_stream(&log);
        lock(&tls.writer).keys.sequence = u64::MAX;
        assert!(tls.write_all(b"x").is_err());
        assert!(log.0.lock().unwrap().iter().any(|l| l.ends_with("tls: internal error")));
        assert_eq!(tls.state().phase, Phase::Closed);
        // The next write fails at once.
        assert!(tls.write_all(b"y").is_err());
    }
}
