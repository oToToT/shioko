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
use super::wire::Reader;
use crate::config::{Config, Site};
use crate::crypto::{self, HASH_LEN, SigningKey};
use crate::log::Log;
use crate::net;
use crate::pem;
use crate::stream::{Buffer, Stream};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::io;
use std::net::IpAddr;
use std::path::Path;
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
    pub identities: &'a [Option<Arc<Identity>>],
    pub peer: IpAddr,
    /// How long the handshake may take; `HANDSHAKE_TIMEOUT` but in tests.
    pub timeout: Duration,
}

impl<'a> Served<'a> {
    fn find(&self, name: &[u8]) -> Option<(&'a Site, &'a Identity)> {
        let mut sites = self.config.sites.iter().zip(self.identities);
        let (site, identity) = sites.find(|(site, _)| name.eq_ignore_ascii_case(site.name.as_bytes()))?;
        Some((site, identity.as_deref()?))
    }
}

/// What the handshake keeps between its steps.
#[derive(Default)]
struct Handshake<'a> {
    transcript: Transcript,
    site: Option<(&'a Site, &'a Identity)>,
    session_id: Vec<u8>,
    alpn: bool,
    /// What a second ClientHello must repeat of the first.
    first_hello: Vec<u8>,
    /// The group of the key exchange (or the one a HelloRetryRequest asks
    /// for), our share, and the secret shared with the client.
    group: u16,
    public: Vec<u8>,
    shared: Vec<u8>,
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
#[derive(Default)]
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

#[derive(Default)]
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

#[derive(Default)]
struct WriteSide {
    keys: Direction,
    /// A write failed: the stream may hold half a record, and nothing more
    /// may be sent.
    dead: bool,
    /// Something was sent since the write lock was taken (`--features
    /// record`: the steps TakeLock and Written of spec/Server.tla).
    #[cfg(feature = "record")]
    sent: bool,
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

/// The alerts of RFC 8446 section 6, for the log.
const ALERT_NAMES: [(u8, &str); 27] = [
    (0, "close_notify"), (10, "unexpected_message"), (20, "bad_record_mac"), (22, "record_overflow"),
    (40, "handshake_failure"), (42, "bad_certificate"), (43, "unsupported_certificate"), (44, "certificate_revoked"),
    (45, "certificate_expired"), (46, "certificate_unknown"), (47, "illegal_parameter"), (48, "unknown_ca"),
    (49, "access_denied"), (50, "decode_error"), (51, "decrypt_error"), (70, "protocol_version"),
    (71, "insufficient_security"), (80, "internal_error"), (86, "inappropriate_fallback"), (90, "user_canceled"),
    (109, "missing_extension"), (110, "unsupported_extension"), (112, "unrecognized_name"),
    (113, "bad_certificate_status_response"), (115, "unknown_psk_identity"), (116, "certificate_required"),
    (120, "no_application_protocol"),
];

/// Test builds only: appends the ServerHello random and the shared secret
/// to the file SHIOKO_KEYLOG names, from which tools/tlstrace.py derives
/// every key of the connection.
#[cfg(feature = "keylog")]
fn keylog(random: &[u8; 32], shared: &[u8]) {
    keylog_to(&std::env::var_os("SHIOKO_KEYLOG").unwrap_or_default(), random, shared);
}

/// One line per handshake, written whole: the line is made first and goes
/// out in one write, while no other handshake writes.
#[cfg(any(test, feature = "keylog"))]
fn keylog_to(path: &std::ffi::OsStr, random: &[u8; 32], shared: &[u8]) {
    use std::io::Write;
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let line = format!("{} {}\n", hex(random), hex(shared));
    let _writing = WRITING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

impl<'a, S: Stream> TlsStream<'a, S> {
    fn new(transport: S, log: &'a dyn Log, peer: IpAddr) -> Self {
        TlsStream {
            transport,
            fsm: Mutex::new(fsm::START),
            reader: Mutex::default(),
            writer: Mutex::default(),
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

    fn note(&self, what: &str) {
        self.log.error(&format!("{} tls: {what}", net::canonical(self.peer)));
    }

    fn note_alert(&self, sent: bool, code: u8) {
        if code != 0 {
            let who = if sent { "sent" } else { "received" };
            let name = ALERT_NAMES.iter().find(|(c, _)| *c == code).map(|(_, name)| name.to_string());
            self.note(&format!("{who} {}", name.unwrap_or_else(|| format!("alert {code}"))));
        }
    }

    /// Reads one record and says what it is, with the application data it
    /// carried; `None` if nothing came in time.
    fn read_record<'s>(&self, reader: &mut ReadSide, hs: Option<&mut Handshake<'s>>, served: Option<&Served<'s>>) -> Option<(Event, Vec<u8>)> {
        let only = |event| Some((event, Vec::new()));
        let record = match record::read(&mut reader.buffer, &self.transport) {
            Ok(record) => record,
            Err(ReadError::Timeout) => return None,
            Err(ReadError::End | ReadError::Cut) => return only(Event::Close),
            Err(ReadError::Refused(alert)) => return only(Event::Invalid(alert)),
        };
        let state = self.state();
        let size = record.payload.len();
        // Early data we did not accept is skipped, up to a limit.
        let skip = |reader: &mut ReadSide, event| {
            reader.skipped = reader.skipped.saturating_add(size);
            only(if reader.skipped > EARLY_DATA_LIMIT { Event::Invalid(Alert::UnexpectedMessage) } else { event })
        };
        let (protected, content_type, content) = match (&reader.keys.keys, record.content_type) {
            (None, record::APPLICATION_DATA) if state.early && state.phase == Phase::Retry => {
                return skip(reader, Event::Plain(Content::Data));
            }
            // With read keys only the dummy ChangeCipherSpec may come
            // unencrypted. An unencrypted alert is refused too, but read so
            // that it is logged: it tells why the client gave up.
            (None, _) | (Some(_), record::CHANGE_CIPHER_SPEC | record::ALERT) => (false, record.content_type, record.payload),
            (Some(keys), record::APPLICATION_DATA) => match record::open(keys, reader.keys.sequence, &record) {
                Opened::Undecryptable if state.early && state.phase == Phase::WaitFinished => {
                    return skip(reader, Event::Undecryptable);
                }
                Opened::Undecryptable => return only(Event::Undecryptable),
                Opened::Refused(alert) => return only(Event::Invalid(alert)),
                Opened::Content(content_type, content) => match reader.keys.take_sequence() {
                    Some(_) => (true, content_type, content),
                    None => return only(Event::Invalid(Alert::InternalError)),
                },
            },
            (Some(_), _) => return only(Event::Plain(Content::Other)),
        };
        let wrap = |c| if protected { Event::Protected(c) } else { Event::Plain(c) };
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
                    self.note("received an empty alert");
                    Event::Invalid(Alert::UnexpectedMessage)
                }
                _ => {
                    self.note("received a malformed alert");
                    Event::Invalid(Alert::DecodeError)
                }
            },
            record::APPLICATION_DATA => {
                return Some((wrap(if content.is_empty() { Content::EmptyData } else { Content::Data }), content));
            }
            record::HANDSHAKE => self.handshake(reader, hs, served, state.phase, &content).map_or_else(Event::Invalid, wrap),
            _ => Event::Invalid(Alert::UnexpectedMessage),
        };
        only(event)
    }

    /// Handshake bytes: put together into messages, which must end where
    /// their record ends.
    fn handshake<'s>(
        &self,
        reader: &mut ReadSide,
        hs: Option<&mut Handshake<'s>>,
        served: Option<&Served<'s>>,
        phase: Phase,
        bytes: &[u8],
    ) -> Result<Content, Alert> {
        if bytes.is_empty() {
            return Err(Alert::UnexpectedMessage);
        }
        reader.message.extend_from_slice(bytes);
        let Some(length) = reader.message.get(1..4).and_then(|header| Reader::new(header).u24()) else {
            return Ok(Content::Fragment);
        };
        if length > msgs::MESSAGE_LIMIT {
            return Err(Alert::DecodeError);
        }
        let whole = length.saturating_add(4);
        if reader.message.len() < whole {
            return Ok(Content::Fragment);
        }
        if reader.message.len() > whole {
            // Something after the end of a message in the same record.
            return Err(Alert::UnexpectedMessage);
        }
        let message = std::mem::take(&mut reader.message);
        match (message.first(), phase, hs, served) {
            (Some(&msgs::CLIENT_HELLO), Phase::Start | Phase::Retry, Some(hs), Some(served)) => {
                self.client_hello(&message, phase, hs, served)
            }
            (Some(&msgs::FINISHED), Phase::WaitFinished, Some(hs), _) => {
                let expected = hs.secrets.as_ref().map(|s| keys::verify_data(&s.client, &hs.finished_hash));
                match (msgs::client_finished(&message), expected) {
                    (Some(got), Some(expected)) if crypto::ct_eq(got, &expected) => Ok(Content::Finished),
                    (Some(_), _) => Ok(Content::FinishedBad),
                    (None, _) => Err(Alert::DecodeError),
                }
            }
            (Some(&msgs::KEY_UPDATE), Phase::Open, _, _) => {
                msgs::client_key_update(&message).map(|asked| if asked { Content::KeyUpdateRequest } else { Content::KeyUpdate })
            }
            _ => Ok(Content::Other),
        }
    }

    /// Checks a ClientHello and gets ready to answer it.
    fn client_hello<'s>(&self, message: &[u8], phase: Phase, hs: &mut Handshake<'s>, served: &Served<'s>) -> Result<Content, Alert> {
        let hello = msgs::client_hello(message)?;
        let found = served.find(hello.server_name).ok_or(Alert::UnrecognizedName)?;
        if !found.0.allows(served.peer) {
            return Err(Alert::AccessDenied);
        }
        // The second ClientHello repeats the first but for what may change,
        // and brings exactly the one key share we asked for (section 4.1.2).
        let asked = hello.share.is_some_and(|(group, _)| group == hs.group);
        if phase == Phase::Retry && (hello.kept != hs.first_hello || hello.shares != 1 || !asked) {
            return Err(Alert::IllegalParameter);
        }
        hs.first_hello = hello.kept;
        hs.site = Some(found);
        hs.session_id = hello.session_id.to_vec();
        hs.alpn = hello.alpn;
        hs.transcript.add(message);
        let Some((group, share)) = hello.share else {
            hs.group = hello.retry_group;
            return Ok(if hello.early { Content::HelloRetryEarly } else { Content::HelloRetry });
        };
        hs.group = group;
        // Either share ends with the client's X25519 share; an
        // X25519MLKEM768 one starts with its ML-KEM key (RFC 10024 4.1).
        let (kem, theirs) = share.split_at_checked(share.len().saturating_sub(32)).ok_or(Alert::IllegalParameter)?;
        let theirs: &[u8; 32] = theirs.try_into().map_err(|_| Alert::IllegalParameter)?;
        let mut secret = [0u8; 32];
        crypto::random(&mut secret).map_err(|_| Alert::InternalError)?;
        let ours = crypto::x25519_public(&secret);
        // An all-zero result means the client's share is a small-order
        // point (section 7.4.2, RFC 10024 4.3).
        let shared = crypto::x25519(&secret, theirs);
        keys::wipe(&mut secret);
        let mut shared = shared.map_err(|_| Alert::IllegalParameter)?;
        if group == msgs::X25519MLKEM768 {
            // A key that fails the check of FIPS 203 section 7.2 is an
            // illegal parameter (RFC 10024 4.2). The ML-KEM secret goes
            // first, then the X25519 one (4.3).
            let kem = kem.try_into().map_err(|_| Alert::IllegalParameter)?;
            let mut randomness = [0u8; 32];
            crypto::random(&mut randomness).map_err(|_| Alert::InternalError)?;
            let encapsulated = crypto::mlkem768_encapsulate(kem, randomness);
            keys::wipe(&mut randomness);
            let (ciphertext, mut kem_shared) = encapsulated.map_err(|_| Alert::IllegalParameter)?;
            hs.public = [&ciphertext[..], &ours].concat();
            hs.shared = [kem_shared, shared].concat();
            keys::wipe(&mut kem_shared);
        } else {
            hs.public = ours.to_vec();
            hs.shared = shared.to_vec();
        }
        keys::wipe(&mut shared);
        Ok(if hello.early { Content::HelloEarly } else { Content::Hello })
    }

    /// Carries out actions in order. Those that need the write lock take it
    /// when the first of them comes. `data` is what `Deliver` hands over,
    /// `out` what `Send(Data)` sends.
    fn carry_out<'g>(
        &'g self,
        actions: Vec<Action>,
        reader: &mut ReadSide,
        hs: Option<&mut Handshake<'_>>,
        data: Vec<u8>,
        mut writer: Option<MutexGuard<'g, WriteSide>>,
        out: &[u8],
    ) -> Result<(), ()> {
        let result = self.carry(actions, reader, hs, data, &mut writer, out);
        // The write lock is about to go: say whether what was sent got out.
        #[cfg(feature = "record")]
        if let Some(w) = writer.as_mut().filter(|w| w.sent) {
            w.sent = false;
            crate::record::lock_step(if w.dead { "unlock_fail" } else { "unlock_ok" });
        }
        result
    }

    fn carry<'g>(
        &'g self,
        actions: Vec<Action>,
        reader: &mut ReadSide,
        mut hs: Option<&mut Handshake<'_>>,
        mut data: Vec<u8>,
        writer: &mut Option<MutexGuard<'g, WriteSide>>,
        out: &[u8],
    ) -> Result<(), ()> {
        for action in actions {
            if action.needs_write_lock() && writer.is_none() {
                *writer = Some(lock(&self.writer));
            }
            match action {
                Action::ReadKeys(level) => match (level, hs.as_deref()) {
                    (Level::Next, _) => reader.keys.next(),
                    (Level::Handshake, Some(Handshake { secrets: Some(secrets), .. })) => reader.keys.switch(secrets.client),
                    (Level::Data, Some(hs)) => reader.keys.switch(hs.client_application),
                    _ => return Err(()),
                },
                Action::Deliver => reader.plain.append(&mut data),
                Action::Skip => {}
                _ => {
                    let Some(w) = writer.as_mut() else { return Err(()) };
                    if w.dead {
                        // Nothing more goes out; what was still to send is
                        // dropped.
                        return Ok(());
                    }
                    let Err(error) = self.write_action(action, w, hs.as_deref_mut(), out) else { continue };
                    if error.kind() == io::ErrorKind::InvalidData {
                        // Something of ours failed, not the transport: say
                        // so to the client, if it can still be said.
                        self.note("internal error");
                        let alerts = self.step(Event::Invalid(Alert::InternalError));
                        let _ = alerts.into_iter().try_for_each(|alert| self.write_action(alert, w, None, &[]));
                    } else {
                        self.step(Event::Lost);
                    }
                    w.dead = true;
                    return Err(());
                }
            }
        }
        Ok(())
    }

    /// Sends records, splitting content longer than a record may carry.
    fn send(&self, w: &mut WriteSide, content_type: u8, content: &[u8]) -> io::Result<()> {
        if content.is_empty() {
            return Ok(());
        }
        #[cfg(feature = "record")]
        if !w.sent {
            w.sent = true;
            crate::record::lock_step("lock");
        }
        let mut bytes = Vec::with_capacity(content.len() + 32);
        for piece in content.chunks(record::MAX_PLAINTEXT) {
            if w.keys.keys.is_none() {
                bytes.extend(record::plain(content_type, piece));
                continue;
            }
            let sequence = w.keys.take_sequence().ok_or(io::ErrorKind::InvalidData)?;
            let keys = w.keys.keys.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            bytes.extend(record::seal(keys, sequence, content_type, piece).map_err(|_| io::ErrorKind::InvalidData)?);
        }
        self.transport.write_all(&bytes)
    }

    fn write_action(&self, action: Action, w: &mut WriteSide, hs: Option<&mut Handshake<'_>>, out: &[u8]) -> io::Result<()> {
        let internal = || io::Error::from(io::ErrorKind::InvalidData);
        match (action, hs) {
            (Action::Alert(alert), _) => {
                self.note_alert(true, alert.code());
                self.send(w, record::ALERT, &msgs::alert(alert))
            }
            (Action::Send(Kind::Ccs), _) => self.transport.write_all(&record::plain(record::CHANGE_CIPHER_SPEC, &[1])),
            (Action::Send(Kind::Data), _) => self.send(w, record::APPLICATION_DATA, out),
            (Action::Send(Kind::KeyUpdate), _) => self.send(w, record::HANDSHAKE, &msgs::key_update(false)),
            (Action::WriteKeys(level), hs) => {
                match (level, hs) {
                    (Level::Next, _) => w.keys.next(),
                    (Level::Handshake, Some(Handshake { secrets: Some(secrets), .. })) => w.keys.switch(secrets.server),
                    (Level::Data, Some(hs)) => w.keys.switch(hs.server_application),
                    _ => return Err(internal()),
                }
                Ok(())
            }
            (Action::Send(Kind::Retry), Some(hs)) => {
                hs.transcript.restart_with_message_hash();
                let retry = msgs::hello_retry_request(&hs.session_id, hs.group);
                hs.transcript.add(&retry);
                self.send(w, record::HANDSHAKE, &retry)
            }
            (Action::Send(Kind::ServerHello), Some(hs)) => {
                let mut random = [0u8; 32];
                crypto::random(&mut random).map_err(|_| internal())?;
                let hello = msgs::server_hello(&random, &hs.session_id, hs.group, &hs.public);
                hs.transcript.add(&hello);
                #[cfg(feature = "keylog")]
                keylog(&random, &hs.shared);
                hs.secrets = Some(keys::handshake_secrets(&hs.shared, &hs.transcript.hash()));
                // The shared secret has served its purpose (section 7.1).
                keys::wipe(&mut hs.shared);
                self.send(w, record::HANDSHAKE, &hello)
            }
            (Action::Send(Kind::Flight), Some(hs)) => {
                let (_, identity) = hs.site.ok_or_else(internal)?;
                let secrets = hs.secrets.as_mut().ok_or_else(internal)?;
                let extensions = msgs::encrypted_extensions(hs.alpn);
                hs.transcript.add(&extensions);
                let certificate = msgs::certificate(&identity.chain);
                hs.transcript.add(&certificate);
                let signature = identity.key.sign(&msgs::signed_content(&hs.transcript.hash())).map_err(|_| internal())?;
                let verify = msgs::certificate_verify(&signature);
                hs.transcript.add(&verify);
                let finished = msgs::finished(&keys::verify_data(&secrets.server, &hs.transcript.hash()));
                hs.transcript.add(&finished);
                hs.finished_hash = hs.transcript.hash();
                (hs.client_application, hs.server_application) = keys::application_secrets(&secrets.master, &hs.finished_hash);
                // All that is still needed is the client's handshake secret,
                // to check its Finished (section 7.1).
                keys::wipe(&mut secrets.server);
                keys::wipe(&mut secrets.master);
                self.send(w, record::HANDSHAKE, &[extensions, certificate, verify, finished].concat())
            }
            _ => Err(internal()),
        }
    }

    /// Handles one record: reads it, lets the state machine decide, and
    /// carries out what it says. `Ok(false)`: nothing came in time.
    fn advance<'s>(&self, reader: &mut ReadSide, mut hs: Option<&mut Handshake<'s>>, served: Option<&Served<'s>>) -> Result<bool, ()> {
        let Some((event, data)) = self.read_record(reader, hs.as_deref_mut(), served) else { return Ok(false) };
        let actions = self.step(event);
        // An orderly end is a close_notify the state machine accepted and
        // answers with ours; one it refused (unencrypted after the
        // handshake, or between the pieces of a message) is none.
        let peer_closed = matches!(event, Event::Plain(Content::CloseNotify) | Event::Protected(Content::CloseNotify));
        if peer_closed && actions == [Action::Alert(Alert::CloseNotify)] {
            self.clean_end.store(true, Ordering::Relaxed);
        }
        self.carry_out(actions, reader, hs, data, None, &[]).map(|()| true)
    }

    /// We end the connection: close_notify, unless it is over already.
    fn close(&self, writer: MutexGuard<'_, WriteSide>) {
        let actions = self.step(Event::Close);
        let _ = self.carry_out(actions, &mut ReadSide::default(), None, Vec::new(), Some(writer), &[]);
    }

    /// Runs the handshake as the server. `None` if it did not complete; the
    /// client has then been sent the alert that says why, if it could be.
    pub fn accept(transport: S, served: &Served<'a>, log: &'a dyn Log) -> Option<(Self, &'a Site)> {
        let tls = TlsStream::new(transport, log, served.peer);
        let mut hs = Handshake::default();
        let mut reader = lock(&tls.reader);
        reader.buffer.set_deadline(Some(Instant::now() + served.timeout));
        let mut failed = false;
        while !failed && !matches!(tls.state().phase, Phase::Open | Phase::Closed) {
            match tls.advance(&mut reader, Some(&mut hs), Some(served)) {
                Ok(true) => {}
                // The deadline passed.
                Ok(false) => tls.close(lock(&tls.writer)),
                Err(()) => failed = true,
            }
        }
        reader.buffer.set_deadline(None);
        drop(reader);
        if failed {
            tls.transport.shutdown();
        } else if tls.state().phase == Phase::Closed {
            tls.transport.finish();
        } else {
            return hs.site.map(|(site, _)| (tls, site));
        }
        None
    }
}

impl<S: Stream> Stream for TlsStream<'_, S> {
    /// Hands out application data, reading records until some comes.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = lock(&self.reader);
        let budget = *lock(&self.read_timeout);
        reader.buffer.set_deadline(budget.map(|timeout| Instant::now() + timeout));
        let result = loop {
            if !reader.plain.is_empty() {
                let n = reader.plain.len().min(buf.len());
                for (to, from) in buf.iter_mut().zip(reader.plain.drain(..n)) {
                    *to = from;
                }
                break Ok(n);
            }
            if self.state().phase == Phase::Closed {
                // Only close_notify is an orderly end; a connection cut off,
                // or ended by an error, is reported as such (section 6).
                break if self.clean_end.load(Ordering::Relaxed) { Ok(0) } else { Err(io::ErrorKind::ConnectionAborted.into()) };
            }
            match self.advance(&mut reader, None, None) {
                Ok(true) => {}
                Ok(false) => break Err(io::ErrorKind::TimedOut.into()),
                Err(()) => break Err(io::ErrorKind::BrokenPipe.into()),
            }
        };
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
        self.carry_out(actions, &mut ReadSide::default(), None, Vec::new(), Some(writer), buf)
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
            Ok(writer) => self.close(writer),
            Err(_) => {
                self.step(Event::Lost);
            }
        }
        self.transport.shutdown();
    }

    fn finish(&self) {
        self.close(lock(&self.writer));
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
        let mut direction = Direction::default();
        direction.switch([5; 32]);
        direction.sequence = 9;
        direction.next();
        assert_eq!(direction.secret, keys::next_secret(&[5; 32]));
        assert_eq!(direction.keys.as_ref().unwrap().key, TrafficKeys::new(&keys::next_secret(&[5; 32])).key);
        assert_eq!(direction.sequence, 0);
    }

    #[test]
    fn sequence_numbers_do_not_wrap() {
        let mut direction = Direction::default();
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
        let mut hs = Handshake::default();
        hs.site = Some((&config.sites[0], &identity));
        hs.secrets = Some(keys::handshake_secrets(&[1; 32], &[2; 32]));
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

    /// Bug (found by tlsfuzzer in CI): the key log of the test build was
    /// written with `writeln!`, which writes a line in pieces, so lines of
    /// handshakes running at the same time got mixed, and tools/tlstrace.py
    /// found a line that was not "random shared". Every line is now written
    /// whole.
    #[test]
    fn bug_concurrent_handshakes_mixed_their_key_log_lines() {
        let path = std::env::temp_dir().join(format!("shioko-keylog-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (threads, lines) = (16u8, 500usize);
        std::thread::scope(|scope| {
            for t in 0..threads {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..lines {
                        keylog_to(path.as_os_str(), &[t; 32], &[t; 64]);
                    }
                });
            }
        });
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        for t in 0..threads {
            let line = format!("{} {}", format!("{t:02x}").repeat(32), format!("{t:02x}").repeat(64));
            assert_eq!(text.lines().filter(|l| *l == line).count(), lines, "lines of thread {t} were mixed");
        }
        assert_eq!(text.lines().count(), usize::from(threads) * lines, "the log has other lines");
    }
}
