//! Listening, the caps on connections, and one thread per connection.
//!
//! An accept loop takes a slot before it accepts, so that when the server
//! is full new connections wait in the kernel's queue. Once the connection
//! has come, the slot is from one of two pools: one for peers inside some
//! site's allowlist, one for everyone else, where one address may also hold
//! only so many. A connection whose pool or address has no room is closed
//! at once. Otherwise the slot goes to the thread that serves the
//! connection and comes back when that thread ends, however it ends.
//! `spec/Server.tla` is the design this follows.

use crate::config::Config;
use crate::http::proxy::{self, Context, Tcp};
use crate::log::Log;
use crate::tls::conn::{self as tls, Identity, Served, TlsStream};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The most connections served at once from each pool.
pub const CONNECTIONS: usize = 512;
/// The most connections at once from one address outside every allowlist:
/// an IPv4 address, or an IPv6 /64.
pub const PER_ADDRESS: usize = 64;
/// The file descriptors the process needs besides its connections': the
/// standard streams, the two listeners, /dev/urandom, and room for a
/// certificate or token file being read.
pub const RESERVED_FILES: usize = 16;

/// The file descriptors a connection holds at most: its client's socket, the
/// duplicate of it through which a stop cuts the connection, and its
/// upstream's socket (or, in its place, a token file being read).
pub const FILES_PER_CONNECTION: usize = 3;

/// The cap of each pool that fits the open-file limit, given the text of
/// /proc/self/limits: the two pools together may hold twice the cap of
/// connections, each with `FILES_PER_CONNECTION` descriptors. With no limit
/// to read, or none set, `CONNECTIONS`.
pub fn cap_for(limits: &str) -> usize {
    let soft = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse::<usize>().ok());
    soft.map_or(CONNECTIONS, |files| (files.saturating_sub(RESERVED_FILES) / (2 * FILES_PER_CONNECTION)).clamp(1, CONNECTIONS))
}

/// The open-file limit that `CONNECTIONS` in each pool needs.
pub const FILES_NEEDED: usize = 2 * FILES_PER_CONNECTION * CONNECTIONS + RESERVED_FILES;
/// How long a write to a client may block.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long an accept loop rests after `accept` failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How often the certificate and key files are read again.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(60);
/// How often at most the log says how many connections were turned away.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// How long a stopping server waits for the requests it is serving.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The certificate and key of each site, in the order of the sites; `None`
/// for a site served over plain HTTP.
pub type Identities = Vec<Option<Arc<Identity>>>;

/// What a site's certificate and key files held, if both could be read.
type Files = Option<(Vec<u8>, Vec<u8>)>;

/// Which pool a connection's slot is from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// The peer is inside some site's allowlist.
    Allowed,
    /// Everyone else.
    Public,
}

impl Pool {
    /// Its name in a recorded run.
    #[cfg_attr(not(feature = "record"), allow(dead_code))]
    fn name(self) -> &'static str {
        match self {
            Pool::Allowed => "allowed",
            Pool::Public => "public",
        }
    }
}

/// Where the public pool counts a connection from: its IPv4 address, or
/// the /64 of its IPv6 address. An IPv4 address written as IPv6 (as the
/// dual-stack listener gives them) counts as itself.
fn address_of(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

/// The server's slots.
#[derive(Default)]
struct Slots {
    /// Taken by accept loops waiting for a connection, and by connections.
    used: usize,
    /// The connections of each pool.
    allowed: usize,
    public: usize,
    /// The connections of the public pool, by address.
    addresses: HashMap<IpAddr, usize>,
    /// Connections turned away since the log last said so, and when it did.
    turned_away: usize,
    reported: Option<Instant>,
}

/// What every connection shares.
pub struct Server {
    pub config: Config,
    /// The identities handshakes use now. A reload puts new ones in place;
    /// a connection keeps those it started with.
    identities: RwLock<Arc<Identities>>,
    /// What each site's certificate and key files held when last read.
    files: Mutex<Vec<Files>>,
    pub acme: PathBuf,
    pub log: Box<dyn Log + Send>,
    /// Connection slots, the signal that one came back, the cap of each
    /// pool and of each address in the public pool. Both accept loops
    /// waiting for room and a stop waiting for the last connection wait
    /// for the signal, so it wakes all of them: woken alone, a waiter of
    /// the wrong kind would leave the other waiting.
    slots: Mutex<Slots>,
    freed: Condvar,
    cap: usize,
    per_address: usize,
    /// Some site with a certificate has no allowlist, so over TLS a peer
    /// outside every allowlist may be served.
    public_tls: bool,
    /// The server is stopping (`drain`): no connection is let in any more.
    /// Set while `interruptible` is locked.
    stopping: AtomicBool,
    /// The client sockets of the connections a stop may cut now: those
    /// waiting for a request head, and tunnels.
    interruptible: Mutex<HashMap<u64, Arc<TcpStream>>>,
    ids: AtomicU64,
}

/// What a site's certificate and key files hold, if both can be read.
fn read_identity_files(site: &crate::config::Site) -> Files {
    let (cert, key) = (site.cert.as_ref()?, site.key.as_ref()?);
    Some((std::fs::read(cert).ok()?, std::fs::read(key).ok()?))
}

/// The work of the thread that stops the server, given what waiting for
/// SIGTERM or SIGINT gave (`signals::wait`): on a signal, let nobody in
/// any more, cut the connections that wait for a request and the tunnels,
/// let the requests being served finish (for up to DRAIN_TIMEOUT), and
/// exit. If waiting failed, say so and stay: the signals are let through
/// to this thread alone, and it must live on for them to end the process.
pub fn stop_on(server: &Server, signal: Result<u32, String>) -> ! {
    let signal = match signal {
        Ok(signal) => signal,
        Err(why) => {
            server.log.error(&format!("no graceful stop: {why}"));
            loop {
                std::thread::park();
            }
        }
    };
    server.log.error(&format!(
        "stopping on signal {signal}: letting nobody in, waiting up to {} s for the requests being served",
        DRAIN_TIMEOUT.as_secs()
    ));
    match server.drain(DRAIN_TIMEOUT) {
        0 => server.log.error("stopped"),
        left => server.log.error(&format!("stopped, cutting {left} connections")),
    }
    std::process::exit(0);
}

/// Reads the certificates and keys again every `RELOAD_INTERVAL`, for ever.
pub fn watch(server: &Server) {
    loop {
        std::thread::sleep(RELOAD_INTERVAL);
        server.reload();
    }
}

/// A slot an accept loop took before it knew which pool the connection
/// would be in. Dropping it gives it back.
pub struct Reserved(Option<Arc<Server>>);

/// A connection's slot. Dropping it gives it back to its pool.
pub struct Slot {
    server: Arc<Server>,
    pool: Pool,
    address: IpAddr,
}

impl Server {
    pub fn new(
        config: Config, identities: Vec<Option<Identity>>, acme: PathBuf, log: Box<dyn Log + Send>, cap: usize,
        per_address: usize,
    ) -> Arc<Server> {
        let files = config.sites.iter().map(read_identity_files).collect();
        let identities = RwLock::new(Arc::new(identities.into_iter().map(|i| i.map(Arc::new)).collect()));
        let public_tls = config.sites.iter().any(|site| site.cert.is_some() && site.allow.is_none());
        Arc::new(Server {
            config,
            identities,
            files: Mutex::new(files),
            acme,
            log,
            slots: Mutex::new(Slots::default()),
            freed: Condvar::new(),
            cap,
            per_address,
            public_tls,
            stopping: AtomicBool::new(false),
            interruptible: Mutex::new(HashMap::new()),
            ids: AtomicU64::new(0),
        })
    }

    /// Connection `id`, whose client socket is `socket`, may be cut by a
    /// stop from now (`now`), or no longer. Answers `false` if it may not
    /// go on: the server is stopping.
    fn interruptible(&self, id: u64, socket: Option<&Arc<TcpStream>>, now: bool) -> bool {
        let mut cut = self.interruptible.lock().unwrap_or_else(PoisonError::into_inner);
        if !now {
            cut.remove(&id);
            return true;
        }
        if self.stopping.load(Ordering::SeqCst) {
            return false;
        }
        if let Some(socket) = socket {
            cut.insert(id, Arc::clone(socket));
        }
        true
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    /// Stops serving: lets no connection in any more, cuts those waiting
    /// for a request head and the tunnels, and waits up to `timeout` for
    /// the requests being served to end. Returns how many connections are
    /// left.
    pub fn drain(&self, timeout: Duration) -> usize {
        {
            let mut cut = self.interruptible.lock().unwrap_or_else(PoisonError::into_inner);
            self.stopping.store(true, Ordering::SeqCst);
            for (_, socket) in cut.drain() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
        let deadline = Instant::now() + timeout;
        let mut slots = self.slots();
        loop {
            let left = slots.allowed.saturating_add(slots.public);
            let wait = deadline.saturating_duration_since(Instant::now());
            if left == 0 || wait.is_zero() {
                return left;
            }
            slots = self.freed.wait_timeout(slots, wait).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// The pool a connection from `peer` is in, or `None` if it is to be
    /// turned away whatever the room: over TLS, a peer outside every
    /// allowlist when every site with a certificate has one.
    pub fn pool_of(&self, peer: IpAddr, secure: bool) -> Option<Pool> {
        let peer = peer.to_canonical();
        if self.config.sites.iter().any(|site| site.allow.is_some() && site.allows(peer)) {
            Some(Pool::Allowed)
        } else if secure && !self.public_tls {
            None
        } else {
            Some(Pool::Public)
        }
    }

    /// The slots, which are left consistent at every step, so a lock
    /// poisoned by a panic elsewhere can still be used.
    fn slots(&self) -> MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The identities in place now.
    pub fn identities(&self) -> Arc<Identities> {
        Arc::clone(&self.identities.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reads each site's certificate and key files again. A site whose
    /// files changed gets the identity they now hold, once it has passed
    /// the checks of startup; if it does not, the site keeps the identity
    /// it had, and the log says why. Connections already open are not
    /// affected.
    pub fn reload(&self) {
        let mut files = self.files.lock().unwrap_or_else(PoisonError::into_inner);
        let mut identities: Identities = self.identities().as_ref().clone();
        let mut changed = false;
        for ((site, seen), identity) in self.config.sites.iter().zip(files.iter_mut()).zip(identities.iter_mut()) {
            let (Some(cert), Some(key)) = (&site.cert, &site.key) else { continue };
            let now = read_identity_files(site);
            if now == *seen {
                continue;
            }
            // A file being replaced may read as neither; once it can be
            // read, it is looked at again.
            *seen = now;
            match Identity::load(cert, key) {
                Ok(loaded) => {
                    *identity = Some(Arc::new(loaded));
                    changed = true;
                    self.log.error(&format!("site '{}': certificate and key reloaded", site.name));
                }
                Err(message) => self.log.error(&format!("site '{}': keeping the certificate it had: {message}", site.name)),
            }
        }
        if changed {
            *self.identities.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(identities);
        }
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.slots().used
    }
}

impl Reserved {
    /// Takes a slot, waiting for one while both pools are full.
    pub fn take(server: &Arc<Server>) -> Reserved {
        let mut slots = server.slots();
        while slots.used >= server.cap.saturating_mul(2) {
            slots = server.freed.wait(slots).unwrap_or_else(PoisonError::into_inner);
        }
        slots.used = slots.used.saturating_add(1);
        record!("reserve");
        Reserved(Some(Arc::clone(server)))
    }

    /// The slot of a connection from `peer` in `pool`, if the pool, and in
    /// the public pool the peer's address, has room. If not, the slot is
    /// given back and the connection is to be closed. `name` is the
    /// connection's in a recorded run.
    #[cfg_attr(not(feature = "record"), allow(unused_variables))]
    pub fn admit(mut self, pool: Option<Pool>, peer: IpAddr, name: &str) -> Option<Slot> {
        let server = self.0.take()?;
        let address = address_of(peer);
        let mut slots = server.slots();
        // A stopping server lets nobody in.
        let room = match pool {
            _ if server.stopping.load(Ordering::SeqCst) => false,
            Some(Pool::Allowed) => slots.allowed < server.cap,
            Some(Pool::Public) => {
                slots.public < server.cap && slots.addresses.get(&address).copied().unwrap_or(0) < server.per_address
            }
            None => false,
        };
        let Some(pool) = pool.filter(|_| room) else {
            slots.used = slots.used.saturating_sub(1);
            record!("turn_away {} {address}", pool.unwrap_or(Pool::Public).name());
            slots.turned_away = slots.turned_away.saturating_add(1);
            if slots.reported.is_none_or(|at| at.elapsed() >= REPORT_INTERVAL) {
                server.log.error(&format!(
                    "turned away {} connections: no room for them in their pool or for their address",
                    slots.turned_away
                ));
                slots.turned_away = 0;
                slots.reported = Some(Instant::now());
            }
            server.freed.notify_all();
            return None;
        };
        match pool {
            Pool::Allowed => slots.allowed = slots.allowed.saturating_add(1),
            Pool::Public => {
                slots.public = slots.public.saturating_add(1);
                let count = slots.addresses.entry(address).or_insert(0);
                *count = count.saturating_add(1);
            }
        }
        record!("accept {name} {} {address}", pool.name());
        drop(slots);
        Some(Slot { server, pool, address })
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        if let Some(server) = self.0.take() {
            let mut slots = server.slots();
            slots.used = slots.used.saturating_sub(1);
            record!("release");
            server.freed.notify_all();
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut slots = self.server.slots();
        slots.used = slots.used.saturating_sub(1);
        match self.pool {
            Pool::Allowed => slots.allowed = slots.allowed.saturating_sub(1),
            Pool::Public => {
                slots.public = slots.public.saturating_sub(1);
                if let Some(count) = slots.addresses.get_mut(&self.address) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        slots.addresses.remove(&self.address);
                    }
                }
            }
        }
        record!("release");
        self.server.freed.notify_all();
    }
}

/// Serves one connection: plain HTTP, or HTTP over TLS.
fn connection(server: &Server, client: TcpStream, secure: bool) {
    let Ok(peer) = client.peer_addr() else { return };
    let _ = client.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = client.set_nodelay(true);
    let id = server.ids.fetch_add(1, Ordering::Relaxed);
    let socket = client.try_clone().ok().map(Arc::new);
    let interruptible = |now| server.interruptible(id, socket.as_ref(), now);
    // However the connection ends, a stop has nothing of it left to cut.
    struct Gone<'a>(&'a Server, u64);
    impl Drop for Gone<'_> {
        fn drop(&mut self) {
            self.0.interruptible(self.1, None, false);
        }
    }
    let _gone = Gone(server, id);
    let context = |tls_site| Context {
        config: &server.config,
        connect: &Tcp,
        log: server.log.as_ref(),
        peer: peer.ip(),
        tls_site,
        acme: &server.acme,
        clock: || SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs()),
        timeouts: proxy::Timeouts::STANDARD,
        interruptible: &interruptible,
    };
    if !secure {
        proxy::serve(&client, &context(None));
        return;
    }
    let identities = server.identities();
    let served = Served {
        config: &server.config,
        identities: &identities,
        peer: peer.ip(),
        timeout: tls::HANDSHAKE_TIMEOUT,
    };
    if let Some((stream, site)) = TlsStream::accept(client, &served, server.log.as_ref()) {
        proxy::serve(&stream, &context(Some(site)));
    }
}

/// Accepts connections for ever, each served on a thread of its own;
/// `secure` connections speak TLS.
pub fn listen(server: &Arc<Server>, listener: &TcpListener, secure: bool) {
    #[cfg(feature = "record")]
    let me = format!("l{}", if secure { 443 } else { 80 });
    #[cfg(feature = "record")]
    crate::record::be(me.clone(), false);
    if secure {
        record!("public_tls {}", server.public_tls);
    }
    loop {
        let reserved = Reserved::take(server);
        match listener.accept() {
            Ok((client, peer)) => {
                #[cfg(feature = "record")]
                let name = crate::record::connection();
                #[cfg(not(feature = "record"))]
                let name = String::new();
                let Some(slot) = reserved.admit(server.pool_of(peer.ip(), secure), peer.ip(), &name) else {
                    // Turned away: closed at once.
                    drop(client);
                    continue;
                };
                let shared = Arc::clone(server);
                // A slot dropped from here on is the connection's.
                #[cfg(feature = "record")]
                crate::record::be(format!("{name} up"), false);
                // The slot moves into the thread. If the thread cannot be
                // started, the closure is dropped and the slot with it.
                let started = std::thread::Builder::new().spawn(move || {
                    #[cfg(feature = "record")]
                    crate::record::be(format!("{name} up"), false);
                    let _slot = slot;
                    connection(&shared, client, secure);
                });
                #[cfg(feature = "record")]
                crate::record::be(me.clone(), false);
                if let Err(error) = started {
                    server.log.error(&format!("cannot start a thread: {error}"));
                }
            }
            Err(error) => {
                drop(reserved);
                server.log.error(&format!("accept failed: {error}"));
                std::thread::sleep(ACCEPT_PAUSE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::parse;
    use crate::log::testing::Kept;
    use std::io::{Read, Write};
    use std::net::Shutdown;

    /// Bug (found in review): the cap was 512 connections whatever the
    /// open-file limit. A full server holds a client and an upstream socket
    /// for each connection, so under the common default limit of 1024 the
    /// last connections, and every /dev/urandom read, failed with EMFILE.
    /// The cap now leaves the process room for all of its descriptors.
    #[test]
    fn bug_the_connection_cap_ignored_the_open_file_limit() {
        let limits = |soft: &str| {
            format!(
                "Limit                     Soft Limit           Hard Limit           Units     \n\
                 Max processes             63413                63413                processes \n\
                 Max open files            {soft:<20} 524288               files     \n"
            )
        };
        let cap = cap_for(&limits("1024"));
        assert!(cap < CONNECTIONS, "two pools of {cap} connections do not fit 1024 descriptors");
        assert_eq!(cap_for(&limits(&FILES_NEEDED.to_string())), CONNECTIONS);
        assert_eq!(cap_for(&limits("4096")), CONNECTIONS);
        assert_eq!(cap_for(&limits("unlimited")), CONNECTIONS);
        assert_eq!(cap_for(&limits("10")), 1);
        assert_eq!(cap_for(""), CONNECTIONS, "no /proc, as on macOS");
    }

    /// Bug (found in review): the cap counted two descriptors for a
    /// connection, its client's and its upstream's, but a connection also
    /// keeps a duplicate of its client's socket, through which a stop cuts
    /// it: three. Under a limit lower than the unit's, two full pools of
    /// proxied connections ran out of descriptors before the cap was
    /// reached.
    #[test]
    fn bug_a_connection_was_counted_as_two_descriptors_but_holds_three() {
        let limits = |soft: usize| format!("Max open files            {soft:<20} 524288               files     \n");
        for soft in [64, 256, 1024, 2064, 3000, 3088, 4096, 65536] {
            let cap = cap_for(&limits(soft));
            assert!(2 * cap * 3 + RESERVED_FILES <= soft, "two pools of {cap} connections, three descriptors each, do not fit {soft}");
        }
        assert_eq!(cap_for(&limits(1024)), 168);
        // What the unit sets holds two full pools.
        assert_eq!(FILES_NEEDED, 3088);
        assert_eq!(cap_for(&limits(4096)), CONNECTIONS);
    }

    /// A log the test can read after the server has taken it.
    struct Shared(Arc<Kept>);
    impl Log for Shared {
        fn access(&self, line: &str) {
            self.0.access(line);
        }
        fn error(&self, line: &str) {
            self.0.error(line);
        }
    }

    /// A renewed certificate is taken up without a restart: reload puts the
    /// new identity in place for the handshakes that follow, while files
    /// that do not make a valid identity leave the one before in place.
    #[test]
    fn renewed_certificates_are_taken_up() {
        let dir = std::env::temp_dir().join(format!("shioko-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let certs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs");
        let put = |chain: &str, key: &str| {
            std::fs::copy(certs.join(format!("{chain}.chain.pem")), dir.join("chain.pem")).unwrap();
            std::fs::copy(certs.join(format!("{key}.key")), dir.join("key.pem")).unwrap();
        };
        let chain_of = |name: &str| {
            Identity::load(&certs.join(format!("{name}.chain.pem")), &certs.join(format!("{name}.key"))).unwrap().chain
        };
        put("site.test", "site.test");
        let conf = dir.join("shioko.conf");
        let text = format!("[site.test]\nupstream = a:1\ncert = {0}/chain.pem\nkey = {0}/key.pem\n", dir.display());
        std::fs::write(&conf, text).unwrap();
        let config = crate::config::Config::load(&conf).unwrap();
        let first = Identity::load(&dir.join("chain.pem"), &dir.join("key.pem")).unwrap();
        let log = Arc::new(Kept::default());
        let server =
            Server::new(config, vec![Some(first)], "/nonexistent".into(), Box::new(Shared(Arc::clone(&log))), 4, PER_ADDRESS);
        let chain = || server.identities()[0].as_ref().unwrap().chain.clone();

        let before = server.identities();
        server.reload();
        assert!(Arc::ptr_eq(&before, &server.identities()), "nothing changed, yet the identities were replaced");
        put("tls.test", "tls.test");
        server.reload();
        assert_eq!(chain(), chain_of("tls.test"));
        assert!(before[0].as_ref().unwrap().chain == chain_of("site.test"), "an open connection's identity changed");
        // A key that does not belong to the certificate: the site keeps
        // what it had, and the log says why.
        put("site.test", "tls.test");
        server.reload();
        assert_eq!(chain(), chain_of("tls.test"));
        assert!(log.0.lock().unwrap().iter().any(|l| l.contains("keeping the certificate it had")), "{:?}", log.0);
        put("site.test", "site.test");
        server.reload();
        assert_eq!(chain(), chain_of("site.test"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Starts a server for `sites` on a free port and returns its address.
    fn start(sites: &str, cap: usize) -> (Arc<Server>, std::net::SocketAddr) {
        let config = parse(sites).unwrap();
        let identities = config.sites.iter().map(|_| None).collect();
        let server = Server::new(config, identities, "/nonexistent".into(), Box::new(Kept::default()), cap, PER_ADDRESS);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::clone(&server);
        std::thread::spawn(move || listen(&shared, &listener, false));
        (server, address)
    }

    /// An upstream that answers each connection with what `answer` makes of
    /// the request head it read.
    fn upstream(answer: impl Fn(&str, &mut TcpStream) + Send + 'static) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut connection in listener.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                answer(&String::from_utf8_lossy(&head), &mut connection);
            }
        });
        address
    }

    fn read_to_end(mut stream: &TcpStream) -> String {
        let mut text = Vec::new();
        let _ = stream.read_to_end(&mut text);
        String::from_utf8_lossy(&text).into_owned()
    }

    fn wait_until(what: impl Fn() -> bool) {
        for _ in 0..500 {
            if what() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("waited five seconds in vain");
    }

    #[test]
    fn a_request_goes_through_real_sockets() {
        let up = upstream(|head, connection| {
            assert!(head.starts_with("GET /hello HTTP/1.1\r\n"));
            assert!(head.contains("\r\nX-Real-IP: 127.0.0.1\r\n"));
            let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld");
        });
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"GET /hello HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n").unwrap();
        let received = read_to_end(&client);
        assert!(received.starts_with("HTTP/1.1 200 OK\r\n"), "{received:?}");
        assert!(received.ends_with("Connection: close\r\n\r\nworld"));
        // The slot of the connection comes back; the accept loop keeps one.
        wait_until(|| server.used() == 1);
    }

    #[test]
    fn an_upstream_that_refuses_connections_is_a_bad_gateway() {
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (_, address) = start(&format!("[site.test]\nupstream = {closed}\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n").unwrap();
        assert!(read_to_end(&client).starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    }

    #[test]
    fn a_websocket_tunnel_carries_bytes_both_ways_and_ends_as_one() {
        let up = upstream(|head, connection| {
            assert!(head.contains("\r\nConnection: upgrade\r\nUpgrade: websocket\r\n"));
            let _ = connection.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello",
            );
            // Echo until the client's side ends.
            let mut space = [0u8; 64];
            while let Ok(n) = connection.read(&mut space) {
                if n == 0 || connection.write_all(&space[..n]).is_err() {
                    break;
                }
            }
        });
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\nwebsocket = yes\n"), 8);
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .unwrap();
        let mut received = Vec::new();
        let mut space = [0u8; 256];
        while !received.ends_with(b"hello") {
            let n = client.read(&mut space).unwrap();
            assert!(n > 0, "the tunnel ended early");
            received.extend_from_slice(&space[..n]);
        }
        assert!(received.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        for message in ["one", "two", "three"] {
            client.write_all(message.as_bytes()).unwrap();
            let mut echo = vec![0u8; message.len()];
            client.read_exact(&mut echo).unwrap();
            assert_eq!(echo, message.as_bytes());
        }
        // The client closes its side: the whole tunnel ends, both threads
        // stop and the slot comes back.
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(read_to_end(&client), "");
        wait_until(|| server.used() == 1);
    }

    #[test]
    fn no_more_connections_are_served_at_once_than_the_cap_allows() {
        let up = upstream(|_, connection| {
            let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        // Three slots in the public pool, three connections from 127.0.0.1:
        // the pool is full, and the accept loop holds a slot of its own.
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\n"), 3);
        let first = TcpStream::connect(address).unwrap();
        let second = TcpStream::connect(address).unwrap();
        let third = TcpStream::connect(address).unwrap();
        wait_until(|| server.used() == 4);
        // A fourth connection is turned away at once: closed, unanswered.
        let mut fourth = TcpStream::connect(address).unwrap();
        let _ = fourth.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n");
        fourth.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut byte = [0u8; 1];
        assert!(matches!(fourth.read(&mut byte), Ok(0) | Err(_)), "the fourth connection was served");
        wait_until(|| server.used() == 4);
        // One of the first three goes away, and a new one gets in.
        drop(first);
        wait_until(|| server.used() == 3);
        let mut fifth = TcpStream::connect(address).unwrap();
        fifth.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n").unwrap();
        fifth.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(read_to_end(&fifth).ends_with("\r\n\r\nok"));
        drop((second, third));
        wait_until(|| server.used() == 1);
    }

    /// When waiting for signals fails, the stopping thread says so and
    /// stays, the one thread the signals are let through to; the server
    /// goes on serving.
    #[test]
    fn a_stop_that_cannot_wait_for_signals_says_so_and_stays() {
        let log = Arc::new(Kept::default());
        let config = parse("[wiki.test]\nupstream = a:1\n").unwrap();
        let server = Server::new(config, vec![None], "/nonexistent".into(), Box::new(Shared(Arc::clone(&log))), 3, 2);
        let stopping = Arc::clone(&server);
        let thread = std::thread::spawn(move || stop_on(&stopping, Err("waiting fails with error 1".into())));
        let said = || log.0.lock().unwrap().iter().any(|l| l == "error: no graceful stop: waiting fails with error 1");
        wait_until(said);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!thread.is_finished(), "the thread that lets the signals through ended");
        assert!(!server.stopping.load(Ordering::SeqCst), "the server stopped");
    }

    /// The pools of the two kinds of peer are apart: a flood from outside
    /// the allowlists, however many addresses it comes from, cannot take
    /// the slots of peers inside them, nor the other way round. In the
    /// public pool one address (an IPv6 /64) holds only so many.
    #[test]
    fn pools_keep_floods_apart() {
        let config = parse(
            "[vault.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\nallow = 10.0.0.0/8\n\n\
             [wiki.test]\nupstream = a:1\n",
        )
        .unwrap();
        let server = Server::new(config, vec![None, None], "/nonexistent".into(), Box::new(Kept::default()), 3, 2);
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let admit = |peer: &str, secure: bool| {
            let peer = ip(peer);
            Reserved::take(&server).admit(server.pool_of(peer, secure), peer, "")
        };
        // One address holds two public slots; a third is turned away, also
        // when it comes as an IPv4 address written as IPv6.
        let a = [admit("192.0.2.1", false).unwrap(), admit("192.0.2.1", false).unwrap()];
        assert!(admit("192.0.2.1", false).is_none());
        assert!(admit("::ffff:192.0.2.1", false).is_none());
        // Another address takes the last public slot; the pool is then full.
        let b = admit("192.0.2.2", false).unwrap();
        assert!(admit("192.0.2.3", false).is_none());
        // The allowed pool has all of its slots all the same; a fourth
        // allowed connection is turned away while a public slot comes back.
        let mut allowed: Vec<Slot> = (1..=2).map(|n| admit(&format!("10.0.0.{n}"), true).unwrap()).collect();
        allowed.push(admit("::ffff:10.0.0.3", true).unwrap());
        assert_eq!(server.used(), 6, "both pools full");
        drop(b);
        assert!(admit("10.0.0.9", false).is_none(), "a fourth allowed connection got in");
        // A slot that comes back is free for the next connection.
        let c = admit("2001:db8::1", false).unwrap();
        drop(a);
        // IPv6 addresses of one /64 are one address.
        let d = admit("2001:db8::2", false).unwrap();
        assert!(admit("2001:db8::3", false).is_none());
        let e = admit("2001:db8:0:1::1", false).unwrap();
        drop((c, d, e, allowed));
        assert_eq!(server.used(), 0);
    }

    /// Over TLS, a peer outside every allowlist is turned away at once when
    /// every site with a certificate has an allowlist: no site could serve
    /// it. Once one site with a certificate has none, it is let in.
    #[test]
    fn over_tls_only_peers_some_site_serves_are_let_in() {
        let tls = "[vault.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\nallow = 10.0.0.0/8\n";
        let server = |text: &str| {
            let config = parse(text).unwrap();
            let none = config.sites.iter().map(|_| None).collect();
            Server::new(config, none, "/nonexistent".into(), Box::new(Kept::default()), 3, 2)
        };
        let outside: IpAddr = "192.0.2.1".parse().unwrap();
        let locked = server(tls);
        assert_eq!(locked.pool_of(outside, true), None);
        assert_eq!(locked.pool_of(outside, false), Some(Pool::Public), "port 80 serves redirects and tokens to all");
        assert_eq!(locked.pool_of("10.1.2.3".parse().unwrap(), true), Some(Pool::Allowed));
        assert!(Reserved::take(&locked).admit(None, outside, "").is_none());
        assert_eq!(locked.used(), 0);
        let open = server(&format!("{tls}\n[media.test]\nupstream = a:1\ncert = /certs/chain.pem\nkey = /certs/key.pem\n"));
        assert_eq!(open.pool_of(outside, true), Some(Pool::Public));
    }

    /// The server ended this connection: its stream ends, or is reset,
    /// rather than going silent.
    fn ended(mut stream: &TcpStream) -> bool {
        match stream.read(&mut [0u8; 1]) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => !matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        }
    }

    /// Reads from `stream` until what came ends with `end`.
    fn read_until(stream: &mut TcpStream, end: &[u8]) -> Vec<u8> {
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(end) {
            assert_eq!(stream.read(&mut byte).unwrap(), 1, "ended early after {:?}", String::from_utf8_lossy(&got));
            got.push(byte[0]);
        }
        got
    }

    /// A stop lets the requests being served finish, cuts at once the
    /// connections that wait for a request and the tunnels, and lets nobody
    /// in any more.
    #[test]
    fn a_stop_lets_requests_finish_and_cuts_the_rest() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut connection in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                        head.push(byte[0]);
                    }
                    if head.starts_with(b"GET /ws ") {
                        let _ = connection.write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                        );
                        let mut space = [0u8; 64];
                        while let Ok(n) = connection.read(&mut space) {
                            if n == 0 || connection.write_all(&space[..n]).is_err() {
                                break;
                            }
                        }
                        return;
                    }
                    if head.starts_with(b"GET /slow ") {
                        std::thread::sleep(Duration::from_millis(700));
                    }
                    let _ = connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                });
            }
        });
        let (server, address) = start(&format!("[site.test]\nupstream = {up}\nwebsocket = yes\n"), 8);
        let connect = || {
            let stream = TcpStream::connect(address).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream
        };
        // A request being served, its upstream slow to answer.
        let mut slow = connect();
        slow.write_all(b"GET /slow HTTP/1.1\r\nHost: site.test\r\n\r\n").unwrap();
        // A kept connection waiting for its next request.
        let mut kept = connect();
        kept.write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n").unwrap();
        read_until(&mut kept, b"\r\n\r\nok");
        // A connection that has sent nothing yet, and a tunnel.
        let quiet = connect();
        let mut tunnel = connect();
        tunnel
            .write_all(b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .unwrap();
        read_until(&mut tunnel, b"\r\n\r\n");
        // Four connections and the slot the accept loop holds.
        wait_until(|| server.used() == 5);

        let stopping = Arc::clone(&server);
        let started = Instant::now();
        let drain = std::thread::spawn(move || stopping.drain(Duration::from_secs(5)));
        for (what, stream) in [("kept", &kept), ("quiet", &quiet), ("tunnel", &tunnel)] {
            assert!(ended(stream), "the {what} connection was not cut");
        }
        let late = connect();
        let _ = (&late).write_all(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n");
        assert!(ended(&late), "a connection was let in after the stop");
        // The request being served is answered whole, and then the
        // connection ends.
        assert!(read_to_end(&slow).ends_with("\r\n\r\nok"));
        assert_eq!(drain.join().unwrap(), 0, "connections were left when the drain ended");
        assert!(started.elapsed() < Duration::from_secs(3), "the drain waited for its deadline");
    }

    #[test]
    fn a_slot_comes_back_however_its_holder_ends() {
        let (server, _) = start("[site.test]\nupstream = 127.0.0.1:9\n", 4);
        wait_until(|| server.used() == 1);
        let shared = Arc::clone(&server);
        let panicking = std::thread::spawn(move || {
            let peer: IpAddr = "192.0.2.1".parse().unwrap();
            let _slot = Reserved::take(&shared).admit(Some(Pool::Public), peer, "").unwrap();
            assert_eq!(shared.used(), 2);
            panic!("a connection thread dies");
        });
        assert!(panicking.join().is_err());
        assert_eq!(server.used(), 1);
        // A reserved slot that is never admitted comes back too.
        drop(Reserved::take(&server));
        assert_eq!(server.used(), 1);
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use crate::config::tests::parse;
    use crate::log::testing::Kept;
    use crate::tls::client::{Client, Got};
    use crate::tls::{msgs, record};
    use std::io::{Read, Write};
    use std::path::Path;

    fn certs(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs").join(name)
    }

    /// An upstream that accepts a WebSocket upgrade and then echoes, also
    /// sending something of its own every so often.
    fn websocket_upstream() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for mut connection in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                        head.push(byte[0]);
                    }
                    let _ = connection.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    );
                    let mut space = [0u8; 4096];
                    while let Ok(n) = connection.read(&mut space) {
                        if n == 0 || connection.write_all(&space[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        address
    }

    fn tls_server(upstream: std::net::SocketAddr) -> (Arc<Server>, std::net::SocketAddr) {
        let config = parse(&format!(
            "[site.test]\nupstream = {upstream}\nwebsocket = yes\ncert = /certs/chain.pem\nkey = /certs/key.pem\n"
        ))
        .unwrap();
        let identity = Identity::load(&certs("site.test.chain.pem"), &certs("site.test.key")).unwrap();
        let server = Server::new(config, vec![Some(identity)], "/nonexistent".into(), Box::new(Kept::default()), 8, PER_ADDRESS);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::clone(&server);
        std::thread::spawn(move || listen(&shared, &listener, true));
        (server, address)
    }

    fn public() -> [u8; 65] {
        Identity::load(&certs("site.test.chain.pem"), &certs("site.test.key")).unwrap().key.public_key().unwrap()
    }

    /// Reads application data until `want` bytes have come, taking the
    /// server's KeyUpdates as they come.
    fn read_data(client: &mut Client, want: usize) -> Vec<u8> {
        let mut got = Vec::new();
        while got.len() < want {
            match client.get() {
                Got::Data(data) => got.extend(data),
                Got::Handshake(messages) if messages == vec![msgs::key_update(false)] => {
                    client.read.as_mut().unwrap().next();
                }
                other => panic!("expected data, got {other:?}"),
            }
        }
        got
    }

    /// A WebSocket tunnel over TLS: two threads share the TLS connection,
    /// one reading from the client, the other writing to it. The client
    /// asks for KeyUpdates in the middle; the writing thread must send ours
    /// before its next data, and every record must decrypt in order.
    #[test]
    fn a_websocket_tunnel_over_tls_with_key_updates() {
        let (server, address) = tls_server(websocket_upstream());
        let mut client = Client::handshake(address, "site.test", &public());
        client.send(record::APPLICATION_DATA, b"GET /ws HTTP/1.1\r\nHost: site.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        let head = read_data(&mut client, 1);
        assert!(head.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"), "{}", String::from_utf8_lossy(&head));
        let mut expected = Vec::new();
        let mut received = Vec::new();
        for round in 0..20u8 {
            if round % 4 == 1 {
                client.send(record::HANDSHAKE, &msgs::key_update(true));
                client.write.as_mut().unwrap().next();
            }
            if round % 4 == 3 {
                client.send(record::HANDSHAKE, &msgs::key_update(false));
                client.write.as_mut().unwrap().next();
            }
            let message = vec![b'a' + round; 3000 + usize::from(round) * 997];
            client.send(record::APPLICATION_DATA, &message);
            expected.extend(&message);
            received.extend(read_data(&mut client, expected.len() - received.len()));
        }
        assert_eq!(received, expected);
        // The client closes: the tunnel ends, both threads stop, the slot
        // comes back.
        client.send(record::ALERT, &[1, 0]);
        loop {
            match client.get() {
                Got::Alert(0) | Got::End => break,
                Got::Data(_) | Got::Handshake(_) => {}
                other => panic!("{other:?}"),
            }
        }
        for _ in 0..500 {
            if server.used() == 1 {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the tunnel's slot did not come back");
    }
}
