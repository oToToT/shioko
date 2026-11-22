//! What the fuzz targets share: a stream over the fuzzer's bytes, an
//! upstream that answers from them, a log that keeps nothing, and the
//! configuration and certificate the connections are served with.

pub mod peer;

use shioko::config::Config;
use shioko::http::proxy::{Connect, Context, Timeouts};
use shioko::log::Log;
use shioko::stream::Stream;
use shioko::tls::conn::Identity;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Writes beyond this are refused, so that nothing grows without bound.
const OUTPUT_LIMIT: usize = 1 << 20;

/// A stream that reads the given bytes, at most `piece` at a time, then
/// ends; what is written to it is kept, up to a limit.
pub struct Memory {
    input: Mutex<(Vec<u8>, usize)>,
    piece: usize,
    pub output: Mutex<Vec<u8>>,
}

impl Memory {
    pub fn new(input: &[u8], piece: usize) -> Memory {
        Memory { input: Mutex::new((input.to_vec(), 0)), piece: piece.max(1), output: Mutex::new(Vec::new()) }
    }
}

impl Stream for Memory {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut input = self.input.lock().unwrap();
        let (data, at) = &mut *input;
        let n = buf.len().min(self.piece).min(data.len() - *at);
        buf[..n].copy_from_slice(&data[*at..*at + n]);
        *at += n;
        Ok(n)
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut output = self.output.lock().unwrap();
        if output.len() + buf.len() > OUTPUT_LIMIT {
            return Err(io::ErrorKind::WriteZero.into());
        }
        output.extend_from_slice(buf);
        Ok(())
    }

    fn set_read_timeout(&self, _: Duration) {}
    fn shutdown(&self) {}
    fn finish(&self) {}
}

/// Every upstream connection answers with the same bytes.
pub struct Upstream {
    pub answer: Vec<u8>,
    pub piece: usize,
}

impl Connect for Upstream {
    type Upstream = Memory;

    fn connect(&self, _: &str) -> Result<Memory, u16> {
        Ok(Memory::new(&self.answer, self.piece))
    }
}

pub struct Quiet;

impl Log for Quiet {
    fn access(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

/// One TLS site with WebSockets and an allowlist, one plain site.
pub fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let text = "[site.test]\nupstream = 127.0.0.1:1\nwebsocket = yes\nmax-body = 64K\n\
                    cert = /chain.pem\nkey = /key.pem\n\n\
                    [plain.test]\nupstream = 127.0.0.1:2\nallow = 10.0.0.0/8 2001:db8::/32\n";
        Config::parse(text, &|_| Ok(String::new())).unwrap()
    })
}

/// The test certificate and key of site.test.
pub fn identities() -> &'static [Option<Arc<Identity>>] {
    static IDENTITIES: OnceLock<Vec<Option<Arc<Identity>>>> = OnceLock::new();
    IDENTITIES.get_or_init(|| {
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/certs");
        let identity = Identity::load(&certs.join("site.test.chain.pem"), &certs.join("site.test.key")).unwrap();
        vec![Some(Arc::new(identity)), None]
    })
}

/// A context for serving one connection, as server.rs makes one.
pub fn context<'a>(upstream: &'a Upstream, tls: bool) -> Context<'a, Upstream> {
    static QUIET: Quiet = Quiet;
    Context {
        config: config(),
        connect: upstream,
        log: &QUIET,
        peer: "192.0.2.1".parse().unwrap(),
        tls_site: tls.then(|| &config().sites[0]),
        acme: Path::new("/nonexistent"),
        clock: || 784_111_777,
        timeouts: Timeouts::STANDARD,
        interruptible: &|_| true,
    }
}

/// Splits the fuzzer's bytes into a piece size and the rest.
pub fn piece_and_rest(data: &[u8]) -> (usize, &[u8]) {
    match data.split_first() {
        Some((&0, rest)) => (usize::MAX, rest),
        Some((&n, rest)) => (usize::from(n), rest),
        None => (1, data),
    }
}

/// Splits the fuzzer's bytes in two, the first part's length in two bytes.
pub fn two_parts(data: &[u8]) -> (&[u8], &[u8]) {
    let (length, rest) = data.split_at_checked(2).unwrap_or((&[0, 0], data));
    let n = usize::from(u16::from_be_bytes([length[0], length[1]])).min(rest.len());
    rest.split_at(n)
}
