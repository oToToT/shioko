//! Development builds only (`--features record`): a log of the steps of
//! `spec/Server.tla` as the server takes them, for TLC to check
//! (tools/servertrace.py, spec/ServerTrace.tla). Each line is a thread and
//! a step: `l443 reserve`, `c7 up tunnel`, `c7 down lock`. A step that a
//! lock guards is written while that lock is held, so the lines come in an
//! order the steps could have happened in. Never deploy such a build.

use std::cell::RefCell;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

thread_local! {
    /// Who this thread is, and whether it is a pump of a tunnel.
    static WHO: RefCell<(String, bool)> = const { RefCell::new((String::new(), false)) };
}

static FILE: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// Writes a step of this thread to the file SHIOKO_RECORD names.
pub fn step(what: &str) {
    let file = FILE.get_or_init(|| {
        let path = std::env::var_os("SHIOKO_RECORD")?;
        std::fs::OpenOptions::new().append(true).create(true).open(path).ok().map(Mutex::new)
    });
    if let Some(file) = file {
        let who = WHO.with(|w| w.borrow().0.clone());
        let mut file = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = writeln!(file, "{who} {what}");
    }
}

/// A step of the TLS write lock, written only by the pumps of a tunnel.
pub fn lock_step(what: &str) {
    if WHO.with(|w| w.borrow().1) {
        step(what);
    }
}

/// From now on this thread is `who`, a pump of a tunnel or not.
pub fn be(who: String, pump: bool) {
    WHO.with(|w| *w.borrow_mut() = (who, pump));
}

pub fn who() -> String {
    WHO.with(|w| w.borrow().0.clone())
}

/// A name for the next connection.
pub fn connection() -> String {
    format!("c{}", CONNECTIONS.fetch_add(1, Ordering::Relaxed))
}
