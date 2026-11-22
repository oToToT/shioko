//! The locks, atomics and threads that connections share. They are std's;
//! in the build of shuttle/ (`--cfg shuttle`) they are shuttle's, whose
//! scheduler then decides every interleaving of the threads, so that the
//! tests of src/interleavings.rs can run the real code under thousands of
//! schedules, and are told of a deadlock rather than hang.

#[cfg(not(shuttle))]
pub use std::sync::{Condvar, Mutex, MutexGuard, RwLock, atomic};
#[cfg(not(shuttle))]
pub use std::thread;

#[cfg(shuttle)]
pub use shuttle::sync::{Condvar, Mutex, MutexGuard, RwLock, atomic};
#[cfg(shuttle)]
pub use shuttle::thread;

pub use std::sync::{Arc, PoisonError};

/// Starts a scoped thread, or says why it could not be.
#[cfg(not(shuttle))]
pub fn spawn_scoped<'scope, 'env, T: Send + 'scope>(
    scope: &'scope thread::Scope<'scope, 'env>, f: impl FnOnce() -> T + Send + 'scope,
) -> std::io::Result<thread::ScopedJoinHandle<'scope, T>> {
    thread::Builder::new().spawn_scoped(scope, f)
}

/// Starts a scoped thread (shuttle has no Builder for these, and its
/// threads always start).
#[cfg(shuttle)]
pub fn spawn_scoped<'scope, 'env, T: Send + 'scope>(
    scope: &'scope thread::Scope<'scope, 'env>, f: impl FnOnce() -> T + Send + 'scope,
) -> std::io::Result<thread::ScopedJoinHandle<'scope, T>> {
    Ok(scope.spawn(f))
}
