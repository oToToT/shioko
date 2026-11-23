//! SIGTERM and SIGINT, with which systemd and a terminal stop the server.
//!
//! The standard library has no way to wait for a signal, and shioko uses no
//! crate but libcrux, so this makes the two system calls itself, which is
//! why it needs `unsafe`. `start` is called before any thread is started:
//! it checks that the signals can be waited for, then blocks them, so they
//! stay pending in every thread instead of ending the process; one thread
//! then takes them with `wait`.
//!
//! Linux on x86-64 and AArch64 only, the system call numbers being theirs;
//! elsewhere shioko stops at once on SIGTERM, as the signal's default.

#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicU32, Ordering};

const SIGINT: u32 = 2;
const SIGTERM: u32 = 15;
/// The kernel's signal set: bit n - 1 for signal n.
const SET: u64 = (1 << (SIGINT - 1)) | (1 << (SIGTERM - 1));
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
/// The errors the waiting can meet: interrupted by a signal handler (there
/// are none, but the call may say so all the same), and no signal pending
/// when no time is given to wait.
const EINTR: isize = 4;
const EAGAIN: isize = 11;
/// The size of a signal set, which the two calls ask for.
const SET_SIZE: usize = 8;

#[cfg(target_arch = "x86_64")]
const RT_SIGPROCMASK: usize = 14;
#[cfg(target_arch = "x86_64")]
const RT_SIGTIMEDWAIT: usize = 128;
#[cfg(target_arch = "aarch64")]
const RT_SIGPROCMASK: usize = 135;
#[cfg(target_arch = "aarch64")]
const RT_SIGTIMEDWAIT: usize = 137;

/// Sets this thread's mask: blocks the two signals, or unblocks them.
fn mask(how: usize) -> bool {
    let set = SET;
    // SAFETY: rt_sigprocmask reads the 8-byte set at `&set`, which lives
    // across the call; the old set is not asked for (null), so it writes
    // nothing.
    let result = unsafe { syscall4(RT_SIGPROCMASK, how, std::ptr::from_ref(&set) as usize, 0, SET_SIZE) };
    result == 0
}

/// rt_sigtimedwait for the two signals, waiting for ever, or not at all.
fn take(wait: bool) -> isize {
    let set = SET;
    // seconds, nanoseconds: no time at all
    let none: [i64; 2] = [0, 0];
    let timeout = if wait { 0 } else { std::ptr::from_ref(&none) as usize };
    // SAFETY: rt_sigtimedwait reads the 8-byte set at `&set` and, if given,
    // the 16-byte timespec at `&none`, both of which live across the call;
    // the signal's details are not asked for (null), so it writes nothing.
    unsafe { syscall4(RT_SIGTIMEDWAIT, std::ptr::from_ref(&set) as usize, 0, timeout, SET_SIZE) }
}

/// What a result of rt_sigtimedwait means.
#[derive(Debug, PartialEq, Eq)]
enum Taken {
    /// One of the two signals came.
    Signal(u32),
    /// Nothing came (interrupted, or no time to wait was given): try again.
    Again,
    /// The call cannot be made: forbidden (a system call filter), unknown,
    /// or refused, with this error number. Waiting again would spin.
    Failed(isize),
}

/// A signal that was pending already when `start` looked, which looking
/// took; `wait` hands it out first.
static EARLY: AtomicU32 = AtomicU32::new(0);

fn taken(result: isize) -> Taken {
    match u32::try_from(result) {
        Ok(signal) if signal == SIGTERM || signal == SIGINT => Taken::Signal(signal),
        _ if result == -EINTR || result == -EAGAIN => Taken::Again,
        _ => Taken::Failed(result.saturating_neg()),
    }
}

/// Makes ready to wait for SIGTERM and SIGINT: checks that they can be
/// waited for, then blocks them in this thread and every thread it starts
/// from now on. Call it before starting any thread. If they cannot be
/// waited for (a system call filter forbids it), nothing is blocked and
/// the signals keep their default: they end the process at once.
pub fn start() -> Result<(), String> {
    match taken(take(false)) {
        Taken::Failed(error) => return Err(format!("rt_sigtimedwait fails with error {error}")),
        // Pending already: whoever started us had it blocked, and a program
        // keeps its mask and its pending signals across exec. Looking took
        // it, so it is kept for wait. (One that came while nothing blocked
        // it has ended the process already.)
        Taken::Signal(signal) => EARLY.store(signal, Ordering::SeqCst),
        Taken::Again => {}
    }
    if mask(SIG_BLOCK) { Ok(()) } else { Err("rt_sigprocmask fails".into()) }
}

/// Waits for SIGTERM or SIGINT, made ready by `start`; returns which came.
/// If waiting fails for good, which `start` makes all but impossible, this
/// thread lets the signals through again, so that the next one ends the
/// process at once as by default, and says so. The caller must then keep
/// this thread alive (and not spinning): it is the one thread that lets
/// them through.
pub fn wait() -> Result<u32, String> {
    match EARLY.swap(0, Ordering::SeqCst) {
        0 => {}
        signal => return Ok(signal),
    }
    loop {
        match taken(take(true)) {
            Taken::Signal(signal) => return Ok(signal),
            Taken::Again => {}
            // rt_sigprocmask fails only on a bad pointer or a bad argument
            // (EFAULT, EINVAL), and gets neither here; were it to fail all
            // the same, the signals would stay blocked everywhere.
            Taken::Failed(error) if mask(SIG_UNBLOCK) => {
                return Err(format!("waiting for a signal fails with error {error}: SIGTERM and SIGINT now end the server at once"));
            }
            Taken::Failed(error) => {
                return Err(format!(
                    "waiting for a signal fails with error {error}, and SIGTERM and SIGINT cannot be let through again: only SIGKILL stops the server"
                ));
            }
        }
    }
}

/// Makes system call `number` with four arguments.
///
/// # Safety
///
/// The arguments must be what the call expects; any pointer among them
/// must be valid for what the call reads and writes through it.
#[cfg(target_arch = "x86_64")]
unsafe fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: the Linux x86-64 system call convention: the number in rax,
    // the arguments in rdi, rsi, rdx and r10, the result in rax; the
    // instruction overwrites rcx and r11. It uses no stack of ours.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") number as isize => result,
            in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    result
}

/// Makes system call `number` with four arguments.
///
/// # Safety
///
/// The arguments must be what the call expects; any pointer among them
/// must be valid for what the call reads and writes through it.
#[cfg(target_arch = "aarch64")]
unsafe fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: the Linux AArch64 system call convention: the number in x8,
    // the arguments in x0 to x3, the result in x0. It uses no stack of ours.
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") number,
            inlateout("x0") a as isize => result,
            in("x1") b, in("x2") c, in("x3") d,
            options(nostack),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The set names the two signals and nothing else, and they can be
    /// waited for and blocked (in this test's own thread, which then ends).
    #[test]
    fn the_two_signals_can_be_blocked() {
        assert_eq!(SET, 0b100_0000_0000_0010);
        assert_eq!(std::thread::spawn(start).join().unwrap(), Ok(()));
    }

    #[cfg(target_arch = "x86_64")]
    const GETPID_GETTID_TGKILL: [usize; 3] = [39, 186, 234];
    #[cfg(target_arch = "aarch64")]
    const GETPID_GETTID_TGKILL: [usize; 3] = [172, 178, 131];

    /// Bug (found in review): a SIGTERM already pending when shioko started
    /// (sent while whoever started it had it blocked, which a program keeps
    /// across exec) was taken by the check in `start` and dropped, and the
    /// stop never happened. In a thread of its own, which blocks the signal
    /// first, so that the signal can reach no other thread.
    #[test]
    fn bug_a_sigterm_pending_at_start_was_lost() {
        std::thread::spawn(|| {
            assert!(mask(SIG_BLOCK));
            let [getpid, gettid, tgkill] = GETPID_GETTID_TGKILL;
            // SAFETY: getpid and gettid take no arguments and touch no
            // memory; tgkill takes three numbers.
            let sent = unsafe {
                let pid = syscall4(getpid, 0, 0, 0, 0);
                let tid = syscall4(gettid, 0, 0, 0, 0);
                syscall4(tgkill, pid as usize, tid as usize, SIGTERM as usize, 0)
            };
            assert_eq!(sent, 0, "tgkill");
            assert_eq!(start(), Ok(()));
            assert_eq!(EARLY.load(Ordering::SeqCst), SIGTERM, "the pending SIGTERM was taken and dropped");
            assert_eq!(wait(), Ok(SIGTERM));
        })
        .join()
        .unwrap();
    }

    /// Bug (found in review): any result of rt_sigtimedwait but a signal
    /// made `wait` call it again, so a call that fails for good (a system
    /// call filter answering EPERM) would have spun for ever. Only an
    /// interruption is tried again now.
    #[test]
    fn bug_a_wait_that_failed_for_good_was_tried_for_ever() {
        assert_eq!(taken(15), Taken::Signal(SIGTERM));
        assert_eq!(taken(2), Taken::Signal(SIGINT));
        assert_eq!(taken(-4), Taken::Again);
        assert_eq!(taken(-11), Taken::Again);
        assert_eq!(taken(-1), Taken::Failed(1), "EPERM, from a system call filter");
        assert_eq!(taken(-38), Taken::Failed(38), "ENOSYS");
        assert_eq!(taken(-22), Taken::Failed(22), "EINVAL");
        assert_eq!(taken(10), Taken::Failed(-10), "a signal we did not ask for");
    }
}
