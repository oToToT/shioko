//! SIGTERM and SIGINT, with which systemd and a terminal stop the server.
//!
//! The standard library has no way to wait for a signal, and shioko uses no
//! crate but libcrux, so this makes the two system calls itself, which is
//! why it needs `unsafe`. `block` is called before any thread is started,
//! so the two signals stay pending in every thread instead of ending the
//! process; one thread then takes them with `wait`.

#![allow(unsafe_code)]

const SIGINT: u32 = 2;
const SIGTERM: u32 = 15;
/// The kernel's signal set: bit n - 1 for signal n.
const SET: u64 = (1 << (SIGINT - 1)) | (1 << (SIGTERM - 1));
const SIG_BLOCK: usize = 0;
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

/// Blocks SIGTERM and SIGINT in this thread and in every thread it starts
/// from now on.
pub fn block() -> bool {
    let set = SET;
    // SAFETY: rt_sigprocmask reads the 8-byte set at `&set`, which lives
    // across the call; the old set is not asked for (null), so it writes
    // nothing.
    let result = unsafe { syscall4(RT_SIGPROCMASK, SIG_BLOCK, std::ptr::from_ref(&set) as usize, 0, SET_SIZE) };
    result == 0
}

/// Waits for SIGTERM or SIGINT, which must be blocked; returns which came.
pub fn wait() -> u32 {
    let set = SET;
    loop {
        // SAFETY: rt_sigtimedwait reads the 8-byte set at `&set`, which
        // lives across the call; neither the signal's details nor a timeout
        // are given (null), so it writes nothing.
        let result = unsafe { syscall4(RT_SIGTIMEDWAIT, std::ptr::from_ref(&set) as usize, 0, 0, SET_SIZE) };
        // Anything but a signal number is an interruption: wait again.
        if let Ok(signal) = u32::try_from(result)
            && (signal == SIGTERM || signal == SIGINT)
        {
            return signal;
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

    /// The set names the two signals and nothing else, and blocking it
    /// works (in this test's own thread, which then ends).
    #[test]
    fn the_two_signals_can_be_blocked() {
        assert_eq!(SET, 0b100_0000_0000_0010);
        assert!(std::thread::spawn(block).join().unwrap());
    }
}
