//! shioko's stand-in for libcrux's CPU-feature detection. shioko uses only
//! the portable code of libcrux, so there is nothing to detect: the answer
//! is always no, and the SIMD paths are never taken. The real crate needs
//! `libc` and `unsafe` to ask the CPU; this needs neither.
#![forbid(unsafe_code)]
#![no_std]

pub fn simd128_support() -> bool {
    false
}

pub fn simd256_support() -> bool {
    false
}
