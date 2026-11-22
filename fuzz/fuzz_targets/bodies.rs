//! Copying bodies, chunked and of a stated length, from a stream that gives
//! the bytes in pieces of the size the first byte says.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::http::body;
use shioko::stream::Buffer;
use shioko_fuzz::{Memory, piece_and_rest};

fuzz_target!(|data: &[u8]| {
    let (piece, rest) = piece_and_rest(data);
    for rechunk in [false, true] {
        let (from, to) = (Memory::new(rest, piece), Memory::new(&[], 1));
        let copied = body::copy_chunked(&mut Buffer::new(), &from, &to, 4096, rechunk);
        if copied.is_ok() && !rechunk {
            assert!(to.output.lock().unwrap().len() <= 4096, "more than the limit went through");
        }
    }
    let length = rest.first().map_or(0, |&n| u64::from(n));
    let (from, to) = (Memory::new(rest, piece), Memory::new(&[], 1));
    if body::copy_length(&mut Buffer::new(), &from, &to, length).is_ok() {
        assert_eq!(to.output.lock().unwrap().len() as u64, length);
    }
});
