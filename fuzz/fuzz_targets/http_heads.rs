//! Request and response heads, read from a stream that gives the bytes in
//! pieces of the size the first byte says.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::http::parse;
use shioko::stream::Buffer;
use shioko_fuzz::{Memory, piece_and_rest};

fuzz_target!(|data: &[u8]| {
    let (piece, rest) = piece_and_rest(data);
    let stream = Memory::new(rest, piece);
    let mut buffer = Buffer::new();
    // Requests one after the other on the same stream, as a kept connection
    // reads them.
    for _ in 0..8 {
        match parse::read_request(&mut buffer, &stream) {
            Ok(request) => {
                if let Some(host) = request.fields.one("host") {
                    let _ = parse::host(host);
                }
            }
            Err(_) => break,
        }
    }
    let stream = Memory::new(rest, piece);
    let _ = parse::read_response(&mut Buffer::new(), &stream);
    let _ = parse::host(rest);
    let _ = parse::chunk_size(rest);
});
