//! A whole plain-HTTP connection: what the client sends, and what each
//! upstream connection answers, both from the fuzzer's bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::http::proxy;
use shioko_fuzz::{Memory, Upstream, context, piece_and_rest, two_parts};

fuzz_target!(|data: &[u8]| {
    let (piece, rest) = piece_and_rest(data);
    let (client, answer) = two_parts(rest);
    let upstream = Upstream { answer: answer.to_vec(), piece };
    let client = Memory::new(client, piece);
    proxy::serve(&client, &context(&upstream, false));
});
