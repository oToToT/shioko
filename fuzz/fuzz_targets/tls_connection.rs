//! A whole TLS connection: the handshake with whatever the client sends,
//! and the HTTP after it if it gets that far.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::http::proxy;
use shioko::tls::conn::{Served, TlsStream};
use shioko_fuzz::{Memory, Quiet, Upstream, config, context, identities, piece_and_rest, two_parts};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let (piece, rest) = piece_and_rest(data);
    let (client, answer) = two_parts(rest);
    let served = Served {
        config: config(),
        identities: identities(),
        peer: "192.0.2.1".parse().unwrap(),
        timeout: Duration::from_secs(10),
    };
    let upstream = Upstream { answer: answer.to_vec(), piece };
    if let Some((tls, _site)) = TlsStream::accept(Memory::new(client, piece), &served, &Quiet) {
        proxy::serve(&tls, &context(&upstream, true));
    }
});
