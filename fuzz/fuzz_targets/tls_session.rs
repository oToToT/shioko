//! A TLS connection past its handshake: a real handshake with a client of
//! the harness, then the records the fuzzer chose, sealed under the
//! client's keys (KeyUpdates followed), and HTTP from an upstream made of
//! the fuzzer's bytes. What the server sends must open under its keys.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::http::proxy;
use shioko::tls::conn::{Served, TlsStream};
use shioko::tls::peer::Peer;
use shioko_fuzz::{Quiet, Upstream, config, context, identities, piece_and_rest, two_parts};
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
    let peer = Peer::new(Peer::records(client), piece);
    let (tls, _site) = TlsStream::accept(peer.clone(), &served, &Quiet).expect("the handshake of a good client succeeds");
    proxy::serve(&tls, &context(&upstream, true));
    drop(tls);
    peer.check();
});
