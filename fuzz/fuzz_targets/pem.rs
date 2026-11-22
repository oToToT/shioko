//! PEM, base64 and the DER walk to the private key.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::pem;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = pem::certificates(&text);
    let _ = pem::private_key(&text);
});
