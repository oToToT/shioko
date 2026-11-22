//! The configuration parser; files it names read as the same text.
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::config::Config;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = Config::parse(&text, &|_| Ok(text.to_string()));
});
