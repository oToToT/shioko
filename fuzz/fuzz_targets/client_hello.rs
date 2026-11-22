//! The ClientHello parser and its checks, on any message: never a panic,
//! and what it accepts it can be asked again (a second ClientHello).
#![no_main]
use libfuzzer_sys::fuzz_target;
use shioko::tls::msgs;

fuzz_target!(|data: &[u8]| {
    // As a whole handshake message: type 1, its length, the body.
    let mut message = vec![msgs::CLIENT_HELLO];
    message.extend_from_slice(&(data.len().min(0xff_ffff) as u32).to_be_bytes()[1..]);
    message.extend_from_slice(data);
    if let Ok(hello) = msgs::client_hello(&message) {
        assert!(!hello.server_name.is_empty());
        assert!(hello.share.is_none_or(|(group, key)| match group {
            msgs::X25519 => key.len() == 32,
            msgs::X25519MLKEM768 => key.len() == msgs::X25519MLKEM768_SHARE_LEN,
            _ => false,
        }));
        let again = msgs::client_hello(&message).unwrap();
        assert_eq!(again.kept, hello.kept);
    }
    // And as it comes, whatever its header says.
    let _ = msgs::client_hello(data);
});
