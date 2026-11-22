//! Log lines. They go to standard output and standard error, where systemd
//! collects them.

/// Where log lines go.
pub trait Log: Sync {
    /// One line per request served.
    fn access(&self, line: &str);
    /// Something went wrong that the operator may want to know about.
    fn error(&self, line: &str);
}

/// Standard output for access lines, standard error for the rest.
pub struct Standard;

impl Log for Standard {
    fn access(&self, line: &str) {
        println!("{line}");
    }

    fn error(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Makes bytes that came from the network safe to print: anything that is
/// not a visible ASCII character or a space is written as `\xNN`, and so is
/// the backslash. A log line can then never be forged by what a peer sends.
pub fn escape(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        if (0x20..0x7f).contains(&byte) && byte != b'\\' && byte != b'"' {
            text.push(char::from(byte));
        } else {
            text.push_str(&format!("\\x{byte:02x}"));
        }
    }
    text
}

#[cfg(test)]
pub mod testing {
    use super::Log;
    use std::sync::Mutex;

    /// Keeps the lines for a test to look at.
    #[derive(Default)]
    pub struct Kept(pub Mutex<Vec<String>>);

    impl Log for Kept {
        fn access(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }

        fn error(&self, line: &str) {
            self.0.lock().unwrap().push(format!("error: {line}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_from_the_network_can_break_a_log_line() {
        assert_eq!(escape(b"GET /a b"), "GET /a b");
        assert_eq!(escape(b"a\r\nforged line"), "a\\x0d\\x0aforged line");
        assert_eq!(escape(b"tab\there \x00 \x7f \xff"), "tab\\x09here \\x00 \\x7f \\xff");
        assert_eq!(escape(b"quote\" and \\ too"), "quote\\x22 and \\x5c too");
    }
}
