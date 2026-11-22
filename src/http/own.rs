//! The responses shioko writes itself: errors, the redirect to HTTPS, and
//! ACME tokens. Each one is followed by closing the connection.

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// A point in time, taken apart for an HTTP date.
#[derive(Debug, PartialEq, Eq)]
pub struct Civil {
    pub weekday: usize,
    pub day: u64,
    pub month: usize,
    pub year: u64,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
}

/// Seconds since 1970 as a calendar date, in UTC. Weekday 0 is Sunday and
/// month 1 is January.
pub fn civil(unix: u64) -> Civil {
    let days = unix / 86_400;
    let rest = unix % 86_400;
    // Days are counted from 1 March of year 0, in eras of 400 years.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    Civil {
        weekday: usize::try_from((days + 4) % 7).unwrap_or(0),
        day,
        month: usize::try_from(month).unwrap_or(1),
        year,
        hour: rest / 3_600,
        minute: rest / 60 % 60,
        second: rest % 60,
    }
}

/// The date in the one format HTTP writes: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let c = civil(unix);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS.get(c.weekday).unwrap_or(&"Sun"),
        c.day,
        MONTHS.get(c.month.wrapping_sub(1)).unwrap_or(&"Jan"),
        c.year,
        c.hour,
        c.minute,
        c.second
    )
}

/// What an own response carries besides its status.
pub enum Content {
    /// The status and its name, as one line of text.
    Text,
    /// A redirect to this location.
    Redirect(String),
    /// An ACME token.
    Token(Vec<u8>),
}

/// The bytes of an own response. `head_only`: the request was HEAD, so the
/// body is left out and only its length is stated.
pub fn response(status: u16, content: &Content, now: u64, head_only: bool) -> Vec<u8> {
    let reason = reason(status);
    let text = format!("{status} {reason}\n");
    let (kind, body) = match content {
        Content::Token(token) => ("application/octet-stream", token.as_slice()),
        _ => ("text/plain", text.as_bytes()),
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nDate: {}\r\n", http_date(now));
    if let Content::Redirect(location) = content {
        head.push_str(&format!("Location: {location}\r\n"));
    }
    head.push_str(&format!("Content-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    if !head_only {
        bytes.extend_from_slice(body);
    }
    bytes
}

// Proofs, checked by Kani (tools/prove.sh).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any time whatever gives a date that exists, without overflow.
    #[kani::proof]
    fn every_time_is_a_date() {
        let c = civil(kani::any());
        assert!(c.weekday < 7);
        assert!((1..=31).contains(&c.day));
        assert!((1..=12).contains(&c.month));
        assert!(c.hour < 24 && c.minute < 60 && c.second < 60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(951_868_799), "Tue, 29 Feb 2000 23:59:59 GMT");
        assert_eq!(http_date(951_868_800), "Wed, 01 Mar 2000 00:00:00 GMT");
        assert_eq!(http_date(1_795_219_200), "Sat, 21 Nov 2026 00:00:00 GMT");
        assert_eq!(http_date(4_102_444_799), "Thu, 31 Dec 2099 23:59:59 GMT");
        assert_eq!(http_date(4_107_542_400), "Mon, 01 Mar 2100 00:00:00 GMT");
    }

    #[test]
    fn every_day_follows_the_one_before() {
        // Forty years of days: each is one more than the last, or the first
        // of the next month, and the weekdays go round.
        let mut previous = civil(0);
        for day in 1..(40 * 366) {
            let today = civil(day * 86_400);
            assert_eq!(today.weekday, (previous.weekday + 1) % 7);
            if today.day != previous.day + 1 {
                assert_eq!(today.day, 1);
                assert!(previous.day >= 28);
                assert_eq!(today.month, previous.month % 12 + 1);
                assert_eq!(today.year, previous.year + u64::from(today.month == 1));
            }
            previous = today;
        }
    }

    #[test]
    fn an_error() {
        let bytes = response(404, &Content::Text, 0, false);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "HTTP/1.1 404 Not Found\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\n\
             Content-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\n404 Not Found\n"
        );
    }

    #[test]
    fn a_response_to_head_has_no_body_but_states_its_length() {
        let bytes = response(404, &Content::Text, 0, true);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.ends_with("Content-Length: 14\r\nConnection: close\r\n\r\n"));
    }

    #[test]
    fn a_redirect_and_a_token() {
        let text = String::from_utf8(response(301, &Content::Redirect("https://a.example/x?y".into()), 0, false)).unwrap();
        assert!(text.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
        assert!(text.contains("\r\nLocation: https://a.example/x?y\r\n"));
        let bytes = response(200, &Content::Token(b"tok.en".to_vec()), 0, false);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\n"));
        assert!(text.ends_with("\r\n\r\ntok.en"));
    }

    #[test]
    fn every_status_we_send_has_a_name() {
        for status in [200, 301, 400, 403, 404, 405, 413, 414, 421, 431, 501, 502, 504] {
            assert_ne!(reason(status), "Error", "{status}");
        }
    }
}
