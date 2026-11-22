//! Address ranges for the allowlists.

use std::net::IpAddr;

/// An address range such as `10.0.0.0/8` or `2001:db8::/32`. IPv4 addresses
/// are kept in their IPv6-mapped form, so that a client is matched the same
/// whether it reached us over an IPv4 or a dual-stack socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    network: u128,
    mask: u128,
}

fn mapped(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

impl Range {
    /// Reads `address` or `address/prefix-length`.
    pub fn parse(text: &str) -> Option<Range> {
        let (address, prefix) = text.split_once('/').map_or((text, None), |(a, p)| (a, Some(p)));
        let address: IpAddr = address.parse().ok()?;
        let width: u32 = if address.is_ipv4() { 32 } else { 128 };
        let prefix: u32 = match prefix {
            Some(digits) if digits.bytes().all(|b| b.is_ascii_digit()) => digits.parse().ok()?,
            Some(_) => return None,
            None => width,
        };
        // The host bits are the last `width - prefix`, so an IPv4 range also
        // covers the 96 bits of the mapping prefix in front of it.
        let mask = u128::MAX.checked_shl(width.checked_sub(prefix)?).unwrap_or(0);
        Some(Range { network: mapped(address) & mask, mask })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        mapped(address) & self.mask == self.network
    }
}

/// The address as we report it: an IPv4 client that arrived on a dual-stack
/// socket is shown as IPv4.
pub fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// An address on which a connection would come back to this host: a
/// loopback address, or the unspecified address, which Linux connects to
/// the host itself.
pub fn is_loopback(address: IpAddr) -> bool {
    canonical(address).is_loopback() || canonical(address).is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ranges() {
        let range = Range::parse("10.1.0.0/16").unwrap();
        assert!(range.contains(ip("10.1.2.3")));
        assert!(range.contains(ip("::ffff:10.1.2.3")));
        assert!(!range.contains(ip("10.2.0.0")));
        assert!(!range.contains(ip("::10.1.2.3")));
        let range = Range::parse("2400:cb00::/32").unwrap();
        assert!(range.contains(ip("2400:cb00:1::1")));
        assert!(!range.contains(ip("2400:cb01::1")));
        assert!(!range.contains(ip("36.203.0.1")));
        // A single address, and the whole of each family.
        assert!(Range::parse("192.0.2.7").unwrap().contains(ip("192.0.2.7")));
        assert!(!Range::parse("192.0.2.7").unwrap().contains(ip("192.0.2.8")));
        assert!(Range::parse("0.0.0.0/0").unwrap().contains(ip("203.0.113.9")));
        assert!(!Range::parse("0.0.0.0/0").unwrap().contains(ip("2001:db8::1")));
        assert!(Range::parse("::/0").unwrap().contains(ip("2001:db8::1")));
        assert!(Range::parse("::/0").unwrap().contains(ip("203.0.113.9")));
        // Host bits in the written range are ignored.
        assert!(Range::parse("10.1.2.3/8").unwrap().contains(ip("10.9.9.9")));
    }

    #[test]
    fn what_is_not_a_range() {
        for text in ["", "10.0.0.0/33", "::/129", "10.0.0.0/", "10.0.0.0/+8", "10.0.0/8", "example.org", "10.0.0.0/8/8", "/8"] {
            assert_eq!(Range::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn canonical_addresses() {
        assert_eq!(canonical(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(canonical(ip("2001:db8::1")), ip("2001:db8::1"));
        assert!(is_loopback(ip("127.0.0.1")));
        assert!(is_loopback(ip("::1")));
        assert!(is_loopback(ip("::ffff:127.0.0.1")));
        assert!(is_loopback(ip("0.0.0.0")));
        assert!(is_loopback(ip("::")));
        assert!(!is_loopback(ip("192.0.2.1")));
    }
}
