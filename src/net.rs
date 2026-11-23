//! Address ranges for the allowlists.

use std::net::IpAddr;

/// An address range such as `10.0.0.0/8` or `2001:db8::/32`. IPv4 addresses
/// are kept in their IPv6-mapped form, so that a client is matched the same
/// whether it reached us over an IPv4 or a dual-stack socket. A range is
/// for the clients of the family it is written in, as in nginx with its
/// `deny all`: an IPv4 client is matched against IPv4 ranges only. So an
/// IPv6 range lets no IPv4 client in, neither `::/0`, which holds the
/// mapped form of every IPv4 address, nor one of mapped addresses alone
/// (`::ffff:0:0/96`), which lets nobody in at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    network: u128,
    mask: u128,
    /// Written as an IPv4 range: for IPv4 clients.
    v4: bool,
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
        Some(Range { network: mapped(address) & mask, mask, v4: address.is_ipv4() })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        canonical(address).is_ipv4() == self.v4 && mapped(address) & self.mask == self.network
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
        // Host bits in the written range are ignored.
        assert!(Range::parse("10.1.2.3/8").unwrap().contains(ip("10.9.9.9")));
    }

    /// Bug (found in review): an IPv6 range that holds the mapped form of
    /// IPv4 addresses, such as `::/0`, let every IPv4 client in as well.
    /// nginx, whose `allow` rules sites bring over, matches an IPv4 client
    /// against IPv4 rules only once there is a `deny all`; so do we now.
    /// That goes for a range of mapped addresses too: `allow
    /// ::ffff:0:0/96; deny all;` lets no IPv4 client into nginx, and no
    /// client has such an address as an IPv6 one, so it lets nobody in.
    #[test]
    fn bug_an_ipv6_range_let_ipv4_clients_in() {
        for range in ["::/0", "::/64", "::ffff:0:0/80", "::ffff:0:0/96", "::ffff:203.0.113.0/120", "::ffff:203.0.113.9"] {
            let range = Range::parse(range).unwrap();
            assert!(!range.contains(ip("203.0.113.9")), "{range:?}");
            assert!(!range.contains(ip("::ffff:203.0.113.9")), "{range:?}");
        }
        for range in ["::/0", "::/64", "::ffff:0:0/80"] {
            assert!(Range::parse(range).unwrap().contains(ip("::1")), "{range}");
        }
        assert!(!Range::parse("::ffff:0:0/96").unwrap().contains(ip("2001:db8::1")));
        assert_ne!(Range::parse("::ffff:10.1.0.0/112"), Range::parse("10.1.0.0/16"));
        // An IPv4 range is for IPv4 clients, however they reached us.
        let all_v4 = Range::parse("0.0.0.0/0").unwrap();
        assert!(all_v4.contains(ip("203.0.113.9")) && all_v4.contains(ip("::ffff:203.0.113.9")));
        assert!(!all_v4.contains(ip("::1")) && !all_v4.contains(ip("2001:db8::1")));
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
