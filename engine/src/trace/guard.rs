//! Which addresses Packet is willing to connect to.
//!
//! A tool that fetches any URL you type is a classic SSRF risk: point it at
//! your router's admin page, a cloud metadata service (169.254.169.254) or
//! something on localhost, and it becomes a proxy into networks you
//! shouldn't reach. This module is the check. It runs on every resolved
//! address, before connect(), on every hop of a redirect chain.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Only globally routable addresses.
    PublicOnly,
    /// Also private, loopback and link-local. For local test servers.
    AllowPrivate,
}

impl Policy {
    pub fn name(self) -> &'static str {
        match self {
            Policy::PublicOnly => "public-only",
            Policy::AllowPrivate => "allow-private (--allow-private)",
        }
    }
}

/// Why an address is special, or None if it's an ordinary public address.
pub fn classify(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Some(reason) if the policy refuses this address.
pub fn refuses(policy: Policy, ip: IpAddr) -> Option<&'static str> {
    let reason = classify(ip)?;
    match policy {
        Policy::PublicOnly => Some(reason),
        // Even when testing locally, never "this host on any interface" or multicast.
        Policy::AllowPrivate => matches!(reason, UNSPECIFIED | MULTICAST | RESERVED).then_some(reason),
    }
}

const UNSPECIFIED: &str = "unspecified / 'this network' (0.0.0.0/8, ::)";
const MULTICAST: &str = "multicast (224.0.0.0/4, ff00::/8)";
const RESERVED: &str = "reserved / broadcast (240.0.0.0/4)";

fn classify_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    Some(match (a, b, c) {
        (0, _, _) => UNSPECIFIED,
        (127, _, _) => "loopback (127.0.0.0/8): this machine",
        (10, _, _) => "private (10.0.0.0/8)",
        (172, 16..=31, _) => "private (172.16.0.0/12)",
        (192, 168, _) => "private (192.168.0.0/16)",
        (169, 254, _) => "link-local (169.254.0.0/16), includes cloud metadata 169.254.169.254",
        (100, 64..=127, _) => "carrier-grade NAT shared space (100.64.0.0/10)",
        (192, 0, 0) => "IETF protocol assignments (192.0.0.0/24)",
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => "documentation (TEST-NET)",
        (198, 18..=19, _) => "benchmarking (198.18.0.0/15)",
        (224..=239, _, _) => MULTICAST,
        (240..=255, _, _) => RESERVED,
        _ => return None,
    })
}

fn classify_v6(ip: Ipv6Addr) -> Option<&'static str> {
    // An IPv4 address wearing IPv6 clothes (::ffff:10.0.0.1) is judged as IPv4.
    // Otherwise "::ffff:127.0.0.1" would slip past every v4 rule.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let seg = ip.segments();
    Some(match seg[0] {
        _ if ip.is_unspecified() => UNSPECIFIED,
        _ if ip.is_loopback() => "loopback (::1): this machine",
        0xfc00..=0xfdff => "unique local (fc00::/7): IPv6's private range",
        0xfe80..=0xfebf => "link-local (fe80::/10)",
        0xff00..=0xffff => MULTICAST,
        0x2001 if seg[1] == 0x0db8 => "documentation (2001:db8::/32)",
        // NAT64 (64:ff9b::/96) embeds an IPv4 address in the last 32 bits.
        0x0064 if seg[1] == 0xff9b && seg[2..6] == [0; 4] => {
            let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
            return classify_v4(v4);
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(s: &str) -> bool {
        refuses(Policy::PublicOnly, s.parse().unwrap()).is_some()
    }

    #[test]
    fn public_addresses_pass() {
        for ip in ["93.184.215.14", "1.1.1.1", "104.20.23.154", "2606:4700:10::6814:179a", "8.8.8.8"] {
            assert!(!refused(ip), "{ip}");
        }
    }

    #[test]
    fn internal_addresses_are_refused() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "172.20.10.1", // your hotspot gateway
            "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
            "::1", "::", "fd00::1", "fe80::1", "ff02::1",
        ] {
            assert!(refused(ip), "{ip}");
        }
    }

    #[test]
    fn disguised_ipv4_is_unwrapped() {
        assert!(refused("::ffff:127.0.0.1"));
        assert!(refused("::ffff:169.254.169.254"));
        assert!(refused("64:ff9b::a00:1")); // NAT64 of 10.0.0.1
        assert!(!refused("64:ff9b::808:808")); // NAT64 of 8.8.8.8
    }

    #[test]
    fn edges_of_ranges() {
        assert!(!refused("172.15.255.255"));
        assert!(!refused("172.32.0.0"));
        assert!(!refused("100.63.255.255"));
        assert!(!refused("100.128.0.0"));
    }

    #[test]
    fn allow_private_still_refuses_nonsense() {
        let p = Policy::AllowPrivate;
        assert!(refuses(p, "127.0.0.1".parse().unwrap()).is_none());
        assert!(refuses(p, "192.168.1.1".parse().unwrap()).is_none());
        assert!(refuses(p, "0.0.0.0".parse().unwrap()).is_some());
        assert!(refuses(p, "224.0.0.1".parse().unwrap()).is_some());
    }
}
