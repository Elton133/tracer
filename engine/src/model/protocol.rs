//! The single protocol → layer registry (docs/ARCHITECTURE.md §E).
//!
//! Events carry only a `ProtocolId`. Their OSI / TCP-IP placement always comes
//! from `info()`, so the mapping can't drift between views. `info` is an
//! exhaustive `match`: adding a protocol without mapping it fails to compile.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export)]
pub enum ProtocolId {
    #[serde(rename = "http/1.1")]
    Http1,
    #[serde(rename = "h2")]
    Http2,
    #[serde(rename = "dns")]
    Dns,
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "ipv4")]
    Ipv4,
    #[serde(rename = "ipv6")]
    Ipv6,
    #[serde(rename = "ethernet")]
    Ethernet,
    #[serde(rename = "wifi")]
    Wifi,
}

impl ProtocolId {
    pub const ALL: [ProtocolId; 10] = [
        Self::Http1, Self::Http2, Self::Dns, Self::Tls, Self::Tcp,
        Self::Udp, Self::Ipv4, Self::Ipv6, Self::Ethernet, Self::Wifi,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum TcpIpLayer {
    Application,
    Transport,
    Internet,
    NetworkAccess,
}

/// The conventional OSI → TCP/IP correspondence used by the layer strip.
pub fn osi_to_tcpip(osi: u8) -> TcpIpLayer {
    match osi {
        5..=7 => TcpIpLayer::Application,
        4 => TcpIpLayer::Transport,
        3 => TcpIpLayer::Internet,
        1 | 2 => TcpIpLayer::NetworkAccess,
        _ => panic!("OSI layer out of range: {osi}"),
    }
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ProtocolInfo {
    pub id: ProtocolId,
    pub name: String,
    /// The OSI layer the strip highlights.
    pub osi_primary: u8,
    /// Every OSI layer the protocol is commonly said to touch.
    pub osi_span: Vec<u8>,
    pub tcpip: TcpIpLayer,
    /// What normally carries it. DNS can ride on UDP or TCP.
    pub carried_by: Vec<ProtocolId>,
    /// Shown whenever this mapping is displayed.
    #[ts(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_note: Option<String>,
}

pub fn info(id: ProtocolId) -> ProtocolInfo {
    use ProtocolId::*;
    let p = |name: &str, osi: u8, span: &[u8], carried_by: &[ProtocolId], note: Option<&str>| ProtocolInfo {
        id,
        name: name.into(),
        osi_primary: osi,
        osi_span: span.to_vec(),
        tcpip: osi_to_tcpip(osi),
        carried_by: carried_by.to_vec(),
        mapping_note: note.map(Into::into),
    };
    match id {
        Http1 => p("HTTP/1.1", 7, &[7], &[Tcp, Tls], None),
        Http2 => p("HTTP/2", 7, &[7], &[Tls], Some(
            "HTTP/2 is negotiated via TLS ALPN. Browsers only speak it over TLS.",
        )),
        Dns => p("DNS", 7, &[7], &[Udp, Tcp], Some(
            "Usually a single UDP datagram to port 53. Falls back to TCP for large answers. DoH puts it inside HTTPS.",
        )),
        Tls => p("TLS", 6, &[5, 6], &[Tcp], Some(
            "TLS sits between the application and TCP. OSI has no clean slot for it: \
             'presentation/session' is a teaching convention, not a spec fact. \
             TCP/IP simply treats it as part of the application.",
        )),
        Tcp => p("TCP", 4, &[4], &[Ipv4, Ipv6], None),
        Udp => p("UDP", 4, &[4], &[Ipv4, Ipv6], None),
        Ipv4 => p("IPv4", 3, &[3], &[Ethernet, Wifi], None),
        Ipv6 => p("IPv6", 3, &[3], &[Ethernet, Wifi], None),
        Ethernet => p("Ethernet II", 2, &[1, 2], &[], None),
        Wifi => p("802.11 Wi-Fi", 2, &[1, 2], &[], None),
    }
}

pub fn registry() -> Vec<ProtocolInfo> {
    ProtocolId::ALL.into_iter().map(info).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_layer_is_inside_span() {
        for p in registry() {
            assert!(p.osi_span.contains(&p.osi_primary), "{:?}", p.id);
        }
    }

    #[test]
    fn carriers_sit_at_or_below_the_protocol() {
        for p in registry() {
            for c in &p.carried_by {
                assert!(info(*c).osi_primary <= p.osi_primary, "{:?} carried by {:?}", p.id, c);
            }
        }
    }

    /// Writes the registry next to the generated TS types so the UI reads
    /// the same mapping instead of keeping its own copy.
    #[test]
    fn export_registry_json() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/generated");
        std::fs::create_dir_all(&dir).unwrap();
        let json = serde_json::to_string_pretty(&registry()).unwrap();
        std::fs::write(dir.join("protocols.json"), json + "\n").unwrap();
    }
}
