use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{ErrorInfo, Fact, GeoPoint, Vantage};

/// A traceroute: the routers that answered as probes ran out of TTL.
///
/// A separate measurement from a Trace. It answers "which routers do ICMP
/// packets to this address pass?", which is usually, but not necessarily,
/// the path the TCP connection's packets took.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PathTrace {
    pub schema_version: u32,
    pub id: String,
    pub target: IpAddr,
    pub method: Fact<String>,
    pub vantage: Vantage,
    pub started_at_unix_ms: f64,
    pub duration_ms: f64,
    /// TTL 1 upward. Hops that never answered are included, with only timeouts.
    pub hops: Vec<PathHop>,
    pub reached: Fact<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error: Option<Fact<ErrorInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PathHop {
    pub ttl: u8,
    /// One per round. A hop can answer from more than one address when
    /// routers load-balance across parallel links.
    pub probes: Fact<Vec<Probe>>,
    pub responders: Vec<Responder>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Probe {
    pub round: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rtt_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub from: Option<IpAddr>,
    /// "time-exceeded" (a router on the way), "echo-reply" (the target),
    /// "unreachable". Absent: no answer before the deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reply: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Responder {
    pub address: IpAddr,
    /// e.g. "private (10.0.0.0/8)", "carrier-grade NAT shared space".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub class: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub location: Option<Fact<GeoPoint>>,
    /// From its fastest reply: it can't be farther than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub max_km: Option<Fact<f64>>,
}
