use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{Evidence, Fact, TraceEvent};

/// One complete run. Its `kind` decides which evidence it may contain:
/// see `invariants::check`.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Trace {
    pub schema_version: u32,
    pub id: String,
    pub kind: TraceKind,
    pub source: TraceSource,
    pub input: TraceInput,
    pub vantage: Vantage,
    /// Wall-clock start (Unix ms). Event times are monotonic offsets from it.
    pub started_at_unix_ms: f64,
    pub entities: Vec<Entity>,
    /// One per request in the redirect chain.
    pub hops: Vec<Hop>,
    pub events: Vec<TraceEvent>,
    pub outcome: Outcome,
}

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum TraceKind {
    Observed,
    Simulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum TraceSource {
    /// The engine made the request through ordinary sockets.
    WebTrace,
    /// The engine made the request *and* captured its packets (V3).
    LocalCapture,
    Simulator,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TraceInput {
    pub url: String,
    pub follow_redirects: bool,
}

/// An index over `events` for one request in the redirect chain. The
/// evidence lives on those events; this only groups them.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Hop {
    pub index: u32,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub redirect_to: Option<String>,
}

/// Where on the network the observations were made. Shown at all times in the UI.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Vantage {
    pub description: String,
    /// True when the engine ran on the user's own machine, so "your request" is accurate.
    pub is_user_machine: bool,
    pub runtime: String,
}

/// A node in the journey view.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Entity {
    pub id: String,
    pub role: EntityRole,
    pub label: String,
    #[serde(default)]
    pub addresses: Vec<Fact<std::net::IpAddr>>,
    /// IP-geolocation estimate, for public addresses when a database is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub location: Option<Fact<super::GeoPoint>>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum EntityRole {
    ClientApp,
    OsResolver,
    DnsServer,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Outcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub summary: Option<String>,
}
