use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// How Packet knows something. See docs/ARCHITECTURE.md §A.
///
/// The engine only ever constructs `Observed` and `Derived` (there are no
/// constructors for the other two on `Fact`). `Explained` belongs to the UI's
/// content library and `Simulated` to the simulator. `invariants::check`
/// enforces this on every trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum Evidence {
    /// Measured or captured directly during this request.
    Observed,
    /// Computed from observed values by a named rule.
    Derived,
    /// Educational description of what generally happens.
    Explained,
    /// Generated on purpose by the simulator.
    Simulated,
}

/// One value plus how we know it. Every protocol field in a trace is a `Fact`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Fact<T> {
    pub value: T,
    pub evidence: Evidence,
    /// Where the value came from: a system call / API, or a derivation rule.
    /// e.g. "getaddrinfo(3)", "dns response header: RCODE", "derive: default port for https"
    pub source: String,
    /// Caveat shown in the inspector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub note: Option<String>,
}

impl<T> Fact<T> {
    pub fn observed(value: T, source: impl Into<String>) -> Self {
        Self { value, evidence: Evidence::Observed, source: source.into(), note: None }
    }

    pub fn derived(value: T, rule: impl Into<String>) -> Self {
        Self { value, evidence: Evidence::Derived, source: rule.into(), note: None }
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}
