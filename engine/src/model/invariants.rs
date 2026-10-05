//! The evidence rule, checked mechanically (docs/ARCHITECTURE.md §A).
//!
//! - an observed trace may contain only `observed` and `derived`
//! - a simulated trace may contain only `simulated`
//!
//! The check walks the serialized JSON rather than the Rust types, so it also
//! covers fields added later without anyone remembering to update it.

use serde_json::Value;

use super::{Evidence, Trace, TraceKind};

#[derive(Debug, PartialEq)]
pub enum Violation {
    ForbiddenEvidence { path: String, evidence: String },
    EventsOutOfOrder { index: usize },
    NegativeSpan { event_id: String },
}

/// A traceroute holds only measurements and derivations, like an observed trace.
pub fn check_path(path: &super::PathTrace) -> Vec<Violation> {
    let allowed: Vec<Value> = [Evidence::Observed, Evidence::Derived].iter().map(|e| serde_json::to_value(e).unwrap()).collect();
    let mut violations = Vec::new();
    walk(&serde_json::to_value(path).expect("path serializes"), "$", &allowed, &mut violations);
    violations
}

pub fn check(trace: &Trace) -> Vec<Violation> {
    let allowed: &[Evidence] = match trace.kind {
        TraceKind::Observed => &[Evidence::Observed, Evidence::Derived],
        TraceKind::Simulated => &[Evidence::Simulated],
    };
    let allowed: Vec<Value> = allowed.iter().map(|e| serde_json::to_value(e).unwrap()).collect();

    let mut violations = Vec::new();
    let json = serde_json::to_value(trace).expect("trace serializes");
    walk(&json, "$", &allowed, &mut violations);

    for (i, pair) in trace.events.windows(2).enumerate() {
        if pair[1].time.start < pair[0].time.start {
            violations.push(Violation::EventsOutOfOrder { index: i + 1 });
        }
    }
    for e in &trace.events {
        if e.time.end.is_some_and(|end| end < e.time.start) {
            violations.push(Violation::NegativeSpan { event_id: e.id.clone() });
        }
    }
    violations
}

fn walk(v: &Value, path: &str, allowed: &[Value], out: &mut Vec<Violation>) {
    match v {
        Value::Object(map) => {
            if let Some(ev) = map.get("evidence") {
                if !allowed.contains(ev) {
                    out.push(Violation::ForbiddenEvidence {
                        path: path.to_string(),
                        evidence: ev.to_string(),
                    });
                }
            }
            for (k, child) in map {
                walk(child, &format!("{path}.{k}"), allowed, out);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk(child, &format!("{path}[{i}]"), allowed, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn trace_with(kind: TraceKind, host: Fact<String>) -> Trace {
        let f = |v: &str| Fact::observed(v.to_string(), "test");
        Trace {
            schema_version: SCHEMA_VERSION,
            id: "t".into(),
            kind,
            source: TraceSource::WebTrace,
            input: TraceInput { url: "https://example.com".into(), follow_redirects: true },
            vantage: Vantage { description: "test".into(), is_user_machine: true, runtime: "test".into() },
            started_at_unix_ms: 0.0,
            entities: vec![],
            hops: vec![],
            events: vec![TraceEvent {
                id: "e1".into(),
                hop_index: 0,
                connection_id: None,
                parent_id: None,
                protocol: None,
                evidence: if kind == TraceKind::Observed { Evidence::Observed } else { Evidence::Simulated },
                time: Span { start: 0.0, end: Some(1.0) },
                from: None,
                to: None,
                status: Status::Ok,
                error: None,
                explain_key: None,
                payload: Payload::UrlParse(UrlParseData {
                    input: f("https://example.com"),
                    scheme: f("https"),
                    host,
                    host_kind: Fact::observed(HostKind::Domain, "test"),
                    port: Fact::derived(443, "test"),
                    path: f("/"),
                }),
            }],
            outcome: Outcome { ok: true, summary: None },
        }
    }

    #[test]
    fn observed_trace_with_observed_and_derived_passes() {
        let t = trace_with(TraceKind::Observed, Fact::observed("example.com".into(), "test"));
        assert_eq!(check(&t), vec![]);
    }

    #[test]
    fn explained_fact_in_observed_trace_is_rejected() {
        let mut host = Fact::observed("example.com".to_string(), "test");
        host.evidence = Evidence::Explained; // the engine has no constructor for this, forced here
        let v = check(&trace_with(TraceKind::Observed, host));
        assert_eq!(v.len(), 1);
        assert!(matches!(&v[0], Violation::ForbiddenEvidence { path, .. } if path.ends_with(".data.host")));
    }

    #[test]
    fn observed_fact_in_simulated_trace_is_rejected() {
        let t = trace_with(TraceKind::Simulated, Fact::observed("example.com".into(), "test"));
        assert!(!check(&t).is_empty());
    }

    #[test]
    fn events_must_be_in_time_order() {
        let mut t = trace_with(TraceKind::Observed, Fact::observed("example.com".into(), "test"));
        let mut later = t.events[0].clone();
        later.time.start = -1.0;
        t.events.push(later);
        assert!(check(&t).contains(&Violation::EventsOutOfOrder { index: 1 }));
    }
}
