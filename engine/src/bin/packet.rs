//! packet trace <url> [--dns <ip>] [--no-follow] [--allow-private] [--json]
//! packet path <host|ip> [--json]

use std::process::ExitCode;

use packet::model::{invariants, Trace};
use packet::trace::guard::Policy;
use packet::trace::{run, Options};
use serde_json::Value;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let (Some("path"), Some(target)) = (args.first().map(String::as_str), args.get(1)) {
        return path(target, args.iter().any(|a| a == "--json")).await;
    }
    let (Some("trace"), Some(url)) = (args.first().map(String::as_str), args.get(1)) else {
        eprintln!("usage: packet trace <url> [--dns <ip>] [--no-follow] [--allow-private] [--json]\n       packet path <host|ip> [--json]");
        return ExitCode::from(2);
    };
    let flag = |name: &str| args.iter().position(|a| a == name);
    let dns_server = match flag("--dns").map(|i| args.get(i + 1).and_then(|v| v.parse().ok())) {
        None => None,
        Some(Some(ip)) => Some(ip),
        Some(None) => {
            eprintln!("--dns needs an IP address, e.g. --dns 1.1.1.1");
            return ExitCode::from(2);
        }
    };

    let policy = if flag("--allow-private").is_some() { Policy::AllowPrivate } else { Policy::PublicOnly };
    let opts = Options {
        dns_server,
        follow_redirects: flag("--no-follow").is_none(),
        policy,
        vantage: "This machine (packet CLI)".into(),
        geo: packet::geo::Geo::load(&packet::geo::default_dir()).ok().map(std::sync::Arc::new),
    };
    let trace = run(url, &opts).await;

    let violations = invariants::check(&trace);
    if flag("--json").is_some() {
        println!("{}", serde_json::to_string_pretty(&trace).unwrap());
    } else {
        print_trace(&trace);
    }
    if !violations.is_empty() {
        eprintln!("\nEVIDENCE INVARIANT VIOLATED: {violations:?}");
        return ExitCode::FAILURE;
    }
    if trace.outcome.ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn print_trace(trace: &Trace) {
    println!("PACKET  trace {}  ·  {}", trace.id, trace.input.url);
    println!("vantage: {} ({})\n", trace.vantage.description, trace.vantage.runtime);
    println!("  {:>9}  {:>9}  {:<11} {}", "START", "DURATION", "EVENT", "STATUS");

    let mut section = String::new();
    for ev in &trace.events {
        let json = serde_json::to_value(ev).unwrap();
        let label = if json["kind"] == "dns.query" {
            "── Packet's own DNS queries (sent after the request, not part of it)".to_string()
        } else if trace.hops.len() > 1 {
            let h = &trace.hops[ev.hop_index as usize];
            format!("── hop {}  {}  {}", h.index, h.url, h.status.map(|s| s.to_string()).unwrap_or_default())
        } else {
            String::new()
        };
        if label != section {
            println!("  {label}\n");
            section = label;
        }
        let dur = ev.time.end.map(|e| format!("{:.2}ms", e - ev.time.start)).unwrap_or_else(|| "·".into());
        println!(
            "  {:>7.2}ms  {:>9}  {:<11} {}",
            ev.time.start,
            dur,
            json["kind"].as_str().unwrap_or("?"),
            json["status"].as_str().unwrap_or("?"),
        );
        if let Some(err) = json.get("error") {
            print_fact("error", err, 6);
        }
        if let Value::Object(fields) = &json["data"] {
            print_fields(fields, 6);
        }
        println!();
    }
    println!(
        "outcome: {}  {}",
        if trace.outcome.ok { "ok" } else { "FAILED" },
        trace.outcome.summary.as_deref().unwrap_or("")
    );
    println!("legend:  [OBS] observed   [DER] derived");
}

fn print_fields(fields: &serde_json::Map<String, Value>, indent: usize) {
    for (key, v) in fields {
        if v.get("evidence").is_some() {
            print_fact(key, v, indent);
        } else if let Value::Object(nested) = v {
            println!("{:indent$}{key}:", "");
            print_fields(nested, indent + 2);
        }
    }
}

fn print_fact(key: &str, fact: &Value, indent: usize) {
    let tag = match fact["evidence"].as_str() {
        Some("observed") => "OBS",
        Some("derived") => "DER",
        _ => "???",
    };
    let source = fact["source"].as_str().unwrap_or("");
    let pad = indent + 2;
    match &fact["value"] {
        Value::Array(items) if items.iter().any(Value::is_object) || items.len() > 3 => {
            println!("{:indent$}{key:<16} [{tag}] {source}", "");
            if items.is_empty() {
                println!("{:pad$}(none)", "");
            }
            for item in items {
                println!("{:pad$}{}", "", compact(item));
            }
        }
        Value::Object(map) if map.len() > 4 => {
            println!("{:indent$}{key:<16} [{tag}] {source}", "");
            for (k, v) in map {
                println!("{:pad$}{k:<22} {}", "", compact(v));
            }
        }
        value => println!("{:indent$}{key:<16} {:<38} [{tag}] {source}", "", compact(value)),
    }
    if let Some(note) = fact["note"].as_str() {
        println!("{:pad$}↳ {note}", "");
    }
}

fn compact(v: &Value) -> String {
    match v {
        Value::String(s) => s.replace('\r', "\\r").replace('\n', "\\n"),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={}", compact(v)))
            .collect::<Vec<_>>()
            .join("  "),
        Value::Array(items) => items.iter().map(compact).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

async fn path(target: &str, json: bool) -> ExitCode {
    let ip: std::net::IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => match tokio::net::lookup_host((target, 0)).await.ok().and_then(|mut a| a.next()) {
            Some(sa) => sa.ip(),
            None => {
                eprintln!("cannot resolve {target}");
                return ExitCode::FAILURE;
            }
        },
    };
    let geo = packet::geo::Geo::load(&packet::geo::default_dir()).ok();
    let vantage = packet::model::Vantage {
        description: "This machine (packet CLI)".into(),
        is_user_machine: true,
        runtime: format!("packet {}", env!("CARGO_PKG_VERSION")),
    };
    let p = packet::trace::path::trace_path(ip, geo.as_ref(), vantage).await;
    let violations = invariants::check_path(&p);
    if json {
        println!("{}", serde_json::to_string_pretty(&p).unwrap());
    } else {
        println!("PACKET  path to {ip}  ·  {}  ·  {:.1} s\n", p.method.value, p.duration_ms / 1000.0);
        for h in &p.hops {
            let rtts: Vec<String> = h.probes.value.iter().map(|x| x.rtt_ms.map(|r| format!("{r:.1}")).unwrap_or_else(|| "*".into())).collect();
            if h.responders.is_empty() {
                println!("  {:>2}  {:<40} {}", h.ttl, "* (no answer)", rtts.join("  "));
            }
            for (i, r) in h.responders.iter().enumerate() {
                let what = r.class.as_ref().map(|c| c.value.clone()).or_else(|| r.location.as_ref().map(|l| format!("db: {}", l.value.place))).unwrap_or_default();
                let ttl = if i == 0 { format!("{:>2}", h.ttl) } else { "  ".into() };
                println!("  {ttl}  {:<40} {:<22} {}", r.address.to_string(), if i == 0 { rtts.join("  ") } else { String::new() }, what);
            }
        }
        println!("\nreached target: {}", p.reached.value);
        if let Some(e) = &p.error {
            println!("error: {}", e.value.message);
        }
    }
    if !violations.is_empty() {
        eprintln!("EVIDENCE INVARIANT VIOLATED: {violations:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
