//! The trace engine. Each phase lives in its own module and runs in the same
//! order the network stack does: url → dns → tcp → tls → http → close,
//! repeated once per hop when the server redirects.

mod clock;
pub mod dns;
pub mod guard;
mod http1;
pub mod path;
mod tcp;
mod tcp_info;
mod tls;
mod tls_records;
mod transport;
mod url;

use std::net::{IpAddr, SocketAddr};

use hickory_proto::rr::RecordType;

use crate::model::*;
pub use clock::Clock;
use transport::Transport;

const MAX_CONNECT_ATTEMPTS: usize = 3;
/// Browsers stop at around 20. Ten is plenty to show a chain.
const MAX_HOPS: usize = 10;

pub struct Options {
    /// Send our own DNS queries here instead of the system resolver.
    pub dns_server: Option<IpAddr>,
    pub follow_redirects: bool,
    pub policy: guard::Policy,
    /// Where this engine is running, shown in the UI as the observation point.
    pub vantage: String,
    /// Offline geolocation, if its data files are present (`npm run geo:fetch`).
    pub geo: Option<std::sync::Arc<crate::geo::Geo>>,
}

pub async fn run(input: &str, opts: &Options) -> Trace {
    let clock = Clock::start();
    let mut t = Collector {
        events: Vec::new(),
        entities: vec![Entity {
            id: dns::entity::APP.into(),
            role: EntityRole::ClientApp,
            label: "Packet engine".into(),
            addresses: vec![],
            location: None,
            evidence: Evidence::Observed,
        }],
    };
    let mut hops: Vec<Hop> = Vec::new();
    let mut hosts: Vec<(String, u32)> = Vec::new(); // for Packet's own DNS queries, with first hop index

    let mut url = input.to_string();
    let outcome = loop {
        let index = hops.len() as u32;
        let first_event = t.events.len();
        let result = trace_hop(&clock, &url, index, opts.policy, &mut t).await;
        for e in &mut t.events[first_event..] {
            e.hop_index = index;
        }
        if let Some(h) = &result.host {
            if !hosts.iter().any(|(seen, _)| seen == h) {
                hosts.push((h.clone(), index));
            }
        }

        let normalized = result.target.as_ref().map(|t| t.url.to_string()).unwrap_or_else(|| url.clone());
        let mut hop = Hop { index, url: normalized, connection_id: result.conn, status: result.status, redirect_to: None };
        if let Some(msg) = result.failure {
            hops.push(hop);
            break Outcome { ok: false, summary: Some(msg) };
        }
        let status = result.status.expect("no failure means a response");

        // Follow it?
        let next = match (&result.target, &result.location) {
            (Some(target), Some(loc)) if opts.follow_redirects && is_redirect(status) => {
                redirect(&clock, status, loc, &target.url, index, &mut t)
            }
            _ => None,
        };
        let Some(next) = next else {
            hops.push(hop);
            let n = hops.len() - 1;
            let via = if n > 0 { format!(" after {n} redirect(s)") } else { String::new() };
            break Outcome { ok: true, summary: Some(format!("HTTP {status}{via}")) };
        };
        hop.redirect_to = Some(next.clone());
        hops.push(hop);

        if hops.iter().any(|h| h.url == next) {
            break Outcome { ok: false, summary: Some(format!("Redirect loop: {next} was already visited")) };
        }
        if hops.len() >= MAX_HOPS {
            break Outcome { ok: false, summary: Some(format!("Stopped after {MAX_HOPS} hops")) };
        }
        url = next;
    };

    // Packet's own DNS queries, after the request so they don't sit in the
    // middle of its timeline. A and AAAA go out in parallel, just as
    // getaddrinfo does for a dual-stack lookup.
    let server = opts.dns_server.map(dns::ServerChoice::UserSpecified).or_else(dns::system_nameserver);
    if let Some(server) = &server {
        for (host, hop_index) in &hosts {
            let (mut a, mut aaaa) = tokio::join!(
                dns::query(&clock, server, host, RecordType::A),
                dns::query(&clock, server, host, RecordType::AAAA),
            );
            a.hop_index = *hop_index;
            aaaa.hop_index = *hop_index;
            t.events.extend([a, aaaa]);
        }
        if !hosts.is_empty() {
            t.entity(Entity {
                id: dns::entity::dns_server(server.ip()),
                role: EntityRole::DnsServer,
                label: format!("DNS resolver {}", server.ip()),
                addresses: vec![Fact::observed(server.ip(), "address we sent queries to")],
                location: None,
                evidence: Evidence::Observed,
            });
        }
    }

    // Locations: database estimates for public endpoints, and whatever data
    // center a CDN says answered. Both are labelled for what they are.
    if let Some(geo) = &opts.geo {
        for e in &mut t.entities {
            if matches!(e.role, EntityRole::Server | EntityRole::DnsServer) {
                e.location = e.addresses.first().and_then(|a| geo.locate(a.value));
            }
        }
        for ev in &mut t.events {
            if let Payload::HttpResponse(d) = &mut ev.payload {
                d.edge = d.headers.as_ref().and_then(|h| geo.edge(&h.value));
            }
        }
    }

    let mut events = t.events;
    events.sort_by(|a, b| a.time.start.total_cmp(&b.time.start));
    for (i, e) in events.iter_mut().enumerate() {
        e.id = format!("e{}", i + 1);
    }

    let trace = Trace {
        schema_version: SCHEMA_VERSION,
        id: format!("{:016x}", getrandom::u64().unwrap_or(0)),
        kind: TraceKind::Observed,
        source: TraceSource::WebTrace,
        input: TraceInput { url: input.into(), follow_redirects: opts.follow_redirects },
        vantage: Vantage {
            description: opts.vantage.clone(),
            is_user_machine: true,
            runtime: format!(
                "packet {} on {}-{}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        },
        started_at_unix_ms: clock.started_at_unix_ms,
        entities: t.entities,
        hops,
        events,
        outcome,
    };
    debug_assert_eq!(invariants::check(&trace), vec![]);
    trace
}

struct Collector {
    events: Vec<TraceEvent>,
    entities: Vec<Entity>,
}

impl Collector {
    fn entity(&mut self, e: Entity) {
        if !self.entities.iter().any(|x| x.id == e.id) {
            self.entities.push(e);
        }
    }
}

struct HopResult {
    target: Option<url::Target>,
    host: Option<String>,
    conn: Option<String>,
    status: Option<u16>,
    location: Option<String>,
    failure: Option<String>,
}

/// One full request: its own lookup, its own connection. Connection reuse
/// for same-origin redirects is not implemented, so every hop pays for DNS,
/// TCP and TLS again (the OS DNS cache usually makes the second lookup ~0 ms).
async fn trace_hop(clock: &Clock, input: &str, hop: u32, policy: guard::Policy, t: &mut Collector) -> HopResult {
    let mut r = HopResult { target: None, host: None, conn: None, status: None, location: None, failure: None };
    let fail = |mut r: HopResult, msg: String| {
        r.failure = Some(msg);
        r
    };

    let (target, ev) = match url::parse(input, clock.now()) {
        Ok(ok) => ok,
        Err(msg) => return fail(r, msg),
    };
    t.events.push(ev);

    // 1. Name → addresses, the way any application would ask.
    let (addrs, choice_source) = match &target.host {
        ::url::Host::Domain(host) => {
            r.host = Some(host.clone());
            let (ev, addrs) = dns::os_lookup(clock, host, target.port).await;
            t.events.push(ev);
            t.entity(Entity {
                id: dns::entity::OS_RESOLVER.into(),
                role: EntityRole::OsResolver,
                label: "Operating system resolver".into(),
                addresses: vec![],
                location: None,
                evidence: Evidence::Observed,
            });
            let Some(addrs) = addrs else {
                return fail(r, format!("{host} could not be resolved"));
            };
            (addrs, "getaddrinfo returned")
        }
        ::url::Host::Ipv4(ip) => (vec![(*ip).into()], "the URL contained"),
        ::url::Host::Ipv6(ip) => (vec![(*ip).into()], "the URL contained"),
    };

    // 2. Safety check on every address, before any packet is sent to it.
    let verdicts: Vec<GuardVerdict> = addrs
        .iter()
        .map(|ip| GuardVerdict {
            address: *ip,
            allowed: guard::refuses(policy, *ip).is_none(),
            class: guard::classify(*ip).map(Into::into),
        })
        .collect();
    let mut ev = event(
        None,
        Span { start: clock.now(), end: None },
        Payload::GuardCheck(GuardCheckData {
            policy: Fact::observed(policy.name().into(), "engine configuration"),
            verdicts: Fact::derived(verdicts.clone(), "derive: address ranges from IANA special-purpose registries"),
        }),
    );
    ev.explain_key = Some("guard.ssrf".into());
    let addrs: Vec<IpAddr> = verdicts.iter().filter(|v| v.allowed).map(|v| v.address).collect();
    if addrs.is_empty() {
        ev.status = Status::Error;
        let why = verdicts.first().and_then(|v| v.class.clone()).unwrap_or_default();
        ev.error = Some(Fact::observed(
            ErrorInfo { code: "BLOCKED".into(), message: format!("no allowed address: {why}") },
            "engine policy",
        ));
        t.events.push(ev);
        return fail(r, format!("Refused by address policy ({}): {why}", policy.name()));
    }
    t.events.push(ev);

    // 3. TCP to one concrete address. Never re-resolve: the IP we connect
    //    to is the one we recorded. Try addresses in the OS's preferred
    //    order (RFC 6724), one at a time. Happy Eyeballs (racing v4/v6)
    //    is not implemented.
    let conn = format!("c{}", hop + 1);
    r.conn = Some(conn.clone());
    let mut stream = None;
    let mut rtt = None;
    for (i, ip) in addrs.iter().take(MAX_CONNECT_ATTEMPTS).enumerate() {
        let remote = SocketAddr::new(*ip, target.port);
        let choice = if i == 0 {
            format!("first of {} allowed address(es) {choice_source}", addrs.len())
        } else {
            format!("address {} of {}, after the previous attempt failed", i + 1, addrs.len())
        };
        t.entity(Entity {
            id: tcp::server_entity(remote),
            role: EntityRole::Server,
            label: r.host.clone().unwrap_or_else(|| ip.to_string()),
            addresses: vec![Fact::observed(*ip, "address passed to connect(2)")],
            location: None,
            evidence: Evidence::Observed,
        });
        let (ev, s) = tcp::connect(clock, remote, choice, &conn).await;
        if let Payload::TcpConnect(d) = &ev.payload {
            rtt = d.rtt_estimate_ms.as_ref().map(|f| f.value);
        }
        t.events.push(ev);
        if let Some(s) = s {
            stream = Some((s, remote));
            break;
        }
    }
    let Some((stream, remote)) = stream else {
        return fail(r, "Could not open a TCP connection".into());
    };

    // 4. TLS, on that same stream. Only for https.
    let transport = if target.https {
        let (ev, session) = tls::handshake(clock, stream, &target.host, remote, &conn).await;
        if let Some(err) = &ev.error {
            r.failure = Some(format!("TLS handshake failed: {} ({})", err.value.code, err.value.message));
        }
        t.events.push(ev);
        session.map(Transport::Tls)
    } else {
        Ok(Transport::Plain(stream))
    };

    // 5. HTTP/1.1 inside it.
    let stream = match transport {
        Ok(mut tr) => {
            let exchange = http1::get(
                clock,
                &mut tr,
                http1::Request {
                    host_header: &target.host_header,
                    target: &target.request_target,
                    conn_id: &conn,
                    server_entity: tcp::server_entity(remote),
                    rtt_ms: rtt,
                },
            )
            .await;
            t.events.extend(exchange.events);
            r.status = exchange.status;
            r.location = exchange.location;
            if let Some(e) = exchange.error {
                r.failure = Some(e);
            }
            tr.into_tcp(clock).await
        }
        Err(tcp) => tcp,
    };

    // 6. Graceful close.
    t.events.push(tcp::close(clock, stream, remote, &conn).await);

    if r.failure.is_none() && r.status.is_none() {
        r.failure = Some("no HTTP response".into());
    }
    r.target = Some(target);
    r
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Record the redirect decision. Returns the next URL, or None if the
/// Location can't be used.
fn redirect(clock: &Clock, status: u16, location: &str, base: &::url::Url, hop: u32, t: &mut Collector) -> Option<String> {
    let next = base.join(location).ok()?;
    if !matches!(next.scheme(), "http" | "https") {
        return None;
    }
    let from_location = "derive: Location resolved against the current URL (RFC 3986 §5)";
    let at = clock.now();
    let mut ev = event(
        Some(ProtocolId::Http1),
        Span { start: at, end: None },
        Payload::HttpRedirect(HttpRedirectData {
            status: Fact::observed(status, "response status line"),
            location: Fact::observed(location.to_string(), "Location header"),
            next_url: Fact::derived(next.to_string(), from_location),
            cross_origin: Fact::derived(next.origin() != base.origin(), "derive: compare scheme, host and port"),
            preserves_method: Fact::derived(matches!(status, 307 | 308), "derive: RFC 9110 §15.4 status semantics"),
            permanent: Fact::derived(matches!(status, 301 | 308), "derive: RFC 9110 §15.4 status semantics"),
        }),
    );
    ev.hop_index = hop;
    ev.explain_key = Some(format!("http.redirect.{status}"));
    t.events.push(ev);
    Some(next.to_string())
}

/// A new event with the defaults every phase starts from. `id` is assigned
/// once all events are collected and sorted.
fn event(protocol: Option<ProtocolId>, time: Span, payload: Payload) -> TraceEvent {
    TraceEvent {
        id: String::new(),
        hop_index: 0,
        connection_id: None,
        parent_id: None,
        protocol,
        evidence: Evidence::Observed,
        time,
        from: None,
        to: None,
        status: Status::Ok,
        error: None,
        explain_key: None,
        payload,
    }
}
