//! Traceroute, done by hand with ICMP Echo and a rising TTL.
//!
//! Every IP packet carries a TTL (IPv6: hop limit). Each router decrements
//! it, and the router that brings it to zero drops the packet and sends back
//! ICMP "Time Exceeded" *from its own address*. Send probes with TTL 1, 2,
//! 3, … and the routers reveal themselves one by one. When a probe gets
//! all the way, the target itself answers with an Echo Reply.
//!
//! macOS lets unprivileged programs open an ICMP *datagram* socket (it's how
//! `ping` works without root), and delivers the Time Exceeded replies for
//! our own probes to it. The system `traceroute` binary is setuid root
//! because it uses raw sockets instead.
//!
//! What this can't tell you:
//! - Routers that don't answer (or rate-limit ICMP) show as silent hops.
//! - Each probe measures a round trip. The return path may differ from the
//!   way out (asymmetric routing), and is invisible.
//! - Routers answer ICMP on a slow path, so a hop can look slower than the
//!   hops after it. That's the router, not the network.
//! - ICMP may be load-balanced differently from TCP, so this is *a* path to
//!   the server, not necessarily the one the HTTPS connection used.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout_at;

use crate::geo::Geo;
use crate::model::*;

use super::{Clock, guard};

const MAX_TTL: u8 = 30;
const ROUNDS: u8 = 3;
/// How long to keep listening after a round's last probe.
const ROUND_WAIT: Duration = Duration::from_millis(1500);
/// Spacing between probes, so routers' ICMP rate limits aren't all hit at once.
const GAP: Duration = Duration::from_millis(4);
const PAYLOAD: &[u8] = b"packet traceroute probe";

pub async fn trace_path(target: IpAddr, geo: Option<&Geo>, vantage: Vantage) -> PathTrace {
    let clock = Clock::start();
    let started = Instant::now();
    let method = Fact::observed(
        format!("ICMP{} Echo, TTL 1–{MAX_TTL}, {ROUNDS} rounds", if target.is_ipv6() { "v6" } else { "" }),
        "engine method",
    )
    .note("Shows the path ICMP takes to this address. TCP packets usually, but not always, take the same one.");

    let mut out = PathTrace {
        schema_version: SCHEMA_VERSION,
        id: format!("{:016x}", getrandom::u64().unwrap_or(0)),
        target,
        method,
        vantage,
        started_at_unix_ms: clock.started_at_unix_ms,
        duration_ms: 0.0,
        hops: vec![],
        reached: Fact::observed(false, "an Echo Reply from the target"),
        error: None,
    };

    let probes = match run(target).await {
        Ok(p) => p,
        Err(e) => {
            out.error = Some(Fact::observed(ErrorInfo { code: "SOCKET".into(), message: e.to_string() }, "ICMP socket"));
            return out;
        }
    };
    out.duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    // Stop the hop list at the target: probes with a bigger TTL just reach it again.
    let last = probes
        .iter()
        .filter(|(_, ps)| ps.iter().any(|p| p.reply.as_deref() == Some("echo-reply")))
        .map(|(ttl, _)| *ttl)
        .min();
    out.reached.value = last.is_some();
    let last = last.unwrap_or_else(|| probes.keys().copied().filter(|t| probes[t].iter().any(|p| p.from.is_some())).max().unwrap_or(0));

    for (ttl, ps) in probes.into_iter().filter(|(t, _)| *t <= last) {
        let mut responders: Vec<Responder> = Vec::new();
        for p in &ps {
            let Some(addr) = p.from else { continue };
            let fastest = ps.iter().filter(|q| q.from == Some(addr)).filter_map(|q| q.rtt_ms).fold(f64::INFINITY, f64::min);
            if responders.iter().any(|r| r.address == addr) {
                continue;
            }
            responders.push(Responder {
                address: addr,
                class: guard::classify(addr).map(|c| Fact::derived(c.to_string(), "derive: IANA special-purpose address ranges")),
                location: geo.and_then(|g| g.locate(addr)),
                max_km: fastest.is_finite().then(|| {
                    Fact::derived(fastest / 2.0 * 200.0, "derive: ½ fastest RTT × 200 km/ms (light in fibre)")
                        .note("Includes the router's own reply delay, so the true distance is smaller still.")
                }),
            });
        }
        out.hops.push(PathHop {
            ttl,
            probes: Fact::observed(ps, "ICMP replies to our probes (source address, type, round trip)"),
            responders,
        });
    }
    out
}

struct Sent {
    ttl: u8,
    round: u8,
    at: Instant,
}

async fn run(target: IpAddr) -> std::io::Result<BTreeMap<u8, Vec<Probe>>> {
    let v6 = target.is_ipv6();
    let sock = Socket::new(
        if v6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(if v6 { Protocol::ICMPV6 } else { Protocol::ICMPV4 }),
    )?;
    sock.set_nonblocking(true)?;
    let sock = UdpSocket::from_std(std::net::UdpSocket::from(sock))?;
    let dest = SocketAddr::new(target, 0);
    let id: u16 = getrandom::u32().map(|v| v as u16).unwrap_or(0x5054);

    // Replies are read by their own task, concurrently with sending, and
    // timestamped the moment they arrive. Reading them only after a round's
    // probes are all sent would add the sending time to every RTT.
    let sock = Arc::new(sock);
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, IpAddr, &'static str, u16, u16)>();
    let reader = {
        let sock = sock.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let at = Instant::now();
                if let Some((kind, rid, seq)) = if v6 { parse_v6(&buf[..n]) } else { parse_v4(&buf[..n]) } {
                    if tx.send((at, from.ip(), kind, rid, seq)).is_err() {
                        break;
                    }
                }
            }
        })
    };

    let mut sent: HashMap<u16, Sent> = HashMap::new();
    let mut got: BTreeMap<u8, Vec<Probe>> = BTreeMap::new();
    let mut target_ttl: Option<u8> = None;

    for round in 0..ROUNDS {
        let top = target_ttl.unwrap_or(MAX_TTL);
        for ttl in 1..=top {
            let r = SockRef::from(&*sock);
            if v6 { r.set_unicast_hops_v6(ttl as u32)? } else { r.set_ttl_v4(ttl as u32)? }
            let seq = (round as u16) << 8 | ttl as u16;
            // Recorded before the send call, so the RTT can only be slightly long, never short.
            sent.insert(seq, Sent { ttl, round, at: Instant::now() });
            sock.send_to(&echo_request(v6, id, seq), dest).await?;
            tokio::time::sleep(GAP).await;
        }
        let deadline = tokio::time::Instant::now() + ROUND_WAIT;
        while let Ok(Some((at, from, kind, rid, seq))) = timeout_at(deadline, rx.recv()).await {
            // The ID marks our probes. Other ICMP traffic on the machine can reach this socket too.
            if rid != id && cfg!(target_os = "macos") {
                continue;
            }
            let Some(s) = sent.remove(&seq) else { continue };
            if kind == "echo-reply" && from == target {
                target_ttl = Some(target_ttl.map_or(s.ttl, |t| t.min(s.ttl)));
            }
            got.entry(s.ttl).or_default().push(Probe {
                round: s.round,
                rtt_ms: Some(at.duration_since(s.at).as_secs_f64() * 1000.0),
                from: Some(from),
                reply: Some(kind.into()),
            });
        }
    }
    reader.abort();
    // Whatever is still unanswered timed out.
    for s in sent.into_values() {
        got.entry(s.ttl).or_default().push(Probe { round: s.round, rtt_ms: None, from: None, reply: None });
    }
    for ps in got.values_mut() {
        ps.sort_by_key(|p| p.round);
    }
    Ok(got)
}

/// ICMP Echo Request: type, code, checksum, identifier, sequence, payload.
fn echo_request(v6: bool, id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(PAYLOAD);
    if !v6 {
        // ICMPv6 checksums cover an IPv6 pseudo-header; the kernel fills those in.
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
    }
    p
}

/// The Internet checksum (RFC 1071): one's-complement sum of 16-bit words.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn id_seq(icmp: &[u8]) -> Option<(u16, u16)> {
    Some((u16::from_be_bytes([*icmp.get(4)?, *icmp.get(5)?]), u16::from_be_bytes([*icmp.get(6)?, *icmp.get(7)?])))
}

/// macOS hands ICMPv4 datagram sockets the whole IP packet; Linux strips the header.
fn parse_v4(data: &[u8]) -> Option<(&'static str, u16, u16)> {
    let icmp = if data.first()? >> 4 == 4 { data.get(((data[0] & 0x0f) as usize) * 4..)? } else { data };
    match *icmp.first()? {
        0 => id_seq(icmp).map(|(i, s)| ("echo-reply", i, s)),
        t @ (3 | 11) => {
            // The error quotes the start of our dropped packet: its IP header, then our ICMP header.
            let inner = icmp.get(8..)?;
            let inner_icmp = inner.get(((inner.first()? & 0x0f) as usize) * 4..)?;
            (*inner_icmp.first()? == 8).then(|| id_seq(inner_icmp)).flatten().map(|(i, s)| (if t == 11 { "time-exceeded" } else { "unreachable" }, i, s))
        }
        _ => None,
    }
}

/// IPv6 sockets never include the IPv6 header.
fn parse_v6(icmp: &[u8]) -> Option<(&'static str, u16, u16)> {
    match *icmp.first()? {
        129 => id_seq(icmp).map(|(i, s)| ("echo-reply", i, s)),
        t @ (1 | 3) => {
            // Quoted packet: the 40-byte IPv6 header, then our ICMPv6 header.
            let inner_icmp = icmp.get(8 + 40..)?;
            (*inner_icmp.first()? == 128).then(|| id_seq(inner_icmp)).flatten().map(|(i, s)| (if t == 3 { "time-exceeded" } else { "unreachable" }, i, s))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_rfc_1071_example() {
        // RFC 1071 §3: 0001 f203 f4f5 f6f7 sums to 0xddf2, complement 0x220d.
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn echo_request_checksum_verifies_to_zero() {
        // A correct checksum makes the whole message sum to 0xffff (complement 0).
        assert_eq!(checksum(&echo_request(false, 0x1234, 0x0105)), 0);
    }

    #[test]
    fn parses_time_exceeded_quoting_our_probe() {
        let probe = echo_request(false, 0xabcd, 0x0207);
        // Outer IPv4 header (20 B) + ICMP Time Exceeded (8 B) + quoted IPv4 header (20 B) + our first 8 bytes.
        let mut pkt = vec![0x45; 1];
        pkt.extend([0u8; 19]);
        pkt.extend([11, 0, 0, 0, 0, 0, 0, 0]);
        pkt.push(0x45);
        pkt.extend([0u8; 19]);
        pkt.extend(&probe[..8]);
        assert_eq!(parse_v4(&pkt), Some(("time-exceeded", 0xabcd, 0x0207)));
    }

    #[test]
    fn parses_v6_echo_reply() {
        let mut reply = echo_request(true, 7, 9);
        reply[0] = 129;
        assert_eq!(parse_v6(&reply), Some(("echo-reply", 7, 9)));
    }
}
