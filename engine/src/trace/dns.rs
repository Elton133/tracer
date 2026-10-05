//! DNS, two ways. They answer different questions.
//!
//! 1. `os_lookup`: ask the operating system, exactly as curl or a browser
//!    would. That's `getaddrinfo(3)`, which on macOS hands the question to
//!    `mDNSResponder` (it has a cache, /etc/hosts, per-interface resolvers,
//!    VPN rules). Fast and realistic, but opaque: we get addresses back and
//!    nothing about *how*.
//!
//! 2. `query`: build a DNS message ourselves, send it as one UDP datagram to
//!    a resolver on port 53, and decode the reply. Slower to explain, but
//!    every header bit, TTL and byte count is genuinely observed, because we
//!    are the client on the wire.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::model::*;

use super::{Clock, event};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn os_lookup(clock: &Clock, host: &str, port: u16) -> (TraceEvent, Option<Vec<IpAddr>>) {
    let start = clock.now();
    // tokio runs the blocking getaddrinfo call on a worker thread.
    let result = timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port))).await;
    let end = clock.now();

    let mut ev = event(
        Some(ProtocolId::Dns),
        Span { start, end: Some(end) },
        Payload::DnsLookup(DnsLookupData {
            hostname: Fact::observed(host.to_string(), "argument to getaddrinfo(3)"),
            addresses: None,
        }),
    );
    ev.from = Some(entity::APP.into());
    ev.to = Some(entity::OS_RESOLVER.into());
    ev.explain_key = Some("dns.os-resolver".into());

    let addrs = match result {
        Ok(Ok(iter)) => {
            let mut ips: Vec<IpAddr> = Vec::new();
            for sa in iter {
                if !ips.contains(&sa.ip()) {
                    ips.push(sa.ip());
                }
            }
            ips
        }
        Ok(Err(e)) => {
            ev.status = Status::Error;
            ev.error = Some(Fact::observed(
                ErrorInfo { code: "LOOKUP_FAILED".into(), message: e.to_string() },
                "getaddrinfo(3) error",
            ));
            return (ev, None);
        }
        Err(_) => {
            ev.status = Status::Timeout;
            ev.error = Some(Fact::observed(
                ErrorInfo { code: "ETIMEDOUT".into(), message: format!("no answer within {LOOKUP_TIMEOUT:?}") },
                "engine timeout",
            ));
            return (ev, None);
        }
    };

    if let Payload::DnsLookup(d) = &mut ev.payload {
        d.addresses = Some(
            Fact::observed(addrs.clone(), "getaddrinfo(3) result, in returned order")
                .note("The OS may have answered from its cache, so this duration can be near zero."),
        );
    }
    (ev, Some(addrs))
}

/// Where to send our own queries.
pub enum ServerChoice {
    UserSpecified(IpAddr),
    ResolvConf(IpAddr),
}

impl ServerChoice {
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::UserSpecified(ip) | Self::ResolvConf(ip) => *ip,
        }
    }

    fn source(&self) -> &'static str {
        match self {
            Self::UserSpecified(_) => "user-specified --dns",
            Self::ResolvConf(_) => "/etc/resolv.conf: first nameserver",
        }
    }
}

/// First `nameserver` line of /etc/resolv.conf.
///
/// On macOS this file is generated for compatibility and isn't what
/// `getaddrinfo` actually consults (`scutil --dns` shows the real config).
/// They usually agree, but with a VPN they can differ, which is why the two
/// DNS paths are recorded separately.
pub fn system_nameserver() -> Option<ServerChoice> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|rest| rest.trim().parse().ok())
        .map(ServerChoice::ResolvConf)
}

pub async fn query(clock: &Clock, server: &ServerChoice, host: &str, rtype: RecordType) -> TraceEvent {
    let server_addr = SocketAddr::new(server.ip(), 53);

    // A fully qualified name ends in "." (the root of the DNS tree).
    let qname = format!("{host}.");
    let mut msg = Message::query(); // random 16-bit ID
    msg.metadata.recursion_desired = true; // "please resolve this fully for me"
    msg.add_query(Query::query(Name::from_ascii(&qname).expect("host is ASCII after URL parsing"), rtype));
    let wire = msg.to_vec().expect("query encodes");

    let mut data = DnsQueryData {
        record_type: Fact::observed(rtype.to_string(), "question section we sent"),
        qname: Fact::observed(qname, "question section we sent"),
        server: Fact::observed(server_addr.into(), server.source()),
        local: None,
        message_id: Fact::observed(msg.metadata.id, "header we sent"),
        query_bytes: Fact::observed(wire.len() as u32, "UDP payload we sent")
            .note("DNS message only. UDP adds 8 header bytes, IP adds 20 (v4) or 40 (v6)."),
        response: None,
    };

    let start = clock.now();
    let result = exchange(server_addr, &wire, msg.metadata.id).await;
    let end = clock.now();

    let mut status = Status::Ok;
    let mut error = None;
    match result {
        Ok((local, reply, n)) => {
            data.local = Some(Fact::observed(local.into(), "getsockname(2) on our UDP socket"));
            let m = &reply.metadata;
            if m.response_code != ResponseCode::NoError {
                status = Status::Error;
                error = Some(Fact::observed(
                    ErrorInfo { code: rcode_name(m.response_code), message: m.response_code.to_string() },
                    "dns response header: RCODE",
                ));
            }
            data.response = Some(DnsResponseData {
                bytes: Fact::observed(n as u32, "UDP payload received"),
                rcode: Fact::observed(rcode_name(m.response_code), "dns response header: RCODE"),
                flags: Fact::observed(
                    DnsFlags {
                        authoritative: m.authoritative,
                        truncated: m.truncation,
                        recursion_desired: m.recursion_desired,
                        recursion_available: m.recursion_available,
                    },
                    "dns response header: AA/TC/RD/RA bits",
                ),
                answers: Fact::observed(
                    reply
                        .answers
                        .iter()
                        .map(|r| DnsRecord {
                            name: r.name.to_string(),
                            record_type: r.record_type().to_string(),
                            ttl: r.ttl,
                            value: r.data.to_string(),
                        })
                        .collect(),
                    "dns response: answer section",
                ),
            });
        }
        Err(Failure::Timeout) => {
            status = Status::Timeout;
            error = Some(Fact::observed(
                ErrorInfo { code: "ETIMEDOUT".into(), message: format!("no reply within {QUERY_TIMEOUT:?}") },
                "engine timeout",
            ));
        }
        Err(Failure::Io(e)) => {
            status = Status::Error;
            error = Some(Fact::observed(ErrorInfo { code: "IO".into(), message: e }, "socket error"));
        }
    }

    let mut ev = event(Some(ProtocolId::Dns), Span { start, end: Some(end) }, Payload::DnsQuery(data));
    ev.status = status;
    ev.error = error;
    ev.from = Some(entity::APP.into());
    ev.to = Some(entity::dns_server(server.ip()));
    ev.explain_key = Some("dns.query".into());
    ev
}

enum Failure {
    Timeout,
    Io(String),
}

/// One UDP round trip. UDP has no connection and no delivery guarantee: if
/// the datagram or its reply is lost, nothing tells us. We just stop waiting.
async fn exchange(server: SocketAddr, wire: &[u8], id: u16) -> Result<(SocketAddr, Message, usize), Failure> {
    let io = |e: std::io::Error| Failure::Io(e.to_string());
    let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).await.map_err(io)?; // port 0 = let the OS pick a random one
    // "connect" on UDP sends nothing. It fixes the peer, so the kernel
    // discards datagrams from anyone else (a cheap anti-spoofing filter).
    sock.connect(server).await.map_err(io)?;
    let local = sock.local_addr().map_err(io)?;
    sock.send(wire).await.map_err(io)?;

    // Without EDNS, a classic DNS-over-UDP reply is at most 512 bytes. Bigger
    // answers arrive with TC=1 and the client is expected to retry over TCP.
    let mut buf = [0u8; 4096];
    let recv = async {
        loop {
            let n = sock.recv(&mut buf).await.map_err(io)?;
            match Message::from_vec(&buf[..n]) {
                // The ID must match ours. Otherwise it's a stale or forged reply.
                Ok(m) if m.metadata.id == id => return Ok((m, n)),
                _ => continue,
            }
        }
    };
    let (reply, n) = timeout(QUERY_TIMEOUT, recv).await.map_err(|_| Failure::Timeout)??;
    Ok((local, reply, n))
}

fn rcode_name(rc: ResponseCode) -> String {
    format!("{rc:?}")
}

pub mod entity {
    pub const APP: &str = "app";
    pub const OS_RESOLVER: &str = "os-resolver";
    pub fn dns_server(ip: std::net::IpAddr) -> String {
        format!("dns:{ip}")
    }
}
