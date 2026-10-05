use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{Evidence, Fact, ProtocolId};

/// One thing that happened during a trace.
///
/// `evidence` covers the event's *existence and timing*. Each field inside
/// `data` carries its own evidence, because one event can mix an observed
/// duration with a derived estimate.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TraceEvent {
    pub id: String,
    /// Which request in a redirect chain (0 for the first).
    pub hop_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub parent_id: Option<String>,
    /// Drives OSI / TCP-IP placement via `protocol::info`. Absent for local
    /// steps that never touch the network (e.g. parsing the URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub protocol: Option<ProtocolId>,
    pub evidence: Evidence,
    pub time: Span,
    /// Entity ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub to: Option<String>,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error: Option<Fact<ErrorInfo>>,
    /// Key into the UI content library for explained overlays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub explain_key: Option<String>,
    #[serde(flatten)]
    pub payload: Payload,
}

/// Milliseconds since trace start, from a monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Span {
    pub start: f64,
    /// Absent for instantaneous events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub end: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum Status {
    Ok,
    Error,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ErrorInfo {
    /// Stable machine code, e.g. "ENOTFOUND", "NXDOMAIN", "ETIMEDOUT".
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Endpoint {
    pub address: std::net::IpAddr,
    pub port: u16,
}

impl From<std::net::SocketAddr> for Endpoint {
    fn from(sa: std::net::SocketAddr) -> Self {
        Self { address: sa.ip(), port: sa.port() }
    }
}

/// Per-kind data. The variant set grows as each engine phase is built,
/// so nothing here describes a measurement we don't actually take yet.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "data")]
#[ts(export)]
pub enum Payload {
    #[serde(rename = "url.parse")]
    UrlParse(UrlParseData),
    /// The operating system's resolver path (getaddrinfo), which is what
    /// applications normally use.
    #[serde(rename = "dns.lookup")]
    DnsLookup(DnsLookupData),
    /// A DNS message Packet built and sent itself over UDP.
    #[serde(rename = "dns.query")]
    DnsQuery(DnsQueryData),
    /// One attempt to open a TCP connection (SYN → SYN-ACK → ACK, done by the kernel).
    #[serde(rename = "tcp.connect")]
    TcpConnect(TcpConnectData),
    /// Our FIN until the server's FIN arrives.
    #[serde(rename = "tcp.close")]
    TcpClose(TcpCloseData),
    /// From our ClientHello until the handshake completes (or fails).
    #[serde(rename = "tls.handshake")]
    TlsHandshake(TlsHandshakeData),
    /// Writing the request into the connection.
    #[serde(rename = "http.request")]
    HttpRequest(HttpRequestData),
    /// From request sent until the full response head (status line + headers) arrived.
    #[serde(rename = "http.response")]
    HttpResponse(HttpResponseData),
    /// From end of head until the body is complete, as determined by its framing.
    #[serde(rename = "http.body")]
    HttpBody(HttpBodyData),
    /// The decision to follow a 3xx response to a new URL (the next hop).
    #[serde(rename = "http.redirect")]
    HttpRedirect(HttpRedirectData),
    /// Packet's own safety check on the resolved addresses, before connecting.
    #[serde(rename = "guard.check")]
    GuardCheck(GuardCheckData),
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct GuardCheckData {
    pub policy: Fact<String>,
    pub verdicts: Fact<Vec<GuardVerdict>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct GuardVerdict {
    pub address: std::net::IpAddr,
    pub allowed: bool,
    /// What kind of address it is, if it's not an ordinary public one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct HttpRedirectData {
    pub status: Fact<u16>,
    /// The Location header exactly as sent. It may be relative ("/login").
    pub location: Fact<String>,
    /// Location resolved against the current URL.
    pub next_url: Fact<String>,
    /// Different scheme, host or port: a new origin, so a new connection is unavoidable.
    pub cross_origin: Fact<bool>,
    /// 307/308 require the same method and body. 301/302/303 let (or make) clients switch to GET.
    pub preserves_method: Fact<bool>,
    /// Permanent (301/308): clients and caches may remember it.
    pub permanent: Fact<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct HttpRequestData {
    pub method: Fact<String>,
    pub target: Fact<String>,
    pub version: Fact<String>,
    /// Exactly what we sent, in order.
    pub headers: Fact<Vec<Header>>,
    /// The literal bytes of the request head, CRLFs included.
    pub raw_head: Fact<String>,
    pub head_bytes: Fact<u32>,
    /// What the request looked like on the wire: TLS records, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tls_records: Option<Fact<Vec<TlsRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct HttpResponseData {
    /// Request sent → first byte of the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ttfb_ms: Option<Fact<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub server_time_estimate_ms: Option<Fact<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub version: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub status: Option<Fact<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reason: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub headers: Option<Fact<Vec<Header>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub head_bytes: Option<Fact<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tls_records: Option<Fact<Vec<TlsRecord>>>,
    /// Which CDN data center says it answered, if the headers tell us.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub edge: Option<EdgeLocation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    /// "Lisbon, PT"
    pub place: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EdgeLocation {
    pub provider: Fact<String>,
    /// Airport-style site code, e.g. "LIS".
    pub code: Fact<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub point: Option<Fact<GeoPoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct HttpBodyData {
    /// How the end of the body was determined: "content-length", "chunked", "until-close", "none".
    pub framing: Fact<String>,
    /// Body payload, with chunk framing removed. Still compressed if Content-Encoding is set.
    pub body_bytes: Fact<u32>,
    /// Bytes after the head, framing included.
    pub wire_bytes: Fact<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub chunks: Option<Fact<u32>>,
    pub truncated: Fact<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tls_records: Option<Fact<Vec<TlsRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TlsHandshakeData {
    /// Server Name Indication: the hostname we sent in the ClientHello, in
    /// cleartext. Absent for IP-literal URLs (RFC 6066 forbids IPs in SNI).
    pub sni: Fact<Option<String>>,
    pub alpn_offered: Fact<Vec<String>>,
    pub trust_store: Fact<String>,
    /// Every TLS record that crossed the socket during the handshake, both directions.
    pub records: Fact<Vec<TlsRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub round_trips: Option<Fact<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub version: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub cipher_suite: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub key_exchange: Option<Fact<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub alpn: Option<Fact<Option<String>>>,
    /// Leaf first, as the server sent it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub chain: Option<Fact<Vec<CertSummary>>>,
    /// "valid", or the reason the chain was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub verification: Option<Fact<String>>,
}

/// One TLS record, read from its 5-byte header: type(1) version(2) length(2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TlsRecord {
    /// When we wrote or read the bytes containing it (userland time).
    pub at_ms: f64,
    pub direction: Direction,
    /// handshake, change_cipher_spec, alert, application_data
    pub content_type: String,
    /// The record-layer version field. TLS 1.3 deliberately says "TLS 1.2"
    /// here so old middleboxes don't choke.
    pub record_version: String,
    /// Payload length, excluding the 5-byte header.
    pub length: u16,
    /// Handshake messages inside, readable only while the record is unencrypted.
    pub messages: Vec<String>,
    /// The payload is ciphertext. Nobody on the path can read it, and neither
    /// can this byte-level tap.
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before_unix: f64,
    pub not_after_unix: f64,
    /// Subject Alternative Names: the hostnames this certificate is valid for.
    pub san: Vec<String>,
    pub public_key: String,
    pub signature_algorithm: String,
    pub is_ca: bool,
    pub sha256: String,
    pub der_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TcpConnectData {
    pub remote: Fact<Endpoint>,
    /// Why this address was tried.
    pub address_choice: Fact<String>,
    /// Our side. Pre-NAT: the server sees your router's public address instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub local: Option<Fact<Endpoint>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rtt_estimate_ms: Option<Fact<f64>>,
    /// Nagle's algorithm disabled? Affects how soon small writes leave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub nodelay: Option<Fact<bool>>,
    /// Kernel state right after the handshake completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub kernel: Option<Fact<TcpKernelInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TcpCloseData {
    pub initiated_by: Fact<String>,
    /// Did the server answer our FIN with its own (read() returned 0)?
    pub peer_closed: Fact<bool>,
    /// Kernel state after the exchange. The side that closes first ends in TIME_WAIT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub kernel: Option<Fact<TcpKernelInfo>>,
}

/// A snapshot of the kernel's TCP control block for one socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TcpKernelInfo {
    /// RFC 793 state, e.g. ESTABLISHED, TIME_WAIT.
    pub state: String,
    /// Smoothed RTT: the kernel's running average (RFC 6298).
    pub srtt_ms: u32,
    pub rttvar_ms: u32,
    pub rtt_latest_ms: u32,
    /// How long the kernel waits for an ACK before retransmitting.
    pub rto_ms: u32,
    /// Maximum segment size: the largest TCP payload per packet.
    pub mss: u32,
    /// Congestion window: how much we may have in flight before an ACK.
    pub cwnd_bytes: u32,
    pub ssthresh_bytes: u32,
    /// The server's advertised receive window (flow control).
    pub send_window_bytes: u32,
    /// The receive window we advertised.
    pub recv_window_bytes: u32,
    pub send_window_scale: u8,
    pub recv_window_scale: u8,
    pub options: TcpOptions,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub bytes_sent: u32,
    pub bytes_received: u32,
    pub retransmitted_packets: u32,
    pub retransmitted_bytes: u32,
    pub out_of_order_bytes: u32,
}

/// TCP options negotiated in the SYN / SYN-ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct TcpOptions {
    pub timestamps: bool,
    pub sack: bool,
    pub window_scaling: bool,
    pub ecn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct UrlParseData {
    pub input: Fact<String>,
    pub scheme: Fact<String>,
    /// Hostname as the URL parser normalised it (lowercased, IDN → punycode).
    pub host: Fact<String>,
    pub host_kind: Fact<HostKind>,
    pub port: Fact<u16>,
    pub path: Fact<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum HostKind {
    Domain,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DnsLookupData {
    pub hostname: Fact<String>,
    /// In the order getaddrinfo returned them. Applications usually try the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub addresses: Option<Fact<Vec<std::net::IpAddr>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DnsQueryData {
    pub record_type: Fact<String>,
    /// The fully qualified name actually put on the wire (note the trailing dot).
    pub qname: Fact<String>,
    pub server: Fact<Endpoint>,
    /// Our side of the UDP exchange. The source port is randomised by the OS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub local: Option<Fact<Endpoint>>,
    /// 16-bit message ID. The reply must echo it.
    pub message_id: Fact<u16>,
    pub query_bytes: Fact<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub response: Option<DnsResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DnsResponseData {
    pub bytes: Fact<u32>,
    /// "NoError", "NXDomain", "ServFail", …
    pub rcode: Fact<String>,
    pub flags: Fact<DnsFlags>,
    pub answers: Fact<Vec<DnsRecord>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DnsFlags {
    /// AA: the responder is authoritative for the name.
    pub authoritative: bool,
    /// TC: the answer didn't fit and was cut off. Retry over TCP.
    pub truncated: bool,
    /// RD: echoed from our query.
    pub recursion_desired: bool,
    /// RA: the server offers recursion (it's a recursive resolver).
    pub recursion_available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    /// Seconds a cache may keep this record. Counts down at caching resolvers.
    pub ttl: u32,
    pub value: String,
}
