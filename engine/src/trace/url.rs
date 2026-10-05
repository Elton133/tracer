use url::{Host, Url};

use crate::model::{Fact, HostKind, Payload, Span, TraceEvent, UrlParseData};

use super::event;

const PARSER: &str = "WHATWG URL parsing (url crate)";

pub struct Target {
    pub url: Url,
    pub https: bool,
    pub host: Host<String>,
    pub port: u16,
    /// Path + query: what goes on the HTTP request line.
    pub request_target: String,
    /// Value for the Host header. The port is included only when it isn't the default.
    pub host_header: String,
}

/// Step 1: no network yet. Just turn the text into a host and port.
///
/// The parser lowercases the host and converts international names to
/// punycode ("münchen.de" → "xn--mnchen-3ya.de"), because DNS only carries ASCII.
pub fn parse(input: &str, at: f64) -> Result<(Target, TraceEvent), String> {
    let url = Url::parse(input).map_err(|e| format!("not a valid URL: {e}"))?;
    let scheme = url.scheme().to_string();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme '{scheme}': only http and https can be traced"));
    }
    let host = url.host().ok_or("URL has no host")?.to_owned();
    let host_kind = match host {
        Host::Domain(_) => HostKind::Domain,
        Host::Ipv4(_) => HostKind::Ipv4,
        Host::Ipv6(_) => HostKind::Ipv6,
    };

    let port = match url.port() {
        Some(p) => Fact::derived(p, PARSER),
        None => Fact::derived(
            url.port_or_known_default().expect("http/https have default ports"),
            format!("derive: default port for {scheme}"),
        ),
    };

    let host_str = match &host {
        Host::Domain(d) => d.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };

    let request_target = url[url::Position::BeforePath..url::Position::AfterQuery].to_string();
    let host_header = match url.port() {
        Some(p) => format!("{host_str}:{p}"), // the url crate drops default ports, so this is non-default
        None => host_str.clone(),
    };
    let host_header = match host { Host::Ipv6(_) => host_header.replacen(&host_str, &format!("[{host_str}]"), 1), _ => host_header };

    let data = UrlParseData {
        input: Fact::observed(input.to_string(), "user input"),
        scheme: Fact::derived(scheme, PARSER),
        host: Fact::derived(host_str, PARSER),
        host_kind: Fact::derived(host_kind, PARSER),
        port: port.clone(),
        path: Fact::derived(request_target.clone(), PARSER)
            .note("Path and query only. A #fragment is never sent to the server; it stays in the client."),
    };
    let ev = event(None, Span { start: at, end: None }, Payload::UrlParse(data));
    Ok((Target { url: url.clone(), https: url.scheme() == "https", port: port.value, host, request_target, host_header }, ev))
}
