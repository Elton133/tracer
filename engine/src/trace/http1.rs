//! HTTP/1.1 (RFC 9112), written by hand over a `Transport`.
//!
//! HTTP/1.1 is text framed by CRLFs:
//!
//!   GET /path HTTP/1.1\r\n          request line
//!   Host: example.com\r\n           headers
//!   \r\n                            blank line = end of head
//!
//! The response has the same shape, then a body. Because the connection
//! stays open (keep-alive is the HTTP/1.1 default), nothing on the wire
//! says "the response is over". The client must work it out from the
//! framing rules (RFC 9112 §6.3), implemented in `framing` below.

use std::time::Duration;

use tokio::time::timeout;

use crate::model::*;

use super::transport::Transport;
use super::{Clock, event};

const USER_AGENT: &str = concat!("packet/", env!("CARGO_PKG_VERSION"));
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: u64 = 2 * 1024 * 1024;

pub struct Exchange {
    pub events: Vec<TraceEvent>,
    pub status: Option<u16>,
    pub location: Option<String>,
    pub error: Option<String>,
}

pub struct Request<'a> {
    pub host_header: &'a str,
    pub target: &'a str,
    pub conn_id: &'a str,
    pub server_entity: String,
    /// From the TCP handshake, used to estimate server time.
    pub rtt_ms: Option<f64>,
}

pub async fn get(clock: &Clock, t: &mut Transport, req: Request<'_>) -> Exchange {
    let mut events = Vec::new();
    let finish = |ev: &mut TraceEvent| {
        ev.connection_id = Some(req.conn_id.into());
        ev.from = Some(super::dns::entity::APP.into());
        ev.to = Some(req.server_entity.clone());
    };

    // ── 1. Request ──────────────────────────────────────────────────────
    // Roughly what `curl` sends, so its numbers stay comparable. No
    // Accept-Encoding, so the server sends the body uncompressed.
    let headers = vec![
        Header { name: "Host".into(), value: req.host_header.into() },
        Header { name: "User-Agent".into(), value: USER_AGENT.into() },
        Header { name: "Accept".into(), value: "*/*".into() },
    ];
    let mut head = format!("GET {} HTTP/1.1\r\n", req.target);
    for h in &headers {
        head.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    head.push_str("\r\n");

    let mark = t.record_mark();
    let start = clock.now();
    let sent = t.send(clock, head.as_bytes()).await;
    let sent_at = clock.now();

    let mut ev = event(
        Some(ProtocolId::Http1),
        Span { start, end: Some(sent_at) },
        Payload::HttpRequest(HttpRequestData {
            method: Fact::observed("GET".into(), "request line we sent"),
            target: Fact::observed(req.target.into(), "request line we sent"),
            version: Fact::observed("HTTP/1.1".into(), "request line we sent"),
            headers: Fact::observed(headers, "request headers we sent"),
            head_bytes: Fact::observed(head.len() as u32, "bytes we wrote"),
            raw_head: Fact::observed(head.clone(), "bytes we wrote"),
            tls_records: records(t, mark, "sent"),
        }),
    );
    ev.explain_key = Some("http.request".into());
    finish(&mut ev);
    if let Err(e) = sent {
        ev.status = Status::Error;
        ev.error = Some(Fact::observed(io_info(&e), "write(2) / TLS"));
        events.push(ev);
        return Exchange { events, status: None, location: None, error: Some(format!("could not send request: {e}")) };
    }
    events.push(ev);

    // ── 2. Response head ───────────────────────────────────────────────
    // Read until the blank line. The same read may also carry body bytes.
    let mark = t.record_mark();
    let mut buf: Vec<u8> = Vec::new();
    let mut first_byte_at = None;
    let head_result = timeout(HEAD_TIMEOUT, async {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = t.recv(clock, &mut chunk).await.map_err(|e| io_info(&e))?;
            if n == 0 {
                return Err(ErrorInfo { code: "EOF".into(), message: "connection closed before a response".into() });
            }
            first_byte_at.get_or_insert_with(|| clock.now());
            buf.extend_from_slice(&chunk[..n]);
            if let Some(parsed) = parse_head(&buf)? {
                return Ok(parsed);
            }
            if buf.len() > MAX_HEAD {
                return Err(ErrorInfo { code: "HEAD_TOO_LARGE".into(), message: format!("over {MAX_HEAD} bytes") });
            }
        }
    })
    .await;
    let head_at = clock.now();

    let mut data = HttpResponseData {
        ttfb_ms: first_byte_at.map(|f| {
            Fact::observed(f - sent_at, "request written → first response byte read")
                .note("Includes the trip to the server, its processing time, and the trip back.")
        }),
        server_time_estimate_ms: None,
        version: None,
        status: None,
        reason: None,
        headers: None,
        head_bytes: None,
        tls_records: None,
        edge: None,
    };
    let parsed = match head_result {
        Ok(Ok(p)) => Some(p),
        Ok(Err(info)) => {
            ev = response_event(data, sent_at, head_at, records(t, mark, "received"));
            ev.status = Status::Error;
            ev.error = Some(Fact::observed(info.clone(), "reading response"));
            finish(&mut ev);
            events.push(ev);
            return Exchange { events, status: None, location: None, error: Some(info.message) };
        }
        Err(_) => None,
    };
    let Some(head) = parsed else {
        ev = response_event(data, sent_at, head_at, records(t, mark, "received"));
        ev.status = Status::Timeout;
        ev.error = Some(Fact::observed(
            ErrorInfo { code: "ETIMEDOUT".into(), message: format!("no complete response head within {HEAD_TIMEOUT:?}") },
            "engine timeout",
        ));
        finish(&mut ev);
        events.push(ev);
        return Exchange { events, status: None, location: None, error: Some("response timed out".into()) };
    };

    let from_head = "response head we received";
    if let (Some(ttfb), Some(rtt)) = (&data.ttfb_ms, req.rtt_ms) {
        data.server_time_estimate_ms = Some(
            Fact::derived((ttfb.value - rtt).max(0.0), "derive: TTFB − TCP handshake RTT")
                .note("Rough. Assumes the network round trip hasn't changed since the handshake."),
        );
    }
    data.version = Some(Fact::observed(head.version.clone(), from_head));
    data.status = Some(Fact::observed(head.status, from_head));
    data.reason = Some(Fact::observed(head.reason.clone(), from_head));
    data.headers = Some(Fact::observed(head.headers.clone(), from_head));
    data.head_bytes = Some(Fact::observed(head.len as u32, from_head));
    let mut ev = response_event(data, sent_at, head_at, records(t, mark, "received"));
    finish(&mut ev);
    events.push(ev);

    // ── 3. Body ────────────────────────────────────────────────────────
    let mark = t.record_mark();
    let framing = framing::decide(head.status, &head.headers);
    let mut body = framing::Reader::new(framing);
    let leftover = buf.split_off(head.len);
    let body_result = timeout(BODY_TIMEOUT, async {
        body.feed(&leftover)?;
        let mut chunk = [0u8; 16 * 1024];
        while !body.done() && body.body_bytes < MAX_BODY {
            match t.recv(clock, &mut chunk).await {
                Ok(0) => return body.eof(),
                Ok(n) => body.feed(&chunk[..n])?,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return body.eof(),
                Err(e) => return Err(io_info(&e)),
            }
        }
        Ok(())
    })
    .await;
    let body_at = clock.now();

    let rule = "derive: RFC 9112 §6.3 message body length rules, applied to the response head";
    let mut ev = event(
        Some(ProtocolId::Http1),
        Span { start: head_at, end: Some(body_at) },
        Payload::HttpBody(HttpBodyData {
            framing: Fact::derived(framing.name().into(), rule),
            body_bytes: Fact::observed(body.body_bytes as u32, "body bytes read, framing removed"),
            wire_bytes: Fact::observed(body.wire_bytes as u32, "bytes read after the head"),
            chunks: (framing == framing::Framing::Chunked)
                .then(|| Fact::observed(body.chunks, "chunk-size lines read")),
            truncated: Fact::observed(!body.done(), "engine body cap / early end").note(format!(
                "Packet reads at most {} MB of body.",
                MAX_BODY / 1024 / 1024
            )),
            tls_records: records(t, mark, "received"),
        }),
    );
    ev.explain_key = Some(format!("http.framing.{}", framing.name()));
    finish(&mut ev);
    let mut error = None;
    match body_result {
        Ok(Ok(())) => {}
        Ok(Err(info)) => {
            ev.status = Status::Error;
            error = Some(info.message.clone());
            ev.error = Some(Fact::observed(info, "reading body"));
        }
        Err(_) => {
            ev.status = Status::Timeout;
            error = Some("body timed out".into());
            ev.error = Some(Fact::observed(
                ErrorInfo { code: "ETIMEDOUT".into(), message: format!("body not complete within {BODY_TIMEOUT:?}") },
                "engine timeout",
            ));
        }
    }
    events.push(ev);
    let location = head.headers.iter().find(|h| h.name.eq_ignore_ascii_case("location")).map(|h| h.value.clone());
    Exchange { events, status: Some(head.status), location, error }
}

fn response_event(data: HttpResponseData, start: f64, end: f64, recs: Option<Fact<Vec<TlsRecord>>>) -> TraceEvent {
    let mut data = data;
    data.tls_records = recs;
    let mut ev = event(Some(ProtocolId::Http1), Span { start, end: Some(end) }, Payload::HttpResponse(data));
    ev.explain_key = Some("http.response".into());
    ev
}

fn records(t: &Transport, mark: usize, what: &str) -> Option<Fact<Vec<TlsRecord>>> {
    t.records_since(mark).map(|r| {
        Fact::observed(r, "5-byte TLS record headers during this phase").note(format!(
            "Every record during this phase, both directions, not only the {what} HTTP bytes. TLS 1.3 session \
             tickets also arrive here, and on the wire they're indistinguishable from response data."
        ))
    })
}

struct Head {
    len: usize,
    version: String,
    status: u16,
    reason: String,
    headers: Vec<Header>,
}

fn parse_head(buf: &[u8]) -> Result<Option<Head>, ErrorInfo> {
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut res = httparse::Response::new(&mut slots);
    match res.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(len)) => Ok(Some(Head {
            len,
            version: format!("HTTP/1.{}", res.version.unwrap_or(1)),
            status: res.code.unwrap_or(0),
            reason: res.reason.unwrap_or("").to_string(),
            headers: res
                .headers
                .iter()
                .map(|h| Header { name: h.name.to_string(), value: String::from_utf8_lossy(h.value).into_owned() })
                .collect(),
        })),
        Err(e) => Err(ErrorInfo { code: "BAD_RESPONSE".into(), message: format!("unparseable response head: {e}") }),
    }
}

fn io_info(e: &std::io::Error) -> ErrorInfo {
    let code = match e.kind() {
        std::io::ErrorKind::ConnectionReset => "ECONNRESET",
        std::io::ErrorKind::UnexpectedEof => "EOF",
        std::io::ErrorKind::InvalidData => "TLS",
        _ => "IO",
    };
    ErrorInfo { code: code.into(), message: e.to_string() }
}

/// Where does the body end? RFC 9112 §6.3, simplified to what a GET needs.
pub mod framing {
    use crate::model::{ErrorInfo, Header};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Framing {
        /// 1xx, 204, 304: no body, whatever the headers say.
        None,
        /// Exactly this many bytes follow the head.
        Length(u64),
        /// A series of `<hex size>\r\n<data>\r\n`, ended by a zero-size chunk.
        Chunked,
        /// No length known. The body ends when the server closes the connection.
        UntilClose,
    }

    impl Framing {
        pub fn name(&self) -> &'static str {
            match self {
                Framing::None => "none",
                Framing::Length(_) => "content-length",
                Framing::Chunked => "chunked",
                Framing::UntilClose => "until-close",
            }
        }
    }

    pub fn decide(status: u16, headers: &[Header]) -> Framing {
        let get = |name: &str| headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.trim());
        if (100..200).contains(&status) || status == 204 || status == 304 {
            return Framing::None;
        }
        // Transfer-Encoding wins over Content-Length. If both are present, a
        // middlebox that disagrees about this is how request smuggling works.
        if let Some(te) = get("transfer-encoding") {
            let last = te.rsplit(',').next().unwrap_or("").trim();
            return if last.eq_ignore_ascii_case("chunked") { Framing::Chunked } else { Framing::UntilClose };
        }
        match get("content-length").and_then(|v| v.parse().ok()) {
            Some(n) => Framing::Length(n),
            None => Framing::UntilClose,
        }
    }

    /// Incremental body reader. Bytes arrive in arbitrary pieces.
    pub struct Reader {
        framing: Framing,
        state: Chunk,
        line: Vec<u8>,
        complete: bool,
        pub body_bytes: u64,
        pub wire_bytes: u64,
        pub chunks: u32,
    }

    enum Chunk {
        Size,
        Data(u64),
        DataEnd(u8),
        Trailers,
    }

    impl Reader {
        pub fn new(framing: Framing) -> Self {
            Self {
                framing,
                state: Chunk::Size,
                line: Vec::new(),
                complete: matches!(framing, Framing::None | Framing::Length(0)),
                body_bytes: 0,
                wire_bytes: 0,
                chunks: 0,
            }
        }

        pub fn done(&self) -> bool {
            self.complete
        }

        /// The connection ended. Fine for until-close, an error otherwise.
        pub fn eof(&mut self) -> Result<(), ErrorInfo> {
            if self.framing == Framing::UntilClose {
                self.complete = true;
            }
            if self.complete {
                Ok(())
            } else {
                Err(ErrorInfo {
                    code: "TRUNCATED".into(),
                    message: format!("connection ended after {} body bytes, before the framing said the body was over", self.body_bytes),
                })
            }
        }

        pub fn feed(&mut self, mut bytes: &[u8]) -> Result<(), ErrorInfo> {
            while !bytes.is_empty() && !self.complete {
                let used = match self.framing {
                    Framing::None => return Ok(()),
                    Framing::UntilClose => {
                        self.body_bytes += bytes.len() as u64;
                        bytes.len()
                    }
                    Framing::Length(n) => {
                        let take = (n - self.body_bytes).min(bytes.len() as u64) as usize;
                        self.body_bytes += take as u64;
                        self.complete = self.body_bytes == n;
                        take
                    }
                    Framing::Chunked => self.chunked(bytes)?,
                };
                self.wire_bytes += used as u64;
                bytes = &bytes[used..];
            }
            Ok(())
        }

        /// Consumes some of `bytes` and returns how many.
        fn chunked(&mut self, bytes: &[u8]) -> Result<usize, ErrorInfo> {
            let bad = |m: &str| ErrorInfo { code: "BAD_CHUNK".into(), message: m.into() };
            match self.state {
                Chunk::Size | Chunk::Trailers => {
                    // Accumulate one CRLF-terminated line.
                    let Some(nl) = bytes.iter().position(|&b| b == b'\n') else {
                        self.line.extend_from_slice(bytes);
                        return Ok(bytes.len());
                    };
                    self.line.extend_from_slice(&bytes[..=nl]);
                    let line = std::mem::take(&mut self.line);
                    let text = String::from_utf8_lossy(&line);
                    let text = text.trim_end_matches(['\r', '\n']);
                    if let Chunk::Trailers = self.state {
                        if text.is_empty() {
                            self.complete = true; // blank line after the last chunk
                        }
                    } else {
                        // "1a3f;ext=val" → 0x1a3f. Extensions are ignored.
                        let hex = text.split(';').next().unwrap_or("").trim();
                        let size = u64::from_str_radix(hex, 16).map_err(|_| bad(&format!("bad chunk size {hex:?}")))?;
                        self.state = if size == 0 { Chunk::Trailers } else { Chunk::Data(size) };
                        if size > 0 {
                            self.chunks += 1;
                        }
                    }
                    Ok(nl + 1)
                }
                Chunk::Data(left) => {
                    let take = left.min(bytes.len() as u64);
                    self.body_bytes += take;
                    self.state = if take == left { Chunk::DataEnd(2) } else { Chunk::Data(left - take) };
                    Ok(take as usize)
                }
                Chunk::DataEnd(left) => {
                    // The CRLF after each chunk's data.
                    let take = (left as usize).min(bytes.len());
                    self.state = if take == left as usize { Chunk::Size } else { Chunk::DataEnd(left - take as u8) };
                    Ok(take)
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn h(name: &str, value: &str) -> Header {
            Header { name: name.into(), value: value.into() }
        }

        #[test]
        fn decide_follows_rfc_9112_precedence() {
            assert_eq!(decide(204, &[h("Content-Length", "10")]), Framing::None);
            assert_eq!(decide(304, &[]), Framing::None);
            assert_eq!(decide(200, &[h("content-length", "42")]), Framing::Length(42));
            assert_eq!(
                decide(200, &[h("Content-Length", "42"), h("Transfer-Encoding", "gzip, chunked")]),
                Framing::Chunked
            );
            assert_eq!(decide(200, &[]), Framing::UntilClose);
        }

        #[test]
        fn chunked_body_split_at_awkward_places() {
            // Two chunks ("Wiki" and "pedia"), then the zero chunk and an empty trailer section.
            let wire = b"4\r\nWiki\r\n5;note=x\r\npedia\r\n0\r\n\r\n";
            for split in 1..wire.len() {
                let mut r = Reader::new(Framing::Chunked);
                r.feed(&wire[..split]).unwrap();
                r.feed(&wire[split..]).unwrap();
                assert!(r.done(), "split at {split}");
                assert_eq!(r.body_bytes, 9);
                assert_eq!(r.chunks, 2);
                assert_eq!(r.wire_bytes, wire.len() as u64);
            }
        }

        #[test]
        fn content_length_stops_exactly() {
            let mut r = Reader::new(Framing::Length(5));
            r.feed(b"hel").unwrap();
            assert!(!r.done());
            r.feed(b"lo").unwrap();
            assert!(r.done());
            assert!(r.eof().is_ok());
        }

        #[test]
        fn early_close_is_truncation_unless_until_close() {
            let mut r = Reader::new(Framing::Length(10));
            r.feed(b"abc").unwrap();
            assert_eq!(r.eof().unwrap_err().code, "TRUNCATED");

            let mut r = Reader::new(Framing::UntilClose);
            r.feed(b"abc").unwrap();
            assert!(r.eof().is_ok());
            assert_eq!(r.body_bytes, 3);
        }
    }
}
