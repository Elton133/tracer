//! TCP: open a reliable byte stream to one IP:port, then close it.
//!
//! What we call vs. what the kernel does:
//!
//!   socket() + connect()   kernel sends SYN, gets SYN-ACK, sends ACK
//!                          (we're parked until the socket becomes writable)
//!   shutdown(SHUT_WR)      kernel sends FIN: "I won't send any more"
//!   read() == 0            the server's FIN arrived: "neither will I"
//!
//! We never see those segments, only the moments our calls return. The
//! kernel will tell us what it measured, though: see `tcp_info`.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::*;

use super::{Clock, event, tcp_info};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(3);
const KERNEL: &str = "getsockopt(IPPROTO_TCP, TCP_CONNECTION_INFO)";

pub async fn connect(clock: &Clock, remote: SocketAddr, choice: String, conn: &str) -> (TraceEvent, Option<TcpStream>) {
    let mut data = TcpConnectData {
        remote: Fact::observed(remote.into(), "address passed to connect(2)"),
        address_choice: Fact::derived(choice, "engine address selection"),
        local: None,
        rtt_estimate_ms: None,
        nodelay: None,
        kernel: None,
    };

    let start = clock.now();
    let result = timeout(CONNECT_TIMEOUT, TcpStream::connect(remote)).await;
    let end = clock.now();

    let (status, error, stream) = match result {
        Ok(Ok(stream)) => {
            // Disable Nagle's algorithm. Nagle holds back a small segment while an
            // earlier one is unacknowledged. Our TLS Finished and the HTTP request
            // are two small writes in a row, so the request waited for the server's
            // (possibly delayed) ACK. Measured: TTFB ~250 ms with Nagle, ~60 ms without.
            // curl and browsers set TCP_NODELAY for the same reason.
            data.nodelay = Some(Fact::observed(
                stream.set_nodelay(true).is_ok() && stream.nodelay().unwrap_or(false),
                "setsockopt(TCP_NODELAY), read back with getsockopt",
            ));
            data.local = stream
                .local_addr()
                .ok()
                .map(|a| Fact::observed(a.into(), "getsockname(2)").note("Before NAT. The server sees your public address."));
            data.rtt_estimate_ms = Some(Fact::derived(
                end - start,
                "derive: connect() duration ≈ 1 RTT (SYN out → SYN-ACK back) + local scheduling",
            ));
            data.kernel = kernel_fact(&stream, "Right after the handshake. The RTT here is from one sample: the SYN → SYN-ACK.");
            (Status::Ok, None, Some(stream))
        }
        Ok(Err(e)) => (Status::Error, Some(Fact::observed(os_error(&e), "connect(2) error")), None),
        Err(_) => (
            Status::Timeout,
            Some(
                Fact::observed(
                    ErrorInfo {
                        code: "ETIMEDOUT".into(),
                        message: format!("no SYN-ACK within {CONNECT_TIMEOUT:?}"),
                    },
                    "engine timeout",
                )
                .note("The kernel would keep retrying the SYN with exponential backoff (about 75 s on macOS)."),
            ),
            None,
        ),
    };

    let mut ev = event(Some(ProtocolId::Tcp), Span { start, end: Some(end) }, Payload::TcpConnect(data));
    ev.status = status;
    ev.error = error;
    ev.connection_id = Some(conn.into());
    ev.from = Some(super::dns::entity::APP.into());
    ev.to = Some(server_entity(remote));
    ev.explain_key = Some("tcp.handshake".into());
    (ev, stream)
}

/// Graceful close. We send FIN, then wait for the server's FIN.
pub async fn close(clock: &Clock, mut stream: TcpStream, remote: SocketAddr, conn: &str) -> TraceEvent {
    let start = clock.now();
    let result = timeout(CLOSE_TIMEOUT, async {
        stream.shutdown().await?; // shutdown(SHUT_WR) → FIN
        let mut buf = [0u8; 4096];
        loop {
            // Anything still in flight from the server drains here. 0 = its FIN.
            if stream.read(&mut buf).await? == 0 {
                return Ok::<_, std::io::Error>(());
            }
        }
    })
    .await;
    let end = clock.now();

    let (status, error, peer_closed) = match result {
        Ok(Ok(())) => (Status::Ok, None, true),
        Ok(Err(e)) => (Status::Error, Some(Fact::observed(os_error(&e), "shutdown(2)/read(2) error")), false),
        Err(_) => (
            Status::Timeout,
            Some(Fact::observed(
                ErrorInfo { code: "ETIMEDOUT".into(), message: format!("server did not close within {CLOSE_TIMEOUT:?}") },
                "engine timeout",
            )),
            false,
        ),
    };

    let data = TcpCloseData {
        initiated_by: Fact::observed("client".into(), "we called shutdown(2) first"),
        peer_closed: Fact::observed(peer_closed, "read(2) returned 0 (end of stream)"),
        kernel: kernel_fact(&stream, "After both FINs. The side that closed first waits in TIME_WAIT."),
    };
    let mut ev = event(Some(ProtocolId::Tcp), Span { start, end: Some(end) }, Payload::TcpClose(data));
    ev.status = status;
    ev.error = error;
    ev.connection_id = Some(conn.into());
    ev.from = Some(super::dns::entity::APP.into());
    ev.to = Some(server_entity(remote));
    ev.explain_key = Some("tcp.close".into());
    ev
}

pub fn server_entity(remote: SocketAddr) -> String {
    format!("server:{}", remote.ip())
}

fn kernel_fact(stream: &TcpStream, note: &str) -> Option<Fact<TcpKernelInfo>> {
    tcp_info::snapshot(stream.as_raw_fd()).ok().map(|k| Fact::observed(k, KERNEL).note(note))
}

/// errno → the name you'd see in C, plus the OS's message.
fn os_error(e: &std::io::Error) -> ErrorInfo {
    let code = match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => "ECONNREFUSED", // server answered our SYN with RST: nothing listening
        Some(libc::ECONNRESET) => "ECONNRESET",     // RST mid-connection
        Some(libc::ETIMEDOUT) => "ETIMEDOUT",
        Some(libc::EHOSTUNREACH) => "EHOSTUNREACH", // usually an ICMP "host unreachable" came back
        Some(libc::ENETUNREACH) => "ENETUNREACH",   // no route, e.g. IPv6 address on an IPv4-only network
        Some(libc::EADDRNOTAVAIL) => "EADDRNOTAVAIL",
        Some(n) => return ErrorInfo { code: format!("errno {n}"), message: e.to_string() },
        None => "IO",
    };
    ErrorInfo { code: code.into(), message: e.to_string() }
}
