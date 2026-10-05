//! The kernel's own view of a TCP connection.
//!
//! TCP lives in the kernel, not in our process. After `connect()` returns,
//! we only hold a file descriptor. But the kernel will report its internal
//! state for that socket through `getsockopt`: the RTT it measured, the
//! negotiated segment size, both windows, packet counters.
//!
//! macOS: `TCP_CONNECTION_INFO` → `struct tcp_connection_info` (netinet/tcp.h).
//! Linux has the equivalent `TCP_INFO` → `struct tcp_info`, not wired up yet.

use std::os::fd::RawFd;

use crate::model::{TcpKernelInfo, TcpOptions};

#[cfg(target_os = "macos")]
pub fn snapshot(fd: RawFd) -> Result<TcpKernelInfo, String> {
    use std::mem::size_of;

    /// Mirrors the SDK header field by field. The 15 `tcpi_tfo_*` flags are
    /// C bitfields packed into a single u32 (`tfo_bits`). The libc crate
    /// declares them as 15 separate u32s, which shifts every u64 counter
    /// that follows, so we don't use its definition.
    #[repr(C)]
    #[derive(Default)]
    struct TcpConnectionInfo {
        state: u8,
        snd_wscale: u8,
        rcv_wscale: u8,
        _pad1: u8,
        options: u32,
        flags: u32,
        rto: u32,
        maxseg: u32,
        snd_ssthresh: u32,
        snd_cwnd: u32,
        snd_wnd: u32,
        snd_sbbytes: u32,
        rcv_wnd: u32,
        rttcur: u32,
        srtt: u32,
        rttvar: u32,
        tfo_bits: u32,
        txpackets: u64,
        txbytes: u64,
        txretransmitbytes: u64,
        rxpackets: u64,
        rxbytes: u64,
        rxoutoforderbytes: u64,
        txretransmitpackets: u64,
    }
    // sizeof(struct tcp_connection_info) from a C probe against the SDK.
    const _: () = assert!(size_of::<TcpConnectionInfo>() == 112);

    let mut info = TcpConnectionInfo::default();
    let mut len = size_of::<TcpConnectionInfo>() as libc::socklen_t;
    // SAFETY: `info` is a correctly sized, writable buffer and `len` tells the
    // kernel its size. The kernel writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            (&mut info as *mut TcpConnectionInfo).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if len as usize != size_of::<TcpConnectionInfo>() {
        return Err(format!("kernel returned {len} bytes, expected {}", size_of::<TcpConnectionInfo>()));
    }

    let small = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    Ok(TcpKernelInfo {
        state: state_name(info.state).into(),
        srtt_ms: info.srtt,
        rttvar_ms: info.rttvar,
        rtt_latest_ms: info.rttcur,
        rto_ms: info.rto,
        mss: info.maxseg,
        cwnd_bytes: info.snd_cwnd,
        ssthresh_bytes: info.snd_ssthresh,
        send_window_bytes: info.snd_wnd,
        recv_window_bytes: info.rcv_wnd,
        send_window_scale: info.snd_wscale,
        recv_window_scale: info.rcv_wscale,
        options: TcpOptions {
            timestamps: info.options & 0x1 != 0,
            sack: info.options & 0x2 != 0,
            window_scaling: info.options & 0x4 != 0,
            ecn: info.options & 0x8 != 0,
        },
        packets_sent: small(info.txpackets),
        packets_received: small(info.rxpackets),
        bytes_sent: small(info.txbytes),
        bytes_received: small(info.rxbytes),
        retransmitted_packets: small(info.txretransmitpackets),
        retransmitted_bytes: small(info.txretransmitbytes),
        out_of_order_bytes: small(info.rxoutoforderbytes),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn snapshot(_fd: RawFd) -> Result<TcpKernelInfo, String> {
    Err("kernel TCP statistics are only implemented for macOS so far".into())
}

/// netinet/tcp_fsm.h
#[allow(dead_code)]
fn state_name(s: u8) -> &'static str {
    match s {
        0 => "CLOSED",
        1 => "LISTEN",
        2 => "SYN_SENT",
        3 => "SYN_RECEIVED",
        4 => "ESTABLISHED",
        5 => "CLOSE_WAIT",
        6 => "FIN_WAIT_1",
        7 => "CLOSING",
        8 => "LAST_ACK",
        9 => "FIN_WAIT_2",
        10 => "TIME_WAIT",
        _ => "UNKNOWN",
    }
}
