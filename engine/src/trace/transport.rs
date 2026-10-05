//! A byte pipe for HTTP: plain TCP, or TCP with TLS in between.
//!
//! HTTP/1.1 doesn't care which. It writes bytes and reads bytes. The
//! difference is what appears on the wire: with TLS, every write becomes
//! one or more encrypted `application_data` records, which `RecordTap` logs.

use std::io::{ErrorKind, Read, Write};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::{Direction, TlsRecord};

use super::Clock;
use super::tls::{self, TlsSession};

pub enum Transport {
    Plain(TcpStream),
    Tls(TlsSession),
}

impl Transport {
    pub async fn send(&mut self, clock: &Clock, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Transport::Plain(tcp) => tcp.write_all(bytes).await,
            Transport::Tls(s) => {
                // Plaintext in → rustls encrypts into records → we write the records.
                s.conn.writer().write_all(bytes)?;
                tls::flush(clock, &mut s.conn, &mut s.tcp, &mut s.tap).await
            }
        }
    }

    /// Ok(0) means the peer finished: TCP FIN, or TLS close_notify.
    pub async fn recv(&mut self, clock: &Clock, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(tcp) => tcp.read(out).await,
            Transport::Tls(s) => loop {
                // Any decrypted plaintext ready?
                match s.conn.reader().read(out) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e), // e.g. TCP closed without close_notify
                }
                // No: give rustls more ciphertext. It's fed only once its plaintext
                // has been drained, because it refuses input past a fixed buffer limit.
                if s.pending.is_empty() {
                    if s.eof {
                        return Err(ErrorKind::UnexpectedEof.into());
                    }
                    let mut wire = [0u8; 16 * 1024];
                    let n = s.tcp.read(&mut wire).await?;
                    if n == 0 {
                        s.eof = true;
                        s.conn.read_tls(&mut &[][..])?; // tells rustls the stream ended
                        s.conn.process_new_packets().map_err(invalid)?;
                        continue;
                    }
                    s.tap.feed(Direction::Received, &wire[..n], clock.now());
                    s.pending.extend_from_slice(&wire[..n]);
                }
                let used = s.conn.read_tls(&mut &s.pending[..])?;
                s.pending.drain(..used);
                s.conn.process_new_packets().map_err(invalid)?;
                tls::flush(clock, &mut s.conn, &mut s.tcp, &mut s.tap).await?;
            },
        }
    }

    /// How many TLS records have been seen so far, to slice out a phase's share.
    pub fn record_mark(&self) -> usize {
        match self {
            Transport::Plain(_) => 0,
            Transport::Tls(s) => s.tap.records.len(),
        }
    }

    pub fn records_since(&self, mark: usize) -> Option<Vec<TlsRecord>> {
        match self {
            Transport::Plain(_) => None,
            Transport::Tls(s) => Some(s.tap.records[mark..].to_vec()),
        }
    }

    /// Hand back the TCP socket, ending TLS politely first.
    pub async fn into_tcp(self, clock: &Clock) -> TcpStream {
        match self {
            Transport::Plain(tcp) => tcp,
            Transport::Tls(s) => tls::close(clock, s).await,
        }
    }
}

fn invalid(e: rustls::Error) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, e)
}
