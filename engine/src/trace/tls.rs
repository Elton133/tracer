//! TLS over the TCP stream we already have, driven by hand.
//!
//! rustls is a pure state machine with no I/O of its own. We feed it the
//! bytes we read from the socket (`read_tls`) and send the bytes it produces
//! (`write_tls`). Being the middleman lets `RecordTap` see every record in
//! both directions.
//!
//! TLS 1.3 handshake, 1 round trip:
//!   →  ClientHello (key share for X25519 etc., SNI, ALPN)
//!   ←  ServerHello (its key share)  ── both sides now derive keys ──
//!   ←  {EncryptedExtensions, Certificate, CertificateVerify, Finished}
//!   →  {Finished}
//! Braces = encrypted. That's why, from the Certificate on, the server's
//! identity is hidden from anyone watching the network (unlike TLS 1.2).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Host;

use crate::model::*;

use super::tls_records::RecordTap;
use super::{Clock, event};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Only what we can actually speak afterwards. "h2" joins when HTTP/2 does.
const ALPN: &[&str] = &["http/1.1"];
const TRUST_STORE: &str = "Mozilla root program (webpki-roots), not the macOS Keychain";

/// An established TLS connection: the rustls state machine plus the socket under it.
pub struct TlsSession {
    pub conn: ClientConnection,
    pub tcp: TcpStream,
    pub tap: RecordTap,
    /// Ciphertext read from the socket that rustls hasn't taken yet.
    pub pending: Vec<u8>,
    pub eof: bool,
}

pub async fn handshake(
    clock: &Clock,
    mut tcp: TcpStream,
    host: &Host<String>,
    remote: SocketAddr,
    conn_id: &str,
) -> (TraceEvent, Result<TlsSession, TcpStream>) {
    let server_name: ServerName<'static> = match host {
        Host::Domain(d) => ServerName::try_from(d.clone()).expect("valid DNS name after URL parsing"),
        Host::Ipv4(ip) => ServerName::IpAddress((*ip).into()),
        Host::Ipv6(ip) => ServerName::IpAddress((*ip).into()),
    };
    let sni = matches!(host, Host::Domain(_)).then(|| host.to_string());

    let verifier = Arc::new(RecordingVerifier::new());
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .dangerous() // only to install our verifier, which still does full WebPKI checks
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    config.alpn_protocols = ALPN.iter().map(|p| p.as_bytes().to_vec()).collect();

    let mut conn = ClientConnection::new(Arc::new(config), server_name).expect("client config is valid");
    let mut tap = RecordTap::default();

    let start = clock.now();
    let result = timeout(HANDSHAKE_TIMEOUT, drive(clock, &mut conn, &mut tcp, &mut tap)).await;
    let end = clock.now();

    let mut data = TlsHandshakeData {
        sni: Fact::observed(sni, "ClientHello server_name extension we sent"),
        alpn_offered: Fact::observed(ALPN.iter().map(|s| s.to_string()).collect(), "ClientHello ALPN extension we sent"),
        trust_store: Fact::observed(TRUST_STORE.into(), "engine configuration").note(
            "A certificate trusted only through your Keychain (e.g. a corporate proxy CA) fails here but works in Safari.",
        ),
        records: Fact::observed(tap.records.clone(), "5-byte TLS record headers on bytes we sent/received").note(
            "Message names are read only from unencrypted records. Encrypted contents are invisible here, as on the wire.",
        ),
        round_trips: None,
        version: None,
        cipher_suite: None,
        key_exchange: None,
        alpn: None,
        chain: None,
        verification: None,
    };

    let presented = verifier.presented.lock().unwrap().take();
    if let Some(chain) = presented {
        data.chain = Some(Fact::observed(
            chain.iter().map(|c| summarize(c)).collect(),
            "Certificate message, decrypted by our TLS client",
        ));
    }
    if let Some(verdict) = verifier.verdict.lock().unwrap().take() {
        data.verification = Some(Fact::observed(
            verdict.map(|_| "valid".to_string()).unwrap_or_else(|e| cert_error_code(&e)),
            "WebPKI verification (rustls-webpki)",
        ));
    }

    let mut ev = event(Some(ProtocolId::Tls), Span { start, end: Some(end) }, Payload::TlsHandshake(data));
    ev.connection_id = Some(conn_id.into());
    ev.from = Some(super::dns::entity::APP.into());
    ev.to = Some(super::tcp::server_entity(remote));
    ev.explain_key = Some("tls.handshake".into());

    let failure = match result {
        Ok(Ok(())) => None,
        Ok(Err(f)) => Some((Status::Error, f)),
        Err(_) => Some((Status::Timeout, Failure::Timeout)),
    };

    let Payload::TlsHandshake(data) = &mut ev.payload else { unreachable!() };
    data.round_trips = Some(Fact::derived(
        round_trips(&tap.records),
        "derive: flights we sent that the server answered (ChangeCipherSpec ignored)",
    ));

    if let Some((status, f)) = failure {
        ev.status = status;
        ev.error = Some(Fact::observed(f.info(), f.source()));
        return (ev, Err(tcp));
    }

    let negotiated = "negotiated, reported by our TLS client";
    data.version = conn.protocol_version().map(|v| Fact::observed(version_name(v), negotiated));
    data.cipher_suite = conn.negotiated_cipher_suite().map(|s| Fact::observed(format!("{:?}", s.suite()), negotiated));
    data.key_exchange = conn.negotiated_key_exchange_group().map(|g| Fact::observed(format!("{:?}", g.name()), negotiated));
    data.alpn = Some(Fact::observed(
        conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
        "ALPN extension in the server's reply",
    ));

    (ev, Ok(TlsSession { conn, tcp, tap, pending: Vec::new(), eof: false }))
}

/// Polite TLS shutdown: send close_notify, so the server can tell a
/// deliberate end from a truncation attack. Then hand the socket back for TCP's FIN.
pub async fn close(clock: &Clock, mut s: TlsSession) -> TcpStream {
    s.conn.send_close_notify();
    let _ = flush(clock, &mut s.conn, &mut s.tcp, &mut s.tap).await;
    s.tcp
}

async fn drive(clock: &Clock, conn: &mut ClientConnection, tcp: &mut TcpStream, tap: &mut RecordTap) -> Result<(), Failure> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        flush(clock, conn, tcp, tap).await.map_err(Failure::Io)?;
        if !conn.is_handshaking() {
            return Ok(());
        }
        let n = tcp.read(&mut buf).await.map_err(Failure::Io)?;
        if n == 0 {
            return Err(Failure::Eof);
        }
        tap.feed(Direction::Received, &buf[..n], clock.now());
        let mut incoming = &buf[..n];
        while !incoming.is_empty() {
            conn.read_tls(&mut incoming).map_err(Failure::Io)?;
            if let Err(e) = conn.process_new_packets() {
                // rustls has queued an alert telling the server why; send it.
                let _ = flush(clock, conn, tcp, tap).await;
                return Err(Failure::Tls(e));
            }
        }
    }
}

pub(super) async fn flush(clock: &Clock, conn: &mut ClientConnection, tcp: &mut TcpStream, tap: &mut RecordTap) -> std::io::Result<()> {
    while conn.wants_write() {
        let mut out = Vec::new();
        conn.write_tls(&mut out)?;
        tap.feed(Direction::Sent, &out, clock.now());
        tcp.write_all(&out).await?;
    }
    Ok(())
}

/// A round trip is a flight we sent that the server then answered.
/// ChangeCipherSpec is skipped: in TLS 1.3 it is a dummy record sent only so
/// old middleboxes recognise the traffic (RFC 8446 D.4), and nobody waits on it.
fn round_trips(records: &[TlsRecord]) -> u32 {
    let flights: Vec<Direction> = records
        .iter()
        .filter(|r| r.content_type != "change_cipher_spec")
        .map(|r| r.direction)
        .collect();
    flights
        .windows(2)
        .filter(|w| w[0] == Direction::Sent && w[1] == Direction::Received)
        .count() as u32
}

enum Failure {
    Io(std::io::Error),
    Eof,
    Tls(rustls::Error),
    Timeout,
}

impl Failure {
    fn info(&self) -> ErrorInfo {
        let (code, message) = match self {
            Failure::Io(e) => ("IO".to_string(), e.to_string()),
            Failure::Eof => ("EOF".into(), "server closed the connection during the handshake".into()),
            Failure::Tls(e) => (cert_error_code(e), e.to_string()),
            Failure::Timeout => ("ETIMEDOUT".into(), format!("handshake not complete within {HANDSHAKE_TIMEOUT:?}")),
        };
        ErrorInfo { code, message }
    }

    fn source(&self) -> &'static str {
        match self {
            Failure::Tls(rustls::Error::InvalidCertificate(_)) => "WebPKI verification (rustls-webpki)",
            Failure::Tls(rustls::Error::AlertReceived(_)) => "alert record from the server",
            Failure::Tls(_) => "TLS client error",
            Failure::Timeout => "engine timeout",
            _ => "socket",
        }
    }
}

fn cert_error_code(e: &rustls::Error) -> String {
    use CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => "CERT_EXPIRED",
            C::NotValidYet | C::NotValidYetContext { .. } => "CERT_NOT_YET_VALID",
            C::NotValidForName | C::NotValidForNameContext { .. } => "CERT_HOSTNAME_MISMATCH",
            C::UnknownIssuer => "CERT_UNKNOWN_ISSUER",
            C::Revoked => "CERT_REVOKED",
            C::BadSignature => "CERT_BAD_SIGNATURE",
            _ => "CERT_INVALID",
        }
        .into(),
        rustls::Error::AlertReceived(a) => format!("ALERT_{a:?}").to_uppercase(),
        other => format!("{other:?}").split(['(', ' ', '{']).next().unwrap_or("TLS").to_uppercase(),
    }
}

fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    }
}

fn summarize(der: &CertificateDer<'_>) -> CertSummary {
    use x509_parser::prelude::*;
    use x509_parser::public_key::PublicKey;
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let sha256 = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    let der_bytes = der.len() as u32;

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return CertSummary {
            subject: "(unparseable)".into(),
            issuer: String::new(),
            serial: String::new(),
            not_before_unix: 0.0,
            not_after_unix: 0.0,
            san: vec![],
            public_key: String::new(),
            signature_algorithm: String::new(),
            is_ca: false,
            sha256,
            der_bytes,
        };
    };

    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(d) => Some(d.to_string()),
                GeneralName::IPAddress(ip) => Some(format!("IP {ip:02x?}")),
                _ => None,
            })
            .collect(),
        _ => vec![],
    };
    let public_key = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(k)) => format!("RSA {} bits", k.key_size()),
        Ok(PublicKey::EC(k)) => format!("EC {} bits", k.key_size()),
        Ok(_) | Err(_) => "other".into(),
    };
    let sig_oid = &cert.signature_algorithm.algorithm;
    let signature_algorithm = x509_parser::objects::oid2sn(sig_oid, x509_parser::objects::oid_registry())
        .map(str::to_string)
        .unwrap_or_else(|_| sig_oid.to_id_string());

    CertSummary {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before_unix: cert.validity().not_before.timestamp() as f64,
        not_after_unix: cert.validity().not_after.timestamp() as f64,
        san,
        public_key,
        signature_algorithm,
        is_ca: cert.is_ca(),
        sha256,
        der_bytes,
    }
}

/// Standard WebPKI verification, plus a copy of what the server presented.
/// Recording happens *before* the verdict, so even a rejected certificate
/// (expired, wrong host) can be inspected as observed data.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    presented: Mutex<Option<Vec<CertificateDer<'static>>>>,
    verdict: Mutex<Option<Result<(), rustls::Error>>>,
}

impl RecordingVerifier {
    fn new() -> Self {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("root store is non-empty");
        Self { inner, presented: Mutex::new(None), verdict: Mutex::new(None) }
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain = std::iter::once(end_entity).chain(intermediates).map(|c| c.clone().into_owned()).collect();
        *self.presented.lock().unwrap() = Some(chain);
        let r = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        *self.verdict.lock().unwrap() = Some(r.as_ref().map(|_| ()).map_err(Clone::clone));
        r
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(direction: Direction, content_type: &str) -> TlsRecord {
        TlsRecord {
            at_ms: 0.0,
            direction,
            content_type: content_type.into(),
            record_version: String::new(),
            length: 0,
            messages: vec![],
            encrypted: false,
        }
    }

    #[test]
    fn tls13_with_compat_ccs_is_one_round_trip() {
        use Direction::*;
        let seq = [
            rec(Sent, "handshake"),            // ClientHello
            rec(Received, "handshake"),        // ServerHello
            rec(Received, "change_cipher_spec"),
            rec(Sent, "change_cipher_spec"),   // compat dummy
            rec(Received, "application_data"), // {EE, Certificate, CV, Finished}
            rec(Sent, "application_data"),     // {Finished}
        ];
        assert_eq!(round_trips(&seq), 1);
    }

    #[test]
    fn tls12_full_handshake_is_two_round_trips() {
        use Direction::*;
        let seq = [
            rec(Sent, "handshake"),     // ClientHello
            rec(Received, "handshake"), // ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
            rec(Sent, "handshake"),     // ClientKeyExchange
            rec(Sent, "change_cipher_spec"),
            rec(Sent, "handshake"),     // Finished (encrypted)
            rec(Received, "change_cipher_spec"),
            rec(Received, "handshake"), // Finished
        ];
        assert_eq!(round_trips(&seq), 2);
    }
}
