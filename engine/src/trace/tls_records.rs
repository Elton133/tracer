//! Reads TLS record boundaries out of the raw TCP byte stream.
//!
//! TCP delivers a stream with no message boundaries: one read() may hold
//! half a record or three of them. TLS adds its own framing on top. Every
//! record starts with a 5-byte header:
//!
//!   content_type (1) | legacy_version (2) | length (2) | payload (length)
//!
//! Until encryption starts in a direction, handshake payloads are readable
//! too: a sequence of `type (1) | length (3) | body` messages. After a
//! ChangeCipherSpec (TLS 1.2), or from the first `application_data`
//! record on (TLS 1.3), payloads are ciphertext and only the header remains
//! meaningful.

use crate::model::{Direction, TlsRecord};

#[derive(Default)]
pub struct RecordTap {
    sent: Stream,
    received: Stream,
    pub records: Vec<TlsRecord>,
}

#[derive(Default)]
struct Stream {
    buf: Vec<u8>,
    encrypted: bool,
    /// Bytes still owed to a handshake message that spilled into the next record.
    carry: usize,
}

impl RecordTap {
    pub fn feed(&mut self, direction: Direction, bytes: &[u8], at_ms: f64) {
        let s = match direction {
            Direction::Sent => &mut self.sent,
            Direction::Received => &mut self.received,
        };
        s.buf.extend_from_slice(bytes);

        while s.buf.len() >= 5 {
            let ct = s.buf[0];
            let version = u16::from_be_bytes([s.buf[1], s.buf[2]]);
            let len = u16::from_be_bytes([s.buf[3], s.buf[4]]);
            if s.buf.len() < 5 + len as usize {
                break; // the rest of this record is still in flight
            }
            let body = &s.buf[5..5 + len as usize];

            let encrypted = s.encrypted || ct == 23;
            let messages = match ct {
                22 if !encrypted => handshake_messages(body, &mut s.carry),
                21 if !encrypted && body.len() == 2 => vec![format!("alert: {}", alert_name(body[1]))],
                _ => vec![],
            };
            if ct == 20 {
                s.encrypted = true; // everything after ChangeCipherSpec is protected
            }

            self.records.push(TlsRecord {
                at_ms,
                direction,
                content_type: content_type_name(ct).into(),
                record_version: version_name(version),
                length: len,
                messages,
                encrypted: encrypted && ct != 20,
            });
            s.buf.drain(..5 + len as usize);
        }
    }
}

fn handshake_messages(body: &[u8], carry: &mut usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = (*carry).min(body.len());
    *carry -= i;
    while i + 4 <= body.len() {
        let len = u32::from_be_bytes([0, body[i + 1], body[i + 2], body[i + 3]]) as usize;
        out.push(handshake_name(body[i]).to_string());
        let end = i + 4 + len;
        if end > body.len() {
            *carry = end - body.len(); // continues in the next record
            break;
        }
        i = end;
    }
    out
}

fn content_type_name(ct: u8) -> &'static str {
    match ct {
        20 => "change_cipher_spec",
        21 => "alert",
        22 => "handshake",
        23 => "application_data",
        _ => "unknown",
    }
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        22 => "CertificateStatus",
        24 => "KeyUpdate",
        _ => "unknown",
    }
}

fn alert_name(d: u8) -> &'static str {
    match d {
        0 => "close_notify",
        10 => "unexpected_message",
        40 => "handshake_failure",
        42 => "bad_certificate",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        48 => "unknown_ca",
        70 => "protocol_version",
        80 => "internal_error",
        112 => "unrecognized_name",
        _ => "other",
    }
}

fn version_name(v: u16) -> String {
    let name = match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "?",
    };
    format!("0x{v:04x} ({name})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_records_across_reads_and_names_messages() {
        // A ServerHello record (type 22) split across two reads, then a
        // ChangeCipherSpec, then an encrypted application_data record.
        let server_hello = [22, 3, 3, 0, 6, /* msg */ 2, 0, 0, 2, 0xaa, 0xbb];
        let ccs = [20, 3, 3, 0, 1, 1];
        let app = [23, 3, 3, 0, 3, 9, 9, 9];

        let mut tap = RecordTap::default();
        tap.feed(Direction::Received, &server_hello[..7], 1.0);
        assert!(tap.records.is_empty(), "half a record must not be emitted");
        tap.feed(Direction::Received, &server_hello[7..], 2.0);
        tap.feed(Direction::Received, &[&ccs[..], &app[..]].concat(), 3.0);

        let r = &tap.records;
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].messages, vec!["ServerHello"]);
        assert_eq!(r[0].at_ms, 2.0);
        assert!(!r[0].encrypted);
        assert_eq!(r[1].content_type, "change_cipher_spec");
        assert!(r[2].encrypted);
        assert!(r[2].messages.is_empty());
    }

    #[test]
    fn handshake_message_spanning_two_records() {
        // Certificate message (type 11) of length 6 split across two records.
        let rec1 = [22, 3, 3, 0, 6, 11, 0, 0, 6, 1, 2];
        let rec2 = [22, 3, 3, 0, 8, 3, 4, 5, 6, /* next msg */ 14, 0, 0, 0];
        let mut tap = RecordTap::default();
        tap.feed(Direction::Received, &[&rec1[..], &rec2[..]].concat(), 0.0);
        assert_eq!(tap.records[0].messages, vec!["Certificate"]);
        assert_eq!(tap.records[1].messages, vec!["ServerHelloDone"]);
    }
}
