// Everything the TLS view shows, derived from one hop of a trace.
//
// Observed: the records (5-byte headers we parsed), the negotiated
// parameters, the certificate chain, the plaintext request we wrote.
// Derived: overhead arithmetic, chain links, days of validity left.
// Explained: what TLS 1.3 puts *inside* records we can't read.

import type { CertSummary } from "../generated/CertSummary";
import type { TlsRecord } from "../generated/TlsRecord";
import type { Trace } from "../generated/Trace";
import type { TraceEvent } from "../generated/TraceEvent";

export interface LadderRecord extends TlsRecord {
  /** Index in the ladder. */
  i: number;
  phase: "handshake" | "request" | "response";
  eventId: string;
  /** Read in the same read() as the record before it: they arrived together. */
  sameReadAsPrevious: boolean;
  /** TLS 1.3 only: what the spec says is inside, since we can't read it. */
  explainedContents?: string;
}

export interface ChainCert extends CertSummary {
  /** Derived: this certificate's issuer is the next certificate's subject. */
  issuedByNext: boolean;
  /** Derived, at the moment of the trace. */
  daysLeft: number;
  validAtTrace: boolean;
}

export interface Encryption {
  plaintext: string;
  plaintextBytes: number;
  recordLength: number;
  /** The 5-byte header an observer sees, from fields we parsed. */
  headerHex: string;
  overhead: number;
  overheadExplained: string;
}

export interface TlsView {
  hop: number;
  handshake: Extract<TraceEvent, { kind: "tls.handshake" }>;
  ladder: LadderRecord[];
  /**
   * Ladder index of the first encrypted record in each direction. Each side
   * switches to encryption on its own (after its own ChangeCipherSpec in
   * TLS 1.2; after ServerHello, server first, in TLS 1.3).
   */
  encryptedFrom: { sent: number; received: number };
  chain: ChainCert[];
  encryption?: Encryption;
}

const CONTENT_TYPE: Record<string, number> = { change_cipher_spec: 20, alert: 21, handshake: 22, application_data: 23 };

/** Handshakes in the trace, one per hop that used TLS. */
export function tlsHops(trace: Trace): number[] {
  return trace.events.filter((e) => e.kind === "tls.handshake").map((e) => e.hopIndex);
}

export function buildTlsView(trace: Trace, hop: number): TlsView | null {
  const handshake = trace.events.find((e): e is Extract<TraceEvent, { kind: "tls.handshake" }> => e.kind === "tls.handshake" && e.hopIndex === hop);
  if (!handshake) return null;
  const tls13 = handshake.data.version?.value === "TLS 1.3";

  const ladder: LadderRecord[] = [];
  const push = (records: TlsRecord[] | undefined, phase: LadderRecord["phase"], eventId: string) => {
    for (const r of records ?? []) {
      const prev = ladder.at(-1);
      ladder.push({
        ...r,
        i: ladder.length,
        phase,
        eventId,
        sameReadAsPrevious: !!prev && prev.direction === r.direction && prev.atMs === r.atMs,
      });
    }
  };
  push(handshake.data.records.value, "handshake", handshake.id);
  for (const e of trace.events) {
    if (e.hopIndex !== hop) continue;
    if (e.kind === "http.request") push(e.data.tlsRecords?.value, "request", e.id);
    if (e.kind === "http.response" || e.kind === "http.body") push(e.data.tlsRecords?.value, "response", e.id);
  }

  if (tls13) explainTls13(ladder);

  const first = (dir: TlsRecord["direction"]) => {
    const i = ladder.findIndex((r) => r.direction === dir && r.encrypted);
    return i === -1 ? ladder.length : i;
  };
  const at = trace.startedAtUnixMs / 1000;
  const certs = handshake.data.chain?.value ?? [];
  const chain: ChainCert[] = certs.map((c, i) => ({
    ...c,
    issuedByNext: i + 1 < certs.length && certs[i + 1].subject === c.issuer,
    daysLeft: Math.floor((c.notAfterUnix - at) / 86400),
    validAtTrace: c.notBeforeUnix <= at && at <= c.notAfterUnix,
  }));

  return { hop, handshake, ladder, encryptedFrom: { sent: first("sent"), received: first("received") }, chain, encryption: encryption(trace, hop, tls13) };
}

/**
 * Label encrypted handshake records with what RFC 8446 says they contain.
 * Only the first encrypted flight each way is handshake; after that it's
 * application data (or session tickets, which look identical on the wire).
 */
function explainTls13(ladder: LadderRecord[]) {
  const firstEncrypted = (dir: TlsRecord["direction"]) => ladder.find((r) => r.phase === "handshake" && r.direction === dir && r.encrypted);
  const server = firstEncrypted("received");
  if (server) server.explainedContents = "EncryptedExtensions, Certificate, CertificateVerify, Finished";
  const client = firstEncrypted("sent");
  if (client) client.explainedContents = "Finished";
}

function encryption(trace: Trace, hop: number, tls13: boolean): Encryption | undefined {
  const req = trace.events.find((e): e is Extract<TraceEvent, { kind: "http.request" }> => e.kind === "http.request" && e.hopIndex === hop);
  const recs = req?.data.tlsRecords?.value.filter((r) => r.direction === "sent");
  // Only when the whole request went out in one record can the arithmetic be exact.
  if (!req || !recs || recs.length !== 1) return undefined;
  const r = recs[0];
  const plaintextBytes = req.data.headBytes.value;
  const hex = (n: number, w: number) => n.toString(16).padStart(w, "0");
  return {
    plaintext: req.data.rawHead?.value ?? "",
    plaintextBytes,
    recordLength: r.length,
    headerHex: `${hex(CONTENT_TYPE[r.contentType] ?? 0, 2)} ${r.recordVersion.slice(2, 4)} ${r.recordVersion.slice(4, 6)} ${hex(r.length >> 8, 2)} ${hex(r.length & 0xff, 2)}`,
    overhead: r.length - plaintextBytes,
    overheadExplained: tls13
      ? "1 byte: the real content type, hidden inside · 16 bytes: authentication tag (AEAD)"
      : "8 bytes: explicit nonce · 16 bytes: authentication tag (AES-GCM)",
  };
}
