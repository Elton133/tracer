// Turns a Trace into waterfall rows. Pure: no React, no DOM, so it's
// testable against real captured traces (test/fixtures).
//
// Every row is one observed event. Nothing here invents timing: a row's
// position and length are exactly the event's measured span.

import type { Trace } from "../generated/Trace";
import type { TraceEvent } from "../generated/TraceEvent";
import type { TlsRecord } from "../generated/TlsRecord";

export type Phase =
  | "parse"
  | "dns"
  | "guard"
  | "tcp"
  | "tls"
  | "request"
  | "wait"
  | "download"
  | "close"
  | "redirect";

export interface RecordTick {
  at: number;
  direction: "sent" | "received";
  bytes: number;
  encrypted: boolean;
}

export interface Row {
  eventId: string;
  hop: number;
  phase: Phase;
  label: string;
  start: number;
  /** Absent for instantaneous events (drawn as markers). */
  end?: number;
  status: TraceEvent["status"];
  /** TLS records that crossed the wire during this phase. */
  records: RecordTick[];
  /** Packet's own DNS queries: real, but not part of the request's path. */
  aside: boolean;
}

export interface HopSpan {
  index: number;
  url: string;
  status?: number;
  start: number;
  end: number;
}

export interface Waterfall {
  rows: Row[];
  hops: HopSpan[];
  /** End of the last event, in ms since trace start. */
  total: number;
}

export function buildWaterfall(trace: Trace): Waterfall {
  const rows: Row[] = [];
  const attempts = new Map<string, number>();

  for (const e of trace.events) {
    const base = {
      eventId: e.id,
      hop: e.hopIndex,
      start: e.time.start,
      end: e.time.end,
      status: e.status,
      records: [] as RecordTick[],
      aside: false,
    };
    switch (e.kind) {
      case "url.parse":
        rows.push({ ...base, phase: "parse", label: "Parse URL" });
        break;
      case "dns.lookup":
        rows.push({ ...base, phase: "dns", label: "DNS lookup" });
        break;
      case "dns.query":
        rows.push({
          ...base,
          phase: "dns",
          label: `DNS ${e.data.recordType.value} @ ${e.data.server.value.address}`,
          aside: true,
        });
        break;
      case "guard.check":
        rows.push({ ...base, phase: "guard", label: "Address check" });
        break;
      case "tcp.connect": {
        const key = `${e.hopIndex}`;
        const n = (attempts.get(key) ?? 0) + 1;
        attempts.set(key, n);
        rows.push({ ...base, phase: "tcp", label: n === 1 ? "TCP connect" : `TCP connect (attempt ${n})` });
        break;
      }
      case "tls.handshake":
        rows.push({ ...base, phase: "tls", label: "TLS handshake", records: ticks(e.data.records.value) });
        break;
      case "http.request":
        rows.push({ ...base, phase: "request", label: "Send request", records: ticks(e.data.tlsRecords?.value) });
        break;
      case "http.response":
        rows.push({ ...base, phase: "wait", label: "Wait for response", records: ticks(e.data.tlsRecords?.value) });
        break;
      case "http.body":
        rows.push({ ...base, phase: "download", label: "Download body", records: ticks(e.data.tlsRecords?.value) });
        break;
      case "tcp.close":
        rows.push({ ...base, phase: "close", label: "Close connection" });
        break;
      case "http.redirect":
        rows.push({ ...base, phase: "redirect", label: `Redirect ${e.data.status.value}` });
        break;
    }
  }

  const total = trace.events.reduce((m, e) => Math.max(m, e.time.end ?? e.time.start), 0);
  const hops: HopSpan[] = trace.hops.map((h) => {
    const own = rows.filter((r) => r.hop === h.index && !r.aside);
    return {
      index: h.index,
      url: h.url,
      status: h.status,
      start: Math.min(...own.map((r) => r.start)),
      end: Math.max(...own.map((r) => r.end ?? r.start)),
    };
  });
  return { rows, hops, total };
}

function ticks(records: TlsRecord[] | undefined): RecordTick[] {
  return (records ?? []).map((r) => ({
    at: r.atMs,
    direction: r.direction,
    bytes: r.length + 5,
    encrypted: r.encrypted,
  }));
}

/** Ticks for an axis from 0 to `total`: steps of 1, 2 or 5 × 10ⁿ, about 6 of them. */
export function axisTicks(total: number, target = 6): number[] {
  if (total <= 0) return [0];
  const raw = total / target;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? 10 * mag;
  const out: number[] = [];
  for (let v = 0; v <= total + 1e-9; v += step) out.push(Math.round(v * 1e6) / 1e6);
  return out;
}
