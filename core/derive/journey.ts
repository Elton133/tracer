// The journey: who talked to whom, and what was in flight when.
//
// Honesty rules for this view:
// - Nodes are only entities the trace observed. The network between them is
//   never invented: the UI draws it as one "path abstracted" band.
// - A flight's *observed* end (when our socket sent or received it) is
//   exact. How long it spent crossing the path is not observable, so it's
//   drawn as half the connection's RTT, a derived approximation.
// - Packets the kernel exchanges without telling us (SYN, SYN-ACK, FIN) are
//   "explained" flights: we know they happen, we don't see them.

import type { Trace } from "../generated/Trace";
import type { TraceEvent } from "../generated/TraceEvent";
import type { Phase } from "./waterfall";

export type NodeRole = "client-app" | "os-resolver" | "dns-server" | "server";

export interface JourneyNode {
  id: string;
  role: NodeRole;
  label: string;
  address?: string;
}

export interface Flight {
  eventId: string;
  from: string;
  to: string;
  depart: number;
  arrive: number;
  phase: Phase;
  label: string;
  /** Bytes on the wire, where known (TLS records). */
  bytes?: number;
  /** observed: one end of the flight is a measured moment. explained: not seen at all. */
  evidence: "observed" | "explained";
  /** True when it crosses the abstracted network path (not local to the machine). */
  viaPath: boolean;
}

/** An edge in use for the length of an event's span. */
export interface Activity {
  eventId: string;
  a: string;
  b: string;
  start: number;
  end: number;
  phase: Phase;
  aside: boolean;
}

export interface Journey {
  nodes: JourneyNode[];
  flights: Flight[];
  activities: Activity[];
}

const APP = "app";

export function buildJourney(trace: Trace): Journey {
  const nodes: JourneyNode[] = trace.entities.map((e) => ({
    id: e.id,
    role: e.role,
    label: e.label,
    address: e.addresses[0]?.value,
  }));

  // Half-RTT per connection, from the TCP handshake (a derived estimate).
  const halfRtt = new Map<string, number>();
  for (const e of trace.events) {
    if (e.kind === "tcp.connect" && e.connectionId && e.data.rttEstimateMs) {
      halfRtt.set(e.connectionId, e.data.rttEstimateMs.value / 2);
    }
  }

  const flights: Flight[] = [];
  const activities: Activity[] = [];

  for (const e of trace.events) {
    const end = e.time.end ?? e.time.start;
    const peer = e.to ?? e.from;
    if (e.from && e.to && e.time.end !== undefined) {
      activities.push({
        eventId: e.id,
        a: e.from,
        b: e.to,
        start: e.time.start,
        end,
        phase: phaseOf(e),
        aside: e.kind === "dns.query",
      });
    }
    if (!peer || peer === APP) continue;
    const half = (e.connectionId && halfRtt.get(e.connectionId)) || 0;
    const out = (at: number, label: string, evidence: Flight["evidence"] = "observed"): Flight => ({
      eventId: e.id, from: APP, to: peer, depart: at, arrive: at + half, phase: phaseOf(e), label, evidence, viaPath: true,
    });
    const back = (at: number, label: string, evidence: Flight["evidence"] = "observed"): Flight => ({
      eventId: e.id, from: peer, to: APP, depart: at - half, arrive: at, phase: phaseOf(e), label, evidence, viaPath: true,
    });

    switch (e.kind) {
      case "dns.query": {
        // A measured UDP round trip: we know when it left and when the answer
        // came back. The midpoint split is the derived part.
        const mid = (e.time.start + end) / 2;
        const t = e.data.recordType.value;
        flights.push({ ...out(e.time.start, `DNS ${t} query`), arrive: mid });
        if (e.data.response) flights.push({ ...back(end, `DNS ${t} answer`), depart: mid });
        break;
      }
      case "tcp.connect": {
        if (e.status !== "ok") {
          flights.push({ ...out(e.time.start, "SYN", "explained"), arrive: Math.min(end, e.time.start + 50) });
          break;
        }
        const mid = (e.time.start + end) / 2;
        flights.push({ ...out(e.time.start, "SYN", "explained"), arrive: mid });
        flights.push({ ...back(end, "SYN-ACK", "explained"), depart: mid });
        break;
      }
      case "tcp.close": {
        const mid = (e.time.start + end) / 2;
        flights.push({ ...out(e.time.start, "FIN", "explained"), arrive: mid });
        if (e.data.peerClosed.value) flights.push({ ...back(end, "FIN", "explained"), depart: mid });
        break;
      }
      case "tls.handshake":
        for (const r of e.data.records.value) {
          const what = r.messages.length ? r.messages.join(" + ") : r.encrypted ? "encrypted record" : r.contentType;
          const f = r.direction === "sent" ? out(r.atMs, `TLS ${what}`) : back(r.atMs, `TLS ${what}`);
          flights.push({ ...f, bytes: r.length + 5 });
        }
        break;
      case "http.request":
      case "http.response":
      case "http.body": {
        const recs = e.data.tlsRecords?.value;
        if (recs) {
          for (const r of recs) {
            const f = r.direction === "sent" ? out(r.atMs, "TLS application data") : back(r.atMs, "TLS application data");
            flights.push({ ...f, bytes: r.length + 5 });
          }
        } else if (e.kind === "http.request") {
          flights.push(out(end, `HTTP ${e.data.method.value} ${e.data.target.value}`));
        } else if (e.kind === "http.response" && e.data.ttfbMs) {
          flights.push(back(e.time.start + e.data.ttfbMs.value, `HTTP ${e.data.status?.value ?? ""} first bytes`));
        } else if (e.kind === "http.body" && e.data.wireBytes.value > 0) {
          flights.push(back(end, "HTTP body, last bytes"));
        }
        break;
      }
    }
  }

  // Only nodes something actually touched, in a stable order.
  const used = new Set(activities.flatMap((a) => [a.a, a.b]));
  const order: NodeRole[] = ["client-app", "os-resolver", "dns-server", "server"];
  return {
    nodes: nodes.filter((n) => n.role === "client-app" || used.has(n.id)).sort((x, y) => order.indexOf(x.role) - order.indexOf(y.role)),
    flights: flights.sort((x, y) => x.depart - y.depart),
    activities,
  };
}

function phaseOf(e: TraceEvent): Phase {
  switch (e.kind) {
    case "dns.lookup":
    case "dns.query":
      return "dns";
    case "tcp.connect":
      return "tcp";
    case "tcp.close":
      return "close";
    case "tls.handshake":
      return "tls";
    case "http.request":
      return "request";
    case "http.response":
      return "wait";
    case "http.body":
      return "download";
    case "http.redirect":
      return "redirect";
    case "guard.check":
      return "guard";
    case "url.parse":
      return "parse";
  }
}
