// Which layers are involved at a moment in the trace, and how we know.
//
// An event names one protocol, but every network event involves a whole
// stack underneath it. This module rebuilds that stack per event, giving
// each layer its own evidence:
//   observed : Packet saw it (bytes it wrote, records it read, its own socket)
//   derived  : inferred (IPv4 vs IPv6 from the address family)
//   explained: certainly happened, never seen (the link layer, the signal)
//
// Layer placement comes from the engine's registry (protocols.json, generated
// from engine/src/model/protocol.rs), never from a second table here.

import registry from "../generated/protocols.json";
import type { ProtocolId } from "../generated/ProtocolId";
import type { ProtocolInfo } from "../generated/ProtocolInfo";
import type { TcpIpLayer } from "../generated/TcpIpLayer";
import type { Trace } from "../generated/Trace";
import type { TraceEvent } from "../generated/TraceEvent";

export type LayerEvidence = "observed" | "derived" | "explained";

/** A protocol in the stack, or the link/physical layers we can't name. */
export type StackProtocol = ProtocolId | "link" | "signal";

export interface StackEntry {
  protocol: StackProtocol;
  name: string;
  evidence: LayerEvidence;
  osi: number[];
  tcpip: TcpIpLayer;
  note?: string;
}

export interface EventStack {
  eventId: string;
  start: number;
  end: number;
  entries: StackEntry[];
}

const INFO = new Map((registry as ProtocolInfo[]).map((p) => [p.id, p]));

function entry(protocol: ProtocolId, evidence: LayerEvidence, note?: string): StackEntry {
  const p = INFO.get(protocol)!;
  return { protocol, name: p.name, evidence, osi: p.osiSpan, tcpip: p.tcpip, note: note ?? p.mappingNote };
}

const LINK: StackEntry = {
  protocol: "link",
  name: "Ethernet / Wi-Fi",
  evidence: "explained",
  osi: [2],
  tcpip: "network-access",
  note: "Some link carried these packets as frames, but a web trace can't see frames or even tell which kind of link it was. Local Lab capture can.",
};
const SIGNAL: StackEntry = {
  protocol: "signal",
  name: "signal",
  evidence: "explained",
  osi: [1],
  tcpip: "network-access",
  note: "Bits as voltage, light or radio. Never visible to software above the network card.",
};

/** IP version per connection, from the address we connected to. */
function ipVersions(trace: Trace): Map<string, ProtocolId> {
  const m = new Map<string, ProtocolId>();
  for (const e of trace.events) {
    if (e.kind === "tcp.connect" && e.connectionId) {
      m.set(e.connectionId, e.data.remote.value.address.includes(":") ? "ipv6" : "ipv4");
    }
  }
  return m;
}

function ip(version: ProtocolId | undefined): StackEntry[] {
  if (!version) return [];
  return [
    entry(version, "derived", `${version === "ipv6" ? "IPv6" : "IPv4"}, known from the address family. Packet never sees an IP header from a normal socket.`),
  ];
}

export function stackOf(e: TraceEvent, versions: Map<string, ProtocolId>): StackEntry[] | null {
  const v = e.connectionId ? versions.get(e.connectionId) : undefined;
  const below = (ver: ProtocolId | undefined) => [...ip(ver), LINK, SIGNAL];
  switch (e.kind) {
    case "url.parse":
    case "guard.check":
    case "http.redirect":
      return null; // local decisions: no protocol on the wire
    case "dns.lookup":
      return [
        entry("dns", "observed", "Packet asked the OS to resolve the name. Whether the OS then sent DNS over the network or answered from its cache isn't visible."),
        entry("udp", "explained", "If the OS went to the network, a UDP datagram to port 53 is the usual carrier."),
      ];
    case "dns.query": {
      const ver: ProtocolId = e.data.server.value.address.includes(":") ? "ipv6" : "ipv4";
      return [entry("dns", "observed"), entry("udp", "observed", "Packet's own UDP socket carried this query."), ...below(ver)];
    }
    case "tcp.connect":
    case "tcp.close":
      return [entry("tcp", "observed", "Packet's socket, with the kernel's TCP statistics."), ...below(v)];
    case "tls.handshake":
      return [entry("tls", "observed"), entry("tcp", "observed"), ...below(v)];
    case "http.request":
    case "http.response":
    case "http.body": {
      const overTls = e.data.tlsRecords !== undefined;
      return [entry("http/1.1", "observed"), ...(overTls ? [entry("tls", "observed")] : []), entry("tcp", "observed"), ...below(v)];
    }
  }
}

export function buildStacks(trace: Trace): EventStack[] {
  const versions = ipVersions(trace);
  return trace.events.flatMap((e) => {
    const entries = e.time.end === undefined ? null : stackOf(e, versions);
    return entries ? [{ eventId: e.id, start: e.time.start, end: e.time.end!, entries }] : [];
  });
}

export const OSI_LAYERS = [
  { n: 7, name: "Application" },
  { n: 6, name: "Presentation" },
  { n: 5, name: "Session" },
  { n: 4, name: "Transport" },
  { n: 3, name: "Network" },
  { n: 2, name: "Data link" },
  { n: 1, name: "Physical" },
] as const;

export const TCPIP_LAYERS: { id: TcpIpLayer; name: string; osi: string }[] = [
  { id: "application", name: "Application", osi: "OSI 5–7" },
  { id: "transport", name: "Transport", osi: "OSI 4" },
  { id: "internet", name: "Internet", osi: "OSI 3" },
  { id: "network-access", name: "Network access", osi: "OSI 1–2" },
];
