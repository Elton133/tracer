# Packet — Architecture (v0, for approval)

> "Make a real request. See what actually happened. Understand why."

Status: **proposal**. Nothing in here is implemented yet. Sections marked **DECISION** need your call.

Environment baseline: Next.js 16.3 (App Router), React 19.2, Tailwind v4, TypeScript strict, Node 24, Rust 1.99.

---

## Revision 1 (2026-10-02): the trace engine is Rust from V1

**Decision:** the engine is written once, in Rust (`engine/`). It is the Web Trace backend now and gains packet capture in V3. Next.js is the UI only. This supersedes the Node engine described in §B, §F, §G and §J. Everything else (the evidence rules, layer model, UI architecture and MVP scope) stands.

**What changes:**

| Was (Node) | Now (Rust) |
|---|---|
| `node:dns` lookup + c-ares `Resolver` | `getaddrinfo` via `tokio::net::lookup_host` (OS path) + **DNS messages we build and send ourselves** over UDP (`hickory-proto` encodes and decodes only; no resolver library) |
| `node:net` / `node:tls` | `tokio::net::TcpStream` + `rustls` (next phases) |
| Node `http` parser | write the HTTP/1.1 request ourselves, parse the head with `httparse`, handle body framing (Content-Length / chunked) ourselves |
| zod schemas as source of truth | **Rust types are the source of truth.** `cargo test` generates `core/generated/*.ts` (ts-rs) and `protocols.json`. The UI imports those, so there is no second copy to drift |
| `invariants` test in TS | `engine/src/model/invariants.rs`: walks the serialized trace; run in tests, in debug builds, and by the CLI on every trace |
| API = Next route handler running the engine | the engine runs as its own local process (`packetd`, step 4); the Next route proxies to it |
| V3 agent = separate Rust program | the same binary, plus a capture module |

**What we gain in observation:**
- Every DNS header bit, message ID, byte count, TTL and source port is observed, because Packet is the DNS client on the wire.
- Later, raw socket options. On macOS `TCP_CONNECTION_INFO` exposes the kernel's own smoothed RTT, congestion window and retransmit counts. That's real TCP state without pcap.

**Event model adjustments:**
- `protocol` is optional. Local steps like `url.parse` touch no protocol and light up no layer.
- `Payload` variants are added only as each phase is built.
- The engine never emits a "network path" entity. "Path abstracted" is purely a UI overlay, which keeps it outside observed data.

---

## A. Product architecture

Packet has three modes. They share one data model and one visual language, but they are separate in the UI and in the data, so observed and simulated material can never mix.

| Mode | What it is | Where data comes from | Evidence it may contain |
|---|---|---|---|
| **TRACE** (V1) | Enter a URL; Packet makes a real request and shows what happened | Trace engine (Node, server-side) | observed, derived (+ explained overlays added by the UI) |
| **LAB** (V2+) | Sliders and "BREAK IT" experiments | Simulator (pure TS, in the browser) | simulated (+ explained) |
| **LOCAL LAB** (V3) | Real packet capture of a request you start, on your own machine | Rust agent on localhost | observed (packet-level), derived |

The main product loop, which every feature should serve:

1. **Do**: run a real request (or a clearly labelled simulated one).
2. **See**: a journey, a waterfall, and layer views, all driven by the same timeline.
3. **Inspect**: click anything to see its fields, each one tagged with its evidence type.
4. **Understand**: "Learn from this request" tells the story of *this* trace, using its real values.

### The evidence rule, made structural

The four evidence types are not just labels. They define who is allowed to produce what:

- **The trace engine (server) emits only `observed` and `derived`.** It has no way to emit `explained`. If the server can't measure something, the field is missing. It is never filled in.
- **Explained content lives in a separate content library** and gets attached to observed events by the UI as *overlays*. Example: the SYN → SYN-ACK → ACK diagram is drawn inside the observed `tcp.connect` span.
- **The simulator emits only `simulated`.** A simulated trace has `kind: "simulated"` and can't be loaded into the TRACE workspace.
- Evidence is tracked **per field**, not just per event. One event can hold an observed duration, a derived RTT estimate, and no sequence numbers at all.

These boundaries can be checked automatically (schema validation plus a test that fails if the engine output ever contains `explained` or `simulated`). That's a much stronger guarantee than reviewing UI copy.

---

## B. Technical architecture

```
┌──────────────────────────── Browser ─────────────────────────────┐
│  Next.js client (React 19)                                       │
│                                                                  │
│  TraceSource ──► Trace (JSON, validated) ──► Workspace store     │
│   ├ WebTraceSource   (POST /api/trace)          │                │
│   ├ SimulatorSource  (V2, in-browser)           ▼                │
│   └ LocalAgentSource (V3, ws://127.0.0.1)   Playback clock (t)   │
│                                                 │                │
│        Content library ──► explain(trace) ──► overlays           │
│                                                 │                │
│   Views = f(trace, overlays, t, selection):                      │
│   Journey · Waterfall · DNS · TCP · TLS · HTTP · Encapsulation   │
│   OSI/TCP-IP strip · Inspector · Learn                           │
└──────────────────────────────────────────────────────────────────┘
              │ POST /api/trace { url }
              ▼
┌──────────── Next.js route handler (runtime: nodejs) ─────────────┐
│  Guard (URL policy, SSRF, rate/size/time limits)                 │
│  Trace engine — each layer done explicitly, in order:            │
│    dns.ts   → node:dns   (lookup = OS resolver; Resolver = c-ares)│
│    tcp.ts   → node:net   (connect to the vetted IP)              │
│    tls.ts   → node:tls   (wrap that socket; SNI, ALPN)           │
│    http1.ts → node:http over our socket (createConnection)       │
│    http2.ts → node:http2 over our socket (if ALPN = h2)          │
│    redirect.ts → new hop, repeat                                 │
│  Clock: process.hrtime.bigint(), one monotonic origin per trace  │
└──────────────────────────────────────────────────────────────────┘
              │ (V3)
┌──────────── packet-agent (Rust, localhost only) ─────────────────┐
│  Performs the request itself → knows the exact 5-tuple            │
│  libpcap capture with BPF filter on that flow only                │
│  Decodes Ethernet/IP/TCP/UDP/DNS/TLS records → same Trace schema  │
└──────────────────────────────────────────────────────────────────┘
```

### Key technical decisions

**1. Trace on the server, one layer at a time, without a high-level HTTP client.**
`fetch`/undici would give us a response and very little about how we got it. Instead the engine does the stack by hand: resolve → `net.connect(ip)` → `tls.connect({ socket, servername })` → HTTP over that socket. Each step has its own start and end timestamps and its own metadata. This is also the learning path: you'll write each layer yourself, in the same order the OS and network handle them.

**2. Connect to the IP we resolved, never re-resolve.**
We resolve once, check every address against the SSRF policy, then connect to a *specific* IP and pass the hostname only as TLS SNI and the HTTP `Host` header. That makes the trace honest (we know exactly which IP we talked to). It also closes the DNS-rebinding hole, where a hostname resolves to a public IP at check time and a private one at connect time.

**3. The trace takes about 1 s, so V1 returns a complete Trace in one JSON response. No streaming.**
The UI *replays* it. Real timings of 18 ms are too short to see, so playback uses an explicit time scale (for example "playing 25× slower than real"), always shown on screen. Streaming (SSE) can come later if traces get long, such as in Local Lab.

**4. Every view is a pure function of `(trace, t)`.**
One playback clock drives everything. Scrubbing, pausing, and clicking a waterfall bar (which sets `t` and the selection) then work the same way in every view. The journey, OSI strip, and encapsulation view stay in sync without coordinating with each other.

**5. Keep the stack small.**
- **Yes:** `zod` (validate trace at the API boundary and in tests), `motion` (Framer Motion, for encapsulation and journey animation), `vitest`.
- **Not in V1:**
  - React Flow: the V1 journey is a fixed, mostly linear topology. Hand-written SVG is simpler, and the animation along edges is custom anyway. Revisit if graphs become user-editable or large.
  - D3: the waterfall is just rectangles on a linear scale.
  - Web Workers: nothing heavy to parse until pcap in V3.
  - A state library: `useReducer` plus context is enough for one workspace.

**6. Build the engine CLI before any UI.**
`npm run trace -- https://example.com` prints the event list. You can compare it against `curl -w` (see §G) before a single pixel exists. curl is our reference for checking the numbers.

---

## C. Browser limitations and security constraints

### What a browser can't do (and why Packet traces server-side)

| Want | Browser reality |
|---|---|
| DNS lookup timing / results for an arbitrary host | No DNS API. Resolution happens inside the browser's network stack and isn't exposed. |
| TCP handshake, ports, seq/ack, flags | No raw sockets. JS never sees TCP. |
| TLS version, cipher, certificate | Not exposed to page JS. (DevTools shows them; pages can't.) |
| Fetch an arbitrary URL and read headers | Blocked by CORS unless the target allows it. Many headers are hidden even then. |
| Timing breakdown of a cross-origin request | Resource Timing API exists, but cross-origin entries are zeroed unless the server sends `Timing-Allow-Origin`. |
| Capture packets | Impossible. Requires OS privileges (BPF on macOS, `CAP_NET_RAW` on Linux). |

So in Web Trace mode the **trace server** makes the request, using Node's `dns`, `net`, `tls`, `http`, and `http2` modules, which do expose these details.

### The vantage-point problem (very important for honesty)

Every observation in Web Trace is *from the trace server's position on the network*, not from your browser.

- **Running `npm run dev` on your laptop:** the vantage point *is* your machine, your resolver, your ISP. Great for learning.
- **Deployed (for example on Vercel):** the vantage point is a datacenter. DNS answers, RTT, and even the IP chosen (CDN/anycast) can differ from what your browser would get.

The Trace includes a `vantage` block. The UI shows it at all times ("Observed from: this machine (dev server)" or "Observed from: Packet trace server, region X"). It never says "your request" without qualifying it.

A second subtlety: the **local address** we observe on the socket (for example `192.168.1.23:54012`) is not what the destination sees. Your router's NAT rewrites it to your public IP. Packet shows the local address as observed, and explains NAT as an explained overlay.

### What Node itself can't observe

Node runs in userland, above the kernel's TCP/IP stack. Through Node's APIs we **can't** see:
- individual TCP segments, SYN/SYN-ACK/ACK packets, sequence/ack numbers, window sizes, retransmissions (needs pcap; Linux `TCP_INFO` would give RTT/retransmits but Node doesn't expose it)
- individual TLS handshake messages (ClientHello, ServerHello, and so on) as structured data
- bytes on the wire including headers (`socket.bytesRead` counts application bytes after TLS decryption, not frame bytes)
- the network path (routers in between)
- Layer 2 / Layer 1 anything

**Timestamps are userland timestamps.** `hrtime` records when *our callback ran*, which is slightly after the kernel event and inflated if the event loop is busy. The UI labels this ("measured in the application, not on the wire"). V3 pcap timestamps will show the gap, which makes a good lesson in itself.

### Security constraints on the trace server

A server that fetches any URL a user types is a textbook **SSRF** risk. Requirements:

- **Schemes:** `http:` and `https:` only.
- **Ports:** 80 and 443 by default. Other ports only in local dev mode.
- **Address policy:** after DNS, reject *every* resolved address in: `0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16` (includes cloud metadata at 169.254.169.254), `172.16/12, 192.168/16, 198.18/15, 224/4, 240/4, ::1, ::/128, fc00::/7, fe80::/10, ::ffff:<private v4>`. Then connect only to the vetted IP (decision 2).
- **Redirects:** every hop goes through the full guard again, with a maximum of 10 hops and loop detection.
- **Limits:** a timeout per phase (DNS 5 s, TCP 5 s, TLS 5 s, TTFB 10 s, body 10 s). Body read is capped (for example 2 MB). Bytes are counted, but the body itself is **not** returned (only an optional 1–2 KB text preview).
- **Rate limiting** per client IP once deployed.
- **What we expose:** never TLS session keys (Node's `keylog` event exists, and we won't subscribe to it in Web Trace), never cookies the server sets on us beyond showing the `set-cookie` header names. No forwarding of the user's own cookies or headers.
- **Local dev flag** `PACKET_ALLOW_PRIVATE=1` lets you trace `localhost` and LAN hosts on your own machine (useful for test servers). It is never on in deployment.

**DECISION 1 — Certificate failures.** I propose `rejectUnauthorized: false` plus a manual check of `socket.authorized` / `authorizationError`. If verification fails (expired, hostname mismatch, untrusted), we record the failure as *observed* and **stop before sending HTTP**, like a browser would. This lets Packet show real cert failures (for example on `expired.badssl.com`) instead of a generic error. An optional "continue anyway" could come later.

---

## D. TraceEvent data model

Lives in `core/model/` (pure TypeScript, no Node or DOM imports, shared by server, client, simulator, and the future agent's JSON). Validated with zod at the API boundary.

```ts
// ── Evidence ──────────────────────────────────────────────
export type Evidence = "observed" | "derived" | "explained" | "simulated";

/** A single value plus how we know it. Every protocol field uses this. */
export interface Fact<T> {
  value: T;
  evidence: Evidence;
  /** Exact origin: an API or a derivation rule.
   *  e.g. "node:tls.TLSSocket.getProtocol()" or "derive:rtt≈tcp.connect.duration" */
  source: string;
  /** Caveat shown in the inspector, e.g. "userland timestamp" */
  note?: string;
}

// ── Trace (one run) ───────────────────────────────────────
export interface Trace {
  schemaVersion: 1;
  id: string;
  kind: "observed" | "simulated";          // never mixed
  source: "web-trace" | "local-agent" | "simulator";
  input: { url: string; method: "GET"; followRedirects: boolean };
  vantage: {
    description: string;                   // "This machine (next dev)"
    isUserMachine: boolean;
    runtime: string;                       // "node 24.20.0 / OpenSSL 3.x"
  };
  startedAt: string;                       // ISO wall-clock; all event times are offsets from this
  entities: Entity[];                      // nodes in the journey
  hops: Hop[];                             // one per request in a redirect chain
  events: TraceEvent[];                    // flat, ordered by time.start
  outcome: { ok: boolean; finalStatus?: number; error?: TraceError };
  packets?: CapturedPacket[];              // V3 only; absent in Web Trace
}

export interface Hop {
  index: number;
  url: string;
  connectionId: string;                    // which TCP/TLS connection carried it
  status?: number;
  redirectTo?: string;
}

// ── Entities (journey nodes) ──────────────────────────────
export interface Entity {
  id: string;
  role: "client-app" | "os" | "dns-resolver" | "network-path" | "server";
  label: string;                            // "Recursive resolver 192.168.1.1"
  addresses?: Fact<string>[];
  /** "network-path" is always { abstracted: true } in V1 — no invented routers */
  abstracted?: boolean;
  evidence: Evidence;                       // does this entity's existence come from observation?
}

// ── Events ────────────────────────────────────────────────
export interface TraceEvent<K extends EventKind = EventKind> {
  id: string;
  hopIndex: number;
  connectionId?: string;
  parentId?: string;                        // e.g. dns.resolve.aaaa under dns.phase
  kind: K;
  protocol: ProtocolId;                     // drives layer mapping (§E)
  evidence: Evidence;                       // evidence that this event happened, and its timing
  time: { start: number; end?: number };    // ms since trace start, monotonic (hrtime)
  from?: string;                            // Entity id
  to?: string;                              // Entity id
  status: "ok" | "error" | "timeout";
  data: EventData[K];                       // typed per kind, fields are Fact<>
  explainKey?: string;                      // hook into content library, e.g. "tcp.handshake"
}

export type EventKind =
  | "url.parse"
  | "dns.lookup"          // OS resolver path (getaddrinfo) — what apps actually use
  | "dns.query"           // direct query via c-ares Resolver, per record type
  | "guard.check"         // SSRF policy decision (shown: it's part of the real story)
  | "tcp.connect"
  | "tls.handshake"
  | "http.request"
  | "http.response.headers"
  | "http.response.body"
  | "http.redirect"
  | "connection.close"
  | "error";

export interface EventData {
  "url.parse": {
    scheme: Fact<"http" | "https">; host: Fact<string>; asciiHost: Fact<string>;
    port: Fact<number>; path: Fact<string>;           // port/asciiHost often derived (defaults, punycode)
  };
  "dns.lookup": { hostname: Fact<string>; addresses: Fact<{ address: string; family: 4 | 6 }[]> };
  "dns.query": {
    server: Fact<string>;                              // from resolver.getServers()
    recordType: Fact<"A" | "AAAA" | "CNAME" | "MX" | "TXT" | "NS">;
    answers: Fact<DnsAnswer[]>;                        // with TTL where Node provides it (A/AAAA)
    rcode?: Fact<string>;                              // e.g. ENODATA, ENOTFOUND
  };
  "guard.check": { address: Fact<string>; allowed: Fact<boolean>; rule?: Fact<string> };
  "tcp.connect": {
    remote: Fact<{ address: string; port: number }>;
    local: Fact<{ address: string; port: number }>;   // pre-NAT, see §C
    rttEstimate: Fact<number>;                         // derived: connect ≈ 1 RTT
  };
  "tls.handshake": {
    sni: Fact<string>; version: Fact<string>; cipher: Fact<{ name: string; standardName: string }>;
    alpn: Fact<string | false>; keyExchange?: Fact<{ type: string; name?: string; size: number }>;
    authorized: Fact<boolean>; authorizationError?: Fact<string>;
    chain: Fact<CertSummary[]>;                        // leaf → root, cycles removed
    roundTrips: Fact<number>;                          // derived from version: 1.3 → 1, 1.2 → 2
  };
  "http.request": {
    version: Fact<"HTTP/1.1" | "HTTP/2">; method: Fact<string>; target: Fact<string>;
    headers: Fact<[string, string][]>;                 // exactly what we sent, in order
    rawHead?: Fact<string>;                            // HTTP/1.1: the literal bytes of the request head
  };
  "http.response.headers": {
    status: Fact<number>; statusText?: Fact<string>;
    headers: Fact<[string, string][]>;
    ttfb: Fact<number>;                                // observed
    waitBreakdown: Fact<string>;                       // derived: "≈ server time + 1 RTT", can't split
    serverTiming?: Fact<ServerTimingEntry[]>;          // parsed Server-Timing header, if present
    altSvc?: Fact<string>;                             // e.g. advertises h3 — we didn't use it
  };
  "http.response.body": {
    bytes: Fact<number>; encoding?: Fact<string>; truncated: Fact<boolean>; preview?: Fact<string>;
  };
  "http.redirect": { from: Fact<string>; to: Fact<string>; status: Fact<number> };
  "connection.close": { initiatedBy: Fact<"client" | "server" | "unknown"> };
  error: { phase: Fact<string>; code: Fact<string>; message: Fact<string> };
}
```

**Explained overlays** (generated client-side, never part of the server payload):

```ts
export interface ExplainedOverlay {
  id: string;
  anchorEventId: string;          // the observed event it decorates
  evidence: "explained";
  explainKey: string;             // "tcp.handshake.3way"
  steps?: { label: string; from: string; to: string; relTime?: [number, number] }[];
  // relTime places steps *within* the anchor's observed span, proportionally —
  // the UI must render these as illustrative (dashed), never as measured instants.
}
```

**V3 packet records** (defined now so the schema doesn't change shape later):

```ts
export interface CapturedPacket {
  index: number; ts: number; wireLength: number; captureLength: number;
  flowId: string;                 // links to connectionId
  layers: DecodedLayer[];         // ethernet → ipv4/6 → tcp/udp → tls/dns
  raw?: string;                   // base64
}
export interface DecodedLayer {
  protocol: ProtocolId;
  byteRange: [number, number];    // for hex-view highlighting
  fields: { name: string; value: string; byteRange?: [number, number] }[];
}
```

### Deliberate departures from the example `TraceEvent` in your brief

- **No `osiLayer` / `tcpIpLayer` field on events.** The layer comes from `protocol` through one registry (§E). If every event stored its own layer, the same protocol would eventually be mapped differently in two places. A per-event override can be added if a real case needs one.
- **No free-text `explanation` on events.** Only an `explainKey` into the content library. Data stays data, and the text is written and reviewed in one place.
- **`evidence` exists at event level *and* per field (`Fact`).** "This TCP connection happened" (observed) is a different claim from "its RTT is about 24 ms" (derived).

---

## E. Protocol / layer model

One registry, `core/model/protocols.ts`:

```ts
export type OsiLayer = 1 | 2 | 3 | 4 | 5 | 6 | 7;
export type TcpIpLayer = "application" | "transport" | "internet" | "network-access";

export interface ProtocolInfo {
  id: ProtocolId;
  name: string;
  osi: { primary: OsiLayer; span?: OsiLayer[] };
  tcpip: TcpIpLayer;
  carriedBy?: ProtocolId[];       // dns → [udp, tcp]; http/1.1 → [tcp] or [tls]
  mappingNote?: string;           // shown whenever this mapping is displayed
}
```

| Protocol | OSI | TCP/IP | Note shown to the user |
|---|---|---|---|
| HTTP/1.1, HTTP/2 | 7 | Application | — |
| DNS | 7 | Application | Usually rides on UDP port 53 (TCP for large answers; DoH puts it inside HTTPS). |
| TLS | 6 (spans 5–6) | Application | TLS sits between the application and TCP. OSI has no clean slot for it. "Presentation/session" is a teaching convention, not a spec fact. TCP/IP just treats it as part of the application. |
| — (Session) | 5 | Application | No modern protocol in this trace *is* "layer 5". Session ideas (TLS sessions, HTTP/2 streams) are spread across other protocols. Packet says this rather than inventing one. |
| TCP, UDP | 4 | Transport | — |
| IPv4, IPv6 | 3 | Internet | — |
| (ICMP) | 3 | Internet | Control messages for IP. Used by ping and traceroute. |
| (ARP / NDP) | 2/3 | Network access | Maps IP to MAC addresses. Sits on the boundary. |
| Ethernet II, 802.11 Wi-Fi | 2 | Network access | — |
| PHY (copper, fibre, radio) | 1 | Network access | — |
| (QUIC, V2+ note only) | 4-ish | Transport | Runs over UDP, builds TLS 1.3 into the transport, and powers HTTP/3. A good example of where OSI stops fitting. |

**The OSI | TCP/IP toggle** changes only how the bottom strip is drawn, not the data. Because both are derived from the same registry, the strip can also show both side by side with brackets (OSI 5–7 ↔ TCP/IP Application, OSI 1–2 ↔ Network Access). The OSI view carries a permanent one-line caption: *"OSI is a conceptual model. The Internet is built on TCP/IP. Real protocols don't always fit one OSI layer."*

**Layers 1–3 in a Web Trace are always explained, never observed.** We know the destination IP (observed) and that IP was used. We never see an IP header, a frame, or a signal. The strip lights them up with a dashed or hatched style to show they were involved but not seen.

---

## F. MVP folder / module structure

```
network/                       (repo root; rename to packet/ whenever you like)
├─ app/                        Next.js routes only — thin
│  ├─ page.tsx                 home: "WHERE DOES YOUR REQUEST GO?"
│  ├─ trace/page.tsx           workspace (trace held in client state; ?url= to re-run)
│  ├─ lab/page.tsx             V2 placeholder
│  └─ api/trace/route.ts       POST → engine.run(), runtime nodejs
├─ core/                       isomorphic, zero Node/DOM imports
│  ├─ model/                   trace.ts, evidence.ts, protocols.ts, layers.ts
│  ├─ schema/                  zod schemas mirroring model/
│  └─ derive/                  pure derivations (rtt, waterfall phases, tls round trips)
├─ engine/                     server-only ("import 'server-only'")
│  ├─ run.ts                   orchestrates phases, builds Trace
│  ├─ clock.ts                 monotonic clock (hrtime) → ms offsets
│  ├─ phases/                  url.ts, dns.ts, tcp.ts, tls.ts, http1.ts, http2.ts, redirect.ts
│  ├─ guard/                   url-policy.ts, ip-policy.ts, limits.ts
│  └─ cli.ts                   `npm run trace -- <url>` → pretty event table
├─ content/                    explanations + lesson templates, keyed by explainKey
│  ├─ explain/                 tcp.handshake.ts, tls.13.ts, dns.recursive.ts, …
│  └─ lessons/                 buildLesson(trace) → ordered story steps
├─ ui/
│  ├─ workspace/               layout shell, store (reducer), playback clock
│  ├─ views/                   journey/, waterfall/, dns/, tcp/, tls/, http/, encapsulation/
│  ├─ layers/                  OSI/TCP-IP strip
│  ├─ inspector/               field tree with evidence badges
│  ├─ learn/                   "Learn from this request"
│  └─ primitives/              EvidenceBadge, Mono, Bytes, Duration, …
├─ test/
│  ├─ fixtures/servers/        local http/https test servers (self-signed, redirects, slow, 500)
│  └─ *.test.ts                engine against fixtures; invariant tests on evidence
├─ agent/                      V3 — Rust cargo workspace (empty until then)
└─ docs/                       this file, ADRs, lab notebook
```

Dependency direction: `ui → core`, `engine → core`, `content → core`. `core` imports nothing. `ui` never imports `engine`. The layout enforces that the browser can't accidentally ship server code, and that the simulator (V2, under `core/sim` or `sim/`) can reuse the same model.

---

## G. Request lifecycle — the first V1 trace

Tracing `https://example.com/` from `npm run dev` on your Mac:

| # | Step | What the engine does | OS/network level | Layer | We record |
|---|---|---|---|---|---|
| 0 | Submit | Browser `POST /api/trace {url}`. (This request is itself a full DNS/TCP/HTTP exchange to localhost. A nice aside later.) | — | — | — |
| 1 | Parse | `new URL()`; IDN → punycode; default port 443 | — | 7 | `url.parse` (scheme/host observed, port derived from default) |
| 2 | DNS (OS path) | `dns.lookup(host, {all:true})` | `getaddrinfo()` → macOS `mDNSResponder` → its cache or your configured resolver (often your router) over UDP/53 | 7 (over 4: UDP) | `dns.lookup`: addresses, duration. Run twice and the second is ~0 ms (OS cache, an observed lesson) |
| 3 | DNS (direct) | in parallel: `Resolver.resolve4/6({ttl:true})`, `resolveCname`, (`resolveNs/Mx/Txt` optional) | c-ares sends its own UDP queries to `resolver.getServers()` (bypasses the OS cache) | 7 | `dns.query` per type: server IP, answers, TTLs, errors like `ENODATA` |
| 4 | Guard | Check every address against the IP policy; pick one (first IPv4, unless only v6) | — | 3 (addresses) | `guard.check` (we explain *why* this IP, and mention Happy Eyeballs as explained) |
| 5 | TCP | `net.connect({host: ip, port: 443})`, time to the `'connect'` event | Kernel sends SYN, gets SYN-ACK, sends ACK. Node is notified once the handshake completes | 4 (over 3) | `tcp.connect`: local/remote 5-tuple, duration; RTT ≈ duration (derived). The SYN/SYN-ACK/ACK diagram is an *explained overlay* |
| 6 | TLS | `tls.connect({socket, servername: host, ALPNProtocols:['h2','http/1.1']})` until `'secureConnect'` | OpenSSL: ClientHello → ServerHello + EncryptedExtensions + Certificate + CertVerify + Finished → client Finished (TLS 1.3, 1 RTT) | 5–6 / App | `tls.handshake`: version (`getProtocol`), cipher (`getCipher`), key exchange (`getEphemeralKeyInfo`), ALPN, chain (`getPeerCertificate(true)`), authorized/error. Message sequence = explained overlay |
| 7 | HTTP request | ALPN `http/1.1` → `http.request({createConnection: () => tlsSocket})`; ALPN `h2` → `http2.connect(origin, {createConnection})` | Bytes go into TLS records, then TCP segments, then IP packets, then frames | 7 | `http.request`: exact headers sent; HTTP/1.1 literal request head |
| 8 | Wait / TTFB | time from request flushed to response headers | Server processing + ≥ 1 RTT; can't be separated from here | 7 | `ttfb` observed; breakdown derived; `Server-Timing` if sent |
| 9 | Body | read up to the cap, count bytes, don't decompress (so the count is the transfer size) | TCP flow control and congestion control live here (invisible to us) | 7 | `http.response.body`: bytes, encoding, truncated |
| 10 | Redirect? | 3xx + `Location` → new hop back to step 1 (new connection in V1; reuse is a V2 lesson) | — | 7 | `http.redirect`, next hop |
| 11 | Close | `socket.end()` | FIN/ACK exchange (explained) | 4 | `connection.close` |
| 12 | Assemble | build `Trace`, run `derive/`, validate with zod, return | — | — | — |
| 13 | Replay | client builds explained overlays, starts playback clock at a visible time scale | — | — | — |

### Your first experiments (run these before we write the engine)

Each one is the command-line version of a phase above. They become our reference for checking the numbers.

```bash
# 2–3: DNS. Compare OS path vs direct query, and see TTLs count down
scutil --dns | head -30                 # which resolver macOS is actually using
dig example.com A +noall +answer +stats  # run twice: TTL decreases, Query time
dig example.com AAAA +short
dig example.com +trace                  # real root → TLD → authoritative walk (V2 DNS Explorer does this in-app)
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder   # clear OS cache, re-run step 2

# 5–9: the whole timeline in one curl — this is Packet's oracle
curl -so /dev/null https://example.com -w '\
dns      %{time_namelookup}\ntcp      %{time_connect}\ntls      %{time_appconnect}\n\
ttfb     %{time_starttransfer}\ntotal    %{time_total}\nhttp     %{http_version}\nip       %{remote_ip}\n'
# (curl's numbers are cumulative from start — our waterfall will show the per-phase deltas)

# 6: TLS
openssl s_client -connect example.com:443 -servername example.com -alpn h2,http/1.1 </dev/null 2>/dev/null \
  | grep -E 'Protocol|Cipher|ALPN|subject=|issuer=|Verify return'
curl -sv https://example.com -o /dev/null 2>&1 | grep -E '^\* (SSL|ALPN|subject|issuer|expire)'

# 5 + 11: watch the real SYN/SYN-ACK/ACK and FIN that Node can't see
sudo tcpdump -i en0 -n 'tcp port 443 and host example.com and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0)'
#   …then in another terminal: curl -so /dev/null https://example.com

# Path: what V1 deliberately *doesn't* claim to know
traceroute -n example.com
```

---

## H. What V1 genuinely observes

**Observed** (measured directly, with the API named in `Fact.source`):
- Resolved addresses (OS path) and per-record-type answers (A, AAAA, CNAME; NS/MX/TXT on request), DNS TTLs for A/AAAA, DNS errors
- Which DNS server c-ares queried. *Not* necessarily the one the OS path used. The UI says so.
- Duration of each phase: DNS lookup, TCP connect, TLS handshake, request write, TTFB, body download, total (userland timestamps)
- Local and remote IP:port of the TCP connection (local = pre-NAT)
- TLS: negotiated version, cipher suite, key-exchange group, ALPN result, SNI we sent, full certificate chain (subject, issuer, SAN, validity, serial, fingerprint, key type/size), verification result and error
- HTTP: protocol version, exact request headers sent (and literal request head for HTTP/1.1), status, all response headers, `Server-Timing`, `Alt-Svc`, transfer byte count, content encoding
- Redirect chain: each hop's status, `Location`, and its own full DNS/TCP/TLS/HTTP phases
- Failures: `ENOTFOUND`, `ECONNREFUSED`, `ETIMEDOUT`, `ECONNRESET`, cert errors, all as real observed events

**Derived** (computed from the above, with the rule named):
- RTT estimate ≈ TCP connect duration
- TLS round trips from version (1.3 → 1 RTT, 1.2 → 2 RTT)
- "Server wait" ≈ TTFB − ~1 RTT (approximate, labelled as such)
- Certificate days-until-expiry, whether the SAN matches the host, chain length
- Default port, punycode hostname, whether the request was cross-origin redirected
- HTTP/3 *available* (from `Alt-Svc`), but not used

---

## I. Explanatory (not observed) in V1

Rendered with the explained style (dashed lines, hatched fills, `EXPLAINED` badge):

- SYN → SYN-ACK → ACK and FIN sequence diagrams (drawn *inside* the observed connect/close spans)
- TLS handshake message ladder (ClientHello, ServerHello, …), drawn inside the observed handshake span
- Recursive DNS walk: OS cache → recursive resolver → root → TLD → authoritative. The observed resolver and answers are marked as observed. Root/TLD/authoritative stay explained until the V2 DNS Explorer actually performs iterative resolution.
- The network path / routers / ISP: one dashed node, **"Path abstracted"**
- The encapsulation animation (HTTP → TLS record → TCP segment → IP packet → frame → bits). Header *field values* we really know (ports, IPs, byte counts) are filled in and tagged observed. Everything else (seq numbers, TTL, MAC addresses, checksums) is shown as a field name with no value and the label "not visible from the application".
- OSI layers 1–3 lighting up
- NAT (local address vs public address)
- "Before TLS: `GET /` / After: `[ENCRYPTED TLS APPLICATION DATA]`". The plaintext is observed (we wrote it). The ciphertext block is explained, because we never see the record bytes in V1. Caption: *"Packet sees plaintext because Packet is the client. Someone capturing your traffic would see only the encrypted records."*

---

## J. Implementation order

Each step ends with something you can run, plus a short "what's happening underneath" note and an experiment, per your learning principle. You write or drive the networking code; I explain and review.

1. **Model first.** `core/model` + zod schemas + protocol registry + evidence-invariant tests. No networking yet.
2. **Engine CLI, one layer per step.** Each one is verified against the matching `dig`/`curl`/`openssl` command:
   1. URL parse + DNS (`lookup` vs `Resolver`, and why they differ)
   2. TCP connect to a chosen IP (watch it with `tcpdump` at the same time)
   3. TLS over that socket (compare with `openssl s_client`)
   4. HTTP/1.1 over that socket, then HTTP/2 via ALPN
   5. Redirects + the error taxonomy
3. **Guard + test fixtures.** SSRF policy with unit tests; local fixture servers (self-signed TLS, redirect chain, slow TTFB, 500, connection reset).
4. **API route.** `POST /api/trace` → validated Trace.
5. **Workspace shell + playback clock + waterfall.** The first view, the most literal one, built straight from observed numbers.
6. **Inspector + evidence badges.** Click any bar or field to see its value and source.
7. **Journey view** (SVG + motion), with "Path abstracted".
8. **OSI / TCP-IP strip** with the toggle and mapping notes.
9. **Protocol views:** DNS, TCP (with explained ladder), TLS (cert chain + encryption before/after), HTTP.
10. **Encapsulation animation.**
11. **Learn from this request:** lesson builder that walks the actual events.
12. **Home page + visual polish pass.**

Steps 1–4 contain no UI at all. That's on purpose: if the data is wrong, the visuals don't matter.

---

## Technical risks

| Risk | Impact | Mitigation |
|---|---|---|
| Users read datacenter observations as "my request" | Undermines the honesty principle | Vantage block always visible. V1 is designed to run locally first |
| Userland timing jitter (event loop, first-call JIT/OpenSSL init) | Misleading small numbers | Single trace per request, no concurrent work; label "application-measured"; optional warm-up flag; check against curl |
| `dns.lookup` and `Resolver` disagree (different servers, caches) | Confusing DNS view | Show both, explain why. That's a real lesson, not a bug |
| HTTP/2 over a hand-supplied socket has fewer timing hooks than HTTP/1.1 | Coarser h2 timing | Accept for V1; record what `http2` exposes (`'response'` / stream events); note it |
| Cert chain object from Node is cyclic at the root | Crash or infinite loop | Walk by fingerprint, stop on repeat |
| Hostile targets (huge bodies, slowloris, redirect loops, tarpits) | Hung or expensive server | Per-phase timeouts, byte cap, hop cap, loop detection |
| SSRF once deployed | Security incident | §C guard, resolve-once/connect-to-IP, fixtures that test private ranges and rebinding |
| OSI mapping pedantry | Teaching something false | One registry with written notes, reviewed once |
| Animation work outgrowing data work | Pretty but shallow | Waterfall (literal) before journey (interpretive); engine before UI |
| V3 capture privileges (macOS BPF needs root or ChmodBPF; Linux CAP_NET_RAW) | Setup friction, security | Separate agent binary, localhost-only, per-session pairing token, capture filter limited to the agent's own flow |
| Local Lab TLS decryption of *own* traffic | Scope/ethics confusion | Only for connections the agent itself opens (it holds the keys); never offered for other traffic |

---

## Open decisions for you

1. **Cert failures:** stop before HTTP and record the failure as observed (proposed), or continue?
2. **HTTP/1.1 implementation:** use Node's `http` parser over our socket (proposed for V1), or write the HTTP/1.1 request and response parser yourself as a learning exercise? The second is very instructive (chunked encoding, `Content-Length`, keep-alive) but adds about a week.
3. **Deployment target:** local-only for V1 (proposed: honest vantage point, no SSRF exposure), or deploy publicly early?
4. **V3 agent design:** the agent performs the request itself in Rust (clean 5-tuple, can hold TLS keys for its own traffic), or the Node engine performs it while the agent only captures? I lean toward the former. We can decide at V3.
