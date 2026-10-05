// What happens at each step, written once and shown wherever that step
// appears (info popovers, the inspector). Keyed by the `explainKey` the
// engine puts on each event. All of it is EXPLAINED material: general
// knowledge about how the step works, never data from this trace, except
// the optional `inTrace` line, which is computed from observed values.

import type { TraceEvent } from "../core/generated/TraceEvent";
import { ms } from "../ui/primitives/format";

export interface Explanation {
  title: string;
  /** One or two sentences: the point of this step. */
  summary: string;
  /** What actually happens, at the OS / protocol level. */
  happens: string[];
  layer: string;
  /** What Packet can observe here, and what it can't. */
  sees: string;
  cannot?: string;
  /** Something to run yourself. */
  tryIt?: string;
  /** One line about this trace, from observed values. */
  inTrace?: (e: TraceEvent) => string | null;
}

const span = (e: TraceEvent) => (e.time.end === undefined ? null : e.time.end - e.time.start);

const LIBRARY: Record<string, Explanation> = {
  "url.parse": {
    title: "Parse the URL",
    summary: "Before anything touches the network, the text you typed is split into a scheme, host, port and path.",
    happens: [
      "The scheme picks the protocol and the default port: https → 443, http → 80.",
      "International hostnames are converted to punycode (münchen.de → xn--mnchen-3ya.de), because DNS only carries ASCII.",
      "The #fragment is dropped here. It never leaves your machine.",
    ],
    layer: "Local: no network yet",
    sees: "Everything: this step is pure computation.",
    tryIt: `node -e "console.log(new URL('https://münchen.de:8443/a?b=1#c'))"`,
  },

  "dns.os-resolver": {
    title: "Ask the operating system for an address",
    summary: "Connections go to IP addresses, not names. getaddrinfo() asks the OS to turn the hostname into addresses, exactly as a browser or curl would.",
    happens: [
      "The OS checks /etc/hosts and its own cache first (mDNSResponder on macOS).",
      "On a miss it sends a DNS query, usually one UDP datagram to port 53 of your configured resolver, often your router.",
      "That recursive resolver walks root → top-level domain → authoritative servers if it hasn't cached the answer.",
      "Each answer carries a TTL: how many seconds anyone may keep it cached.",
    ],
    layer: "Application (DNS), normally carried by UDP",
    sees: "The addresses returned and how long the call took.",
    cannot: "Whether the OS answered from cache or asked the network, or which server it asked.",
    tryIt: "dig example.com +stats    # then run it again and compare Query time",
    inTrace: (e) => {
      const d = span(e);
      if (d === null) return null;
      return d < 5
        ? `Answered in ${ms(d)}: almost certainly from the OS cache.`
        : `Took ${ms(d)}, so the OS probably had to ask the network.`;
    },
  },

  "dns.query": {
    title: "Packet's own DNS query",
    summary: "To show the DNS protocol itself, Packet builds a query message and sends it to the resolver directly, bypassing the OS cache.",
    happens: [
      "The message is a 12-byte header (a random ID and flags) plus the question: a name and a record type. A is IPv4, AAAA is IPv6.",
      "It goes out as one UDP datagram to port 53. UDP has no connection and no delivery guarantee: if it's lost, the client just waits and retries.",
      "The reply must echo the same ID. Its answers each carry a TTL. The RD/RA flags say recursion was asked for and is available.",
    ],
    layer: "Application (DNS) over UDP",
    sees: "Every byte of the DNS message both ways.",
    cannot: "How the resolver found the answer: its own queries further up are invisible.",
    tryIt: "dig @1.1.1.1 example.com A +noall +answer +stats",
    inTrace: (e) => (e.kind === "dns.query" && e.data.response ? `${e.data.queryBytes.value} bytes out, ${e.data.response.bytes.value} bytes back, in ${ms(span(e) ?? 0)}.` : null),
  },

  "guard.ssrf": {
    title: "Address safety check",
    summary: "Before any packet is sent, Packet checks that each resolved address is an ordinary public one.",
    happens: [
      "Loopback (127.0.0.0/8), private ranges (10/8, 172.16/12, 192.168/16), link-local (169.254/16, including cloud metadata) and others are refused.",
      "IPv4 addresses disguised as IPv6 (::ffff:127.0.0.1) are unwrapped first.",
      "Packet then connects to exactly the address it checked, so a second DNS answer can't swap it for a private one (DNS rebinding).",
    ],
    layer: "Local decision",
    sees: "Everything: this is Packet's own rule.",
    tryIt: "npm run trace -- http://127.0.0.1    # refused before any packet is sent",
  },

  "tcp.handshake": {
    title: "Open a TCP connection",
    summary: "TCP turns unreliable packets into a reliable, ordered byte stream. Opening one takes a three-way handshake, so a full round trip before any data.",
    happens: [
      "Your kernel sends SYN: a random starting sequence number plus options (maximum segment size, window scaling, SACK, timestamps).",
      "The server answers SYN-ACK: its own sequence number, acknowledging yours.",
      "Your kernel sends ACK, connect() returns, and the connection is ESTABLISHED.",
      "If nothing listens on the port, the server answers RST instead: \"connection refused\".",
    ],
    layer: "Transport (TCP) over Internet (IP)",
    sees: "When connect() started and returned, both endpoints, and the kernel's own statistics for the socket (RTT, MSS, windows).",
    cannot: "The SYN, SYN-ACK and ACK packets themselves. Only packet capture shows those.",
    tryIt: "sudo tcpdump -i en0 -n 'tcp[tcpflags] & tcp-syn != 0'",
    inTrace: (e) => {
      const d = span(e);
      return d === null || e.status !== "ok" ? null : `Connected in ${ms(d)}, so one round trip to this server takes about ${ms(d)}.`;
    },
  },

  "tcp.close": {
    title: "Close the connection",
    summary: "Each side says it's done sending (FIN) and the other acknowledges it, so closing takes two half-closes.",
    happens: [
      "Packet calls shutdown(): its kernel sends FIN, meaning \"I won't send any more\".",
      "The server acknowledges it and, once done, sends its own FIN. Packet's read() returns 0.",
      "The side that closed first waits in TIME_WAIT (up to about a minute), so stray late packets can't be mistaken for a new connection.",
    ],
    layer: "Transport (TCP)",
    sees: "When each side finished, and the kernel's final state (TIME_WAIT).",
    cannot: "The FIN and ACK packets themselves.",
    tryIt: "netstat -an -p tcp | grep TIME_WAIT",
  },

  "tls.handshake": {
    title: "TLS handshake",
    summary: "Agree on keys without ever sending them, prove the server is who it claims to be, then encrypt everything.",
    happens: [
      "ClientHello: the TLS versions and ciphers Packet supports, a key share, and the server name (SNI), which is not encrypted.",
      "ServerHello: the server picks a cipher and sends its key share. Both sides now compute the same secret (ECDHE) that never crossed the network.",
      "The server sends its certificate chain and signs the handshake with the certificate's private key, proving it holds that key. Packet checks the chain up to a trusted root.",
      "Finished messages on both sides confirm nobody tampered with any of it.",
    ],
    layer: "Between the application and TCP (OSI 5–6 by convention)",
    sees: "Every record's header, the negotiated version, cipher and key exchange, and the full certificate chain.",
    cannot: "Anyone on the network, including Packet's byte-level tap, sees only ciphertext after ServerHello. Packet records no keys.",
    tryIt: "openssl s_client -connect example.com:443 -servername example.com -msg </dev/null",
    inTrace: (e) =>
      e.kind === "tls.handshake" && e.data.version
        ? `${e.data.version.value} with ${e.data.cipherSuite?.value ?? "?"}, in ${ms(span(e) ?? 0)}.`
        : null,
  },

  "http.request": {
    title: "Send the HTTP request",
    summary: "HTTP/1.1 is plain text: a request line, headers, and a blank line.",
    happens: [
      "\"GET /path HTTP/1.1\", then headers such as Host, each line ending in \\r\\n, and an empty line to end the head.",
      "Over https these bytes go into the TLS layer, which encrypts them into a record.",
      "The kernel splits whatever it's given into TCP segments. With TCP_NODELAY set, small writes leave immediately.",
    ],
    layer: "Application (HTTP), over TLS when https",
    sees: "The exact bytes Packet wrote.",
    tryIt: "curl -v --http1.1 https://example.com -o /dev/null",
  },

  "http.response": {
    title: "Wait for the response",
    summary: "Time to first byte covers the trip to the server, the server's work, and the trip back.",
    happens: [
      "The request reaches the server, which runs its code or serves a cached copy.",
      "It answers with a status line (\"HTTP/1.1 200 OK\") and headers, then a blank line.",
      "Packet can't separate network time from server time; subtracting the TCP round trip gives a rough estimate.",
    ],
    layer: "Application (HTTP)",
    sees: "When the first byte arrived and the full response head.",
    cannot: "What the server did internally, unless it says so in a Server-Timing header.",
    tryIt: "curl -so /dev/null -w 'ttfb %{time_starttransfer}\\n' https://example.com",
    inTrace: (e) => (e.kind === "http.response" && e.data.ttfbMs ? `First byte after ${ms(e.data.ttfbMs.value)}.` : null),
  },

  "http.framing": {
    title: "Know where the body ends",
    summary: "The connection stays open after a response, so nothing on the wire marks the end of one. The headers have to say.",
    happens: [
      "Content-Length: exactly this many bytes follow the head.",
      "Transfer-Encoding: chunked: a series of \"<size in hex>\\r\\n<data>\\r\\n\", ending with a zero-size chunk. Used when the server doesn't know the size up front.",
      "Neither: the body runs until the server closes the connection.",
      "When Transfer-Encoding and Content-Length disagree, a proxy and a server that resolve it differently can be tricked into seeing different requests (request smuggling).",
    ],
    layer: "Application (HTTP)",
    sees: "Every byte of the body and its framing.",
    tryIt: "curl -s --raw --http1.1 https://example.com | head -c 200 | xxd | head",
  },

  "http.redirect": {
    title: "Follow a redirect",
    summary: "A 3xx status with a Location header means \"what you want is over there\". Packet starts a new hop: new lookup, new connection.",
    happens: [
      "301 and 308 are permanent: browsers and caches may remember them.",
      "302, 303 and 307 are temporary.",
      "307 and 308 require the same method and body. 301/302 let clients switch to GET, and 303 requires it.",
      "A relative Location (\"/login\") is resolved against the current URL.",
    ],
    layer: "Application (HTTP)",
    sees: "The status and Location header, and every step of the next hop.",
    tryIt: "curl -sIL http://github.com | grep -iE '^(HTTP|location)'",
  },

  http: {
    title: "The HTTP exchange",
    summary: "Request out, then response head, then body. Everything the application actually asked for happens here.",
    happens: [
      "Send the request: a request line, headers, and a blank line.",
      "Wait for the first byte of the response (TTFB).",
      "Read the body until its framing says it's complete.",
    ],
    layer: "Application (HTTP)",
    sees: "The exact bytes in both directions, as plaintext, because Packet is the client.",
  },
};

/** The explanation for an event: by its explainKey, or its kind, or the key's family. */
export function explanationFor(e: Pick<TraceEvent, "kind" | "explainKey">): Explanation | null {
  return explanation(e.explainKey ?? e.kind) ?? explanation(e.kind);
}

export function explanation(key: string): Explanation | null {
  if (LIBRARY[key]) return LIBRARY[key];
  // "http.redirect.301" → "http.redirect", "http.framing.chunked" → "http.framing"
  const parent = key.split(".").slice(0, -1).join(".");
  return parent ? explanation(parent) : null;
}
