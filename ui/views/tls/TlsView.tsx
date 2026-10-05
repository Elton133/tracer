"use client";

import { useMemo, useState } from "react";

import { buildTlsView, tlsHops, type ChainCert, type LadderRecord, type TlsView as View } from "@/core/derive/tls";
import type { Evidence } from "@/core/generated/Evidence";
import type { TraceEvent } from "@/core/generated/TraceEvent";
import { EvidenceBadge } from "@/ui/primitives/EvidenceBadge";
import { ms } from "@/ui/primitives/format";
import { useWorkspace } from "@/ui/workspace/store";

export function TlsView() {
  const { trace } = useWorkspace().state;
  const hops = useMemo(() => tlsHops(trace), [trace]);
  const [hop, setHop] = useState(hops[0]);
  const view = useMemo(() => (hop === undefined ? null : buildTlsView(trace, hop)), [trace, hop]);

  if (!view) return <NoTls />;

  return (
    <div className="mx-auto max-w-5xl space-y-10 px-6 py-6">
      {hops.length > 1 && (
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-faint uppercase">Handshake on</span>
          {hops.map((h) => (
            <button
              key={h}
              type="button"
              onClick={() => setHop(h)}
              className={`rounded border px-2 py-0.5 ${h === hop ? "border-fg text-fg" : "border-line-strong text-muted hover:text-fg"}`}
            >
              hop {h}
            </button>
          ))}
        </div>
      )}
      <Negotiated view={view} />
      <Ladder view={view} />
      {view.encryption && <Observer view={view} />}
      {view.chain.length > 0 && <Chain view={view} />}
    </div>
  );
}

function Section({ title, sub, children }: { title: string; sub?: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="font-mono text-[11px] tracking-[0.16em] text-muted uppercase">{title}</h2>
      {sub && <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-faint">{sub}</p>}
      <div className="mt-4">{children}</div>
    </section>
  );
}

// ── Negotiated parameters ─────────────────────────────────────────────

function Negotiated({ view }: { view: View }) {
  const d = view.handshake.data;
  const failed = view.handshake.status !== "ok";
  const items: { k: string; v?: string; ev: Evidence; src?: string; bad?: boolean }[] = [
    { k: "Version", v: d.version?.value, ev: "observed", src: d.version?.source },
    { k: "Cipher suite", v: d.cipherSuite?.value, ev: "observed", src: "how records are encrypted and authenticated" },
    { k: "Key exchange", v: d.keyExchange?.value, ev: "observed", src: "how both sides agreed on keys without sending them" },
    { k: "ALPN", v: d.alpn ? (d.alpn.value ?? "none") : undefined, ev: "observed", src: `offered: ${d.alpnOffered.value.join(", ")}` },
    { k: "Certificate", v: d.verification?.value, ev: "observed", src: d.trustStore.value, bad: d.verification?.value !== "valid" },
    { k: "Round trips", v: d.roundTrips ? String(d.roundTrips.value) : undefined, ev: "derived", src: d.roundTrips?.source },
    { k: "Handshake took", v: view.handshake.time.end !== undefined ? ms(view.handshake.time.end - view.handshake.time.start) : undefined, ev: "observed", src: "ClientHello sent → handshake complete" },
  ];
  return (
    <Section title={failed ? "Handshake failed" : "Negotiated"} sub={failed ? view.handshake.error?.value.message : undefined}>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3 lg:grid-cols-4">
        {items
          .filter((x) => x.v !== undefined)
          .map((x) => (
            <div key={x.k} className="min-w-0">
              <dt className="flex items-center gap-2 text-[11.5px] text-muted">
                {x.k} <EvidenceBadge evidence={x.ev} />
              </dt>
              <dd className={`mt-1 font-mono text-[13px] break-words ${x.bad ? "text-p-error" : "text-fg"}`}>{x.v}</dd>
              {x.src && <dd className="mt-0.5 text-[11px] leading-snug text-faint">{x.src}</dd>}
            </div>
          ))}
      </dl>
    </Section>
  );
}

// ── Record ladder ─────────────────────────────────────────────────────

function Ladder({ view }: { view: View }) {
  const { state, dispatch } = useWorkspace();
  const { t } = state;

  return (
    <Section
      title="Every TLS record, in order"
      sub="Read from the 5-byte header each record starts with. Sizes include that header. Times are when Packet wrote or read the bytes. Contents are named only while they're unencrypted."
    >
      <div className="grid grid-cols-[64px_120px_minmax(0,1fr)_120px] font-mono text-[11px] text-faint uppercase">
        <span />
        <span>Packet</span>
        <span />
        <span className="text-right">Server</span>
      </div>
      <div className="mt-1">
        {view.ladder.map((r) => {
          const rows: React.ReactNode[] = [];
          if (r.i === 0 || view.ladder[r.i - 1].phase !== r.phase) {
            rows.push(
              <PhaseDivider key={`p-${r.i}`} label={{ handshake: "Handshake", request: "HTTP request", response: "HTTP response" }[r.phase]} />,
            );
          }
          if (r.i === view.encryptedFrom.sent) rows.push(<EncryptionDivider key="enc-s" who="Packet → server" />);
          if (r.i === view.encryptedFrom.received) rows.push(<EncryptionDivider key="enc-r" who="server → Packet" />);
          rows.push(<LadderRow key={r.i} r={r} lit={t >= r.atMs} onClick={() => dispatch({ type: "select", id: r.eventId })} />);
          return rows;
        })}
      </div>
      {view.ladder.some((r) => r.explainedContents) && (
      <p className="mt-3 text-[11px] text-faint">
        <span className="hatch-soft rounded-[2px] border border-dashed border-faint px-1 text-muted">dashed</span> labels are{" "}
        <span className="text-muted">explained</span>: what TLS 1.3 puts inside records nobody but the two endpoints can read.
      </p>
      )}
    </Section>
  );
}

function PhaseDivider({ label }: { label: string }) {
  return (
    <div className="mt-4 mb-1 grid grid-cols-[64px_minmax(0,1fr)] font-mono text-[10px] tracking-[0.14em] text-faint uppercase first:mt-0">
      <span />
      <span className="border-b border-line pb-1">{label}</span>
    </div>
  );
}

function EncryptionDivider({ who }: { who: string }) {
  return (
    <div className="my-2 grid grid-cols-[64px_minmax(0,1fr)] items-center">
      <span />
      <div className="flex items-center gap-3">
        <span className="h-px flex-1 bg-p-tls/50" />
        <span className="font-mono text-[10.5px] tracking-[0.12em] text-p-tls uppercase">{who}: encrypted from here on</span>
        <span className="h-px flex-1 bg-p-tls/50" />
      </div>
    </div>
  );
}

function LadderRow({ r, lit, onClick }: { r: LadderRecord; lit: boolean; onClick: () => void }) {
  const sent = r.direction === "sent";
  const what = r.encrypted ? r.contentType : r.messages.length ? r.messages.join(" + ") : r.contentType;
  return (
    <button
      type="button"
      onClick={onClick}
      className={`grid w-full grid-cols-[64px_minmax(0,1fr)] items-center py-1 text-left transition-opacity hover:bg-raised/50 ${lit ? "opacity-100" : "opacity-30"}`}
    >
      <span className="font-mono text-[11px] text-faint tabular-nums">{r.sameReadAsPrevious ? "″" : ms(r.atMs)}</span>
      <span className="relative block">
        <span className={`flex items-baseline gap-2 ${sent ? "justify-start pl-2" : "justify-end pr-2"}`}>
          <span className={`font-mono text-[12px] ${r.encrypted ? "text-muted italic" : "text-fg"}`}>{what}</span>
          <span className="font-mono text-[11px] text-faint">{r.length + 5} B</span>
          {r.encrypted && <span className="font-mono text-[10px] text-p-tls/80">encrypted</span>}
        </span>
        {r.explainedContents && (
          <span className={`mt-0.5 flex ${sent ? "justify-start pl-2" : "justify-end pr-2"}`}>
            <span className="hatch-soft rounded-[2px] border border-dashed border-faint px-1.5 py-px font-mono text-[10.5px] text-muted">
              inside (explained): {r.explainedContents}
            </span>
          </span>
        )}
        <Arrow sent={sent} encrypted={r.encrypted} />
      </span>
    </button>
  );
}

function Arrow({ sent, encrypted }: { sent: boolean; encrypted: boolean }) {
  return (
    <svg viewBox="0 0 100 8" preserveAspectRatio="none" className={`mt-0.5 block h-2 w-full ${encrypted ? "text-p-tls/70" : "text-fg/70"}`}>
      <line x1="1" y1="4" x2="99" y2="4" stroke="currentColor" strokeWidth="1" vectorEffect="non-scaling-stroke" />
      {sent ? (
        <path d="M99 4 L96 1 M99 4 L96 7" stroke="currentColor" strokeWidth="1" fill="none" vectorEffect="non-scaling-stroke" />
      ) : (
        <path d="M1 4 L4 1 M1 4 L4 7" stroke="currentColor" strokeWidth="1" fill="none" vectorEffect="non-scaling-stroke" />
      )}
    </svg>
  );
}

// ── What a network observer sees ──────────────────────────────────────

function Observer({ view }: { view: View }) {
  const e = view.encryption!;
  const [type, v1, v2, l1, l2] = e.headerHex.split(" ");
  const sni = view.handshake.data.sni.value;
  return (
    <Section
      title="What someone watching the network sees"
      sub="Packet is the client, so it has the plaintext. Anyone in between (your Wi-Fi, your ISP) sees only the encrypted record."
    >
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded border border-line p-4">
          <div className="flex items-center justify-between text-[11.5px] text-muted">
            What Packet wrote <EvidenceBadge evidence="observed" />
          </div>
          <pre className="mt-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-fg">
            {e.plaintext.split("\r\n").filter((l, i, a) => i < a.length - 1 || l).map((l, i) => (
              <div key={i}>
                {l}
                <span className="text-faint">\r\n</span>
              </div>
            ))}
          </pre>
          <div className="mt-2 font-mono text-[11px] text-faint">{e.plaintextBytes} bytes</div>
        </div>

        <div className="rounded border border-line p-4">
          <div className="flex items-center justify-between text-[11.5px] text-muted">
            What crossed the network <EvidenceBadge evidence="observed" />
          </div>
          <div className="mt-3 flex flex-wrap items-stretch gap-1 font-mono text-[12px]">
            <HexBox bytes={type} label="type: application_data" />
            <HexBox bytes={`${v1} ${v2}`} label="version (always 1.2)" />
            <HexBox bytes={`${l1} ${l2}`} label={`length ${e.recordLength}`} />
            <div className="hatch-soft flex min-w-40 flex-1 flex-col justify-center rounded-[3px] border border-dashed border-line-strong px-3 py-2 text-muted">
              <span>{e.recordLength} bytes of ciphertext</span>
              <span className="text-[10px] text-faint">not stored by Packet · {e.recordLength + 5} B on the wire with the header</span>
            </div>
          </div>
          <div className="mt-4 flex items-start justify-between gap-3 text-[12px]">
            <div>
              <div className="font-mono text-fg">
                {e.recordLength} = {e.plaintextBytes} + {e.overhead}
              </div>
              <div className="mt-0.5 text-[11px] leading-snug text-faint">{e.overheadExplained}</div>
            </div>
            <EvidenceBadge evidence="derived" />
          </div>
        </div>
      </div>

      {sni && (
        <div className="mt-4 rounded border border-p-http/30 p-4">
          <div className="flex items-center justify-between text-[11.5px] text-muted">
            Still in the clear: the server name <EvidenceBadge evidence="observed" />
          </div>
          <p className="mt-2 text-[13px] leading-relaxed text-fg/90">
            The ClientHello named <span className="font-mono text-fg">{sni}</span> unencrypted (SNI), so the server knows which certificate
            to present. That also means the network can see <em>which site</em> you connected to, just not what you asked it.
          </p>
          <p className="mt-1 text-[11px] text-faint">Encrypted Client Hello (ECH) can hide it. Packet doesn&apos;t use ECH.</p>
        </div>
      )}
    </Section>
  );
}

function HexBox({ bytes, label }: { bytes: string; label: string }) {
  return (
    <div className="rounded-[3px] border border-line-strong bg-raised px-2.5 py-1.5">
      <div className="text-fg">{bytes}</div>
      <div className="text-[10px] text-faint">{label}</div>
    </div>
  );
}

// ── Certificate chain ─────────────────────────────────────────────────

function Chain({ view }: { view: View }) {
  const verdict = view.handshake.data.verification?.value;
  const traceAt = useWorkspace().state.trace.startedAtUnixMs / 1000;
  return (
    <Section
      title="Certificate chain"
      sub="Each certificate is signed by the one below it. The last one is vouched for by a root in Packet's trust store. Servers don't usually send the root itself."
    >
      <div className="space-y-0">
        {view.chain.map((c, i) => (
          <div key={c.sha256}>
            <CertCard c={c} leaf={i === 0} atUnix={traceAt} />
            {i < view.chain.length - 1 && (
              <div className={`flex items-center gap-2 py-1.5 pl-5 font-mono text-[11px] ${c.issuedByNext ? "text-faint" : "text-p-error"}`}>
                <span>↑ signed by</span>
                {!c.issuedByNext && <span>(issuer doesn&apos;t match the next certificate)</span>}
              </div>
            )}
          </div>
        ))}
        <div className={`flex items-center gap-2 pt-2 pl-5 font-mono text-[11px] ${verdict === "valid" ? "text-p-tls" : "text-p-error"}`}>
          {verdict === "valid" ? "↑ trusted: chains to a root in the Mozilla root program" : `✗ ${verdict}`}
          <EvidenceBadge evidence="observed" />
        </div>
      </div>
    </Section>
  );
}

function CertCard({ c, leaf, atUnix }: { c: ChainCert; leaf: boolean; atUnix: number }) {
  const cn = (s: string) => /CN=([^,]+)/.exec(s)?.[1] ?? s;
  const span = c.notAfterUnix - c.notBeforeUnix;
  // Positioned at the moment of the trace (what was observed), not "now".
  const pos = Math.min(1, Math.max(0, (atUnix - c.notBeforeUnix) / span));
  const date = (u: number) => new Date(u * 1000).toISOString().slice(0, 10);
  const [showAll, setShowAll] = useState(false);
  const sans = showAll ? c.san : c.san.slice(0, 6);
  return (
    <div className="rounded border border-line p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <div className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">{leaf ? "Server certificate" : c.isCa ? "Intermediate CA" : "Certificate"}</div>
          <div className="mt-0.5 text-[15px] text-fg">{cn(c.subject)}</div>
        </div>
        <EvidenceBadge evidence="observed" />
      </div>
      <div className="mt-1 font-mono text-[11px] text-muted">issued by {cn(c.issuer)}</div>

      <div className="mt-4">
        <div className="relative h-1.5 rounded-full bg-line">
          <div className={`absolute inset-y-0 left-0 rounded-full ${c.validAtTrace ? "bg-p-tls/60" : "bg-p-error/70"}`} style={{ width: `${pos * 100}%` }} />
          <div className="absolute -top-1 h-3.5 w-px bg-fg" style={{ left: `${pos * 100}%` }} title="when this trace ran" />
        </div>
        <div className="mt-1.5 flex justify-between font-mono text-[10.5px] text-faint tabular-nums">
          <span>{date(c.notBeforeUnix)}</span>
          <span className={c.validAtTrace ? "text-muted" : "text-p-error"}>
            {c.validAtTrace ? `${c.daysLeft.toLocaleString()} days left` : c.daysLeft < 0 ? `expired ${(-c.daysLeft).toLocaleString()} days ago` : "not valid yet"}
          </span>
          <span>{date(c.notAfterUnix)}</span>
        </div>
      </div>

      {c.san.length > 0 && (
        <div className="mt-4">
          <div className="text-[11px] text-muted">Valid for these names (SAN)</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {sans.map((s) => (
              <span key={s} className="rounded-[3px] border border-line-strong px-1.5 py-px font-mono text-[11px] text-fg/90">
                {s}
              </span>
            ))}
            {c.san.length > 6 && (
              <button type="button" onClick={() => setShowAll(!showAll)} className="px-1.5 font-mono text-[11px] text-faint hover:text-muted">
                {showAll ? "fewer" : `+${c.san.length - 6} more`}
              </button>
            )}
          </div>
        </div>
      )}

      <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] sm:grid-cols-4">
        <Kv k="Key" v={c.publicKey} />
        <Kv k="Signed with" v={c.signatureAlgorithm} />
        <Kv k="Size" v={`${c.derBytes} B`} />
        <Kv k="SHA-256" v={`${c.sha256.slice(0, 23)}…`} title={c.sha256} />
      </dl>
    </div>
  );
}

function Kv({ k, v, title }: { k: string; v: string; title?: string }) {
  return (
    <div className="min-w-0" title={title}>
      <dt className="text-faint">{k}</dt>
      <dd className="truncate text-fg/90">{v}</dd>
    </div>
  );
}

// ── No TLS at all ─────────────────────────────────────────────────────

function NoTls() {
  const { trace } = useWorkspace().state;
  const req = trace.events.find((e): e is Extract<TraceEvent, { kind: "http.request" }> => e.kind === "http.request");
  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <h2 className="font-mono text-[11px] tracking-[0.16em] text-muted uppercase">No TLS in this trace</h2>
      <p className="mt-2 text-[14px] leading-relaxed text-fg/90">
        This request used plain <span className="font-mono">http://</span>. Nothing was encrypted: every router and network on the path could
        read, and change, exactly what Packet sent.
      </p>
      {req?.data.rawHead && (
        <div className="mt-5 rounded border border-p-error/30 p-4">
          <div className="flex items-center justify-between text-[11.5px] text-muted">
            Readable by anyone on the path <EvidenceBadge evidence="observed" />
          </div>
          <pre className="mt-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-fg">{req.data.rawHead.value}</pre>
        </div>
      )}
    </div>
  );
}
