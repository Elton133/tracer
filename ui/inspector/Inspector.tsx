"use client";

import type { Evidence } from "@/core/generated/Evidence";
import type { TraceEvent } from "@/core/generated/TraceEvent";
import { explanationFor } from "@/content/explain";
import { EvidenceBadge } from "@/ui/primitives/EvidenceBadge";
import { ExplanationBody } from "@/ui/primitives/InfoButton";
import { bytes, fieldLabel, ms } from "@/ui/primitives/format";
import { useWorkspace } from "@/ui/workspace/store";

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
interface FactJson {
  value: Json;
  evidence: Evidence;
  source: string;
  note?: string;
}

function isFact(v: unknown): v is FactJson {
  return typeof v === "object" && v !== null && "evidence" in v && "source" in v && "value" in v;
}

const KIND_TITLE: Record<TraceEvent["kind"], string> = {
  "url.parse": "Parse URL",
  "dns.lookup": "DNS lookup (operating system)",
  "dns.query": "DNS query (sent by Packet)",
  "guard.check": "Address check",
  "tcp.connect": "TCP connect",
  "tcp.close": "TCP close",
  "tls.handshake": "TLS handshake",
  "http.request": "HTTP request",
  "http.response": "HTTP response head",
  "http.body": "HTTP response body",
  "http.redirect": "HTTP redirect",
};

export function Inspector() {
  const { state } = useWorkspace();
  const event = state.trace.events.find((e) => e.id === state.selectedId);

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center border-b border-line px-4 font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
        Inspector
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">{event ? <EventDetail event={event} /> : <TraceSummary />}</div>
      <Legend />
    </div>
  );
}

function TraceSummary() {
  const { trace, waterfall } = useWorkspace().state;
  return (
    <div className="space-y-5 p-4 text-[13px]">
      <p className="leading-relaxed text-muted">Select a row to see exactly what was observed, and how Packet knows it.</p>
      <dl className="space-y-3">
        <Pair k="Input" v={<span className="font-mono break-all">{trace.input.url}</span>} />
        <Pair k="Outcome" v={trace.outcome.summary ?? (trace.outcome.ok ? "ok" : "failed")} />
        <Pair k="Total" v={<span className="font-mono">{ms(waterfall.total)}</span>} />
        <Pair k="Hops" v={<span className="font-mono">{trace.hops.length}</span>} />
        <Pair k="Events" v={<span className="font-mono">{trace.events.length}</span>} />
        <Pair k="Observed from" v={trace.vantage.description} />
        <Pair k="Runtime" v={<span className="font-mono text-xs">{trace.vantage.runtime}</span>} />
        <Pair k="Started" v={<span className="font-mono text-xs">{utc(trace.startedAtUnixMs)}</span>} />
      </dl>
    </div>
  );
}

/** Same output on server and client (no locale or time zone involved). */
function utc(unixMs: number): string {
  return `${new Date(unixMs).toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

function Pair({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <dt className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase">{k}</dt>
      <dd className="mt-0.5 text-fg/90">{v}</dd>
    </div>
  );
}

function EventDetail({ event }: { event: TraceEvent }) {
  const { start, end } = event.time;
  return (
    <div>
      <header className="space-y-2 border-b border-line p-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[15px] font-medium">{KIND_TITLE[event.kind]}</h2>
          {event.status !== "ok" && (
            <span className="rounded-[3px] border border-p-error/50 px-1 font-mono text-[10px] text-p-error uppercase">
              {event.status}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted tabular-nums">
          <span>{event.kind}</span>
          {event.protocol && <span className="text-faint">{event.protocol}</span>}
          <span>
            {ms(start)}
            {end !== undefined && <> → {ms(end)} · <span className="text-fg">{ms(end - start)}</span></>}
          </span>
          <EvidenceBadge evidence={event.evidence} />
        </div>
      </header>

      {event.error && (
        <div className="border-b border-line bg-p-error/[0.06] p-4">
          <FactRow name="error" fact={event.error as unknown as FactJson} />
        </div>
      )}

      <About event={event} />
      <Fields data={event.data as unknown as Record<string, Json>} />
    </div>
  );
}

function About({ event }: { event: TraceEvent }) {
  const x = explanationFor(event);
  if (!x) return null;
  return (
    <details key={event.id} className="group border-b border-line">
      <summary className="flex cursor-pointer list-none items-start gap-3 p-4 hover:bg-raised/40">
        <span className="mt-0.5 font-mono text-[10px] text-faint transition-transform group-open:rotate-90">▸</span>
        <span className="flex-1">
          <span className="flex items-center justify-between gap-2">
            <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">What happens here</span>
            <EvidenceBadge evidence="explained" />
          </span>
          <span className="mt-1 block text-[12.5px] leading-relaxed text-muted group-open:hidden">{x.summary}</span>
        </span>
      </summary>
      <div className="px-4 pb-4 pl-10">
        <ExplanationBody explanation={x} event={event} compact />
      </div>
    </details>
  );
}

function Fields({ data, depth = 0 }: { data: Record<string, Json>; depth?: number }) {
  return (
    <div className={depth ? "border-l border-line pl-3" : ""}>
      {Object.entries(data).map(([key, v]) =>
        isFact(v) ? (
          <div key={key} className={depth ? "py-2" : "border-b border-line/70 px-4 py-2.5"}>
            <FactRow name={key} fact={v} />
          </div>
        ) : v && typeof v === "object" && !Array.isArray(v) ? (
          <div key={key} className="border-b border-line/70 px-4 py-2.5">
            <div className="mb-1 text-[12px] text-muted">{fieldLabel(key)}</div>
            <Fields data={v} depth={depth + 1} />
          </div>
        ) : null,
      )}
    </div>
  );
}

function FactRow({ name, fact }: { name: string; fact: FactJson }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-3">
        <span className="text-[12px] text-muted">{fieldLabel(name)}</span>
        <EvidenceBadge evidence={fact.evidence} />
      </div>
      <Value name={name} v={fact.value} />
      <div className="font-mono text-[10px] leading-snug text-faint">{fact.source}</div>
      {fact.note && <div className="text-[11px] leading-snug text-muted/90">{fact.note}</div>}
    </div>
  );
}

function Value({ name, v }: { name: string; v: Json }) {
  const mono = "font-mono text-[12.5px] text-fg break-words";
  if (v === null) return <div className="font-mono text-[12px] text-faint">none</div>;
  if (typeof v === "boolean") return <div className={mono}>{v ? "yes" : "no"}</div>;
  if (typeof v === "number") {
    if (/Ms$/.test(name)) return <div className={mono}>{ms(v)}</div>;
    if (/[bB]ytes$/.test(name))
      return (
        <div className={mono}>
          {bytes(v)}
          {v >= 1024 && <span className="text-faint"> ({v.toLocaleString()} B)</span>}
        </div>
      );
    return <div className={`${mono} tabular-nums`}>{v.toLocaleString()}</div>;
  }
  if (typeof v === "string") return <div className={`${mono} whitespace-pre-wrap`}>{name === "rawHead" ? showCrlf(v) : v}</div>;
  if (Array.isArray(v)) {
    if (v.length === 0) return <div className="font-mono text-[12px] text-faint">none</div>;
    if (v.every((x) => typeof x !== "object" || x === null)) {
      return (
        <div className={mono}>
          {v.map((x, i) => (
            <div key={i}>{String(x)}</div>
          ))}
        </div>
      );
    }
    return (
      <div className="space-y-1">
        {v.map((x, i) => (
          <Item key={i} v={x as { [k: string]: Json }} />
        ))}
      </div>
    );
  }
  if ("address" in v && "port" in v && Object.keys(v).length === 2) return <div className={mono}>{endpoint(v)}</div>;
  return <KeyValues obj={v} />;
}

/** Readable one-liners for the shapes that repeat across protocols. */
function Item({ v }: { v: { [k: string]: Json } }) {
  const line = "font-mono text-[12px] leading-relaxed";
  if ("name" in v && "value" in v && Object.keys(v).length === 2) {
    return (
      <div className={`${line} break-all`}>
        <span className="text-muted">{String(v.name)}:</span> <span className="text-fg">{String(v.value)}</span>
      </div>
    );
  }
  if ("contentType" in v && "direction" in v) {
    const sent = v.direction === "sent";
    const msgs = (v.messages as string[]).join(", ");
    return (
      <div className={`${line} flex gap-2 tabular-nums`}>
        <span className="w-12 shrink-0 text-faint">{ms(v.atMs as number)}</span>
        <span className={sent ? "text-fg" : "text-muted"}>{sent ? "→" : "←"}</span>
        <span className="w-14 shrink-0 text-right text-muted">{String(v.length)} B</span>
        <span className="min-w-0 break-words">
          <span className="text-faint">{String(v.contentType)}</span>{" "}
          <span className={v.encrypted ? "text-faint italic" : "text-fg"}>{v.encrypted ? "encrypted" : msgs}</span>
        </span>
      </div>
    );
  }
  if ("recordType" in v && "ttl" in v) {
    return (
      <div className={`${line} flex gap-2`}>
        <span className="w-12 shrink-0 text-muted">{String(v.recordType)}</span>
        <span className="truncate text-fg">{String(v.value)}</span>
        <span className="ml-auto shrink-0 text-faint">ttl {String(v.ttl)}s</span>
      </div>
    );
  }
  if ("allowed" in v && "address" in v) {
    return (
      <div className={`${line} flex gap-2`}>
        <span className={v.allowed ? "text-fg" : "text-p-error"}>{v.allowed ? "allow" : "refuse"}</span>
        <span className="text-fg/90">{String(v.address)}</span>
        {v.class && <span className="truncate text-faint">{String(v.class)}</span>}
      </div>
    );
  }
  return (
    <div className="rounded border border-line bg-ink/50 p-2">
      <KeyValues obj={v} />
    </div>
  );
}

function KeyValues({ obj }: { obj: { [k: string]: Json } }) {
  return (
    <dl className="grid grid-cols-[minmax(0,auto)_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-[11.5px]">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="truncate text-faint">{k}</dt>
          <dd className="text-fg/90 [overflow-wrap:anywhere]">{format(k, v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function format(k: string, v: Json): string {
  if (v === null) return "none";
  if (Array.isArray(v)) return v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") || "none";
  if (typeof v === "object") return Object.entries(v).map(([a, b]) => `${a}=${String(b)}`).join(" ");
  if (typeof v === "number" && /Unix$/.test(k)) return new Date(v * 1000).toISOString().slice(0, 10);
  return String(v);
}

function endpoint(v: { [k: string]: Json }): string {
  const a = String(v.address);
  return a.includes(":") ? `[${a}]:${v.port}` : `${a}:${v.port}`;
}

/** Make the invisible framing of HTTP/1.1 visible. */
function showCrlf(s: string) {
  return s.split("\r\n").map((line, i, all) =>
    i === all.length - 1 && line === "" ? null : (
      <div key={i}>
        {line}
        <span className="text-faint">\r\n</span>
      </div>
    ),
  );
}

function Legend() {
  return (
    <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line px-4 py-2.5">
      {(["observed", "derived", "explained", "simulated"] as const).map((e) => (
        <EvidenceBadge key={e} evidence={e} />
      ))}
    </div>
  );
}
