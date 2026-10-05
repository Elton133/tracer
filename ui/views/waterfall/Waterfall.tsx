"use client";

import { axisTicks, type Row } from "@/core/derive/waterfall";
import { explanationFor } from "@/content/explain";
import { axisMs, ms } from "@/ui/primitives/format";
import { InfoButton } from "@/ui/primitives/InfoButton";
import { phaseColor } from "@/ui/primitives/protocol";
import { useWorkspace } from "@/ui/workspace/store";

// Column layout shared by the axis, every row and the playhead overlay, so
// they line up exactly: [label | track | duration].
const COLS = "grid grid-cols-[200px_minmax(0,1fr)_76px]";
const TRACK_INSET = "left-[200px] right-[76px]";

export function Waterfall() {
  const { state } = useWorkspace();
  const { waterfall: w, t, trace } = state;
  const total = Math.max(w.total, 0.001);
  const pct = (v: number) => `${(v / total) * 100}%`;
  const ticks = axisTicks(total);

  const request = w.rows.filter((r) => !r.aside);
  const aside = w.rows.filter((r) => r.aside);

  return (
    <div className="relative min-h-full pb-10">
      {/* Axis */}
      <div className={`${COLS} sticky top-0 z-20 h-8 items-end border-b border-line bg-ink/95 backdrop-blur-sm`}>
        <div className="px-5 pb-2 font-mono text-[10px] tracking-[0.14em] text-faint uppercase">Phase</div>
        <div className="relative h-full">
          {ticks.map((v) => (
            <span
              key={v}
              className="absolute bottom-2 -translate-x-1/2 font-mono text-[10px] text-faint tabular-nums first:translate-x-0"
              style={{ left: pct(v) }}
            >
              {axisMs(v, total)}
            </span>
          ))}
        </div>
        <div className="pr-5 pb-2 text-right font-mono text-[10px] tracking-[0.14em] text-faint uppercase">Took</div>
      </div>

      <div className="relative">
        {/* Gridlines and playhead, drawn once over every row. */}
        <div className={`pointer-events-none absolute inset-y-0 ${TRACK_INSET} z-0`}>
          {ticks.map((v) => (
            <div key={v} className="absolute inset-y-0 w-px bg-line/60" style={{ left: pct(v) }} />
          ))}
        </div>
        <div className={`pointer-events-none absolute inset-y-0 ${TRACK_INSET} z-10`}>
          <div className="absolute inset-y-0 w-px bg-fg/70" style={{ left: pct(t) }}>
            <div className="absolute -top-px -left-[3px] size-[7px] rotate-45 bg-fg" />
          </div>
        </div>

        {w.hops.map((hop) => (
          <section key={hop.index}>
            <GroupHeader>
              <span className="text-muted">Hop {hop.index}</span>
              <span className="truncate tracking-normal text-fg/80 normal-case">{hop.url}</span>
              {hop.status !== undefined && <StatusChip status={hop.status} />}
            </GroupHeader>
            {request
              .filter((r) => r.hop === hop.index)
              .map((r) => (
                <WaterfallRow key={r.eventId} row={r} pct={pct} />
              ))}
          </section>
        ))}

        {/* A failure before any hop finished (e.g. URL refused) has no hop entry. */}
        {w.hops.length === 0 &&
          request.map((r) => <WaterfallRow key={r.eventId} row={r} pct={pct} />)}

        {aside.length > 0 && (
          <section className="mt-3">
            <GroupHeader>
              <span className="text-muted">Packet&apos;s own DNS queries</span>
              <span className="text-faint normal-case tracking-normal">
                sent after the request, not part of its path
              </span>
            </GroupHeader>
            <div className="opacity-70">
              {aside.map((r) => (
                <WaterfallRow key={r.eventId} row={r} pct={pct} />
              ))}
            </div>
          </section>
        )}
      </div>

      {!trace.outcome.ok && trace.outcome.summary && (
        <p className="mx-5 mt-6 max-w-2xl border-l-2 border-p-error pl-3 font-mono text-xs leading-relaxed text-p-error/90">
          {trace.outcome.summary}
        </p>
      )}
    </div>
  );
}

function GroupHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative z-10 flex h-8 items-center gap-3 px-5 pt-2 font-mono text-[10px] tracking-[0.12em] uppercase">
      {children}
    </div>
  );
}

function StatusChip({ status }: { status: number }) {
  const tone = status >= 400 ? "text-p-error border-p-error/40" : status >= 300 ? "text-p-http border-p-http/40" : "text-fg/80 border-line-strong";
  return <span className={`rounded-[3px] border px-1.5 py-px tabular-nums ${tone}`}>{status}</span>;
}

function WaterfallRow({ row, pct }: { row: Row; pct: (v: number) => string }) {
  const { state, dispatch } = useWorkspace();
  const { t, selectedId } = state;
  const selected = selectedId === row.eventId;
  const failed = row.status !== "ok";
  const color = failed ? "text-p-error" : phaseColor[row.phase];
  const reached = t >= row.start;

  const event = state.trace.events.find((e) => e.id === row.eventId);
  const about = event ? explanationFor(event) : null;

  return (
    <div className="relative">
    <button
      type="button"
      onClick={() => dispatch({ type: "select", id: row.eventId })}
      className={`${COLS} group relative z-[5] h-7 w-full items-center text-left transition-colors ${
        selected ? "bg-raised" : "hover:bg-raised/60"
      }`}
    >
      {selected && <span className="absolute inset-y-1 left-0 w-0.5 bg-fg" />}
      <span className={`flex items-center gap-2 truncate pr-8 pl-5 text-[13px] ${reached ? "text-fg" : "text-faint"}`}>
        <span className={`size-1.5 shrink-0 rounded-full bg-current ${color} ${reached ? "" : "opacity-30"}`} />
        <span className="truncate">{row.label}</span>
      </span>

      <span className={`relative h-full ${color}`}>
        {row.end === undefined ? <Marker row={row} pct={pct} reached={reached} /> : <Bar row={row} pct={pct} t={t} />}
        {row.records.map((r, i) => (
          <span
            key={i}
            title={`TLS record ${r.direction} · ${r.bytes} B${r.encrypted ? " · encrypted" : ""}`}
            className={`absolute w-px bg-current transition-opacity ${r.direction === "sent" ? "top-[3px]" : "bottom-[3px]"} ${
              t >= r.at ? "h-[5px] opacity-90" : "h-[5px] opacity-0"
            }`}
            style={{ left: pct(r.at) }}
          />
        ))}
      </span>

      <span className={`pr-5 text-right font-mono text-xs tabular-nums ${t >= (row.end ?? row.start) ? "text-muted" : "text-faint/50"}`}>
        {row.end !== undefined ? ms(row.end - row.start) : "·"}
      </span>
    </button>
    {about && event && <InfoButton explanation={about} event={event} className="absolute top-1.5 left-[174px] z-[6]" />}
    </div>
  );
}

function Bar({ row, pct, t }: { row: Row; pct: (v: number) => string; t: number }) {
  const end = row.end!;
  const span = Math.max(end - row.start, 0);
  const progress = span === 0 ? (t >= end ? 1 : 0) : Math.min(1, Math.max(0, (t - row.start) / span));
  const timeout = row.status === "timeout";
  return (
    <span
      className={`absolute top-1/2 h-2.5 min-w-[2px] -translate-y-1/2 overflow-hidden rounded-[2px] border border-current/35 ${
        timeout ? "border-dashed" : ""
      }`}
      style={{ left: pct(row.start), width: pct(span) }}
    >
      <span className="absolute inset-y-0 left-0 bg-current/85" style={{ width: `${progress * 100}%` }} />
    </span>
  );
}

function Marker({ row, pct, reached }: { row: Row; pct: (v: number) => string; reached: boolean }) {
  return (
    <span
      className={`absolute top-1/2 size-[7px] -translate-x-1/2 -translate-y-1/2 rotate-45 border border-current transition-colors ${
        reached ? "bg-current" : "bg-transparent opacity-40"
      }`}
      style={{ left: pct(row.start) }}
    />
  );
}
