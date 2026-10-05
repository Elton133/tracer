"use client";

import { useMemo } from "react";

import { buildStacks, OSI_LAYERS, TCPIP_LAYERS, type StackEntry, type StackProtocol } from "@/core/derive/layers";
import { useWorkspace, type LayerModel } from "@/ui/workspace/store";

const COLOR: Partial<Record<StackProtocol, string>> = {
  "http/1.1": "text-p-http",
  h2: "text-p-http",
  tls: "text-p-tls",
  tcp: "text-p-tcp",
  udp: "text-p-tcp",
  dns: "text-p-dns",
};

/** Keep a layer lit briefly after its event ends, so sub-millisecond events are visible at all. */
const HOLD_REAL_MS = 250;

interface Lit {
  entry: StackEntry;
  eventId: string;
  now: boolean;
}

export function LayerStrip() {
  const { state, dispatch } = useWorkspace();
  const { trace, t, speed, layerModel, layersOpen } = state;
  const stacks = useMemo(() => buildStacks(trace), [trace]);

  if (!layersOpen) {
    return (
      <button
        type="button"
        onClick={() => dispatch({ type: "layersOpen", open: true })}
        className="flex h-7 w-full items-center gap-2 px-4 font-mono text-[10px] tracking-[0.14em] text-faint uppercase hover:text-muted"
      >
        <span>▸</span> Layers
      </button>
    );
  }

  // What's active right now. Only when nothing is (an idle gap) does the most
  // recently finished event stay lit, dimmed, so sub-millisecond events are
  // visible at all without ever overlaying something that isn't happening.
  const hold = HOLD_REAL_MS * speed;
  const active = stacks.filter((s) => t >= s.start && t <= s.end);
  const shown =
    active.length > 0
      ? active
      : stacks.filter((s) => t > s.end && t <= s.end + hold).sort((a, b) => b.end - a.end).slice(0, 1);
  const lit = new Map<StackProtocol, Lit>();
  for (const s of shown) {
    const now = active.length > 0;
    for (const entry of s.entries) {
      const prev = lit.get(entry.protocol);
      if (!prev || rank(entry) > rank(prev.entry)) lit.set(entry.protocol, { entry, eventId: s.eventId, now });
    }
  }
  const all = [...lit.values()];

  const cells =
    layerModel === "osi"
      ? OSI_LAYERS.map((l) => ({ key: String(l.n), num: String(l.n), name: l.name, sub: "", items: all.filter((x) => x.entry.osi.includes(l.n)) }))
      : TCPIP_LAYERS.map((l) => ({ key: l.id, num: "", name: l.name, sub: l.osi, items: all.filter((x) => x.entry.tcpip === l.id) }));

  return (
    <div className="flex h-[68px] items-stretch">
      <div className="flex w-[200px] shrink-0 flex-col justify-center gap-1.5 border-r border-line px-4">
        <div className="flex items-center gap-2">
          <ModelToggle value={layerModel} onChange={(model) => dispatch({ type: "layerModel", model })} />
          <button
            type="button"
            aria-label="Hide layers"
            onClick={() => dispatch({ type: "layersOpen", open: false })}
            className="ml-auto font-mono text-[11px] text-faint hover:text-muted"
          >
            ▾
          </button>
        </div>
        <p
          className="text-[10.5px] leading-tight text-faint"
          title="OSI is a conceptual model for teaching and talking about networks. The Internet's protocols were designed around the simpler TCP/IP model, and real protocols don't always fit one OSI layer (TLS is the classic example)."
        >
          {layerModel === "osi" ? "A conceptual model. The Internet runs on TCP/IP." : "The model Internet protocols were built on."}
        </p>
      </div>

      {cells.map((c) => (
        <div key={c.key} className="flex min-w-0 flex-1 flex-col justify-center gap-1.5 border-r border-line/60 px-3 last:border-r-0">
          <div className="flex items-baseline gap-1.5 font-mono text-[10px] tracking-[0.1em] uppercase">
            {c.num && <span className={c.items.length ? "text-fg" : "text-faint"}>{c.num}</span>}
            <span className={`truncate ${c.items.length ? "text-muted" : "text-faint/70"}`}>{c.name}</span>
            {c.sub && <span className="truncate text-faint/70 normal-case tracking-normal">{c.sub}</span>}
          </div>
          <div className="flex min-h-[22px] flex-wrap items-center gap-1">
            {c.items.length === 0 ? (
              <span className="font-mono text-[11px] text-faint/40">·</span>
            ) : (
              c.items.map((x) => (
                <Chip key={x.entry.protocol} lit={x} onClick={() => dispatch({ type: "select", id: x.eventId })} />
              ))
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function rank(e: StackEntry) {
  return { observed: 3, derived: 2, explained: 1 }[e.evidence];
}

function Chip({ lit, onClick }: { lit: Lit; onClick: () => void }) {
  const { entry, now } = lit;
  const color = COLOR[entry.protocol] ?? "text-muted";
  const style = {
    observed: "border-current/50 bg-current/15",
    derived: "border-current/60 bg-transparent",
    explained: "hatch-soft border-dashed border-current/40",
  }[entry.evidence];
  return (
    <button
      type="button"
      onClick={onClick}
      title={`${entry.name} · ${entry.evidence}${entry.note ? `\n\n${entry.note}` : ""}`}
      className={`flex h-[22px] max-w-full items-center gap-1.5 truncate rounded-[3px] border px-1.5 font-mono text-[11px] transition-opacity ${color} ${style} ${
        now ? "opacity-100" : "opacity-45"
      }`}
    >
      <span className={entry.evidence === "explained" ? "text-muted" : "text-fg"}>{entry.name}</span>
      <span className="text-[9px] tracking-[0.08em] uppercase opacity-70">{entry.evidence.slice(0, 3)}</span>
    </button>
  );
}

function ModelToggle({ value, onChange }: { value: LayerModel; onChange: (m: LayerModel) => void }) {
  return (
    <div className="flex rounded border border-line-strong p-0.5 font-mono text-[10px] tracking-[0.1em]">
      {(["osi", "tcpip"] as const).map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onChange(m)}
          className={`rounded-[2px] px-1.5 py-0.5 transition-colors ${value === m ? "bg-raised text-fg" : "text-faint hover:text-muted"}`}
        >
          {m === "osi" ? "OSI" : "TCP/IP"}
        </button>
      ))}
    </div>
  );
}
