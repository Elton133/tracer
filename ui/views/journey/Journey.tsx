"use client";

import { useMemo } from "react";

import { buildJourney, type Activity, type Flight, type JourneyNode } from "@/core/derive/journey";
import { bytes, ms } from "@/ui/primitives/format";
import { phaseColor } from "@/ui/primitives/protocol";
import { useWorkspace } from "@/ui/workspace/store";

// Geometry, in viewBox units. Left: this machine. Middle: the path we can't
// see. Right: the remote endpoints we talked to.
const W = 1000;
const NODE_H = 68;
const LEFT = { x: 40, w: 240 };
const BAND = { x: 380, w: 230 };
const RIGHT = { x: 700, w: 280 };
const ROW = 124;
const TOP = 120;

type Pt = { x: number; y: number };

export function Journey() {
  const { state, dispatch } = useWorkspace();
  const { trace, waterfall, t } = state;
  const journey = useMemo(() => buildJourney(trace), [trace]);

  const app = journey.nodes.find((n) => n.role === "client-app")!;
  const os = journey.nodes.find((n) => n.role === "os-resolver");
  const remotes = journey.nodes.filter((n) => n.role === "dns-server" || n.role === "server");

  const remoteY = new Map(remotes.map((n, i) => [n.id, TOP + i * ROW]));
  const appY = remotes.length ? TOP + ((remotes.length - 1) * ROW) / 2 : TOP;
  const osY = appY + 120;
  const H = Math.max(TOP + remotes.length * ROW + 40, osY + NODE_H + 70);

  const center = (id: string): Pt =>
    id === app.id ? { x: LEFT.x + LEFT.w / 2, y: appY } : id === os?.id ? { x: LEFT.x + LEFT.w / 2, y: osY } : { x: RIGHT.x + RIGHT.w / 2, y: remoteY.get(id) ?? appY };

  // App → remote: a curve whose middle section crosses the abstracted band.
  const curve = (id: string): [Pt, Pt, Pt, Pt] => {
    const y = remoteY.get(id) ?? appY;
    return [
      { x: LEFT.x + LEFT.w, y: appY },
      { x: BAND.x + 40, y: appY },
      { x: BAND.x + BAND.w - 40, y },
      { x: RIGHT.x, y },
    ];
  };

  const active = journey.activities.filter((a) => t >= a.start && t <= a.end);
  const touching = (id: string) => active.some((a) => a.a === id || a.b === id);
  const inFlight = journey.flights.filter((f) => t >= f.depart && t <= f.arrive);
  const labelOf = (eventId: string) => waterfall.rows.find((r) => r.eventId === eventId)?.label ?? eventId;
  const lastFlight = [...journey.flights].reverse().find((f) => (f.from === app.id ? f.depart : f.arrive) <= t);

  const select = (nodeId: string) => {
    const mine = journey.activities.filter((a) => a.a === nodeId || a.b === nodeId);
    const pick = [...mine].reverse().find((a) => a.start <= t) ?? mine[0];
    if (pick) dispatch({ type: "select", id: pick.eventId });
  };

  return (
    <div className="flex min-h-full flex-col">
      <NowCaption t={t} active={active} labelOf={labelOf} last={lastFlight} />

      <div className="mx-auto flex w-full max-w-[1180px] flex-1 items-center px-6 pt-4 pb-2">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" role="img" aria-label="Request journey">
          <defs>
            <pattern id="hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(-45)">
              <line x1="0" y1="0" x2="0" y2="7" className="stroke-line-strong" strokeWidth="1" />
            </pattern>
            <clipPath id="in-band">
              <rect x={BAND.x} y={0} width={BAND.w} height={H} />
            </clipPath>
            <clipPath id="out-band">
              <rect x={0} y={0} width={BAND.x} height={H} />
              <rect x={BAND.x + BAND.w} y={0} width={W - BAND.x - BAND.w} height={H} />
            </clipPath>
          </defs>

          {/* The path we cannot see. */}
          <rect x={BAND.x} y={32} width={BAND.w} height={H - 62} fill="url(#hatch)" opacity={0.7} rx={3} />
          <text x={BAND.x + BAND.w / 2} y={20} textAnchor="middle" className="fill-muted font-mono text-[13px] tracking-[0.18em]">
            PATH ABSTRACTED
          </text>
          <text x={BAND.x + BAND.w / 2} y={H - 10} textAnchor="middle" className="fill-faint font-mono text-[12px]">
            routers and distance in between are not observed
          </text>

          {/* This machine. */}
          <rect x={LEFT.x - 20} y={32} width={LEFT.w + 40} height={H - 62} rx={6} className="fill-none stroke-line-strong" strokeDasharray="4 4" />
          <text x={LEFT.x - 10} y={20} className="fill-muted font-mono text-[13px] tracking-[0.18em]">
            THIS MACHINE
          </text>

          {/* Edges: app ↔ each remote. Solid where we stand, dashed across the band. */}
          {remotes.map((n) => {
            const c = curve(n.id);
            const d = `M${c[0].x},${c[0].y} C${c[1].x},${c[1].y} ${c[2].x},${c[2].y} ${c[3].x},${c[3].y}`;
            const act = active.find((a) => a.a === n.id || a.b === n.id);
            const tone = act ? `${phaseColor[act.phase]} ${act.aside ? "opacity-60" : ""}` : "text-line-strong";
            return (
              <g key={n.id} className={`${tone} transition-colors`}>
                <path d={d} fill="none" stroke="currentColor" strokeWidth={act ? 1.6 : 1} clipPath="url(#out-band)" />
                <path d={d} fill="none" stroke="currentColor" strokeWidth={act ? 1.6 : 1} strokeDasharray="2 5" clipPath="url(#in-band)" />
              </g>
            );
          })}

          {/* App ↔ OS resolver: local, no network involved. */}
          {os && (
            <g className={active.some((a) => a.b === os.id) ? phaseColor.dns : "text-line-strong"}>
              <line x1={center(app.id).x} y1={appY + NODE_H / 2} x2={center(os.id).x} y2={osY - NODE_H / 2} stroke="currentColor" strokeWidth={1.4} />
              {/* Where the OS sends the question next: getaddrinfo doesn't tell us. */}
              <line x1={LEFT.x + LEFT.w} y1={osY} x2={BAND.x + 30} y2={osY} className="stroke-faint" strokeDasharray="2 4" />
              <text x={BAND.x + 36} y={osY + 4} className="fill-faint font-mono text-[12px]">
                upstream: not observed
              </text>
            </g>
          )}


          <NodeBox n={app} x={LEFT.x} y={appY} w={LEFT.w} lit={touching(app.id)} sub={trace.vantage.description} onClick={() => select(app.id)} />
          {os && <NodeBox n={os} x={LEFT.x} y={osY} w={LEFT.w} lit={touching(os.id)} sub="OS cache · /etc/hosts · resolvers" onClick={() => select(os.id)} />}
          {remotes.map((n) => (
            <NodeBox
              key={n.id}
              n={n}
              x={RIGHT.x}
              y={remoteY.get(n.id)!}
              w={RIGHT.w}
              lit={touching(n.id)}
              sub={n.role === "dns-server" ? `${n.address} · queried by Packet` : n.address}
              onClick={() => select(n.id)}
            />
          ))}

          {/* Packets in flight, above everything so labels stay readable. */}
          {(() => {
            const groups = groupFlights(inFlight);
            const newest = groups.reduce((best, g, i) => (g.flights[0].depart > groups[best].flights[0].depart ? i : best), 0);
            return groups.map((g, i) => (
              <FlightDot key={g.key} group={g.flights} t={t} curve={curve} appId={app.id} labelled={i === newest} />
            ));
          })()}
        </svg>
      </div>

      <Legend />
    </div>
  );
}

function NowCaption({ t, active, labelOf, last }: { t: number; active: Activity[]; labelOf: (id: string) => string; last?: Flight }) {
  return (
    <div className="flex min-h-14 flex-wrap items-center gap-x-6 gap-y-1 border-b border-line px-5 py-3">
      <span className="w-20 font-mono text-[12px] text-fg tabular-nums">{ms(t)}</span>
      {active.length === 0 ? (
        <span className="text-[13px] text-faint">idle: nothing on the wire right now</span>
      ) : (
        active.map((a) => (
          <span key={a.eventId} className={`flex items-center gap-2 text-[13px] ${a.aside ? "opacity-60" : ""}`}>
            <span className={`size-1.5 rounded-full bg-current ${phaseColor[a.phase]}`} />
            <span className="text-fg">{labelOf(a.eventId)}</span>
          </span>
        ))
      )}
      {last && (
        <span className="ml-auto truncate font-mono text-[11px] text-muted">
          {last.from === "app" ? "→" : "←"} {last.label}
          {last.evidence === "explained" && <span className="text-faint"> (explained)</span>}
        </span>
      )}
    </div>
  );
}

function NodeBox({ n, x, y, w, lit, sub, onClick }: { n: JourneyNode; x: number; y: number; w: number; lit: boolean; sub?: string; onClick: () => void }) {
  const role = { "client-app": "APPLICATION", "os-resolver": "OS RESOLVER", "dns-server": "DNS RESOLVER", server: "SERVER" }[n.role];
  const label = n.role === "os-resolver" ? "getaddrinfo()" : n.label;
  const fit = (s: string, px: number) => truncate(s, Math.floor((w - 32) / (px * 0.58)));
  return (
    <g onClick={onClick} className="cursor-pointer">
      <rect
        x={x}
        y={y - NODE_H / 2}
        width={w}
        height={NODE_H}
        rx={5}
        className={`fill-panel transition-colors ${lit ? "stroke-fg" : "stroke-line-strong"}`}
        strokeWidth={lit ? 1.5 : 1}
      />
      <text x={x + 16} y={y - 12} className="fill-faint font-mono text-[11px] tracking-[0.16em]">
        {role}
      </text>
      <text x={x + 16} y={y + 8} className={`font-sans text-[17px] ${lit ? "fill-fg" : "fill-fg/80"}`}>
        {fit(label, 17)}
      </text>
      {sub && (
        <text x={x + 16} y={y + 25} className="fill-muted font-mono text-[12px]">
          {fit(sub, 12)}
        </text>
      )}
    </g>
  );
}

/** Records read in the same read() share their times exactly. Draw them as one group. */
function groupFlights(fs: Flight[]): { key: string; flights: Flight[] }[] {
  const groups = new Map<string, Flight[]>();
  for (const f of fs) {
    const key = `${f.from}>${f.to}@${f.depart}:${f.arrive}`;
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  return [...groups].map(([key, flights]) => ({ key, flights }));
}

function FlightDot({
  group,
  t,
  curve,
  appId,
  labelled,
}: {
  group: Flight[];
  t: number;
  curve: (id: string) => [Pt, Pt, Pt, Pt];
  appId: string;
  /** Only the newest group is labelled, so neighbouring dots never print over each other. */
  labelled: boolean;
}) {
  const f = group[0];
  const remote = f.from === appId ? f.to : f.from;
  const span = Math.max(f.arrive - f.depart, 1e-6);
  const u = Math.min(1, Math.max(0, (t - f.depart) / span));
  const p = bezier(curve(remote), f.from === appId ? u : 1 - u);
  const total = group.reduce((n, x) => n + (x.bytes ?? 0), 0);
  const label =
    group.length > 1
      ? `${group.length} records${total ? ` · ${bytes(total)}` : ""}`
      : `${f.label.replace(/^TLS /, "")}${total ? ` · ${bytes(total)}` : ""}`;
  const explained = f.evidence === "explained";
  return (
    <g className={phaseColor[f.phase]}>
      <title>{group.map((x) => `${x.label}${x.bytes ? ` (${x.bytes} B)` : ""}`).join("\n") + (explained ? "\n(explained)" : "")}</title>
      <circle cx={p.x} cy={p.y} r={11} fill="currentColor" opacity={0.12} />
      {explained ? (
        <circle cx={p.x} cy={p.y} r={5} className="fill-ink" stroke="currentColor" strokeWidth={1.6} />
      ) : (
        <circle cx={p.x} cy={p.y} r={5} fill="currentColor" />
      )}
      {labelled && u > 0.08 && u < 0.92 && (
        <text x={p.x} y={p.y - 16} textAnchor="middle" className="fill-current stroke-ink font-mono text-[12px]" strokeWidth={4} paintOrder="stroke">
          {f.from === appId ? "→ " : "← "}
          {label}
        </text>
      )}
    </g>
  );
}

function Legend() {
  return (
    <div className="mt-auto flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-line px-5 py-3 text-[11.5px] text-muted">
      <span className="flex items-center gap-2">
        <svg width="10" height="10"><circle cx="5" cy="5" r="4" className="fill-fg" /></svg>
        bytes sent or received, at the observed moment
      </span>
      <span className="flex items-center gap-2">
        <svg width="10" height="10"><circle cx="5" cy="5" r="3.5" className="fill-ink stroke-fg" strokeWidth="1.3" /></svg>
        explained: kernel packets Packet doesn&apos;t see (SYN, FIN)
      </span>
      <span className="text-faint">travel across the path is drawn as ½ RTT (derived)</span>
    </div>
  );
}

function bezier([p0, p1, p2, p3]: [Pt, Pt, Pt, Pt], u: number): Pt {
  const v = 1 - u;
  const a = v * v * v, b = 3 * v * v * u, c = 3 * v * u * u, d = u * u * u;
  return { x: a * p0.x + b * p1.x + c * p2.x + d * p3.x, y: a * p0.y + b * p1.y + c * p2.y + d * p3.y };
}

function truncate(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
