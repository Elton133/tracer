"use client";

import type { Phase, Row } from "@/core/derive/waterfall";
import { explanation } from "@/content/explain";
import { ms } from "@/ui/primitives/format";
import { InfoButton } from "@/ui/primitives/InfoButton";
import { useWorkspace } from "./store";

const STAGES: { name: string; phases: Phase[]; color: string; about: string }[] = [
  { name: "DNS", phases: ["dns"], color: "text-p-dns", about: "dns.os-resolver" },
  { name: "TCP", phases: ["tcp"], color: "text-p-tcp", about: "tcp.handshake" },
  { name: "TLS", phases: ["tls"], color: "text-p-tls", about: "tls.handshake" },
  { name: "HTTP", phases: ["request", "wait", "download"], color: "text-p-http", about: "http" },
];

export function StageRail() {
  const { state, dispatch } = useWorkspace();
  const { waterfall: w, t } = state;

  return (
    <nav className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center border-b border-line px-4 font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
        Trace
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto py-2">
        {w.hops.map((hop) => (
          <div key={hop.index} className="mb-3">
            {w.hops.length > 1 && (
              <div className="px-4 pt-1 pb-1.5 font-mono text-[10px] tracking-[0.12em] text-faint uppercase">
                Hop {hop.index} · {hop.status ?? "—"}
              </div>
            )}
            {STAGES.map((stage) => {
              const rows = w.rows.filter((r) => r.hop === hop.index && !r.aside && stage.phases.includes(r.phase));
              return <StageItem key={stage.name} stage={stage} rows={rows} t={t} onSelect={(id) => dispatch({ type: "select", id })} />;
            })}
          </div>
        ))}
      </div>
      <div className="border-t border-line px-4 py-3">
        <div className="flex items-center justify-between text-[13px] text-faint">
          <span>Packets</span>
          <span className="font-mono text-[10px] tracking-[0.1em] uppercase">Local Lab</span>
        </div>
        <p className="mt-1 text-[11px] leading-snug text-faint">
          Individual packets need capture privileges a web trace doesn&apos;t have.
        </p>
      </div>
    </nav>
  );
}

function StageItem({
  stage,
  rows,
  t,
  onSelect,
}: {
  stage: (typeof STAGES)[number];
  rows: Row[];
  t: number;
  onSelect: (id: string) => void;
}) {
  if (rows.length === 0) {
    // Not every request has every stage (plain http has no TLS). Say so instead of hiding it.
    return (
      <div className="flex h-8 items-center gap-2.5 px-4 text-[13px] text-faint/70">
        <span className="size-1.5 rounded-full border border-current" />
        <span>{stage.name}</span>
        <span className="ml-auto font-mono text-[11px]">not used</span>
      </div>
    );
  }
  const start = Math.min(...rows.map((r) => r.start));
  const end = Math.max(...rows.map((r) => r.end ?? r.start));
  const failed = rows.some((r) => r.status !== "ok");
  const reached = t >= start;
  const about = explanation(stage.about);
  return (
    <div className="relative">
    <button
      type="button"
      onClick={() => onSelect(rows[0].eventId)}
      className="flex h-8 w-full items-center gap-2.5 px-4 text-left text-[13px] transition-colors hover:bg-raised"
    >
      <span className={`size-1.5 rounded-full bg-current ${failed ? "text-p-error" : stage.color} ${reached ? "" : "opacity-30"}`} />
      <span className={reached ? "text-fg" : "text-faint"}>{stage.name}</span>
      <span className={`ml-auto font-mono text-[12px] tabular-nums ${t >= end ? "text-muted" : "text-faint/60"}`}>
        {failed ? <span className="text-p-error">failed</span> : ms(end - start)}
      </span>
    </button>
    {about && <InfoButton explanation={about} className="absolute top-2 left-[78px]" />}
    </div>
  );
}
