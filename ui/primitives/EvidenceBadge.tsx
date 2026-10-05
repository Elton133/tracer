import type { Evidence } from "@/core/generated/Evidence";

// Monochrome on purpose: evidence must never be confused with protocol colour.
// observed = solid, derived = outlined, explained = dashed, simulated = hatched.
const styles: Record<Evidence, string> = {
  observed: "bg-fg text-ink border-fg",
  derived: "border-muted text-muted",
  explained: "border-dashed border-faint text-faint",
  simulated: "hatch border-faint text-muted",
};

const titles: Record<Evidence, string> = {
  observed: "Measured or captured directly during this request",
  derived: "Computed from observed values by a named rule",
  explained: "Educational description of what generally happens",
  simulated: "Generated on purpose by the simulator",
};

export function EvidenceBadge({ evidence }: { evidence: Evidence }) {
  return (
    <span
      title={titles[evidence]}
      className={`inline-flex h-4 shrink-0 items-center rounded-[3px] border px-1 font-mono text-[9px] font-medium tracking-[0.08em] uppercase ${styles[evidence]}`}
    >
      {evidence}
    </span>
  );
}
