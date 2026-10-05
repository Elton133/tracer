import Link from "next/link";

import type { Trace } from "@/core/generated/Trace";

export function TopBar({ url, trace }: { url: string; trace?: Trace }) {
  return (
    <header className="flex h-full items-center gap-6 border-b border-line px-4">
      <Link href="/" className="font-mono text-[13px] font-semibold tracking-[0.28em] text-fg">
        PACKET
      </Link>
      <nav className="flex items-center gap-4 font-mono text-[11px] tracking-[0.14em] uppercase">
        <span className="text-fg">Trace</span>
        <span className="cursor-not-allowed text-faint" title="Simulation lab: coming in V2">
          Lab
        </span>
      </nav>

      <form action="/trace" className="flex min-w-0 flex-1 items-center">
        <input
          name="url"
          defaultValue={url}
          spellCheck={false}
          aria-label="URL to trace"
          className="h-8 min-w-0 flex-1 rounded-l border border-line-strong bg-panel px-3 font-mono text-[12.5px] text-fg focus:border-muted focus:outline-none"
        />
        <button className="h-8 shrink-0 rounded-r border border-l-0 border-line-strong bg-raised px-3 font-mono text-[11px] tracking-[0.12em] text-fg uppercase transition-colors hover:bg-line-strong">
          Trace
        </button>
      </form>

      {trace && (
        <div className="hidden shrink-0 items-center gap-2 text-[12px] lg:flex" title={trace.vantage.runtime}>
          <span className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase">Observed from</span>
          <span className="text-muted">{trace.vantage.description}</span>
        </div>
      )}
    </header>
  );
}
