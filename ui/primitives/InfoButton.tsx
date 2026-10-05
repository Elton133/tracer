"use client";

import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

import type { Explanation } from "@/content/explain";
import type { TraceEvent } from "@/core/generated/TraceEvent";
import { EvidenceBadge } from "./EvidenceBadge";

const W = 380;

/**
 * A small (i) that opens "what happens at this step". Rendered into
 * document.body so scrolling panels can't clip it.
 */
export function InfoButton({ explanation, event, className = "" }: { explanation: Explanation; event?: TraceEvent; className?: string }) {
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const id = useId();

  useEffect(() => {
    if (!at) return;
    const close = () => setAt(null);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!document.getElementById(id)?.contains(t) && !button.current?.contains(t)) close();
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("resize", close);
    document.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("resize", close);
      document.removeEventListener("scroll", close, true);
    };
  }, [at, id]);

  const toggle = (ev: React.MouseEvent) => {
    ev.stopPropagation();
    if (at) return setAt(null);
    const r = button.current!.getBoundingClientRect();
    // Prefer the right of the icon; flip left if it would leave the window.
    const x = r.right + 8 + W > window.innerWidth - 8 ? Math.max(8, r.left - 8 - W) : r.right + 8;
    setAt({ x, y: Math.max(8, Math.min(r.top - 8, window.innerHeight - 420)) });
  };

  return (
    <>
      <button
        ref={button}
        type="button"
        aria-label={`What happens: ${explanation.title}`}
        aria-expanded={at !== null}
        aria-controls={id}
        onClick={toggle}
        className={`grid size-4 shrink-0 place-items-center rounded-full border font-serif text-[10px] leading-none italic transition-colors ${
          at ? "border-fg bg-fg text-ink" : "border-line-strong text-faint hover:border-muted hover:text-fg"
        } ${className}`}
      >
        i
      </button>
      {at &&
        createPortal(
          <div
            id={id}
            role="dialog"
            aria-label={explanation.title}
            style={{ left: at.x, top: at.y, width: W }}
            className="fixed z-50 max-h-[420px] overflow-y-auto rounded border border-line-strong bg-panel p-4 shadow-2xl shadow-black/60"
          >
            <ExplanationBody explanation={explanation} event={event} />
          </div>,
          document.body,
        )}
    </>
  );
}

/** Shared by the popover and the inspector. */
export function ExplanationBody({ explanation: x, event, compact = false }: { explanation: Explanation; event?: TraceEvent; compact?: boolean }) {
  const line = event && x.inTrace ? x.inTrace(event) : null;
  return (
    <div className="space-y-3 text-[12.5px] leading-relaxed">
      {!compact && (
        <div className="flex items-start justify-between gap-3">
          <h3 className="text-[14px] font-medium text-fg">{x.title}</h3>
          <EvidenceBadge evidence="explained" />
        </div>
      )}
      <p className="text-fg/90">{x.summary}</p>
      <ol className="list-decimal space-y-1 pl-4 text-muted marker:text-faint">
        {x.happens.map((h) => (
          <li key={h}>{h}</li>
        ))}
      </ol>
      <dl className="space-y-1.5 text-[12px]">
        <div>
          <dt className="inline text-faint">Layer: </dt>
          <dd className="inline text-muted">{x.layer}</dd>
        </div>
        <div>
          <dt className="inline text-faint">Packet sees: </dt>
          <dd className="inline text-muted">{x.sees}</dd>
        </div>
        {x.cannot && (
          <div>
            <dt className="inline text-faint">Packet can&apos;t see: </dt>
            <dd className="inline text-muted">{x.cannot}</dd>
          </div>
        )}
      </dl>
      {line && (
        <div className="flex items-start justify-between gap-3 rounded border border-line p-2 text-[12px] text-fg/90">
          <span>{line}</span>
          <span className="shrink-0 font-mono text-[9px] tracking-[0.08em] text-faint uppercase">from this trace</span>
        </div>
      )}
      {x.tryIt && (
        <div>
          <div className="text-[11px] text-faint">Try it yourself</div>
          <pre className="mt-1 overflow-x-auto rounded border border-line bg-ink px-2 py-1.5 font-mono text-[11px] text-fg/90">{x.tryIt}</pre>
        </div>
      )}
    </div>
  );
}
