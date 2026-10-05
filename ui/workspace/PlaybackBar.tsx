"use client";

import { ms } from "@/ui/primitives/format";
import { SPEEDS, speedLabel, useWorkspace } from "./store";

export function PlaybackBar() {
  const { state, dispatch } = useWorkspace();
  const { t, playing, speed, waterfall } = state;
  const total = waterfall.total;

  return (
    <div className="flex h-full items-center gap-4 px-4">
      <button
        type="button"
        aria-label={playing ? "Pause" : "Play"}
        onClick={() => dispatch({ type: playing ? "pause" : "play" })}
        className="grid size-8 shrink-0 place-items-center rounded-full border border-line-strong text-fg transition-colors hover:bg-raised"
      >
        {playing ? (
          <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><rect x="1" y="0" width="3" height="10" /><rect x="6" y="0" width="3" height="10" /></svg>
        ) : (
          <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><path d="M1 0l9 5-9 5z" /></svg>
        )}
      </button>

      <div className="w-36 shrink-0 font-mono text-[12px] tabular-nums">
        <span className="text-fg">{ms(t)}</span>
        <span className="text-faint"> / {ms(total)}</span>
      </div>

      <input
        type="range"
        aria-label="Playhead"
        min={0}
        max={total}
        step={total / 1000}
        value={t}
        onChange={(e) => {
          dispatch({ type: "pause" });
          dispatch({ type: "seek", t: Number(e.target.value) });
        }}
        className="h-1 min-w-0 flex-1 cursor-pointer accent-fg"
      />

      <label className="flex shrink-0 items-center gap-2 font-mono text-[11px] text-muted">
        <span className="sr-only">Playback speed</span>
        <select
          value={speed}
          onChange={(e) => dispatch({ type: "speed", speed: Number(e.target.value) })}
          className="rounded border border-line-strong bg-panel px-2 py-1 text-fg focus:outline-none"
        >
          {SPEEDS.map((s) => (
            <option key={s} value={s}>
              {speedLabel(s)}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
