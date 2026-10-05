"use client";

// One store for the workspace. Every view renders from (trace, t, selection),
// so scrubbing, pausing and clicking stay consistent across views without
// any view coordinating with another.

import { createContext, useContext, useEffect, useMemo, useReducer, type Dispatch, type ReactNode } from "react";

import { buildWaterfall, type Waterfall } from "@/core/derive/waterfall";
import type { PathTrace } from "@/core/generated/PathTrace";
import type { Trace } from "@/core/generated/Trace";

/** Playback rates: trace milliseconds per real millisecond. */
export const SPEEDS = [5, 2, 1, 0.5, 0.25, 0.1, 0.05, 0.02, 0.01] as const;
const TARGET_PLAYBACK_MS = 5000;

export interface State {
  trace: Trace;
  waterfall: Waterfall;
  /** Playhead, in trace milliseconds. */
  t: number;
  playing: boolean;
  speed: number;
  selectedId: string | null;
  view: View;
  layerModel: LayerModel;
  layersOpen: boolean;
  /** The viewer's position, from the browser's geolocation. Never leaves the page. */
  you: You | null;
  /** Traceroutes run from the map, by target address. */
  paths: Record<string, PathLoad>;
}

export type PathLoad =
  | { state: "running" }
  | { state: "done"; path: PathTrace }
  | { state: "failed"; message: string };

export interface You {
  lat: number;
  lon: number;
  accuracyM: number;
}

export type View = "journey" | "waterfall" | "map" | "tls";
export type LayerModel = "osi" | "tcpip";

export type Action =
  | { type: "tick"; realMs: number }
  | { type: "play" }
  | { type: "pause" }
  | { type: "seek"; t: number }
  | { type: "speed"; speed: number }
  | { type: "select"; id: string | null }
  | { type: "view"; view: View }
  | { type: "layerModel"; model: LayerModel }
  | { type: "layersOpen"; open: boolean }
  | { type: "you"; you: You | null }
  | { type: "path"; target: string; load: PathLoad };

function reducer(s: State, a: Action): State {
  const total = s.waterfall.total;
  switch (a.type) {
    case "tick": {
      const t = Math.min(total, s.t + a.realMs * s.speed);
      return { ...s, t, playing: t < total };
    }
    case "play":
      return { ...s, playing: true, t: s.t >= total ? 0 : s.t };
    case "pause":
      return { ...s, playing: false };
    case "seek":
      return { ...s, t: Math.max(0, Math.min(total, a.t)) };
    case "speed":
      return { ...s, speed: a.speed };
    case "view":
      return { ...s, view: a.view };
    case "layerModel":
      return { ...s, layerModel: a.model };
    case "layersOpen":
      return { ...s, layersOpen: a.open };
    case "you":
      return { ...s, you: a.you };
    case "path":
      return { ...s, paths: { ...s.paths, [a.target]: a.load } };
    case "select": {
      // Selecting something the playhead hasn't reached yet jumps there,
      // so the selected bar is never shown half-drawn.
      const e = s.trace.events.find((x) => x.id === a.id);
      const end = e ? (e.time.end ?? e.time.start) : 0;
      return { ...s, selectedId: a.id, t: e && s.t < end ? end : s.t, playing: e && s.t < end ? false : s.playing };
    }
  }
}

/** The speed that plays the whole trace in about five seconds. */
export function autoSpeed(total: number): number {
  const ideal = total / TARGET_PLAYBACK_MS;
  return SPEEDS.reduce((best, s) => (Math.abs(Math.log(s / ideal)) < Math.abs(Math.log(best / ideal)) ? s : best));
}

export function speedLabel(speed: number): string {
  if (speed === 1) return "real time";
  if (speed > 1) return `${speed}× faster than real`;
  return `${Math.round(1 / speed)}× slower than real`;
}

const Ctx = createContext<{ state: State; dispatch: Dispatch<Action> } | null>(null);

export function WorkspaceProvider({
  trace,
  initialSelectedId,
  initialT,
  initial,
  children,
}: {
  trace: Trace;
  initialSelectedId?: string;
  /** Start paused at this moment instead of playing from 0. */
  initialT?: number;
  initial?: { view?: View; you?: You; paths?: Record<string, PathLoad> };
  children: ReactNode;
}) {
  const [state, dispatch] = useReducer(reducer, trace, (tr): State => {
    const waterfall = buildWaterfall(tr);
    const base = { trace: tr, waterfall, t: 0, playing: true, speed: autoSpeed(waterfall.total), selectedId: null, view: "journey" as View, layerModel: "osi" as LayerModel, layersOpen: true, you: initial?.you ?? null, paths: initial?.paths ?? {} };
    const selected = initialSelectedId ? reducer(base, { type: "select", id: initialSelectedId }) : base;
    const viewed = initial?.view ? { ...selected, view: initial.view } : selected;
    return initialT === undefined ? viewed : { ...viewed, t: Math.min(initialT, waterfall.total), playing: false };
  });

  // The playback clock. Real elapsed time × speed = trace time advanced.
  useEffect(() => {
    if (!state.playing) return;
    let last = performance.now();
    let frame = requestAnimationFrame(function step(now) {
      dispatch({ type: "tick", realMs: now - last });
      last = now;
      frame = requestAnimationFrame(step);
    });
    return () => cancelAnimationFrame(frame);
  }, [state.playing]);

  // Space toggles playback.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.code !== "Space" || (e.target as HTMLElement).closest("input, textarea, select, button")) return;
      e.preventDefault();
      dispatch({ type: state.playing ? "pause" : "play" });
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state.playing]);

  const value = useMemo(() => ({ state, dispatch }), [state]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWorkspace() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useWorkspace outside WorkspaceProvider");
  return v;
}
