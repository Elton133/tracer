"use client";

import { useEffect, useRef, useState } from "react";

import type { Trace } from "@/core/generated/Trace";
import { Inspector } from "@/ui/inspector/Inspector";
import { LayerStrip } from "@/ui/layers/LayerStrip";
import { Journey } from "@/ui/views/journey/Journey";
import { MapView } from "@/ui/views/map/MapView";
import { TlsView } from "@/ui/views/tls/TlsView";
import { Waterfall } from "@/ui/views/waterfall/Waterfall";
import { PlaybackBar } from "./PlaybackBar";
import { StageRail } from "./StageRail";
import { TopBar } from "./TopBar";
import { useWorkspace, WorkspaceProvider, type PathLoad, type View, type You } from "./store";

type Load =
  | { state: "tracing"; since: number }
  | { state: "done"; trace: Trace }
  | { state: "failed"; error: string; message: string };

export function TraceWorkspace({ url }: { url: string }) {
  const [load, setLoad] = useState<Load>({ state: "tracing", since: 0 });
  // A trace is a real network action, so it must run exactly once per page
  // visit, including under React's dev-mode double effects.
  const started = useRef<string | null>(null);

  useEffect(() => {
    if (started.current === url) return;
    started.current = url;
    setLoad({ state: "tracing", since: performance.now() });
    fetch("/api/trace", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
    })
      .then(async (res) => {
        const body = await res.json();
        if (res.ok) setLoad({ state: "done", trace: body as Trace });
        else setLoad({ state: "failed", error: body.error ?? `http_${res.status}`, message: body.message ?? res.statusText });
      })
      .catch((e: unknown) => setLoad({ state: "failed", error: "network", message: String(e) }));
  }, [url]);

  if (load.state !== "done") {
    return (
      <div className="grid h-dvh grid-rows-[48px_1fr]">
        <TopBar url={url} />
        <div className="grid place-items-center px-4">
          {load.state === "tracing" ? <Tracing url={url} since={load.since} /> : <Failed {...load} />}
        </div>
      </div>
    );
  }

  return <Workspace url={url} trace={load.trace} />;
}

/** The workspace for a finished trace: any trace, however it was obtained. */
export function Workspace({
  url,
  trace,
  initialSelectedId,
  initialT,
  initial,
}: {
  url: string;
  trace: Trace;
  initialSelectedId?: string;
  initialT?: number;
  initial?: { view?: View; you?: You; paths?: Record<string, PathLoad> };
}) {
  return (
    <WorkspaceProvider key={trace.id} trace={trace} initialSelectedId={initialSelectedId} initialT={initialT} initial={initial}>
      <div className="grid h-dvh grid-rows-[48px_minmax(0,1fr)_auto_52px]">
        <TopBar url={url} trace={trace} />
        <div className="grid min-h-0 grid-cols-1 md:grid-cols-[200px_minmax(0,1fr)] xl:grid-cols-[200px_minmax(0,1fr)_360px]">
          <aside className="hidden min-h-0 border-r border-line bg-panel md:block">
            <StageRail />
          </aside>
          <main className="flex min-h-0 flex-col">
            <ViewTabs />
            <div className="min-h-0 flex-1 overflow-auto">
              <MainView />
            </div>
          </main>
          <aside className="hidden min-h-0 border-l border-line bg-panel xl:block">
            <Inspector />
          </aside>
        </div>
        <section aria-label="Network layers" className="border-t border-line bg-panel">
          <LayerStrip />
        </section>
        <footer className="border-t border-line bg-panel">
          <PlaybackBar />
        </footer>
      </div>
    </WorkspaceProvider>
  );
}

const VIEWS: { id: View; name: string }[] = [
  { id: "journey", name: "Journey" },
  { id: "waterfall", name: "Waterfall" },
  { id: "map", name: "Map" },
  { id: "tls", name: "TLS" },
];

function ViewTabs() {
  const { state, dispatch } = useWorkspace();
  return (
    <div className="flex h-9 shrink-0 items-stretch gap-5 border-b border-line px-5">
      {VIEWS.map((v) => (
        <button
          key={v.id}
          type="button"
          onClick={() => dispatch({ type: "view", view: v.id })}
          className={`-mb-px border-b font-mono text-[10.5px] tracking-[0.14em] uppercase transition-colors ${
            state.view === v.id ? "border-fg text-fg" : "border-transparent text-faint hover:text-muted"
          }`}
        >
          {v.name}
        </button>
      ))}
    </div>
  );
}

function MainView() {
  const { view } = useWorkspace().state;
  switch (view) {
    case "journey":
      return <Journey />;
    case "waterfall":
      return <Waterfall />;
    case "map":
      return <MapView />;
    case "tls":
      return <TlsView />;
  }
}

function Tracing({ url, since }: { url: string; since: number }) {
  const [now, setNow] = useState(since);
  useEffect(() => {
    const id = setInterval(() => setNow(performance.now()), 100);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="max-w-md text-center">
      <div className="mx-auto mb-6 h-px w-48 overflow-hidden bg-line">
        <div className="h-px w-1/3 animate-[slide_1.2s_ease-in-out_infinite] bg-fg/70" />
      </div>
      <p className="font-mono text-[13px] break-all text-fg">{url}</p>
      <p className="mt-3 text-[13px] leading-relaxed text-muted">
        Making a real request from this machine. Nothing is shown until it has actually happened.
      </p>
      <p className="mt-4 font-mono text-[11px] text-faint tabular-nums">{((now - since) / 1000).toFixed(1)} s</p>
      <style>{`@keyframes slide { from { transform: translateX(-100%) } to { transform: translateX(300%) } }`}</style>
    </div>
  );
}

function Failed({ error, message }: { error: string; message: string }) {
  return (
    <div className="max-w-md space-y-3">
      <p className="font-mono text-[11px] tracking-[0.12em] text-p-error uppercase">{error.replace(/_/g, " ")}</p>
      <p className="text-[14px] leading-relaxed text-fg">{message}</p>
      {error === "engine_unavailable" && (
        <pre className="rounded border border-line bg-panel p-3 font-mono text-[12px] text-muted">npm run packetd</pre>
      )}
    </div>
  );
}
