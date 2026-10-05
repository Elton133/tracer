"use client";

import { geoCircle, geoGraticule10, geoInterpolate, geoNaturalEarth1, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";

import { buildSites, distanceKm, plausibility, type LatLon, type ServerSite } from "@/core/derive/geo";
import { buildJourney, type Flight } from "@/core/derive/journey";
import { hopRows, mapPoints, type HopRow } from "@/core/derive/path";
import type { PathTrace } from "@/core/generated/PathTrace";
import { EvidenceBadge } from "@/ui/primitives/EvidenceBadge";
import { ms } from "@/ui/primitives/format";
import { phaseColor } from "@/ui/primitives/protocol";
import { useWorkspace, type PathLoad, type You } from "@/ui/workspace/store";

const W = 960;
const H = 520;
const KM_PER_DEG = 111.195;

const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
const COUNTRIES = feature(topo, topo.objects.countries) as FeatureCollection;

type Locate = { state: "idle" } | { state: "asking" } | { state: "denied"; message: string } | { state: "ok"; you: You };

export function MapView() {
  const { state, dispatch } = useWorkspace();
  const { trace, t } = state;
  const sites = useMemo(() => buildSites(trace), [trace]);
  const flights = useMemo(() => buildJourney(trace).flights, [trace]);
  const [request, setRequest] = useState<Locate>({ state: "idle" });
  const you = state.you;
  const loc: Locate = you ? { state: "ok", you } : request;
  // The RTT bound is measured from wherever the engine ran. Only when that is
  // this machine does the browser's position stand in for it.
  const bound = trace.vantage.isUserMachine;

  const locate = () => {
    if (!("geolocation" in navigator)) return setRequest({ state: "denied", message: "This browser has no location support." });
    setRequest({ state: "asking" });
    navigator.geolocation.getCurrentPosition(
      (p) => {
        setRequest({ state: "idle" });
        dispatch({ type: "you", you: { lat: p.coords.latitude, lon: p.coords.longitude, accuracyM: p.coords.accuracy } });
      },
      (e) => setRequest({ state: "denied", message: e.message || "Permission denied." }),
      { enableHighAccuracy: false, timeout: 15_000, maximumAge: 600_000 },
    );
  };

  const hasGeo = sites.some((s) => s.db || s.edges.length);
  const meYou = bound ? you : null;
  const routes = sites.flatMap((s) => {
    const load = state.paths[s.address];
    return load?.state === "done" ? [{ site: s, path: load.path, rows: hopRows(load.path, meYou) }] : [];
  });

  const runPath = (target: string) => {
    dispatch({ type: "path", target, load: { state: "running" } });
    fetch("/api/path", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target }) })
      .then(async (res) => {
        const body = await res.json();
        dispatch({
          type: "path",
          target,
          load: res.ok ? { state: "done", path: body as PathTrace } : { state: "failed", message: body.message ?? res.statusText },
        });
      })
      .catch((e: unknown) => dispatch({ type: "path", target, load: { state: "failed", message: String(e) } }));
  };

  return (
    <div className="flex min-h-full flex-col">
      <WorldMap sites={sites} you={you} bound={bound} t={t} flights={flights} routes={routes} />
      <p className="px-5 pb-1 text-[11px] leading-relaxed text-faint">
        Dotted arcs are straight lines, <span className="text-muted">not the route packets took</span>.
        {routes.length > 0 && <> Solid lines join the routers a traceroute found, drawn at their database locations (estimates).</>}
        {hasGeo && (
          <>
            {" "}IP geolocation by{" "}
            <a href="https://db-ip.com" className="underline decoration-line-strong hover:text-muted">DB-IP</a> (CC BY 4.0) · airport
            codes: OurAirports · map: Natural Earth.
          </>
        )}
      </p>

      <div className="grid gap-4 p-4 md:grid-cols-2 2xl:grid-cols-3">
        <div className="space-y-4">
          <YouControl loc={loc} onLocate={locate} onForget={() => dispatch({ type: "you", you: null })} />
          {!bound && (
            <p className="rounded border border-line p-3 text-[12px] leading-relaxed text-muted">
              This trace ran on {trace.vantage.description}, not this device, so distances from you can&apos;t be checked against its RTT.
            </p>
          )}
          {!hasGeo && (
            <p className="rounded border border-line p-3 text-[12px] leading-relaxed text-muted">
              No location data in this trace. Run <code className="font-mono text-fg">npm run geo:fetch</code> and restart packetd.
            </p>
          )}
        </div>
        {sites.map((s) => (
          <SiteCard key={s.entityId} site={s} you={meYou} path={state.paths[s.address]} onTrace={() => runPath(s.address)} />
        ))}
      </div>

      {routes.map((r) => (
        <RouteTable key={r.site.entityId} label={r.site.label} path={r.path} rows={r.rows} located={meYou !== null} />
      ))}
    </div>
  );
}

interface Route {
  site: ServerSite;
  path: PathTrace;
  rows: HopRow[];
}

function WorldMap({
  sites,
  you,
  bound,
  t,
  flights,
  routes,
}: {
  sites: ServerSite[];
  you: You | null;
  bound: boolean;
  t: number;
  flights: Flight[];
  routes: Route[];
}) {
  const { state } = useWorkspace();

  const projection = useMemo(() => {
    // Fit to everything we can place, padded with small circles so a single
    // city doesn't zoom to street level.
    const pts: LatLon[] = [
      ...(you ? [you] : []),
      ...sites.flatMap((s) => [s.db?.value, ...s.edges.map((e) => e.point?.value)].filter(Boolean) as LatLon[]),
      ...routes.flatMap((r) => mapPoints(r.rows).map((p) => p.point)),
    ];
    const p = geoNaturalEarth1();
    if (pts.length === 0) return p.fitExtent([[16, 16], [W - 16, H - 16]], { type: "Sphere" });
    const pads: Feature<Geometry>[] = pts.map((x) => ({ type: "Feature", properties: {}, geometry: geoCircle().center([x.lon, x.lat]).radius(9)() }));
    return p.fitExtent([[24, 24], [W - 24, H - 24]], { type: "FeatureCollection", features: pads });
  }, [sites, you, routes]);

  // Fixed precision: server and browser trig differ in the last few digits,
  // and full-precision coordinates would fail hydration.
  const path = geoPath(projection).digits(1);
  const round = ([x, y]: [number, number]): [number, number] => [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
  const xy = (p: LatLon) => round(projection([p.lon, p.lat]) ?? [-999, -999]);
  const active = (s: ServerSite) =>
    state.trace.events.some((e) => e.connectionId && s.connectionIds.includes(e.connectionId) && e.time.end !== undefined && t >= e.time.start && t <= e.time.end);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" role="img" aria-label="Map of the servers in this trace">
      <defs>
        <clipPath id="map-clip">
          <rect width={W} height={H} />
        </clipPath>
      </defs>
      <g clipPath="url(#map-clip)">
        <path d={path({ type: "Sphere" }) ?? ""} className="fill-ink stroke-line" />
        <path d={path(geoGraticule10()) ?? ""} className="fill-none stroke-line/50" strokeWidth={0.5} />
        <path d={path(COUNTRIES) ?? ""} className="fill-panel stroke-line-strong" strokeWidth={0.5} />

        {/* The physics bound: nowhere outside this circle could have answered in time. */}
        {you &&
          bound &&
          sites.map((s) =>
            s.maxKm !== undefined && s.maxKm / KM_PER_DEG < 175 ? (
              <path
                key={`b-${s.entityId}`}
                d={path(geoCircle().center([you.lon, you.lat]).radius(s.maxKm / KM_PER_DEG)()) ?? ""}
                className="fill-p-tcp/[0.04] stroke-p-tcp/50"
                strokeDasharray="4 4"
                strokeWidth={1}
              />
            ) : null,
          )}

        {/* You → each server, straight arcs. */}
        {you &&
          sites.map((s) => {
            const target = s.edges[0]?.point?.value ?? s.db?.value;
            if (!target) return null;
            const line = { type: "LineString" as const, coordinates: [[you.lon, you.lat], [target.lon, target.lat]] };
            const mid = geoInterpolate([you.lon, you.lat], [target.lon, target.lat])(0.5);
            const [mx, my] = round(projection(mid) ?? [0, 0]);
            const [ax, ay] = xy(you);
            const [bx, by] = xy(target);
            const long = Math.hypot(bx - ax, by - ay) > 140;
            const lit = active(s);
            return (
              <g key={`l-${s.entityId}`} className={lit ? "text-p-http" : "text-muted"}>
                <path d={path(line) ?? ""} className="fill-none stroke-current" strokeWidth={lit ? 1.6 : 1} strokeDasharray="1 4" strokeLinecap="round" />
                {long && s.rttMs !== undefined && (
                  <text x={mx} y={my - 8} textAnchor="middle" className="fill-fg stroke-ink font-mono text-[14px]" strokeWidth={4} paintOrder="stroke">
                    RTT {ms(s.rttMs)}
                  </text>
                )}
              </g>
            );
          })}

        {/* Measured routes: routers in TTL order, at their (estimated) locations. */}
        {routes.map((r) => {
          const pts = mapPoints(r.rows).filter((p) => !r.rows.find((x) => x.ttl === p.ttl)?.isTarget);
          const end = r.site.edges[0]?.point?.value ?? r.site.db?.value;
          const coords = [...(you && bound ? [[you.lon, you.lat]] : []), ...pts.map((p) => [p.point.lon, p.point.lat]), ...(end ? [[end.lon, end.lat]] : [])];
          return (
            <g key={`r-${r.site.entityId}`}>
              {coords.length > 1 && (
                <path d={path({ type: "LineString", coordinates: coords }) ?? ""} className="fill-none stroke-fg/60" strokeWidth={1.3} />
              )}
              {pts.map((p) => (
                <g key={p.ttl} transform={`translate(${xy(p.point).join(",")})`}>
                  <circle r={3.5} className="fill-ink stroke-fg" strokeWidth={1.2} />
                  <text x={6} y={-6} className="fill-muted stroke-ink font-mono text-[12px]" strokeWidth={4} paintOrder="stroke">
                    {p.ttl}
                  </text>
                </g>
              ))}
            </g>
          );
        })}

        {/* Bytes in flight, travelling the arc (travel time is ½ RTT, derived). */}
        {you &&
          flights
            .filter((f) => t >= f.depart && t <= f.arrive)
            .map((f, i) => {
              const s = sites.find((x) => x.entityId === f.to || x.entityId === f.from);
              const target = s && (s.edges[0]?.point?.value ?? s.db?.value);
              if (!target) return null;
              const u = (t - f.depart) / Math.max(f.arrive - f.depart, 1e-6);
              const along = geoInterpolate([you.lon, you.lat], [target.lon, target.lat])(f.from === "app" ? u : 1 - u);
              const [x, y] = round(projection(along) ?? [0, 0]);
              return f.evidence === "observed" ? (
                <circle key={i} cx={x} cy={y} r={4} className={`fill-current ${phaseColor[f.phase]}`} />
              ) : (
                <circle key={i} cx={x} cy={y} r={4} className={`fill-ink stroke-current ${phaseColor[f.phase]}`} strokeWidth={1.4} />
              );
            })}

        {sites.map((s) => {
          const db = s.db?.value;
          const ruledOut = db && plausibility(s, bound ? you : null, db) === "impossible";
          return (
            <g key={`m-${s.entityId}`}>
              {db && (
                <g transform={`translate(${xy(db).join(",")})`}>
                  <circle r={6} className={`fill-none ${ruledOut ? "stroke-p-error" : "stroke-muted"}`} strokeWidth={1.4} />
                  <text x={10} y={4} className={`stroke-ink font-mono text-[14px] ${ruledOut ? "fill-p-error" : "fill-muted"}`} strokeWidth={4} paintOrder="stroke">
                    {`database: ${db.place || s.address}${ruledOut ? " (ruled out by RTT)" : ""}`}
                  </text>
                </g>
              )}
              {s.edges.map((e) =>
                e.point ? (
                  <g key={e.code.value} transform={`translate(${xy(e.point.value).join(",")})`}>
                    <rect x={-5} y={-5} width={10} height={10} className="fill-fg" />
                    <text x={10} y={-6} className="fill-fg stroke-ink font-mono text-[14px]" strokeWidth={4} paintOrder="stroke">
                      {`${e.provider.value} ${e.code.value}`}
                    </text>
                  </g>
                ) : null,
              )}
            </g>
          );
        })}

        {you && (
          <g transform={`translate(${xy(you).join(",")})`}>
            <circle r={9} className="fill-fg/15" />
            <circle r={4.5} className="fill-fg" />
            <text x={0} y={-15} textAnchor="middle" className="fill-fg stroke-ink font-mono text-[13px] tracking-[0.14em]" strokeWidth={4} paintOrder="stroke">
              YOU
            </text>
          </g>
        )}
      </g>
    </svg>
  );
}

function YouControl({ loc, onLocate, onForget }: { loc: Locate; onLocate: () => void; onForget: () => void }) {
  return (
    <div className="space-y-2">
      <div className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">Your location</div>
      {loc.state === "ok" ? (
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="font-mono text-[12.5px] text-fg tabular-nums">
              {loc.you.lat.toFixed(3)}, {loc.you.lon.toFixed(3)}
            </div>
            <div className="text-[11px] text-muted">from your browser, ±{Math.round(loc.you.accuracyM).toLocaleString()} m</div>
          </div>
          <button type="button" onClick={onForget} className="font-mono text-[10.5px] text-faint uppercase hover:text-muted">
            Forget
          </button>
        </div>
      ) : (
        <>
          <button
            type="button"
            onClick={onLocate}
            disabled={loc.state === "asking"}
            className="h-8 w-full rounded border border-line-strong bg-raised font-mono text-[11px] tracking-[0.12em] text-fg uppercase transition-colors hover:bg-line-strong disabled:opacity-50"
          >
            {loc.state === "asking" ? "Waiting for permission…" : "Show me on the map"}
          </button>
          <p className="text-[11px] leading-relaxed text-faint">
            Your browser asks first. The position stays in this page: it isn&apos;t sent to packetd or anywhere else.
          </p>
          {loc.state === "denied" && <p className="text-[11.5px] text-p-error">{loc.message}</p>}
        </>
      )}
    </div>
  );
}

function SiteCard({ site, you, path, onTrace }: { site: ServerSite; you: You | null; path?: PathLoad; onTrace: () => void }) {
  const db = site.db;
  return (
    <section className="space-y-3 rounded border border-line p-3">
      <header>
        <div className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">Server · hop {site.hops.join(", ")}</div>
        <div className="mt-0.5 text-[14px] text-fg">{site.label}</div>
        <div className="font-mono text-[11px] break-all text-muted">{site.address}</div>
      </header>

      {site.edges.map((e) => (
        <Line
          key={e.code.value}
          k={`${e.provider.value} says`}
          v={`${e.code.value}${e.point ? ` · ${e.point.value.place}` : ""}`}
          ev="observed"
          src={e.code.source}
          extra={you && e.point ? verdictText(site, you, e.point.value) : undefined}
        />
      ))}
      {db ? (
        <Line k="Database says" v={db.value.place || "unknown place"} ev="derived" src={db.source} extra={you ? verdictText(site, you, db.value) : undefined} />
      ) : (
        <Line k="Database says" v="no location" ev="derived" src="no geolocation for this address" />
      )}
      {site.rttMs !== undefined && (
        <Line k="Round trip" v={ms(site.rttMs)} ev="derived" src="TCP handshake duration" />
      )}
      {site.ttfbMs !== undefined && <Line k="First byte after request" v={ms(site.ttfbMs)} ev="observed" src="TTFB" />}
      {site.maxKm !== undefined && (
        <Line
          k="Can't be farther than"
          v={`${Math.round(site.maxKm).toLocaleString()} km`}
          ev="derived"
          src="½ RTT × 200 km/ms (light in fibre)"
        />
      )}

      <div className="border-t border-line pt-3">
        {path?.state === "done" ? (
          <p className="text-[11.5px] text-muted">
            Route measured: {path.path.hops.length} hops, {path.path.hops.filter((h) => h.responders.length === 0).length} silent,{" "}
            {path.path.reached.value ? "reached the server" : "didn't reach the server"}. Table below.
          </p>
        ) : (
          <>
            <button
              type="button"
              onClick={onTrace}
              disabled={path?.state === "running"}
              className="h-8 w-full rounded border border-line-strong bg-raised font-mono text-[11px] tracking-[0.12em] text-fg uppercase transition-colors hover:bg-line-strong disabled:opacity-50"
            >
              {path?.state === "running" ? "Tracing route… (~5 s)" : "Trace the route"}
            </button>
            <p className="mt-1.5 text-[11px] leading-relaxed text-faint">
              traceroute: probes with TTL 1, 2, 3… so each router on the way reports itself.
            </p>
            {path?.state === "failed" && <p className="mt-1 text-[11.5px] text-p-error">{path.message}</p>}
          </>
        )}
      </div>
    </section>
  );
}

function RouteTable({ label, path, rows, located }: { label: string; path: PathTrace; rows: HopRow[]; located: boolean }) {
  return (
    <section className="mx-4 mb-6 rounded border border-line">
      <header className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line px-3 py-2.5">
        <div>
          <div className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">Route to {label}</div>
          <div className="mt-0.5 font-mono text-[11px] text-muted">
            {path.method.value} · {(path.durationMs / 1000).toFixed(1)} s · {path.target}
          </div>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-faint">
          responders &amp; times <EvidenceBadge evidence="observed" /> places &amp; limits <EvidenceBadge evidence="derived" />
        </div>
      </header>
      <table className="w-full font-mono text-[11.5px]">
        <thead className="text-left text-[10px] tracking-[0.1em] text-faint uppercase">
          <tr className="border-b border-line">
            <th className="px-3 py-1.5 font-normal">TTL</th>
            <th className="px-3 py-1.5 font-normal">Answered from</th>
            <th className="px-3 py-1.5 font-normal">What / where</th>
            <th className="px-3 py-1.5 text-right font-normal">Round trips</th>
            {located && <th className="px-3 py-1.5 font-normal">RTT check</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.ttl} className={`border-b border-line/60 last:border-b-0 ${r.silent ? "text-faint" : "text-fg/90"}`}>
              <td className="px-3 py-1.5 tabular-nums">{r.ttl}</td>
              <td className="px-3 py-1.5 break-all">
                {r.silent ? "* no answer" : r.address}
                {r.isTarget && <span className="ml-2 text-p-tls">target</span>}
                {r.alternates.length > 0 && <div className="text-faint">also {r.alternates.join(", ")}</div>}
              </td>
              <td className="px-3 py-1.5 text-muted">{r.kind ?? r.location?.place ?? (r.silent ? "" : "no location")}</td>
              <td className="px-3 py-1.5 text-right whitespace-nowrap tabular-nums">
                {r.rtts.map((x, i) => (
                  <span key={i} className={`ml-2 ${x === undefined ? "text-faint" : ""}`}>
                    {x === undefined ? "*" : ms(x)}
                  </span>
                ))}
              </td>
              {located && (
                <td className="px-3 py-1.5">
                  {r.plausibility === "impossible" ? (
                    <span className="text-p-error">place ruled out (≤ {Math.round(r.maxKm!).toLocaleString()} km)</span>
                  ) : r.plausibility === "possible" ? (
                    <span className="text-muted">consistent</span>
                  ) : (
                    <span className="text-faint">–</span>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="border-t border-line px-3 py-2 text-[11px] leading-relaxed text-faint">
        Silent hops don&apos;t answer ICMP, which is normal. A slow hop followed by faster ones means that router answers probes on a slow path, not that
        the network is slow there. Replies may come back by a different route than the probe took.
      </p>
    </section>
  );
}

function verdictText(site: ServerSite, you: LatLon, p: LatLon) {
  const km = Math.round(distanceKm(you, p)).toLocaleString();
  const v = plausibility(site, you, p);
  return v === "impossible" ? (
    <span className="text-p-error">{km} km from you: too far for a {ms(site.rttMs!)} round trip</span>
  ) : v === "possible" ? (
    <span className="text-muted">{km} km from you: consistent with the RTT</span>
  ) : undefined;
}

function Line({ k, v, ev, src, extra }: { k: string; v: string; ev: "observed" | "derived"; src: string; extra?: React.ReactNode }) {
  return (
    <div className="space-y-0.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11.5px] text-muted">{k}</span>
        <EvidenceBadge evidence={ev} />
      </div>
      <div className="font-mono text-[12.5px] text-fg">{v}</div>
      <div className="font-mono text-[10px] text-faint">{src}</div>
      {extra && <div className="text-[11px]">{extra}</div>}
    </div>
  );
}
