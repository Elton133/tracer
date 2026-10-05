// Where the servers are, as far as the evidence allows, and what the RTT
// says about it.
//
// The physics: light in optical fibre travels at about 2/3 of c, roughly
// 200 km per millisecond. A round trip of R ms therefore means the far end
// is at most R/2 × 200 km away, as the crow flies. Real cables aren't
// straight and routers add delay, so the true distance is always less. The
// bound can't place a server, but it can rule locations *out*.

import type { EdgeLocation } from "../generated/EdgeLocation";
import type { Fact } from "../generated/Fact";
import type { GeoPoint } from "../generated/GeoPoint";
import type { Trace } from "../generated/Trace";

export const FIBRE_KM_PER_MS = 200;
const EARTH_KM = 6371;

export interface LatLon {
  lat: number;
  lon: number;
}

export interface ServerSite {
  entityId: string;
  label: string;
  address: string;
  /** IP-geolocation estimate (derived, third-party). */
  db?: Fact<GeoPoint>;
  /** Data centers the CDN said answered (observed header, derived coordinates). */
  edges: EdgeLocation[];
  /** Fastest TCP handshake to this server: the tightest bound we have. */
  rttMs?: number;
  ttfbMs?: number;
  /** Farthest the server can be from the vantage point, from rttMs. */
  maxKm?: number;
  hops: number[];
  connectionIds: string[];
}

export function buildSites(trace: Trace): ServerSite[] {
  const sites = new Map<string, ServerSite>();
  for (const ent of trace.entities) {
    if (ent.role !== "server") continue;
    sites.set(ent.id, {
      entityId: ent.id,
      label: ent.label,
      address: ent.addresses[0]?.value ?? "",
      db: ent.location,
      edges: [],
      hops: [],
      connectionIds: [],
    });
  }
  const byConn = new Map<string, ServerSite>();
  for (const e of trace.events) {
    if (e.kind === "tcp.connect" && e.to && e.connectionId && e.status === "ok") {
      const s = sites.get(e.to);
      if (!s) continue;
      byConn.set(e.connectionId, s);
      s.connectionIds.push(e.connectionId);
      if (!s.hops.includes(e.hopIndex)) s.hops.push(e.hopIndex);
      const rtt = e.data.rttEstimateMs?.value;
      if (rtt !== undefined && (s.rttMs === undefined || rtt < s.rttMs)) s.rttMs = rtt;
    }
  }
  for (const e of trace.events) {
    if (e.kind !== "http.response" || !e.connectionId) continue;
    const s = byConn.get(e.connectionId);
    if (!s) continue;
    if (e.data.ttfbMs && s.ttfbMs === undefined) s.ttfbMs = e.data.ttfbMs.value;
    const edge = e.data.edge;
    if (edge && !s.edges.some((x) => x.code.value === edge.code.value)) s.edges.push(edge);
  }
  for (const s of sites.values()) {
    if (s.rttMs !== undefined) s.maxKm = (s.rttMs / 2) * FIBRE_KM_PER_MS;
  }
  return [...sites.values()].filter((s) => s.connectionIds.length > 0);
}

/** Great-circle distance (haversine). */
export function distanceKm(a: LatLon, b: LatLon): number {
  const rad = Math.PI / 180;
  const dLat = (b.lat - a.lat) * rad;
  const dLon = (b.lon - a.lon) * rad;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

export type Plausibility = "possible" | "impossible" | "unknown";

/** Could a server at `p` have answered within the measured RTT? */
export function plausibility(site: ServerSite, you: LatLon | null, p: LatLon): Plausibility {
  if (!you || site.maxKm === undefined) return "unknown";
  return distanceKm(you, p) <= site.maxKm ? "possible" : "impossible";
}
