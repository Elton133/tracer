// A traceroute, turned into rows and map points.
//
// Each router that answered gets the same physics check as a server: half
// its fastest RTT × 200 km/ms is the farthest away it can be. A database
// location outside that is ruled out, and the map won't route a line
// through it.

import type { GeoPoint } from "../generated/GeoPoint";
import type { PathTrace } from "../generated/PathTrace";
import { distanceKm, type LatLon, type Plausibility } from "./geo";

export interface HopRow {
  ttl: number;
  address?: string;
  /** Other addresses that answered for the same TTL (load-balanced links). */
  alternates: string[];
  /** private / CGNAT / … when it isn't an ordinary public address. */
  kind?: string;
  bestRttMs?: number;
  rtts: (number | undefined)[];
  location?: GeoPoint;
  maxKm?: number;
  plausibility: Plausibility;
  isTarget: boolean;
  silent: boolean;
}

export function hopRows(path: PathTrace, you: LatLon | null): HopRow[] {
  return path.hops.map((h) => {
    const probes = h.probes.value;
    const [first, ...rest] = h.responders;
    const rtts = probes.map((p) => p.rttMs ?? undefined);
    const best = first ? probes.filter((p) => p.from === first.address && p.rttMs !== undefined).reduce((m, p) => Math.min(m, p.rttMs!), Infinity) : Infinity;
    const location = first?.location?.value;
    const maxKm = first?.maxKm?.value;
    const plausibility: Plausibility =
      !you || !location || maxKm === undefined ? "unknown" : distanceKm(you, location) <= maxKm ? "possible" : "impossible";
    return {
      ttl: h.ttl,
      address: first?.address,
      alternates: rest.map((r) => r.address),
      kind: first?.class?.value,
      bestRttMs: Number.isFinite(best) ? best : undefined,
      rtts,
      location,
      maxKm,
      plausibility,
      isTarget: first?.address === path.target,
      silent: h.responders.length === 0,
    };
  });
}

/**
 * Points for the map line, in TTL order: only routers we could place and
 * that the RTT doesn't rule out. Silent and private hops simply aren't on it.
 */
export function mapPoints(rows: HopRow[]): { ttl: number; point: GeoPoint }[] {
  return rows.filter((r) => r.location && r.plausibility !== "impossible").map((r) => ({ ttl: r.ttl, point: r.location! }));
}
