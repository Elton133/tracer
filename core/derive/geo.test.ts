import { describe, expect, it } from "vitest";

import type { Trace } from "../generated/Trace";
import vercel from "../../test/fixtures/vercel-cdn.json";
import github from "../../test/fixtures/github-redirect.json";
import { buildSites, distanceKm, FIBRE_KM_PER_MS, plausibility } from "./geo";

const cdn = vercel as unknown as Trace;

describe("buildSites", () => {
  it("keeps the database estimate and the CDN's own claim side by side", () => {
    const [site] = buildSites(cdn);
    expect(site.db?.evidence).toBe("derived");
    expect(site.edges).toHaveLength(1);
    expect(site.edges[0].code.evidence).toBe("observed");
    expect(site.edges[0].point?.evidence).toBe("derived");
  });

  it("derives the distance bound from the fastest handshake", () => {
    const [site] = buildSites(cdn);
    expect(site.maxKm).toBeCloseTo((site.rttMs! / 2) * FIBRE_KM_PER_MS);
  });

  it("works without any location data (older traces, no database)", () => {
    const sites = buildSites(github as unknown as Trace);
    expect(sites.length).toBeGreaterThan(0);
    expect(sites.every((s) => s.db === undefined && s.edges.length === 0)).toBe(true);
  });
});

describe("plausibility", () => {
  const capeTown = { lat: -33.92, lon: 18.42 };
  it("rules out a database location the RTT can't reach", () => {
    const [site] = buildSites(cdn);
    const db = site.db!.value;
    // From Cape Town, California is ~16,000 km away: no 40 ms round trip covers that.
    expect(distanceKm(capeTown, db)).toBeGreaterThan(site.maxKm!);
    expect(plausibility(site, capeTown, db)).toBe("impossible");
    expect(plausibility(site, capeTown, site.edges[0].point!.value)).toBe("possible");
  });

  it("is unknown until we know where you are", () => {
    const [site] = buildSites(cdn);
    expect(plausibility(site, null, site.db!.value)).toBe("unknown");
  });
});

describe("distanceKm", () => {
  it("matches a known distance", () => {
    // Lisbon ↔ London is about 1,585 km.
    expect(distanceKm({ lat: 38.72, lon: -9.14 }, { lat: 51.51, lon: -0.13 })).toBeCloseTo(1585, -1);
  });
});
