import { describe, expect, it } from "vitest";

import type { PathTrace } from "../generated/PathTrace";
import fixture from "../../test/fixtures/path-vercel.json";
import { hopRows, mapPoints } from "./path";

// A real traceroute to vercel.com's address, captured with `packet path 64.239.109.1 --json`.
const path = fixture as unknown as PathTrace;

describe("hopRows", () => {
  it("keeps silent hops, so the gap is visible instead of hidden", () => {
    const rows = hopRows(path, null);
    expect(rows).toHaveLength(path.hops.length);
    expect(rows.filter((r) => r.silent).length).toBeGreaterThan(0);
    expect(rows.find((r) => r.silent)!.address).toBeUndefined();
  });

  it("labels the home router and carrier NAT instead of placing them", () => {
    const rows = hopRows(path, null);
    expect(rows[0].kind).toMatch(/private/);
    expect(rows[0].location).toBeUndefined();
    expect(rows.some((r) => r.kind?.includes("carrier-grade NAT"))).toBe(true);
  });

  it("ends at the target", () => {
    const rows = hopRows(path, null);
    expect(rows.at(-1)!.isTarget).toBe(true);
  });

  it("rules out router locations the RTT can't reach, and keeps them off the line", () => {
    const capeTown = { lat: -33.92, lon: 18.42 };
    const rows = hopRows(path, capeTown);
    const out = rows.filter((r) => r.plausibility === "impossible");
    expect(out.length).toBeGreaterThan(0); // the database's California for ~25 ms hops
    const onLine = new Set(mapPoints(rows).map((p) => p.ttl));
    for (const r of out) expect(onLine.has(r.ttl)).toBe(false);
  });
});
