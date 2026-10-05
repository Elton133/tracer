import { describe, expect, it } from "vitest";

import type { Trace } from "../generated/Trace";
import github from "../../test/fixtures/github-redirect.json";
import expired from "../../test/fixtures/expired-cert.json";
import { axisTicks, buildWaterfall } from "./waterfall";

// Real traces, captured with `npm run trace -- <url> --json`.
const redirect = github as unknown as Trace;
const badCert = expired as unknown as Trace;

describe("buildWaterfall", () => {
  it("emits one row per event, with the measured span unchanged", () => {
    const w = buildWaterfall(redirect);
    expect(w.rows).toHaveLength(redirect.events.length);
    for (const row of w.rows) {
      const e = redirect.events.find((x) => x.id === row.eventId)!;
      expect(row.start).toBe(e.time.start);
      expect(row.end).toBe(e.time.end);
    }
  });

  it("groups the http→https redirect into two hops in order", () => {
    const w = buildWaterfall(redirect);
    expect(w.hops.map((h) => h.status)).toEqual([301, 200]);
    expect(w.hops[0].end).toBeLessThanOrEqual(w.hops[1].start);
    // Plain http on hop 0, so no TLS there. TLS only on hop 1.
    expect(w.rows.filter((r) => r.phase === "tls").map((r) => r.hop)).toEqual([1]);
  });

  it("keeps Packet's own DNS queries aside from the request path", () => {
    const w = buildWaterfall(redirect);
    const aside = w.rows.filter((r) => r.aside);
    expect(aside.length).toBeGreaterThan(0);
    expect(aside.every((r) => r.label.startsWith("DNS "))).toBe(true);
    // Hop spans ignore them, so they don't stretch the request's own timeline.
    expect(Math.max(...w.hops.map((h) => h.end))).toBeLessThan(Math.max(...aside.map((r) => r.end!)));
  });

  it("attaches TLS record ticks to the handshake, inside its span", () => {
    const w = buildWaterfall(badCert);
    const tls = w.rows.find((r) => r.phase === "tls")!;
    expect(tls.status).toBe("error");
    expect(tls.records.length).toBeGreaterThan(0);
    for (const t of tls.records) {
      expect(t.at).toBeGreaterThanOrEqual(tls.start);
      expect(t.at).toBeLessThanOrEqual(tls.end!);
    }
  });
});

describe("axisTicks", () => {
  it("uses 1/2/5 steps", () => {
    expect(axisTicks(1000)).toEqual([0, 200, 400, 600, 800, 1000]);
    expect(axisTicks(130)).toEqual([0, 50, 100]);
    expect(axisTicks(12)).toEqual([0, 2, 4, 6, 8, 10, 12]);
  });
});
