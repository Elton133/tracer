import { describe, expect, it } from "vitest";

import type { Trace } from "../generated/Trace";
import github from "../../test/fixtures/github-redirect.json";
import expired from "../../test/fixtures/expired-cert.json";
import { buildJourney } from "./journey";

const redirect = github as unknown as Trace;
const badCert = expired as unknown as Trace;

describe("buildJourney", () => {
  it("uses only observed entities as nodes, never invented routers", () => {
    const j = buildJourney(redirect);
    const ids = new Set(redirect.entities.map((e) => e.id));
    expect(j.nodes.every((n) => ids.has(n.id))).toBe(true);
    expect(j.nodes[0].role).toBe("client-app");
  });

  it("anchors every observed TLS flight exactly at a recorded record time", () => {
    const j = buildJourney(badCert);
    const tls = badCert.events.find((e) => e.kind === "tls.handshake")!;
    if (tls.kind !== "tls.handshake") throw new Error();
    const times = new Set(tls.data.records.value.map((r) => r.atMs));
    const flights = j.flights.filter((f) => f.eventId === tls.id);
    expect(flights).toHaveLength(tls.data.records.value.length);
    for (const f of flights) {
      // Sent: departs at the observed moment. Received: arrives at it.
      const anchor = f.from === "app" ? f.depart : f.arrive;
      expect(times.has(anchor)).toBe(true);
      expect(f.evidence).toBe("observed");
    }
  });

  it("marks the kernel's handshake packets as explained, inside the connect span", () => {
    const j = buildJourney(redirect);
    const syn = j.flights.filter((f) => f.label === "SYN" || f.label === "SYN-ACK");
    expect(syn.length).toBeGreaterThan(0);
    for (const f of syn) {
      expect(f.evidence).toBe("explained");
      const e = redirect.events.find((x) => x.id === f.eventId)!;
      expect(f.depart).toBeGreaterThanOrEqual(e.time.start);
      expect(f.arrive).toBeLessThanOrEqual(e.time.end!);
    }
  });

  it("plain http (hop 0) gets HTTP flights from request/response timings", () => {
    const j = buildJourney(redirect);
    const labels = j.flights.map((f) => f.label);
    expect(labels).toContain("HTTP GET /");
    expect(labels.some((l) => l.startsWith("HTTP 301"))).toBe(true);
  });
});
