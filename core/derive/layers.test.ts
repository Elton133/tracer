import { describe, expect, it } from "vitest";

import type { Trace } from "../generated/Trace";
import github from "../../test/fixtures/github-redirect.json";
import { buildStacks } from "./layers";

const trace = github as unknown as Trace;
const stacks = buildStacks(trace);
const of = (kind: string, hop: number) => {
  const e = trace.events.find((x) => x.kind === kind && x.hopIndex === hop)!;
  return stacks.find((s) => s.eventId === e.id)!.entries;
};

describe("buildStacks", () => {
  it("HTTPS request: HTTP and TLS and TCP observed, IP derived, link explained", () => {
    const s = of("http.request", 1);
    expect(s.map((x) => [x.protocol, x.evidence])).toEqual([
      ["http/1.1", "observed"],
      ["tls", "observed"],
      ["tcp", "observed"],
      ["ipv4", "derived"],
      ["link", "explained"],
      ["signal", "explained"],
    ]);
  });

  it("plain HTTP (hop 0) has no TLS layer", () => {
    expect(of("http.request", 0).map((x) => x.protocol)).not.toContain("tls");
  });

  it("takes layer placement from the engine's registry", () => {
    const tls = of("tls.handshake", 1).find((x) => x.protocol === "tls")!;
    expect(tls.osi).toEqual([5, 6]);
    expect(tls.tcpip).toBe("application");
    expect(tls.note).toMatch(/teaching convention/);
  });

  it("never claims to have observed anything below layer 4", () => {
    for (const s of stacks) {
      for (const x of s.entries) {
        if (Math.max(...x.osi) <= 3) expect(x.evidence).not.toBe("observed");
      }
    }
  });

  it("local steps (parse, address check, redirect decision) light no layers", () => {
    const local = new Set(trace.events.filter((e) => ["url.parse", "guard.check", "http.redirect"].includes(e.kind)).map((e) => e.id));
    expect(stacks.some((s) => local.has(s.eventId))).toBe(false);
  });
});
