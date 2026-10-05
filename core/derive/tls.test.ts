import { describe, expect, it } from "vitest";

import type { Trace } from "../generated/Trace";
import t12 from "../../test/fixtures/tls12.json";
import t13 from "../../test/fixtures/tls13.json";
import github from "../../test/fixtures/github-redirect.json";
import { buildTlsView, tlsHops } from "./tls";

const tls12 = t12 as unknown as Trace;
const tls13 = t13 as unknown as Trace;

describe("buildTlsView", () => {
  it("TLS 1.3: the request record is plaintext + 17 bytes", () => {
    const v = buildTlsView(tls13, 0)!;
    expect(v.encryption!.overhead).toBe(17);
    expect(v.encryption!.headerHex).toBe(`17 03 03 00 ${v.encryption!.recordLength.toString(16).padStart(2, "0")}`);
  });

  it("TLS 1.2 with AES-GCM: plaintext + 24 bytes", () => {
    expect(buildTlsView(tls12, 0)!.encryption!.overhead).toBe(24);
  });

  it("TLS 1.3 encryption starts right after ServerHello, server side first", () => {
    const v = buildTlsView(tls13, 0)!;
    const clear = v.ladder.filter((r) => !r.encrypted).flatMap((r) => r.messages);
    expect(clear).toEqual(["ClientHello", "ServerHello"]);
    expect(v.encryptedFrom.received).toBeLessThan(v.encryptedFrom.sent);
  });

  it("TLS 1.2 sends the Certificate in the clear, and each side switches on its own", () => {
    const v = buildTlsView(tls12, 0)!;
    const clear = v.ladder.filter((r) => !r.encrypted).flatMap((r) => r.messages);
    expect(clear).toContain("Certificate");
    // The server's NewSessionTicket comes after we started encrypting, yet is in the clear.
    const ticket = v.ladder.find((r) => r.messages.includes("NewSessionTicket"))!;
    expect(ticket.i).toBeGreaterThan(v.encryptedFrom.sent);
    expect(ticket.encrypted).toBe(false);
  });

  it("only TLS 1.3's hidden handshake records get explained contents", () => {
    const v13 = buildTlsView(tls13, 0)!;
    const explained = v13.ladder.filter((r) => r.explainedContents);
    expect(explained.every((r) => r.encrypted && r.phase === "handshake")).toBe(true);
    expect(explained.map((r) => r.direction).sort()).toEqual(["received", "sent"]);
    expect(buildTlsView(tls12, 0)!.ladder.some((r) => r.explainedContents)).toBe(false);
  });

  it("links the chain: each certificate's issuer is the next one's subject", () => {
    const v = buildTlsView(tls13, 0)!;
    expect(v.chain.length).toBeGreaterThan(1);
    expect(v.chain.slice(0, -1).every((c) => c.issuedByNext)).toBe(true);
    expect(v.chain[0].validAtTrace).toBe(true);
  });

  it("plain-http hops have no TLS view", () => {
    const g = github as unknown as Trace;
    expect(tlsHops(g)).toEqual([1]);
    expect(buildTlsView(g, 0)).toBeNull();
  });
});
