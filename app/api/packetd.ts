// Shared by the API routes: forward a JSON request to packetd, server-side.
// Not a route itself (only route.ts files are).

const PACKETD_URL = process.env.PACKETD_URL ?? "http://127.0.0.1:4100";

// Ten redirect hops, each with DNS/TCP/TLS/HTTP timeouts, can take a while.
const TIMEOUT_MS = 120_000;

export async function forward(request: Request, path: "/trace" | "/path"): Promise<Response> {
  // Any page open in the browser can send requests to localhost:3000.
  // Only accept them from Packet's own pages.
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== new URL(request.url).origin) {
    return Response.json({ error: "cross_origin", message: "requests must come from the Packet UI" }, { status: 403 });
  }
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ error: "bad_content_type", message: "expected application/json" }, { status: 415 });
  }

  let res: Response;
  try {
    // Server-side fetch sends no Origin header, which is how packetd tells
    // this server apart from a browser.
    res = await fetch(`${PACKETD_URL}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: await request.text(),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    return Response.json(
      { error: "engine_unavailable", message: "packetd is not running. Start it with `npm run packetd`." },
      { status: 503 },
    );
  }
  if (res.status === 404) {
    // An older packetd that predates this endpoint.
    return Response.json(
      { error: "engine_outdated", message: "This packetd doesn't have that endpoint yet. Restart it: npm run packetd" },
      { status: 502 },
    );
  }
  // packetd's own errors (busy, blocked, bad request) are already JSON.
  return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
}
