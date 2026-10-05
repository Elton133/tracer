import { forward } from "../packetd";

// Traceroute toward one address. Takes about 5 seconds.
export async function POST(request: Request) {
  return forward(request, "/path");
}
