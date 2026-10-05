import { forward } from "../packetd";

export async function POST(request: Request) {
  return forward(request, "/trace");
}
