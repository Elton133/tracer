import type { Phase } from "@/core/derive/waterfall";

/** Tailwind classes per phase. Text colour drives currentColor for fills. */
export const phaseColor: Record<Phase, string> = {
  parse: "text-p-local",
  guard: "text-p-local",
  dns: "text-p-dns",
  tcp: "text-p-tcp",
  close: "text-p-tcp",
  tls: "text-p-tls",
  request: "text-p-http",
  wait: "text-p-http",
  download: "text-p-http",
  redirect: "text-p-http",
};

export const phaseProtocol: Record<Phase, string> = {
  parse: "local",
  guard: "local",
  dns: "DNS",
  tcp: "TCP",
  close: "TCP",
  tls: "TLS",
  request: "HTTP",
  wait: "HTTP",
  download: "HTTP",
  redirect: "HTTP",
};
