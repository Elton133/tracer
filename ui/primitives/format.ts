/** 0.42 ms, 7.3 ms, 128 ms, 4.21 s */
export function ms(v: number): string {
  if (v >= 10_000) return `${(v / 1000).toFixed(1)} s`;
  if (v >= 1000) return `${(v / 1000).toFixed(2)} s`;
  if (v >= 10) return `${Math.round(v)} ms`;
  if (v >= 1) return `${v.toFixed(1)} ms`;
  return `${v.toFixed(2)} ms`;
}

export function bytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

/** "rttEstimateMs" → "RTT estimate ms" style labels for generic fields. */
export function fieldLabel(key: string): string {
  const words = key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
  return words
    .replace(/\b(dns|tcp|tls|http|alpn|sni|rtt|ttfb|mss|ip|url|ecn|sack|der|rto|cwnd)\b/g, (w) => w.toUpperCase())
    .replace(/^./, (c) => c.toUpperCase());
}

/** Axis labels: no false precision. 0, 200 ms, 1.5 s, 10 s */
export function axisMs(v: number, total: number): string {
  if (v === 0) return "0";
  if (total >= 2000) return `${+(v / 1000).toFixed(2)} s`;
  return `${+v.toFixed(2)} ms`;
}
