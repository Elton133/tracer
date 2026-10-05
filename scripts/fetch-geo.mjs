// Downloads the offline geolocation data packetd uses for the map:
//
//   engine/data/dbip-city-lite-YYYY-MM.mmdb   IP → approximate city (DB-IP Lite, CC BY 4.0)
//   engine/data/iata.json                     airport code → coordinates (OurAirports, public domain)
//
// Lookups then happen locally: no third party learns which IPs you trace.
// Run: npm run geo:fetch

import { createWriteStream } from "node:fs";
import { mkdir, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";

const DIR = new URL("../engine/data/", import.meta.url).pathname;

async function dbip() {
  // DB-IP publishes monthly. Early in a month the new file may not exist yet.
  const now = new Date();
  const months = [0, 1].map((back) => {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
  });
  for (const m of months) {
    const name = `dbip-city-lite-${m}.mmdb`;
    const out = join(DIR, name);
    if (await stat(out).catch(() => null)) return console.log(`✓ ${name} already present`);
    const res = await fetch(`https://download.db-ip.com/free/${name}.gz`);
    if (!res.ok) continue;
    console.log(`↓ ${name} (~60 MB compressed)…`);
    await pipeline(Readable.fromWeb(res.body), createGunzip(), createWriteStream(out));
    // Keep only the newest month.
    for (const f of await readdir(DIR)) if (f.startsWith("dbip-city-lite-") && f !== name) await rm(join(DIR, f));
    return console.log(`✓ ${name}`);
  }
  throw new Error("could not download a DB-IP Lite database");
}

async function airports() {
  const res = await fetch("https://davidmegginson.github.io/ourairports-data/airports.csv");
  if (!res.ok) throw new Error(`airports.csv: HTTP ${res.status}`);
  const rows = parseCsv(await res.text());
  const head = rows.shift();
  const col = (n) => head.indexOf(n);
  const [type, lat, lon, city, country, iata] = ["type", "latitude_deg", "longitude_deg", "municipality", "iso_country", "iata_code"].map(col);
  const out = {};
  for (const r of rows) {
    if (!r[iata] || !["large_airport", "medium_airport"].includes(r[type])) continue;
    out[r[iata]] = [Number(Number(r[lat]).toFixed(3)), Number(Number(r[lon]).toFixed(3)), r[city], r[country]];
  }
  await writeFile(join(DIR, "iata.json"), JSON.stringify(out));
  console.log(`✓ iata.json (${Object.keys(out).length} airport codes)`);
}

/** Minimal RFC 4180 CSV: quoted fields, doubled quotes, commas inside quotes. */
function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (c !== "\r") field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

await mkdir(DIR, { recursive: true });
await Promise.all([dbip(), airports()]);
