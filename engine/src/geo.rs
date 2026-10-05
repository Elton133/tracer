//! Where things are, as far as anyone can tell without traceroute.
//!
//! Two very different sources, kept apart on purpose:
//!
//! - IP geolocation (DB-IP Lite): a third-party database mapping address
//!   blocks to cities. A derived estimate, often wrong for CDNs: an anycast
//!   address is announced from dozens of cities at once, and the database
//!   can only name one of them (often the company's headquarters).
//!
//! - CDN location headers: the server telling us which of its data centers
//!   answered (`CF-RAY: …-LIS` = Cloudflare Lisbon). Observed, but
//!   self-reported. CDNs name sites after the nearest airport, so the
//!   coordinates come from the OurAirports table (derived).
//!
//! Both files live in engine/data and are fetched by `npm run geo:fetch`.
//! Lookups are local: no third party learns which addresses you trace.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::Reader;
use serde::Deserialize;

use crate::model::{EdgeLocation, Fact, GeoPoint, Header};
use crate::trace::guard;

pub struct Geo {
    reader: Reader<Vec<u8>>,
    /// e.g. "DB-IP Lite city 2026-10"
    db_name: String,
    airports: HashMap<String, (f64, f64, String, String)>,
}

pub fn default_dir() -> PathBuf {
    std::env::var_os("PACKET_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("data"))
}

impl Geo {
    pub fn load(dir: &Path) -> Result<Geo, String> {
        let db = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("dbip-city-lite-") && n.ends_with(".mmdb")))
            .max()
            .ok_or("no dbip-city-lite-*.mmdb (run `npm run geo:fetch`)")?;
        let month = db.file_stem().and_then(|s| s.to_str()).unwrap_or("").trim_start_matches("dbip-city-lite-").to_string();
        let reader = Reader::open_readfile(&db).map_err(|e| format!("{}: {e}", db.display()))?;

        let raw = std::fs::read_to_string(dir.join("iata.json")).map_err(|e| format!("iata.json: {e}"))?;
        let table: HashMap<String, (f64, f64, String, String)> = serde_json::from_str(&raw).map_err(|e| format!("iata.json: {e}"))?;

        Ok(Geo { reader, db_name: format!("DB-IP Lite city {month}"), airports: table })
    }

    /// Database estimate for a public address. None for private/special
    /// addresses: they aren't anywhere on a world map.
    pub fn locate(&self, ip: IpAddr) -> Option<Fact<GeoPoint>> {
        if guard::classify(ip).is_some() {
            return None;
        }
        let rec: Record = self.reader.lookup(ip).ok()?.decode().ok()??;
        let loc = rec.location?;
        let (lat, lon) = (loc.latitude?, loc.longitude?);
        let city = rec.city.and_then(|c| c.names).and_then(|n| n.get("en").map(|s| s.to_string()));
        let country = rec.country.and_then(|c| c.iso_code).map(str::to_string);
        let place = [city, country].into_iter().flatten().collect::<Vec<_>>().join(", ");
        Some(
            Fact::derived(GeoPoint { lat, lon, place }, format!("IP geolocation: {} (CC BY 4.0)", self.db_name)).note(
                "A database estimate for this address block, not a measurement. CDN and anycast addresses are often placed at the company's headquarters.",
            ),
        )
    }

    /// The data center a CDN says answered, from its response headers.
    pub fn edge(&self, headers: &[Header]) -> Option<EdgeLocation> {
        let (provider, header, code) = edge_code(headers)?;
        let point = self.airports.get(&code).map(|(lat, lon, city, country)| {
            Fact::derived(
                GeoPoint { lat: *lat, lon: *lon, place: format!("{city}, {country}") },
                "derive: airport code → coordinates (OurAirports)",
            )
            .note("CDNs name sites after the nearest airport. The data center is in that metro area, not at the airport.")
        });
        Some(EdgeLocation {
            provider: Fact::observed(provider.to_string(), format!("{header} response header")),
            code: Fact::observed(code, format!("{header} response header"))
                .note("Self-reported by the server. Packet can't verify it, but the RTT can rule it out."),
            point,
        })
    }
}

/// (provider, header name, IATA-style code)
fn edge_code(headers: &[Header]) -> Option<(&'static str, &'static str, String)> {
    let get = |name: &str| headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.trim());
    let iata = |s: &str| {
        let c: String = s.chars().take(3).collect::<String>().to_ascii_uppercase();
        (c.len() == 3 && c.chars().all(|ch| ch.is_ascii_alphabetic())).then_some(c)
    };
    // Cloudflare: "a44252a4cc3f526e-LIS"
    if let Some(v) = get("cf-ray") {
        return iata(v.rsplit('-').next()?).map(|c| ("Cloudflare", "CF-RAY", c));
    }
    // CloudFront: "LIS50-P1"
    if let Some(v) = get("x-amz-cf-pop") {
        return iata(v).map(|c| ("Amazon CloudFront", "X-Amz-Cf-Pop", c));
    }
    // Fastly: "cache-iad-kiad7000106-IAD, cache-lis1490060-LIS". The last entry is the edge nearest the client.
    if let Some(v) = get("x-served-by").filter(|v| v.starts_with("cache-")) {
        let last = v.rsplit(',').next()?.trim();
        return iata(last.rsplit('-').next()?).map(|c| ("Fastly", "X-Served-By", c));
    }
    // Vercel: "lhr1::iad1::abcd-123". The first segment is the edge region.
    if let Some(v) = get("x-vercel-id") {
        return iata(v.split("::").next()?).map(|c| ("Vercel", "X-Vercel-Id", c));
    }
    None
}

#[derive(Deserialize)]
struct Record<'a> {
    #[serde(borrow, default)]
    city: Option<Named<'a>>,
    #[serde(borrow, default)]
    country: Option<Country<'a>>,
    #[serde(default)]
    location: Option<Location>,
}

#[derive(Deserialize)]
struct Named<'a> {
    #[serde(borrow, default)]
    names: Option<BTreeMap<&'a str, &'a str>>,
}

#[derive(Deserialize)]
struct Country<'a> {
    #[serde(borrow, default)]
    iso_code: Option<&'a str>,
}

#[derive(Deserialize)]
struct Location {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> Header {
        Header { name: name.into(), value: value.into() }
    }

    #[test]
    fn reads_cdn_location_headers() {
        assert_eq!(edge_code(&[h("CF-RAY", "a44252a4cc3f526e-LIS")]).unwrap().2, "LIS");
        assert_eq!(edge_code(&[h("x-amz-cf-pop", "FRA56-P3")]).unwrap().2, "FRA");
        assert_eq!(edge_code(&[h("X-Served-By", "cache-iad-kiad7000106-IAD, cache-lis1490060-LIS")]).unwrap().2, "LIS");
        assert_eq!(edge_code(&[h("x-vercel-id", "lhr1::iad1::xyz-123")]).unwrap().2, "LHR");
        assert!(edge_code(&[h("Server", "nginx")]).is_none());
        assert!(edge_code(&[h("CF-RAY", "garbage-1x")]).is_none());
    }

    #[test]
    fn private_addresses_have_no_location() {
        // Needs the database only if present; the private check comes first.
        if let Ok(geo) = Geo::load(&default_dir()) {
            assert!(geo.locate("172.20.10.1".parse().unwrap()).is_none());
            assert!(geo.locate("1.1.1.1".parse().unwrap()).is_some());
        }
    }
}
