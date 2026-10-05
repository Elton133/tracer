//! packetd: the trace engine as a local HTTP service for the Packet UI.
//!
//!   packetd [--port 4100] [--allow-private]
//!
//!   POST /trace   {"url": "https://example.com", "followRedirects": true}  → Trace JSON
//!   POST /path    {"target": "104.20.23.154"}                              → PathTrace JSON (traceroute)
//!   GET  /health
//!
//! It listens on 127.0.0.1 only, but "only local" isn't "safe": any web page
//! in your browser can send requests to 127.0.0.1. So:
//!   - requests carrying an `Origin` header (i.e. from a browser) are refused.
//!     The Next.js server calls packetd server-side, which sends no Origin.
//!   - the Host header must name 127.0.0.1/localhost. A DNS-rebinding page
//!     reaching us through its own hostname fails this check.
//!   - every resolved address passes the address policy (trace::guard).
//!   - one trace at a time.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use packet::geo::Geo;
use packet::model::{PathTrace, Trace, Vantage};
use packet::trace::guard::Policy;
use packet::trace::{Options, run};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

const DEFAULT_PORT: u16 = 4100;
const MAX_URL_LEN: usize = 2048;

struct App {
    port: u16,
    policy: Policy,
    geo: Option<Arc<Geo>>,
    /// One trace at a time: limits abuse, and concurrent traces would
    /// disturb each other's timings.
    busy: Semaphore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TraceRequest {
    url: String,
    #[serde(default = "yes")]
    follow_redirects: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
    message: String,
}

type Reply<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

fn reject(status: StatusCode, error: &'static str, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error, message: message.into() }))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let policy = if args.iter().any(|a| a == "--allow-private") { Policy::AllowPrivate } else { Policy::PublicOnly };

    let geo = match Geo::load(&packet::geo::default_dir()) {
        Ok(g) => Some(Arc::new(g)),
        Err(e) => {
            eprintln!("packetd: map locations disabled: {e}");
            None
        }
    };
    let app = Arc::new(App { port, policy, geo, busy: Semaphore::new(1) });
    let router = Router::new()
        .route("/health", get(health))
        .route("/trace", post(trace))
        .route("/path", post(path))
        .with_state(app);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("packetd: cannot listen on {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("packetd {} listening on http://{addr}  (address policy: {})", env!("CARGO_PKG_VERSION"), policy.name());
    axum::serve(listener, router).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "name": "packetd", "version": env!("CARGO_PKG_VERSION") }))
}

async fn trace(State(app): State<Arc<App>>, headers: HeaderMap, Json(req): Json<TraceRequest>) -> Reply<Trace> {
    check_caller(&headers, app.port)?;
    if req.url.len() > MAX_URL_LEN {
        return Err(reject(StatusCode::BAD_REQUEST, "url_too_long", format!("max {MAX_URL_LEN} characters")));
    }
    let Ok(_permit) = app.busy.try_acquire() else {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "busy", "a trace is already running"));
    };

    let opts = Options {
        dns_server: None,
        follow_redirects: req.follow_redirects,
        policy: app.policy,
        vantage: "This machine (packetd)".into(),
        geo: app.geo.clone(),
    };
    // A failed trace (DNS error, refused connection, bad certificate) is
    // still a successful observation, so it's a 200 with outcome.ok = false.
    Ok(Json(run(&req.url, &opts).await))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathRequest {
    target: String,
}

async fn path(State(app): State<Arc<App>>, headers: HeaderMap, Json(req): Json<PathRequest>) -> Reply<PathTrace> {
    check_caller(&headers, app.port)?;
    let Ok(target) = req.target.parse::<std::net::IpAddr>() else {
        return Err(reject(StatusCode::BAD_REQUEST, "bad_target", "target must be an IP address"));
    };
    // Same address policy as /trace: probing your LAN or loopback through packetd is refused.
    if let Some(why) = packet::trace::guard::refuses(app.policy, target) {
        return Err(reject(StatusCode::BAD_REQUEST, "blocked", format!("refused by address policy: {why}")));
    }
    let Ok(_permit) = app.busy.try_acquire() else {
        return Err(reject(StatusCode::TOO_MANY_REQUESTS, "busy", "a measurement is already running"));
    };
    let vantage = Vantage { description: "This machine (packetd)".into(), is_user_machine: true, runtime: format!("packetd {}", env!("CARGO_PKG_VERSION")) };
    Ok(Json(packet::trace::path::trace_path(target, app.geo.as_deref(), vantage).await))
}

fn check_caller(headers: &HeaderMap, port: u16) -> Result<(), (StatusCode, Json<ApiError>)> {
    if headers.contains_key(header::ORIGIN) {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "browser_request",
            "packetd doesn't accept requests from browsers; use the Packet UI",
        ));
    }
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let ok = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !ok.iter().any(|h| h == host) {
        return Err(reject(StatusCode::FORBIDDEN, "bad_host", format!("unexpected Host header {host:?}")));
    }
    Ok(())
}
