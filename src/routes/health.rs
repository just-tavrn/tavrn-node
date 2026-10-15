// SPDX-License-Identifier: AGPL-3.0-only
use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use crate::{app::AppState, db, voice::livekit::LiveKitStatus};

#[derive(Serialize, utoipa::ToSchema)]
pub struct Health {
    /// Always `ok` while the process serves requests.
    pub status: String,
    /// The supervised LiveKit process: `disabled`, `stopped`, `starting`, `running` or `restarting`.
    pub voice: LiveKitStatus,
    /// A voice setup problem the operator should fix (e.g. no announced address of
    /// `TAVRN_RTC_EXTERNAL_IP`/`TAVRN_RTC_ADVERTISE_IPS` resolves); absent when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice_problem: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct Readiness {
    pub ready: bool,
    pub database: bool,
    /// LiveKit answers on its local port (`null` with `TAVRN_VOICE_ENABLED=false`).
    pub livekit: Option<bool>,
    /// The shared Valkey/Redis answers and the cache bus is subscribed (`null` without `TAVRN_CACHE_URL`). Not
    /// part of `ready`: a cache outage degrades every instance alike, it does not take them out of the balancer.
    pub cache: Option<bool>,
}

/// Is the process alive? Always answers 200 while the server runs; reports the state of LiveKit.
#[utoipa::path(get, path = "/healthz", responses((status = 200, body = Health)))]
pub async fn healthz(State(state): State<AppState>) -> Json<Health> {
    Json(Health { status: "ok".into(), voice: state.voice.status(), voice_problem: state.voice.problem() })
}

/// Can the node serve requests? Checks the database, with voice whether LiveKit answers, and with
/// `TAVRN_CACHE_URL` the shared cache.
#[utoipa::path(get, path = "/readyz", responses((status = 200, body = Readiness), (status = 503, body = Readiness)))]
pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Readiness>) {
    let database = db::ping(&state.db).await;
    let livekit = if state.config.voice_enabled {
        Some(crate::voice::livekit::reachable(state.config.livekit_port).await)
    } else {
        None
    };
    // Reported, but not part of `ready`: while the cache is down every instance is affected alike and still serves
    // (degraded: local rate limits, no relaying, resync afterwards); failing them all would take the node offline.
    let cache = state.cluster.ready().await;
    let ready = database && livekit.unwrap_or(true);
    let status = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(Readiness { ready, database, livekit, cache }))
}

// ---------------------------------------------------------------- `tavrn-node health`

/// How long `tavrn-node health` waits for the answer.
pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The URL `tavrn-node health` probes: `/healthz` (or `/readyz`) on the listen address, a wildcard address replaced
/// by loopback. `None` when `listen` is no `address:port`.
pub fn probe_url(listen: &str, ready: bool) -> Option<String> {
    let addr: std::net::SocketAddr = listen.parse().ok()?;
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    let path = if ready { "readyz" } else { "healthz" };
    Some(format!("http://{}/{path}", std::net::SocketAddr::new(ip, addr.port())))
}

/// Probes the server running on this machine (the image's Docker `HEALTHCHECK`): `Ok` when [`probe_url`] answers
/// `2xx` within [`PROBE_TIMEOUT`]. Cheap: one local request, no configuration output, no call to an identity provider.
pub async fn probe(listen: &str, ready: bool) -> Result<(), String> {
    let url = probe_url(listen, ready).ok_or_else(|| format!("TAVRN_LISTEN='{listen}' is not an address:port"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let response = client.get(&url).send().await.map_err(|e| format!("{url}: {}", e.without_url()))?;
    if response.status().is_success() { Ok(()) } else { Err(format!("{url} answered {}", response.status())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_targets_the_listen_port_on_loopback() {
        assert_eq!(probe_url("0.0.0.0:8080", false).as_deref(), Some("http://127.0.0.1:8080/healthz"));
        assert_eq!(probe_url("[::]:9000", true).as_deref(), Some("http://[::1]:9000/readyz"));
        assert_eq!(probe_url("10.0.0.5:8080", false).as_deref(), Some("http://10.0.0.5:8080/healthz"));
        assert_eq!(probe_url("localhost", false), None);
    }
}
