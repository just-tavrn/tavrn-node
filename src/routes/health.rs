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
