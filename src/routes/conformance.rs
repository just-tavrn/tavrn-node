// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance routes (FEDERATION.md §9): the throwaway rooms this node hosts for the probes of other
//! nodes, the public state of a peer as this node sees it (§9.2 client checks), and the admin view of the
//! peers with their reputation record, forced checks, manual blocks and unblocks (all audited).

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};

use crate::{
    app::AppState,
    auth::{AuthUser, ClientIp, NodeAdmin},
    error::{ApiError, ProblemDetails},
    federation::{
        self,
        conformance::{self, ConformanceRoom, Record},
        discovery,
    },
    routes::directory::KeyFingerprint,
    store::{self, conformance::PeerStateRow},
    util,
    validate::{self, bad},
};

/// Throwaway conformance room for the probe of another node (FEDERATION.md §9.1): only a federated
/// session of a `tavrn-conformance` user, regardless of `TAVRN_ROOM_CREATION`, deleted after 15 minutes.
#[utoipa::path(post, path = "/api/v1/federation/conformance/room", security(("bearer" = [])),
    responses((status = 201, body = ConformanceRoom), (status = 401, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn create_room(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<(StatusCode, Json<ConformanceRoom>), ApiError> {
    Ok((StatusCode::CREATED, Json(conformance::create_room(&state, &auth.user).await?)))
}

/// Deletes the probe's conformance room.
#[utoipa::path(delete, path = "/api/v1/federation/conformance/room/{room_id}", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    conformance::delete_own_room(&state, &auth.user, &room_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `pass`, `warn`, `fail` or `unknown` (never checked).
fn result_of(row: Option<&PeerStateRow>) -> String {
    row.and_then(|r| r.conformance_result.clone()).unwrap_or_else(|| "unknown".into())
}

/// A peer as this node sees it, for clients (§9.2).
#[derive(Serialize, ToSchema)]
pub struct PeerPublicState {
    pub domain: String,
    /// Latest conformance result: `pass`, `warn`, `fail` or `unknown`.
    pub conformance: String,
    /// This node does not federate with the peer (configuration, node ban, operator or automatic block).
    pub blocked: bool,
    /// The peer's signing keys from this node's cached copy of its discovery document (clients compare
    /// them with their own fetch; a mismatch means a split view).
    pub keys: Vec<KeyFingerprint>,
}

/// State of a peer as this node sees it: conformance result, block state and key fingerprints. Public,
/// CORS-open, limited per client IP.
#[utoipa::path(get, path = "/api/v1/federation/peers/{domain}/state", params(("domain" = String, Path)),
    responses((status = 200, body = PeerPublicState), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn peer_state(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(domain): Path<String>,
) -> Result<Json<PeerPublicState>, ApiError> {
    state.directory_limiter.check_all(&[format!("dir-ip:{ip}")])?;
    let domain = domain.trim().to_lowercase();
    if !federation::valid_node_domain(&domain) {
        return Err(bad("federation.domain_invalid", "Not a valid node domain"));
    }
    if domain == state.config.domain {
        return Err(bad("federation.target_self", "This is the node's own domain"));
    }
    let row = store::conformance::peer_state(&state.db, &domain).await?;
    let blocked = federation::check_policy(&state, &domain).await.is_err();
    let keys = store::federation::peer(&state.db, &domain)
        .await?
        .and_then(|p| discovery::validate(&domain, p.document.as_bytes()).ok())
        .map(|doc| {
            doc.keys
                .iter()
                .map(|k| KeyFingerprint {
                    kid: k.kid.clone(),
                    sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(k.key.as_bytes())),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(PeerPublicState { conformance: result_of(row.as_ref()), domain, blocked, keys }))
}

#[derive(Serialize, ToSchema)]
pub struct ViolationCount {
    /// `issuer_mismatch`, `type_forbidden`, `body_hash` or `key_conflict`.
    pub kind: String,
    pub count: i64,
    pub last_at: String,
}

/// A peer with its reputation record (§9.3).
#[derive(Serialize, ToSchema)]
pub struct FederationPeer {
    pub domain: String,
    /// `ok`, `blocked` (operator), `blocked_auto` (hard failure or observed spoofing) or `key_conflict`.
    pub status: String,
    /// Latest conformance result: `pass`, `warn`, `fail` or `unknown`.
    pub conformance: String,
    pub checked_at: Option<String>,
    /// Hard (crypto) failures over all runs.
    pub hard_failures: i64,
    /// Warnings over all runs.
    pub soft_failures: i64,
    /// Live-traffic violations observed (all time).
    pub violations: i64,
    pub blocked_at: Option<String>,
    pub blocked_reason: Option<String>,
    /// Last time this node fetched the peer's discovery document.
    pub fetched_at: String,
    /// The latest run with every check and the last 10 results.
    pub record: Option<Record>,
    /// Violations of the last 30 days.
    pub recent_violations: Vec<ViolationCount>,
}

async fn to_peer(state: &AppState, row: PeerStateRow) -> Result<FederationPeer, ApiError> {
    let since = util::format_time(Utc::now() - chrono::Duration::days(conformance::VIOLATION_DAYS));
    let recent = store::conformance::violation_summary(&state.db, &row.domain, &since).await?;
    Ok(FederationPeer {
        conformance: result_of(Some(&row)),
        record: row.conformance.as_deref().and_then(|r| serde_json::from_str(r).ok()),
        recent_violations: recent
            .into_iter()
            .map(|(kind, count, last_at)| ViolationCount { kind, count, last_at })
            .collect(),
        domain: row.domain,
        status: row.status,
        checked_at: row.conformance_checked_at,
        hard_failures: row.hard_failures,
        soft_failures: row.soft_failures,
        violations: row.violations,
        blocked_at: row.blocked_at,
        blocked_reason: row.blocked_reason,
        fetched_at: row.fetched_at,
    })
}

async fn peer(state: &AppState, domain: &str) -> Result<FederationPeer, ApiError> {
    let row = store::conformance::peer_state(&state.db, domain)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "federation.peer_unknown", what: "Peer".into() })?;
    to_peer(state, row).await
}

#[derive(Deserialize, IntoParams)]
pub struct PeerQuery {
    /// 1–200, default 100.
    pub limit: Option<i64>,
    /// Domain of the last entry of the previous page.
    pub after: Option<String>,
}

/// Peers this node knows (fetched their discovery document, checked or blocked them), by domain.
#[utoipa::path(get, path = "/api/v1/admin/federation/peers", security(("bearer" = [])), params(PeerQuery),
    responses((status = 200, body = Vec<FederationPeer>), (status = 403, body = ProblemDetails)))]
pub async fn list_peers(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<PeerQuery>,
) -> Result<Json<Vec<FederationPeer>>, ApiError> {
    let rows = store::conformance::peer_states(
        &state.db,
        q.after.as_deref().unwrap_or(""),
        validate::limit(q.limit, 100, 200),
    )
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(to_peer(&state, row).await?);
    }
    Ok(Json(out))
}

fn checked_domain(state: &AppState, domain: &str) -> Result<String, ApiError> {
    let domain = domain.trim().to_lowercase();
    if !federation::valid_node_domain(&domain) {
        return Err(bad("federation.domain_invalid", "Not a valid node domain"));
    }
    if domain == state.config.domain {
        return Err(bad("federation.target_self", "This node does not check or block itself"));
    }
    Ok(domain)
}

/// Runs the conformance checks against a peer now (forced) and returns its state. Consequences apply as
/// for automatic runs: a hard failure blocks the peer, a clean run lifts an automatic block. Audited.
#[utoipa::path(post, path = "/api/v1/admin/federation/peers/{domain}/check", security(("bearer" = [])), params(("domain" = String, Path)),
    responses((status = 200, body = FederationPeer), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails)))]
pub async fn check_peer(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(domain): Path<String>,
) -> Result<Json<FederationPeer>, ApiError> {
    let domain = checked_domain(&state, &domain)?;
    let record = conformance::run(&state, &domain, true).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.federation_check",
        &domain,
        "",
        serde_json::json!({ "result": record.result }),
    )
    .await?;
    Ok(Json(peer(&state, &domain).await?))
}

#[derive(Deserialize, ToSchema, Default)]
pub struct BlockPeerRequest {
    #[serde(default)]
    pub reason: String,
}

/// Blocks a peer by hand (`status = blocked`): no federation with it in either direction, its users'
/// federated sessions end. Stays until an admin unblocks it. Audited.
#[utoipa::path(post, path = "/api/v1/admin/federation/peers/{domain}/block", security(("bearer" = [])), params(("domain" = String, Path)),
    request_body = BlockPeerRequest,
    responses((status = 200, body = FederationPeer), (status = 400, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn block_peer(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(domain): Path<String>,
    body: Option<Json<BlockPeerRequest>>,
) -> Result<Json<FederationPeer>, ApiError> {
    let domain = checked_domain(&state, &domain)?;
    let reason = validate::text("reason", &body.map(|b| b.0.reason).unwrap_or_default(), 0, 500)?;
    if !conformance::set_manual_block(&state, &domain, true, &reason).await? {
        return Err(ApiError::conflict("federation.already_blocked", "This node is already blocked by an admin"));
    }
    tracing::warn!(domain, "peer blocked by an admin");
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.federation_block",
        &domain,
        &reason,
        serde_json::json!({}),
    )
    .await?;
    Ok(Json(peer(&state, &domain).await?))
}

/// Lifts a manual or automatic block or a key conflict (the keys the peer publishes now are accepted on
/// the next fetch). Audited.
#[utoipa::path(post, path = "/api/v1/admin/federation/peers/{domain}/unblock", security(("bearer" = [])), params(("domain" = String, Path)),
    responses((status = 200, body = FederationPeer), (status = 400, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn unblock_peer(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(domain): Path<String>,
) -> Result<Json<FederationPeer>, ApiError> {
    let domain = checked_domain(&state, &domain)?;
    let previous = store::conformance::peer_state(&state.db, &domain).await?.map(|p| p.status).unwrap_or_default();
    if !conformance::set_manual_block(&state, &domain, false, "").await? {
        return Err(ApiError::conflict("federation.not_blocked", "This node is not blocked"));
    }
    tracing::warn!(domain, previous, "peer unblocked by an admin");
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.federation_unblock",
        &domain,
        "",
        serde_json::json!({ "previous": previous }),
    )
    .await?;
    Ok(Json(peer(&state, &domain).await?))
}
