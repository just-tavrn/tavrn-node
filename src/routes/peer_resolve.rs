// SPDX-License-Identifier: AGPL-3.0-only
//! `GET /federation/resolve/{domain}`: where another node lives, as this node resolves it (//! FEDERATION.md §1.4). Browsers cannot read SRV records and often cannot fetch a foreign well-known (CORS,
//! TLS, development peers); this route hands them the result of the node's own resolution (well-known →
//! `_tavrn._tcp` SRV → `https://<domain>`), so SRV-only setups work for the connect flow too.
//!
//! Not an open proxy: the domain must be a node domain other than this node's, the domain policy applies,
//! every host is vetted by the federation client (SSRF rules), and the answer only carries the validated
//! endpoint URLs, never a body of the peer.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::ClientIp,
    error::{ApiError, ProblemDetails},
    federation::{self, client::DelegationSource},
};

/// The endpoints of a node (`api`, `ws`, `web` like in its discovery document).
#[derive(Serialize, ToSchema)]
pub struct PeerResolution {
    /// The identity domain that was resolved.
    pub domain: String,
    /// API base URL ending in `/api/v1`, e.g. `https://app.tavrn.org/api/v1`.
    pub api: String,
    /// WebSocket URL.
    pub ws: String,
    /// Origin of the node's web client.
    pub web: String,
    /// Where the endpoints came from: `well_known` (the domain's document), `srv` (the document of the
    /// `_tavrn._tcp.<domain>` target) or `domain` (no document, no SRV record: `https://<domain>`).
    pub source: DelegationSource,
}

/// Resolves another node like this node does for its own requests (well-known, then the
/// `_tavrn._tcp.<domain>` SRV record, then `https://<domain>`) and returns its endpoints. Public, rate
/// limited per IP together with `/federation/peer/{domain}`.
#[utoipa::path(get, path = "/api/v1/federation/resolve/{domain}", params(("domain" = String, Path)),
    responses((status = 200, body = PeerResolution), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn resolve_peer(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(domain): Path<String>,
) -> Result<Response, ApiError> {
    let domain = super::connect::peer_lookup(&state, &ip, &domain).await?;
    federation::check_policy(&state, &domain).await?;
    let delegation = state.federation.delegation(&domain).await.map_err(|e| {
        tracing::info!(domain, result = %e.label(), "peer resolution for a browser failed");
        e.to_api()
    })?;
    let mut resp = Json(PeerResolution {
        domain,
        api: delegation.public_api.as_str().trim_end_matches('/').to_string(),
        ws: delegation.ws.as_str().to_string(),
        web: delegation.web.as_str().trim_end_matches('/').to_string(),
        source: delegation.source,
    })
    .into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    Ok(resp)
}
