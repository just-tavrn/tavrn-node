// SPDX-License-Identifier: AGPL-3.0-only
//! KeyPackage claims across nodes (FEDERATION.md §3.5).
//!
//! - **Home node** ([`serve`]): `POST /api/v1/federation/key-packages/claim` with a node token
//!   (`htm`/`htu`, body hash) `{ user, requester }` → one KeyPackage per attested device of the local
//!   `user`, deleted on claim. Refused when `user` blocked `requester` (`federation.claim_refused`);
//!   limited per requesting node (`TAVRN_FEDERATION_RATE_CLAIMS` per minute) and per
//!   `(requester, user)` (10 per hour).
//! - **Conversation's node** ([`proxy`]): `POST /users/{address}/key-packages/claim` for a remote user
//!   performs the S2S claim and returns the KeyPackages that pass `ds::inspect_key_package` with the
//!   credential `address/<device_id>` and the device key from the key cache. KeyPackages are never cached.

use std::time::Instant;

use axum::{
    body::Body,
    http::{HeaderMap, header},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{client::Kind, tokens};
use crate::{app::AppState, auth, error::ApiError, models::UserRow, store, util};

pub const CLAIM_PATH: &str = "/api/v1/federation/key-packages/claim";
pub const MAX_BODY_BYTES: usize = 4096;
/// KeyPackages accepted from one answer (one per device).
pub const MAX_PACKAGES: usize = 100;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Address of the user whose KeyPackages are claimed (local to the home node).
    pub user: String,
    /// Address of the user on whose behalf the conversation's node claims.
    pub requester: String,
}

fn invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

fn not_found() -> ApiError {
    ApiError::NotFound { code: "user.not_found", what: "User".into() }
}

/// One KeyPackage per attested device of a local user, deleted on claim: `(device id, base64url)`.
pub async fn claim_local(state: &AppState, user: &UserRow) -> Result<Vec<(String, String)>, ApiError> {
    let mut out = Vec::new();
    for device in store::e2ee::attested_devices(&state.db, &user.id).await? {
        if let Some(kp) = store::e2ee::claim_key_package(&state.db, &device.id).await? {
            out.push((device.id, tavrn_crypto::util::b64url_encode(&kp)));
        }
    }
    Ok(out)
}

/// The home node's S2S claim route.
pub async fn serve(state: &AppState, headers: &HeaderMap, body: Body) -> Result<Value, ApiError> {
    let started = Instant::now();
    if !state.config.federation_enabled {
        return Err(super::disabled());
    }
    let too_large = || ApiError::PayloadTooLarge {
        code: "federation.payload_too_large",
        detail: "Request too large".into(),
        meta: json!({ "max_bytes": MAX_BODY_BYTES }),
    };
    let length = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if length.is_some_and(|n| n > MAX_BODY_BYTES as u64) {
        return Err(too_large());
    }
    let token = auth::bearer(headers).ok_or_else(tokens::token_invalid)?;
    let iss = tokens::peek_issuer(state, token)?;
    super::check_policy(state, &iss).await?;
    state.federation_claim_limiter.check_all(&[format!("domain:{iss}")])?;
    let claims = tokens::verify_node_token(state, token, &iss, "POST", CLAIM_PATH).await?;
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| too_large())?;
    tokens::check_body(&claims, &bytes)?;
    tokens::spend_jti(state, &claims.std).await?;
    let req: ClaimRequest = serde_json::from_slice(&bytes).map_err(|_| invalid("invalid request"))?;

    let (username, domain) = util::parse_address(&req.user).ok_or_else(|| invalid("invalid user"))?;
    let (requester_name, requester_domain) =
        util::parse_address(&req.requester).ok_or_else(|| invalid("invalid requester"))?;
    if domain != state.config.domain {
        return Err(not_found());
    }
    let user = store::users::by_username(&state.db, username, domain)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .ok_or_else(not_found)?;
    if let Some(requester) = store::federation::user_by_address(&state.db, requester_name, requester_domain).await?
        && store::social::has_blocked(&state.db, &user.id, &requester.id).await?
    {
        return Err(ApiError::Forbidden {
            code: "federation.claim_refused",
            detail: "This user does not hand out key packages".into(),
        });
    }
    state.claim_pair_limiter.check_all(&[format!("{}|{}", req.requester, req.user)]).await?;
    let packages = claim_local(state, &user).await?;
    tracing::info!(
        node = iss,
        user = req.user,
        count = packages.len(),
        ms = started.elapsed().as_millis() as u64,
        "federation key package claim"
    );
    Ok(json!({
        "key_packages": packages.iter().map(|(d, k)| json!({ "device_id": d, "key_package": k })).collect::<Vec<_>>()
    }))
}

/// Claims KeyPackages of the remote user `target` from its home node on behalf of `requester`.
pub async fn proxy(state: &AppState, requester: &UserRow, target: &UserRow) -> Result<Vec<(String, String)>, ApiError> {
    if !state.config.federation_enabled {
        return Err(super::disabled());
    }
    super::check_policy(state, &target.domain).await?;
    super::keys::ensure(state, target, None).await?;
    let address = target.address();
    let body = serde_json::to_vec(&ClaimRequest { user: address.clone(), requester: requester.address() })
        .map_err(|e| ApiError::Internal(e.into()))?;
    let token = tokens::issue_node_token(state, &target.domain, "POST", CLAIM_PATH, &body)?;
    let fetched =
        state.federation.post_json(&target.domain, CLAIM_PATH, &token, body, Kind::Claim).await.map_err(|e| {
            tracing::info!(domain = target.domain, result = e.label(), "federation key package claim failed");
            e.to_api()
        })?;
    let answer: Value = serde_json::from_slice(&fetched.body)
        .map_err(|_| super::discovery::peer_invalid(&target.domain, "answer is not JSON"))?;
    let items = answer
        .get("key_packages")
        .and_then(Value::as_array)
        .ok_or_else(|| super::discovery::peer_invalid(&target.domain, "key_packages missing"))?;
    let mut out: Vec<(String, String)> = Vec::new();
    for item in items.iter().take(MAX_PACKAGES) {
        let (Some(device_id), Some(kp)) =
            (item.get("device_id").and_then(Value::as_str), item.get("key_package").and_then(Value::as_str))
        else {
            continue;
        };
        if !util::is_ulid(device_id) || out.iter().any(|(d, _)| d == device_id) {
            continue;
        }
        if valid_package(state, target, &address, device_id, kp).await? {
            out.push((device_id.to_string(), kp.to_string()));
        } else {
            tracing::warn!(domain = target.domain, "invalid KeyPackage from a home node dropped");
        }
    }
    Ok(out)
}

/// The KeyPackage carries `address/device_id` and the device key attested by the home node.
async fn valid_package(
    state: &AppState,
    target: &UserRow,
    address: &str,
    device_id: &str,
    kp: &str,
) -> Result<bool, ApiError> {
    let Ok(bytes) = tavrn_crypto::util::b64url_decode(kp) else { return Ok(false) };
    if bytes.len() > crate::routes::keys::MAX_KEY_PACKAGE_BYTES {
        return Ok(false);
    }
    let Ok(entry) = tavrn_crypto::ds::inspect_key_package(&bytes) else { return Ok(false) };
    if entry.identity != format!("{address}/{device_id}") {
        return Ok(false);
    }
    let Some((_, key)) = super::keys::remote_device_key(state, target, device_id).await? else { return Ok(false) };
    Ok(key == entry.signature_key)
}
