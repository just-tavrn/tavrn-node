// SPDX-License-Identifier: AGPL-3.0-only
//! Identity key rotation with continuity (ENCRYPTION.md §2.3, §9a): the client replaces
//! the account's signing identity with a fresh key, signs a continuity statement with both keys, attests every
//! active device again and leaves the new key wrapped under its master secret on the home node.

use axum::{Json, extract::State, http::HeaderMap};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    e2ee,
    error::{ApiError, ApiJson, ProblemDetails},
    store,
    util::{self, now},
    validate::bad,
};

/// Clock tolerance for `continuity.at`.
pub const ROTATION_SKEW_SECS: i64 = 300;
/// At most one rotation per user in this interval.
pub const ROTATION_INTERVAL_SECS: i64 = 3600;
/// Continuity statements in a keys document (the clients' limit): no rotation beyond it.
pub const MAX_CONTINUITY: i64 = 100;
/// Upper bound of the attestation list (the device limit of the key cache, `federation::keys::MAX_DEVICES`).
pub const MAX_ROTATION_ATTESTATIONS: usize = 100;
/// Body limit of the rotation request (100 attestations of about 150 bytes plus the statement).
pub const ROTATE_BODY_LIMIT: usize = 32 * 1024;

/// A continuity statement (ENCRYPTION.md §9a): `old_key` is replaced by `new_key` at `at`, signed by both keys
/// over `"tavrn identity continuity v1" || JCS({ old_key, new_key, at })`. Keys and signatures are base64url.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContinuityStatement {
    pub old_key: String,
    pub new_key: String,
    /// RFC 3339
    pub at: String,
    pub sig_old: String,
    pub sig_new: String,
}

impl From<store::e2ee::ContinuityRow> for ContinuityStatement {
    fn from(r: store::e2ee::ContinuityRow) -> Self {
        Self { old_key: r.old_key, new_key: r.new_key, at: r.at, sig_old: r.sig_old, sig_new: r.sig_new }
    }
}

impl ContinuityStatement {
    fn to_crypto(&self) -> tavrn_crypto::ContinuityStatement {
        tavrn_crypto::ContinuityStatement {
            old_key: self.old_key.clone(),
            new_key: self.new_key.clone(),
            at: self.at.clone(),
            sig_old: self.sig_old.clone(),
            sig_new: self.sig_new.clone(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotationAttestation {
    pub device_id: String,
    /// Signature of the **new** identity key over the device key (ENCRYPTION.md §3.1), base64url.
    pub identity_signature: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateIdentityRequest {
    /// The new Ed25519 identity key, base64url.
    pub new_identity_public_key: String,
    pub continuity: ContinuityStatement,
    /// The new key wrapped under the master secret (61 bytes, base64url; ENCRYPTION.md §9a).
    pub identity_blob: String,
    /// New attestations of every active device of the user.
    pub attestations: Vec<RotationAttestation>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RotateIdentityResponse {
    pub identity_public_key: String,
    /// The new generation (1 for the first rotation).
    pub identity_generation: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityBlob {
    pub identity_blob: String,
    pub identity_generation: i64,
    /// The public key the blob holds.
    pub identity_public_key: String,
}

fn continuity_invalid(detail: &str) -> ApiError {
    bad("e2ee.continuity_invalid", detail.to_string())
}

/// Rotates the identity key with continuity (ENCRYPTION.md §9a). Needs a full session and a reauth token
/// (`Tavrn-Reauth`, PROTOCOL.md §5c). Not for bots (their owner resets them, `403`). At most one rotation per hour.
#[utoipa::path(post, path = "/api/v1/users/me/identity/rotate", security(("bearer" = [])), request_body = RotateIdentityRequest,
    responses((status = 200, body = RotateIdentityResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<RotateIdentityRequest>,
) -> Result<Json<RotateIdentityResponse>, ApiError> {
    if auth.user.is_bot() {
        return Err(ApiError::Forbidden {
            code: "e2ee.rotation_bot",
            detail: "A bot's key cannot be rotated; its owner resets it".into(),
        });
    }
    crate::reauth::require(&state, &auth, &headers).await?;
    let Some(current) = auth.user.identity_pubkey.clone() else {
        return Err(ApiError::conflict("e2ee.identity_missing", "Upload the account's security key first"));
    };
    let last = store::e2ee::current_rotation(&state.db, &auth.user.id).await?;
    // Clients refuse a keys document with more than `MAX_CONTINUITY` statements: the chain never grows beyond it.
    if last.as_ref().is_some_and(|l| l.generation >= MAX_CONTINUITY) {
        return Err(ApiError::conflict(
            "e2ee.rotation_limit",
            "The account's security key was rotated as often as a keys document allows; reset it instead",
        ));
    }
    if let Some(last) = last
        && let Some(at) = util::parse_time(&last.created_at)
    {
        let elapsed = (Utc::now() - at).num_seconds();
        if elapsed < ROTATION_INTERVAL_SECS {
            return Err(ApiError::RateLimited { retry_after_secs: (ROTATION_INTERVAL_SECS - elapsed).max(1) as u32 });
        }
    }

    let new_key = util_b64(&e2ee::decode_public_key(&req.new_identity_public_key)?);
    let c = &req.continuity;
    if c.new_key != new_key {
        return Err(continuity_invalid("continuity.new_key must be the new identity key"));
    }
    if c.old_key != current {
        return Err(continuity_invalid("continuity.old_key must be the current identity key"));
    }
    match util::parse_time(&c.at) {
        Some(at) if (Utc::now() - at).num_seconds().abs() <= ROTATION_SKEW_SECS => {}
        _ => return Err(bad("e2ee.continuity_stale", "continuity.at must be the current time (±5 minutes)")),
    }
    if tavrn_crypto::verify_continuity(&c.to_crypto()).is_err() {
        return Err(continuity_invalid("The continuity statement must be signed by the old and the new key"));
    }
    let blob = e2ee::decode("identity_blob", &req.identity_blob, 256, "e2ee.identity_blob_invalid")?;
    if blob.len() != tavrn_crypto::identity::IDENTITY_BLOB_LEN
        || blob[0] != tavrn_crypto::identity::IDENTITY_BLOB_VERSION
    {
        return Err(bad("e2ee.identity_blob_invalid", "identity_blob must be 61 bytes of version 1"));
    }

    // Every active device (attested under the current key) needs an attestation by the new key.
    if req.attestations.len() > MAX_ROTATION_ATTESTATIONS {
        return Err(bad("e2ee.rotation_incomplete", "Too many attestations"));
    }
    let new_bytes: [u8; 32] = tavrn_crypto::util::b64url_decode(&new_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("new key not decodable")))?;
    let active = store::e2ee::attested_devices(&state.db, &auth.user.id).await?;
    let mut attestations = Vec::with_capacity(active.len());
    let mut missing = Vec::new();
    for device in &active {
        let Some(device_key) = device.public_key.as_deref() else { continue };
        let found = req.attestations.iter().find(|a| a.device_id == device.id);
        let valid = found.and_then(|a| {
            let signature: [u8; 64] = tavrn_crypto::util::b64url_decode(&a.identity_signature).ok()?.try_into().ok()?;
            let device_public_key: [u8; 32] = tavrn_crypto::util::b64url_decode(device_key).ok()?.try_into().ok()?;
            let att = tavrn_crypto::DeviceAttestation {
                user_address: auth.user.address(),
                device_id: device.id.clone(),
                device_public_key,
                identity_public_key: new_bytes,
                signature,
            };
            tavrn_crypto::verify_device_attestation(&att, &new_bytes).ok().map(|_| util_b64(&signature))
        });
        match valid {
            Some(sig) => attestations.push((device.id.clone(), sig)),
            None => missing.push(device.id.clone()),
        }
    }
    let unknown = req.attestations.iter().filter(|a| !active.iter().any(|d| d.id == a.device_id)).count();
    if !missing.is_empty() || unknown > 0 {
        return Err(bad(
            "e2ee.rotation_incomplete",
            format!(
                "Every active device needs a valid attestation by the new key (missing or invalid: {}; unknown: {unknown})",
                missing.join(", ")
            ),
        ));
    }

    let generation = store::e2ee::rotate_identity(
        &state.db,
        &store::e2ee::Rotation {
            user_id: &auth.user.id,
            old_key: &current,
            new_key: &new_key,
            at: &c.at,
            sig_old: &c.sig_old,
            sig_new: &c.sig_new,
            identity_blob: &util_b64(&blob),
            attestations: &attestations,
        },
    )
    .await?
    .ok_or_else(|| ApiError::conflict("e2ee.identity_changed", "The security key changed in the meantime"))?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.identity_rotated",
        &auth.user.address(),
        "",
        json!({ "generation": generation }),
    )
    .await?;

    let mut recipients = store::social::contact_ids(&state.db, &auth.user.id).await?;
    for (friend, _) in store::social::friends_of(&state.db, &auth.user.id).await? {
        if !recipients.contains(&friend) {
            recipients.push(friend);
        }
    }
    recipients.push(auth.user.id.clone());
    state.hub.users(
        recipients,
        "identity.rotated",
        json!({ "user": auth.user.address(), "user_id": auth.user.id, "identity_public_key": new_key,
                "identity_generation": generation, "at": now() }),
    );
    crate::welcome::key_changed(&state, &auth.user, true).await;
    // Other nodes refetch the keys document and find the new key with its continuity chain.
    crate::federation::remote::devices_changed(&state, &auth.user).await?;
    Ok(Json(RotateIdentityResponse { identity_public_key: new_key, identity_generation: generation }))
}

/// The current `identity_blob` of the own account (ENCRYPTION.md §9a); `404 e2ee.identity_blob_not_found` for
/// generation 0 (the key derived from the master secret).
#[utoipa::path(get, path = "/api/v1/users/me/identity/blob", security(("bearer" = [])),
    responses((status = 200, body = IdentityBlob), (status = 404, body = ProblemDetails)))]
pub async fn blob(State(state): State<AppState>, auth: AuthUser) -> Result<Json<IdentityBlob>, ApiError> {
    let not_found = || ApiError::NotFound { code: "e2ee.identity_blob_not_found", what: "Identity blob".into() };
    let row = store::e2ee::current_rotation(&state.db, &auth.user.id).await?.ok_or_else(not_found)?;
    // A reset after the rotation deletes the chain; a row whose key is not current is never served.
    if auth.user.identity_pubkey.as_deref() != Some(row.new_key.as_str()) {
        return Err(not_found());
    }
    Ok(Json(IdentityBlob {
        identity_blob: row.identity_blob,
        identity_generation: row.generation,
        identity_public_key: row.new_key,
    }))
}

fn util_b64(bytes: &[u8]) -> String {
    tavrn_crypto::util::b64url_encode(bytes)
}
