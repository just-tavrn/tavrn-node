// SPDX-License-Identifier: AGPL-3.0-only
//! Identity keys, device keys, KeyPackages and identity reset (ENCRYPTION.md §2.3, §3, §9).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::{self, AuthUser},
    e2ee,
    error::{ApiError, ApiJson, ProblemDetails},
    store,
    util::{self, now},
    validate::bad,
};

/// Stored KeyPackages per device (§3.2).
pub const MAX_KEY_PACKAGES: i64 = 100;
/// Maximum size of one KeyPackage (decoded).
pub const MAX_KEY_PACKAGE_BYTES: usize = 4096;
/// Body limit of the KeyPackage upload (100 × 4 KiB as base64url plus JSON).
pub const KEY_PACKAGE_BODY_LIMIT: usize = 600 * 1024;

#[derive(Deserialize, ToSchema)]
pub struct IdentityKeyRequest {
    /// Ed25519 public identity key, base64url (32 bytes).
    pub identity_public_key: String,
}

/// Upload the account's identity key once (§2.3). Replacing it requires the reset.
#[utoipa::path(put, path = "/api/v1/users/me/identity", security(("bearer" = [])), request_body = IdentityKeyRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn put_identity(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<IdentityKeyRequest>,
) -> Result<StatusCode, ApiError> {
    let key = e2ee::decode_public_key(&req.identity_public_key)?;
    if !store::e2ee::set_identity_once(&state.db, &auth.user.id, &util_b64(&key)).await? {
        return Err(ApiError::conflict(
            "e2ee.identity_exists",
            "The security key is already set; it can only be changed through a reset",
        ));
    }
    // A bot after an owner-driven reset (APPLICATIONS.md §3.4) announces its new key now: the reset itself
    // carried none.
    if auth.user.is_bot()
        && let Some(reset_at) = auth.user.identity_reset_at.as_deref()
    {
        let mut recipients = store::social::contact_ids(&state.db, &auth.user.id).await?;
        recipients.push(auth.user.id.clone());
        state.hub.users(
            recipients,
            "identity.changed",
            json!({ "user": auth.user.address(), "user_id": auth.user.id, "identity_reset_at": reset_at, "at": now() }),
        );
        crate::welcome::key_changed(&state, &auth.user, false).await;
        crate::federation::remote::identity_changed(&state, &auth.user, &util_b64(&key), reset_at).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn util_b64(bytes: &[u8]) -> String {
    tavrn_crypto::util::b64url_encode(bytes)
}

#[derive(Serialize, ToSchema)]
pub struct DeviceKey {
    pub device_id: String,
    pub device_public_key: String,
    pub identity_signature: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserKeys {
    /// `username@domain`
    pub user: String,
    /// `user`, `bot`, …: clients take a user's kind from its home node, so a room node cannot disguise a
    /// bot (APPLICATIONS.md §3.5).
    #[schema(required = false)]
    pub kind: String,
    pub identity_public_key: Option<String>,
    pub identity_reset_at: Option<String>,
    /// Only devices attested under the current identity key.
    pub devices: Vec<DeviceKey>,
    /// Deleted devices with their attestation (ENCRYPTION.md §2.3, §5.2): only for verifying and decrypting history
    /// they wrote before `deleted_at`, never for new messages, KeyPackages or group membership. Local users only.
    #[serde(default)]
    pub retired: Vec<RetiredDeviceKey>,
    /// The continuity chain of the identity key, oldest first (ENCRYPTION.md §9a): each statement replaces one key
    /// by the next, signed by both. Empty until the first rotation and after an identity reset. Local users only.
    #[serde(default)]
    pub continuity: Vec<crate::routes::identity::ContinuityStatement>,
    /// Generation of the current identity key: 0 = derived from the master secret, n = after n rotations. Null for
    /// remote users (ask their home node).
    pub identity_generation: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct RetiredDeviceKey {
    pub device_id: String,
    pub device_public_key: String,
    pub identity_signature: String,
    /// The identity key the signature was checked against when the device was attested.
    pub attested_identity_key: Option<String>,
    /// When the device was deleted (for devices attested again after their deletion: when that happened).
    pub deleted_at: String,
}

/// Public keys of a user (no authentication; also the federation lookup). For a remote user this node
/// knows (`alice@other.example`), the answer comes from its key cache, i.e. the view of the user's home
/// node (FEDERATION.md §3.5); clients verify keys against the home node themselves.
#[utoipa::path(get, path = "/api/v1/users/{username}/keys", params(("username" = String, Path)),
    responses((status = 200, body = UserKeys), (status = 404, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn get_keys(State(state): State<AppState>, Path(username): Path<String>) -> Result<Json<UserKeys>, ApiError> {
    if let Some(user) = remote_user(&state, &username).await? {
        crate::federation::keys::ensure(&state, &user, None).await?;
        let user = store::users::by_id(&state.db, &user.id).await?.unwrap_or(user);
        let devices = store::federation::remote_attested_devices(&state.db, &user.id).await?;
        return Ok(Json(UserKeys {
            user: user.address(),
            kind: user.kind.clone(),
            identity_public_key: user.identity_pubkey.clone(),
            identity_reset_at: user.identity_reset_at.clone(),
            devices: devices
                .into_iter()
                .map(|(device_id, device_public_key, identity_signature, created_at)| DeviceKey {
                    device_id,
                    device_public_key,
                    identity_signature,
                    created_at,
                })
                .collect(),
            retired: vec![],
            continuity: vec![],
            identity_generation: None,
        }));
    }
    let user = local_user(&state, &username).await?;
    let devices = store::e2ee::attested_devices(&state.db, &user.id).await?;
    let retired = store::users::retired_devices(&state.db, &user.id).await?;
    let continuity = store::e2ee::continuity(&state.db, &user.id).await?;
    let identity_generation = user.identity_pubkey.is_some().then_some(continuity.len() as i64);
    Ok(Json(UserKeys {
        user: user.address(),
        kind: user.kind.clone(),
        identity_public_key: user.identity_pubkey.clone(),
        identity_reset_at: user.identity_reset_at.clone(),
        devices: devices
            .into_iter()
            .filter_map(|d| {
                Some(DeviceKey {
                    device_id: d.id,
                    device_public_key: d.public_key?,
                    identity_signature: d.identity_signature?,
                    created_at: d.created_at,
                })
            })
            .collect(),
        retired: retired
            .into_iter()
            .map(|r| RetiredDeviceKey {
                device_id: r.device_id,
                device_public_key: r.public_key,
                identity_signature: r.identity_signature,
                attested_identity_key: r.attested_identity_key,
                deleted_at: r.deleted_at,
            })
            .collect(),
        continuity: continuity.into_iter().map(Into::into).collect(),
        identity_generation,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct RetiredDeviceRequest {
    /// A device of the user that no longer exists (its leaf may still be in MLS groups).
    pub device_id: String,
    /// The device key (the leaf signature key), base64url.
    pub public_key: String,
    /// Attestation of the key by the current identity key (ENCRYPTION.md §3.1), base64url.
    pub identity_signature: String,
}

/// Attests a deleted device again as retired (ENCRYPTION.md §5.2): for devices deleted before the node kept retired
/// keys, a device of the same user takes the key from the device's leaf in an MLS roster, so the history the
/// device wrote stays readable. Refused for ids of active devices, ids this node never deleted (no tombstone,
/// `404 device.unknown`) and when another key is already retired.
#[utoipa::path(post, path = "/api/v1/users/me/devices/retired", security(("bearer" = [])), request_body = RetiredDeviceRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_retired_device(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<RetiredDeviceRequest>,
) -> Result<StatusCode, ApiError> {
    state.key_package_limiter.check_all(&[format!("retired:{}", auth.user.id)])?;
    if !tavrn_crypto::util::valid_ulid(&req.device_id) {
        return Err(bad("validation.device_id", "Invalid device id"));
    }
    let Some(identity_b64) = auth.user.identity_pubkey.clone() else {
        return Err(ApiError::conflict("e2ee.identity_missing", "Upload the account's security key first"));
    };
    let identity: [u8; 32] = tavrn_crypto::util::b64url_decode(&identity_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("stored identity key invalid")))?;
    let device_key = e2ee::decode_public_key(&req.public_key)?;
    let signature: [u8; 64] = tavrn_crypto::util::b64url_decode(&req.identity_signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("e2ee.attestation_invalid", "Signature must be 64 bytes of base64url"))?;
    let attestation = tavrn_crypto::DeviceAttestation {
        user_address: auth.user.address(),
        device_id: req.device_id.clone(),
        device_public_key: device_key,
        identity_public_key: identity,
        signature,
    };
    if tavrn_crypto::verify_device_attestation(&attestation, &identity).is_err() {
        return Err(bad("e2ee.attestation_invalid", "The device attestation does not match the security key"));
    }
    if store::users::device_id_in_use(&state.db, &req.device_id).await? {
        return Err(ApiError::conflict("device.active", "This device id belongs to an active device"));
    }
    // Only ids this node deleted itself (ENCRYPTION.md §2.3): a leaf planted under the user's address in some roster
    // cannot be turned into a "removed device" of the user.
    if !store::users::has_tombstone(&state.db, &auth.user.id, &req.device_id).await? {
        return Err(ApiError::NotFound { code: "device.unknown", what: "Deleted device".into() });
    }
    let key = util_b64(&device_key);
    if let Some(existing) = store::users::retired_device(&state.db, &req.device_id).await? {
        if existing.user_id == auth.user.id && existing.public_key == key {
            return Ok(StatusCode::NO_CONTENT);
        }
        return Err(ApiError::conflict("device.retired_conflict", "Another key is already retired for this device id"));
    }
    store::users::insert_reattested(
        &state.db,
        &auth.user.id,
        &req.device_id,
        &key,
        &util_b64(&signature),
        &identity_b64,
    )
    .await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.device_reattested",
        &auth.user.address(),
        &req.device_id,
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn user_not_found() -> ApiError {
    ApiError::NotFound { code: "user.not_found", what: "User".into() }
}

/// A remote user this node already knows, named by address (`None` for local references; `404` for
/// unknown remote addresses: this node never fetches users on behalf of anonymous callers).
async fn remote_user(state: &AppState, reference: &str) -> Result<Option<crate::models::UserRow>, ApiError> {
    let Some((username, domain)) = util::parse_address(reference.trim()) else { return Ok(None) };
    if domain == state.config.domain {
        return Ok(None);
    }
    store::federation::user_by_address(&state.db, username, domain)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .map(Some)
        .ok_or_else(user_not_found)
}

/// Active local user by username (`user.not_found` otherwise).
pub async fn local_user(state: &AppState, username: &str) -> Result<crate::models::UserRow, ApiError> {
    let username = username.trim().to_lowercase();
    let username = username.strip_suffix(&format!("@{}", state.config.domain)).unwrap_or(&username);
    if !util::valid_username(username) {
        return Err(ApiError::NotFound { code: "user.not_found", what: "User".into() });
    }
    store::users::by_username(&state.db, username, &state.config.domain)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceKeyRequest {
    /// Ed25519 public key of the device, base64url (32 bytes).
    pub device_public_key: String,
    /// Signature of the identity key over the attestation message (§3.1), base64url (64 bytes).
    pub identity_signature: String,
}

fn own_device(auth: &AuthUser, device_id: &str) -> Result<(), ApiError> {
    if device_id != auth.device_id {
        return Err(ApiError::Forbidden {
            code: "e2ee.wrong_device",
            detail: "Only for the device of the current session".into(),
        });
    }
    Ok(())
}

/// Attest the session's device (§3.1). The node verifies the identity signature; device keys are
/// immutable, after an identity reset only the attestation of the same key can be renewed.
#[utoipa::path(put, path = "/api/v1/users/me/devices/{device_id}/key", security(("bearer" = [])), params(("device_id" = String, Path)), request_body = DeviceKeyRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn put_device_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<String>,
    ApiJson(req): ApiJson<DeviceKeyRequest>,
) -> Result<StatusCode, ApiError> {
    own_device(&auth, &device_id)?;
    let Some(identity_b64) = auth.user.identity_pubkey.clone() else {
        return Err(ApiError::conflict("e2ee.identity_missing", "Upload the account's security key first"));
    };
    let identity: [u8; 32] = tavrn_crypto::util::b64url_decode(&identity_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("stored identity key invalid")))?;
    let device_key = e2ee::decode_public_key(&req.device_public_key)?;
    let signature: [u8; 64] = tavrn_crypto::util::b64url_decode(&req.identity_signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("e2ee.attestation_invalid", "Signature must be 64 bytes of base64url"))?;
    let attestation = tavrn_crypto::DeviceAttestation {
        user_address: auth.user.address(),
        device_id: device_id.clone(),
        device_public_key: device_key,
        identity_public_key: identity,
        signature,
    };
    if tavrn_crypto::verify_device_attestation(&attestation, &identity).is_err() {
        return Err(bad("e2ee.attestation_invalid", "The device attestation does not match the security key"));
    }
    let stored = store::e2ee::set_device_key(
        &state.db,
        &auth.user.id,
        &device_id,
        &util_b64(&device_key),
        &util_b64(&signature),
        &identity_b64,
    )
    .await?;
    if !stored {
        return Err(ApiError::conflict(
            "e2ee.device_key_exists",
            "This device already has a key; a new key needs a new device",
        ));
    }
    crate::federation::remote::devices_changed(&state, &auth.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct KeyPackagesRequest {
    /// MLSMessages carrying KeyPackages, base64url, at most 100, each at most 4 KiB.
    pub key_packages: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct KeyPackageCount {
    pub count: i64,
}

/// Upload KeyPackages of the session's attested device (§3.2).
#[utoipa::path(post, path = "/api/v1/users/me/devices/{device_id}/key-packages", security(("bearer" = [])), params(("device_id" = String, Path)), request_body = KeyPackagesRequest,
    responses((status = 201, body = KeyPackageCount), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn upload_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<String>,
    ApiJson(req): ApiJson<KeyPackagesRequest>,
) -> Result<(StatusCode, Json<KeyPackageCount>), ApiError> {
    own_device(&auth, &device_id)?;
    state.key_package_limiter.check_all(&[format!("kp:{device_id}")])?;
    let device_key = e2ee::attested_session_key(&state, &auth).await?;
    if req.key_packages.is_empty() || req.key_packages.len() > MAX_KEY_PACKAGES as usize {
        return Err(bad("e2ee.key_package_count", format!("1 to {MAX_KEY_PACKAGES} KeyPackages per request")));
    }
    let identity = e2ee::device_identity(&auth.user, &device_id);
    let mut packages = Vec::with_capacity(req.key_packages.len());
    for kp in &req.key_packages {
        let bytes = e2ee::decode("key_packages", kp, MAX_KEY_PACKAGE_BYTES, "e2ee.key_package_too_large")?;
        let entry = tavrn_crypto::ds::inspect_key_package(&bytes)
            .map_err(|e| bad("e2ee.key_package_invalid", format!("Invalid KeyPackage ({})", e.code())))?;
        if entry.identity != identity || entry.signature_key != device_key {
            return Err(bad("e2ee.key_package_mismatch", "KeyPackage does not belong to this device or key"));
        }
        let hash = util_b64(&Sha256::digest(&bytes));
        if !packages.iter().any(|(_, h)| h == &hash) {
            packages.push((bytes, hash));
        }
    }
    let existing = store::e2ee::key_package_count(&state.db, &device_id).await?;
    if existing + packages.len() as i64 > MAX_KEY_PACKAGES {
        return Err(ApiError::Conflict {
            code: "e2ee.key_package_limit",
            detail: format!("At most {MAX_KEY_PACKAGES} KeyPackages per device"),
            meta: json!({ "max": MAX_KEY_PACKAGES, "stored": existing }),
        });
    }
    let count = store::e2ee::insert_key_packages(&state.db, &auth.user.id, &device_id, &packages).await?;
    Ok((StatusCode::CREATED, Json(KeyPackageCount { count })))
}

/// Number of stored KeyPackages of one of the user's devices.
#[utoipa::path(get, path = "/api/v1/users/me/devices/{device_id}/key-packages", security(("bearer" = [])), params(("device_id" = String, Path)),
    responses((status = 200, body = KeyPackageCount), (status = 404, body = ProblemDetails)))]
pub async fn count_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<String>,
) -> Result<Json<KeyPackageCount>, ApiError> {
    match store::e2ee::device_key(&state.db, &device_id).await? {
        Some(d) if d.user_id == auth.user.id => {}
        _ => return Err(ApiError::NotFound { code: "device.not_found", what: "Device".into() }),
    }
    Ok(Json(KeyPackageCount { count: store::e2ee::key_package_count(&state.db, &device_id).await? }))
}

#[derive(Serialize, ToSchema)]
pub struct ClaimedKeyPackage {
    pub device_id: String,
    pub key_package: String,
}

#[derive(Serialize, ToSchema)]
pub struct ClaimedKeyPackages {
    pub key_packages: Vec<ClaimedKeyPackage>,
}

/// Claim one KeyPackage per attested device of a user (single use, rate-limited). For a user of another
/// node (`alice@other.example`) this node claims them from the user's home node and returns the ones
/// that match the user's attested devices (FEDERATION.md §3.5).
#[utoipa::path(post, path = "/api/v1/users/{username}/key-packages/claim", security(("bearer" = [])), params(("username" = String, Path)),
    responses((status = 200, body = ClaimedKeyPackages), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn claim_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<ClaimedKeyPackages>, ApiError> {
    state.claim_limiter.check_all(&[format!("claim:{}", auth.user.id)])?;
    if let Some((_, domain)) = util::parse_address(username.trim())
        && domain != state.config.domain
    {
        if !state.config.federation_enabled {
            return Err(crate::federation::disabled());
        }
        crate::federation::check_policy(&state, domain).await?;
    }
    let packages = match remote_user(&state, &username).await? {
        Some(target) => crate::federation::claims::proxy(&state, &auth.user, &target).await?,
        None => {
            let target = local_user(&state, &username).await?;
            // The same rules as for claims of other nodes (FEDERATION.md §3.5): nothing for people the user blocked,
            // and a limit per requester and user, so nobody drains another user's KeyPackages.
            if target.id != auth.user.id && store::social::has_blocked(&state.db, &target.id, &auth.user.id).await? {
                return Err(ApiError::Forbidden {
                    code: "federation.claim_refused",
                    detail: "This user does not hand out key packages".into(),
                });
            }
            if target.id != auth.user.id {
                state.claim_pair_limiter.check_all(&[format!("{}|{}", auth.user.address(), target.address())]).await?;
            }
            crate::federation::claims::claim_local(&state, &target).await?
        }
    };
    Ok(Json(ClaimedKeyPackages {
        key_packages: packages
            .into_iter()
            .map(|(device_id, key_package)| ClaimedKeyPackage { device_id, key_package })
            .collect(),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct IdentityResetRequest {
    /// The new Ed25519 identity key, base64url.
    pub identity_public_key: String,
    /// Current password as confirmation (accounts with a password).
    #[serde(default)]
    pub password: Option<String>,
    /// A reauth token (PROTOCOL.md §5c; SSO accounts get one from `POST /auth/oidc/token`, purpose `reauth`,
    /// APPLICATIONS.md §8.4) instead of the password. The `Tavrn-Reauth` header works as well.
    #[serde(default)]
    pub reauth_token: Option<String>,
}

/// Identity reset after losing the key file (§9): new identity key, all attestations, KeyPackages
/// and backups are deleted; contacts receive `identity.changed`.
#[utoipa::path(post, path = "/api/v1/users/me/identity/reset", security(("bearer" = [])), request_body = IdentityResetRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn reset_identity(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<IdentityResetRequest>,
) -> Result<StatusCode, ApiError> {
    state.login_limiter.check_all(&[format!("user:{}", auth.user.username)]).await?;
    let ok = match (req.reauth_token.as_deref(), req.password.as_deref().filter(|p| !p.is_empty())) {
        (Some(token), _) => {
            state.oidc.as_ref().is_some_and(|o| o.take_reauth(token, &auth.user.id))
                || crate::reauth::valid(&state, &auth, token).await?
        }
        (None, Some(password)) => {
            auth.user.password_hash.as_deref().is_some_and(|h| auth::verify_password(password, h))
        }
        (None, None) => {
            if !crate::reauth::header_valid(&state, &auth, &headers).await? {
                return Err(crate::reauth::required(&state, &auth.user).await);
            }
            true
        }
    };
    if !ok {
        return Err(ApiError::Unauthorized { code: "auth.invalid_credentials" });
    }
    let key = e2ee::decode_public_key(&req.identity_public_key)?;
    let reset_at = store::e2ee::reset_identity(&state.db, &auth.user.id, &util_b64(&key)).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.identity_reset",
        &auth.user.address(),
        "",
        json!({}),
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
        "identity.changed",
        json!({ "user": auth.user.address(), "user_id": auth.user.id, "identity_reset_at": reset_at, "at": now() }),
    );
    e2ee::identity_reset(&state, &auth.user).await?;
    crate::welcome::key_changed(&state, &auth.user, false).await;
    crate::federation::remote::identity_changed(&state, &auth.user, &util_b64(&key), &reset_at).await?;
    Ok(StatusCode::NO_CONTENT)
}
