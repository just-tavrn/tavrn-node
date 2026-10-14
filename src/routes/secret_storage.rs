// SPDX-License-Identifier: AGPL-3.0-only
//! Secret storage (ENCRYPTION.md §2.4): the master secret wrapped per unlock method. Only the
//! owner with a full session (password and second factor) can read or write it; the node cannot
//! unwrap it.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tavrn_crypto::secret_storage::{METHOD_RECOVERY, WRAPPED_LEN, WRAPPED_VERSION};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    second_factor as sf, store,
    validate::bad,
};

/// Maximum size of `params` (serialized JSON).
pub const MAX_PARAMS_BYTES: usize = 2048;

#[derive(Serialize, ToSchema)]
pub struct SecretStorageEntry {
    /// `recovery` or `passkey:<credential id>`.
    pub method: String,
    /// `0x01 || nonce(12) || AES-256-GCM(master secret)`, base64url (61 bytes).
    pub wrapped: String,
    /// Client data stored with the entry (at most 2 KiB of JSON).
    #[schema(value_type = Object)]
    pub params: Value,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct SecretStorageList {
    pub items: Vec<SecretStorageEntry>,
}

#[derive(Deserialize, ToSchema)]
pub struct PutSecretStorage {
    /// base64url of the wrapped master secret (ENCRYPTION.md §2.4).
    pub wrapped: String,
    /// JSON object, at most 2 KiB.
    #[schema(value_type = Object)]
    pub params: Value,
}

/// All entries of the own account.
#[utoipa::path(get, path = "/api/v1/users/me/secret-storage", security(("bearer" = [])),
    responses((status = 200, body = SecretStorageList), (status = 401, body = ProblemDetails)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<SecretStorageList>, ApiError> {
    let rows = store::factors::secret_storage(&state.db, &auth.user.id).await?;
    Ok(Json(SecretStorageList {
        items: rows
            .into_iter()
            .map(|r| SecretStorageEntry {
                method: r.method,
                wrapped: tavrn_crypto::util::b64url_encode(&r.wrapped),
                params: serde_json::from_str(&r.params).unwrap_or(Value::Null),
                updated_at: r.updated_at,
            })
            .collect(),
    }))
}

/// Checks format and size; returns the wrapped bytes and the serialized params.
fn validate(state: &AppState, auth: &AuthUser, req: &PutSecretStorage) -> Result<(Vec<u8>, String), ApiError> {
    state.secret_storage_limiter.check_all(&[format!("secret-storage:{}", auth.user.id)])?;
    let invalid = || bad("secret_storage.invalid", "wrapped: expected 61 bytes of base64url with version 1");
    if req.wrapped.len() > 128 {
        return Err(invalid());
    }
    let wrapped = tavrn_crypto::util::b64url_decode(&req.wrapped).map_err(|_| invalid())?;
    if wrapped.len() != WRAPPED_LEN || wrapped[0] != WRAPPED_VERSION {
        return Err(invalid());
    }
    if !req.params.is_object() {
        return Err(bad("secret_storage.params_invalid", "params must be a JSON object"));
    }
    let params = req.params.to_string();
    if params.len() > MAX_PARAMS_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "secret_storage.params_too_large",
            detail: format!("params: at most {MAX_PARAMS_BYTES} bytes"),
            meta: serde_json::json!({ "max_bytes": MAX_PARAMS_BYTES }),
        });
    }
    Ok((wrapped, params))
}

/// Stores the entry wrapped with the recovery key. Replacing an existing entry (a new recovery key) needs a reauth
/// token (`Tavrn-Reauth`, PROTOCOL.md §5c); the first entry of a new account does not.
#[utoipa::path(put, path = "/api/v1/users/me/secret-storage/recovery", security(("bearer" = [])), request_body = PutSecretStorage,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_recovery(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<PutSecretStorage>,
) -> Result<StatusCode, ApiError> {
    let (wrapped, params) = validate(&state, &auth, &req)?;
    let exists =
        store::factors::secret_storage(&state.db, &auth.user.id).await?.iter().any(|e| e.method == METHOD_RECOVERY);
    if exists {
        crate::reauth::require(&state, &auth, &headers).await?;
    }
    store::factors::put_secret_storage(&state.db, &auth.user.id, METHOD_RECOVERY, &wrapped, &params, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn credential_id(id: &str) -> Result<(), ApiError> {
    if sf::valid_credential_id(id) {
        Ok(())
    } else {
        Err(bad("validation.credential_id", "Invalid security key ID (base64url)"))
    }
}

fn credential_not_found() -> ApiError {
    ApiError::NotFound { code: "webauthn.not_found", what: "Security key".into() }
}

/// Stores or replaces the entry of a WebAuthn credential of the user and marks the credential as PRF-capable: the
/// entry (a wrap under the credential's PRF output) proves the extension works even when the registration did not
/// announce it (needs a reauth token).
#[utoipa::path(put, path = "/api/v1/users/me/secret-storage/passkey/{credential_id}", security(("bearer" = [])), params(("credential_id" = String, Path)), request_body = PutSecretStorage,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_passkey(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<PutSecretStorage>,
) -> Result<StatusCode, ApiError> {
    credential_id(&id)?;
    crate::reauth::require(&state, &auth, &headers).await?;
    let (wrapped, params) = validate(&state, &auth, &req)?;
    store::factors::credential(&state.db, &auth.user.id, &id).await?.ok_or_else(credential_not_found)?;
    let method = format!("passkey:{id}");
    if !store::factors::put_secret_storage(&state.db, &auth.user.id, &method, &wrapped, &params, Some(&id)).await? {
        return Err(credential_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the entry of a credential (the credential itself stays; needs a reauth token).
#[utoipa::path(delete, path = "/api/v1/users/me/secret-storage/passkey/{credential_id}", security(("bearer" = [])), params(("credential_id" = String, Path)),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_passkey(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    credential_id(&id)?;
    crate::reauth::require(&state, &auth, &headers).await?;
    if !store::factors::delete_secret_storage(&state.db, &auth.user.id, &format!("passkey:{id}")).await? {
        return Err(ApiError::NotFound { code: "secret_storage.not_found", what: "Entry".into() });
    }
    Ok(StatusCode::NO_CONTENT)
}
