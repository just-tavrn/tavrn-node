// SPDX-License-Identifier: AGPL-3.0-only
//! Encrypted history backups (ENCRYPTION.md §7). Only the owner reads and writes them.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    store,
    validate::bad,
};

/// Maximum size of one backup blob.
pub const MAX_BACKUP_BYTES: usize = 1024 * 1024;
/// Maximum number of backups (conversations) per user.
pub const MAX_BACKUPS_PER_USER: i64 = 1000;
/// Smallest valid blob: version, nonce, GCM tag.
const MIN_BACKUP_BYTES: usize = 1 + 12 + 16;

#[derive(Serialize, ToSchema)]
pub struct BackupInfo {
    /// Qualified conversation id `<domain>/<ULID>`.
    pub conversation: String,
    pub size: i64,
    pub etag: String,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct BackupList {
    pub items: Vec<BackupInfo>,
}

fn conversation(domain: &str, ulid: &str) -> Result<String, ApiError> {
    let c = format!("{domain}/{ulid}");
    if !tavrn_crypto::util::valid_conversation(&c) {
        return Err(bad("backup.conversation_invalid", "Expected: <domain>/<conversation ULID>"));
    }
    Ok(c)
}

fn not_found() -> ApiError {
    ApiError::NotFound { code: "backup.not_found", what: "Backup".into() }
}

/// Store the backup of one conversation. Overwriting needs `If-Match` with the current `ETag`;
/// creating needs no `If-Match` (412 `backup.etag_mismatch` otherwise).
#[utoipa::path(put, path = "/api/v1/users/me/backups/{domain}/{conversation_id}", security(("bearer" = [])),
    params(("domain" = String, Path), ("conversation_id" = String, Path), ("If-Match" = Option<String>, Header, description = "ETag of the backup being replaced")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = BackupInfo), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 412, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_backup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((domain, conversation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let conversation = conversation(&domain, &conversation_id)?;
    state.backup_limiter.check_all(&[format!("backup:{}", auth.user.id)])?;
    let blob = axum::body::to_bytes(body, MAX_BACKUP_BYTES).await.map_err(|_| ApiError::PayloadTooLarge {
        code: "backup.too_large",
        detail: format!("A backup may be at most {} KiB", MAX_BACKUP_BYTES / 1024),
        meta: serde_json::json!({ "max_bytes": MAX_BACKUP_BYTES }),
    })?;
    if blob.len() < MIN_BACKUP_BYTES || blob[0] != 1 {
        return Err(bad("backup.invalid", "Not a valid backup (format version 1)"));
    }
    let if_match = headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()).map(str::trim);
    if if_match.is_none() && store::e2ee::backup_count(&state.db, &auth.user.id).await? >= MAX_BACKUPS_PER_USER {
        return Err(ApiError::Forbidden {
            code: "backup.limit",
            detail: format!("At most {MAX_BACKUPS_PER_USER} backups per account"),
        });
    }
    let etag = format!("\"{}\"", tavrn_crypto::util::b64url_encode(&Sha256::digest(&blob)));
    let stored = store::e2ee::put_backup(&state.db, &auth.user.id, &conversation, &blob, &etag, if_match).await?;
    let Some(updated_at) = stored else {
        return Err(ApiError::PreconditionFailed {
            code: "backup.etag_mismatch",
            detail: "The backup has changed in the meantime; reload, merge and send again".into(),
            meta: serde_json::Value::Null,
        });
    };
    let info = BackupInfo { conversation, size: blob.len() as i64, etag: etag.clone(), updated_at };
    let mut resp = Json(info).into_response();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    Ok(resp)
}

/// Download the backup of one conversation (with `ETag`).
#[utoipa::path(get, path = "/api/v1/users/me/backups/{domain}/{conversation_id}", security(("bearer" = [])), params(("domain" = String, Path), ("conversation_id" = String, Path)),
    responses((status = 200, description = "Backup blob (application/octet-stream)"), (status = 404, body = ProblemDetails)))]
pub async fn get_backup(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((domain, conversation_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let conversation = conversation(&domain, &conversation_id)?;
    let (blob, etag) = store::e2ee::backup(&state.db, &auth.user.id, &conversation).await?.ok_or_else(not_found)?;
    let mut resp = Response::new(Body::from(blob));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    Ok(resp)
}

/// All backups of the account.
#[utoipa::path(get, path = "/api/v1/users/me/backups", security(("bearer" = [])), responses((status = 200, body = BackupList)))]
pub async fn list_backups(State(state): State<AppState>, auth: AuthUser) -> Result<Json<BackupList>, ApiError> {
    let rows = store::e2ee::backups(&state.db, &auth.user.id).await?;
    Ok(Json(BackupList {
        items: rows
            .into_iter()
            .map(|b| BackupInfo { conversation: b.conversation, size: b.size, etag: b.etag, updated_at: b.updated_at })
            .collect(),
    }))
}
