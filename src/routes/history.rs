// SPDX-License-Identifier: AGPL-3.0-only
//! History key shares (ENCRYPTION.md §7b): members hand the content keys of past
//! epochs to a new member, encrypted under the conversation's current content key. The node cannot read
//! a share; it checks who may send one to whom, limits size and rate, stores it until the recipient
//! acknowledges it and tells the recipient's sockets that keys are waiting.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    e2ee,
    error::{ApiError, ApiJson, ProblemDetails},
    history::{self, Policy},
    permissions, store, util,
    validate::bad,
};

fn forbidden(detail: &str) -> ApiError {
    ApiError::Forbidden { code: "history.forbidden", detail: detail.into() }
}

/// The conversation for the history routes: the requester must be entitled (member with read access).
async fn entitled(state: &AppState, auth: &AuthUser, conversation_id: &str) -> Result<Conv, ApiError> {
    let conv = access::conversation(state, conversation_id, &auth.user).await?;
    conv.require_entitled()?;
    Ok(conv)
}

#[derive(Deserialize, ToSchema)]
pub struct CreateHistoryShareRequest {
    /// Recipient address `name@domain` (a member of the conversation other than the sender).
    pub to_user: String,
    /// First and last epoch whose keys the share carries (at most 1000 epochs).
    pub epoch_from: i64,
    pub epoch_to: i64,
    /// The key list, encrypted like message content under the current epoch (ENCRYPTION.md §7b), base64url;
    /// at most 64 KiB.
    pub ciphertext: String,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryShareCreated {
    pub id: String,
}

/// Share keys of past epochs with a new member. Allowed only in encrypted room channels whose policy
/// grants history, from an attested device of a member to a member with `read_history`.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/history-keys", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = CreateHistoryShareRequest,
    responses((status = 201, body = HistoryShareCreated), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<CreateHistoryShareRequest>,
) -> Result<(StatusCode, Json<HistoryShareCreated>), ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    if !conv.encrypted {
        return Err(bad("history.not_encrypted", "This conversation is not end-to-end encrypted"));
    }
    let ConvKind::Channel { channel, .. } = &conv.kind else {
        // DMs: both participants are members from the start; group DMs: `since_join`.
        return Err(forbidden("History keys are shared only in room channels"));
    };
    if !Policy::of(channel.history_for_new_members.as_deref()).grants_history() {
        return Err(forbidden("The channel does not give new members its history"));
    }
    if req.ciphertext.len() > history::MAX_SHARE_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "history.too_large",
            detail: "A share is limited to 64 KiB".into(),
            meta: json!({ "max_bytes": history::MAX_SHARE_BYTES }),
        });
    }
    let current = store::e2ee::group_epoch(&state.db, &conv.id)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "mls.no_group", what: "MLS group".into() })?;
    if req.epoch_from < 0
        || req.epoch_to < req.epoch_from
        || req.epoch_to > current
        || req.epoch_to - req.epoch_from >= history::MAX_EPOCHS_PER_SHARE
    {
        return Err(bad("history.invalid", "epoch_from..epoch_to must be a range of at most 1000 known epochs"));
    }
    // The ciphertext is message content (format 1) under an epoch the node knows.
    let header = tavrn_crypto::content_header(&req.ciphertext)
        .map_err(|_| bad("history.invalid", "ciphertext is not encrypted content (format 1)"))?;
    if header.epoch > current as u64 {
        return Err(bad("history.invalid", "ciphertext is encrypted under an unknown epoch"));
    }
    e2ee::attested_session_key(&state, &auth).await?;
    // The recipient: another member with read access and `read_history` in this channel.
    let me = auth.user.address();
    if req.to_user == me {
        return Err(bad("history.self", "Your own devices get the keys from the history backup"));
    }
    let recipient = match util::parse_address(&req.to_user) {
        Some((username, domain)) => store::federation::user_by_address(&state.db, username, domain).await?,
        None => return Err(bad("history.invalid", "to_user must be an address name@domain")),
    };
    let Some(recipient) = recipient else { return Err(forbidden("The recipient is not a member")) };
    if !recipient_may_read_history(&state, &conv, &recipient).await? {
        return Err(forbidden("The recipient may not receive this channel's history"));
    }
    let to = recipient.address();
    let since = util::format_time(Utc::now() - Duration::hours(24));
    if store::history::count_since(&state.db, &conv.id, &to, &since).await? >= history::SHARES_PER_DAY {
        return Err(ApiError::RateLimited { retry_after_secs: 3600 });
    }
    let id = store::history::insert_share(
        &state.db,
        store::history::NewShare {
            conversation_id: &conv.id,
            to_user: &to,
            from_user: &me,
            from_device: auth.public_device_id(),
            epoch_from: req.epoch_from,
            epoch_to: req.epoch_to,
            ciphertext: &req.ciphertext,
        },
    )
    .await?;
    state.hub.users(vec![recipient.id.clone()], "history.keys_available", json!({ "conversation_id": conv.id }));
    Ok((StatusCode::CREATED, Json(HistoryShareCreated { id })))
}

/// Entitled to the channel (member with `view_channel`, not disabled) and `read_history` there.
async fn recipient_may_read_history(
    state: &AppState,
    conv: &Conv,
    user: &crate::models::UserRow,
) -> Result<bool, ApiError> {
    let ConvKind::Channel { access, channel } = &conv.kind else { return Ok(false) };
    if user.disabled_at.is_some() {
        return Ok(false);
    }
    let member_access = match access::room_access(state, &access.room.id, user).await {
        Ok(a) if a.member.is_some() => a,
        Ok(_) | Err(ApiError::Forbidden { .. }) => return Ok(false),
        Err(e) => return Err(e),
    };
    let perms = access::channel_perms(state, &member_access, channel, &user.id).await?;
    Ok(permissions::has(perms, permissions::VIEW_CHANNEL | permissions::READ_HISTORY))
}

#[derive(Serialize, ToSchema)]
pub struct HistoryShare {
    pub id: String,
    /// Sharing user and device: the recipient verifies the signature against this device's attestation.
    pub from_user: String,
    pub from_device: String,
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub ciphertext: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryShareList {
    pub items: Vec<HistoryShare>,
}

/// Unacknowledged shares addressed to the requester (oldest first, at most 100).
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/history-keys", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = HistoryShareList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_shares(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<HistoryShareList>, ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    let rows = store::history::shares_for(&state.db, &conv.id, &auth.user.address(), 100).await?;
    Ok(Json(HistoryShareList {
        items: rows
            .into_iter()
            .map(|r| HistoryShare {
                id: r.id,
                from_user: r.from_user,
                from_device: r.from_device,
                epoch_from: r.epoch_from,
                epoch_to: r.epoch_to,
                ciphertext: r.ciphertext,
                created_at: r.created_at,
            })
            .collect(),
    }))
}

/// Acknowledge (and drop) a share addressed to the requester; the requester is no longer pending.
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/history-keys/{share_id}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("share_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn ack_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, share_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    if !store::history::ack(&state.db, &conv.id, &auth.user.address(), &share_id).await? {
        return Err(ApiError::NotFound { code: "history.share_not_found", what: "History share".into() });
    }
    store::history::clear_pending(&state.db, &conv.id, &auth.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct HistoryPendingMember {
    /// Member address.
    pub user: String,
    /// The membership's `joined_at` (start of the policy window).
    pub since: String,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryPendingList {
    pub items: Vec<HistoryPendingMember>,
}

/// Members of the channel who still wait for history keys (at most 100, the last 30 days). Empty for DMs,
/// group DMs, plaintext channels and channels whose policy is `since_join`.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/history-pending", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = HistoryPendingList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_pending(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<HistoryPendingList>, ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    let ConvKind::Channel { access, channel } = &conv.kind else {
        return Ok(Json(HistoryPendingList { items: vec![] }));
    };
    if !conv.encrypted || !Policy::of(channel.history_for_new_members.as_deref()).grants_history() {
        return Ok(Json(HistoryPendingList { items: vec![] }));
    }
    let newer_than = util::format_time(Utc::now() - Duration::days(history::MAX_AGE_DAYS));
    let rows = store::history::pending_members(&state.db, &conv.id, &access.room.id, &newer_than).await?;
    Ok(Json(HistoryPendingList {
        items: rows
            .into_iter()
            .map(|(_, username, domain, since)| HistoryPendingMember { user: format!("{username}@{domain}"), since })
            .collect(),
    }))
}
