// SPDX-License-Identifier: AGPL-3.0-only
//! History key shares (ENCRYPTION.md §7b): members hand the content keys of past
//! epochs to a new member, encrypted under the conversation's current content key (format 1) or under a fresh key
//! sealed to each device of the recipient (format 2). The node cannot read a share; it checks who may send one to
//! whom, limits size and rate, stores it until the recipient acknowledges it, serves every recipient device only its
//! own box and tells the recipient's sockets that keys are waiting.

use std::collections::BTreeMap;

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
    history, permissions, store, util,
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
    /// at most 64 KiB. Format 2: under the share's fresh key, with the current epoch in the header.
    pub ciphertext: String,
    /// Share format: 1 (default) or 2 (sealed per recipient device, capability `history.shares2`).
    #[serde(default)]
    pub v: Option<i64>,
    /// Format 2: the share's key sealed to each device of the recipient, device id → base64url box: 1 to 20 boxes,
    /// each at most 128 bytes, every device an attested device of `to_user` with a share key.
    #[serde(default)]
    pub boxes: Option<BTreeMap<String, String>>,
}

/// Boxes per v2 share.
pub const MAX_BOXES: usize = 20;
/// Largest box (bytes, decoded): a sealed 32-byte key is 80.
pub const MAX_BOX_BYTES: usize = 128;

/// The format and the decoded-and-checked boxes of a share request (`history.invalid` otherwise).
fn share_format(req: &CreateHistoryShareRequest) -> Result<(i64, Vec<(String, String)>), ApiError> {
    match (req.v.unwrap_or(1), &req.boxes) {
        (1, None) => Ok((1, Vec::new())),
        (2, Some(boxes)) if (1..=MAX_BOXES).contains(&boxes.len()) => {
            let mut out = Vec::with_capacity(boxes.len());
            for (device_id, sealed) in boxes {
                let size = tavrn_crypto::util::b64url_decode(sealed).map(|b| b.len()).unwrap_or(0);
                if !tavrn_crypto::util::valid_ulid(device_id) || size == 0 || size > MAX_BOX_BYTES {
                    return Err(bad(
                        "history.invalid",
                        "Every box must name a device id and be 1 to 128 bytes of base64url",
                    ));
                }
                out.push((device_id.clone(), sealed.clone()));
            }
            Ok((2, out))
        }
        (2, _) => Err(bad("history.invalid", "A format 2 share carries 1 to 20 boxes")),
        (1, Some(_)) => Err(bad("history.invalid", "A format 1 share carries no boxes")),
        _ => Err(bad("history.invalid", "Unknown share format")),
    }
}

/// Every box of a v2 share must be for an attested device of the recipient that has a share key (ENCRYPTION.md
/// §7b). For a recipient of another node the key cache is refreshed once when a device is missing.
async fn check_box_devices(
    state: &AppState,
    recipient: &crate::models::UserRow,
    boxes: &[(String, String)],
) -> Result<(), ApiError> {
    if boxes.is_empty() {
        return Ok(());
    }
    let mut known = store::e2ee::share_key_devices(&state.db, &recipient.id).await?;
    let missing = |known: &[String]| boxes.iter().find(|(d, _)| !known.contains(d)).map(|(d, _)| d.clone());
    if let Some(first) = missing(&known)
        && recipient.domain != state.config.domain
    {
        crate::federation::keys::ensure(state, recipient, Some(&first)).await?;
        known = store::e2ee::share_key_devices(&state.db, &recipient.id).await?;
    }
    if missing(&known).is_some() {
        return Err(bad(
            "history.invalid",
            "Every box must be for an attested device of the recipient with a share key",
        ));
    }
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct HistoryShareCreated {
    pub id: String,
}

/// Share keys of past epochs with a member who joined later. Allowed in encrypted room channels under every policy
/// (under `since_join` for the epochs since the recipient's join: its window bounds what it is served and accepts),
/// from an attested device of a member to a member with `read_history`.
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
    if !matches!(conv.kind, ConvKind::Channel { .. }) {
        // DMs: both participants are members from the start; group DMs: `since_join`.
        return Err(forbidden("History keys are shared only in room channels"));
    }
    let (version, boxes) = share_format(&req)?;
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
    let Some(target) = recipient_access(&state, &conv, &recipient).await? else {
        return Err(forbidden("The recipient is not a member"));
    };
    // After the recipient's key reset, keys up to the reset epoch are a restore (ENCRYPTION.md §7b "History after a
    // key reset"): only from a member with `restore_history` while an approved restore is valid.
    let reset_epoch = match target.member.key_reset_at {
        Some(_) => store::history::reset_epoch(&state.db, &conv.id, &recipient.id).await?,
        None => None,
    };
    if reset_epoch.is_some_and(|e| req.epoch_from <= e) {
        let valid_since = util::format_time(Utc::now() - Duration::days(history::RESTORE_VALID_DAYS));
        let approved = target.member.history_restored_at.as_deref().is_some_and(|t| t >= valid_since.as_str());
        if !approved || !permissions::has(conv.perms, permissions::RESTORE_HISTORY) {
            return Err(forbidden("Keys from before the recipient's key reset need an approved restore"));
        }
        if !permissions::has(target.perms, permissions::VIEW_CHANNEL) {
            return Err(forbidden("The recipient may not read this channel"));
        }
    } else if !permissions::has(target.perms, permissions::VIEW_CHANNEL | permissions::READ_HISTORY) {
        // Every policy: under `since_join` the recipient's window starts at its join, and its node serves it nothing
        // older to check a key against (ENCRYPTION.md §7b).
        return Err(forbidden("The recipient may not receive this channel's history"));
    }
    check_box_devices(&state, &recipient, &boxes).await?;
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
            version,
            boxes: &boxes,
        },
    )
    .await?;
    state.hub.users(vec![recipient.id.clone()], "history.keys_available", json!({ "conversation_id": conv.id }));
    Ok((StatusCode::CREATED, Json(HistoryShareCreated { id })))
}

/// The recipient's membership and channel permissions; `None` for non-members and disabled accounts.
struct Recipient {
    member: crate::models::MemberRow,
    perms: permissions::Perms,
}

async fn recipient_access(
    state: &AppState,
    conv: &Conv,
    user: &crate::models::UserRow,
) -> Result<Option<Recipient>, ApiError> {
    let ConvKind::Channel { access, channel } = &conv.kind else { return Ok(None) };
    if user.disabled_at.is_some() {
        return Ok(None);
    }
    let member_access = match access::room_access(state, &access.room.id, user).await {
        Ok(a) => a,
        Err(ApiError::Forbidden { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(member) = member_access.member.clone() else { return Ok(None) };
    let perms = access::channel_perms(state, &member_access, channel, &user.id).await?;
    Ok(Some(Recipient { member, perms }))
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
    /// Share format: 1 or 2.
    pub v: i64,
    /// Format 2: the share's key sealed to the requesting device (base64url); null for format 1.
    #[serde(rename = "box")]
    #[schema(rename = "box")]
    pub sealed_box: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryShareList {
    pub items: Vec<HistoryShare>,
}

/// Unacknowledged shares addressed to the requester (oldest first, at most 100): every format 1 share and the format 2
/// shares with a box for the requesting device, with only that box.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/history-keys", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = HistoryShareList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_shares(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<HistoryShareList>, ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    let rows =
        store::history::shares_for(&state.db, &conv.id, &auth.user.address(), auth.public_device_id(), 100).await?;
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
                v: r.version,
                sealed_box: r.sealed,
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
    /// Start of the automatic window: the membership's `joined_at`, after a key reset its `key_reset_at`.
    pub since: String,
    /// After a key reset of the member (ENCRYPTION.md §7b "History after a key reset"): the reset time; null otherwise.
    pub key_reset_at: Option<String>,
    /// After a key reset: the lowest epoch an automatic share may carry (reset epoch + 1); null without a
    /// pre-reset range.
    pub min_epoch: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryPendingList {
    pub items: Vec<HistoryPendingMember>,
}

/// Members of the channel who still wait for history keys (at most 100, the last 30 days): also under `since_join`,
/// for the messages posted between a member's join and its device's first leaf. Empty for DMs, group DMs and
/// plaintext channels.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/history-pending", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = HistoryPendingList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_pending(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<HistoryPendingList>, ApiError> {
    let conv = entitled(&state, &auth, &conversation_id).await?;
    let ConvKind::Channel { access, .. } = &conv.kind else {
        return Ok(Json(HistoryPendingList { items: vec![] }));
    };
    if !conv.encrypted {
        return Ok(Json(HistoryPendingList { items: vec![] }));
    }
    let newer_than = util::format_time(Utc::now() - Duration::days(history::MAX_AGE_DAYS));
    let rows = store::history::pending_members(&state.db, &conv.id, &access.room.id, &newer_than).await?;
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        let min_epoch = match r.key_reset_at {
            Some(_) => history::min_epoch(&state, &conv.id, &r.user_id).await?,
            None => None,
        };
        items.push(HistoryPendingMember {
            user: format!("{}@{}", r.username, r.domain),
            since: r.member_since,
            key_reset_at: r.key_reset_at,
            min_epoch,
        });
    }
    Ok(Json(HistoryPendingList { items }))
}
