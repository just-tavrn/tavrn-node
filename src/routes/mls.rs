// SPDX-License-Identifier: AGPL-3.0-only
//! MLS delivery service (ENCRYPTION.md §4.4, §4.5): group creation, GroupInfo, commits with the
//! node's authorization rules, the handshake log and Welcomes.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tavrn_crypto::{CryptoError, ds::DsGroup, util::b64url_encode};
use utoipa::ToSchema;

use crate::{
    access::{self, Conv},
    app::AppState,
    auth::AuthUser,
    e2ee,
    error::{ApiError, ApiJson, ProblemDetails},
    permissions as p, store,
    validate::{self, bad},
};

/// Maximum decoded size of a commit, GroupInfo or Welcome (about 2000 devices per group).
pub const MAX_MLS_BYTES: usize = 1024 * 1024;
/// Body limit of the MLS routes (three fields as base64url plus JSON).
pub const MLS_BODY_LIMIT: usize = 5 * 1024 * 1024;

fn forbidden(detail: impl Into<String>) -> ApiError {
    ApiError::Forbidden { code: "mls.forbidden", detail: detail.into() }
}

fn invalid(e: &CryptoError) -> ApiError {
    // Crypto error messages are static and contain no secrets.
    bad("mls.invalid", format!("Invalid MLS message: {e}"))
}

fn no_group() -> ApiError {
    ApiError::NotFound { code: "mls.no_group", what: "MLS group".into() }
}

fn epoch_conflict(current: i64) -> ApiError {
    ApiError::Conflict {
        code: "mls.epoch_conflict",
        detail: "Another commit has already taken this epoch".into(),
        meta: json!({ "epoch": current }),
    }
}

/// Resolves the conversation for the delivery service: the requester must be entitled (§4.5).
async fn entitled_conv(state: &AppState, auth: &AuthUser, conversation_id: &str) -> Result<Conv, ApiError> {
    let conv = access::conversation(state, conversation_id, &auth.user).await?;
    // Bots are never entitled in a "no bots" channel (APPLICATIONS.md §3.5): no group info, no external join.
    if auth.user.is_bot()
        && let access::ConvKind::Channel { channel, .. } = &conv.kind
        && channel.no_bots()
    {
        return Err(forbidden("Bots are not allowed in this channel"));
    }
    conv.require_entitled()?;
    Ok(conv)
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    /// GroupInfo (MLSMessage) of epoch 0 with ratchet tree and external public key, base64url.
    pub group_info: String,
}

#[derive(Serialize, ToSchema)]
pub struct EpochResponse {
    pub epoch: i64,
}

/// Create the conversation's MLS group (first wins). The GroupInfo must be for epoch 0 and
/// contain exactly the uploader's attested device.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/mls/group", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = CreateGroupRequest,
    responses((status = 201, body = EpochResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<CreateGroupRequest>,
) -> Result<(StatusCode, Json<EpochResponse>), ApiError> {
    let conv = entitled_conv(&state, &auth, &conversation_id).await?;
    // Files channels have no messages: whoever may upload creates their group (FILES.md §8.1).
    if matches!(&conv.kind, access::ConvKind::Channel { channel, .. } if channel.kind == "files") {
        conv.require(p::ATTACH_FILES, "files.upload_forbidden", "attach files")?;
    } else {
        conv.require(p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
    }
    if !conv.encrypted {
        return Err(bad("mls.not_encrypted", "This conversation is not end-to-end encrypted"));
    }
    let device_key = e2ee::attested_session_key(&state, &auth).await?;
    let exists = || ApiError::conflict("mls.group_exists", "This conversation already has a group");
    // Cheap check first; the unique key below decides races.
    if store::e2ee::group_epoch(&state.db, &conv.id).await?.is_some() {
        return Err(exists());
    }
    let gi = e2ee::decode("group_info", &req.group_info, MAX_MLS_BYTES, "mls.too_large")?;
    let ds = DsGroup::create(&e2ee::qualified(&state, &conv.id), &gi).map_err(|e| invalid(&e))?;
    if ds.epoch() != 0 {
        return Err(bad("mls.invalid", "A new group starts at epoch 0"));
    }
    let roster = ds.roster().map_err(|e| invalid(&e))?;
    let me = e2ee::device_identity(&auth.user, auth.public_device_id());
    if roster.len() != 1 || roster[0].identity != me || roster[0].signature_key != device_key {
        return Err(forbidden("The group must contain exactly this device"));
    }
    let ds_state = ds.export_state().map_err(|e| ApiError::Internal(anyhow::anyhow!("DS state: {e}")))?;
    if !store::e2ee::create_group(&state.db, &conv.id, &gi, &ds_state).await? {
        return Err(exists());
    }
    conv.publish(&state.hub, "mls.commit", json!({ "conversation_id": conv.id, "epoch": 0 }));
    crate::bot_channels::after_group_created(&state, &conv, &auth.user).await;
    Ok((StatusCode::CREATED, Json(EpochResponse { epoch: 0 })))
}

#[derive(Serialize, ToSchema)]
pub struct GroupInfoResponse {
    pub epoch: i64,
    /// Latest GroupInfo (MLSMessage), base64url.
    pub group_info: String,
}

/// Latest GroupInfo for joining by external commit.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/mls/group-info", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = GroupInfoResponse), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn group_info(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<GroupInfoResponse>, ApiError> {
    let conv = entitled_conv(&state, &auth, &conversation_id).await?;
    let group = store::e2ee::group(&state.db, &conv.id).await?.ok_or_else(no_group)?;
    Ok(Json(GroupInfoResponse { epoch: group.epoch, group_info: b64url_encode(&group.group_info) }))
}

#[derive(Deserialize, ToSchema)]
pub struct CommitRequest {
    /// Current epoch of the group (the epoch the commit was created in).
    pub epoch: i64,
    /// Commit as PublicMessage (MLSMessage), base64url.
    pub commit: String,
    /// GroupInfo of the resulting epoch, base64url.
    pub group_info: String,
    /// Welcome for added devices, base64url; required when the commit adds devices.
    pub welcome: Option<String>,
}

/// Submit a commit (§4.4). The first commit for an epoch wins; the node validates it and applies
/// the authorization rules of §4.5.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/mls/commits", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = CommitRequest,
    responses((status = 201, body = EpochResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn post_commit(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<CommitRequest>,
) -> Result<(StatusCode, Json<EpochResponse>), ApiError> {
    let conv = entitled_conv(&state, &auth, &conversation_id).await?;
    state.commit_limiter.check_all(&[format!("commit:{}", auth.device_id)])?;
    let device_key = e2ee::attested_session_key(&state, &auth).await?;
    let commit = e2ee::decode("commit", &req.commit, MAX_MLS_BYTES, "mls.too_large")?;
    let gi = e2ee::decode("group_info", &req.group_info, MAX_MLS_BYTES, "mls.too_large")?;
    let welcome =
        req.welcome.as_deref().map(|w| e2ee::decode("welcome", w, MAX_MLS_BYTES, "mls.too_large")).transpose()?;

    let group = store::e2ee::group(&state.db, &conv.id).await?.ok_or_else(no_group)?;
    if req.epoch != group.epoch {
        return Err(epoch_conflict(group.epoch));
    }
    let mut ds = DsGroup::import_state(&group.ds_state)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("DS state unreadable: {e}")))?;
    let roster_before = ds.roster().map_err(|e| ApiError::Internal(anyhow::anyhow!("DS roster unreadable: {e}")))?;
    let summary = match ds.process_commit(&commit, &gi) {
        Ok(s) => s,
        Err(CryptoError::StaleEpoch | CryptoError::FutureEpoch) => return Err(epoch_conflict(group.epoch)),
        Err(e) => return Err(invalid(&e)),
    };
    let welcome_devices = authorize(&state, &conv, &auth, &device_key, &summary, &roster_before).await?;
    match (&welcome, welcome_devices.is_empty()) {
        (None, false) => return Err(bad("mls.welcome_missing", "A commit adding devices needs a Welcome")),
        (Some(_), true) => return Err(bad("mls.invalid", "Welcome without new devices")),
        _ => {}
    }
    let ds_state = ds.export_state().map_err(|e| ApiError::Internal(anyhow::anyhow!("DS state: {e}")))?;
    let accepted = store::e2ee::apply_commit(
        &state.db,
        store::e2ee::AcceptedCommit {
            conversation_id: &conv.id,
            epoch: group.epoch,
            commit: &commit,
            group_info: &gi,
            ds_state: &ds_state,
            committer_device_id: &auth.device_id,
            welcome_devices: &welcome_devices,
            welcome: welcome.as_deref(),
        },
    )
    .await?;
    if !accepted {
        let current = store::e2ee::group_epoch(&state.db, &conv.id).await?.unwrap_or(group.epoch);
        return Err(epoch_conflict(current));
    }
    // Removed leaves are no longer pending (ENCRYPTION.md §4.7).
    if !summary.removed.is_empty()
        && let Err(e) = store::pending_removals::clear(&state.db, &conv.id, &summary.removed).await
    {
        tracing::warn!(error = %e, conversation = conv.id, "pending MLS removals not cleared");
    }
    let new_epoch = group.epoch + 1;
    conv.publish(&state.hub, "mls.commit", json!({ "conversation_id": conv.id, "epoch": new_epoch }));
    if !welcome_devices.is_empty() {
        state.hub.devices(welcome_devices, "mls.welcome", json!({ "conversation_id": conv.id, "epoch": new_epoch }));
    }
    // New members of a channel whose policy gives them history wait for keys (ENCRYPTION.md §7b).
    crate::history::after_commit(&state, &conv, &auth.user, &summary, &group.ds_state).await;
    // Bots joining or leaving an encrypted channel's group go to the room's security log.
    if let Ok(roster) = ds.roster() {
        crate::bot_channels::after_commit(&state, &conv, &auth.user, &summary, &group.ds_state, &roster).await;
    }
    Ok((StatusCode::CREATED, Json(EpochResponse { epoch: new_epoch })))
}

/// Authorization rules of §4.5 on a validated commit. Returns the local device ids that were
/// added (Welcome recipients).
async fn authorize(
    state: &AppState,
    conv: &Conv,
    auth: &AuthUser,
    device_key: &[u8; 32],
    summary: &tavrn_crypto::ds::CommitSummary,
    roster_before: &[tavrn_crypto::RosterEntry],
) -> Result<Vec<String>, ApiError> {
    // Rule 1: the committer is the session's attested device with its attested key (for a remote user:
    // the home device id and the key published by the home node).
    let me = e2ee::device_identity(&auth.user, auth.public_device_id());
    if summary.committer.identity != me || &summary.committer.signature_key != device_key {
        return Err(forbidden("The commit is not from this device"));
    }
    // Rule 2: an external join (entitlement checked by the route) removes at most its own old leaf, and it must
    // remove every leaf that carries its identity or its key: a device is in the group at most once.
    if summary.external_join {
        if !summary.added.is_empty() || summary.removed.iter().any(|r| r != &me) {
            return Err(forbidden("An external join may only replace its own old device"));
        }
        let stale = roster_before.iter().any(|leaf| {
            (leaf.identity == me || leaf.signature_key == summary.committer.signature_key)
                && !summary.removed_leaves.contains(leaf)
        });
        if stale {
            return Err(forbidden("An external join must remove the old leaf of this device"));
        }
    }
    // Rule 3: added devices are attested devices of entitled users.
    let mut added_devices = Vec::new();
    for added in &summary.added {
        let device = resolve_device(state, &added.identity).await?;
        let Some((user, device_id, key)) = device else {
            return Err(forbidden(format!("Unknown or unattested device: {}", added.identity)));
        };
        if key != added.signature_key {
            return Err(forbidden(format!("Key does not match the attested device: {}", added.identity)));
        }
        if !access::user_entitled(state, conv, &user).await? {
            return Err(forbidden(format!("{} does not belong to this conversation", user.address())));
        }
        added_devices.push(device_id);
    }
    // Rule 4: removed leaves belong to the committer's user, to users no longer entitled, or to
    // deleted / unattested devices, or carry a key other than the attested key of the device they name.
    for removed in &summary.removed_leaves {
        let Some((address, _)) = removed.identity.split_once('/') else { continue };
        if address == auth.user.address() {
            continue;
        }
        if let Some((user, _, key)) = resolve_device(state, &removed.identity).await?
            && key == removed.signature_key
            && access::user_entitled(state, conv, &user).await?
        {
            return Err(forbidden(format!(
                "{} is an attested device of an entitled member; the node governs membership",
                removed.identity
            )));
        }
    }
    // Rule 5: a self update needs nothing beyond rule 1.
    Ok(added_devices)
}

/// Resolves a device identity to (user, local device row id, attested key). `None` for unknown users or
/// devices and devices not attested under the current identity key. Devices of remote users are looked up
/// in the key cache (refetched from the home node on a miss, FEDERATION.md §3.6); remote users this node
/// has never seen are unknown.
async fn resolve_device(
    state: &AppState,
    identity: &str,
) -> Result<Option<(crate::models::UserRow, String, [u8; 32])>, ApiError> {
    let Some((address, device_id)) = tavrn_crypto::util::parse_device_identity(identity) else { return Ok(None) };
    let Some((username, domain)) = crate::util::parse_address(address) else { return Ok(None) };
    let Some(user) = store::federation::user_by_address(&state.db, username, domain).await? else {
        return Ok(None);
    };
    if domain != state.config.domain {
        let found = crate::federation::keys::remote_device_key(state, &user, device_id).await?;
        return Ok(found.map(|(row_id, key)| (user, row_id, key)));
    }
    let row = store::e2ee::device_key(&state.db, device_id).await?;
    Ok(e2ee::attested_key_of(row.as_ref(), &user.id).map(|key| (user, device_id.to_string(), key)))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct LogQuery {
    /// First epoch to return (default 0).
    pub since_epoch: Option<i64>,
    /// At most 100 (default 100).
    pub limit: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct LogEntry {
    /// Epoch the commit was created in.
    pub epoch: i64,
    /// Commit (MLSMessage), base64url.
    pub commit: String,
}

#[derive(Serialize, ToSchema)]
pub struct LogPage {
    pub items: Vec<LogEntry>,
    /// `since_epoch` of the next page, or null.
    pub next: Option<i64>,
}

/// Handshake log in ascending epoch order.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/mls/messages", security(("bearer" = [])), params(("conversation_id" = String, Path), LogQuery),
    responses((status = 200, body = LogPage), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn log(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    Query(q): Query<LogQuery>,
) -> Result<Json<LogPage>, ApiError> {
    let conv = entitled_conv(&state, &auth, &conversation_id).await?;
    let limit = validate::limit(q.limit, 100, 100);
    let since = q.since_epoch.unwrap_or(0).max(0);
    let rows = store::e2ee::commits(&state.db, &conv.id, since, limit).await?;
    let next = (rows.len() as i64 == limit).then(|| rows.last().map(|(e, _)| e + 1)).flatten();
    Ok(Json(LogPage {
        items: rows.into_iter().map(|(epoch, c)| LogEntry { epoch, commit: b64url_encode(&c) }).collect(),
        next,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct WelcomeItem {
    pub id: String,
    pub conversation_id: String,
    /// Epoch the Welcome leads into.
    pub epoch: i64,
    /// Welcome (MLSMessage), base64url.
    pub welcome: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct WelcomeList {
    pub items: Vec<WelcomeItem>,
}

/// Pending Welcomes for the session's device.
#[utoipa::path(get, path = "/api/v1/mls/welcomes", security(("bearer" = [])), responses((status = 200, body = WelcomeList)))]
pub async fn welcomes(State(state): State<AppState>, auth: AuthUser) -> Result<Json<WelcomeList>, ApiError> {
    let rows = store::e2ee::welcomes_for(&state.db, &auth.device_id).await?;
    Ok(Json(WelcomeList {
        items: rows
            .into_iter()
            .map(|w| WelcomeItem {
                id: w.id,
                conversation_id: w.conversation_id,
                epoch: w.epoch,
                welcome: b64url_encode(&w.welcome),
                created_at: w.created_at,
            })
            .collect(),
    }))
}

/// Delete a processed Welcome of the session's device.
#[utoipa::path(delete, path = "/api/v1/mls/welcomes/{welcome_id}", security(("bearer" = [])), params(("welcome_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_welcome(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(welcome_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if store::e2ee::delete_welcome(&state.db, &auth.device_id, &welcome_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound { code: "mls.welcome_not_found", what: "Welcome".into() })
    }
}

#[derive(Serialize, ToSchema)]
pub struct PendingRemoval {
    /// Conversation (bare ULID) of the group with the leaf.
    pub conversation_id: String,
    /// Leaf identity `<user address>/<device id>`.
    pub identity: String,
    /// `deleted` (the device was deleted), `unattested` (not attested under the current identity key) or
    /// `not_member` (the user is no longer entitled).
    pub reason: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct PendingRemovalList {
    pub items: Vec<PendingRemoval>,
}

fn pending_items(rows: Vec<store::pending_removals::PendingRemoval>) -> PendingRemovalList {
    PendingRemovalList {
        items: rows
            .into_iter()
            .map(|r| PendingRemoval {
                conversation_id: r.conversation_id,
                identity: r.identity,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    }
}

/// Leaves of the conversation's group that must be removed (ENCRYPTION.md §4.7): for members, so that a device
/// that was offline when `mls.remove_needed` went out still cleans up. Only leaves still in the group are listed.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/mls/pending-removals", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = PendingRemovalList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn pending_removals(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<PendingRemovalList>, ApiError> {
    let conv = entitled_conv(&state, &auth, &conversation_id).await?;
    let rows = store::pending_removals::of_conversation(&state.db, &conv.id).await?;
    if rows.is_empty() {
        return Ok(Json(PendingRemovalList { items: vec![] }));
    }
    let roster: std::collections::HashSet<String> = match store::e2ee::group(&state.db, &conv.id).await? {
        Some(g) => DsGroup::import_state(&g.ds_state)
            .and_then(|ds| ds.roster())
            .map(|r| r.into_iter().map(|e| e.identity).collect())
            .unwrap_or_default(),
        None => Default::default(),
    };
    // Leaves that left the group otherwise (external rejoin, a commit before this table existed) are done.
    let (live, gone): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| roster.contains(&r.identity));
    if !gone.is_empty() {
        let ids: Vec<String> = gone.into_iter().map(|r| r.identity).collect();
        store::pending_removals::clear(&state.db, &conv.id, &ids).await?;
    }
    Ok(Json(pending_items(live)))
}

/// Pending removals of the caller's own leaves on this node, in every conversation (ENCRYPTION.md §4.7): any device
/// of the user may remove them (own-user rule of §4.5), e.g. right after connecting.
#[utoipa::path(get, path = "/api/v1/mls/pending-removals", security(("bearer" = [])),
    responses((status = 200, body = PendingRemovalList)))]
pub async fn own_pending_removals(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<PendingRemovalList>, ApiError> {
    let rows = store::pending_removals::of_address(&state.db, &auth.user.address()).await?;
    Ok(Json(pending_items(rows)))
}
