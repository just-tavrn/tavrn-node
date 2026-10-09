// SPDX-License-Identifier: AGPL-3.0-only
//! History restore after a key reset (ENCRYPTION.md §7b "History after a key reset"): a member whose key was reset
//! asks for its history from before the reset; a member with `restore_history` approves (and then shares the keys
//! from its own device) or denies. Every step is in the audit log, the decision also in the welcome channel.

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
    access::{self, RoomAccess},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    history::{self, Policy},
    models::{MemberRow, UserRow},
    permissions as p,
    store::{self, history::RequestRow},
    util, validate,
};

fn forbidden(detail: &str) -> ApiError {
    ApiError::Forbidden { code: "history.forbidden", detail: detail.into() }
}

fn disabled() -> ApiError {
    ApiError::Forbidden { code: "history.restore_disabled", detail: "This room does not take restore requests".into() }
}

fn not_found() -> ApiError {
    access::not_found("History request", "history.request_not_found")
}

fn nothing_to_restore() -> ApiError {
    ApiError::conflict("history.nothing_to_restore", "There is no key reset without a restore for this membership")
}

#[derive(Serialize, ToSchema)]
pub struct HistoryRequestChannel {
    pub channel_id: String,
    /// The channel's kind (`text`, `announcement`, `forum`, `files`).
    pub kind: String,
    /// The requester's normal window start in this channel (policy and `read_history` from `joined_at`); null =
    /// everything.
    pub window_start: Option<String>,
    /// The group epoch at the requester's key reset; keys up to it are the pre-reset range. Null: no group then.
    pub reset_epoch: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryRequest {
    pub id: String,
    pub room_id: String,
    /// Requester address.
    pub user: String,
    pub display_name: String,
    pub message: String,
    /// `open`, `approved`, `denied` or `cancelled`.
    pub status: String,
    /// The requester's membership start.
    pub joined_at: String,
    /// The requester's current key reset (null once the membership ended or nothing is reset).
    pub key_reset_at: Option<String>,
    pub created_at: String,
    pub decided_at: Option<String>,
    /// Address of the member who decided.
    pub decided_by: Option<String>,
    /// Reason of a denial.
    pub reason: Option<String>,
    /// The approving device did not hold every key of the window.
    pub partial: bool,
    /// For members with `restore_history`: the encrypted channels the requester may view (else empty).
    pub channels: Vec<HistoryRequestChannel>,
}

#[derive(Serialize, ToSchema)]
pub struct HistoryRequestList {
    pub items: Vec<HistoryRequest>,
}

#[derive(Serialize, ToSchema)]
pub struct MyHistoryState {
    /// The membership's key reset (null: none).
    pub key_reset_at: Option<String>,
    /// When a restore of the membership was approved (null: none).
    pub restored_at: Option<String>,
    /// The latest request of the current membership.
    pub request: Option<HistoryRequest>,
}

fn base(row: RequestRow, user: Option<&UserRow>, member: Option<&MemberRow>) -> HistoryRequest {
    HistoryRequest {
        id: row.id,
        room_id: row.room_id,
        user: user.map(UserRow::address).unwrap_or_default(),
        display_name: user.map(|u| u.display_name.clone()).unwrap_or_default(),
        message: row.message,
        status: row.status,
        joined_at: row.member_since,
        key_reset_at: member.and_then(|m| m.key_reset_at.clone()),
        created_at: row.created_at,
        decided_at: row.decided_at,
        decided_by: row.decided_by,
        reason: row.reason,
        partial: row.partial != 0,
        channels: Vec::new(),
    }
}

/// The request as the API shows it; with `channels` the encrypted channels the requester may view.
async fn view(state: &AppState, row: RequestRow, with_channels: bool) -> Result<HistoryRequest, ApiError> {
    let user = store::users::by_id(&state.db, &row.user_id).await?;
    let member = store::rooms::member(&state.db, &row.room_id, &row.user_id).await?;
    let room_id = row.room_id.clone();
    let mut out = base(row, user.as_ref(), member.as_ref());
    if let (true, Some(user), Some(member)) = (with_channels, &user, &member) {
        out.channels = channels_of(state, &room_id, user, member).await?;
    }
    Ok(out)
}

async fn channels_of(
    state: &AppState,
    room_id: &str,
    user: &UserRow,
    member: &MemberRow,
) -> Result<Vec<HistoryRequestChannel>, ApiError> {
    let access = match access::room_access(state, room_id, user).await {
        Ok(a) => a,
        Err(ApiError::Forbidden { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let joined = util::parse_time(&member.joined_at);
    let mut out = Vec::new();
    for channel in store::rooms::channels(&state.db, room_id).await? {
        if channel.encrypted == 0 || !history::restorable_kind(&channel.kind) {
            continue;
        }
        let perms = access::channel_perms(state, &access, &channel, &user.id).await?;
        if !p::has(perms, p::VIEW_CHANNEL) {
            continue;
        }
        let policy = Policy::of(channel.history_for_new_members.as_deref());
        let window_start =
            joined.and_then(|j| history::cutoff(policy, p::has(perms, p::READ_HISTORY), j)).map(util::format_time);
        let reset_epoch = store::history::reset_epoch(&state.db, &channel.id, &user.id).await?;
        out.push(HistoryRequestChannel { channel_id: channel.id, kind: channel.kind, window_start, reset_epoch });
    }
    Ok(out)
}

/// Members with `restore_history` for the request events; never bots.
async fn restorers(state: &AppState, room_id: &str, skip: &str) -> Result<Vec<String>, ApiError> {
    let mut ids = store::history::restorer_ids(&state.db, room_id).await?;
    ids.retain(|id| id != skip);
    Ok(ids)
}

fn require_restorer(access: &RoomAccess) -> Result<(), ApiError> {
    if access.member.is_none() || !access.has(p::RESTORE_HISTORY) {
        return Err(forbidden("Missing permission: Restore history"));
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct CreateHistoryRequest {
    /// A note for the moderators (at most 500 characters).
    #[serde(default)]
    pub message: Option<String>,
}

/// Ask for the history from before the own key reset.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/history-requests", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = CreateHistoryRequest,
    summary = "Ask to restore the history after a key reset",
    description = "A member whose security key was reset asks the members with `restore_history` to restore its encrypted history from before the reset (ENCRYPTION.md §7b). One open request per room; at most 5 per day. The owner and the members with `restore_history` get `history.request`.",
    responses((status = 201, body = HistoryRequest), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<CreateHistoryRequest>,
) -> Result<(StatusCode, Json<HistoryRequest>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if auth.user.is_bot() {
        return Err(forbidden("Bots cannot ask for a restore"));
    }
    let Some(member) = access.member.as_ref() else { return Err(forbidden("Only members can ask")) };
    let message = validate::text("message", req.message.as_deref().unwrap_or(""), 0, history::MAX_REQUEST_TEXT)?;
    if member.key_reset_at.is_none() || member.history_restored_at.is_some() {
        return Err(nothing_to_restore());
    }
    if access.room.history_restore != "request" {
        return Err(disabled());
    }
    if store::history::has_open_request(&state.db, &room_id, &auth.user.id).await? {
        return Err(open_conflict());
    }
    let since = util::format_time(Utc::now() - Duration::hours(24));
    if store::history::count_requests_since(&state.db, &room_id, &auth.user.id, &since).await?
        >= history::REQUESTS_PER_DAY
    {
        return Err(ApiError::RateLimited { retry_after_secs: 3600 });
    }
    let row = store::history::insert_request(&state.db, &room_id, &auth.user.id, &member.joined_at, &message)
        .await?
        .ok_or_else(open_conflict)?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "history.restore_requested",
        &auth.user.address(),
        "",
        json!({ "request_id": row.id }),
    )
    .await?;
    let created = view(&state, row.clone(), false).await?;
    let detailed = view(&state, row, true).await?;
    let to = restorers(&state, &room_id, &auth.user.id).await?;
    state.hub.users(to, "history.request", json!({ "room_id": room_id, "request": detailed }));
    Ok((StatusCode::CREATED, Json(created)))
}

fn open_conflict() -> ApiError {
    ApiError::conflict("history.request_open", "There is an open request already")
}

/// The requester's own state: its key reset, an approved restore and the latest request.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/history-requests/mine", security(("bearer" = [])), params(("room_id" = String, Path)),
    summary = "Own history restore state",
    description = "The requester's key reset in this room, an approved restore and its latest request of the current membership (ENCRYPTION.md §7b).",
    responses((status = 200, body = MyHistoryState), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn mine(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<MyHistoryState>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let Some(member) = access.member.as_ref() else {
        return Ok(Json(MyHistoryState { key_reset_at: None, restored_at: None, request: None }));
    };
    let request = match store::history::latest_request(&state.db, &room_id, &auth.user.id, &member.joined_at).await? {
        Some(row) => Some(base(row, Some(&auth.user), Some(member))),
        None => None,
    };
    Ok(Json(MyHistoryState {
        key_reset_at: member.key_reset_at.clone(),
        restored_at: member.history_restored_at.clone(),
        request,
    }))
}

/// The requester cancels its open request.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/history-requests/{request_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("request_id" = String, Path)),
    summary = "Cancel an own history restore request",
    description = "The requester withdraws its open request (ENCRYPTION.md §7b).",
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn cancel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, request_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    access::room_access(&state, &room_id, &auth.user).await?;
    if !store::history::cancel(&state.db, &room_id, &auth.user.id, &request_id).await? {
        return Err(not_found());
    }
    let to = restorers(&state, &room_id, &auth.user.id).await?;
    if let Some(row) = store::history::request(&state.db, &room_id, &request_id).await? {
        let request = view(&state, row, false).await?;
        state.hub.users(to, "history.request_decided", json!({ "room_id": room_id, "request": request }));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The open requests of the room, for members with `restore_history`.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/history-requests", security(("bearer" = [])), params(("room_id" = String, Path)),
    summary = "Open history restore requests",
    description = "The open requests to restore a member's history after a key reset, oldest first (at most 100), each with the encrypted channels the requester may view and its window there (ENCRYPTION.md §7b). Needs `restore_history`.",
    responses((status = 200, body = HistoryRequestList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<HistoryRequestList>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    require_restorer(&access)?;
    let mut items = Vec::new();
    for row in store::history::open_requests(&state.db, &room_id).await? {
        items.push(view(&state, row, true).await?);
    }
    Ok(Json(HistoryRequestList { items }))
}

#[derive(Deserialize, ToSchema)]
pub struct ApproveHistoryRequest {
    /// The approving device does not hold every key of the requester's window.
    #[serde(default)]
    pub partial: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct DenyHistoryRequest {
    /// Why (1–500 characters); in the audit log and shown to the requester.
    pub reason: Option<String>,
}

/// An open request, its requester (still a member) and the requester's membership.
async fn open_request(
    state: &AppState,
    access: &RoomAccess,
    auth: &AuthUser,
    room_id: &str,
    request_id: &str,
) -> Result<(RequestRow, UserRow, MemberRow), ApiError> {
    require_restorer(access)?;
    let row = store::history::request(&state.db, room_id, request_id).await?.ok_or_else(not_found)?;
    if row.status != "open" {
        return Err(ApiError::conflict("history.request_decided", "The request was decided or cancelled"));
    }
    if row.user_id == auth.user.id {
        return Err(forbidden("Nobody decides their own request"));
    }
    let user = store::users::by_id(&state.db, &row.user_id).await?.ok_or_else(not_found)?;
    let member = store::rooms::member(&state.db, room_id, &row.user_id)
        .await?
        .filter(|m| m.joined_at == row.member_since && m.key_reset_at.is_some() && m.history_restored_at.is_none())
        .ok_or_else(nothing_to_restore)?;
    Ok((row, user, member))
}

async fn decided(
    state: &AppState,
    room_id: &str,
    request_id: &str,
    requester: &str,
) -> Result<HistoryRequest, ApiError> {
    let row = store::history::request(&state.db, room_id, request_id).await?.ok_or_else(not_found)?;
    let request = view(state, row, false).await?;
    let mut to = restorers(state, room_id, requester).await?;
    to.push(requester.to_string());
    state.hub.users(to, "history.request_decided", json!({ "room_id": room_id, "request": request }));
    Ok(request)
}

/// Approve a request: the cut is lifted and restore shares are accepted; the approving client then shares the keys.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/history-requests/{request_id}/approve", security(("bearer" = [])), params(("room_id" = String, Path), ("request_id" = String, Path)), request_body = ApproveHistoryRequest,
    summary = "Approve a history restore request",
    description = "A member with `restore_history` approves another member's request (ENCRYPTION.md §7b): the requester's history window is the normal one again and restore shares (keys from before the reset) from members with `restore_history` are accepted for 30 days. Audit `history.restore_approved`, welcome channel `system.history_restored`, event `history.request_decided`. The approving client then sends the keys from its device.",
    responses((status = 200, body = HistoryRequest), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn approve(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, request_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<ApproveHistoryRequest>,
) -> Result<Json<HistoryRequest>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let (row, user, _) = open_request(&state, &access, &auth, &room_id, &request_id).await?;
    if access.room.history_restore != "request" {
        return Err(disabled());
    }
    let by = auth.user.address();
    if !store::history::decide(&state.db, &row.id, "approved", &by, None, req.partial).await? {
        return Err(ApiError::conflict("history.request_decided", "The request was decided or cancelled"));
    }
    store::history::set_restored(&state.db, &room_id, &user.id, &util::now()).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "history.restore_approved",
        &user.address(),
        "",
        json!({ "user": user.address(), "by": by }),
    )
    .await?;
    crate::welcome::history_restore_decided(&state, &access.room, &user, true, &by).await;
    Ok(Json(decided(&state, &room_id, &row.id, &user.id).await?))
}

/// Deny a request with a reason.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/history-requests/{request_id}/deny", security(("bearer" = [])), params(("room_id" = String, Path), ("request_id" = String, Path)), request_body = DenyHistoryRequest,
    summary = "Deny a history restore request",
    description = "A member with `restore_history` denies another member's request with a reason (ENCRYPTION.md §7b). Audit `history.restore_denied` with the reason, welcome channel `system.history_restore_denied` without it, event `history.request_decided`.",
    responses((status = 200, body = HistoryRequest), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn deny(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, request_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<DenyHistoryRequest>,
) -> Result<Json<HistoryRequest>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let reason = validate::text("reason", req.reason.as_deref().unwrap_or(""), 1, history::MAX_REQUEST_TEXT)?;
    let (row, user, _) = open_request(&state, &access, &auth, &room_id, &request_id).await?;
    let by = auth.user.address();
    if !store::history::decide(&state.db, &row.id, "denied", &by, Some(&reason), false).await? {
        return Err(ApiError::conflict("history.request_decided", "The request was decided or cancelled"));
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "history.restore_denied",
        &user.address(),
        &reason,
        json!({ "user": user.address(), "by": by, "reason": reason }),
    )
    .await?;
    crate::welcome::history_restore_decided(&state, &access.room, &user, false, &by).await;
    Ok(Json(decided(&state, &room_id, &row.id, &user.id).await?))
}
