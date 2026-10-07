// SPDX-License-Identifier: AGPL-3.0-only
//! Friends and blocks. Friends of other nodes (FEDERATION.md §6.2): requests, accepts and removals are
//! mirrored to the other user's home node (`friend.request` / `friend.accept` / `friend.remove`); both
//! home nodes store their local user's side with the other user as a stub.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    federation::{remote, social},
    models::{User, UserRow},
    store,
    validate::bad,
};

/// Pending outgoing requests per user.
pub const MAX_OUTGOING_REQUESTS: i64 = 100;

#[derive(Serialize, ToSchema)]
pub struct Friend {
    pub user: User,
    pub since: String,
}

#[derive(Serialize, ToSchema)]
pub struct FriendRequest {
    pub id: String,
    /// The other party.
    pub user: User,
    /// incoming | outgoing
    pub direction: String,
    pub created_at: String,
    /// The requester's optional message (≤ 256 characters), e.g. "it's Daniel from school".
    pub message: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct FriendList {
    pub friends: Vec<Friend>,
    pub incoming: Vec<FriendRequest>,
    pub outgoing: Vec<FriendRequest>,
    pub blocked: Vec<User>,
}

#[derive(Deserialize, ToSchema)]
pub struct UserRef {
    /// `username` (this node) or `username@domain` (any node).
    pub user: String,
}

/// Maximum length of a friend request message and of a block reason.
pub const NOTE_MAX_CHARS: usize = 256;

#[derive(Deserialize, ToSchema)]
pub struct FriendRequestBody {
    /// `username` (this node) or `username@domain` (any node).
    pub user: String,
    /// Optional message shown with the request (≤ 256 characters).
    pub message: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct BlockRequest {
    /// `username` (this node) or `username@domain` (any node).
    pub user: String,
    /// Private note, only shown to the blocking user (≤ 256 characters).
    pub reason: Option<String>,
}

/// A user I blocked, with my private note.
#[derive(Serialize, ToSchema)]
pub struct BlockedUser {
    pub user: User,
    pub reason: String,
    pub created_at: String,
}

/// An optional note (friend request message, block reason): trimmed, empty = none.
fn note(field: &str, v: Option<&str>) -> Result<Option<String>, ApiError> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => crate::validate::text(field, s, 1, NOTE_MAX_CHARS).map(Some),
    }
}

#[derive(Serialize, ToSchema)]
pub struct FriendRequestResult {
    /// pending | accepted (the other user had already asked)
    pub status: String,
    pub user: User,
    pub request_id: Option<String>,
}

/// Resolves a user reference of any node (remote users become stubs, FEDERATION.md §2.6).
async fn target(state: &AppState, me: &UserRow, reference: &str) -> Result<UserRow, ApiError> {
    let user = remote::resolve_or_stub(state, reference).await?;
    if user.id == me.id {
        return Err(bad("friend.self", "That is you"));
    }
    Ok(user)
}

pub fn request_view(row: &store::social::FriendRequestRow, me: &str, other: &UserRow) -> FriendRequest {
    FriendRequest {
        id: row.id.clone(),
        user: other.to_public(),
        direction: if row.to_user_id == me { "incoming" } else { "outgoing" }.into(),
        created_at: row.created_at.clone(),
        message: row.message.clone(),
    }
}

/// Friends, pending requests and blocked users.
#[utoipa::path(get, path = "/api/v1/users/me/friends", security(("bearer" = [])), responses((status = 200, body = FriendList)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<FriendList>, ApiError> {
    let me = &auth.user.id;
    let mut friends = Vec::new();
    for (id, since) in store::social::friends_of(&state.db, me).await? {
        if let Some(u) = store::users::by_id(&state.db, &id).await? {
            friends.push(Friend { user: u.to_public(), since });
        }
    }
    let (mut incoming, mut outgoing) = (Vec::new(), Vec::new());
    for r in store::social::requests_of(&state.db, me).await? {
        let other_id = if &r.to_user_id == me { &r.from_user_id } else { &r.to_user_id };
        if let Some(other) = store::users::by_id(&state.db, other_id).await? {
            let view = request_view(&r, me, &other);
            if view.direction == "incoming" { incoming.push(view) } else { outgoing.push(view) }
        }
    }
    let blocked_ids = store::social::blocked_by(&state.db, me).await?;
    let blocked = store::users::by_ids(&state.db, &blocked_ids).await?.iter().map(UserRow::to_public).collect();
    Ok(Json(FriendList { friends, incoming, outgoing, blocked }))
}

fn accept_events(state: &AppState, a: &UserRow, b: &UserRow, since: &str) {
    state.hub.users(vec![a.id.clone()], "friend.accept", json!({ "user": b.to_public(), "since": since }));
    state.hub.users(vec![b.id.clone()], "friend.accept", json!({ "user": a.to_public(), "since": since }));
}

/// Send a friend request with an optional message (rate-limited). If the other user already asked, both
/// become friends.
#[utoipa::path(post, path = "/api/v1/users/me/friends/requests", security(("bearer" = [])), request_body = FriendRequestBody,
    responses((status = 201, body = FriendRequestResult), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn send_request(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<FriendRequestBody>,
) -> Result<(StatusCode, Json<FriendRequestResult>), ApiError> {
    let message = note("message", req.message.as_deref())?;
    state.friend_limiter.check_all(&[format!("friend:{}", auth.user.id)])?;
    let other = target(&state, &auth.user, &req.user).await?;
    if store::social::blocked_either(&state.db, &auth.user.id, &other.id).await? {
        return Err(ApiError::Forbidden { code: "friend.blocked", detail: "Request not possible".into() });
    }
    if store::social::are_friends(&state.db, &auth.user.id, &other.id).await? {
        return Err(ApiError::conflict("friend.exists", "You are already friends"));
    }
    if let Some(incoming) = store::social::request_between(&state.db, &other.id, &auth.user.id).await? {
        let since = store::social::add_friendship(&state.db, &auth.user.id, &other.id).await?;
        accept_events(&state, &auth.user, &other, &since);
        let reference = incoming.remote_request_id.as_deref().unwrap_or(&incoming.id);
        social::friend(&state, &auth.user, &other, "friend.accept", Some(reference)).await?;
        return Ok((
            StatusCode::CREATED,
            Json(FriendRequestResult { status: "accepted".into(), user: other.to_public(), request_id: None }),
        ));
    }
    if store::social::outgoing_count(&state.db, &auth.user.id).await? >= MAX_OUTGOING_REQUESTS {
        return Err(ApiError::Forbidden {
            code: "friend.request_limit",
            detail: format!("At most {MAX_OUTGOING_REQUESTS} pending requests"),
        });
    }
    let Some(row) = store::social::create_request(&state.db, &auth.user.id, &other.id, message.as_deref()).await?
    else {
        return Err(ApiError::conflict("friend.request_exists", "The request has already been sent"));
    };
    state.hub.users(
        vec![other.id.clone()],
        "friend.request",
        json!({ "request": request_view(&row, &other.id, &auth.user) }),
    );
    state.hub.users(
        vec![auth.user.id.clone()],
        "friend.request",
        json!({ "request": request_view(&row, &auth.user.id, &other) }),
    );
    social::friend_request_to(&state, &auth.user, &other, &row.id, message.as_deref()).await?;
    Ok((
        StatusCode::CREATED,
        Json(FriendRequestResult { status: "pending".into(), user: other.to_public(), request_id: Some(row.id) }),
    ))
}

fn request_not_found() -> ApiError {
    ApiError::NotFound { code: "friend.request_not_found", what: "Friend request".into() }
}

/// Accept an incoming request (recipient only).
#[utoipa::path(post, path = "/api/v1/users/me/friends/requests/{request_id}/accept", security(("bearer" = [])), params(("request_id" = String, Path)),
    responses((status = 200, body = Friend), (status = 404, body = ProblemDetails)))]
pub async fn accept(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
) -> Result<Json<Friend>, ApiError> {
    let row = store::social::request_by_id(&state.db, &request_id)
        .await?
        .filter(|r| r.to_user_id == auth.user.id)
        .ok_or_else(request_not_found)?;
    let other = store::users::by_id(&state.db, &row.from_user_id).await?.ok_or_else(request_not_found)?;
    let since = store::social::add_friendship(&state.db, &auth.user.id, &other.id).await?;
    accept_events(&state, &auth.user, &other, &since);
    let reference = row.remote_request_id.as_deref().unwrap_or(&row.id);
    social::friend(&state, &auth.user, &other, "friend.accept", Some(reference)).await?;
    Ok(Json(Friend { user: other.to_public(), since }))
}

/// Decline (recipient) or withdraw (sender) a request.
#[utoipa::path(delete, path = "/api/v1/users/me/friends/requests/{request_id}", security(("bearer" = [])), params(("request_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = store::social::request_by_id(&state.db, &request_id)
        .await?
        .filter(|r| r.to_user_id == auth.user.id || r.from_user_id == auth.user.id)
        .ok_or_else(request_not_found)?;
    store::social::delete_request(&state.db, &row.id).await?;
    let other_id = if row.from_user_id == auth.user.id { &row.to_user_id } else { &row.from_user_id };
    if let Some(other) = store::users::by_id(&state.db, other_id).await? {
        // Declining names the other node's id of the request, withdrawing our own (§6.2).
        let reference = if row.to_user_id == auth.user.id { row.remote_request_id.as_deref() } else { Some(&*row.id) };
        if let Some(reference) = reference {
            social::friend(&state, &auth.user, &other, "friend.remove", Some(reference)).await?;
        }
    }
    for (to, other) in [(&row.from_user_id, &row.to_user_id), (&row.to_user_id, &row.from_user_id)] {
        if let Some(other) = store::users::by_id(&state.db, other).await? {
            state.hub.users(
                vec![to.clone()],
                "friend.remove",
                json!({ "request_id": row.id, "user": other.to_public() }),
            );
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// End a friendship.
#[utoipa::path(delete, path = "/api/v1/users/me/friends/{username}", security(("bearer" = [])), params(("username" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn remove(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    let not_found = || ApiError::NotFound { code: "friend.not_found", what: "Friendship".into() };
    let other = remote::known_user(&state, &username).await?.ok_or_else(not_found)?;
    if !store::social::remove_friendship(&state.db, &auth.user.id, &other.id).await? {
        return Err(not_found());
    }
    social::friend(&state, &auth.user, &other, "friend.remove", None).await?;
    state.hub.users(
        vec![auth.user.id.clone()],
        "friend.remove",
        json!({ "request_id": null, "user": other.to_public() }),
    );
    state.hub.users(
        vec![other.id.clone()],
        "friend.remove",
        json!({ "request_id": null, "user": auth.user.to_public() }),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// My blocked users with my private notes, oldest first.
#[utoipa::path(get, path = "/api/v1/users/me/blocks", security(("bearer" = [])), responses((status = 200, body = Vec<BlockedUser>)))]
pub async fn blocks(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<BlockedUser>>, ApiError> {
    let mut out = Vec::new();
    for (id, reason, created_at) in store::social::blocks_of(&state.db, &auth.user.id).await? {
        if let Some(u) = store::users::by_id(&state.db, &id).await? {
            out.push(BlockedUser { user: u.to_public(), reason, created_at });
        }
    }
    Ok(Json(out))
}

/// Block a user with an optional private note: ends friendship and requests; they can no longer send
/// requests or DMs. Blocking again updates the note.
#[utoipa::path(post, path = "/api/v1/users/me/blocks", security(("bearer" = [])), request_body = BlockRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn block(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<BlockRequest>,
) -> Result<StatusCode, ApiError> {
    let reason = note("reason", req.reason.as_deref())?;
    let other = target(&state, &auth.user, &req.user).await?;
    block_user(&state, &auth.user, &other, reason.as_deref().unwrap_or("")).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Blocks `other` for `me` (also used when declining a message request with "block").
pub async fn block_user(state: &AppState, auth_user: &UserRow, other: &UserRow, reason: &str) -> Result<(), ApiError> {
    let had_request = store::social::request_between(&state.db, &auth_user.id, &other.id).await?.is_some()
        || store::social::request_between(&state.db, &other.id, &auth_user.id).await?.is_some();
    let was_friend = store::social::remove_friendship(&state.db, &auth_user.id, &other.id).await?;
    store::social::block(&state.db, &auth_user.id, &other.id, reason).await?;
    if was_friend || had_request {
        // The other node only learns that the friendship or request ended, never about the block.
        social::friend(state, auth_user, other, "friend.remove", None).await?;
    }
    if was_friend {
        state.hub.users(
            vec![auth_user.id.clone()],
            "friend.remove",
            json!({ "request_id": null, "user": other.to_public() }),
        );
        state.hub.users(
            vec![other.id.clone()],
            "friend.remove",
            json!({ "request_id": null, "user": auth_user.to_public() }),
        );
    }
    // Presence is hidden between the two from now on.
    crate::presence::hide_between(state, auth_user, other);
    Ok(())
}

/// Unblock a user.
#[utoipa::path(delete, path = "/api/v1/users/me/blocks/{username}", security(("bearer" = [])), params(("username" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn unblock(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
) -> Result<StatusCode, ApiError> {
    let not_found = || ApiError::NotFound { code: "block.not_found", what: "Block".into() };
    let other = remote::known_user(&state, &username).await?.ok_or_else(not_found)?;
    if !store::social::unblock(&state.db, &auth.user.id, &other.id).await? {
        return Err(not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
