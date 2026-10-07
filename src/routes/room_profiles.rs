// SPDX-License-Identifier: AGPL-3.0-only
//! Per-room profiles ("server profiles"): nickname, avatar and bio of a member in one room.
//! Members change their own with `change_nickname`; moderators with `manage_nicknames` change or reset
//! those of members below them (audited as `member.profile`); the owner can reset everybody's. The
//! profile belongs to the membership: leaving, kick and ban delete it (and its avatar files). Members
//! of every node may set one; the avatar goes through the media pipeline like user avatars.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    access::{self, RoomAccess},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    media::MediaKind,
    models::{Member, MemberRow},
    permissions as p, profile, store, validate,
};

/// Media kind of per-room avatars in the `media` table (public like user avatars).
pub const ROOM_AVATAR: &str = "room_avatar";

#[derive(Deserialize, ToSchema)]
pub struct RoomProfileRequest {
    /// Nickname in this room (1–32 characters); null removes it, absent keeps it.
    #[serde(default, with = "crate::serde_with_double_option")]
    pub nickname: Option<Option<String>>,
    /// Bio in this room (Markdown subset, at most 512 characters); empty removes it.
    pub bio: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct ModerateProfileRequest {
    /// Nickname; null removes it, absent keeps it.
    #[serde(default, with = "crate::serde_with_double_option")]
    pub nickname: Option<Option<String>>,
    /// Bio; empty removes it.
    pub bio: Option<String>,
    /// Remove the member's per-room avatar.
    #[serde(default)]
    pub reset_avatar: bool,
}

fn own_member(access: &RoomAccess) -> Result<&MemberRow, ApiError> {
    access.member.as_ref().ok_or_else(|| ApiError::Forbidden {
        code: "room.not_member",
        detail: "Only members have a profile in this room".into(),
    })
}

async fn member_view(state: &AppState, room_id: &str, user_id: &str) -> Result<Member, ApiError> {
    let row = store::rooms::member(&state.db, room_id, user_id)
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    let member = crate::routes::rooms::to_member(state, room_id, &row)
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    crate::subscriptions::room_event(
        state,
        room_id,
        "member.update",
        serde_json::json!({ "room_id": room_id, "member": member }),
    )
    .await;
    Ok(member)
}

async fn apply(
    state: &AppState,
    room_id: &str,
    user_id: &str,
    nickname: Option<Option<String>>,
    bio: Option<String>,
) -> Result<serde_json::Value, ApiError> {
    let mut changed = serde_json::Map::new();
    if let Some(nick) = nickname {
        let nick = nick.as_deref().map(|n| validate::name("nickname", n, 32)).transpose()?;
        store::rooms::set_nickname(&state.db, room_id, user_id, nick.as_deref()).await?;
        changed.insert("nickname".into(), serde_json::json!(nick));
    }
    if let Some(bio) = bio {
        let bio = profile::validate_bio(&bio)?;
        store::rooms::set_member_bio(&state.db, room_id, user_id, &bio).await?;
        changed.insert("bio".into(), serde_json::json!(!bio.is_empty()));
    }
    Ok(serde_json::Value::Object(changed))
}

/// Replaces (or removes) a member's per-room avatar; the old files go right away.
async fn set_avatar(
    state: &AppState,
    room_id: &str,
    user_id: &str,
    media: Option<&profile::StoredMedia>,
) -> Result<(), ApiError> {
    let previous = store::rooms::set_member_avatar(
        &state.db,
        room_id,
        user_id,
        media.map(|m| m.id.as_str()),
        media.is_some_and(|m| m.animated),
    )
    .await?;
    if let Some(old) = previous.filter(|old| media.is_none_or(|m| m.id != *old)) {
        profile::delete_media(state, &old).await?;
    }
    Ok(())
}

/// Set the own nickname and bio in this room (`change_nickname`).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/members/me/profile", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body = RoomProfileRequest,
    responses((status = 200, body = Member), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn put_own(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<RoomProfileRequest>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    own_member(&access)?;
    access.require(p::CHANGE_NICKNAME, "member.nickname_forbidden", "change_nickname")?;
    apply(&state, &room_id, &auth.user.id, req.nickname, req.bio).await?;
    Ok(Json(member_view(&state, &room_id, &auth.user.id).await?))
}

/// Reset the own profile in this room (nickname, bio and avatar).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/members/me/profile", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Member), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_own(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    own_member(&access)?;
    apply(&state, &room_id, &auth.user.id, Some(None), Some(String::new())).await?;
    set_avatar(&state, &room_id, &auth.user.id, None).await?;
    Ok(Json(member_view(&state, &room_id, &auth.user.id).await?))
}

/// Upload the own avatar for this room (`change_nickname`; like user avatars: PNG, JPEG, GIF, WebP, MP4
/// or WebM, at most 20 MB, stored as WebP 256 × 256 with an animated variant for animated input).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/members/me/avatar", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Member), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 413, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn put_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    own_member(&access)?;
    access.require(p::CHANGE_NICKNAME, "member.nickname_forbidden", "change_nickname")?;
    let bytes = crate::routes::profile::read_upload(&state, &auth, &headers, body).await?;
    let processed = state.media.process(MediaKind::Avatar, bytes).await?;
    let stored = profile::store_media(
        &state,
        ROOM_AVATAR,
        &auth.user.id,
        &processed.still,
        processed.still_mime,
        processed.animated.as_deref(),
    )
    .await?;
    // The membership may have ended while the image was converted.
    if store::rooms::member(&state.db, &room_id, &auth.user.id).await?.is_none() {
        profile::delete_media(&state, &stored.id).await?;
        return Err(access::not_found("Member", "member.not_found"));
    }
    set_avatar(&state, &room_id, &auth.user.id, Some(&stored)).await?;
    Ok(Json(member_view(&state, &room_id, &auth.user.id).await?))
}

/// Remove the own avatar for this room.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/members/me/avatar", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Member), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    own_member(&access)?;
    set_avatar(&state, &room_id, &auth.user.id, None).await?;
    Ok(Json(member_view(&state, &room_id, &auth.user.id).await?))
}

/// Change or reset another member's profile in this room (`manage_nicknames`, members below the own
/// highest role; the owner can reset everybody's). Audited as `member.profile`.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/members/{user_id}/profile", security(("bearer" = [])), params(("room_id" = String, Path), ("user_id" = String, Path)),
    request_body = ModerateProfileRequest,
    responses((status = 200, body = Member), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn moderate(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, user_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<ModerateProfileRequest>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_NICKNAMES, "member.nickname_forbidden", "manage_nicknames")?;
    if store::rooms::member(&state.db, &room_id, &user_id).await?.is_none() {
        return Err(access::not_found("Member", "member.not_found"));
    }
    if user_id != auth.user.id {
        crate::routes::rooms::moderation_target(&state, &access, &user_id).await?;
    }
    let mut changed = apply(&state, &room_id, &user_id, req.nickname, req.bio).await?;
    if req.reset_avatar {
        set_avatar(&state, &room_id, &user_id, None).await?;
        changed["avatar_reset"] = serde_json::json!(true);
    }
    store::rooms::audit(&state.db, Some(&room_id), Some(&auth.user.id), "member.profile", &user_id, "", changed)
        .await?;
    Ok(Json(member_view(&state, &room_id, &user_id).await?))
}
