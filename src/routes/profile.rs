// SPDX-License-Identifier: AGPL-3.0-only
//! Profiles: avatar, header and voice background uploads through the media pipeline,
//! bio, linked accounts and settings (`PATCH /users/me`), public profiles and the public image route,
//! room icons.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    config::DmPolicy,
    error::{ApiError, ApiJson, ProblemDetails},
    media::{self, MediaKind},
    models::{Room, User, UserPrivate, UserRow, media_url},
    permissions as p,
    profile::{self, ProfileLink, ProfileLinkInput},
    store, util, validate,
};

/// Public profile of a user (`GET /users/{address}/profile`), also read by other nodes to mirror it
/// (FEDERATION.md §2.7). Image paths point to this node.
#[derive(Serialize, ToSchema)]
pub struct Profile {
    #[serde(flatten)]
    pub user: User,
    /// Incremented on every change of the public profile (name, images, bio, links, DM setting).
    pub profile_version: i64,
    /// base64url SHA-256 of the avatar's still image, null without avatar.
    pub avatar_sha256: Option<String>,
    /// The avatar has an animated variant (`avatar` points to it, `avatar_still` to the first frame).
    pub avatar_animated: bool,
    pub avatar_animated_sha256: Option<String>,
    /// Profile header (1200 × 400): the animated variant if there is one, else the still.
    pub header: Option<String>,
    pub header_still: Option<String>,
    pub header_animated: bool,
    pub header_sha256: Option<String>,
    pub header_animated_sha256: Option<String>,
    /// Markdown subset, at most 512 characters.
    pub bio: String,
    pub links: Vec<ProfileLink>,
    /// Who may start a DM with this user (effective under the node's bound): friends | everyone_shared | everyone
    pub dm_policy: String,
}

async fn hashes(state: &AppState, media_id: Option<&str>) -> Result<(Option<String>, Option<String>), ApiError> {
    let Some(id) = media_id else { return Ok((None, None)) };
    Ok(match store::media::by_id(&state.db, id).await? {
        Some(m) => (Some(m.still_sha256), m.animated_sha256),
        None => (None, None),
    })
}

/// The profile of a user row of this node (local user or mirror of a remote user).
pub async fn profile_of(state: &AppState, user: &UserRow) -> Result<Profile, ApiError> {
    let (bio, links, profile_version) = store::users::profile_extra(&state.db, &user.id).await?;
    let (avatar_sha256, avatar_animated_sha256) = hashes(state, user.avatar_blob_id.as_deref()).await?;
    let (header_sha256, header_animated_sha256) = hashes(state, user.header_blob_id.as_deref()).await?;
    let header_animated = user.header_animated != 0;
    let node_bound = if user.domain == state.config.domain { state.config.dm_policy } else { DmPolicy::Everyone };
    Ok(Profile {
        user: user.to_public(),
        profile_version,
        avatar_sha256,
        avatar_animated: user.avatar_animated != 0,
        avatar_animated_sha256,
        header: media_url(user.header_blob_id.as_deref(), header_animated),
        header_still: media_url(user.header_blob_id.as_deref(), false),
        header_animated,
        header_sha256,
        header_animated_sha256,
        bio,
        links: profile::parse_links(&links),
        dm_policy: user.dm_policy(node_bound).as_str().into(),
    })
}

fn user_not_found() -> ApiError {
    ApiError::NotFound { code: "user.not_found", what: "User".into() }
}

/// Public profile of a local user (`name` or `name@this.node`) or this node's mirror of a remote user
/// (`name@other.node`, only users this node knows; the mirror is refreshed in the background when stale).
#[utoipa::path(get, path = "/api/v1/users/{address}/profile", params(("address" = String, Path)),
    responses((status = 200, body = Profile), (status = 404, body = ProblemDetails)))]
pub async fn get_profile(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Profile>, ApiError> {
    let (username, domain) = crate::federation::remote::parse_reference(&state, &address).ok_or_else(user_not_found)?;
    let user = store::federation::user_by_address(&state.db, &username, &domain).await?.ok_or_else(user_not_found)?;
    if user.disabled_at.is_some() || (user.domain != state.config.domain && !state.config.federation_enabled) {
        return Err(user_not_found());
    }
    // At most one background refresh per remote user and minute, however often the profile is read.
    if user.domain != state.config.domain && state.profile_refresh_limiter.check(&user.id).is_ok() {
        let (state, user) = (state.clone(), user.clone());
        tokio::spawn(async move {
            if let Err(e) = crate::federation::profiles::refresh(&state, &user, None).await {
                tracing::debug!(error = %e, "profile refresh failed");
            }
        });
    }
    Ok(Json(profile_of(&state, &user).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMeRequest {
    pub display_name: Option<String>,
    /// Markdown subset, at most 512 characters; empty removes it.
    pub bio: Option<String>,
    /// Linked accounts (at most 10); replaces the list. The node derives every URL itself.
    pub links: Option<Vec<ProfileLinkInput>>,
    /// Who can message me: friends | everyone_shared | everyone (the node's `dm_policy` is the upper bound).
    pub dm_policy: Option<String>,
    /// Hide my activity from everyone else.
    pub hide_activity: Option<bool>,
    /// Load image previews automatically: always | friends_and_shared | never.
    pub auto_preview: Option<String>,
    /// The language of the node's mails: a language tag such as `de` or `pt-BR` (stored lowercase), `""` = English.
    pub locale: Option<String>,
}

/// Change the own profile and settings.
#[utoipa::path(patch, path = "/api/v1/users/me", security(("bearer" = [])), request_body = UpdateMeRequest,
    responses((status = 200, body = UserPrivate), (status = 400, body = ProblemDetails)))]
pub async fn update_me(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<UpdateMeRequest>,
) -> Result<Json<UserPrivate>, ApiError> {
    let display_name = req.display_name.as_deref().map(|d| validate::name("display_name", d, 64)).transpose()?;
    let bio = req.bio.as_deref().map(profile::validate_bio).transpose()?;
    let links = req
        .links
        .as_deref()
        .map(|l| profile::validate_links(l).map(|v| serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())))
        .transpose()?;
    let dm_policy = req.dm_policy.as_deref().map(|d| validate::one_of("dm_policy", d, &DmPolicy::ALL)).transpose()?;
    let auto_preview =
        req.auto_preview.as_deref().map(|a| validate::one_of("auto_preview", a, &AUTO_PREVIEW)).transpose()?;
    let locale = req
        .locale
        .as_deref()
        .map(|l| match l.trim() {
            "" => Ok(None),
            tag => crate::mail_templates::normalize_locale(tag)
                .map(Some)
                .ok_or_else(|| validate::bad("validation.locale", "locale: a language tag such as de or pt-BR")),
        })
        .transpose()?;
    if let Some(d) = &display_name {
        store::users::update_profile(&state.db, &auth.user.id, d).await?;
    }
    store::users::update_profile_fields(
        &state.db,
        &auth.user.id,
        store::users::ProfileUpdate {
            bio: bio.as_deref(),
            links: links.as_deref(),
            dm_policy: dm_policy.as_deref(),
            hide_activity: req.hide_activity,
        },
    )
    .await?;
    if display_name.is_some() || bio.is_some() || links.is_some() {
        profile::announce_user(&state, &auth.user.id).await?;
    }
    if req.hide_activity.is_some() {
        crate::presence::changed(&state, &auth.user.id);
    }
    if let Some(a) = &auto_preview {
        store::users::set_auto_preview(&state.db, &auth.user.id, a).await?;
    }
    if let Some(l) = &locale {
        store::users::set_locale(&state.db, &auth.user.id, l.as_deref()).await?;
    }
    let user = store::users::by_id(&state.db, &auth.user.id)
        .await?
        .ok_or(ApiError::Unauthorized { code: "auth.token_invalid" })?;
    let mut me = user.to_private();
    me.auto_preview = Some(store::users::auto_preview(&state.db, &auth.user.id).await?);
    me.locale = store::users::locale(&state.db, &auth.user.id).await?;
    Ok(Json(me))
}

/// Values of the `auto_preview` setting.
pub const AUTO_PREVIEW: [&str; 3] = ["always", "friends_and_shared", "never"];

/// Reads an upload body with the pipeline's input cap (`413 media.too_large` beyond it).
pub(crate) async fn read_upload(
    state: &AppState,
    auth: &AuthUser,
    headers: &HeaderMap,
    body: Body,
) -> Result<axum::body::Bytes, ApiError> {
    state.media_limiter.check_all(&[format!("media:{}", auth.user.id)])?;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > media::MAX_INPUT_BYTES) {
        return Err(media::input_too_large());
    }
    axum::body::to_bytes(body, media::MAX_INPUT_BYTES).await.map_err(|_| media::input_too_large())
}

fn local_only(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    if user.domain != state.config.domain {
        return Err(ApiError::Forbidden {
            code: "federation.local_only",
            detail: "The profile is edited on the home node".into(),
        });
    }
    Ok(())
}

async fn own_profile(state: &AppState, user_id: &str) -> Result<Json<Profile>, ApiError> {
    let user =
        store::users::by_id(&state.db, user_id).await?.ok_or(ApiError::Unauthorized { code: "auth.token_invalid" })?;
    Ok(Json(profile_of(state, &user).await?))
}

async fn put_user_image(
    state: &AppState,
    auth: &AuthUser,
    kind: MediaKind,
    headers: &HeaderMap,
    body: Body,
) -> Result<Json<Profile>, ApiError> {
    local_only(state, &auth.user)?;
    let bytes = read_upload(state, auth, headers, body).await?;
    let stored = profile::convert_and_store(state, kind, &auth.user.id, bytes).await?;
    profile::set_user_media(state, &auth.user.id, kind, Some(&stored)).await?;
    if kind != MediaKind::Background {
        profile::announce_user(state, &auth.user.id).await?;
    }
    own_profile(state, &auth.user.id).await
}

async fn delete_user_image(state: &AppState, auth: &AuthUser, kind: MediaKind) -> Result<Json<Profile>, ApiError> {
    local_only(state, &auth.user)?;
    profile::set_user_media(state, &auth.user.id, kind, None).await?;
    if kind != MediaKind::Background {
        profile::announce_user(state, &auth.user.id).await?;
    }
    own_profile(state, &auth.user.id).await
}

/// Upload an avatar (raw body: PNG, JPEG, GIF, WebP, MP4 or WebM, at most 20 MB and 30 s). Stored as WebP
/// 256 × 256, animated input additionally as animated WebP (≤ 10 s loop, ≤ 1 MB) with its first frame as still.
#[utoipa::path(put, path = "/api/v1/users/me/avatar", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Profile), (status = 400, body = ProblemDetails), (status = 413, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn put_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Profile>, ApiError> {
    put_user_image(&state, &auth, MediaKind::Avatar, &headers, body).await
}

/// Remove the avatar.
#[utoipa::path(delete, path = "/api/v1/users/me/avatar", security(("bearer" = [])), responses((status = 200, body = Profile)))]
pub async fn delete_avatar(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Profile>, ApiError> {
    delete_user_image(&state, &auth, MediaKind::Avatar).await
}

/// Upload a profile header (like the avatar; 1200 × 400, ≤ 2 MB per variant).
#[utoipa::path(put, path = "/api/v1/users/me/header", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Profile), (status = 400, body = ProblemDetails), (status = 413, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn put_header(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Profile>, ApiError> {
    put_user_image(&state, &auth, MediaKind::Header, &headers, body).await
}

/// Remove the profile header.
#[utoipa::path(delete, path = "/api/v1/users/me/header", security(("bearer" = [])), responses((status = 200, body = Profile)))]
pub async fn delete_header(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Profile>, ApiError> {
    delete_user_image(&state, &auth, MediaKind::Header).await
}

/// The own voice/video background (private; images at `/users/me/background/still|animated`).
#[derive(Serialize, ToSchema)]
pub struct Background {
    pub still: Option<String>,
    pub animated: Option<String>,
}

async fn background_info(state: &AppState, user_id: &str) -> Result<Json<Background>, ApiError> {
    let row = match store::media::user_background(&state.db, user_id).await? {
        Some(id) => store::media::by_id(&state.db, &id).await?,
        None => None,
    };
    Ok(Json(Background {
        still: row.as_ref().map(|_| "/api/v1/users/me/background/still".to_string()),
        animated: row.and_then(|r| r.animated_id).map(|_| "/api/v1/users/me/background/animated".to_string()),
    }))
}

/// Upload the background for background replacement in video calls (1280 px, ≤ 2 MB per variant).
#[utoipa::path(put, path = "/api/v1/users/me/background", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Background), (status = 400, body = ProblemDetails), (status = 413, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn put_background(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Background>, ApiError> {
    let _ = put_user_image(&state, &auth, MediaKind::Background, &headers, body).await?;
    background_info(&state, &auth.user.id).await
}

#[utoipa::path(get, path = "/api/v1/users/me/background", security(("bearer" = [])), responses((status = 200, body = Background)))]
pub async fn get_background(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Background>, ApiError> {
    background_info(&state, &auth.user.id).await
}

#[utoipa::path(delete, path = "/api/v1/users/me/background", security(("bearer" = [])), responses((status = 200, body = Background)))]
pub async fn delete_background(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Background>, ApiError> {
    let _ = delete_user_image(&state, &auth, MediaKind::Background).await?;
    background_info(&state, &auth.user.id).await
}

/// The background image (`still` or `animated`) of the requester only.
#[utoipa::path(get, path = "/api/v1/users/me/background/{variant}", security(("bearer" = [])), params(("variant" = String, Path)),
    responses((status = 200, content_type = "image/webp"), (status = 404, body = ProblemDetails)))]
pub async fn background_image(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(variant): Path<String>,
) -> Result<Response, ApiError> {
    let id = store::media::user_background(&state.db, &auth.user.id).await?.ok_or_else(media_not_found)?;
    let row = store::media::by_id(&state.db, &id).await?.ok_or_else(media_not_found)?;
    let resp = serve_variant(&state, &row, variant == "animated").await?;
    let mut resp = resp;
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    Ok(resp)
}

fn media_not_found() -> ApiError {
    ApiError::NotFound { code: "media.not_found", what: "Bild".into() }
}

async fn serve_variant(state: &AppState, row: &store::media::MediaRow, animated: bool) -> Result<Response, ApiError> {
    let (storage_id, mime) = if animated {
        (row.animated_id.clone().ok_or_else(media_not_found)?, "image/webp".to_string())
    } else {
        (row.id.clone(), row.mime.clone())
    };
    if !util::is_ulid(&storage_id) || !crate::federation::client::AVATAR_TYPES.contains(&mime.as_str()) {
        return Err(media_not_found());
    }
    let bytes = state.storage.read(&storage_id).await?.ok_or_else(media_not_found)?;
    let mut resp = bytes.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("image/webp")));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    h.insert(
        axum::http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    Ok(resp)
}

/// A stored image (avatar, header, room icon) by its id; public. The id changes with every upload, so
/// responses are cached for a year.
#[utoipa::path(get, path = "/api/v1/media/{media_id}", params(("media_id" = String, Path)),
    responses((status = 200, content_type = "image/webp"), (status = 404, body = ProblemDetails)))]
pub async fn get_media(State(state): State<AppState>, Path(media_id): Path<String>) -> Result<Response, ApiError> {
    serve_public(&state, &media_id, false).await
}

/// The animated variant of a stored image (animated WebP).
#[utoipa::path(get, path = "/api/v1/media/{media_id}/animated", params(("media_id" = String, Path)),
    responses((status = 200, content_type = "image/webp"), (status = 404, body = ProblemDetails)))]
pub async fn get_media_animated(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> Result<Response, ApiError> {
    serve_public(&state, &media_id, true).await
}

async fn serve_public(state: &AppState, media_id: &str, animated: bool) -> Result<Response, ApiError> {
    if !util::is_ulid(media_id) {
        return Err(media_not_found());
    }
    let row = store::media::by_id(&state.db, media_id).await?.ok_or_else(media_not_found)?;
    // Backgrounds are private (`/users/me/background/…`).
    if row.kind == MediaKind::Background.as_str() {
        return Err(media_not_found());
    }
    let mut resp = serve_variant(state, &row, animated).await?;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    if let Ok(etag) = HeaderValue::from_str(&format!("\"{media_id}{}\"", if animated { "a" } else { "" })) {
        h.insert(header::ETAG, etag);
    }
    Ok(resp)
}

// ---------------------------------------------------------------- room icons

/// Upload a room icon (`manage_room`; like avatars: WebP 256 × 256, animated allowed). Audited.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/icon", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Room), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn put_room_icon(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Room>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    let bytes = read_upload(&state, &auth, &headers, body).await?;
    let stored = profile::convert_and_store(&state, MediaKind::Icon, &room_id, bytes).await?;
    profile::set_room_icon(&state, &room_id, Some(&stored)).await?;
    room_icon_changed(&state, &auth, &room_id, "room.icon", serde_json::json!({ "animated": stored.animated })).await
}

/// Remove the room icon (`manage_room`). Audited.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/icon", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Room), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_room_icon(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Room>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    profile::set_room_icon(&state, &room_id, None).await?;
    room_icon_changed(&state, &auth, &room_id, "room.icon_remove", serde_json::json!({})).await
}

async fn room_icon_changed(
    state: &AppState,
    auth: &AuthUser,
    room_id: &str,
    action: &str,
    meta: serde_json::Value,
) -> Result<Json<Room>, ApiError> {
    store::rooms::audit(&state.db, Some(room_id), Some(&auth.user.id), action, room_id, "", meta).await?;
    let room = store::rooms::room_by_id(&state.db, room_id)
        .await?
        .ok_or_else(|| access::not_found("Room", "room.not_found"))?;
    state.hub.room(room_id, "room.update", &room);
    Ok(Json(room))
}

/// Deletes the icon of a room that is being deleted.
pub async fn drop_room_icon(state: &AppState, room: &Room) {
    if let Some(id) = room.icon_blob_id.as_deref()
        && let Err(e) = profile::delete_media(state, id).await
    {
        tracing::warn!(error = %e, "room icon not deleted");
    }
}
