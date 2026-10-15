// SPDX-License-Identifier: AGPL-3.0-only
//! Whiteboard (`protocol/WHITEBOARD.md`): ephemeral events of a conversation, the session
//! the node derives from them, the personal scene library on the home node and the conversion of
//! background images through the media pipeline.

use std::time::Instant;

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    models::UserRow,
    permissions as p, store,
    validate::bad,
    whiteboard::{self, Actor, MAX_CONTENT_BYTES, SessionState, WhiteboardSession},
};

/// Largest encrypted scene blob.
pub const MAX_SCENE_BYTES: usize = 5 * 1024 * 1024;
/// Largest encrypted thumbnail blob.
pub const MAX_THUMBNAIL_BYTES: usize = 64 * 1024;
/// Longest scene name (characters).
pub const MAX_SCENE_NAME_CHARS: usize = 64;
/// Smallest valid encrypted blob: version, nonce, GCM tag.
const MIN_BLOB_BYTES: usize = 1 + 12 + 16;

// ---------------------------------------------------------------- ephemeral events

#[derive(Deserialize, ToSchema)]
pub struct EphemeralRequest {
    /// `cursor` or `whiteboard.<name>` (`[a-z_]`, at most 32 characters).
    #[serde(rename = "type")]
    pub kind: String,
    /// Encrypted conversations: base64url content exactly like a message (ENCRYPTION.md §5.2);
    /// plaintext conversations: a JSON object. At most 64 KiB either way.
    #[schema(value_type = Value)]
    pub content: Value,
    /// `whiteboard.open` and `whiteboard.grant` only: the plaintext session state the node keeps.
    pub session: Option<SessionState>,
}

#[derive(Serialize, ToSchema)]
pub struct EphemeralAccepted {
    /// The session after `whiteboard.open`, `whiteboard.grant` and `whiteboard.close` (null after closing
    /// and for every other type).
    pub session: Option<WhiteboardSession>,
}

#[derive(Serialize, ToSchema)]
pub struct EphemeralSender {
    /// Address of the sending user.
    pub user: String,
    /// The sending device (the id other clients know, also in MLS identities).
    pub device_id: String,
}

/// Data of the WebSocket event `ephemeral`.
#[derive(Serialize, ToSchema)]
pub struct EphemeralEvent {
    pub conversation_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub from: EphemeralSender,
    #[schema(value_type = Value)]
    pub content: Value,
}

#[derive(Serialize, ToSchema)]
pub struct SessionResponse {
    pub session: Option<WhiteboardSession>,
}

/// `cursor` or `whiteboard.<name>`.
pub fn valid_type(kind: &str) -> bool {
    kind == "cursor"
        || kind.strip_prefix("whiteboard.").is_some_and(|name| {
            !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
}

fn too_large() -> ApiError {
    ApiError::PayloadTooLarge {
        code: "ephemeral.too_large",
        detail: format!("Ephemeral content is limited to {} KiB", MAX_CONTENT_BYTES / 1024),
        meta: serde_json::json!({ "max_bytes": MAX_CONTENT_BYTES }),
    }
}

/// Checks the content against the conversation's encryption like a message (ENCRYPTION.md §5.3).
async fn check_content(state: &AppState, auth: &AuthUser, conv: &Conv, content: &Value) -> Result<(), ApiError> {
    match (conv.encrypted, content) {
        (true, Value::String(s)) => {
            if s.len() > MAX_CONTENT_BYTES {
                return Err(too_large());
            }
            let header = tavrn_crypto::content_header(s)
                .map_err(|_| bad("ephemeral.ciphertext_invalid", "Not valid encrypted content (format 1)"))?;
            let known = match i64::try_from(header.epoch) {
                Ok(epoch) => whiteboard::epoch_known(state, &conv.id, epoch).await?,
                Err(_) => false,
            };
            if !known {
                return Err(bad("ephemeral.epoch_unknown", "The node does not know this epoch (yet)"));
            }
            whiteboard::require_attested(state, auth).await
        }
        (true, _) => Err(bad("ephemeral.encryption_mismatch", "This conversation is encrypted; plaintext is refused")),
        (false, Value::Object(_)) => {
            if serde_json::to_vec(content).map_err(|e| ApiError::Internal(e.into()))?.len() > MAX_CONTENT_BYTES {
                return Err(too_large());
            }
            Ok(())
        }
        (false, _) => Err(bad(
            "ephemeral.encryption_mismatch",
            "This conversation is not encrypted; content must be a JSON object",
        )),
    }
}

/// May the requester open a board here: `use_whiteboard` (DMs and group DMs always have it), in voice
/// channels also `connect`; never in the welcome channel.
fn may_open(conv: &Conv) -> bool {
    match &conv.kind {
        ConvKind::Channel { channel, .. } if channel.kind == "system" => false,
        ConvKind::Channel { channel, .. } if channel.kind == "voice" => {
            p::has(conv.perms, p::USE_WHITEBOARD | p::CONNECT)
        }
        _ => p::has(conv.perms, p::USE_WHITEBOARD),
    }
}

/// Moderates boards of others (close any board, change its grants): `manage_whiteboard` in room channels.
fn may_moderate(conv: &Conv) -> bool {
    matches!(conv.kind, ConvKind::Channel { .. }) && p::has(conv.perms, p::MANAGE_WHITEBOARD)
}

/// The conversation of an ephemeral event. Room channels are evaluated on the shared channel visibility snapshot
/// (`crate::visibility`, as typing over the WebSocket): cursors and strokes arrive many times per second, and the
/// snapshot is dropped synchronously on every role, override, channel and membership event. DMs, group DMs and
/// node admins who are not members take the full check (`access::conversation`).
async fn ephemeral_conversation(state: &AppState, conversation_id: &str, user: &UserRow) -> Result<Conv, ApiError> {
    if !crate::util::is_ulid(conversation_id) {
        return Err(access::conversation_not_found());
    }
    let row =
        store::social::conversation(&state.db, conversation_id).await?.ok_or_else(access::conversation_not_found)?;
    if let ("channel", Some(room_id)) = (row.kind.as_str(), &row.room_id)
        && let Some(view) = crate::visibility::room(state, room_id).await?
        && let Some(conv) = view.conversation(conversation_id, user)
    {
        return conv;
    }
    access::conversation_of_row(state, row, user).await
}

/// Send an ephemeral event to the conversation: fanned out over the WebSocket (`ephemeral`) to every
/// member with read access except the sending device, never stored. The node reads only the type and,
/// for `whiteboard.open`, `whiteboard.grant` and `whiteboard.close`, the plaintext `session` field; it
/// announces session changes as `whiteboard.session`. 30 events per second and sender.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/ephemeral", security(("bearer" = [])),
    params(("conversation_id" = String, Path)), request_body = EphemeralRequest,
    responses((status = 200, body = EphemeralAccepted), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn post_ephemeral(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<EphemeralRequest>,
) -> Result<Json<EphemeralAccepted>, ApiError> {
    if !valid_type(&req.kind) {
        return Err(bad("ephemeral.type_invalid", "type must be `cursor` or `whiteboard.<name>`"));
    }
    if req.kind.starts_with("whiteboard.") {
        crate::applications::require_scope(&auth, "whiteboard")?;
    }
    state.ephemeral_limiter.check_all(&[format!("eph:{}", auth.user.id)])?;
    let conv = ephemeral_conversation(&state, &conversation_id, &auth.user).await?;
    conv.require_entitled()?;
    if conv.is_request_for(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "conversation.request_pending",
            detail: "Accept the message request first".into(),
        });
    }
    crate::routes::messages::check_not_blocked(&state, &auth, &conv).await?;
    // A timeout limits writing (permissions.md step 5): cursors and strokes are writing too.
    if let ConvKind::Channel { access, .. } = &conv.kind
        && !access.is_owner
        && !access.is_node_admin
        && access.member.as_ref().is_some_and(crate::models::MemberRow::is_timed_out)
    {
        return Err(ApiError::Forbidden {
            code: "member.timed_out",
            detail: "Members in timeout send no ephemeral events".into(),
        });
    }
    check_content(&state, &auth, &conv, &req.content).await?;

    let now = Instant::now();
    let actor = Actor { user_id: &auth.user.id, address: &auth.user.address(), public_device: auth.public_device_id() };
    let boards = &state.whiteboards;
    // (session after the event, did the visible session change)
    let (session, changed) = match req.kind.as_str() {
        "whiteboard.open" => {
            if !may_open(&conv) {
                return Err(ApiError::Forbidden {
                    code: "whiteboard.open_forbidden",
                    detail: "Opening a whiteboard needs use_whiteboard (voice channels also connect)".into(),
                });
            }
            let normalized = req.session.as_ref().map(SessionState::normalized).transpose()?;
            let (s, changed) = boards.open(&conv.id, &actor, normalized.as_ref(), now)?;
            (Some(s), changed)
        }
        "whiteboard.grant" => {
            let state_req = req
                .session
                .as_ref()
                .ok_or_else(|| bad("whiteboard.state_missing", "whiteboard.grant needs the session field"))?
                .normalized()?;
            let (s, changed) = boards.grant(&conv.id, &actor, &state_req, may_moderate(&conv), now)?;
            (Some(s), changed)
        }
        "whiteboard.close" => {
            boards.close(&conv.id, &actor, may_moderate(&conv), now)?;
            (None, true)
        }
        _ => {
            boards.touch(&conv.id, &auth.user.id, now);
            (None, false)
        }
    };

    let audience = whiteboard::audience(&state, &conv.id).await?;
    state.hub.users_except_device(
        audience.as_ref().clone(),
        &auth.device_id,
        "ephemeral",
        EphemeralEvent {
            conversation_id: conv.id.clone(),
            kind: req.kind.clone(),
            from: EphemeralSender { user: auth.user.address(), device_id: auth.public_device_id().to_string() },
            content: req.content,
        },
    );
    if changed {
        whiteboard::publish_session(&state, &conv.id, session.as_ref()).await;
    }
    Ok(Json(EphemeralAccepted { session }))
}

/// The current whiteboard session of a conversation (null without one); changes arrive as
/// `whiteboard.session`.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/whiteboard", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = SessionResponse), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<SessionResponse>, ApiError> {
    let conv = ephemeral_conversation(&state, &conversation_id, &auth.user).await?;
    conv.require_entitled()?;
    Ok(Json(SessionResponse { session: state.whiteboards.get(&conv.id, Instant::now()) }))
}

// ---------------------------------------------------------------- scene library

#[derive(Serialize, ToSchema)]
pub struct SceneInfo {
    pub id: String,
    pub name: String,
    /// Size of the encrypted scene blob in bytes.
    pub size: i64,
    /// Size of the encrypted thumbnail (0 without one).
    pub thumbnail_size: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct SceneList {
    pub items: Vec<SceneInfo>,
    /// Scenes allowed per user on this node (`TAVRN_WHITEBOARD_MAX_SCENES`).
    pub max_scenes: u32,
    /// Largest scene blob in bytes.
    pub max_scene_bytes: u64,
}

#[derive(Deserialize, ToSchema)]
pub struct RenameSceneRequest {
    pub name: String,
}

fn info(r: store::whiteboards::SceneRow) -> SceneInfo {
    SceneInfo {
        id: r.id,
        name: r.name,
        size: r.size,
        thumbnail_size: r.thumbnail_size,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

fn scene_not_found() -> ApiError {
    ApiError::NotFound { code: "whiteboard.scene_not_found", what: "Scene".into() }
}

/// The scene library lives on the home node: remote users are refused.
fn local_only(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    if auth.is_remote() || auth.user.domain != state.config.domain {
        return Err(crate::federation::guard::local_only());
    }
    Ok(())
}

/// Scene ids are canonical (uppercase) ULIDs: the client binds the encryption to exactly this spelling.
fn scene_id(id: &str) -> Result<(), ApiError> {
    if crate::util::is_ulid(id) && !id.bytes().any(|b| b.is_ascii_lowercase()) {
        Ok(())
    } else {
        Err(bad("whiteboard.scene_id_invalid", "Scene ids are ULIDs (uppercase)"))
    }
}

/// 1–64 characters after trimming, no control characters.
pub fn scene_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    let n = name.chars().count();
    if n == 0 || n > MAX_SCENE_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(bad(
            "whiteboard.scene_name_invalid",
            format!("Scene names have 1 to {MAX_SCENE_NAME_CHARS} characters"),
        ));
    }
    Ok(name.to_string())
}

/// Reads an encrypted blob (version byte 1) of at most `max` bytes.
async fn read_blob(headers: &HeaderMap, body: Body, max: usize, code: &'static str) -> Result<Vec<u8>, ApiError> {
    let too_large = || ApiError::PayloadTooLarge {
        code,
        detail: format!("At most {} KiB", max / 1024),
        meta: serde_json::json!({ "max_bytes": max }),
    };
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > max) {
        return Err(too_large());
    }
    let blob = axum::body::to_bytes(body, max).await.map_err(|_| too_large())?;
    if blob.len() < MIN_BLOB_BYTES || blob[0] != 1 {
        return Err(bad("whiteboard.blob_invalid", "Not an encrypted scene blob (format version 1)"));
    }
    Ok(blob.to_vec())
}

fn binary(bytes: Vec<u8>) -> Response {
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

/// The own scenes (without their blobs), most recently changed first.
#[utoipa::path(get, path = "/api/v1/users/me/whiteboards", security(("bearer" = [])),
    responses((status = 200, body = SceneList), (status = 403, body = ProblemDetails)))]
pub async fn list_scenes(State(state): State<AppState>, auth: AuthUser) -> Result<Json<SceneList>, ApiError> {
    local_only(&state, &auth)?;
    let items = store::whiteboards::list(&state.db, &auth.user.id).await?.into_iter().map(info).collect();
    Ok(Json(SceneList {
        items,
        max_scenes: state.config.whiteboard_max_scenes,
        max_scene_bytes: MAX_SCENE_BYTES as u64,
    }))
}

/// Create or replace a scene (raw body: the encrypted scene blob, at most 5 MB). The name comes in
/// `Tavrn-Scene-Name` (UTF-8, percent-encoded): required when creating, optional when replacing.
#[utoipa::path(put, path = "/api/v1/users/me/whiteboards/{scene_id}", security(("bearer" = [])),
    params(("scene_id" = String, Path), ("Tavrn-Scene-Name" = Option<String>, Header, description = "Scene name, percent-encoded UTF-8")),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = SceneInfo), (status = 201, body = SceneInfo), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_scene(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    state.scene_limiter.check_all(&[format!("scenes:{}", auth.user.id)])?;
    let name = headers
        .get("tavrn-scene-name")
        .and_then(|v| v.to_str().ok())
        .map(|v| scene_name(&crate::routes::attachments::percent_decode(v)))
        .transpose()?;
    let blob = read_blob(&headers, body, MAX_SCENE_BYTES, "whiteboard.scene_too_large").await?;
    let user = &auth.user.id;
    if store::whiteboards::replace(&state.db, user, &scene_id_raw, name.as_deref(), &blob).await? {
        let row = store::whiteboards::info(&state.db, user, &scene_id_raw).await?.ok_or_else(scene_not_found)?;
        return Ok(Json(info(row)).into_response());
    }
    let name = name.ok_or_else(|| bad("whiteboard.scene_name_invalid", "New scenes need a name (Tavrn-Scene-Name)"))?;
    let max = i64::from(state.config.whiteboard_max_scenes);
    if store::whiteboards::count(&state.db, user).await? >= max {
        return Err(ApiError::Forbidden {
            code: "whiteboard.scene_limit",
            detail: format!("At most {max} scenes per account"),
        });
    }
    if !store::whiteboards::create(&state.db, user, &scene_id_raw, &name, &blob).await? {
        // Created by a parallel request in between: replace it.
        store::whiteboards::replace(&state.db, user, &scene_id_raw, Some(&name), &blob).await?;
    }
    let row = store::whiteboards::info(&state.db, user, &scene_id_raw).await?.ok_or_else(scene_not_found)?;
    Ok((StatusCode::CREATED, Json(info(row))).into_response())
}

/// The encrypted scene blob.
#[utoipa::path(get, path = "/api/v1/users/me/whiteboards/{scene_id}", security(("bearer" = [])), params(("scene_id" = String, Path)),
    responses((status = 200, description = "Encrypted scene (application/octet-stream)"), (status = 404, body = ProblemDetails)))]
pub async fn get_scene(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
) -> Result<Response, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    let blob = store::whiteboards::scene(&state.db, &auth.user.id, &scene_id_raw).await?.ok_or_else(scene_not_found)?;
    Ok(binary(blob))
}

/// Rename a scene.
#[utoipa::path(patch, path = "/api/v1/users/me/whiteboards/{scene_id}", security(("bearer" = [])), params(("scene_id" = String, Path)),
    request_body = RenameSceneRequest,
    responses((status = 200, body = SceneInfo), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn rename_scene(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
    ApiJson(req): ApiJson<RenameSceneRequest>,
) -> Result<Json<SceneInfo>, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    state.scene_limiter.check_all(&[format!("scenes:{}", auth.user.id)])?;
    let name = scene_name(&req.name)?;
    if !store::whiteboards::rename(&state.db, &auth.user.id, &scene_id_raw, &name).await? {
        return Err(scene_not_found());
    }
    let row = store::whiteboards::info(&state.db, &auth.user.id, &scene_id_raw).await?.ok_or_else(scene_not_found)?;
    Ok(Json(info(row)))
}

/// Delete a scene and its thumbnail.
#[utoipa::path(delete, path = "/api/v1/users/me/whiteboards/{scene_id}", security(("bearer" = [])), params(("scene_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_scene(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    if !store::whiteboards::delete(&state.db, &auth.user.id, &scene_id_raw).await? {
        return Err(scene_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Store the encrypted thumbnail of a scene (raw body, at most 64 KiB).
#[utoipa::path(put, path = "/api/v1/users/me/whiteboards/{scene_id}/thumbnail", security(("bearer" = [])), params(("scene_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails)))]
pub async fn put_thumbnail(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    state.scene_limiter.check_all(&[format!("scenes:{}", auth.user.id)])?;
    let blob = read_blob(&headers, body, MAX_THUMBNAIL_BYTES, "whiteboard.thumbnail_too_large").await?;
    if !store::whiteboards::set_thumbnail(&state.db, &auth.user.id, &scene_id_raw, &blob).await? {
        return Err(scene_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The encrypted thumbnail of a scene (404 `whiteboard.thumbnail_not_found` without one).
#[utoipa::path(get, path = "/api/v1/users/me/whiteboards/{scene_id}/thumbnail", security(("bearer" = [])), params(("scene_id" = String, Path)),
    responses((status = 200, description = "Encrypted thumbnail (application/octet-stream)"), (status = 404, body = ProblemDetails)))]
pub async fn get_thumbnail(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(scene_id_raw): Path<String>,
) -> Result<Response, ApiError> {
    local_only(&state, &auth)?;
    scene_id(&scene_id_raw)?;
    let thumb =
        store::whiteboards::thumbnail(&state.db, &auth.user.id, &scene_id_raw).await?.ok_or_else(scene_not_found)?;
    let thumb =
        thumb.ok_or_else(|| ApiError::NotFound { code: "whiteboard.thumbnail_not_found", what: "Thumbnail".into() })?;
    Ok(binary(thumb))
}

/// Convert a background image for a whiteboard through the media pipeline (PNG, JPEG, GIF,
/// WebP, MP4, WebM by magic bytes, ≤ 20 MB, fit into 1280 px, metadata removed) and return the still image
/// (WebP; PNG/JPEG without ffmpeg). Nothing is stored: the client puts the image into its encrypted board.
#[utoipa::path(post, path = "/api/v1/users/me/whiteboards/background", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, content_type = "image/webp"), (status = 400, body = ProblemDetails), (status = 413, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn convert_background(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    local_only(&state, &auth)?;
    state.media_limiter.check_all(&[format!("media:{}", auth.user.id)])?;
    let max = crate::media::MAX_INPUT_BYTES;
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > max) {
        return Err(crate::media::input_too_large());
    }
    let bytes = axum::body::to_bytes(body, max).await.map_err(|_| crate::media::input_too_large())?;
    let processed = state.media.process(crate::media::MediaKind::Background, bytes).await?;
    let mut resp = Response::new(Body::from(processed.still));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(processed.still_mime).unwrap_or(HeaderValue::from_static("image/webp")),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_types() {
        for ok in ["cursor", "whiteboard.update", "whiteboard.open", "whiteboard.a_b"] {
            assert!(valid_type(ok), "{ok}");
        }
        let long = format!("whiteboard.{}", "a".repeat(33));
        for bad in ["", "whiteboard.", "whiteboard.Update", "whiteboard.x-y", "chat.update", "cursor2", long.as_str()] {
            assert!(!valid_type(bad), "{bad}");
        }
    }

    #[test]
    fn scene_names() {
        assert_eq!(scene_name("  Raid plan  ").ok().as_deref(), Some("Raid plan"));
        assert_eq!(scene_name(&"ä".repeat(64)).ok().map(|s| s.chars().count()), Some(64));
        for bad in ["", "   ", "a\nb", "tab\there"] {
            assert!(scene_name(bad).is_err(), "{bad:?}");
        }
        assert!(scene_name(&"x".repeat(65)).is_err());
    }
}
