// SPDX-License-Identifier: AGPL-3.0-only
//! Uploads, blob delivery, reactions and pins.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    access::{self, Conv},
    app::AppState,
    auth::AuthUser,
    entitlements::{self, Entitlements},
    error::{ApiError, ProblemDetails},
    models::{Attachment, Message, MessageRow},
    permissions as p,
    storage::mime_allowed,
    store,
    validate::{self, bad},
};

const MAX_NAME_LEN: usize = 255;

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Upload a file (`attach_files`). The body is the raw file; the name comes via `Tavrn-File-Name` (UTF-8,
/// URL-encoded), the type via `Content-Type`. The blob belongs to the channel and is bound when the message is
/// sent; unused uploads are deleted after 24 hours. In encrypted conversations the body is ciphertext: the node
/// then stores neither name nor type (`""`, `application/octet-stream`, ENCRYPTION.md §6).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/uploads", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 201, body = Attachment), (status = 403, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn upload(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<Attachment>), ApiError> {
    if !state.config.uploads_enabled {
        return Err(uploads_disabled());
    }
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    upload_in(&state, &auth, &conv, &headers, body).await
}

/// Upload an attachment to any conversation (see the room route).
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/uploads", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 201, body = Attachment), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn upload_to_conversation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<Attachment>), ApiError> {
    if !state.config.uploads_enabled {
        return Err(uploads_disabled());
    }
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    upload_in(&state, &auth, &conv, &headers, body).await
}

fn uploads_disabled() -> ApiError {
    ApiError::Forbidden { code: "upload.disabled", detail: "Uploads are disabled on this node".into() }
}

/// The room a conversation belongs to (channels), for entitlements.
fn conv_room(conv: &Conv) -> Option<&crate::models::Room> {
    match &conv.kind {
        access::ConvKind::Channel { access, .. } => Some(&access.room),
        access::ConvKind::Direct { .. } => None,
    }
}

/// Upload size and storage quota of a conversation for `user` (entitlements): the upload size
/// for the uploader in the room, the storage per room for the room (DMs: for the uploader). `None` quota =
/// unlimited.
async fn upload_limits(
    state: &AppState,
    user: &crate::models::UserRow,
    conv: &Conv,
) -> Result<(u64, Option<i64>), ApiError> {
    let e = Entitlements::load(state, Some(user), conv_room(conv)).await?;
    Ok((e.upload_max_bytes(&state.config), e.limit(entitlements::STORAGE_MAX_BYTES_PER_ROOM)))
}

fn too_large(max: u64) -> ApiError {
    ApiError::PayloadTooLarge {
        code: "upload.too_large",
        detail: format!("At most {} MB per file", max / 1024 / 1024),
        meta: serde_json::json!({ "max_bytes": max }),
    }
}

async fn upload_in(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    headers: &HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<Attachment>), ApiError> {
    let cfg = &state.config;
    conv.require(p::VIEW_CHANNEL | p::SEND_MESSAGES | p::ATTACH_FILES, "upload.forbidden", "Attach files")?;
    let (max, quota) = upload_limits(state, &auth.user, conv).await?;
    // The body is read here with the effective limit (the route has no body limit of its own; the router's
    // global limit is `TAVRN_UPLOAD_MAX_BYTES_CEILING`).
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max) {
        return Err(too_large(max));
    }
    let body =
        axum::body::to_bytes(body, usize::try_from(max).unwrap_or(usize::MAX)).await.map_err(|_| too_large(max))?;
    if body.is_empty() {
        return Err(bad("upload.empty", "Empty file"));
    }
    let (name, mime, class) = if conv.encrypted {
        // Ciphertext: name and type travel inside the encrypted content; the client declares the category.
        let class = crate::uploads::declared(header_str(headers, "tavrn-upload-category")).ok_or_else(|| {
            bad(
                "upload.category_invalid",
                "Tavrn-Upload-Category: images, audio, video, documents, archives, other or executable",
            )
        })?;
        (String::new(), "application/octet-stream".to_string(), class)
    } else {
        let mime = header_str(headers, "content-type")
            .unwrap_or("application/octet-stream")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !mime_allowed(&cfg.upload_allowed_types(), &mime) {
            return Err(ApiError::BadRequest {
                code: "upload.type_not_allowed",
                detail: format!("File type {mime} is not allowed on this node"),
            }
            .with_status(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        let raw_name = header_str(headers, "tavrn-file-name").map(percent_decode).unwrap_or_else(|| "file".into());
        let class = crate::uploads::classify(&body, &raw_name, &mime);
        // SVG is stored as what it is, whatever type was declared: clients never render it inline.
        let mime = if crate::uploads::is_svg(&body, &raw_name, &mime) { "image/svg+xml".to_string() } else { mime };
        (sanitize_name(&raw_name), mime, class)
    };
    check_category(state, conv, &auth.user.id, class).await?;
    let room_id = conv.room_id();
    let usage = match room_id {
        Some(room_id) => store::blobs::room_usage(&state.db, room_id).await?,
        None => store::blobs::conversation_usage(&state.db, &conv.id).await?,
    };
    if let Some(quota) = quota
        && usage.saturating_add(body.len() as i64) > quota
    {
        return Err(ApiError::PayloadTooLarge {
            code: "upload.quota_exceeded",
            detail: "The storage quota of this room is exhausted".into(),
            meta: serde_json::json!({ "quota_bytes": quota, "used_bytes": usage }),
        });
    }
    let sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(&body));
    let blob = store::blobs::insert(
        &state.db,
        store::blobs::NewBlob {
            uploader_id: &auth.user.id,
            conversation_id: &conv.id,
            room_id,
            name: &name,
            mime: &mime,
            size: body.len() as i64,
            sha256: &sha256,
        },
    )
    .await?;
    if let Err(e) = state.storage.write(&blob.id, &body).await {
        store::blobs::delete_rows(&state.db, std::slice::from_ref(&blob.id)).await?;
        return Err(ApiError::Internal(e));
    }
    state.metrics.upload_bytes.inc_by(body.len() as u64);
    Ok((StatusCode::CREATED, Json(blob.to_api())))
}

/// The member's upload categories in this conversation must include the file's; executables also need
/// `TAVRN_UPLOAD_ALLOW_EXECUTABLES=true` (and `other`). `403 upload.type_forbidden` names the category.
pub(crate) async fn check_category(
    state: &AppState,
    conv: &Conv,
    user_id: &str,
    class: crate::uploads::Classified,
) -> Result<(), ApiError> {
    let allowed = access::upload_categories(state, conv, user_id).await?;
    let category = crate::uploads::name_of(class.category);
    let meta = serde_json::json!({
        "category": category,
        "executable": class.executable,
        "allowed_categories": crate::uploads::names(allowed),
    });
    if class.executable && !state.config.upload_allow_executables {
        return Err(ApiError::ForbiddenMeta {
            code: "upload.type_forbidden",
            detail: "Executables and scripts cannot be uploaded on this node".into(),
            meta,
        });
    }
    if allowed & class.category == 0 {
        return Err(ApiError::ForbiddenMeta {
            code: "upload.type_forbidden",
            detail: format!("Uploads of the category {category} are not allowed here"),
            meta,
        });
    }
    Ok(())
}

/// What the requester may upload in a conversation (for the composer's file picker).
#[derive(Serialize, ToSchema)]
pub struct UploadPolicy {
    /// Categories the requester may upload here (`images`, `audio`, `video`, `documents`, `archives`, `other`).
    pub allowed_categories: Vec<String>,
    /// Executables and scripts are accepted (node setting and `other` allowed).
    pub executables_allowed: bool,
    /// Largest file in bytes (encrypted uploads: plus 16 bytes of the GCM tag).
    pub max_bytes: u64,
    /// The requester may attach files here at all (`attach_files`, uploads enabled).
    pub can_attach: bool,
}

/// The requester's upload categories in a conversation (room channels: roles and overrides; DMs: the
/// node's `TAVRN_UPLOAD_DM_CATEGORIES`).
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/upload-policy", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = UploadPolicy), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn upload_policy(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<UploadPolicy>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    let allowed = access::upload_categories(&state, &conv, &auth.user.id).await?;
    let (max_bytes, _) = upload_limits(&state, &auth.user, &conv).await?;
    Ok(Json(UploadPolicy {
        allowed_categories: crate::uploads::names(allowed),
        executables_allowed: state.config.upload_allow_executables && allowed & crate::uploads::OTHER != 0,
        max_bytes,
        can_attach: state.config.uploads_enabled
            && p::has(conv.perms, p::VIEW_CHANNEL | p::SEND_MESSAGES | p::ATTACH_FILES),
    }))
}

pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match decoded {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// File name for display only: strip control characters and path separators, limit the length.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String =
        name.chars().filter(|c| !c.is_control()).map(|c| if matches!(c, '/' | '\\') { '_' } else { c }).collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    let out: String = trimmed.chars().take(MAX_NAME_LEN).collect();
    if out.is_empty() { "file".into() } else { out }
}

/// Download a blob (member with `view_channel` in the conversation).
#[utoipa::path(get, path = "/api/v1/blobs/{blob_id}", security(("bearer" = [])), params(("blob_id" = String, Path)), responses((status = 200, description = "File content"), (status = 404, body = ProblemDetails)))]
pub async fn download(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<String>,
) -> Result<Response, ApiError> {
    validate::ulid("blob_id", &blob_id)?;
    let blob =
        store::blobs::by_id(&state.db, &blob_id).await?.ok_or_else(|| access::not_found("File", "blob.not_found"))?;
    let conv = access::conversation(&state, &blob.conversation_id, &auth.user).await.map_err(|e| {
        if e.code() == "conversation.not_found" { access::not_found("File", "blob.not_found") } else { e }
    })?;
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    if blob.expired_at.is_some() {
        return Err(ApiError::Gone {
            code: "attachment.expired",
            detail: "This file was deleted after the retention period".into(),
        });
    }
    // Decrypted while streaming (encryption at rest); the length is the plaintext's.
    let reader = state
        .storage
        .open_reader(&blob.id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| access::not_found("File", "blob.not_found"))?;
    let len = reader.len;
    let mut resp = Response::new(Body::from_stream(reader.into_stream()));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&blob.mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    let ascii: String = blob
        .name
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' })
        .filter(|c| *c != '"')
        .collect();
    let encoded: String = blob
        .name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let disposition = if blob.name.is_empty() {
        HeaderValue::from_static("attachment")
    } else {
        HeaderValue::from_str(&format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"))
            .unwrap_or(HeaderValue::from_static("attachment"))
    };
    // Every download is an attachment (never rendered by the browser); SVG in particular, which can carry
    // scripts, is download-only everywhere, together with `nosniff` and the sandbox below.
    debug_assert!(disposition.as_bytes().starts_with(b"attachment"));
    h.insert(header::CONTENT_DISPOSITION, disposition);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}

// ---------------------------------------------------------------- Reactions and pins

/// A reaction: Unicode emoji, `:name:` of the room or a custom emoji token (`crate::emoji`).
fn valid_emoji(e: &str) -> bool {
    crate::emoji::valid_reaction(e)
}

async fn message_in_conv(
    state: &AppState,
    conv: &Conv,
    message_id: &str,
    needed: u64,
    code: &'static str,
    what: &str,
) -> Result<MessageRow, ApiError> {
    conv.require(p::VIEW_CHANNEL | needed, code, what)?;
    store::messages::by_id(&state.db, message_id)
        .await?
        .filter(|m| m.conversation_id == conv.id)
        .ok_or_else(|| access::not_found("Message", "message.not_found"))
}

async fn react(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    message_id: &str,
    emoji: &str,
    add: bool,
) -> Result<Json<Message>, ApiError> {
    if add {
        if !valid_emoji(emoji) {
            return Err(bad("reaction.invalid", "Invalid emoji"));
        }
        message_in_conv(state, conv, message_id, p::ADD_REACTIONS, "reaction.forbidden", "Add reactions").await?;
        if let Some(token) = crate::emoji::parse_token(emoji) {
            crate::emoji::check_external(state, conv, &[token]).await?;
        }
        store::blobs::add_reaction(&state.db, message_id, &auth.user.id, emoji).await?;
    } else {
        message_in_conv(state, conv, message_id, 0, "channel.view_forbidden", "View channel").await?;
        store::blobs::remove_reaction(&state.db, message_id, &auth.user.id, emoji).await?;
    }
    let message = crate::routes::messages::enrich_one(state, &auth.user.id, message_id).await?;
    conv.publish(&state.hub, "message.update", &message);
    Ok(Json(message))
}

async fn set_pin(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    message_id: &str,
    pinned: bool,
) -> Result<Json<Message>, ApiError> {
    message_in_conv(state, conv, message_id, p::PIN_MESSAGES, "pin.forbidden", "Pin messages").await?;
    if pinned {
        if store::blobs::pin_count(&state.db, &conv.id).await? >= 50 {
            return Err(bad("pin.limit", "At most 50 pinned messages per channel"));
        }
        store::blobs::pin(&state.db, &conv.id, message_id, &auth.user.id).await?;
    } else {
        store::blobs::unpin(&state.db, &conv.id, message_id).await?;
    }
    let message = crate::routes::messages::enrich_one(state, &auth.user.id, message_id).await?;
    conv.publish(&state.hub, "message.update", &message);
    Ok(Json(message))
}

async fn pins_of(state: &AppState, auth: &AuthUser, conv: &Conv) -> Result<Json<PinList>, ApiError> {
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    let mut rows = Vec::new();
    for id in store::blobs::pinned_ids(&state.db, &conv.id).await? {
        if let Some(m) = store::messages::by_id(&state.db, &id).await? {
            rows.push(m);
        }
    }
    Ok(Json(PinList { messages: crate::routes::messages::enrich(state, &auth.user.id, &rows).await? }))
}

/// Add a reaction (`add_reactions`).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}/reactions/{emoji}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path), ("emoji" = String, Path)), responses((status = 200, body = Message)))]
pub async fn add_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id, emoji)): Path<(String, String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    react(&state, &auth, &conv, &message_id, &emoji, true).await
}

/// Remove an own reaction.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}/reactions/{emoji}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path), ("emoji" = String, Path)), responses((status = 200, body = Message)))]
pub async fn remove_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id, emoji)): Path<(String, String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    react(&state, &auth, &conv, &message_id, &emoji, false).await
}

/// Pin a message (`pin_messages`), at most 50 per channel.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{message_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path)), responses((status = 200, body = Message)))]
pub async fn pin(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id)): Path<(String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    set_pin(&state, &auth, &conv, &message_id, true).await
}

/// Unpin a message (`pin_messages`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{message_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path)), responses((status = 200, body = Message)))]
pub async fn unpin(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id)): Path<(String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    set_pin(&state, &auth, &conv, &message_id, false).await
}

#[derive(Serialize, ToSchema)]
pub struct PinList {
    pub messages: Vec<Message>,
}

/// Pinned messages of a channel.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/pins", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)), responses((status = 200, body = PinList)))]
pub async fn list_pins(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<Json<PinList>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    pins_of(&state, &auth, &conv).await
}

/// Add a reaction in any conversation.
#[utoipa::path(put, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}/reactions/{emoji}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path), ("emoji" = String, Path)), responses((status = 200, body = Message), (status = 404, body = ProblemDetails)))]
pub async fn add_conversation_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id, emoji)): Path<(String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    react(&state, &auth, &conv, &message_id, &emoji, true).await
}

/// Remove an own reaction in any conversation.
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}/reactions/{emoji}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path), ("emoji" = String, Path)), responses((status = 200, body = Message), (status = 404, body = ProblemDetails)))]
pub async fn remove_conversation_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id, emoji)): Path<(String, String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    react(&state, &auth, &conv, &message_id, &emoji, false).await
}

/// Pin a message in any conversation.
#[utoipa::path(put, path = "/api/v1/conversations/{conversation_id}/pins/{message_id}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path)), responses((status = 200, body = Message), (status = 404, body = ProblemDetails)))]
pub async fn pin_in_conversation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    set_pin(&state, &auth, &conv, &message_id, true).await
}

/// Unpin a message in any conversation.
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/pins/{message_id}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path)), responses((status = 200, body = Message), (status = 404, body = ProblemDetails)))]
pub async fn unpin_in_conversation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    set_pin(&state, &auth, &conv, &message_id, false).await
}

/// Pinned messages of any conversation.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/pins", security(("bearer" = [])), params(("conversation_id" = String, Path)), responses((status = 200, body = PinList), (status = 404, body = ProblemDetails)))]
pub async fn list_conversation_pins(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<PinList>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    pins_of(&state, &auth, &conv).await
}

impl ApiError {
    /// Special case: a BadRequest with a different status code (415 for file types).
    pub fn with_status(self, status: StatusCode) -> Self {
        match self {
            Self::BadRequest { code, detail } if status == StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                Self::UnsupportedMedia { code, detail }
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_name("image\u{0}.png"), "image.png");
        assert_eq!(sanitize_name("   "), "file");
        assert_eq!(sanitize_name(&"a".repeat(300)).len(), 255);
        assert_eq!(sanitize_name("c:\\path\\file.txt"), "c:_path_file.txt");
    }

    #[test]
    fn emoji_validation() {
        assert!(valid_emoji("👍"));
        assert!(valid_emoji("🇩🇪"));
        assert!(valid_emoji(":custom:"));
        assert!(valid_emoji(":a_custom_emoji_with_a_long_name:"));
        assert!(valid_emoji("<:pog:01J9ZK8Q4V6X3M2N1P0R5S7T8W@b.example>"));
        assert!(!valid_emoji("<:pog:01J9ZK8Q4V6X3M2N1P0R5S7T8W@b.example/x>"));
        assert!(!valid_emoji(""));
        assert!(!valid_emoji("a b"));
        assert!(!valid_emoji(&"x".repeat(17)));
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("Image%20%C3%A4.png"), "Image ä.png");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
