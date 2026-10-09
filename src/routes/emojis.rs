// SPDX-License-Identifier: AGPL-3.0-only
//! Custom emojis: per room (`manage_emojis`), personal ones on the home node and the public
//! image route; GIF search over the configured provider.
//!
//! Every uploaded emoji goes through the media pipeline (`media::MediaKind::Emoji`): WebP of at most 128 px,
//! at most 256 KiB per variant, animations cut to 5 s / 60 frames, plus a still variant (`?still=1`).

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    emoji::{personal_limits, valid_name as valid_emoji_name},
    error::{ApiError, ProblemDetails},
    gifs::Gif,
    media::{MediaKind, Processed},
    models::Emoji,
    permissions as p,
    store::{self, emojis::NewEmojiFiles},
    validate::{self, bad},
};

const EMOJI_TYPES: &[&str] = &["image/png", "image/gif", "image/webp", "image/jpeg"];

/// The declared type of an upload (only a first filter: the pipeline sniffs the real format).
fn check_upload(state: &AppState, headers: &HeaderMap, body: &Bytes) -> Result<(), ApiError> {
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !EMOJI_TYPES.contains(&mime.as_str()) {
        return Err(ApiError::UnsupportedMedia {
            code: "emoji.type_not_allowed",
            detail: "Allowed are PNG, GIF, WebP and JPEG".into(),
        });
    }
    let max = state.config.emoji_max_bytes as usize;
    if body.is_empty() || body.len() > max {
        return Err(ApiError::PayloadTooLarge {
            code: "emoji.too_large",
            detail: format!("Emojis may be at most {} KB", max / 1024),
            meta: serde_json::json!({ "max_bytes": max }),
        });
    }
    Ok(())
}

fn emoji_name(headers: &HeaderMap) -> Result<String, ApiError> {
    let name = headers.get("tavrn-emoji-name").and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_ascii_lowercase();
    if !valid_emoji_name(&name) {
        return Err(bad("emoji.name_invalid", "Name: 2–32 characters of a-z, 0-9 and _"));
    }
    Ok(name)
}

/// Stored files of a converted emoji.
struct StoredEmoji {
    id: String,
    still_id: Option<String>,
    mime: &'static str,
    size: i64,
    animated: bool,
}

impl StoredEmoji {
    fn files(&self) -> NewEmojiFiles<'_> {
        NewEmojiFiles {
            id: &self.id,
            still_id: self.still_id.as_deref(),
            mime: self.mime,
            size: self.size,
            animated: self.animated,
        }
    }

    async fn remove(&self, state: &AppState) {
        remove_files(state, &self.id, self.still_id.as_deref()).await;
    }
}

async fn remove_files(state: &AppState, id: &str, still_id: Option<&str>) {
    state.storage.delete(id).await;
    if let Some(still) = still_id.filter(|s| crate::util::is_ulid(s)) {
        state.storage.delete(still).await;
    }
}

/// Runs an upload through the pipeline and stores the result (the animated WebP under `id` and its first
/// frame under `still_id`, or the still under `id`).
async fn convert_and_store(state: &AppState, body: Bytes) -> Result<StoredEmoji, ApiError> {
    let Processed { still, still_mime, animated } = state.media.process(MediaKind::Emoji, body).await?;
    let (id, still_id) = store::emojis::new_ids(animated.is_some());
    let (main, mime) = match &animated {
        Some(a) => (a.as_slice(), "image/webp"),
        None => (still.as_slice(), still_mime),
    };
    state.storage.write(&id, main).await?;
    if let Some(sid) = &still_id
        && let Err(e) = state.storage.write(sid, &still).await
    {
        state.storage.delete(&id).await;
        return Err(e.into());
    }
    Ok(StoredEmoji { id, still_id, mime, size: main.len() as i64, animated: animated.is_some() })
}

/// The room's emojis.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/emojis", security(("bearer" = [])), params(("room_id" = String, Path)), responses((status = 200, body = Vec<Emoji>)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Emoji>>, ApiError> {
    access::room_access(&state, &room_id, &auth.user).await?;
    Ok(Json(store::emojis::list(&state.db, &room_id).await?.iter().map(|e| e.to_api()).collect()))
}

/// Upload an emoji (`manage_emojis`). Body = PNG, GIF, WebP or JPEG (at most `TAVRN_EMOJI_MAX_BYTES`), name in
/// `Tavrn-Emoji-Name` (a-z, 0-9, _). The node converts it to WebP (128 px, ≤ 256 KiB, animations ≤ 5 s / 60
/// frames).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/emojis", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 201, body = Emoji), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Emoji>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_EMOJIS, "emoji.manage_forbidden", "Manage emojis")?;
    let name = emoji_name(&headers)?;
    check_upload(&state, &headers, &body)?;
    // `emoji.max_per_room` (entitlements; node default `TAVRN_EMOJI_MAX_PER_ROOM`).
    let max = crate::entitlements::Entitlements::for_room(&state, &access.room)
        .await?
        .limit(crate::entitlements::EMOJI_MAX_PER_ROOM);
    if let Some(max) = max
        && store::emojis::count(&state.db, &room_id).await? >= max
    {
        return Err(ApiError::Forbidden { code: "emoji.limit", detail: format!("At most {max} emojis per room") });
    }
    let stored = convert_and_store(&state, body).await?;
    let emoji = match store::emojis::insert(&state.db, &room_id, &name, &stored.files(), &auth.user.id).await {
        Ok(e) => e,
        Err(e) => {
            stored.remove(&state).await;
            return Err(e);
        }
    };
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "emoji.create",
        &emoji.id,
        "",
        serde_json::json!({ "name": name }),
    )
    .await?;
    let api = emoji.to_api();
    state.hub.room(&room_id, "emoji.update", serde_json::json!({ "room_id": room_id }));
    Ok((StatusCode::CREATED, Json(api)))
}

/// Delete an emoji (`manage_emojis`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/emojis/{emoji_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("emoji_id" = String, Path)), responses((status = 204)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, emoji_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_EMOJIS, "emoji.manage_forbidden", "Manage emojis")?;
    let emoji = store::emojis::by_id(&state.db, &room_id, &emoji_id)
        .await?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    store::emojis::delete(&state.db, &room_id, &emoji_id).await?;
    remove_files(&state, &emoji.id, emoji.still_id.as_deref()).await;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "emoji.delete",
        &emoji_id,
        "",
        serde_json::json!({ "name": emoji.name }),
    )
    .await?;
    state.hub.room(&room_id, "emoji.update", serde_json::json!({ "room_id": room_id }));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ImageQuery {
    /// `1`: the still variant (first frame) of an animated emoji.
    pub still: Option<String>,
    /// The node hosting the emoji when it is not this one: this node serves its cached copy (fetched once).
    pub host: Option<String>,
}

impl ImageQuery {
    fn still(&self) -> bool {
        matches!(self.still.as_deref(), Some("1" | "true"))
    }
}

/// Only these types are ever sent for emoji files (anything else stored by mistake goes out as bytes).
fn image_type(mime: &str) -> HeaderValue {
    match mime {
        "image/webp" | "image/png" | "image/gif" | "image/jpeg" => {
            HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream"))
        }
        _ => HeaderValue::from_static("application/octet-stream"),
    }
}

/// A stored file as a strict, cacheable response.
pub fn file_response(data: Vec<u8>, content_type: HeaderValue, public: bool) -> Response {
    file_response_tagged(data, content_type, public, None)
}

/// Like [`file_response`] with an ETag (`etag`: the immutable id of the bytes).
pub fn file_response_tagged(data: Vec<u8>, content_type: HeaderValue, public: bool, etag: Option<&str>) -> Response {
    let mut resp = Response::new(Body::from(data));
    let h = resp.headers_mut();
    if let Some(tag) = etag.and_then(|t| HeaderValue::from_str(&format!("\"{t}\"")).ok()) {
        h.insert(header::ETAG, tag);
    }
    h.insert(header::CONTENT_TYPE, content_type);
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if public {
            "public, max-age=31536000, immutable"
        } else {
            "private, max-age=31536000, immutable"
        }),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    if public {
        // Readers of every node embed these files.
        h.insert("cross-origin-resource-policy", HeaderValue::from_static("cross-origin"));
    }
    resp
}

/// Emoji image (members). `?still=1`: the first frame of an animated emoji.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/emojis/{emoji_id}/image", security(("bearer" = [])), params(("room_id" = String, Path), ("emoji_id" = String, Path), ImageQuery), responses((status = 200, description = "Bild")))]
pub async fn image(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, emoji_id)): Path<(String, String)>,
    Query(q): Query<ImageQuery>,
) -> Result<Response, ApiError> {
    validate::ulid("emoji_id", &emoji_id)?;
    access::room_access(&state, &room_id, &auth.user).await?;
    let emoji = store::emojis::by_id(&state.db, &room_id, &emoji_id)
        .await?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    let (file, mime) = match (&emoji.still_id, q.still()) {
        (Some(still), true) => (still.as_str(), "image/webp"),
        _ => (emoji.id.as_str(), emoji.mime.as_str()),
    };
    let data = state
        .storage
        .read(file)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    Ok(file_response(data, image_type(mime), false))
}

/// The proxy for emojis and sounds of other nodes (`?host=`) answers without authentication and may fetch from
/// other nodes: limited per client address (`429`).
pub(crate) fn proxy_limit(state: &AppState, ip: &str) -> Result<(), ApiError> {
    state.media_proxy_limiter.check_all(&[format!("ip:{ip}")])
}

/// The image of any emoji of this node, room or personal, without authentication: content of
/// every conversation references emojis by id (`<:name:ID@host>`), and readers on every node load them from
/// here. Ids are random; nothing about rooms or owners is revealed. `?still=1`: the still variant.
#[utoipa::path(get, path = "/api/v1/emojis/{emoji_id}/image", params(("emoji_id" = String, Path), ImageQuery),
    responses((status = 200, description = "WebP (or PNG/GIF/JPEG of emojis uploaded before conversion)"), (status = 404, body = ProblemDetails)))]
pub async fn public_image(
    State(state): State<AppState>,
    crate::auth::ClientIp(ip): crate::auth::ClientIp,
    Path(emoji_id): Path<String>,
    Query(q): Query<ImageQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate::ulid("emoji_id", &emoji_id)?;
    if let Some(host) = q.host.as_deref().filter(|h| !h.eq_ignore_ascii_case(&state.config.domain)) {
        let kind =
            if q.still() { crate::emoji_cache::CacheKind::EmojiStill } else { crate::emoji_cache::CacheKind::Emoji };
        let tag = format!("{emoji_id}@{host}{}", if q.still() { "-still" } else { "" });
        if let Some(r) = not_modified(&headers, &tag) {
            return Ok(r);
        }
        proxy_limit(&state, &ip)?;
        let cached = crate::emoji_cache::get(&state, kind, host, &emoji_id).await?;
        return Ok(file_response_tagged(cached.data, image_type(&cached.mime), true, Some(&tag)));
    }
    let tag = format!("{emoji_id}{}", if q.still() { "-still" } else { "" });
    if let Some(r) = not_modified(&headers, &tag) {
        return Ok(r);
    }
    let (mime, id, still_id) = store::emojis::files_by_id(&state.db, &emoji_id)
        .await?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    let (file, mime) = match (&still_id, q.still()) {
        (Some(still), true) => (still.as_str(), "image/webp"),
        _ => (id.as_str(), mime.as_str()),
    };
    let data = state
        .storage
        .read(file)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    Ok(file_response_tagged(data, image_type(mime), true, Some(&tag)))
}

/// `304 Not Modified` when the client already has these immutable bytes (`If-None-Match`).
pub fn not_modified(headers: &HeaderMap, tag: &str) -> Option<Response> {
    let sent = headers.get(header::IF_NONE_MATCH)?.to_str().ok()?;
    let quoted = format!("\"{tag}\"");
    if sent.split(',').any(|t| t.trim() == quoted || t.trim() == "*") {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::NOT_MODIFIED;
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
        if let Ok(v) = HeaderValue::from_str(&quoted) {
            resp.headers_mut().insert(header::ETAG, v);
        }
        return Some(resp);
    }
    None
}

#[derive(Serialize, ToSchema)]
pub struct CachePurged {
    pub deleted: u64,
}

/// Purge the cached copies of another node's emoji or clip (node admins, abuse cases). The origin's
/// own deletion never reaches cached copies.
#[utoipa::path(delete, path = "/api/v1/admin/media-cache/{host}/{origin_id}", security(("bearer" = [])),
    params(("host" = String, Path), ("origin_id" = String, Path)), responses((status = 200, body = CachePurged), (status = 403, body = ProblemDetails)))]
pub async fn purge_cache(
    State(state): State<AppState>,
    admin: crate::auth::NodeAdmin,
    Path((host, origin_id)): Path<(String, String)>,
) -> Result<Json<CachePurged>, ApiError> {
    validate::ulid("origin_id", &origin_id)?;
    let deleted = crate::emoji_cache::purge(&state, &host, &origin_id).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.0.user.id),
        "media_cache.purge",
        &format!("{origin_id}@{host}"),
        "",
        serde_json::json!({ "host": host, "origin_id": origin_id, "deleted": deleted }),
    )
    .await?;
    Ok(Json(CachePurged { deleted }))
}

// ---------------------------------------------------------------- personal emojis

#[derive(Serialize, ToSchema)]
pub struct PersonalEmojis {
    pub items: Vec<store::emojis::UserEmoji>,
    /// Most personal emojis this user may have (entitlement `emoji.max_personal`; 0 = unlimited).
    pub max_personal: i64,
    /// Largest accepted upload in bytes.
    pub max_bytes: u64,
}

fn local_only(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    if auth.is_remote() || auth.user.domain != state.config.domain {
        return Err(crate::federation::guard::local_only());
    }
    Ok(())
}

/// The own personal emojis (home node).
#[utoipa::path(get, path = "/api/v1/users/me/emojis", security(("bearer" = [])), responses((status = 200, body = PersonalEmojis)))]
pub async fn list_personal(State(state): State<AppState>, auth: AuthUser) -> Result<Json<PersonalEmojis>, ApiError> {
    local_only(&state, &auth)?;
    Ok(Json(PersonalEmojis {
        items: store::emojis::user_list(&state.db, &auth.user.id).await?,
        max_personal: personal_limits(&state, &auth.user).await?.emojis.unwrap_or(0),
        max_bytes: state.config.emoji_max_bytes,
    }))
}

/// Upload a personal emoji: like room emojis (body = image, name in `Tavrn-Emoji-Name`, converted to WebP),
/// at most `TAVRN_EMOJI_MAX_PERSONAL` per user (`403 emoji.limit`).
#[utoipa::path(post, path = "/api/v1/users/me/emojis", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 201, body = store::emojis::UserEmoji), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn create_personal(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<store::emojis::UserEmoji>), ApiError> {
    local_only(&state, &auth)?;
    let name = emoji_name(&headers)?;
    check_upload(&state, &headers, &body)?;
    if let Some(max) = personal_limits(&state, &auth.user).await?.emojis
        && store::emojis::user_count(&state.db, &auth.user.id).await? >= max
    {
        return Err(ApiError::Forbidden { code: "emoji.limit", detail: format!("At most {max} personal emojis") });
    }
    let stored = convert_and_store(&state, body).await?;
    match store::emojis::user_insert(&state.db, &auth.user.id, &name, &stored.files()).await {
        Ok(e) => Ok((StatusCode::CREATED, Json(e))),
        Err(e) => {
            stored.remove(&state).await;
            Err(e)
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RenameEmoji {
    pub name: String,
}

/// Rename a personal emoji (readers keep finding it: tokens name it by id).
#[utoipa::path(patch, path = "/api/v1/users/me/emojis/{emoji_id}", security(("bearer" = [])), params(("emoji_id" = String, Path)),
    request_body = RenameEmoji, responses((status = 200, body = store::emojis::UserEmoji), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn rename_personal(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(emoji_id): Path<String>,
    Json(req): Json<RenameEmoji>,
) -> Result<Json<store::emojis::UserEmoji>, ApiError> {
    local_only(&state, &auth)?;
    let name = req.name.trim().to_ascii_lowercase();
    if !valid_emoji_name(&name) {
        return Err(bad("emoji.name_invalid", "Name: 2–32 characters of a-z, 0-9 and _"));
    }
    if !store::emojis::user_rename(&state.db, &auth.user.id, &emoji_id, &name).await? {
        return Err(access::not_found("Emoji", "emoji.not_found"));
    }
    store::emojis::user_emoji(&state.db, &auth.user.id, &emoji_id)
        .await?
        .map(Json)
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))
}

/// Delete a personal emoji (messages that used it show its name).
#[utoipa::path(delete, path = "/api/v1/users/me/emojis/{emoji_id}", security(("bearer" = [])), params(("emoji_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_personal(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(emoji_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    local_only(&state, &auth)?;
    let emoji = store::emojis::user_emoji(&state.db, &auth.user.id, &emoji_id)
        .await?
        .ok_or_else(|| access::not_found("Emoji", "emoji.not_found"))?;
    store::emojis::user_delete(&state.db, &auth.user.id, &emoji.id).await?;
    remove_files(&state, &emoji.id, emoji.still_id.as_deref()).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct GifQuery {
    /// Search term; empty = trending
    pub q: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct GifResults {
    pub provider: String,
    pub results: Vec<Gif>,
}

/// GIF search through the provider the node configured (Giphy or Tenor).
#[utoipa::path(get, path = "/api/v1/gifs", security(("bearer" = [])), params(GifQuery), responses((status = 200, body = GifResults), (status = 404, body = ProblemDetails)))]
pub async fn gifs(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(q): Query<GifQuery>,
) -> Result<Json<GifResults>, ApiError> {
    let client =
        state.gifs.as_ref().ok_or_else(|| ApiError::NotFound { code: "gif.disabled", what: "GIF search".into() })?;
    let query = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = query
        && s.chars().count() > 100
    {
        return Err(bad("gif.query_too_long", "Search term too long"));
    }
    let results = client.search(query, q.limit.unwrap_or(24)).await?;
    Ok(Json(GifResults {
        provider: serde_json::to_value(client.provider())
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default(),
        results,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn emoji_names() {
        assert!(super::valid_emoji_name("pogchamp"));
        assert!(super::valid_emoji_name("gg_wp2"));
        assert!(!super::valid_emoji_name("a"));
        assert!(!super::valid_emoji_name("Groß"));
        assert!(!super::valid_emoji_name("a-b"));
    }
}
