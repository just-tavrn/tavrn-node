// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of incoming webhooks (protocol/APPLICATIONS.md §6.1): management by holders of `manage_webhooks`
//! (bots additionally need the scope `webhooks:manage`, `applications::APP_ROUTES`) and the public execution
//! route, authenticated by the secret in its URL.

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access::{self, RoomAccess},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    media::MediaKind,
    models::{ChannelRow, Message},
    permissions as p, profile, store,
    store::webhooks::WebhookRow,
    validate::bad,
    webhooks::{self as wh, InboxKey, PublishInboxKeyRequest, Sealing, Webhook, WebhookPayload},
};

pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route("/rooms/{room_id}/channels/{channel_id}/webhooks", get(list_channel).post(create).layer(small()))
        .route("/rooms/{room_id}/webhooks", get(list_room))
        .route("/rooms/{room_id}/webhooks/{webhook_id}", axum::routing::patch(update).delete(delete).layer(small()))
        .route(
            "/rooms/{room_id}/webhooks/{webhook_id}/avatar",
            put(put_avatar).delete(delete_avatar).layer(DefaultBodyLimit::disable()),
        )
        .route("/rooms/{room_id}/webhooks/{webhook_id}/reset", post(reset))
        // The handler reads the body itself with the 32 KiB cap (`webhook.too_large`).
        .route("/webhooks/{webhook_id}/{secret}", post(execute).layer(DefaultBodyLimit::disable()))
        // Write-only webhooks in encrypted channels (APPLICATIONS.md §6.1a).
        .route("/webhooks/{webhook_id}/{secret}/inbox-key", get(inbox_key))
        .route("/conversations/{conversation_id}/inbox-key", put(publish_inbox_key).layer(small()))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_channel,
        create,
        list_room,
        update,
        delete,
        put_avatar,
        delete_avatar,
        reset,
        execute,
        inbox_key,
        publish_inbox_key
    ),
    components(schemas(
        Webhook,
        wh::InboxKey,
        wh::PublishInboxKeyRequest,
        wh::SealedPayload,
        CreatedWebhook,
        CreateWebhookRequest,
        UpdateWebhookRequest,
        WebhookPayload,
        crate::models::WebhookRef
    ))
)]
pub struct WebhooksApi;

fn manage_forbidden() -> ApiError {
    ApiError::Forbidden { code: "webhook.manage_forbidden", detail: "You lack the permission: manage webhooks".into() }
}

fn limit_reached(max: usize) -> ApiError {
    ApiError::Conflict {
        code: "webhook.limit",
        detail: format!("At most {max} webhooks here"),
        meta: json!({ "max": max }),
    }
}

/// The caller's permissions in a channel of the room.
async fn channel_perms(
    state: &AppState,
    access: &RoomAccess,
    channel: &ChannelRow,
    user_id: &str,
) -> Result<u64, ApiError> {
    access::channel_perms(state, access, channel, user_id).await
}

/// `manage_webhooks` in the channel (`403 webhook.manage_forbidden`).
async fn require_manage(
    state: &AppState,
    access: &RoomAccess,
    channel: &ChannelRow,
    user_id: &str,
) -> Result<u64, ApiError> {
    let perms = channel_perms(state, access, channel, user_id).await?;
    if !p::has(perms, p::MANAGE_WEBHOOKS) {
        return Err(manage_forbidden());
    }
    Ok(perms)
}

/// A channel webhooks can post in: a text, announcement or forum channel of the room (forum: into posts only).
/// Returns the sealing mode for it: `requested` (default `sender`) in encrypted channels, none in unencrypted ones
/// (where asking for one is an error).
fn check_target_channel(channel: &ChannelRow, requested: Option<&str>) -> Result<Option<Sealing>, ApiError> {
    if !wh::CHANNEL_KINDS.contains(&channel.kind.as_str()) {
        return Err(bad("channel.no_text", "Webhooks post into text, announcement and forum channels only"));
    }
    let requested = requested.map(Sealing::parse).transpose()?;
    if channel.encrypted == 0 {
        if requested.is_some() {
            return Err(bad("webhook.sealing_invalid", "sealing applies to encrypted channels only"));
        }
        return Ok(None);
    }
    Ok(Some(requested.unwrap_or(Sealing::Sender)))
}

/// `has_webhooks` of a channel may have changed: its members learn it with `channel.update`.
async fn channel_changed(state: &AppState, room_id: &str, channel_id: &str) -> Result<(), ApiError> {
    if let Some(channel) = store::rooms::channel_by_id(&state.db, channel_id).await? {
        state.hub.room(room_id, "channel.update", channel.to_api());
    }
    Ok(())
}

/// `allow_mentions_everyone` can only be set by someone holding `mention_everyone` in the channel.
fn check_everyone(perms: u64, allow: Option<bool>) -> Result<(), ApiError> {
    if allow == Some(true) && !p::has(perms, p::MENTION_EVERYONE) {
        return Err(ApiError::Forbidden {
            code: "message.mention_everyone_forbidden",
            detail: "Only members who may mention @everyone can allow it for a webhook".into(),
        });
    }
    Ok(())
}

/// Per-channel and per-room limits for one more webhook in `channel_id`.
async fn check_limits(state: &AppState, room_id: &str, channel_id: &str) -> Result<(), ApiError> {
    let (in_channel, in_room) = store::webhooks::counts(&state.db, room_id, channel_id).await?;
    let per_channel = state.config.webhooks_per_channel as usize;
    if in_channel as usize >= per_channel {
        return Err(limit_reached(per_channel));
    }
    if in_room as usize >= wh::MAX_PER_ROOM {
        return Err(limit_reached(wh::MAX_PER_ROOM));
    }
    Ok(())
}

/// The webhook `webhook_id` of the room (`404 webhook.not_found` otherwise).
async fn webhook_in_room(state: &AppState, room_id: &str, webhook_id: &str) -> Result<WebhookRow, ApiError> {
    if !crate::util::is_ulid(webhook_id) {
        return Err(wh::not_found());
    }
    store::webhooks::by_id(&state.db, webhook_id).await?.filter(|w| w.room_id == room_id).ok_or_else(wh::not_found)
}

/// Room access and the webhook, with `manage_webhooks` in the webhook's channel.
async fn managed(
    state: &AppState,
    auth: &AuthUser,
    room_id: &str,
    webhook_id: &str,
) -> Result<(RoomAccess, WebhookRow, ChannelRow, u64), ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    let webhook = webhook_in_room(state, room_id, webhook_id).await?;
    let channel = access::channel_in_room(state, room_id, &webhook.channel_id).await?;
    let perms = require_manage(state, &access, &channel, &auth.user.id).await?;
    Ok((access, webhook, channel, perms))
}

async fn audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    w: &WebhookRow,
    meta: serde_json::Value,
) -> Result<(), ApiError> {
    let mut meta = meta;
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("webhook_id".into(), json!(w.id));
        obj.entry("channel_id").or_insert(json!(w.channel_id));
    }
    store::rooms::audit(&state.db, Some(&w.room_id), Some(&auth.user.id), action, &w.id, "", meta).await
}

/// Tells the room's clients that a webhook's pseudo user changed (name, avatar), so author caches refresh.
async fn announce(state: &AppState, w: &WebhookRow) -> Result<(), ApiError> {
    if let Some(user) = store::users::by_id(&state.db, &w.user_id).await? {
        state.hub.room(&w.room_id, "user.update", json!({ "user": user.to_public() }));
    }
    Ok(())
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedWebhook {
    pub webhook: Webhook,
    /// The execution URL with the secret; shown only in this answer.
    pub url: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookRequest {
    /// 1–32 characters.
    pub name: String,
    /// Executions may mention @everyone (needs `mention_everyone`).
    #[serde(default)]
    pub allow_mentions_everyone: bool,
    /// Encrypted channels only: `sender` (default; the service seals to the inbox key) or `node` (the node seals
    /// the plaintext it receives and sees it once). Refused in unencrypted channels.
    pub sealing: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    /// Move to another text channel of the room (`manage_webhooks` there too).
    pub channel_id: Option<String>,
    pub allow_mentions_everyone: Option<bool>,
    /// Encrypted channels only: `sender` or `node` (APPLICATIONS.md §6.1a).
    pub sealing: Option<String>,
}

/// Webhooks of a channel (`manage_webhooks` in the channel).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/webhooks", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    responses((status = 200, body = Vec<Webhook>), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<Json<Vec<Webhook>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let channel = access::channel_in_room(&state, &room_id, &channel_id).await?;
    require_manage(&state, &access, &channel, &auth.user.id).await?;
    let mut out = Vec::new();
    for w in store::webhooks::of_channel(&state.db, &channel_id).await? {
        out.push(wh::view(&state, &w).await?);
    }
    Ok(Json(out))
}

/// Webhooks of every channel of the room (`manage_webhooks` at room level).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/webhooks", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Vec<Webhook>), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Webhook>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if !access.has(p::MANAGE_WEBHOOKS) {
        return Err(manage_forbidden());
    }
    // `manage_webhooks` is channel-scoped: only the webhooks of channels the caller can view and manage.
    let channels = store::rooms::channels(&state.db, &room_id).await?;
    let overrides = store::rooms::overrides_of_room(&state.db, &room_id).await?;
    let manages = |channel_id: &str| {
        channels.iter().find(|c| c.id == channel_id).is_some_and(|c| {
            p::has(
                access::channel_perms_with(&access, c, &overrides, &auth.user.id),
                p::VIEW_CHANNEL | p::MANAGE_WEBHOOKS,
            )
        })
    };
    let mut out = Vec::new();
    for w in store::webhooks::of_room(&state.db, &room_id).await? {
        if manages(&w.channel_id) {
            out.push(wh::view(&state, &w).await?);
        }
    }
    Ok(Json(out))
}

/// Create a webhook in an unencrypted text channel; the URL with its secret is returned once.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/webhooks", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = CreateWebhookRequest,
    responses((status = 201, body = CreatedWebhook), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<CreatedWebhook>), ApiError> {
    wh::require_enabled(&state)?;
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let channel = access::channel_in_room(&state, &room_id, &channel_id).await?;
    let perms = require_manage(&state, &access, &channel, &auth.user.id).await?;
    let sealing = check_target_channel(&channel, req.sealing.as_deref())?;
    let name = wh::validate_name(&req.name)?;
    check_everyone(perms, Some(req.allow_mentions_everyone))?;
    check_limits(&state, &room_id, &channel_id).await?;
    let id = crate::util::ulid();
    let (secret, hash) = wh::new_secret();
    let row = store::webhooks::create(
        &state.db,
        store::webhooks::NewWebhook {
            id: &id,
            room_id: &room_id,
            channel_id: &channel_id,
            name: &name,
            token_hash: &hash,
            allow_mentions_everyone: req.allow_mentions_everyone,
            domain: &state.config.domain,
            creator_id: &auth.user.id,
            creator_address: &auth.user.address(),
            sealing: sealing.map(Sealing::as_str),
        },
    )
    .await?;
    audit(&state, &auth, "webhook.create", &row, json!({ "name": name, "sealing": sealing.map(Sealing::as_str) }))
        .await?;
    channel_changed(&state, &room_id, &channel_id).await?;
    let url = wh::url(&state, &id, &secret);
    Ok((StatusCode::CREATED, Json(CreatedWebhook { webhook: wh::view(&state, &row).await?, url })))
}

/// Rename a webhook, move it to another channel or change `allow_mentions_everyone`.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/webhooks/{webhook_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("webhook_id" = String, Path)), request_body = UpdateWebhookRequest,
    responses((status = 200, body = Webhook), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, webhook_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<UpdateWebhookRequest>,
) -> Result<Json<Webhook>, ApiError> {
    let (access, webhook, current, mut perms) = managed(&state, &auth, &room_id, &webhook_id).await?;
    let name = req.name.as_deref().map(wh::validate_name).transpose()?;
    // A moved webhook keeps its mode where the new channel is encrypted (unless a new one is asked for).
    let requested = req.sealing.as_deref().or(webhook.sealing.as_deref().filter(|_| req.channel_id.is_some()));
    let (target, sealing) = match req.channel_id.as_deref().filter(|c| *c != webhook.channel_id) {
        Some(channel_id) => {
            let channel = access::channel_in_room(&state, &room_id, channel_id).await?;
            perms = require_manage(&state, &access, &channel, &auth.user.id).await?;
            let sealing = check_target_channel(&channel, if channel.encrypted != 0 { requested } else { None })?;
            check_limits(&state, &room_id, channel_id).await?;
            (Some(channel), Some(sealing))
        }
        None if req.sealing.is_some() => (None, Some(check_target_channel(&current, req.sealing.as_deref())?)),
        None => (None, None),
    };
    // Moving a webhook that may mention @everyone needs the right in the new channel as well.
    let keeps_everyone =
        target.is_some() && webhook.allow_mentions_everyone != 0 && req.allow_mentions_everyone != Some(false);
    check_everyone(perms, if keeps_everyone { Some(true) } else { req.allow_mentions_everyone })?;
    store::webhooks::update(
        &state.db,
        &webhook,
        store::webhooks::WebhookUpdate {
            name: name.as_deref(),
            channel_id: target.as_ref().map(|c| c.id.as_str()),
            allow_mentions_everyone: req.allow_mentions_everyone,
            sealing: sealing.map(|s| s.map(Sealing::as_str)),
        },
    )
    .await?;
    let changed: Vec<&str> = [
        ("name", name.is_some()),
        ("channel_id", target.is_some()),
        ("allow_mentions_everyone", req.allow_mentions_everyone.is_some()),
        ("sealing", sealing.is_some_and(|s| s.map(Sealing::as_str) != webhook.sealing.as_deref())),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect();
    let updated = webhook_in_room(&state, &room_id, &webhook_id).await?;
    audit(
        &state,
        &auth,
        "webhook.update",
        &updated,
        json!({ "changed": changed, "from_channel_id": webhook.channel_id }),
    )
    .await?;
    if name.is_some() {
        announce(&state, &updated).await?;
    }
    if target.is_some() {
        channel_changed(&state, &room_id, &webhook.channel_id).await?;
        channel_changed(&state, &room_id, &updated.channel_id).await?;
    }
    Ok(Json(wh::view(&state, &updated).await?))
}

/// Set the webhook's avatar (raw body, media pipeline of PROTOCOL.md §6b, avatar rules).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/avatar", security(("bearer" = [])),
    params(("room_id" = String, Path), ("webhook_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Webhook), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, webhook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Webhook>, ApiError> {
    let (_, webhook, _, _) = managed(&state, &auth, &room_id, &webhook_id).await?;
    let bytes = crate::routes::profile::read_upload(&state, &auth, &headers, body).await?;
    let stored = profile::convert_and_store(&state, MediaKind::Avatar, &webhook.user_id, bytes).await?;
    profile::set_user_media(&state, &webhook.user_id, MediaKind::Avatar, Some(&stored)).await?;
    audit(&state, &auth, "webhook.update", &webhook, json!({ "changed": ["avatar"] })).await?;
    announce(&state, &webhook).await?;
    Ok(Json(wh::view(&state, &webhook).await?))
}

/// Remove the webhook's avatar.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/avatar", security(("bearer" = [])),
    params(("room_id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 200, body = Webhook), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, webhook_id)): Path<(String, String)>,
) -> Result<Json<Webhook>, ApiError> {
    let (_, webhook, _, _) = managed(&state, &auth, &room_id, &webhook_id).await?;
    profile::set_user_media(&state, &webhook.user_id, MediaKind::Avatar, None).await?;
    audit(&state, &auth, "webhook.update", &webhook, json!({ "changed": ["avatar"] })).await?;
    announce(&state, &webhook).await?;
    Ok(Json(wh::view(&state, &webhook).await?))
}

/// A new secret; the old URL stops working at once. The new URL is returned once.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/reset", security(("bearer" = [])),
    params(("room_id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 200, body = CreatedWebhook), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn reset(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, webhook_id)): Path<(String, String)>,
) -> Result<Json<CreatedWebhook>, ApiError> {
    let (_, webhook, _, _) = managed(&state, &auth, &room_id, &webhook_id).await?;
    let (secret, hash) = wh::new_secret();
    store::webhooks::set_token_hash(&state.db, &webhook.id, &hash).await?;
    audit(&state, &auth, "webhook.reset", &webhook, json!({})).await?;
    let url = wh::url(&state, &webhook.id, &secret);
    Ok(Json(CreatedWebhook { webhook: wh::view(&state, &webhook).await?, url }))
}

/// Delete a webhook. Its messages stay (author: the disabled pseudo user).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/webhooks/{webhook_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("webhook_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, webhook_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let (_, webhook, _, _) = managed(&state, &auth, &room_id, &webhook_id).await?;
    store::webhooks::delete(&state.db, &webhook).await?;
    profile::set_user_media(&state, &webhook.user_id, MediaKind::Avatar, None).await?;
    audit(&state, &auth, "webhook.delete", &webhook, json!({ "name": webhook.name })).await?;
    channel_changed(&state, &room_id, &webhook.channel_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExecuteQuery {
    /// `true`: answer `200` with the created message instead of `204`.
    pub wait: Option<String>,
}

/// Post a message through a webhook (no authentication: the secret is part of the URL). Unknown ids and wrong
/// secrets both answer `404 webhook.not_found`. In encrypted channels: a `SealedPayload` for webhooks sealed by the
/// sender (`400 webhook.sealed_required` otherwise), the plaintext payload for webhooks sealed by the node;
/// `409 webhook.pending_key` until a member has published the channel's inbox key.
#[utoipa::path(post, path = "/api/v1/webhooks/{webhook_id}/{secret}", params(("webhook_id" = String, Path), ("secret" = String, Path), ExecuteQuery),
    request_body(content = WebhookPayload, description = "or a `SealedPayload` (webhooks sealed by the sender)"),
    responses((status = 204), (status = 200, body = Message), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn execute(
    State(state): State<AppState>,
    Path((webhook_id, secret)): Path<(String, String)>,
    Query(q): Query<ExecuteQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    wh::require_enabled(&state)?;
    let too_large = || ApiError::PayloadTooLarge {
        code: "webhook.too_large",
        detail: format!("Payloads have at most {} KiB", wh::MAX_PAYLOAD_BYTES / 1024),
        meta: json!({ "max_bytes": wh::MAX_PAYLOAD_BYTES }),
    };
    let declared =
        headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > wh::MAX_PAYLOAD_BYTES) {
        return Err(too_large());
    }
    let bytes = axum::body::to_bytes(body, wh::MAX_PAYLOAD_BYTES).await.map_err(|_| too_large())?;
    let webhook = wh::authenticate(&state, &webhook_id, &secret).await?;
    let message = wh::execute(&state, &webhook, &bytes).await?;
    if matches!(q.wait.as_deref(), Some("true" | "1")) {
        Ok((StatusCode::OK, Json(message)).into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

/// The inbox key a webhook sealed by the sender seals to (APPLICATIONS.md §6.1a; authenticated by the secret like
/// the execution route, `404 webhook.not_found` for unknown ids and wrong secrets alike).
#[utoipa::path(get, path = "/api/v1/webhooks/{webhook_id}/{secret}/inbox-key", params(("webhook_id" = String, Path), ("secret" = String, Path)),
    responses((status = 200, body = InboxKey), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn inbox_key(
    State(state): State<AppState>,
    Path((webhook_id, secret)): Path<(String, String)>,
) -> Result<Json<InboxKey>, ApiError> {
    wh::require_enabled(&state)?;
    let webhook = wh::authenticate(&state, &webhook_id, &secret).await?;
    Ok(Json(wh::inbox_key_of(&state, &webhook).await?))
}

/// Publish the inbox key of an epoch of an encrypted channel with webhooks (ENCRYPTION.md §5b): sent by the device
/// that committed the epoch, by the creator of a webhook and by members whose node has no key yet.
#[utoipa::path(put, path = "/api/v1/conversations/{conversation_id}/inbox-key", security(("bearer" = [])),
    params(("conversation_id" = String, Path)), request_body = PublishInboxKeyRequest,
    responses((status = 200, body = InboxKey), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn publish_inbox_key(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<PublishInboxKeyRequest>,
) -> Result<Json<InboxKey>, ApiError> {
    Ok(Json(wh::publish_inbox_key(&state, &auth, &conversation_id, &req).await?))
}
