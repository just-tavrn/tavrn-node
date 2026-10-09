// SPDX-License-Identifier: AGPL-3.0-only
//! Categories, channels and permission overrides.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    models::{CHANNEL_KINDS, Category, Channel, PermissionOverride},
    permissions as p, store,
    validate::{self, bad},
};

#[derive(Deserialize, ToSchema)]
pub struct CreateCategoryRequest {
    pub name: String,
    pub position: Option<i64>,
}

/// Create a category (`manage_channels`).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/categories", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = CreateCategoryRequest, responses((status = 201, body = Category), (status = 403, body = ProblemDetails)))]
pub async fn create_category(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<(StatusCode, Json<Category>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let name = validate::name("name", &req.name, 100)?;
    let position = req.position.unwrap_or(store::rooms::categories(&state.db, &room_id).await?.len() as i64);
    let id = store::rooms::create_category(&state.db, &room_id, &name, position).await?;
    let category = Category { id, room_id: room_id.clone(), name, position, system_name: None, no_bots: 0 };
    state.hub.room(&room_id, "category.create", &category);
    Ok((StatusCode::CREATED, Json(category)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateCategoryRequest {
    pub name: Option<String>,
    pub position: Option<i64>,
    /// "No bots" for every channel in the category (APPLICATIONS.md §3.5); also needs `manage_room`.
    pub no_bots: Option<bool>,
}

/// Update a category.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/categories/{category_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("category_id" = String, Path)), request_body = UpdateCategoryRequest, responses((status = 200, body = Category)))]
pub async fn update_category(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, category_id)): Path<(String, String)>,
    Json(req): Json<UpdateCategoryRequest>,
) -> Result<Json<Category>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let name = req.name.as_deref().map(|n| validate::name("name", n, 100)).transpose()?;
    if req.no_bots.is_some() {
        access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
        crate::bot_channels::refuse_bots(&auth.user)?;
    }
    if !store::rooms::update_category(&state.db, &room_id, &category_id, name.as_deref(), req.position).await? {
        return Err(access::not_found("Category", "category.not_found"));
    }
    if let Some(value) = req.no_bots {
        store::applications::set_no_bots(&state.db, "category", &room_id, &category_id, value).await?;
        let channels: Vec<_> = store::rooms::channels(&state.db, &room_id)
            .await?
            .into_iter()
            .filter(|c| c.category_id.as_deref() == Some(category_id.as_str()))
            .collect();
        no_bots_changed(&state, &room_id, &auth.user.id, "category.no_bots", &category_id, value, &channels).await?;
    }
    let category = store::rooms::categories(&state.db, &room_id)
        .await?
        .into_iter()
        .find(|c| c.id == category_id)
        .ok_or_else(|| access::not_found("Category", "category.not_found"))?;
    state.hub.room(&room_id, "category.update", &category);
    Ok(Json(category))
}

/// After a "no bots" flag changed: audit, `mls.remove_needed` for the bot leaves when it was set, and
/// `channel.update` for the channels whose effective flag may have changed.
async fn no_bots_changed(
    state: &AppState,
    room_id: &str,
    actor_id: &str,
    action: &str,
    target: &str,
    value: bool,
    channels: &[crate::models::ChannelRow],
) -> Result<(), ApiError> {
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(actor_id),
        action,
        target,
        "",
        serde_json::json!({ "value": value }),
    )
    .await?;
    if value {
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        crate::e2ee::bots_excluded(state, room_id, &ids).await?;
    }
    for c in channels {
        if let Some(fresh) = store::rooms::channel_by_id(&state.db, &c.id).await? {
            state.hub.room(room_id, "channel.update", fresh.to_api());
        }
    }
    Ok(())
}

/// Delete a category; its channels remain, without a category.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/categories/{category_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("category_id" = String, Path)), responses((status = 204)))]
pub async fn delete_category(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, category_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    if !store::rooms::delete_category(&state.db, &room_id, &category_id).await? {
        return Err(access::not_found("Category", "category.not_found"));
    }
    state.hub.room(&room_id, "category.delete", serde_json::json!({ "room_id": room_id, "id": category_id }));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct CreateChannelRequest {
    /// text | voice | announcement | forum | files
    pub kind: String,
    pub name: String,
    pub topic: Option<String>,
    pub category_id: Option<String>,
    pub position: Option<i64>,
    /// Can be switched off only for text/announcement/forum. DMs and voice are always encrypted.
    pub encrypted: Option<bool>,
    pub bitrate_kbps: Option<i64>,
    pub user_limit: Option<i64>,
}

fn files_never_encrypted() -> ApiError {
    bad("channel.files_unencrypted", "Files channels are never end-to-end encrypted")
}

/// The welcome channel is fixed: no renaming, moving, deleting (only its topic and overrides change).
fn system_protected() -> ApiError {
    bad("channel.system_protected", "The welcome channel cannot be renamed, moved or deleted")
}

fn channel_name(kind: &str, name: &str) -> Result<String, ApiError> {
    let name = validate::name("name", name, 100)?;
    if kind == "voice" { Ok(name) } else { Ok(name.to_lowercase().replace(' ', "-")) }
}

/// Validates a voice channel's bitrate and user limit. `new_bitrate`: the bitrate is being set, so the node's
/// cap applies; a stored bitrate above a cap the operator lowered later stays (the join caps it).
fn check_voice_limits(
    state: &AppState,
    bitrate: i64,
    new_bitrate: bool,
    user_limit: i64,
) -> Result<(i64, i64), ApiError> {
    let max = i64::from(state.config.voice_max_bitrate_kbps);
    if new_bitrate && bitrate > max {
        return Err(bad("channel.bitrate_too_high", format!("This node allows at most {max} kbit/s")));
    }
    Ok((validate::range("bitrate_kbps", bitrate, 8, 512)?, validate::range("user_limit", user_limit, 0, 99)?))
}

/// Create a channel (`manage_channels`).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = CreateChannelRequest, responses((status = 201, body = Channel), (status = 403, body = ProblemDetails)))]
pub async fn create_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<Channel>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let kind = validate::one_of("kind", &req.kind, CHANNEL_KINDS)?;
    let name = channel_name(&kind, &req.name)?;
    let topic = validate::text("topic", req.topic.as_deref().unwrap_or(""), 0, 1024)?;
    if let Some(cat) = &req.category_id
        && !store::rooms::category_exists(&state.db, &room_id, cat).await?
    {
        return Err(bad("category.not_found", "This category does not exist in this room"));
    }
    let encrypted = match (kind.as_str(), req.encrypted) {
        // Files channels are never end-to-end encrypted: no MLS group, a banner instead.
        ("files", Some(true)) => return Err(files_never_encrypted()),
        ("files", _) => false,
        ("voice", Some(false)) => {
            return Err(bad("channel.voice_always_encrypted", "Voice channels are always encrypted"));
        }
        ("voice", _) => true,
        (_, Some(e)) => e,
        _ => store::rooms::DEFAULT_CHANNEL_ENCRYPTED,
    };
    if kind == "files" && !crate::routes::files::enabled_for(&state, &access.room).await? {
        return Err(ApiError::Forbidden {
            code: "files.disabled",
            detail: "Files channels are not available for this room".into(),
        });
    }
    if kind == "voice" && !state.config.voice_enabled {
        return Err(ApiError::Forbidden {
            code: "voice.disabled",
            detail: "Voice is switched off on this node".into(),
        });
    }
    // 64 kbit/s by default, never more than the node allows.
    let default_bitrate =
        i64::from(crate::config::DEFAULT_CHANNEL_BITRATE_KBPS.min(state.config.voice_max_bitrate_kbps));
    let (bitrate_kbps, user_limit) =
        check_voice_limits(&state, req.bitrate_kbps.unwrap_or(default_bitrate), true, req.user_limit.unwrap_or(0))?;
    let position = req.position.unwrap_or(store::rooms::channels(&state.db, &room_id).await?.len() as i64);
    let id = store::rooms::create_channel(
        &state.db,
        &room_id,
        store::rooms::NewChannel {
            kind: &kind,
            name: &name,
            topic: &topic,
            category_id: req.category_id.as_deref(),
            position,
            encrypted,
            bitrate_kbps,
            user_limit,
        },
    )
    .await?;
    let channel = store::rooms::channel_by_id(&state.db, &id)
        .await?
        .ok_or_else(|| access::not_found("Channel", "channel.not_found"))?
        .to_api();
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "channel.create",
        &id,
        "",
        serde_json::json!({ "name": name, "kind": kind, "encrypted": encrypted }),
    )
    .await?;
    state.hub.room(&room_id, "channel.create", &channel);
    Ok((StatusCode::CREATED, Json(channel)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateChannelRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    #[serde(default, with = "crate::serde_with_double_option")]
    pub category_id: Option<Option<String>>,
    pub position: Option<i64>,
    /// Deprecated and ignored (protocol permissions.md "Changes", 2026-10-09): overrides are layered, a channel
    /// always inherits its category's overrides underneath its own. Accepted for one release, then unknown.
    #[schema(deprecated)]
    pub sync_with_category: Option<bool>,
    pub slowmode_secs: Option<i64>,
    pub bitrate_kbps: Option<i64>,
    pub user_limit: Option<i64>,
    /// Switching applies to new messages only and is recorded in the audit log.
    pub encrypted: Option<bool>,
    /// "No bots" for this channel (APPLICATIONS.md §3.5); also needs `manage_room`.
    pub no_bots: Option<bool>,
    /// Encrypted channels of a `per_channel` room: bots may join this channel's group (APPLICATIONS.md §3.5; the
    /// `no_bots` flags still win). Also needs `manage_room`; never a bot.
    pub bots_allowed: Option<bool>,
    /// History for new members (`since_join`, `days:<n>`, `all`; ENCRYPTION.md §7b). Audit-logged; a narrower
    /// value does not revoke keys already shared.
    pub history_for_new_members: Option<String>,
    /// Threads without a message for this many minutes are archived (60–43200; PROTOCOL.md §7e).
    pub auto_archive_minutes: Option<i64>,
    /// Forum channels: the complete new tag list (at most 20; entries without `id` are new tags). Audit-logged.
    pub tags: Option<Vec<crate::threads::TagInput>>,
}

/// Update a channel (`manage_channels`).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/channels/{channel_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = UpdateChannelRequest, responses((status = 200, body = Channel)))]
pub async fn update_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Json(req): Json<UpdateChannelRequest>,
) -> Result<Json<Channel>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let current = access::channel_in_room(&state, &room_id, &channel_id).await?;
    if current.kind == "system"
        && (req.name.is_some()
            || req.category_id.is_some()
            || req.position.is_some()
            || req.slowmode_secs.is_some()
            || req.bitrate_kbps.is_some()
            || req.user_limit.is_some()
            || req.encrypted.is_some()
            || req.bots_allowed.is_some()
            || req.history_for_new_members.is_some()
            || req.auto_archive_minutes.is_some()
            || req.tags.is_some())
    {
        return Err(system_protected());
    }
    let auto_archive = req
        .auto_archive_minutes
        .map(|m| {
            validate::range(
                "auto_archive_minutes",
                m,
                crate::threads::MIN_AUTO_ARCHIVE_MINUTES,
                crate::threads::MAX_AUTO_ARCHIVE_MINUTES,
            )
        })
        .transpose()?;
    let tags = req.tags.as_deref().map(|t| crate::threads::check_channel_tags(&current, t)).transpose()?;
    let history_policy = req.history_for_new_members.as_deref().map(crate::history::validate).transpose()?;
    let name = req.name.as_deref().map(|n| channel_name(&current.kind, n)).transpose()?;
    let topic = req.topic.as_deref().map(|t| validate::text("topic", t, 0, 1024)).transpose()?;
    if let Some(Some(cat)) = &req.category_id
        && !store::rooms::category_exists(&state.db, &room_id, cat).await?
    {
        return Err(bad("category.not_found", "This category does not exist in this room"));
    }
    let slowmode = req.slowmode_secs.map(|s| validate::range("slowmode_secs", s, 0, 6 * 3600)).transpose()?;
    let (bitrate, user_limit) = match (req.bitrate_kbps, req.user_limit) {
        (None, None) => (None, None),
        (b, u) => {
            let (b2, u2) = check_voice_limits(
                &state,
                b.unwrap_or(current.bitrate_kbps),
                b.is_some(),
                u.unwrap_or(current.user_limit),
            )?;
            (Some(b2), Some(u2))
        }
    };
    if current.kind == "files" && req.encrypted == Some(true) {
        return Err(files_never_encrypted());
    }
    if current.kind == "voice" && req.encrypted == Some(false) {
        return Err(bad("channel.voice_always_encrypted", "Voice channels are always encrypted"));
    }
    if req.no_bots.is_some() || req.bots_allowed.is_some() {
        access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
        // Bots never decide who may read along (APPLICATIONS.md §3.5).
        crate::bot_channels::refuse_bots(&auth.user)?;
    }
    store::rooms::update_channel(
        &state.db,
        &channel_id,
        store::rooms::ChannelUpdate {
            name: name.as_deref(),
            topic: topic.as_deref(),
            category_id: req.category_id.as_ref().map(|c| c.as_deref()),
            position: req.position,
            slowmode_secs: slowmode,
            bitrate_kbps: bitrate,
            user_limit,
            encrypted: req.encrypted,
        },
    )
    .await?;
    if let Some(value) = req.no_bots
        && value != (current.no_bots != 0)
    {
        store::applications::set_no_bots(&state.db, "channel", &room_id, &channel_id, value).await?;
        // `channel.update` follows below.
        no_bots_changed(&state, &room_id, &auth.user.id, "channel.no_bots", &channel_id, value, &[]).await?;
        if value {
            crate::e2ee::bots_excluded(&state, &room_id, std::slice::from_ref(&channel_id)).await?;
        }
    }
    if let Some(value) = req.bots_allowed {
        crate::bot_channels::set_channel_setting(&state, &room_id, &auth.user, &current, value).await?;
    }
    if let Some(minutes) = auto_archive {
        store::threads::set_auto_archive(&state.db, &channel_id, minutes).await?;
    }
    if let Some(tags) = &tags {
        let json = serde_json::to_string(tags).map_err(|e| ApiError::Internal(e.into()))?;
        store::threads::set_forum_tags(&state.db, &channel_id, &json).await?;
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "channel.tags",
            &channel_id,
            "",
            serde_json::json!({ "tags": tags }),
        )
        .await?;
    }
    if let Some(policy) = history_policy {
        let before = crate::history::Policy::of(current.history_for_new_members.as_deref());
        if policy != before {
            store::history::set_policy(&state.db, &channel_id, &policy.to_string()).await?;
            store::rooms::audit(
                &state.db,
                Some(&room_id),
                Some(&auth.user.id),
                "channel.history_policy",
                &channel_id,
                "",
                serde_json::json!({ "from": before.to_string(), "to": policy.to_string() }),
            )
            .await?;
        }
    }
    let channel = store::rooms::channel_by_id(&state.db, &channel_id)
        .await?
        .ok_or_else(|| access::not_found("Channel", "channel.not_found"))?
        .to_api();
    if let Some(enc) = req.encrypted
        && enc != (current.encrypted != 0)
    {
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "channel.encryption",
            &channel_id,
            "",
            serde_json::json!({ "encrypted": enc }),
        )
        .await?;
        // Webhooks stay: sealed while encrypted, plaintext again otherwise (APPLICATIONS.md §6.1a).
        crate::webhooks::encryption_changed(&state, &room_id, &channel_id, enc, &auth.user).await?;
        // In a `per_channel` room the switch also opens or closes the channel to bots (APPLICATIONS.md §3.5).
        if !current.no_bots() && channel.no_bots_effective {
            crate::e2ee::bots_excluded(&state, &room_id, std::slice::from_ref(&channel_id)).await?;
        }
        // The node's search index holds only unencrypted channels: dropped now, or the
        // plaintext messages indexed again in the background when the channel is unencrypted again.
        if enc {
            crate::search::drop_conversation(&state.db, &channel_id).await?;
        } else {
            let (state, channel_id) = (state.clone(), channel_id.clone());
            tokio::spawn(async move {
                if let Err(e) = crate::search::reindex_conversation(&state, &channel_id).await {
                    tracing::warn!(error = %e, channel = channel_id, "search index of the channel not rebuilt");
                }
            });
        }
        let system = crate::routes::messages::system_message(
            &state,
            &channel,
            &auth.user,
            "system.encryption_changed",
            serde_json::json!({ "encrypted": enc, "by": auth.user.address() }),
        )
        .await?;
        state.hub.room(&room_id, "message.create", &system);
    }
    state.hub.room(&room_id, "channel.update", &channel);
    Ok(Json(channel))
}

/// Permanently delete a channel with its entire history (`manage_channels`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)), responses((status = 204)))]
pub async fn delete_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let channel = access::channel_in_room(&state, &room_id, &channel_id).await?;
    if channel.kind == "system" {
        return Err(system_protected());
    }
    // The files of every upload in the channel go with it (rows cascade, files are deleted here).
    let blob_ids = store::blobs::ids_of_conversation(&state.db, &channel_id).await?;
    let files = crate::routes::files::Cleanup::collect(&state, "channel_id", &channel_id).await?;
    store::rooms::delete_channel(&state.db, &channel_id).await?;
    for id in &blob_ids {
        state.storage.delete(id).await;
    }
    files.run(&state).await;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "channel.delete",
        &channel_id,
        "",
        serde_json::json!({ "name": channel.name }),
    )
    .await?;
    state.hub.room(&room_id, "channel.delete", serde_json::json!({ "room_id": room_id, "id": channel_id }));
    if channel.kind == "voice" {
        let (room, id) = (room_id.clone(), channel_id.clone());
        crate::voice::spawn_effect(&state, move |s| async move { crate::voice::close_channel(&s, &room, &id).await });
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct SetOverrideRequest {
    /// category | channel
    pub target_type: String,
    pub target_id: String,
    /// role | member
    pub subject_type: String,
    pub subject_id: String,
    pub allow: String,
    pub deny: String,
    /// Upload categories allowed on top of the roles' setting (absent: unchanged).
    pub upload_allow: Option<Vec<String>>,
    /// Upload categories denied (absent: unchanged).
    pub upload_deny: Option<Vec<String>>,
}

/// Overrides carry channel-scoped bits only (protocol permissions.md "Channel-scoped bits"): room-level bits are
/// granted through roles. `400 permissions.not_channel_scoped` with the refused names in `meta.names`.
fn check_channel_scoped(bits: u64) -> Result<(), ApiError> {
    let refused = bits & !p::CHANNEL_SCOPED;
    if refused == 0 {
        return Ok(());
    }
    Err(ApiError::BadRequestMeta {
        code: "permissions.not_channel_scoped",
        detail: format!(
            "These permissions are room-wide and cannot be set per channel: {}",
            p::names(refused).join(", ")
        ),
        meta: serde_json::json!({ "names": p::names(refused) }),
    })
}

/// Set an override, or remove it when allow = deny = 0 (`manage_roles`).
///
/// Overrides are layered (protocol permissions.md "Evaluation"): a category's overrides apply to the role base of
/// every channel in it, the channel's own on top; a bit an override neither allows nor denies inherits from the
/// layer below. Only channel-scoped bits are accepted (`400 permissions.not_channel_scoped`).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/overrides", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = SetOverrideRequest, responses((status = 200, body = Vec<PermissionOverride>), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn set_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<SetOverrideRequest>,
) -> Result<Json<Vec<PermissionOverride>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
    let target_type = validate::one_of("target_type", &req.target_type, &["category", "channel"])?;
    let subject_type = validate::one_of("subject_type", &req.subject_type, &["role", "member"])?;
    let exists = match target_type.as_str() {
        "category" => store::rooms::category_exists(&state.db, &room_id, &req.target_id).await?,
        _ => access::channel_in_room(&state, &room_id, &req.target_id).await.is_ok(),
    };
    if !exists {
        return Err(access::not_found("Target", "override.target_not_found"));
    }
    let allow = validate::permissions("allow", &req.allow)?;
    let deny = validate::permissions("deny", &req.deny)?;
    check_channel_scoped(allow | deny)?;
    match subject_type.as_str() {
        "role" => {
            let role = store::rooms::role_by_id(&state.db, &room_id, &req.subject_id)
                .await?
                .ok_or_else(|| access::not_found("Role", "role.not_found"))?;
            if role.is_everyone == 0 && !access.outranks(role.position) {
                return Err(ApiError::Forbidden {
                    code: "role.hierarchy",
                    detail: "The role is above your highest role".into(),
                });
            }
            if role.is_everyone != 0 {
                crate::routes::roles::check_everyone(allow)?;
            }
        }
        _ => {
            if store::rooms::member(&state.db, &room_id, &req.subject_id).await?.is_none() {
                return Err(access::not_found("Member", "member.not_found"));
            }
        }
    }
    if allow & deny != 0 {
        return Err(bad("override.conflict", "A permission cannot be allowed and denied at once"));
    }
    let upload_allow = req.upload_allow.as_deref().map(crate::routes::roles::upload_categories).transpose()?;
    let upload_deny = req.upload_deny.as_deref().map(crate::routes::roles::upload_categories).transpose()?;
    if upload_allow.unwrap_or(0) & upload_deny.unwrap_or(0) != 0 {
        return Err(bad("override.conflict", "An upload category cannot be allowed and denied at once"));
    }
    // Nobody can grant themselves more permissions through an override than they have.
    if !access.is_owner && !access.is_node_admin && allow & !access.room_perms != 0 {
        return Err(ApiError::Forbidden {
            code: "override.escalation",
            detail: "You can only grant permissions you have yourself".into(),
        });
    }
    store::rooms::set_override(
        &state.db,
        store::rooms::SetOverride {
            room_id: &room_id,
            target_type: &target_type,
            target_id: &req.target_id,
            subject_type: &subject_type,
            subject_id: &req.subject_id,
            allow,
            deny,
            upload_allow,
            upload_deny,
        },
    )
    .await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "override.set",
        &req.target_id,
        "",
        serde_json::json!({ "subject": req.subject_id, "allow": allow.to_string(), "deny": deny.to_string(), "upload_allow": req.upload_allow, "upload_deny": req.upload_deny }),
    )
    .await?;
    let overrides: Vec<PermissionOverride> = store::rooms::overrides_for(&state.db, &target_type, &req.target_id)
        .await?
        .iter()
        .map(|o| o.to_api())
        .collect();
    state.hub.room(&room_id, "override.update", serde_json::json!({ "room_id": room_id, "target_type": target_type, "target_id": req.target_id, "overrides": overrides }));
    Ok(Json(overrides))
}
