// SPDX-License-Identifier: AGPL-3.0-only
//! Categories, channels and permission overrides.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ApiQuery as Query, ProblemDetails},
    models::{CHANNEL_KINDS, Category, Channel, ChannelRow, OverrideRow, PermissionOverride},
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
    ApiJson(req): ApiJson<CreateCategoryRequest>,
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
    ApiJson(req): ApiJson<UpdateCategoryRequest>,
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

/// The actor's permissions in a category: the layered evaluation (permissions.md) with the category's overrides on top of
/// the role base and no channel layer.
async fn category_perms(
    state: &AppState,
    access: &access::RoomAccess,
    category: &Category,
) -> Result<p::Perms, ApiError> {
    let no_bots = category.no_bots != 0 || access.room.no_bots != 0;
    if access.is_owner || access.is_node_admin {
        return Ok(p::cap_bot(p::ALL, &access.kind, no_bots, access.scopes.as_deref()));
    }
    let user_id = access.member.as_ref().map(|m| m.user_id.clone()).unwrap_or_default();
    let overrides = store::rooms::overrides_for(&state.db, "category", &category.id).await?;
    Ok(p::compute(&p::Input {
        user_id,
        is_owner: false,
        everyone_role_id: access.everyone.id.clone(),
        everyone_permissions: access.everyone.perms(),
        member_roles: access.member_roles_eval(),
        category_overrides: overrides.iter().map(|o| o.to_eval()).collect(),
        channel_overrides: Vec::new(),
        timed_out: access.member.as_ref().is_some_and(crate::models::MemberRow::is_timed_out),
        kind: access.kind.clone(),
        no_bots,
        scopes: access.scopes.clone(),
        system_channel: false,
        moved: false,
    }))
}

/// Delete a category; its channels remain, without a category, and keep what the category's overrides gave and
/// denied (its overrides are copied into each channel first, protocol permissions.md "Moving channels").
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/categories/{category_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("category_id" = String, Path)), responses((status = 204)))]
pub async fn delete_category(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, category_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    // Its channels lose the category's "no bots" flag: bots never decide that (APPLICATIONS.md §3.5).
    let category = store::rooms::categories(&state.db, &room_id).await?.into_iter().find(|c| c.id == category_id);
    if category.as_ref().is_some_and(|c| c.no_bots != 0) {
        crate::bot_channels::refuse_bots(&auth.user)?;
    }
    if category.is_none() {
        return Err(access::not_found("Category", "category.not_found"));
    }
    // Its channels keep what the category's overrides gave and denied (permissions.md "Moving channels").
    for channel in store::rooms::channels(&state.db, &room_id).await? {
        if channel.category_id.as_deref() == Some(category_id.as_str()) {
            leave_category(&state, &room_id, &auth.user, &channel, None).await?;
        }
    }
    if !store::rooms::delete_category(&state.db, &room_id, &category_id).await? {
        return Err(access::not_found("Category", "category.not_found"));
    }
    state.hub.room(&room_id, "category.delete", serde_json::json!({ "room_id": room_id, "id": category_id }));
    Ok(StatusCode::NO_CONTENT)
}

/// The channel's own overrides with its category's merged in, for a channel that leaves the category: per subject
/// the channel's setting of a bit wins, the category's fills the bits it leaves neutral; a bit the channel's
/// `@everyone` override decides is decided for everybody in the channel layer, so it drops from the category's.
fn merge_layers(
    category: &[OverrideRow],
    channel: &[OverrideRow],
    channel_id: &str,
    everyone_id: &str,
) -> Vec<OverrideRow> {
    let decided = |o: &OverrideRow| (o.allow | o.deny, o.upload_allow | o.upload_deny);
    let (everyone, everyone_uploads) =
        channel.iter().find(|o| o.subject_type == "role" && o.subject_id == everyone_id).map(decided).unwrap_or((0, 0));
    let mut merged: Vec<OverrideRow> = channel.to_vec();
    for c in category {
        let i = match merged.iter().position(|o| o.subject_type == c.subject_type && o.subject_id == c.subject_id) {
            Some(i) => i,
            None => {
                merged.push(OverrideRow {
                    id: String::new(),
                    target_type: "channel".into(),
                    target_id: channel_id.into(),
                    allow: 0,
                    deny: 0,
                    upload_allow: 0,
                    upload_deny: 0,
                    ..c.clone()
                });
                merged.len() - 1
            }
        };
        let o = &mut merged[i];
        let (bits, uploads) = decided(o);
        let open = !(bits | everyone);
        let open_uploads = !(uploads | everyone_uploads);
        o.allow |= c.allow & open;
        o.deny |= c.deny & open;
        o.upload_allow |= c.upload_allow & open_uploads;
        o.upload_deny |= c.upload_deny & open_uploads;
    }
    merged
}

/// A channel leaves its category (the category is deleted, or the channel moves to `to`): the category's overrides
/// are written into the channel's own ([`merge_layers`]) so that nothing becomes visible that was not; a member who
/// would still gain a permission (one layer cannot express every pair of layers) gets a deny of their own for it.
/// Audited as `channel.overrides_copied`; `override.update` for the channel (permissions.md "Moving channels").
async fn leave_category(
    state: &AppState,
    room_id: &str,
    actor: &crate::models::UserRow,
    channel: &ChannelRow,
    to: Option<&str>,
) -> Result<(), ApiError> {
    let Some(category_id) = channel.category_id.as_deref() else { return Ok(()) };
    let Some(view) = crate::visibility::load(state, room_id).await? else { return Ok(()) };
    let everyone_id = view.everyone_id().unwrap_or_default().to_string();
    let of = |target_type: &str, target_id: &str| -> Vec<OverrideRow> {
        view.overrides().iter().filter(|o| o.target_type == target_type && o.target_id == target_id).cloned().collect()
    };
    let own = of("channel", &channel.id);
    let mut merged = merge_layers(&of("category", category_id), &own, &channel.id, &everyone_id);
    let moved = ChannelRow { category_id: to.map(str::to_string), ..channel.clone() };
    let before = view.perms_with(channel, view.overrides());
    let with = |merged: &[OverrideRow]| -> Vec<OverrideRow> {
        let others = view.overrides().iter().filter(|o| !(o.target_type == "channel" && o.target_id == channel.id));
        others.cloned().chain(merged.iter().cloned()).collect()
    };
    let after = view.perms_with(&moved, &with(&merged));
    let mut denied = Vec::new();
    for (user_id, perms) in after {
        let gained = (perms & !before.get(&user_id).copied().unwrap_or(0) & p::CHANNEL_SCOPED) as i64;
        if gained == 0 {
            continue;
        }
        denied.push(user_id.clone());
        match merged.iter_mut().find(|o| o.subject_type == "member" && o.subject_id == user_id) {
            Some(o) => {
                o.allow &= !gained;
                o.deny |= gained;
            }
            None => merged.push(OverrideRow {
                id: String::new(),
                room_id: room_id.to_string(),
                target_type: "channel".into(),
                target_id: channel.id.clone(),
                subject_type: "member".into(),
                subject_id: user_id,
                allow: 0,
                deny: gained,
                upload_allow: 0,
                upload_deny: 0,
            }),
        }
    }
    let changed: Vec<&OverrideRow> = merged
        .iter()
        .filter(|m| {
            !own.iter().any(|o| {
                o.subject_type == m.subject_type
                    && o.subject_id == m.subject_id
                    && (o.allow, o.deny, o.upload_allow, o.upload_deny)
                        == (m.allow, m.deny, m.upload_allow, m.upload_deny)
            })
        })
        .collect();
    for m in &changed {
        store::rooms::set_override(
            &state.db,
            store::rooms::SetOverride {
                room_id,
                target_type: "channel",
                target_id: &channel.id,
                subject_type: &m.subject_type,
                subject_id: &m.subject_id,
                allow: m.allow as u64,
                deny: m.deny as u64,
                upload_allow: Some(m.upload_allow as u64),
                upload_deny: Some(m.upload_deny as u64),
            },
        )
        .await?;
    }
    if changed.is_empty() {
        return Ok(());
    }
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(&actor.id),
        "channel.overrides_copied",
        &channel.id,
        "",
        serde_json::json!({ "category_id": category_id, "to": to, "overrides": changed.len(), "members_denied": denied }),
    )
    .await?;
    let overrides: Vec<PermissionOverride> =
        store::rooms::overrides_for(&state.db, "channel", &channel.id).await?.iter().map(|o| o.to_api()).collect();
    state.hub.room(room_id, "override.update", serde_json::json!({ "room_id": room_id, "target_type": "channel", "target_id": channel.id, "overrides": overrides }));
    Ok(())
}

/// A channel without a category moves into `to`: the category's overrides apply underneath the channel's own from
/// then on. If that grants anybody more than today, the actor needs `manage_roles` in that category, as for setting
/// those overrides (`403 role.manage_forbidden`).
async fn enter_category(
    state: &AppState,
    access: &access::RoomAccess,
    channel: &ChannelRow,
    to: &str,
) -> Result<(), ApiError> {
    let Some(view) = crate::visibility::load(state, &access.room.id).await? else { return Ok(()) };
    let moved = ChannelRow { category_id: Some(to.to_string()), ..channel.clone() };
    let before = view.perms_with(channel, view.overrides());
    let grants = view
        .perms_with(&moved, view.overrides())
        .into_iter()
        .any(|(user_id, perms)| perms & !before.get(&user_id).copied().unwrap_or(0) & p::CHANNEL_SCOPED != 0);
    if !grants {
        return Ok(());
    }
    let category = store::rooms::categories(&state.db, &access.room.id)
        .await?
        .into_iter()
        .find(|c| c.id == to)
        .ok_or_else(|| bad("category.not_found", "This category does not exist in this room"))?;
    let held = category_perms(state, access, &category).await?;
    access::require(held, p::VIEW_CHANNEL | p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")
}

#[derive(Deserialize, ToSchema)]
pub struct CreateChannelRequest {
    /// text | voice | announcement | forum | files
    pub kind: String,
    pub name: String,
    pub topic: Option<String>,
    pub category_id: Option<String>,
    pub position: Option<i64>,
    /// Can be switched off only for text/announcement/forum. DMs and voice are always encrypted. Files channels:
    /// chosen here (default `true`) and fixed afterwards (FILES.md §1).
    pub encrypted: Option<bool>,
    pub bitrate_kbps: Option<i64>,
    pub user_limit: Option<i64>,
    /// `none` (default) or `adults_only` (PROTOCOL.md §5e); the room's gate is the minimum. Only an adult can set
    /// `adults_only`.
    pub age_gate: Option<String>,
}

fn encryption_fixed() -> ApiError {
    bad(
        "channel.encryption_fixed",
        "The encryption of a files channel is chosen when it is created; create a new channel and upload the files again",
    )
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
    ApiJson(req): ApiJson<CreateChannelRequest>,
) -> Result<(StatusCode, Json<Channel>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let kind = validate::one_of("kind", &req.kind, CHANNEL_KINDS)?;
    let name = channel_name(&kind, &req.name)?;
    let age_gate = req.age_gate.as_deref().map(crate::age::validate_gate).transpose()?;
    if let Some(gate) = &age_gate {
        crate::age::require_adult_to_gate(&state, &auth.user, gate, "channel").await?;
    }
    let topic = validate::text("topic", req.topic.as_deref().unwrap_or(""), 0, 1024)?;
    if let Some(cat) = &req.category_id
        && !store::rooms::category_exists(&state.db, &room_id, cat).await?
    {
        return Err(bad("category.not_found", "This category does not exist in this room"));
    }
    let encrypted = match (kind.as_str(), req.encrypted) {
        // Files channels are end-to-end encrypted unless created without (FILES.md §1).
        ("files", e) => e.unwrap_or(true),
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
    if let Some(gate) = age_gate.as_deref().filter(|g| *g != crate::age::GATE_NONE) {
        store::rooms::set_channel_age_gate(&state.db, &id, gate).await?;
    }
    if kind == "files" {
        // A file share shows new members everything by default (FILES.md §8.7).
        store::history::set_policy(&state.db, &id, &crate::history::Policy::All.to_string()).await?;
    }
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
        serde_json::json!({ "name": name, "kind": kind, "encrypted": encrypted, "age_gate": channel.age_gate }),
    )
    .await?;
    state.hub.room(&room_id, "channel.create", &channel);
    Ok((StatusCode::CREATED, Json(channel)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateChannelRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    /// Voice channels: the status line (plain text, at most 128 characters after trimming, `""` clears it;
    /// VOICE.md §2a). Needs `voice_status` in the channel instead of `manage_channels` when it is the only field
    /// (`403 channel.status_forbidden`); refused on other kinds (`400 channel.status_not_voice`). Audited as
    /// `channel.voice_status`.
    pub status: Option<String>,
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
    /// `none` or `adults_only` (PROTOCOL.md §5e): the channel's own age gate; the room's gate stays the minimum.
    /// Only an adult can switch it on. Audited as `channel.age_gate`.
    pub age_gate: Option<String>,
}

/// The length limit of a voice channel's status line (VOICE.md §2a).
pub const STATUS_MAX_CHARS: usize = 128;

impl UpdateChannelRequest {
    /// `status` is the only field: the request is a status change (`voice_status`), not a channel edit.
    fn status_only(&self) -> bool {
        self.status.is_some()
            && self.name.is_none()
            && self.topic.is_none()
            && self.category_id.is_none()
            && self.position.is_none()
            && self.sync_with_category.is_none()
            && self.slowmode_secs.is_none()
            && self.bitrate_kbps.is_none()
            && self.user_limit.is_none()
            && self.encrypted.is_none()
            && self.no_bots.is_none()
            && self.bots_allowed.is_none()
            && self.history_for_new_members.is_none()
            && self.auto_archive_minutes.is_none()
            && self.tags.is_none()
            && self.age_gate.is_none()
    }
}

/// Update a channel (`manage_channels`). Moving it out of its category copies the category's overrides into the
/// channel; moving it into a category that grants more needs `manage_roles` there (protocol permissions.md "Moving
/// channels"). A request that carries only `status` sets a voice channel's status line and needs `voice_status`
/// in the channel instead (VOICE.md §2a).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/channels/{channel_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = UpdateChannelRequest, responses((status = 200, body = Channel), (status = 403, body = ProblemDetails)))]
pub async fn update_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<UpdateChannelRequest>,
) -> Result<Json<Channel>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let status_only = req.status_only();
    if !status_only {
        access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    }
    let current = access::channel_in_room(&state, &room_id, &channel_id).await?;
    // In the channel itself (permissions.md step 4; bots get nothing in "no bots" channels, APPLICATIONS.md §3.5).
    let perms = access::channel_perms(&state, &access, &current, &auth.user.id).await?;
    if !status_only {
        access::require(perms, p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    }
    // The status line of a voice channel (VOICE.md §2a): its own bit, also next to other fields.
    let status = match req.status.as_deref() {
        Some(_) if current.kind != "voice" => {
            return Err(bad("channel.status_not_voice", "Only voice channels carry a status"));
        }
        Some(text) => {
            access::require(perms, p::VOICE_STATUS, "channel.status_forbidden", "Set the voice channel status")?;
            let text = validate::text("status", text, 0, STATUS_MAX_CHARS)?;
            if text.contains('\n') {
                return Err(bad("validation.multiline", "status: a single line only"));
            }
            Some(text)
        }
        None => None,
    };
    let before = store::rooms::channels(&state.db, &room_id).await?;
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
    let age_gate = req.age_gate.as_deref().map(crate::age::validate_gate).transpose()?;
    if let Some(gate) = &age_gate {
        crate::age::require_adult_to_gate(&state, &auth.user, gate, "channel").await?;
    }
    let history_policy = req.history_for_new_members.as_deref().map(crate::history::validate).transpose()?;
    if current.kind == "files" && matches!(history_policy, Some(crate::history::Policy::Days(_))) {
        // A file share shows new members everything or nothing from before (FILES.md §8.7).
        return Err(bad("channel.history_policy_invalid", "Files channels share their history with all or since_join"));
    }
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
    if current.kind == "files" && req.encrypted.is_some_and(|e| e != (current.encrypted != 0)) {
        return Err(encryption_fixed());
    }
    if current.kind == "voice" && req.encrypted == Some(false) {
        return Err(bad("channel.voice_always_encrypted", "Voice channels are always encrypted"));
    }
    if req.no_bots.is_some() || req.bots_allowed.is_some() {
        access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
        // Bots never decide who may read along (APPLICATIONS.md §3.5).
        crate::bot_channels::refuse_bots(&auth.user)?;
    }
    if let Some(to) = &req.category_id
        && to.as_deref() != current.category_id.as_deref()
    {
        if current.category_id.is_some() {
            leave_category(&state, &room_id, &auth.user, &current, to.as_deref()).await?;
        } else if let Some(to) = to {
            enter_category(&state, &access, &current, to).await?;
        }
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
    // A move into a "no bots" category closes the channel to bots like the flag itself (APPLICATIONS.md §3.5).
    if req.category_id.is_some() {
        let moved: Vec<_> = before.iter().filter(|c| c.id == channel_id).cloned().collect();
        crate::bot_channels::effective_changed(&state, &room_id, &moved, Some(&channel_id)).await?;
    }
    if let Some(minutes) = auto_archive {
        store::threads::set_auto_archive(&state.db, &channel_id, minutes).await?;
    }
    if let Some(gate) = age_gate.filter(|g| *g != current.age_gate) {
        store::rooms::set_channel_age_gate(&state.db, &channel_id, &gate).await?;
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "channel.age_gate",
            &channel_id,
            "",
            serde_json::json!({ "age_gate": gate }),
        )
        .await?;
        if gate == crate::age::GATE_ADULTS {
            crate::e2ee::below_age_gate(&state, &room_id, std::slice::from_ref(&channel_id)).await?;
        }
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
    if let Some(status) = status.filter(|s| *s != current.status) {
        store::rooms::set_channel_status(&state.db, &channel_id, &status).await?;
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "channel.voice_status",
            &channel_id,
            "",
            serde_json::json!({ "status": status }),
        )
        .await?;
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

#[derive(Deserialize, IntoParams, Default)]
pub struct DeleteFilesQuery {
    /// Files channels on an external store that are not end-to-end encrypted: keep the objects on the store
    /// (FILES.md §9; ignored for encrypted channels, whose objects are unreadable without the channel's keys).
    #[serde(default)]
    pub keep_external: bool,
}

/// Permanently delete a channel with its entire history (`manage_channels`). The files of a files channel go
/// with it: stored on the node at once, on an external store in the background (FILES.md §9).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), DeleteFilesQuery), responses((status = 204)))]
pub async fn delete_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<DeleteFilesQuery>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    let channel = access::channel_in_room(&state, &room_id, &channel_id).await?;
    let perms = access::channel_perms(&state, &access, &channel, &auth.user.id).await?;
    access::require(perms, p::MANAGE_CHANNELS, "channel.manage_forbidden", "Manage channels")?;
    if channel.kind == "system" {
        return Err(system_protected());
    }
    // The files of every upload in the channel go with it (rows cascade, files are deleted here).
    let blob_ids = store::blobs::ids_of_conversation(&state.db, &channel_id).await?;
    let files = crate::routes::files::Cleanup::collect(&state, "channel_id", &channel_id, q.keep_external).await?;
    let kept = files.kept_objects();
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
        if channel.kind == "files" {
            serde_json::json!({ "name": channel.name, "keep_external": q.keep_external && kept > 0, "kept_objects": kept })
        } else {
            serde_json::json!({ "name": channel.name })
        },
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
    ApiJson(req): ApiJson<SetOverrideRequest>,
) -> Result<Json<Vec<PermissionOverride>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
    let target_type = validate::one_of("target_type", &req.target_type, &["category", "channel"])?;
    let subject_type = validate::one_of("subject_type", &req.subject_type, &["role", "member"])?;
    // The actor's permissions where the override applies: an override can only be set with `manage_roles` there,
    // and grants only what the actor holds there (permissions.md step 4 and "Hierarchy").
    // The upload categories the actor can use there bound those an override may hand out or take away.
    let overrides = store::rooms::overrides_of_room(&state.db, &room_id).await?;
    let held = match target_type.as_str() {
        "category" => {
            match store::rooms::categories(&state.db, &room_id).await?.into_iter().find(|c| c.id == req.target_id) {
                Some(category) => Some((
                    category_perms(&state, &access, &category).await?,
                    access::upload_categories_at(&access, Some(&category.id), None, &overrides, &auth.user.id),
                )),
                None => None,
            }
        }
        _ => match access::channel_in_room(&state, &room_id, &req.target_id).await {
            Ok(channel) => Some((
                access::channel_perms(&state, &access, &channel, &auth.user.id).await?,
                access::channel_upload_categories_with(&access, &channel, &overrides, &auth.user.id),
            )),
            Err(_) => None,
        },
    };
    let Some((held, held_uploads)) = held else {
        return Err(access::not_found("Target", "override.target_not_found"));
    };
    access::require(held, p::VIEW_CHANNEL | p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
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
            // Like roles: only members below the actor (or the actor themselves, within what they hold).
            if req.subject_id != auth.user.id {
                crate::routes::rooms::moderation_target(&state, &access, &req.subject_id).await?;
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
    // Nobody can grant more permissions through an override than they have, nor take away from others what they
    // do not hold themselves; the same for upload categories (permissions.md "Hierarchy"). Only what changes counts:
    // bits of the stored override (set by someone above) may stay while the actor edits the bits they hold.
    let stored = overrides.iter().find(|o| {
        o.target_type == target_type
            && o.target_id == req.target_id
            && o.subject_type == subject_type
            && o.subject_id == req.subject_id
    });
    let (old_allow, old_deny, old_up_allow, old_up_deny) =
        stored.map_or((0, 0, 0, 0), |o| (o.allow as u64, o.deny as u64, o.upload_allow as u64, o.upload_deny as u64));
    let changed = (allow ^ old_allow) | (deny ^ old_deny);
    let changed_uploads =
        (upload_allow.unwrap_or(old_up_allow) ^ old_up_allow) | (upload_deny.unwrap_or(old_up_deny) ^ old_up_deny);
    if !access.is_owner && !access.is_node_admin && (changed & !held != 0 || changed_uploads & !held_uploads != 0) {
        return Err(ApiError::Forbidden {
            code: "override.escalation",
            detail: "You can only grant or deny permissions and upload categories you have yourself".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn o(target_type: &str, subject_type: &str, subject_id: &str, allow: u64, deny: u64) -> OverrideRow {
        OverrideRow {
            id: String::new(),
            room_id: "r".into(),
            target_type: target_type.into(),
            target_id: if target_type == "channel" { "ch".into() } else { "cat".into() },
            subject_type: subject_type.into(),
            subject_id: subject_id.into(),
            allow: allow as i64,
            deny: deny as i64,
            upload_allow: 0,
            upload_deny: 0,
        }
    }

    fn bits(merged: &[OverrideRow], subject_id: &str) -> (u64, u64) {
        merged.iter().find(|o| o.subject_id == subject_id).map(|o| (o.allow as u64, o.deny as u64)).unwrap_or((0, 0))
    }

    #[test]
    fn the_channel_wins_per_subject_and_the_category_fills_the_rest() {
        let (v, s) = (p::VIEW_CHANNEL, p::SEND_MESSAGES);
        let category = [o("category", "role", "everyone", 0, v | s), o("category", "role", "staff", v, 0)];
        let channel = [o("channel", "role", "staff", s, v)];
        let merged = merge_layers(&category, &channel, "ch", "nobody");
        assert_eq!(bits(&merged, "everyone"), (0, v | s), "copied");
        assert_eq!(bits(&merged, "staff"), (s, v), "the channel's own deny of view stays");
        assert!(merged.iter().all(|o| o.target_type == "channel" && o.target_id == "ch"));
    }

    #[test]
    fn bits_the_channel_decides_for_everyone_drop_from_the_category() {
        let v = p::VIEW_CHANNEL;
        let category = [o("category", "role", "staff", v, 0), o("category", "member", "u1", v, 0)];
        let channel = [o("channel", "role", "everyone", 0, v)];
        let merged = merge_layers(&category, &channel, "ch", "everyone");
        assert_eq!(bits(&merged, "everyone"), (0, v));
        assert_eq!(bits(&merged, "staff"), (0, 0));
        assert_eq!(bits(&merged, "u1"), (0, 0));
    }
}
