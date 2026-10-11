// SPDX-License-Identifier: AGPL-3.0-only
//! Rooms: create, join, members, invites, bans, moderation, audit log.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    access::{self, RoomAccess},
    app::AppState,
    auth::AuthUser,
    config::RoomCreation,
    error::{ApiError, ApiJson, ProblemDetails},
    jwt,
    models::{AuditEntry, Ban, Category, Channel, Invite, Member, PermissionOverride, Role, Room, UserRow},
    permissions as p, store,
    store::messages::PurgeFilter,
    util::{self, now},
    validate::{self, bad},
    welcome::LeaveKind,
};

const JOIN_MODES: &[&str] = &["public", "invite"];

#[derive(Deserialize, ToSchema)]
pub struct CreateRoomRequest {
    pub name: String,
    pub description: Option<String>,
    /// public | invite (default)
    pub join_mode: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RoomDetail {
    #[serde(flatten)]
    pub room: Room,
    pub member_count: i64,
    pub categories: Vec<Category>,
    pub channels: Vec<Channel>,
    pub roles: Vec<Role>,
    pub overrides: Vec<PermissionOverride>,
    pub my_roles: Vec<String>,
    /// Room-wide permissions of the requester as a decimal string.
    pub my_permissions: String,
    pub is_owner: bool,
    /// Unread and mention counts of the channels the requester can view (members only).
    pub read_states: Vec<crate::store::messages::ReadState>,
}

pub(crate) async fn detail(state: &AppState, access: &RoomAccess) -> Result<RoomDetail, ApiError> {
    let db = &state.db;
    let id = &access.room.id;
    let mut channels = store::rooms::channels(db, id).await?;
    let overrides = store::rooms::overrides_of_room(db, id).await?;
    // Channels the requester cannot view are not listed (layered overrides, protocol permissions.md "Evaluation"),
    // for bots "no bots" zones included (APPLICATIONS.md §3.5). Owners, node admins and administrators see all.
    // Age-gated channels stay listed for users below the gate, without any permission in them (PROTOCOL.md §5e).
    let user_id = access.member.as_ref().map(|m| m.user_id.clone()).unwrap_or_default();
    let ungated = (!access.adult).then(|| RoomAccess { adult: true, ..access.clone() });
    let viewable = |a: &RoomAccess, c: &crate::models::ChannelRow| {
        p::has(access::channel_perms_with(a, c, &overrides, &user_id), p::VIEW_CHANNEL)
    };
    let visible: Vec<String> = channels.iter().filter(|c| viewable(access, c)).map(|c| c.id.clone()).collect();
    channels.retain(|c| visible.contains(&c.id) || ungated.as_ref().is_some_and(|a| viewable(a, c)));
    // A category is a container: it is listed when one of its channels is visible, or to those who manage channels.
    let mut categories = store::rooms::categories(db, id).await?;
    if !access.has(p::MANAGE_CHANNELS) {
        categories.retain(|cat| channels.iter().any(|c| c.category_id.as_deref() == Some(cat.id.as_str())));
    }
    let read_states = match &access.member {
        Some(member) => {
            let system: Vec<String> = channels.iter().filter(|c| c.kind == "system").map(|c| c.id.clone()).collect();
            let user = store::users::by_id(db, &member.user_id)
                .await?
                .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("member without user")))?;
            let settings = if user.domain == state.config.domain {
                Some(crate::notifications::load(db, &user.id).await?)
            } else {
                None
            };
            let role_ids: Vec<String> = access.member_roles.iter().map(|r| r.id.clone()).collect();
            let ctx = store::messages::ReadContext {
                role_ids: &role_ids,
                settings: settings.as_ref(),
                room_id: Some(id),
                system_channels: &system,
            };
            store::messages::read_states(db, &user.id, &user.address(), &visible, &member.joined_at, &ctx).await?
        }
        None => Vec::new(),
    };
    // Only the overrides of the listed channels and categories (PROTOCOL.md §6 "Audiences").
    let overrides = overrides
        .iter()
        .filter(|o| match o.target_type.as_str() {
            "category" => categories.iter().any(|c| c.id == o.target_id),
            _ => channels.iter().any(|c| c.id == o.target_id),
        })
        .map(|o| o.to_api())
        .collect();
    Ok(RoomDetail {
        room: access.room.clone(),
        member_count: store::rooms::member_count(db, id).await?,
        categories,
        channels: channels.iter().map(|c| c.to_api()).collect(),
        roles: store::rooms::roles(db, id).await?.iter().map(|r| r.to_api()).collect(),
        overrides,
        my_roles: access.member_roles.iter().map(|r| r.id.clone()).collect(),
        my_permissions: access.room_perms.to_string(),
        is_owner: access.is_owner,
        read_states,
    })
}

async fn may_create_room(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    if user.is_node_admin() {
        return Ok(());
    }
    let forbidden = |detail: &str| ApiError::Forbidden { code: "room.creation_forbidden", detail: detail.into() };
    match state.config.room_creation {
        RoomCreation::None => return Err(forbidden("Only admins may create rooms on this node")),
        RoomCreation::Invite => match store::users::room_creation_grant(&state.db, &user.id).await? {
            Some(n) if n > 0 => {}
            _ => return Err(forbidden("You need a grant from the node admin to create rooms")),
        },
        RoomCreation::Local | RoomCreation::Federated => {}
    }
    // `rooms.max_owned` (entitlements): node default `TAVRN_MAX_ROOMS_PER_USER`, 0 = unlimited.
    let max = crate::entitlements::Entitlements::load(state, Some(user), None)
        .await?
        .limit(crate::entitlements::ROOMS_MAX_OWNED);
    let owned = store::rooms::rooms_owned_count(&state.db, &user.id).await?;
    if let Some(max) = max
        && owned >= max
    {
        return Err(ApiError::ForbiddenMeta {
            code: "room.limit_reached",
            detail: format!("At most {max} rooms per user on this node"),
            meta: serde_json::json!({ "max": max }),
        });
    }
    Ok(())
}

/// Create a room (with @everyone role, default category, text and voice channel).
#[utoipa::path(post, path = "/api/v1/rooms", security(("bearer" = [])), request_body = CreateRoomRequest, responses((status = 201, body = RoomDetail), (status = 403, body = ProblemDetails)))]
pub async fn create_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateRoomRequest>,
) -> Result<(StatusCode, Json<RoomDetail>), ApiError> {
    may_create_room(&state, &auth.user).await?;
    let name = validate::name("name", &req.name, 100)?;
    let description = validate::text("description", req.description.as_deref().unwrap_or(""), 0, 1000)?;
    let join_mode = validate::one_of("join_mode", req.join_mode.as_deref().unwrap_or("invite"), JOIN_MODES)?;
    let room = store::rooms::create_room(
        &state.db,
        store::rooms::NewRoom {
            name: &name,
            description: &description,
            join_mode: &join_mode,
            owner_id: &auth.user.id,
        },
    )
    .await?;
    if state.config.room_creation == RoomCreation::Invite && !auth.user.is_node_admin() {
        store::users::consume_room_creation_grant(&state.db, &auth.user.id).await?;
    }
    store::rooms::audit(
        &state.db,
        Some(&room.id),
        Some(&auth.user.id),
        "room.create",
        &room.id,
        "",
        serde_json::json!({ "name": name }),
    )
    .await?;
    // The owner is the first member: open WebSockets of the owner subscribe to the room on this event
    // (otherwise they would miss its events until they reconnect), other devices refresh their lists.
    crate::subscriptions::room_event(
        &state,
        &room.id,
        "member.join",
        serde_json::json!({ "room_id": room.id, "user": auth.user.to_public() }),
    )
    .await;
    crate::welcome::joined(&state, &room, &auth.user).await;
    let access = access::room_access(&state, &room.id, &auth.user).await?;
    Ok((StatusCode::CREATED, Json(detail(&state, &access).await?)))
}

/// Rooms I am a member of.
#[utoipa::path(get, path = "/api/v1/rooms", security(("bearer" = [])), responses((status = 200, body = Vec<Room>)))]
pub async fn list_my_rooms(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<Room>>, ApiError> {
    Ok(Json(store::rooms::rooms_of_user(&state.db, &auth.user.id).await?))
}

#[derive(Serialize, ToSchema)]
pub struct PublicRoom {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon_blob_id: Option<String>,
    /// Icon paths on this node (see [`Room`]).
    pub icon: Option<String>,
    pub icon_still: Option<String>,
    pub icon_animated: bool,
    pub member_count: i64,
    /// `none` or `adults_only` (PROTOCOL.md §5e). Gated rooms are listed only to adults; invite previews carry the
    /// gate so clients can explain a refused join.
    pub age_gate: String,
}

impl PublicRoom {
    fn of(room: Room, member_count: i64) -> Self {
        Self {
            icon_animated: room.icon_animated != 0,
            icon: room.icon,
            icon_still: room.icon_still,
            icon_blob_id: room.icon_blob_id,
            id: room.id,
            name: room.name,
            description: room.description,
            member_count,
            age_gate: room.age_gate,
        }
    }
}

/// Public rooms of this node ("Discover"). Rooms with an age gate are listed only when the request carries the
/// session of an adult (the `Authorization` header is optional here; PROTOCOL.md §5e).
#[utoipa::path(get, path = "/api/v1/rooms/discover", responses((status = 200, body = Vec<PublicRoom>)))]
pub async fn discover_rooms(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<PublicRoom>>, ApiError> {
    let adult = crate::age::requester_is_adult(&state, &headers).await;
    let mut out = Vec::new();
    for r in store::rooms::public_rooms(&state.db, 100, adult).await? {
        let member_count = store::rooms::member_count(&state.db, &r.id).await?;
        out.push(PublicRoom::of(r, member_count));
    }
    Ok(Json(out))
}

/// Room with categories, channels, roles and own permissions.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}", security(("bearer" = [])), params(("room_id" = String, Path)), responses((status = 200, body = RoomDetail), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<RoomDetail>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    Ok(Json(detail(&state, &access).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateRoomRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rules: Option<String>,
    pub join_mode: Option<String>,
    /// List the room in the directory and on Discover (FEDERATION.md §7.3). Public rooms only; switching
    /// a room to `invite` removes it from the directory.
    pub discoverable: Option<bool>,
    /// "No bots" zone (APPLICATIONS.md §3.5): setting it removes every bot from the room and refuses new
    /// ones. Owner or `manage_room`.
    pub no_bots: Option<bool>,
    /// Bots in encrypted channels (APPLICATIONS.md §3.5): `per_channel` (every encrypted channel is closed to bots
    /// unless it sets `bots_allowed`) or `allowed`. Owner or `manage_room`; never a bot.
    pub bots_in_encrypted_channels: Option<String>,
    /// Delete attachments after this many days (1–36500; 0 = use the node's value). Effective is the
    /// shortest non-zero of this, the node value and room grants: a room can only shorten.
    pub attachment_retention_days: Option<i64>,
    /// Delete messages after this many days (1–36500; 0 = use the node's value, PROTOCOL.md §7f). Effective is the
    /// shorter non-zero of this and the node's `TAVRN_RETENTION_DAYS`: a room can only shorten.
    pub message_retention_days: Option<i64>,
    /// `none` or `adults_only` (PROTOCOL.md §5e): the room's age gate, the minimum of every channel. Only an adult can
    /// switch it on. Audited as `room.age_gate`.
    pub age_gate: Option<String>,
    /// History restore after a key reset (ENCRYPTION.md §7b): `request` (members may ask, default) or `off`.
    /// Owner or `manage_room`; never a bot.
    pub history_restore: Option<String>,
}

/// Change room settings (`manage_room`).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = UpdateRoomRequest, responses((status = 200, body = RoomDetail)))]
pub async fn update_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<UpdateRoomRequest>,
) -> Result<Json<RoomDetail>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    // Bots never decide who may read along (APPLICATIONS.md §3.5).
    if req.no_bots.is_some() || req.bots_in_encrypted_channels.is_some() || req.history_restore.is_some() {
        crate::bot_channels::refuse_bots(&auth.user)?;
    }
    let bots_setting =
        req.bots_in_encrypted_channels.as_deref().map(crate::bot_channels::validate_setting).transpose()?;
    let name = req.name.as_deref().map(|n| validate::name("name", n, 100)).transpose()?;
    let description = req.description.as_deref().map(|d| validate::text("description", d, 0, 1000)).transpose()?;
    let rules = req.rules.as_deref().map(|r| validate::text("rules", r, 0, 10_000)).transpose()?;
    let join_mode = req.join_mode.as_deref().map(|j| validate::one_of("join_mode", j, JOIN_MODES)).transpose()?;
    let was_listed = access.room.is_discoverable();
    let public = join_mode.as_deref().unwrap_or(&access.room.join_mode) == "public";
    if req.discoverable == Some(true) && !public {
        return Err(bad("room.discoverable_public_only", "Only public rooms can be listed in the directory"));
    }
    // A room that stops being public leaves the directory.
    let discoverable = if public { req.discoverable } else { Some(false) };
    let retention = req
        .attachment_retention_days
        .map(|d| validate::range("attachment_retention_days", d, 0, 36_500))
        .transpose()?;
    let message_retention =
        req.message_retention_days.map(|d| validate::range("message_retention_days", d, 0, 36_500)).transpose()?;
    let age_gate = req.age_gate.as_deref().map(crate::age::validate_gate).transpose()?;
    if let Some(gate) = &age_gate {
        crate::age::require_adult_to_gate(&state, &auth.user, gate, "room").await?;
    }
    let history_restore = req
        .history_restore
        .as_deref()
        .map(|v| validate::one_of("history_restore", v, crate::history::RESTORE_SETTINGS))
        .transpose()?;
    store::rooms::update_room(
        &state.db,
        &room_id,
        store::rooms::RoomUpdate {
            name: name.as_deref(),
            description: description.as_deref(),
            rules: rules.as_deref(),
            join_mode: join_mode.as_deref(),
            discoverable,
        },
    )
    .await?;
    if let Some(days) = retention {
        store::entitlements::set_room_retention(&state.db, &room_id, Some(days).filter(|d| *d > 0)).await?;
    }
    if let Some(days) = message_retention {
        store::rooms::set_message_retention(&state.db, &room_id, Some(days).filter(|d| *d > 0)).await?;
    }
    if let Some(value) = &history_restore {
        store::history::set_room_setting(&state.db, &room_id, value).await?;
    }
    let mut meta = serde_json::json!({});
    if let (Some(days), Some(obj)) = (retention, meta.as_object_mut()) {
        obj.insert("attachment_retention_days".into(), days.into());
    }
    if let (Some(days), Some(obj)) = (message_retention, meta.as_object_mut()) {
        obj.insert("message_retention_days".into(), days.into());
    }
    if let (Some(value), Some(obj)) = (history_restore, meta.as_object_mut()) {
        obj.insert("history_restore".into(), value.into());
    }
    store::rooms::audit(&state.db, Some(&room_id), Some(&auth.user.id), "room.update", &room_id, "", meta).await?;
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let listed = access.room.is_discoverable();
    if listed != was_listed {
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "room.discoverable",
            &room_id,
            "",
            serde_json::json!({ "discoverable": listed }),
        )
        .await?;
    }
    if listed != was_listed || (listed && (name.is_some() || description.is_some())) {
        crate::federation::announce::listing_changed(&state).await;
    }
    let access = match req.no_bots {
        Some(value) if value != (access.room.no_bots != 0) => {
            set_room_no_bots(&state, &access.room, &auth.user, value).await?;
            access::room_access(&state, &room_id, &auth.user).await?
        }
        _ => access,
    };
    let access = match bots_setting {
        Some(value) if value != access.room.bots_in_encrypted_channels => {
            crate::bot_channels::set_room_setting(&state, &access.room, &auth.user, value).await?;
            access::room_access(&state, &room_id, &auth.user).await?
        }
        _ => access,
    };
    let access = match age_gate {
        Some(gate) if gate != access.room.age_gate => {
            set_room_age_gate(&state, &access.room, &auth.user, &gate).await?;
            access::room_access(&state, &room_id, &auth.user).await?
        }
        _ => access,
    };
    state.hub.room(&room_id, "room.update", &access.room);
    Ok(Json(detail(&state, &access).await?))
}

/// Sets the room's age gate (PROTOCOL.md §5e): audited, every channel changes its effective gate (`channel.update`),
/// members below a new gate leave the encrypted groups and voice of the room.
async fn set_room_age_gate(state: &AppState, room: &Room, actor: &UserRow, gate: &str) -> Result<(), ApiError> {
    store::rooms::set_room_age_gate(&state.db, &room.id, gate).await?;
    store::rooms::audit(
        &state.db,
        Some(&room.id),
        Some(&actor.id),
        "room.age_gate",
        &room.id,
        "",
        serde_json::json!({ "age_gate": gate }),
    )
    .await?;
    let channels = store::rooms::channels(&state.db, &room.id).await?;
    if gate == crate::age::GATE_ADULTS {
        let ids: Vec<String> = channels.iter().map(|c| c.id.clone()).collect();
        crate::e2ee::below_age_gate(state, &room.id, &ids).await?;
    }
    for channel in channels {
        state.hub.room(&room.id, "channel.update", channel.to_api());
    }
    Ok(())
}

/// Sets the room-level "no bots" flag: every bot member is removed (uninstall, reason `no_bots`), and the
/// room's channels change their effective flag (`channel.update`).
async fn set_room_no_bots(state: &AppState, room: &Room, actor: &UserRow, value: bool) -> Result<(), ApiError> {
    store::applications::set_no_bots(&state.db, "room", &room.id, &room.id, value).await?;
    let mut removed = 0;
    if value {
        let room = store::rooms::room_by_id(&state.db, &room.id).await?.unwrap_or_else(|| room.clone());
        for bot in
            store::users::by_ids(&state.db, &store::applications::bot_member_ids(&state.db, &room.id).await?).await?
        {
            if crate::applications::remove_from_room(state, &room, &bot, "no_bots").await? {
                removed += 1;
            }
        }
    }
    store::rooms::audit(
        &state.db,
        Some(&room.id),
        Some(&actor.id),
        "room.no_bots",
        &room.id,
        "",
        serde_json::json!({ "value": value, "bots_removed": removed }),
    )
    .await?;
    for channel in store::rooms::channels(&state.db, &room.id).await? {
        state.hub.room(&room.id, "channel.update", channel.to_api());
    }
    Ok(())
}

/// Permanently delete a room (owner or node admin only).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}", security(("bearer" = [])), params(("room_id" = String, Path), crate::routes::channels::DeleteFilesQuery), responses((status = 204), (status = 403, body = ProblemDetails)))]
pub async fn delete_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Query(q): Query<crate::routes::channels::DeleteFilesQuery>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if !access.is_owner && !access.is_node_admin {
        return Err(ApiError::Forbidden {
            code: "room.owner_required",
            detail: "Only the owner can delete the room".into(),
        });
    }
    state.hub.room(&room_id, "room.delete", serde_json::json!({ "id": room_id }));
    crate::routes::profile::drop_room_icon(&state, &access.room).await;
    // Every file of the room goes right away: uploads (also encrypted ones and whiteboard shares),
    // custom emojis, soundboard clips and the members' per-room avatars. The rows cascade.
    let files = store::rooms::room_files(&state.db, &room_id).await?;
    let room_media = store::rooms::room_member_media(&state.db, &room_id).await?;
    let channel_files = crate::routes::files::Cleanup::collect(&state, "room_id", &room_id, q.keep_external).await?;
    let kept = channel_files.kept_objects();
    store::rooms::delete_room(&state.db, &room_id).await?;
    channel_files.run(&state).await;
    for id in &files {
        state.storage.delete(id).await;
    }
    for id in &room_media {
        if let Err(e) = crate::profile::delete_media(&state, id).await {
            tracing::warn!(error = %e, "room avatar not deleted");
        }
    }
    let room = room_id.clone();
    crate::voice::spawn_effect(&state, move |s| async move { crate::voice::close_room(&s, &room).await });
    if access.room.is_discoverable() {
        crate::federation::announce::listing_changed(&state).await;
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "room.delete",
        &room_id,
        "",
        serde_json::json!({ "name": access.room.name, "keep_external": q.keep_external && kept > 0, "kept_objects": kept }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Joining

#[derive(Deserialize, ToSchema, Default)]
pub struct JoinRequest {
    /// Must be `true` if the room has rules.
    #[serde(default)]
    pub accept_rules: bool,
}

/// Room or node ban of the user's address or domain, and for bots of their owner's (FEDERATION.md §3.2).
async fn banned(state: &AppState, room_id: &str, user: &UserRow) -> Result<bool, ApiError> {
    if store::rooms::is_banned(&state.db, Some(room_id), &user.address(), &user.domain).await? {
        return Ok(true);
    }
    match user.owner_id.as_deref() {
        Some(owner_id) if user.kind == "bot" => match store::users::by_id(&state.db, owner_id).await? {
            Some(owner) => store::rooms::is_banned(&state.db, Some(room_id), &owner.address(), &owner.domain).await,
            None => Ok(false),
        },
        _ => Ok(false),
    }
}

async fn join(state: &AppState, user: &UserRow, room: &Room, accept_rules: bool) -> Result<RoomDetail, ApiError> {
    if banned(state, &room.id, user).await? {
        return Err(ApiError::Forbidden { code: "room.banned", detail: "You are banned from this room".into() });
    }
    // Age gate (PROTOCOL.md §5e): also with an invite link or a direct invite; existing members stay.
    if room.age_gate == crate::age::GATE_ADULTS
        && store::rooms::member(&state.db, &room.id, &user.id).await?.is_none()
        && !crate::age::is_adult(state, user).await?
    {
        return Err(crate::age::restricted("room"));
    }
    if !room.rules.trim().is_empty() && !accept_rules {
        return Err(ApiError::Forbidden {
            code: "room.rules_not_accepted",
            detail: "The room rules must be accepted".into(),
        });
    }
    if store::rooms::member(&state.db, &room.id, &user.id).await?.is_none() {
        store::rooms::add_member(&state.db, &room.id, &user.id, true).await?;
        crate::subscriptions::room_event(
            state,
            &room.id,
            "member.join",
            serde_json::json!({ "room_id": room.id, "user": user.to_public() }),
        )
        .await;
        crate::welcome::joined(state, room, user).await;
    }
    let access = access::room_access(state, &room.id, user).await?;
    detail(state, &access).await
}

/// Join a public room.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/join", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = JoinRequest, responses((status = 200, body = RoomDetail), (status = 403, body = ProblemDetails)))]
pub async fn join_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    body: Option<Json<JoinRequest>>,
) -> Result<Json<RoomDetail>, ApiError> {
    let room = store::rooms::room_by_id(&state.db, &room_id)
        .await?
        .ok_or_else(|| access::not_found("Room", "room.not_found"))?;
    if room.join_mode != "public" {
        return Err(ApiError::Forbidden {
            code: "room.invite_required",
            detail: "This room can only be joined by invite".into(),
        });
    }
    Ok(Json(join(&state, &auth.user, &room, body.map(|b| b.accept_rules).unwrap_or(false)).await?))
}

#[derive(Serialize, ToSchema)]
pub struct InvitePreview {
    pub code: String,
    pub room: PublicRoom,
    pub rules: String,
}

async fn valid_invite(state: &AppState, code: &str) -> Result<(Invite, Room), ApiError> {
    let invalid = || ApiError::NotFound { code: "invite.invalid", what: "Invite".into() };
    let invite = store::rooms::invite_by_code(&state.db, code).await?.ok_or_else(invalid)?;
    if invite.expires_at.as_deref().is_some_and(|e| e <= now().as_str())
        || (invite.max_uses > 0 && invite.uses >= invite.max_uses)
    {
        return Err(invalid());
    }
    let room = store::rooms::room_by_id(&state.db, &invite.room_id).await?.ok_or_else(invalid)?;
    Ok((invite, room))
}

/// Preview of an invite (room name, rules), without joining.
#[utoipa::path(get, path = "/api/v1/invites/{code}", params(("code" = String, Path)), responses((status = 200, body = InvitePreview), (status = 404, body = ProblemDetails)))]
pub async fn get_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<InvitePreview>, ApiError> {
    let (invite, room) = valid_invite(&state, &code).await?;
    Ok(Json(InvitePreview {
        code: invite.code,
        rules: room.rules.clone(),
        room: PublicRoom::of(room.clone(), store::rooms::member_count(&state.db, &room.id).await?),
    }))
}

/// Join by invite.
#[utoipa::path(post, path = "/api/v1/invites/{code}/join", security(("bearer" = [])), params(("code" = String, Path)), request_body = JoinRequest, responses((status = 200, body = RoomDetail), (status = 404, body = ProblemDetails)))]
pub async fn join_by_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(code): Path<String>,
    body: Option<Json<JoinRequest>>,
) -> Result<Json<RoomDetail>, ApiError> {
    let (invite, room) = valid_invite(&state, &code).await?;
    if invite.user.as_ref().is_some_and(|bound| *bound != auth.user.address()) {
        return Err(ApiError::Forbidden {
            code: "invite.wrong_user",
            detail: "This invite is for a different person".into(),
        });
    }
    // Bots enter rooms only through an installation (APPLICATIONS.md §4.2).
    if auth.user.is_bot() {
        return Err(crate::applications::bot_forbidden());
    }
    let was_member = store::rooms::member(&state.db, &room.id, &auth.user.id).await?.is_some();
    // The use is claimed before the join (atomically, so a limited invite admits exactly as many people as it
    // allows) and given back when the join fails.
    if !was_member && !store::rooms::claim_invite(&state.db, &invite.code, &now()).await? {
        return Err(ApiError::NotFound { code: "invite.invalid", what: "Invite".into() });
    }
    match join(&state, &auth.user, &room, body.map(|b| b.accept_rules).unwrap_or(false)).await {
        Ok(detail) => Ok(Json(detail)),
        Err(e) => {
            if !was_member {
                store::rooms::release_invite(&state.db, &invite.code).await?;
            }
            Err(e)
        }
    }
}

/// Leave a room (owners must transfer or delete it first).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/leave", security(("bearer" = [])), params(("room_id" = String, Path)), responses((status = 204), (status = 403, body = ProblemDetails)))]
pub async fn leave_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if access.is_owner {
        return Err(ApiError::Forbidden {
            code: "room.owner_cannot_leave",
            detail: "The owner cannot leave the room, only delete it".into(),
        });
    }
    if store::rooms::remove_member(&state.db, &room_id, &auth.user.id).await? {
        crate::subscriptions::room_event(
            &state,
            &room_id,
            "member.leave",
            serde_json::json!({ "room_id": room_id, "user_id": auth.user.id }),
        )
        .await;
        crate::welcome::membership_ended(&state, &access.room, &auth.user, access.member.as_ref(), LeaveKind::Leave)
            .await;
        crate::e2ee::user_left_room(&state, &room_id, &auth.user).await?;
        // A bot leaving uninstalls itself (APPLICATIONS.md §4.3).
        crate::installations::uninstalled(&state, &access.room, &auth.user, "left", Some(&auth.user.id)).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Members

#[derive(Deserialize, utoipa::IntoParams)]
pub struct MemberQuery {
    pub limit: Option<i64>,
    pub after: Option<String>,
}

pub(crate) async fn to_member(
    state: &AppState,
    room_id: &str,
    m: &crate::models::MemberRow,
) -> Result<Option<Member>, ApiError> {
    let Some(user) = store::users::by_id(&state.db, &m.user_id).await? else { return Ok(None) };
    let avatar = m.avatar_media_id.as_deref();
    Ok(Some(Member {
        user: user.to_public(),
        nickname: m.nickname.clone(),
        joined_at: m.joined_at.clone(),
        roles: store::rooms::member_role_ids(&state.db, room_id, &m.user_id).await?,
        timeout_until: m.timeout_until.clone().filter(|t| t.as_str() > now().as_str()),
        nick: m.nickname.clone(),
        room_avatar: crate::models::media_url(avatar, m.avatar_animated != 0),
        room_avatar_still: crate::models::media_url(avatar, false),
        room_avatar_animated: avatar.is_some() && m.avatar_animated != 0,
        room_bio: Some(m.bio.clone()).filter(|b| !b.is_empty()),
    }))
}

/// Members (paginated via `after` = last user ID).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/members", security(("bearer" = [])), params(("room_id" = String, Path), MemberQuery), responses((status = 200, body = Vec<Member>)))]
pub async fn list_members(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Query(q): Query<MemberQuery>,
) -> Result<Json<Vec<Member>>, ApiError> {
    access::room_access(&state, &room_id, &auth.user).await?;
    let rows =
        store::rooms::members(&state.db, &room_id, validate::limit(q.limit, 100, 500), q.after.as_deref()).await?;
    let mut out = Vec::with_capacity(rows.len());
    for m in &rows {
        if let Some(member) = to_member(&state, &room_id, m).await? {
            out.push(member);
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMemberRequest {
    #[serde(default, with = "crate::serde_with_double_option")]
    pub nickname: Option<Option<String>>,
    pub roles: Option<Vec<String>>,
}

/// Change a member: nickname (`manage_nicknames`, or one's own with `change_nickname`), roles (`manage_roles`).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/members/{user_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("user_id" = String, Path)), request_body = UpdateMemberRequest, responses((status = 200, body = Member)))]
pub async fn update_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let target = store::rooms::member(&state.db, &room_id, &user_id)
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    if let Some(nick) = req.nickname {
        let own = user_id == auth.user.id;
        if own {
            access.require(p::CHANGE_NICKNAME, "member.nickname_forbidden", "Change nickname")?
        } else {
            access.require(p::MANAGE_NICKNAMES, "member.nickname_forbidden", "Manage nicknames")?
        }
        let nick = nick.as_deref().map(|n| validate::name("nickname", n, 32)).transpose()?;
        if !own {
            moderation_target(&state, &access, &user_id).await?;
        }
        store::rooms::set_nickname(&state.db, &room_id, &user_id, nick.as_deref()).await?;
        if !own {
            store::rooms::audit(
                &state.db,
                Some(&room_id),
                Some(&auth.user.id),
                "member.profile",
                &user_id,
                "",
                serde_json::json!({ "nickname": nick }),
            )
            .await?;
        }
    }
    if let Some(role_ids) = req.roles {
        access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
        let roles = store::rooms::roles(&state.db, &room_id).await?;
        // Own roles at or above the own top position may stay in the list (they are not assigned anew).
        let current = store::rooms::member_role_ids(&state.db, &room_id, &user_id).await?;
        let mut clean = Vec::new();
        for id in role_ids {
            let role = roles
                .iter()
                .find(|r| r.id == id && r.is_everyone == 0)
                .ok_or_else(|| bad("role.unknown", format!("Role {id} does not exist in this room")))?;
            if !access.outranks(role.position) && !current.contains(&id) {
                return Err(ApiError::Forbidden {
                    code: "role.hierarchy",
                    detail: format!("The role '{}' is above your highest role", role.name),
                });
            }
            // Assigning a role grants its bits: only bits the actor holds (permissions.md "Hierarchy"), for other
            // members and for the actor themselves alike. Roles the member already holds are not granted anew.
            if !access.is_owner
                && !access.is_node_admin
                && !current.contains(&id)
                && role.perms() & !access.room_perms != 0
            {
                return Err(ApiError::Forbidden {
                    code: "role.escalation",
                    detail: format!("The role '{}' carries permissions you do not have yourself", role.name),
                });
            }
            if !clean.contains(&id) {
                clean.push(id);
            }
        }
        // The list replaces the member's roles: only members below the actor (permissions.md "Hierarchy"), so none
        // of their current roles is at or above the actor's top position either.
        if user_id != auth.user.id {
            moderation_target(&state, &access, &user_id).await?;
        }
        store::rooms::set_member_roles(&state.db, &room_id, &user_id, &clean).await?;
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "member.roles",
            &user_id,
            "",
            serde_json::json!({ "roles": clean }),
        )
        .await?;
    }
    let _ = target;
    let updated = store::rooms::member(&state.db, &room_id, &user_id)
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    let member =
        to_member(&state, &room_id, &updated).await?.ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    crate::subscriptions::room_event(
        &state,
        &room_id,
        "member.update",
        serde_json::json!({ "room_id": room_id, "member": member }),
    )
    .await;
    Ok(Json(member))
}

#[derive(Deserialize, ToSchema, Default)]
pub struct ReasonRequest {
    #[serde(default)]
    pub reason: String,
}

/// Checks that the actor may moderate the target (rank, not the owner).
pub(crate) async fn moderation_target(
    state: &AppState,
    access: &RoomAccess,
    user_id: &str,
) -> Result<UserRow, ApiError> {
    if user_id == access.room.owner_id {
        return Err(ApiError::Forbidden { code: "member.is_owner", detail: "The owner cannot be moderated".into() });
    }
    let target =
        store::users::by_id(&state.db, user_id).await?.ok_or_else(|| access::not_found("User", "user.not_found"))?;
    if target.is_node_admin() && !access.is_node_admin {
        return Err(ApiError::Forbidden {
            code: "member.is_node_admin",
            detail: "Node admins can only be moderated by node admins".into(),
        });
    }
    let target_roles = store::rooms::member_role_ids(&state.db, &access.room.id, user_id).await?;
    let roles = store::rooms::roles(&state.db, &access.room.id).await?;
    let target_top = roles.iter().filter(|r| target_roles.contains(&r.id)).map(|r| r.position).max().unwrap_or(0);
    if !access.outranks(target_top) {
        return Err(ApiError::Forbidden {
            code: "member.hierarchy",
            detail: "The member has an equal or higher role".into(),
        });
    }
    Ok(target)
}

/// Remove a member (`kick_members`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/members/{user_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("user_id" = String, Path)), request_body = ReasonRequest, responses((status = 204), (status = 403, body = ProblemDetails)))]
pub async fn kick_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, user_id)): Path<(String, String)>,
    body: Option<Json<ReasonRequest>>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::KICK_MEMBERS, "member.kick_forbidden", "Kick members")?;
    let target = moderation_target(&state, &access, &user_id).await?;
    let reason = body.map(|b| b.0.reason).unwrap_or_default();
    let member = store::rooms::member(&state.db, &room_id, &user_id).await?;
    if store::rooms::remove_member(&state.db, &room_id, &user_id).await? {
        crate::welcome::membership_ended(&state, &access.room, &target, member.as_ref(), LeaveKind::Kick).await;
        store::rooms::audit(
            &state.db,
            Some(&room_id),
            Some(&auth.user.id),
            "member.kick",
            &target.address(),
            &reason,
            serde_json::json!({}),
        )
        .await?;
        crate::subscriptions::room_event(
            &state,
            &room_id,
            "member.leave",
            serde_json::json!({ "room_id": room_id, "user_id": user_id, "kicked": true }),
        )
        .await;
        state.hub.users(
            vec![user_id.clone()],
            "member.leave",
            serde_json::json!({ "room_id": room_id, "user_id": user_id, "kicked": true }),
        );
        crate::e2ee::user_left_room(&state, &room_id, &target).await?;
        crate::installations::uninstalled(&state, &access.room, &target, "kicked", Some(&auth.user.id)).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct TimeoutRequest {
    /// Minutes; 0 lifts the timeout.
    pub minutes: i64,
    #[serde(default)]
    pub reason: String,
}

/// Set or lift a timeout (`moderate_members`).
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/members/{user_id}/timeout", security(("bearer" = [])), params(("room_id" = String, Path), ("user_id" = String, Path)), request_body = TimeoutRequest, responses((status = 200, body = Member)))]
pub async fn timeout_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, user_id)): Path<(String, String)>,
    Json(req): Json<TimeoutRequest>,
) -> Result<Json<Member>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MODERATE_MEMBERS, "member.timeout_forbidden", "Moderate members")?;
    let target = moderation_target(&state, &access, &user_id).await?;
    let minutes = validate::range("minutes", req.minutes, 0, 60 * 24 * 28)?;
    let until = (minutes > 0).then(|| util::in_seconds(minutes * 60));
    let member = store::rooms::member(&state.db, &room_id, &user_id)
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    store::rooms::set_timeout(&state.db, &room_id, &user_id, until.as_deref()).await?;
    if minutes > 0 {
        // Members in timeout keep only `view_channel`: they leave voice too.
        let (room, user) = (room_id.clone(), user_id.clone());
        crate::voice::spawn_effect(
            &state,
            move |s| async move { crate::voice::disconnect_user(&s, &room, &user).await },
        );
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        if minutes > 0 { "member.timeout" } else { "member.timeout_clear" },
        &target.address(),
        &req.reason,
        serde_json::json!({ "minutes": minutes }),
    )
    .await?;
    let member = to_member(&state, &room_id, &crate::models::MemberRow { timeout_until: until, ..member })
        .await?
        .ok_or_else(|| access::not_found("Member", "member.not_found"))?;
    crate::subscriptions::room_event(
        &state,
        &room_id,
        "member.update",
        serde_json::json!({ "room_id": room_id, "member": member }),
    )
    .await;
    Ok(Json(member))
}

// ---------------------------------------------------------------- Bans

#[derive(Deserialize, ToSchema)]
pub struct BanRequest {
    /// User address `alice@domain` or an entire domain.
    pub subject: String,
    #[serde(default)]
    pub reason: String,
}

/// Ban (`ban_members`). Members are removed; a domain ban bans all users of that domain.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/bans", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = BanRequest, responses((status = 201, body = Ban)))]
pub async fn ban(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<BanRequest>,
) -> Result<(StatusCode, Json<Ban>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::BAN_MEMBERS, "member.ban_forbidden", "Ban members")?;
    let subject = req.subject.trim().to_lowercase();
    let reason = validate::text("reason", &req.reason, 0, 500)?;
    if let Some((username, domain)) = util::parse_address(&subject) {
        if let Some(target) = store::users::by_username(&state.db, username, domain).await? {
            if let Some(member) = store::rooms::member(&state.db, &room_id, &target.id).await? {
                moderation_target(&state, &access, &target.id).await?;
                store::rooms::remove_member(&state.db, &room_id, &target.id).await?;
                crate::welcome::membership_ended(&state, &access.room, &target, Some(&member), LeaveKind::Ban).await;
                crate::subscriptions::room_event(
                    &state,
                    &room_id,
                    "member.leave",
                    serde_json::json!({ "room_id": room_id, "user_id": target.id, "banned": true }),
                )
                .await;
                state.hub.users(
                    vec![target.id.clone()],
                    "member.leave",
                    serde_json::json!({ "room_id": room_id, "user_id": target.id, "banned": true }),
                );
                crate::e2ee::user_left_room(&state, &room_id, &target).await?;
                crate::installations::uninstalled(&state, &access.room, &target, "banned", Some(&auth.user.id)).await?;
                crate::federation::remote::notify_ban(&state, &target, &room_id, &access.room.name, "room").await;
            } else if target.id == access.room.owner_id {
                return Err(ApiError::Forbidden {
                    code: "member.is_owner",
                    detail: "The owner cannot be banned".into(),
                });
            }
        }
    } else if util::valid_domain(&subject) {
        if subject == state.config.domain {
            return Err(bad("ban.own_domain", "The node's own domain cannot be banned"));
        }
        // Every member of the domain (and every bot of an owner there) leaves (FEDERATION.md §3.3).
        let members = store::rooms::members_of_domain(&state.db, &room_id, &subject).await?;
        if members.contains(&access.room.owner_id) {
            return Err(ApiError::Forbidden { code: "member.is_owner", detail: "The owner cannot be banned".into() });
        }
        // Nobody of the domain may outrank the actor (permissions.md "Hierarchy"), checked before anyone leaves.
        for user_id in &members {
            moderation_target(&state, &access, user_id).await?;
        }
        for user_id in members {
            let Some(target) = store::users::by_id(&state.db, &user_id).await? else { continue };
            let member = store::rooms::member(&state.db, &room_id, &user_id).await?;
            if store::rooms::remove_member(&state.db, &room_id, &user_id).await? {
                crate::welcome::membership_ended(&state, &access.room, &target, member.as_ref(), LeaveKind::Ban).await;
                let data = serde_json::json!({ "room_id": room_id, "user_id": user_id, "banned": true });
                crate::subscriptions::room_event(&state, &room_id, "member.leave", &data).await;
                state.hub.users(vec![user_id.clone()], "member.leave", &data);
                crate::e2ee::user_left_room(&state, &room_id, &target).await?;
                crate::installations::uninstalled(&state, &access.room, &target, "banned", Some(&auth.user.id)).await?;
                crate::federation::remote::notify_ban(&state, &target, &room_id, &access.room.name, "room").await;
            }
        }
    } else {
        return Err(bad("ban.subject_invalid", "Specify: alice@domain or domain"));
    }
    let ban = store::rooms::add_ban(&state.db, Some(&room_id), &subject, &reason, &auth.user.id).await?;
    // Banning an owner bans their bots (APPLICATIONS.md §1.7).
    crate::applications::ban_cascade(&state, Some(&room_id), &subject).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "member.ban",
        &subject,
        &reason,
        serde_json::json!({}),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(ban)))
}

/// Lift a ban.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/bans/{subject}", security(("bearer" = [])), params(("room_id" = String, Path), ("subject" = String, Path)), responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn unban(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, subject)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::BAN_MEMBERS, "member.ban_forbidden", "Ban members")?;
    if !store::rooms::remove_ban(&state.db, Some(&room_id), &subject.to_lowercase()).await? {
        return Err(access::not_found("Ban", "ban.not_found"));
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "member.unban",
        &subject,
        "",
        serde_json::json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Bans of the room.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/bans", security(("bearer" = [])), params(("room_id" = String, Path)), responses((status = 200, body = Vec<Ban>)))]
pub async fn list_bans(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Ban>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::BAN_MEMBERS, "member.ban_forbidden", "Ban members")?;
    Ok(Json(store::rooms::bans(&state.db, Some(&room_id)).await?))
}

// ---------------------------------------------------------------- Invites

#[derive(Deserialize, ToSchema, Default)]
pub struct CreateInviteRequest {
    /// 0 = unlimited
    #[serde(default)]
    pub max_uses: i64,
    /// Validity in hours. `0` = never expires (`manage_room` only). Without `manage_room` at most 720
    /// (30 days); missing: 168 (7 days), or never for `manage_room` (older clients).
    #[serde(default)]
    pub expires_hours: Option<i64>,
}

/// Longest validity of an invite created with `create_invites` alone.
pub const INVITE_MAX_HOURS_WITHOUT_MANAGE: i64 = 30 * 24;
/// Default validity without `manage_room`.
pub const INVITE_DEFAULT_HOURS: i64 = 7 * 24;

/// Create an invite link (`create_invites`). Invites that never expire and validity beyond 30 days
/// need `manage_room`.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/invites", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = CreateInviteRequest, responses((status = 201, body = Invite)))]
pub async fn create_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    body: Option<Json<CreateInviteRequest>>,
) -> Result<(StatusCode, Json<Invite>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::CREATE_INVITES, "invite.create_forbidden", "Create invites")?;
    let req = body.map(|b| b.0).unwrap_or_default();
    let max_uses = validate::range("max_uses", req.max_uses, 0, 10_000)?;
    let manage = access.has(p::MANAGE_ROOM);
    let hours = match (req.expires_hours, manage) {
        (Some(h), true) => validate::range("expires_hours", h, 0, 24 * 365)?,
        (None, true) => 0,
        (Some(0), false) => {
            return Err(ApiError::Forbidden {
                code: "invite.never_forbidden",
                detail: "Invites that never expire need manage_room".into(),
            });
        }
        (Some(h), false) => validate::range("expires_hours", h, 1, INVITE_MAX_HOURS_WITHOUT_MANAGE)?,
        (None, false) => INVITE_DEFAULT_HOURS,
    };
    let expires_at = (hours > 0).then(|| util::in_seconds(hours * 3600));
    let invite =
        store::rooms::create_invite(&state.db, &room_id, &auth.user.id, max_uses, expires_at.as_deref()).await?;
    Ok((StatusCode::CREATED, Json(invite)))
}

#[derive(Deserialize, ToSchema)]
pub struct DirectInviteRequest {
    /// `username` (this node) or `username@domain` (any node).
    pub user: String,
}

#[derive(Serialize, ToSchema)]
pub struct DirectInviteResponse {
    /// Single-use invite bound to the user, valid for 7 days.
    pub invite: Invite,
}

/// Invite one user of any node (`create_invites`, FEDERATION.md §3.4): a single-use invite bound to the
/// address goes to the user's invite list (on their home node via `room.invite`). Rate-limited per inviter.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/invites/direct", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = DirectInviteRequest,
    responses((status = 202, body = DirectInviteResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn direct_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<DirectInviteRequest>,
) -> Result<(StatusCode, Json<DirectInviteResponse>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::CREATE_INVITES, "invite.create_forbidden", "Create invites")?;
    if crate::federation::remote::parse_reference(&state, &req.user).is_none() {
        return Err(bad("invite.user_invalid", "Specify: name or name@domain"));
    }
    state.direct_invite_limiter.check_all(&[format!("invite:{}", auth.user.id)])?;
    let invitee = crate::federation::remote::resolve_or_stub(&state, &req.user).await?;
    if invitee.id == auth.user.id {
        return Err(bad("invite.self", "You are already here"));
    }
    if store::rooms::member(&state.db, &room_id, &invitee.id).await?.is_some() {
        return Err(ApiError::conflict("invite.already_member", "Already a member of this room"));
    }
    if banned(&state, &room_id, &invitee).await? {
        return Err(ApiError::Forbidden { code: "room.banned", detail: "This person is banned from the room".into() });
    }
    let expires_at = util::in_seconds(crate::federation::social::INVITE_TTL_SECS);
    let invite =
        store::rooms::create_bound_invite(&state.db, &room_id, &auth.user.id, &expires_at, &invitee.address()).await?;
    crate::federation::social::invite_to_room(&state, &auth.user, &invitee, &access.room, &invite).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "invite.direct",
        &invitee.address(),
        "",
        serde_json::json!({}),
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(DirectInviteResponse { invite })))
}

/// Invites of the room (`manage_room`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/invites", security(("bearer" = [])), params(("room_id" = String, Path)), responses((status = 200, body = Vec<Invite>)))]
pub async fn list_invites(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Invite>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    Ok(Json(store::rooms::invites_of_room(&state.db, &room_id).await?))
}

/// Delete an invite (`manage_room`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/invites/{code}", security(("bearer" = [])), params(("room_id" = String, Path), ("code" = String, Path)), responses((status = 204)))]
pub async fn delete_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, code)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    if !store::rooms::delete_invite(&state.db, &room_id, &code).await? {
        return Err(access::not_found("Invite", "invite.not_found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Audit log and bulk deletion

#[derive(Deserialize, utoipa::IntoParams)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

/// Audit log of the room (`view_audit_log`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/audit-log", security(("bearer" = [])), params(("room_id" = String, Path), AuditQuery), responses((status = 200, body = Vec<AuditEntry>)))]
pub async fn audit_log(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::VIEW_AUDIT_LOG, "audit.forbidden", "View audit log")?;
    let rows =
        store::rooms::audit_entries(&state.db, Some(&room_id), validate::limit(q.limit, 50, 200), q.before.as_deref())
            .await?;
    Ok(Json(rows.iter().map(|r| r.to_api()).collect()))
}

#[derive(Deserialize, Serialize, ToSchema, Clone)]
pub struct PurgeRequest {
    /// Channels; empty = all channels of the room.
    #[serde(default)]
    pub channel_ids: Vec<String>,
    pub author_id: Option<String>,
    /// RFC 3339
    pub from: Option<String>,
    pub to: Option<String>,
    /// Token from the preview; without a token, messages are only counted.
    pub confirm_token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PurgeResponse {
    /// true = only counted, nothing deleted
    pub dry_run: bool,
    pub messages: i64,
    /// Token for execution (valid for 2 minutes), only with dry_run
    pub confirm_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ConfirmClaims {
    #[serde(flatten)]
    std: jwt::StandardClaims,
    filter_hash: String,
}

#[derive(Deserialize)]
struct ConfirmExtra {
    filter_hash: String,
}

/// Bulk deletion (`purge`): first a preview with count and confirmation token, then permanent deletion.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/moderation/purge", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = PurgeRequest, responses((status = 200, body = PurgeResponse), (status = 403, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn purge(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<PurgeRequest>,
) -> Result<Json<PurgeResponse>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::PURGE, "moderation.purge_forbidden", "Purge")?;
    // A preview counts messages across the room's channels: limited per moderator.
    if req.confirm_token.is_none() {
        state.purge_limiter.check_all(&[format!("purge:{}", auth.user.id)])?;
    }
    let all_channels = store::rooms::channels(&state.db, &room_id).await?;
    let room_channels: Vec<String> = all_channels.iter().map(|c| c.id.clone()).collect();
    // Only channels in which the actor holds `purge` (permissions.md step 4: nothing without `view_channel`).
    let overrides = store::rooms::overrides_of_room(&state.db, &room_id).await?;
    let may_purge = |c: &crate::models::ChannelRow| {
        p::has(access::channel_perms_with(&access, c, &overrides, &auth.user.id), p::VIEW_CHANNEL | p::PURGE)
    };
    let conversation_ids: Vec<String> = if req.channel_ids.is_empty() {
        // "All channels" are the members' channels; the welcome channel only when named.
        all_channels.iter().filter(|c| c.kind != "system" && may_purge(c)).map(|c| c.id.clone()).collect()
    } else {
        for id in &req.channel_ids {
            if !room_channels.contains(id) {
                return Err(bad("channel.not_in_room", format!("Channel {id} does not belong to this room")));
            }
            if !all_channels.iter().any(|c| &c.id == id && may_purge(c)) {
                return Err(ApiError::Forbidden {
                    code: "moderation.purge_forbidden",
                    detail: format!("Missing permission in channel {id}: Purge"),
                });
            }
        }
        req.channel_ids.clone()
    };
    // Never without a channel: the filter would otherwise reach every conversation of the node.
    if conversation_ids.is_empty() {
        return Err(bad("moderation.purge_no_channels", "There is no channel of this room you may purge"));
    }
    if let Some(t) = req.from.as_deref().or(req.to.as_deref())
        && util::parse_time(t).is_none()
    {
        return Err(bad("validation.time", "Specify from/to as RFC 3339 timestamps"));
    }
    if req.author_id.is_none() && req.from.is_none() && req.to.is_none() && req.channel_ids.is_empty() {
        return Err(bad("moderation.purge_unbounded", "Specify at least a channel, author or time range"));
    }
    let filter = PurgeFilter {
        conversation_ids,
        author_id: req.author_id.clone(),
        from: req.from.clone().map(|t| util::format_time(util::parse_time(&t).unwrap_or_default())),
        to: req.to.clone().map(|t| util::format_time(util::parse_time(&t).unwrap_or_default())),
    };
    let filter_hash = util::sha256_b64(&format!(
        "{room_id}|{}|{:?}|{:?}|{:?}",
        filter.conversation_ids.join(","),
        filter.author_id,
        filter.from,
        filter.to
    ));
    let key = state.signing_key();
    let expected =
        jwt::Expected { iss: state.config.domain.clone(), aud: format!("purge:{}", auth.user.id), typ: "confirm" };

    match req.confirm_token.as_deref() {
        None => {
            let count = store::messages::purge_count(&state.db, &filter).await?;
            let now = jwt::now_unix();
            let claims = ConfirmClaims {
                std: jwt::StandardClaims {
                    iss: expected.iss,
                    sub: room_id,
                    aud: expected.aud,
                    exp: now + 120,
                    iat: now,
                    jti: util::ulid(),
                    typ: "confirm".into(),
                },
                filter_hash,
            };
            let token = jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))?;
            Ok(Json(PurgeResponse { dry_run: true, messages: count, confirm_token: Some(token) }))
        }
        Some(token) => {
            let (_, extra): (jwt::StandardClaims, ConfirmExtra) = jwt::verify(token, &key.verifying(), &expected)
                .map_err(|_| {
                    bad(
                        "moderation.confirm_invalid",
                        "Confirmation token invalid or expired, please repeat the preview",
                    )
                })?;
            if extra.filter_hash != filter_hash {
                return Err(bad("moderation.confirm_mismatch", "The filter changed after the preview"));
            }
            // Channel by channel: each `message.purge` names one channel and reaches only its viewers, so no member
            // learns of channels hidden from them (PROTOCOL.md §6).
            let mut deleted = 0;
            for channel_id in &filter.conversation_ids {
                let one = PurgeFilter {
                    conversation_ids: vec![channel_id.clone()],
                    author_id: filter.author_id.clone(),
                    from: filter.from.clone(),
                    to: filter.to.clone(),
                };
                let n = crate::routes::messages::purge_with_blobs(&state, &one).await?;
                deleted += n;
                state.hub.room(&room_id, "message.purge", serde_json::json!({ "room_id": room_id, "conversation_ids": [channel_id], "author_id": filter.author_id, "from": filter.from, "to": filter.to, "deleted": n }));
            }
            store::rooms::audit(&state.db, Some(&room_id), Some(&auth.user.id), "moderation.purge", "", "", serde_json::json!({ "deleted": deleted, "channels": filter.conversation_ids, "author_id": filter.author_id, "from": filter.from, "to": filter.to })).await?;
            Ok(Json(PurgeResponse { dry_run: false, messages: deleted, confirm_token: None }))
        }
    }
}
