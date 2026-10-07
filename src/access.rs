// SPDX-License-Identifier: AGPL-3.0-only
//! Access checks: load a room, determine a user's membership and permissions.

use crate::{
    app::AppState,
    error::ApiError,
    models::{ChannelRow, MemberRow, OverrideRow, RoleRow, Room, UserRow},
    permissions::{self, Perms},
    store,
};

pub struct RoomAccess {
    pub room: Room,
    /// `None` only for node admins who are not members.
    pub member: Option<MemberRow>,
    pub everyone: RoleRow,
    /// The member's roles, without @everyone.
    pub member_roles: Vec<RoleRow>,
    pub is_owner: bool,
    pub is_node_admin: bool,
    /// Room-level permissions; for bots already capped by the scopes (0 in a "no bots" room).
    pub room_perms: Perms,
    /// Kind of the account (`user`, `bot`, …) and, for a bot's own request, its effective scopes.
    pub kind: String,
    pub scopes: Option<Vec<String>>,
}

impl RoomAccess {
    pub fn has(&self, needed: Perms) -> bool {
        permissions::has(self.room_perms, needed)
    }

    pub fn require(&self, needed: Perms, code: &'static str, what: &str) -> Result<(), ApiError> {
        if self.has(needed) {
            Ok(())
        } else {
            Err(ApiError::Forbidden { code, detail: format!("Missing permission: {what}") })
        }
    }

    /// `manage_applications` (APPLICATIONS.md §4.2, §4.3, §5.3): install and remove applications, edit the room's
    /// command settings. `403 app.manage_forbidden` without it.
    pub fn require_manage_applications(&self) -> Result<(), ApiError> {
        self.require(permissions::MANAGE_APPLICATIONS, "app.manage_forbidden", "Manage applications")
    }

    /// Reading the room's installations and command settings: `manage_applications` or `manage_room`.
    pub fn require_view_applications(&self) -> Result<(), ApiError> {
        if self.has(permissions::MANAGE_ROOM) {
            return Ok(());
        }
        self.require_manage_applications()
    }

    /// Highest role position of the member (owner: infinite).
    pub fn top_position(&self) -> i64 {
        if self.is_owner || self.is_node_admin {
            return i64::MAX;
        }
        self.member_roles.iter().map(|r| r.position).max().unwrap_or(0)
    }

    /// May the actor manage roles at this position or moderate members at this position?
    pub fn outranks(&self, position: i64) -> bool {
        self.top_position() > position
    }

    pub fn member_roles_eval(&self) -> Vec<(String, Perms)> {
        self.member_roles.iter().map(|r| (r.id.clone(), r.perms())).collect()
    }

    /// Owner, node admin or `administrator`: may upload every category.
    pub fn privileged(&self) -> bool {
        self.is_owner || self.is_node_admin || self.has(permissions::ADMINISTRATOR)
    }
}

/// What nobody can do in a system channel (the welcome channel is read-only for everyone).
pub use permissions::SYSTEM_CHANNEL_DENIED;

pub fn not_found(what: &str, code: &'static str) -> ApiError {
    ApiError::NotFound { code, what: what.into() }
}

/// Loads room and membership. Non-members get `room.not_member`; node admins always get access.
pub async fn room_access(state: &AppState, room_id: &str, user: &UserRow) -> Result<RoomAccess, ApiError> {
    let room =
        store::rooms::room_by_id(&state.db, room_id).await?.ok_or_else(|| not_found("Room", "room.not_found"))?;
    let member = store::rooms::member(&state.db, room_id, &user.id).await?;
    let is_node_admin = user.is_node_admin();
    if member.is_none() && !is_node_admin {
        return Err(ApiError::Forbidden {
            code: "room.not_member",
            detail: "You are not a member of this room".into(),
        });
    }
    let roles = store::rooms::roles(&state.db, room_id).await?;
    let everyone = roles
        .iter()
        .find(|r| r.is_everyone != 0)
        .cloned()
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("room without an @everyone role")))?;
    let role_ids = match &member {
        Some(_) => store::rooms::member_role_ids(&state.db, room_id, &user.id).await?,
        None => Vec::new(),
    };
    let member_roles: Vec<RoleRow> = roles.into_iter().filter(|r| role_ids.contains(&r.id)).collect();
    let is_owner = room.owner_id == user.id;
    let eval_roles: Vec<(String, Perms)> = member_roles.iter().map(|r| (r.id.clone(), r.perms())).collect();
    let mut room_perms = permissions::room_level(is_owner || is_node_admin, everyone.perms(), &eval_roles);
    if member.as_ref().is_some_and(MemberRow::is_timed_out) && !is_owner && !is_node_admin {
        room_perms &= permissions::TIMEOUT_KEEPS;
    }
    // Bots (APPLICATIONS.md §2.4, §3.5): capped by the token's scopes, nothing in a "no bots" room.
    room_perms = permissions::cap_bot(room_perms, &user.kind, room.no_bots != 0, user.app_scopes.as_deref());
    Ok(RoomAccess {
        room,
        member,
        everyone,
        member_roles,
        is_owner,
        is_node_admin,
        room_perms,
        kind: user.kind.clone(),
        scopes: user.app_scopes.clone(),
    })
}

/// Loads a channel of a room (404 if it does not belong to this room).
pub async fn channel_in_room(state: &AppState, room_id: &str, channel_id: &str) -> Result<ChannelRow, ApiError> {
    match store::rooms::channel_by_id(&state.db, channel_id).await? {
        Some(c) if c.room_id == room_id => Ok(c),
        _ => Err(not_found("Channel", "channel.not_found")),
    }
}

/// Effective permissions in a channel.
pub async fn channel_perms(
    state: &AppState,
    access: &RoomAccess,
    channel: &ChannelRow,
    user_id: &str,
) -> Result<Perms, ApiError> {
    if access.is_owner || access.is_node_admin {
        return Ok(channel_perms_with(access, channel, &[], user_id));
    }
    let mut overrides = match &channel.category_id {
        Some(cat) => store::rooms::overrides_for(&state.db, "category", cat).await?,
        None => Vec::new(),
    };
    overrides.extend(store::rooms::overrides_for(&state.db, "channel", &channel.id).await?);
    Ok(channel_perms_with(access, channel, &overrides, user_id))
}

/// Effective permissions in a channel from already loaded overrides (any superset of the
/// channel's and its category's overrides, e.g. all overrides of the room).
pub fn channel_perms_with(
    access: &RoomAccess,
    channel: &ChannelRow,
    overrides: &[OverrideRow],
    user_id: &str,
) -> Perms {
    let bot = |p: Perms| permissions::cap_bot(p, &access.kind, channel.no_bots(), access.scopes.as_deref());
    let system = channel.kind == "system";
    let restrict = |p: Perms| bot(if system { p & !SYSTEM_CHANNEL_DENIED } else { p });
    if access.is_owner || access.is_node_admin {
        return restrict(permissions::ALL);
    }
    let of = |target_type: &str, target_id: Option<&str>| {
        overrides
            .iter()
            .filter(|o| o.target_type == target_type && Some(o.target_id.as_str()) == target_id)
            .map(|o| o.to_eval())
            .collect()
    };
    let input = permissions::Input {
        user_id: user_id.to_string(),
        is_owner: access.is_owner,
        everyone_role_id: access.everyone.id.clone(),
        everyone_permissions: access.everyone.perms(),
        member_roles: access.member_roles_eval(),
        category_overrides: of("category", channel.category_id.as_deref()),
        channel_overrides: of("channel", Some(&channel.id)),
        // Without a category there is nothing to inherit: the channel's own overrides apply.
        sync_with_category: channel.sync_with_category != 0 && channel.category_id.is_some(),
        timed_out: access.member.as_ref().is_some_and(MemberRow::is_timed_out),
        kind: access.kind.clone(),
        no_bots: channel.no_bots(),
        scopes: access.scopes.clone(),
        system_channel: system,
    };
    permissions::compute(&input)
}

/// Upload categories (`uploads.rs`) of the member in a channel: the highest role with a setting (else
/// `@everyone`), then the channel's overrides (or the category's when synced) on top.
pub fn channel_upload_categories_with(
    access: &RoomAccess,
    channel: &ChannelRow,
    overrides: &[OverrideRow],
    user_id: &str,
) -> crate::uploads::Categories {
    use crate::uploads;
    let synced = channel.sync_with_category != 0 && channel.category_id.is_some();
    let (target_type, target_id) =
        if synced { ("category", channel.category_id.as_deref()) } else { ("channel", Some(channel.id.as_str())) };
    let chosen: Vec<&OverrideRow> =
        overrides.iter().filter(|o| o.target_type == target_type && Some(o.target_id.as_str()) == target_id).collect();
    let evals: Vec<permissions::Override> = chosen.iter().map(|o| o.to_eval()).collect();
    let upload_overrides: Vec<uploads::UploadOverride<'_>> = evals
        .iter()
        .zip(&chosen)
        .map(|(e, o)| uploads::UploadOverride::of(e, o.upload_allow as u64, o.upload_deny as u64))
        .collect();
    let roles: Vec<uploads::RoleCategories<'_>> = access
        .member_roles
        .iter()
        .map(|r| uploads::RoleCategories { id: &r.id, position: r.position, categories: r.upload_categories() })
        .collect();
    uploads::effective(
        access.privileged(),
        &access.everyone.id,
        access.everyone.upload_categories().unwrap_or(uploads::DEFAULT_EVERYONE),
        &roles,
        &upload_overrides,
        user_id,
    )
}

/// Upload categories of the requester in a conversation: room channels as above, DMs and group DMs the
/// node's `TAVRN_UPLOAD_DM_CATEGORIES`.
pub async fn upload_categories(
    state: &AppState,
    conv: &Conv,
    user_id: &str,
) -> Result<crate::uploads::Categories, ApiError> {
    match &conv.kind {
        ConvKind::Channel { access, channel } => {
            let mut overrides = match &channel.category_id {
                Some(cat) => store::rooms::overrides_for(&state.db, "category", cat).await?,
                None => Vec::new(),
            };
            overrides.extend(store::rooms::overrides_for(&state.db, "channel", &channel.id).await?);
            Ok(channel_upload_categories_with(access, channel, &overrides, user_id))
        }
        ConvKind::Direct { .. } => Ok(state.config.upload_dm_categories()),
    }
}

pub fn require(perms: Perms, needed: Perms, code: &'static str, what: &str) -> Result<(), ApiError> {
    if permissions::has(perms, needed) {
        Ok(())
    } else {
        Err(ApiError::Forbidden { code, detail: format!("Missing permission: {what}") })
    }
}

// ---------------------------------------------------------------- Conversations (channels, DMs, group DMs)

/// Permissions of a member in a DM or group DM. Nobody moderates other members' messages there.
pub const DIRECT_PERMS: Perms = permissions::VIEW_CHANNEL
    | permissions::SEND_MESSAGES
    | permissions::ATTACH_FILES
    | permissions::ADD_REACTIONS
    | permissions::PIN_MESSAGES
    | permissions::USE_WHITEBOARD;

pub enum ConvKind {
    /// A room channel; the conversation id is the channel id.
    Channel { access: Box<RoomAccess>, channel: ChannelRow },
    /// A DM (`dm`) or group DM (`group`) of which the requester is a member.
    /// `requested`: members who have not accepted the message request yet (they get no message events).
    Direct { row: crate::store::social::ConversationRow, member_ids: Vec<String>, requested: Vec<String> },
}

/// A conversation resolved for one user, with that user's effective permissions.
pub struct Conv {
    pub id: String,
    pub encrypted: bool,
    pub perms: Perms,
    pub kind: ConvKind,
}

impl Conv {
    /// `true` while `user_id` has not accepted this DM or group DM (a message request).
    pub fn is_request_for(&self, user_id: &str) -> bool {
        matches!(&self.kind, ConvKind::Direct { requested, .. } if requested.iter().any(|r| r == user_id))
    }

    pub fn require(&self, needed: Perms, code: &'static str, what: &str) -> Result<(), ApiError> {
        require(self.perms, needed, code, what)
    }

    pub fn room_id(&self) -> Option<&str> {
        match &self.kind {
            ConvKind::Channel { access, .. } => Some(&access.room.id),
            ConvKind::Direct { .. } => None,
        }
    }

    /// May this user be part of the conversation's MLS group (ENCRYPTION.md §4.5)? For channels:
    /// room member with `view_channel` (node admins who are not members are not entitled).
    pub fn entitled(&self) -> bool {
        match &self.kind {
            ConvKind::Channel { access, .. } => {
                access.member.is_some() && permissions::has(self.perms, permissions::VIEW_CHANNEL)
            }
            ConvKind::Direct { .. } => true,
        }
    }

    /// Requires [`Conv::entitled`] with the usual error codes.
    pub fn require_entitled(&self) -> Result<(), ApiError> {
        if let ConvKind::Channel { access, .. } = &self.kind
            && access.member.is_none()
        {
            return Err(ApiError::Forbidden {
                code: "room.not_member",
                detail: "You are not a member of this room".into(),
            });
        }
        self.require(permissions::VIEW_CHANNEL, "channel.view_forbidden", "View channel")
    }

    /// Publishes an event to everyone who sees the conversation (room members or DM members).
    /// Returns the event id.
    pub fn publish(&self, hub: &crate::hub::Hub, kind: &str, data: impl serde::Serialize) -> String {
        match &self.kind {
            ConvKind::Channel { access, .. } => hub.room(&access.room.id, kind, data),
            ConvKind::Direct { member_ids, requested, .. } => {
                let active: Vec<String> = member_ids.iter().filter(|m| !requested.contains(m)).cloned().collect();
                hub.users(active, kind, data)
            }
        }
    }

    /// Publishes like [`Conv::publish`] and queues the event for the event subscriptions of the room
    /// (APPLICATIONS.md §6.2; DMs never feed subscriptions).
    pub async fn publish_recorded(&self, state: &crate::app::AppState, kind: &str, data: impl serde::Serialize) {
        let id = self.publish(&state.hub, kind, &data);
        if let Some(room_id) = self.room_id() {
            crate::subscriptions::record(state, room_id, kind, &id, &data).await;
        }
    }
}

fn conversation_not_found() -> ApiError {
    not_found("Conversation", "conversation.not_found")
}

async fn channel_conv(
    state: &AppState,
    access: RoomAccess,
    channel: ChannelRow,
    user: &UserRow,
) -> Result<Conv, ApiError> {
    let perms = channel_perms(state, &access, &channel, &user.id).await?;
    Ok(Conv {
        id: channel.id.clone(),
        encrypted: channel.encrypted != 0,
        perms,
        kind: ConvKind::Channel { access: Box::new(access), channel },
    })
}

/// Channel addressed through its room (`/rooms/{room_id}/channels/{channel_id}/…`).
pub async fn channel_conversation(
    state: &AppState,
    room_id: &str,
    channel_id: &str,
    user: &UserRow,
) -> Result<Conv, ApiError> {
    let access = room_access(state, room_id, user).await?;
    let channel = channel_in_room(state, room_id, channel_id).await?;
    channel_conv(state, access, channel, user).await
}

/// Any conversation by its id (`/conversations/{conversation_id}/…`). DMs and group DMs are
/// only visible to their members (`conversation.not_found` for everybody else).
pub async fn conversation(state: &AppState, conversation_id: &str, user: &UserRow) -> Result<Conv, ApiError> {
    if !crate::util::is_ulid(conversation_id) {
        return Err(conversation_not_found());
    }
    let row = store::social::conversation(&state.db, conversation_id).await?.ok_or_else(conversation_not_found)?;
    match (row.kind.as_str(), &row.room_id) {
        ("channel", Some(room_id)) => {
            let access = room_access(state, room_id, user).await?;
            let channel = channel_in_room(state, room_id, conversation_id).await?;
            channel_conv(state, access, channel, user).await
        }
        ("dm" | "group", _) => direct_conversation(state, row, &user.id).await,
        _ => Err(conversation_not_found()),
    }
}

/// A DM or group DM by id (404 for channels and non-members).
pub async fn direct(state: &AppState, conversation_id: &str, user_id: &str) -> Result<Conv, ApiError> {
    if !crate::util::is_ulid(conversation_id) {
        return Err(conversation_not_found());
    }
    let row = store::social::conversation(&state.db, conversation_id).await?.ok_or_else(conversation_not_found)?;
    if !matches!(row.kind.as_str(), "dm" | "group") {
        return Err(conversation_not_found());
    }
    direct_conversation(state, row, user_id).await
}

async fn direct_conversation(
    state: &AppState,
    row: crate::store::social::ConversationRow,
    user_id: &str,
) -> Result<Conv, ApiError> {
    let member_ids = store::social::member_ids(&state.db, &row.id).await?;
    if !member_ids.iter().any(|m| m == user_id) {
        return Err(conversation_not_found());
    }
    Ok(Conv {
        id: row.id.clone(),
        encrypted: row.encrypted != 0,
        perms: DIRECT_PERMS,
        kind: ConvKind::Direct { requested: store::social::requested_ids(&state.db, &row.id).await?, row, member_ids },
    })
}

/// Is `user` entitled to be in the conversation (§4.5)? Used for other users than the requester
/// (added devices, removed leaves). Disabled accounts are never entitled.
pub async fn user_entitled(state: &AppState, conv: &Conv, user: &UserRow) -> Result<bool, ApiError> {
    if user.disabled_at.is_some() {
        return Ok(false);
    }
    match &conv.kind {
        ConvKind::Channel { access, channel } => match room_access(state, &access.room.id, user).await {
            Ok(a) if a.member.is_some() => {
                let perms = channel_perms(state, &a, channel, &user.id).await?;
                Ok(permissions::has(perms, permissions::VIEW_CHANNEL))
            }
            Ok(_) | Err(ApiError::Forbidden { .. }) => Ok(false),
            Err(e) => Err(e),
        },
        ConvKind::Direct { member_ids, .. } => Ok(member_ids.contains(&user.id)),
    }
}
