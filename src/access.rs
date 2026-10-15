// SPDX-License-Identifier: AGPL-3.0-only
//! Access checks: load a room, determine a user's membership and permissions.

use crate::{
    app::AppState,
    error::ApiError,
    models::{ChannelRow, MemberRow, OverrideRow, RoleRow, Room, UserRow},
    permissions::{self, Perms},
    store,
};

#[derive(Clone)]
pub struct RoomAccess {
    pub room: Room,
    /// `None` only for node admins who are not members.
    pub member: Option<MemberRow>,
    pub everyone: RoleRow,
    /// The member's roles, without @everyone.
    pub member_roles: Vec<RoleRow>,
    /// Every role of the room, @everyone included (loaded with the access; later steps of the request use it).
    pub roles: std::sync::Arc<Vec<RoleRow>>,
    pub is_owner: bool,
    pub is_node_admin: bool,
    /// Room-level permissions; for bots already capped by the scopes (0 in a "no bots" room).
    pub room_perms: Perms,
    /// Kind of the account (`user`, `bot`, …) and, for a bot's own request, its effective scopes.
    pub kind: String,
    pub scopes: Option<Vec<String>>,
    /// The user passes `adults_only` gates (PROTOCOL.md §5e, `age::is_adult`). Below a channel's gate every
    /// permission in that channel is 0.
    pub adult: bool,
    /// The voice channel in which the member has a moved participation (`VOICE.md` §7 "Moved participations"):
    /// there they hold [`permissions::MOVED_FORCED`] whatever the overrides say.
    pub moved_channel: Option<String>,
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
    let roles = std::sync::Arc::new(store::rooms::roles(&state.db, room_id).await?);
    let role_ids = match &member {
        Some(_) => store::rooms::member_role_ids(&state.db, room_id, &user.id).await?,
        None => Vec::new(),
    };
    let adult = crate::age::is_adult(state, user).await?;
    let moved_channel = if member.is_some() { crate::voice::moved::channel_of(state, room_id, &user.id) } else { None };
    member_access(room, &roles, member, &role_ids, user, adult, moved_channel)
}

/// The [`RoomAccess`] of `user` from already loaded room data: the room's `roles` (with @everyone), the user's
/// membership and role ids, whether the user passes age gates (`age::is_adult`) and the voice channel of a moved
/// participation (`voice::moved`). [`room_access`] uses it for one request, the channel visibility snapshot
/// (`visibility.rs`) for every member of a room at once.
pub fn member_access(
    room: Room,
    roles: &std::sync::Arc<Vec<RoleRow>>,
    member: Option<MemberRow>,
    role_ids: &[String],
    user: &UserRow,
    adult: bool,
    moved_channel: Option<String>,
) -> Result<RoomAccess, ApiError> {
    let is_node_admin = user.is_node_admin();
    let everyone = roles
        .iter()
        .find(|r| r.is_everyone != 0)
        .cloned()
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("room without an @everyone role")))?;
    let member_roles: Vec<RoleRow> =
        roles.iter().filter(|r| r.is_everyone == 0 && role_ids.contains(&r.id)).cloned().collect();
    let is_owner = room.owner_id == user.id;
    let eval_roles: Vec<(String, Perms)> = member_roles.iter().map(|r| (r.id.clone(), r.perms())).collect();
    let timed_out = member.as_ref().is_some_and(MemberRow::is_timed_out);
    let room_perms = room_perms_of(
        &Subject {
            user_id: &user.id,
            is_owner,
            is_node_admin,
            everyone_role_id: &everyone.id,
            everyone_permissions: everyone.perms(),
            member_roles: &eval_roles,
            timed_out,
            kind: &user.kind,
            scopes: user.app_scopes.as_deref(),
            adult,
            moved_channel: None,
        },
        room.no_bots != 0,
    );
    Ok(RoomAccess {
        room,
        member,
        everyone,
        member_roles,
        roles: roles.clone(),
        is_owner,
        is_node_admin,
        room_perms,
        kind: user.kind.clone(),
        scopes: user.app_scopes.clone(),
        adult,
        moved_channel,
    })
}

/// Room-level permissions of a member (no channel): their roles, a timeout, and for bots the scopes and the room's
/// "no bots" flag (APPLICATIONS.md §2.4, §3.5).
pub fn room_perms_of(subject: &Subject<'_>, room_no_bots: bool) -> Perms {
    let privileged = subject.is_owner || subject.is_node_admin;
    let mut room_perms = permissions::room_level(privileged, subject.everyone_permissions, subject.member_roles);
    if subject.timed_out && !privileged {
        room_perms &= permissions::TIMEOUT_KEEPS;
    }
    permissions::cap_bot(room_perms, subject.kind, room_no_bots, subject.scopes)
}

/// Does the user of `access` pass the channel's effective age gate?
pub fn age_passes(access: &RoomAccess, channel: &ChannelRow) -> bool {
    access.adult || !channel.adults_only()
}

/// `403 age.restricted` when the user of `access` is below the channel's effective age gate: the channel stays
/// listed, its content (messages, files, voice, …) is refused (PROTOCOL.md §5e).
pub fn require_age(access: &RoomAccess, channel: &ChannelRow) -> Result<(), ApiError> {
    if age_passes(access, channel) { Ok(()) } else { Err(crate::age::restricted("channel")) }
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
    let overrides = store::rooms::overrides_of_channel(&state.db, channel).await?;
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
    let of = |target_type: &str, target_id: Option<&str>| -> Vec<permissions::Override> {
        overrides
            .iter()
            .filter(|o| o.target_type == target_type && Some(o.target_id.as_str()) == target_id)
            .map(|o| o.to_eval())
            .collect()
    };
    let member_roles = access.member_roles_eval();
    let subject = Subject {
        user_id,
        is_owner: access.is_owner,
        is_node_admin: access.is_node_admin,
        everyone_role_id: &access.everyone.id,
        everyone_permissions: access.everyone.perms(),
        member_roles: &member_roles,
        timed_out: access.member.as_ref().is_some_and(MemberRow::is_timed_out),
        kind: &access.kind,
        scopes: access.scopes.as_deref(),
        adult: access.adult,
        moved_channel: access.moved_channel.as_deref(),
    };
    channel_perms_of(
        &subject,
        channel,
        &of("category", channel.category_id.as_deref()),
        &of("channel", Some(&channel.id)),
    )
}

/// What the evaluation of a channel needs of a member, borrowed (the visibility snapshot keeps it per member and
/// evaluates every channel of a room with it).
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    pub user_id: &'a str,
    pub is_owner: bool,
    pub is_node_admin: bool,
    pub everyone_role_id: &'a str,
    pub everyone_permissions: Perms,
    /// The member's roles without @everyone.
    pub member_roles: &'a [(String, Perms)],
    pub timed_out: bool,
    pub kind: &'a str,
    pub scopes: Option<&'a [String]>,
    /// Passes `adults_only` gates (PROTOCOL.md §5e).
    pub adult: bool,
    pub moved_channel: Option<&'a str>,
}

/// The single evaluation of a member's permissions in a channel ([`channel_perms_with`] and the visibility snapshot):
/// `category_overrides` and `channel_overrides` are exactly the overrides of the channel's category and of the
/// channel.
pub fn channel_perms_of(
    subject: &Subject<'_>,
    channel: &ChannelRow,
    category_overrides: &[permissions::Override],
    channel_overrides: &[permissions::Override],
) -> Perms {
    // Age gates (PROTOCOL.md §5e) come before everything: below the gate nothing, owners and admins included.
    if !(subject.adult || !channel.adults_only()) {
        return 0;
    }
    let bot = |p: Perms| permissions::cap_bot(p, subject.kind, channel.no_bots(), subject.scopes);
    let system = channel.kind == "system";
    let restrict = |p: Perms| bot(if system { p & !SYSTEM_CHANNEL_DENIED } else { p });
    if subject.is_owner || subject.is_node_admin {
        return restrict(permissions::ALL);
    }
    permissions::compute_ref(&permissions::InputRef {
        user_id: subject.user_id,
        is_owner: subject.is_owner,
        everyone_role_id: subject.everyone_role_id,
        everyone_permissions: subject.everyone_permissions,
        member_roles: subject.member_roles,
        category_overrides,
        channel_overrides,
        timed_out: subject.timed_out,
        kind: subject.kind,
        no_bots: channel.no_bots(),
        scopes: subject.scopes,
        system_channel: system,
        moved: channel.kind == "voice" && subject.moved_channel == Some(channel.id.as_str()),
    })
}

/// Upload categories (`uploads.rs`) of the member in a channel: the highest role with a setting (else
/// `@everyone`), then the category's overrides and the channel's own on top (the same layers as the permissions).
pub fn channel_upload_categories_with(
    access: &RoomAccess,
    channel: &ChannelRow,
    overrides: &[OverrideRow],
    user_id: &str,
) -> crate::uploads::Categories {
    upload_categories_at(access, channel.category_id.as_deref(), Some(&channel.id), overrides, user_id)
}

/// Upload categories of the member at the layers of a category and (optionally) a channel in it: for a category
/// alone (`channel_id` `None`) what holds in its channels before their own overrides.
pub fn upload_categories_at(
    access: &RoomAccess,
    category_id: Option<&str>,
    channel_id: Option<&str>,
    overrides: &[OverrideRow],
    user_id: &str,
) -> crate::uploads::Categories {
    use crate::uploads;
    let layer = |target_type: &str, target_id: Option<&str>| -> Vec<(permissions::Override, u64, u64)> {
        overrides
            .iter()
            .filter(|o| o.target_type == target_type && Some(o.target_id.as_str()) == target_id)
            .map(|o| (o.to_eval(), o.upload_allow as u64, o.upload_deny as u64))
            .collect()
    };
    let (category_layer, own_layer) = (layer("category", category_id), layer("channel", channel_id));
    fn to_upload(l: &[(permissions::Override, u64, u64)]) -> Vec<crate::uploads::UploadOverride<'_>> {
        l.iter().map(|(e, allow, deny)| crate::uploads::UploadOverride::of(e, *allow, *deny)).collect()
    }
    let (category, own) = (to_upload(&category_layer), to_upload(&own_layer));
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
        &[&category, &own],
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
            let overrides = store::rooms::overrides_of_channel(&state.db, channel).await?;
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
    | permissions::USE_WHITEBOARD
    | permissions::CREATE_POLLS
    | permissions::USE_COMPONENTS;

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

/// Does [`message`] apply the requester's history window?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// Reading the message (or acting on it in a way that serves it): an encrypted message older than the
    /// requester's history window (ENCRYPTION.md §7b) is not found, as on a page of messages.
    Apply,
    /// Writes addressed to the message by id that serve no older content (edit, delete, the read marker).
    Ignore,
}

/// The message `message_id` (any case) of `conv`: `404 message.not_found` when there is no such message in this
/// conversation or, with [`Window::Apply`], when it lies before the requester's history window. The one lookup of
/// a conversation's message by id; the caller has checked the permissions it needs.
pub async fn message(
    state: &AppState,
    user: &UserRow,
    conv: &Conv,
    message_id: &str,
    window: Window,
) -> Result<crate::models::MessageRow, ApiError> {
    let missing = || not_found("Message", "message.not_found");
    let message = store::messages::by_id(&state.db, &message_id.to_ascii_uppercase())
        .await?
        .filter(|m| m.conversation_id == conv.id)
        .ok_or_else(missing)?;
    if window == Window::Apply
        && message.encrypted != 0
        && let Some(cut) = crate::history::list_cutoff(state, conv, user).await?
        && message.id.as_str() < cut.as_str()
    {
        return Err(missing());
    }
    Ok(message)
}

pub(crate) fn conversation_not_found() -> ApiError {
    not_found("Conversation", "conversation.not_found")
}

async fn channel_conv(
    state: &AppState,
    access: RoomAccess,
    channel: ChannelRow,
    user: &UserRow,
) -> Result<Conv, ApiError> {
    require_age(&access, &channel)?;
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
    conversation_of_row(state, row, user).await
}

/// [`conversation`] for an already loaded conversation row.
pub async fn conversation_of_row(
    state: &AppState,
    row: crate::store::social::ConversationRow,
    user: &UserRow,
) -> Result<Conv, ApiError> {
    match (row.kind.as_str(), &row.room_id) {
        ("channel", Some(room_id)) => {
            let access = room_access(state, room_id, user).await?;
            let channel = channel_in_room(state, room_id, &row.id).await?;
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
    Ok(entitled_users(state, conv, &[user]).await?.contains(&user.id))
}

/// [`user_entitled`] for several users at once (the added and removed devices of an MLS commit): the ids of the
/// entitled ones, with a constant number of statements. For channels: room members with `view_channel`, evaluated
/// like [`room_access`] and [`channel_perms`] with the room and roles of `conv` (loaded by this request).
pub async fn entitled_users(
    state: &AppState,
    conv: &Conv,
    users: &[&UserRow],
) -> Result<std::collections::HashSet<String>, ApiError> {
    let candidates: Vec<&UserRow> = users.iter().copied().filter(|u| u.disabled_at.is_none()).collect();
    let (access, channel) = match &conv.kind {
        ConvKind::Direct { member_ids, .. } => {
            return Ok(candidates.iter().filter(|u| member_ids.contains(&u.id)).map(|u| u.id.clone()).collect());
        }
        ConvKind::Channel { access, channel } => (access, channel),
    };
    let room_id = &access.room.id;
    let mut ids: Vec<String> = candidates.iter().map(|u| u.id.clone()).collect();
    ids.sort();
    ids.dedup();
    let mut out = std::collections::HashSet::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let members = store::rooms::members_by_ids(&state.db, room_id, &ids).await?;
    let role_ids = store::rooms::member_role_ids_of(&state.db, room_id, &ids).await?;
    let overrides = store::rooms::overrides_of_channel(&state.db, channel).await?;
    for user in candidates {
        let Some(member) = members.get(&user.id) else { continue };
        if out.contains(&user.id) {
            continue;
        }
        let adult = crate::age::is_adult(state, user).await?;
        let moved = crate::voice::moved::channel_of(state, room_id, &user.id);
        let roles = role_ids.get(&user.id).map(Vec::as_slice).unwrap_or_default();
        let a = member_access(access.room.clone(), &access.roles, Some(member.clone()), roles, user, adult, moved)?;
        if permissions::has(channel_perms_with(&a, channel, &overrides, &user.id), permissions::VIEW_CHANNEL) {
            out.insert(user.id.clone());
        }
    }
    Ok(out)
}
