// SPDX-License-Identifier: AGPL-3.0-only
//! The welcome channel: a fixed system channel per room (`kind = "system"`,
//! `system_name = "welcome"`) that is the room's security log. The node writes `system.join`, `system.leave`,
//! `system.key_changed`, `system.bot_added`, `system.bot_removed`, `system.history_restored` and
//! `system.history_restore_denied` entries; clients render them localized. Only entries about members are written
//! here unconditionally: an entry about a channel (`system.bot_*`) names the channel, so it comes here only when
//! `@everyone` can view that channel and otherwise goes into the channel itself ([`bot_membership`]). Nobody can write there (reactions are allowed),
//! nobody can hide it (`view_channel` is forced, `permissions::SYSTEM_CHANNEL_FORCED`), it is never encrypted and
//! its whole history is readable for every member, including new ones.

use serde_json::json;

use crate::{
    app::AppState,
    error::ApiError,
    models::{Room, UserRow, media_url},
    store,
};

/// Why a member left: `leave` (by themselves), `kick` or `ban`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveKind {
    Leave,
    Kick,
    Ban,
}

impl LeaveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Leave => "leave",
            Self::Kick => "kick",
            Self::Ban => "ban",
        }
    }
}

/// The plaintext content of an entry: the user's address, a snapshot of the display name and the
/// avatar paths at that moment.
fn entry(kind: &str, user: &UserRow) -> serde_json::Value {
    json!({
        "type": kind,
        "user": user.address(),
        "display_name": user.display_name,
        "avatar": media_url(user.avatar_blob_id.as_deref(), user.avatar_animated != 0),
        "avatar_still": media_url(user.avatar_blob_id.as_deref(), false),
    })
}

async fn write(state: &AppState, room: &Room, user: &UserRow, content: serde_json::Value) -> Result<(), ApiError> {
    let Some(channel) = store::rooms::welcome_channel(&state.db, &room.id).await? else { return Ok(()) };
    let kind = content.get("type").and_then(|t| t.as_str()).unwrap_or("system.join").to_string();
    let message = crate::routes::messages::system_message(state, &channel.to_api(), user, &kind, content).await?;
    state.hub.room(&room.id, "message.create", &message);
    Ok(())
}

/// `system.join` for a new member. Failures are logged: joining never fails because of the entry.
pub async fn joined(state: &AppState, room: &Room, user: &UserRow) {
    if let Err(e) = write(state, room, user, entry("system.join", user)).await {
        tracing::warn!(error = %e, room = room.id, "welcome entry not written");
    }
}

/// `system.leave` with `reason_kind` (`leave`, `kick`, `ban`).
pub async fn left(state: &AppState, room: &Room, user: &UserRow, kind: LeaveKind) {
    let mut content = entry("system.leave", user);
    content["reason_kind"] = json!(kind.as_str());
    if let Err(e) = write(state, room, user, content).await {
        tracing::warn!(error = %e, room = room.id, "welcome entry not written");
    }
}

/// After a membership ended (leave, kick, ban, node ban): the per-room profile goes with it (its avatar
/// files are deleted right away) and the welcome channel gets the `system.leave` entry.
pub async fn membership_ended(
    state: &AppState,
    room: &Room,
    user: &UserRow,
    member: Option<&crate::models::MemberRow>,
    kind: LeaveKind,
) {
    if let Some(id) = member.and_then(|m| m.avatar_media_id.as_deref())
        && let Err(e) = crate::profile::delete_media(state, id).await
    {
        tracing::warn!(error = %e, "room avatar not deleted");
    }
    if let Err(e) = store::history::membership_ended(&state.db, &room.id, &user.id).await {
        tracing::warn!(error = %e, "history requests of the membership not closed");
    }
    left(state, room, user, kind).await;
}

/// `system.history_restored { user, …, by }` or `system.history_restore_denied { user, …, by }`: a member with
/// `restore_history` decided a member's request to restore the history after a key reset (ENCRYPTION.md §7b). The
/// reason of a denial stays in the audit log. Failures are logged (the decision already happened).
pub async fn history_restore_decided(state: &AppState, room: &Room, user: &UserRow, approved: bool, by: &str) {
    let kind = if approved { "system.history_restored" } else { "system.history_restore_denied" };
    let mut content = entry(kind, user);
    content["by"] = json!(by);
    if let Err(e) = write(state, room, user, content).await {
        tracing::warn!(error = %e, room = room.id, "history restore entry not written");
    }
}

/// `system.key_changed { user, display_name, avatar, avatar_still, at, rotated }` in the welcome channel of every room on this node that `user` is a
/// member of (ENCRYPTION.md §9, §9a): the identity key changed by a reset (`rotated: false`) or by a rotation with
/// a valid continuity statement (`rotated: true`). Informational only: clients decide with their own pin what the
/// change means. Failures are logged, never returned (the key change itself already happened).
pub async fn key_changed(state: &AppState, user: &UserRow, rotated: bool) {
    let rooms = match store::rooms::room_ids_of_user(&state.db, &user.id).await {
        Ok(rooms) => rooms,
        Err(e) => {
            tracing::warn!(error = %e, user = user.address(), "rooms for the key change entry not loaded");
            return;
        }
    };
    let at = crate::util::now();
    // A reset (not a rotation) starts the member's history window anew (ENCRYPTION.md §7b).
    if !rotated {
        crate::history::key_reset(state, user, &at).await;
    }
    for room_id in rooms {
        let room = match store::rooms::room_by_id(&state.db, &room_id).await {
            Ok(Some(room)) => room,
            _ => continue,
        };
        let mut content = entry("system.key_changed", user);
        content["at"] = json!(at);
        content["rotated"] = json!(rotated);
        if let Err(e) = write(state, &room, user, content).await {
            tracing::warn!(error = %e, room = room.id, "key change entry not written");
        }
    }
}

/// The bot's leaf joined or left the encryption group of an encrypted channel (APPLICATIONS.md §3.6).
pub enum BotChange<'a> {
    /// `by`: the address of the member whose commit added the leaf (the bot itself for an external join).
    Added { by: &'a str },
    /// `reason`: `uninstalled`, `kicked`, `banned`, `left`, `no_bots`, `bots_not_allowed`, `no_access`, `device_removed`, …
    Removed { reason: &'a str },
}

/// `system.bot_added { bot, display_name, avatar, avatar_still, channel, channel_name, channel_system_name, by }` or
/// `system.bot_removed { …, reason }`, so every member who can read the channel sees who can read along
/// (APPLICATIONS.md §3.6). The entry goes into the room's welcome channel only when `@everyone` can view the channel
/// ([`access::everyone_views`]): the welcome channel is read by every member and its events reach every member, so
/// an entry about any other channel would name it to members who cannot view it. Those entries go into the channel
/// itself as a security notice (`messages.notice`: never unread, protected), which reaches exactly the channel's
/// viewers. If the check fails, the channel is chosen (never the wider audience). Failures are logged, never
/// returned (the commit already happened).
pub async fn bot_membership(
    state: &AppState,
    room: &Room,
    bot: &UserRow,
    channel: &crate::models::ChannelRow,
    change: BotChange<'_>,
) {
    let kind = match change {
        BotChange::Added { .. } => "system.bot_added",
        BotChange::Removed { .. } => "system.bot_removed",
    };
    let mut content = entry(kind, bot);
    content["bot"] = json!(bot.address());
    content["channel"] = json!(channel.id);
    content["channel_name"] = json!(channel.name);
    // Default channels are named by clients in the viewer's language (`system_name`, null after a rename).
    content["channel_system_name"] = json!(channel.system_name);
    match change {
        BotChange::Added { by } => content["by"] = json!(by),
        BotChange::Removed { reason } => content["reason"] = json!(reason),
    }
    let public = match crate::access::everyone_views_channel(state, channel).await {
        Ok(public) => public,
        Err(e) => {
            tracing::warn!(error = %e, room = room.id, "channel audience not evaluated; the entry goes into the channel");
            false
        }
    };
    let written =
        if public { write(state, room, bot, content).await } else { notice(state, room, bot, channel, content).await };
    if let Err(e) = written {
        tracing::warn!(error = %e, room = room.id, "bot membership entry not written");
    }
}

/// A security notice in `channel` itself (APPLICATIONS.md §3.6): a plaintext system message marked `notice`, sent
/// as `message.create` to the channel's viewers only (the hub filters room events by the channel they name).
async fn notice(
    state: &AppState,
    room: &Room,
    author: &UserRow,
    channel: &crate::models::ChannelRow,
    content: serde_json::Value,
) -> Result<(), ApiError> {
    let kind = content.get("type").and_then(|t| t.as_str()).unwrap_or_default().to_string();
    let message = crate::routes::messages::system_message(state, &channel.to_api(), author, &kind, content).await?;
    store::messages::mark_notice(&state.db, &message.id).await?;
    state.hub.room(&room.id, "message.create", &message);
    Ok(())
}
