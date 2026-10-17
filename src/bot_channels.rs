// SPDX-License-Identifier: AGPL-3.0-only
//! Bots and end-to-end encrypted channels (decided 2026-10-06; APPLICATIONS.md §3.5, §3.6).
//!
//! - The room setting `bots_in_encrypted_channels` (`per_channel` | `allowed`) and the channel setting
//!   `bots_allowed` feed the effective "no bots" flag of a channel (`permissions::no_bots_effective`, computed by
//!   `ChannelRow::no_bots`). Everything that already honours that flag follows: permission evaluation (a bot has
//!   nothing in such a channel), the MLS entitlement of external joins and Adds (`403 mls.forbidden`), the channel list
//!   served to bots, the conversation member list for the roster check and the clients' ghost rule.
//! - When a change closes a channel to bots, the bots' leaves are announced with `mls.remove_needed`; when it opens a
//!   channel, `channel.update` tells the bot runtime to join.
//! - Whenever a bot's leaf joins or leaves an encrypted channel's group, the security log gets
//!   `system.bot_added` / `system.bot_removed` (the commit decides, so the entry says what really happened): the
//!   welcome channel when `@everyone` can view the channel, else the channel itself (`welcome::bot_membership`).

use std::collections::HashSet;

use serde_json::json;
use tavrn_crypto::ds::{CommitSummary, DsGroup};

use crate::{
    access::{Conv, ConvKind},
    app::AppState,
    error::ApiError,
    models::{ChannelRow, Room, UserRow},
    permissions, store,
    validate::bad,
    welcome::{self, BotChange},
};

/// `400 validation.bots_in_encrypted_channels` for anything but `per_channel` / `allowed`.
pub fn validate_setting(value: &str) -> Result<&'static str, ApiError> {
    permissions::BOTS_IN_ENCRYPTED_CHANNELS.iter().copied().find(|v| *v == value).ok_or_else(|| {
        bad("validation.bots_in_encrypted_channels", "bots_in_encrypted_channels: per_channel or allowed")
    })
}

/// Bots never change who may read along: they cannot open channels or rooms to bots (`403 app.bot_forbidden`).
pub fn refuse_bots(actor: &UserRow) -> Result<(), ApiError> {
    if actor.is_bot() {
        return Err(crate::applications::bot_forbidden());
    }
    Ok(())
}

/// After the effective "no bots" flags of some channels may have changed (`before` = the channels as they were):
/// the bots' leaves of newly closed channels are announced (`mls.remove_needed`) and every changed channel is sent
/// as `channel.update` (unless it is in `skip_update`, whose caller sends it). Returns the channels that changed.
pub async fn effective_changed(
    state: &AppState,
    room_id: &str,
    before: &[ChannelRow],
    skip_update: Option<&str>,
) -> Result<Vec<ChannelRow>, ApiError> {
    let after = store::rooms::channels(&state.db, room_id).await?;
    let mut closed = Vec::new();
    let mut changed = Vec::new();
    for c in after {
        let was = before.iter().find(|b| b.id == c.id).map(ChannelRow::no_bots);
        if was == Some(c.no_bots()) {
            continue;
        }
        if c.no_bots() {
            closed.push(c.id.clone());
        }
        changed.push(c);
    }
    if !closed.is_empty() {
        crate::e2ee::bots_excluded(state, room_id, &closed).await?;
    }
    for c in &changed {
        if skip_update != Some(c.id.as_str()) {
            state.hub.room(room_id, "channel.update", c.to_api());
        }
    }
    Ok(changed)
}

/// `PATCH /rooms/{id} { bots_in_encrypted_channels }` (owner or `manage_room`, never a bot): stores the setting,
/// audits `room.bots_in_encrypted_channels` and applies the changed flags.
pub async fn set_room_setting(state: &AppState, room: &Room, actor: &UserRow, value: &str) -> Result<(), ApiError> {
    refuse_bots(actor)?;
    let value = validate_setting(value)?;
    if room.bots_in_encrypted_channels == value {
        return Ok(());
    }
    let before = store::rooms::channels(&state.db, &room.id).await?;
    store::applications::set_bots_in_encrypted(&state.db, &room.id, value).await?;
    let changed = effective_changed(state, &room.id, &before, None).await?;
    store::rooms::audit(
        &state.db,
        Some(&room.id),
        Some(&actor.id),
        "room.bots_in_encrypted_channels",
        &room.id,
        "",
        json!({ "from": room.bots_in_encrypted_channels, "to": value, "channels_changed": changed.len() }),
    )
    .await?;
    Ok(())
}

/// `PATCH …/channels/{id} { bots_allowed }` (`manage_channels` and `manage_room`, never a bot): stores the setting,
/// audits `channel.bots_allowed` and, if the channel closed, announces the bots' leaves. The caller sends the
/// `channel.update`.
pub async fn set_channel_setting(
    state: &AppState,
    room_id: &str,
    actor: &UserRow,
    current: &ChannelRow,
    value: bool,
) -> Result<(), ApiError> {
    refuse_bots(actor)?;
    if (current.bots_allowed != 0) == value {
        return Ok(());
    }
    store::applications::set_bots_allowed(&state.db, room_id, &current.id, value).await?;
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(&actor.id),
        "channel.bots_allowed",
        &current.id,
        "",
        json!({ "value": value, "encrypted": current.encrypted != 0 }),
    )
    .await?;
    effective_changed(state, room_id, std::slice::from_ref(current), Some(&current.id)).await?;
    Ok(())
}

// ---------------------------------------------------------------- security log (system.bot_added / _removed)

fn addresses(roster: &[tavrn_crypto::RosterEntry]) -> HashSet<String> {
    roster.iter().filter_map(|e| e.identity.split_once('/').map(|(a, _)| a.to_string())).collect()
}

/// After an accepted commit in a channel's group: a security log entry for every bot whose first leaf joined or
/// whose last leaf left. `before` is the DS state before the commit, `after` the roster after it.
pub async fn after_commit(
    state: &AppState,
    conv: &Conv,
    committer: &UserRow,
    summary: &CommitSummary,
    before: &[u8],
    after: &[tavrn_crypto::RosterEntry],
) {
    let ConvKind::Channel { access, channel } = &conv.kind else { return };
    let mut candidates: Vec<String> = Vec::new();
    if summary.external_join {
        candidates.push(committer.address());
    }
    for identity in summary.added.iter().map(|a| a.identity.as_str()).chain(summary.removed.iter().map(String::as_str))
    {
        if let Some((address, _)) = identity.split_once('/') {
            candidates.push(address.to_string());
        }
    }
    candidates.sort();
    candidates.dedup();
    if candidates.is_empty() {
        return;
    }
    let had = DsGroup::import_state(before).and_then(|g| g.roster()).map(|r| addresses(&r)).unwrap_or_default();
    let has = addresses(after);
    for address in candidates {
        let (was, is) = (had.contains(&address), has.contains(&address));
        if was == is {
            continue;
        }
        let Some(bot) = bot_by_address(state, &address).await else { continue };
        if is {
            let by = committer.address();
            welcome::bot_membership(state, &access.room, &bot, channel, BotChange::Added { by: &by }).await;
        } else {
            let reason = removal_reason(state, &access.room, channel, &bot, committer).await;
            welcome::bot_membership(state, &access.room, &bot, channel, BotChange::Removed { reason: &reason }).await;
        }
    }
}

/// A bot created a channel's group (its own leaf is the first).
pub async fn after_group_created(state: &AppState, conv: &Conv, creator: &UserRow) {
    let ConvKind::Channel { access, channel } = &conv.kind else { return };
    if creator.is_bot() {
        let by = creator.address();
        welcome::bot_membership(state, &access.room, creator, channel, BotChange::Added { by: &by }).await;
    }
}

async fn bot_by_address(state: &AppState, address: &str) -> Option<UserRow> {
    let (username, domain) = crate::util::parse_address(address)?;
    let user = store::federation::user_by_address(&state.db, username, domain).await.ok()??;
    user.is_bot().then_some(user)
}

/// Why a bot's last leaf left the group, from the node's view right after the commit: the bot itself (`left`), the
/// reason of its uninstall when it is no member any more (`uninstalled`, `kicked`, `banned`, `no_bots`, …), a closed
/// channel (`no_bots` for an explicit flag, `bots_not_allowed` for an encrypted channel of a `per_channel` room
/// without `bots_allowed`), lost read access (`no_access`), else a deleted or unattested device (`device_removed`).
async fn removal_reason(
    state: &AppState,
    room: &Room,
    channel: &ChannelRow,
    bot: &UserRow,
    committer: &UserRow,
) -> String {
    if committer.id == bot.id {
        return "left".into();
    }
    let member = store::rooms::member(&state.db, &room.id, &bot.id).await.ok().flatten();
    if member.is_none() {
        return last_uninstall_reason(state, &room.id, &bot.address()).await;
    }
    if channel.no_bots != 0 || channel.inherited_no_bots != 0 {
        return "no_bots".into();
    }
    if channel.no_bots() {
        return "bots_not_allowed".into();
    }
    let entitled = match crate::access::room_access(state, &room.id, bot).await {
        Ok(a) => crate::access::channel_perms(state, &a, channel, &bot.id)
            .await
            .is_ok_and(|p| permissions::has(p, permissions::VIEW_CHANNEL)),
        Err(_) => false,
    };
    if entitled { "device_removed".into() } else { "no_access".into() }
}

/// The `meta.reason` of the bot's latest `app.uninstall` in the room (`removed` is reported as `uninstalled`).
async fn last_uninstall_reason(state: &AppState, room_id: &str, address: &str) -> String {
    let meta: Option<String> = sqlx::query_scalar(
        "SELECT meta FROM audit_log WHERE room_id = $1 AND action = 'app.uninstall' AND target = $2 ORDER BY id DESC LIMIT 1",
    )
    .bind(room_id)
    .bind(address)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let reason = meta
        .and_then(|m| serde_json::from_str::<serde_json::Value>(&m).ok())
        .and_then(|m| m["reason"].as_str().map(String::from))
        .unwrap_or_default();
    match reason.as_str() {
        "" | "removed" => "uninstalled".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_validated() {
        assert_eq!(validate_setting("per_channel").ok(), Some("per_channel"));
        assert_eq!(validate_setting("allowed").ok(), Some("allowed"));
        for bad in ["", "ALLOWED", "always", "per_channel ", "allowed'--"] {
            assert!(validate_setting(bad).is_err(), "{bad}");
        }
    }
}
