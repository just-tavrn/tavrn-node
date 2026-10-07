// SPDX-License-Identifier: AGPL-3.0-only
//! Notification settings of local users and how the node applies them.
//!
//! Stored per user as validated JSON (`GET/PUT /users/me/notification-settings`, home node only):
//!
//! ```json
//! { "global":   { "mode": "all", "sound": true, "browser": false },
//!   "rooms":    { "<room id>": { "mode": "mentions", "muted_until": null, "suppress_everyone": true } },
//!   "channels": { "<conversation id>": { "mode": "nothing", "muted_until": "forever" } } }
//! ```
//!
//! `mode` is `all` (every message notifies), `mentions` (only mentions of the user, one of their roles or
//! `@everyone`) or `nothing`. A channel's mode wins over its room's, which wins over the global one.
//! `muted_until` (RFC 3339 or `"forever"`) mutes until then; a muted room mutes all its channels. The
//! node applies the settings to the unread and mention counts of its room and conversation lists
//! (muted: both 0 and `muted: true`; mode `nothing`: no mentions counted; `suppress_everyone`:
//! `@everyone` is no mention) and to received `notify` hints (FEDERATION.md §5.2): muted conversations and
//! those whose mode does not ask for the hint are dropped before they are stored or forwarded. Sound and
//! browser notifications are the client's to apply.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{db::Pool, error::ApiError, util, validate::bad};

/// Largest serialized settings document.
pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_ROOMS: usize = 500;
pub const MAX_CHANNELS: usize = 2000;
/// `muted_until` value for "until I unmute".
pub const FOREVER: &str = "forever";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    All,
    Mentions,
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalSettings {
    #[serde(default)]
    pub mode: Mode,
    /// Play a sound for notifications (client side).
    #[serde(default = "yes")]
    pub sound: bool,
    /// Browser notifications while the tab is in the background (client side).
    #[serde(default)]
    pub browser: bool,
    /// Web push (PROTOCOL.md §6d): include a preview of unencrypted messages (default off; never for encrypted
    /// conversations). Left out of the document while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub push_text: bool,
}

fn yes() -> bool {
    true
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self { mode: Mode::All, sound: true, browser: false, push_text: false }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// RFC 3339 time or `"forever"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted_until: Option<String>,
    /// `@everyone` and `@here` do not count as mentions in this room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppress_everyone: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// RFC 3339 time or `"forever"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted_until: Option<String>,
}

/// The notification settings of a user. (OpenAPI name `StoredNotificationSettings`: the SDK hand-writes a
/// stricter `NotificationSettings` type for clients.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = StoredNotificationSettings)]
#[serde(deny_unknown_fields)]
pub struct NotificationSettings {
    #[serde(default)]
    pub global: GlobalSettings,
    /// By room id.
    #[serde(default)]
    pub rooms: BTreeMap<String, RoomSettings>,
    /// By conversation id (channels, DMs, group DMs).
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelSettings>,
}

fn invalid(detail: impl Into<String>) -> ApiError {
    bad("notifications.invalid", detail)
}

fn normalize_until(v: &Option<String>) -> Result<Option<String>, ApiError> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(FOREVER) => Ok(Some(FOREVER.into())),
        Some(t) => util::parse_time(t)
            .map(|t| Some(util::format_time(t)))
            .ok_or_else(|| invalid("muted_until: RFC 3339 time or \"forever\"")),
    }
}

impl NotificationSettings {
    /// Checks ids, limits and times; drops entries that set nothing. Returns the normalized settings.
    pub fn validated(mut self) -> Result<Self, ApiError> {
        if self.rooms.len() > MAX_ROOMS || self.channels.len() > MAX_CHANNELS {
            return Err(invalid(format!("At most {MAX_ROOMS} rooms and {MAX_CHANNELS} channels")));
        }
        for (id, r) in self.rooms.iter_mut() {
            if !util::is_ulid(id) {
                return Err(invalid("rooms: keys are room ids"));
            }
            r.muted_until = normalize_until(&r.muted_until)?;
        }
        for (id, c) in self.channels.iter_mut() {
            if !util::is_ulid(id) {
                return Err(invalid("channels: keys are conversation ids"));
            }
            c.muted_until = normalize_until(&c.muted_until)?;
        }
        self.rooms.retain(|_, r| *r != RoomSettings::default());
        self.channels.retain(|_, c| *c != ChannelSettings::default());
        let size = serde_json::to_vec(&self).map_err(|e| ApiError::Internal(e.into()))?.len();
        if size > MAX_BYTES {
            return Err(ApiError::PayloadTooLarge {
                code: "notifications.too_large",
                detail: format!("Notification settings are limited to {} KiB", MAX_BYTES / 1024),
                meta: serde_json::json!({ "max_bytes": MAX_BYTES }),
            });
        }
        Ok(self)
    }

    /// What applies to one conversation (`room_id` for room channels).
    pub fn effective(&self, room_id: Option<&str>, conversation_id: &str, now: &str) -> Effective {
        let room = room_id.and_then(|r| self.rooms.get(r));
        let channel = self.channels.get(conversation_id);
        let muted_at = |until: Option<&String>| until.is_some_and(|u| u == FOREVER || u.as_str() > now);
        Effective {
            muted: muted_at(channel.and_then(|c| c.muted_until.as_ref()))
                || muted_at(room.and_then(|r| r.muted_until.as_ref())),
            mode: channel.and_then(|c| c.mode).or(room.and_then(|r| r.mode)).unwrap_or(self.global.mode),
            suppress_everyone: room.and_then(|r| r.suppress_everyone).unwrap_or(false),
        }
    }
}

impl NotificationSettings {
    /// Should a new message notify the user by web push? The rules clients apply to their own notifications
    /// (PROTOCOL.md §6d): nothing while muted or under `nothing`; DMs and group DMs (`room_id` = `None`) follow
    /// their own mode, else every message unless the global mode is `nothing`, and always count as mentions;
    /// in channels `mentions` lets through direct mentions (`direct`: the user or one of their roles) and
    /// `@everyone` (`everyone`) unless the room suppresses it. `Some(true)` for a mention or DM, `Some(false)` for
    /// another message, `None` for no push.
    pub fn push_decision(
        &self,
        room_id: Option<&str>,
        conversation_id: &str,
        now: &str,
        direct: bool,
        everyone: bool,
    ) -> Option<bool> {
        let effective = self.effective(room_id, conversation_id, now);
        if effective.muted {
            return None;
        }
        let mode = match room_id {
            Some(_) => effective.mode,
            None => self.channels.get(conversation_id).and_then(|c| c.mode).unwrap_or(match self.global.mode {
                Mode::Nothing => Mode::Nothing,
                _ => Mode::All,
            }),
        };
        let mentioned = room_id.is_none() || direct || (everyone && !effective.suppress_everyone);
        match mode {
            Mode::Nothing => None,
            Mode::Mentions if !mentioned => None,
            _ => Some(mentioned),
        }
    }
}

/// Settings as they apply to one conversation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Effective {
    pub muted: bool,
    pub mode: Mode,
    pub suppress_everyone: bool,
}

impl Effective {
    /// The mention count given direct mentions (user or role) and `@everyone` mentions.
    pub fn mentions(&self, direct: i64, everyone: i64) -> i64 {
        if self.muted || self.mode == Mode::Nothing {
            return 0;
        }
        if self.suppress_everyone { direct } else { direct + everyone }
    }

    /// Should a `notify` hint (a new message, `mention` = it mentions the user directly or by role,
    /// `everyone` = only by `@everyone`) reach the user?
    pub fn wants_hint(&self, mention: bool, everyone: bool) -> bool {
        let mention = mention || (everyone && !self.suppress_everyone);
        !self.muted
            && match self.mode {
                Mode::All => true,
                Mode::Mentions => mention,
                Mode::Nothing => false,
            }
    }
}

pub async fn load(db: &Pool, user_id: &str) -> Result<NotificationSettings, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT settings FROM notification_settings WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|(s,)| serde_json::from_str(&s).ok()).unwrap_or_default())
}

pub async fn save(db: &Pool, user_id: &str, settings: &NotificationSettings) -> Result<(), ApiError> {
    let json = serde_json::to_string(settings).map_err(|e| ApiError::Internal(e.into()))?;
    let now = util::now();
    sqlx::query(
        "INSERT INTO notification_settings (user_id, settings, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET settings = excluded.settings, updated_at = excluded.updated_at",
    )
    .bind(user_id)
    .bind(json)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const ROOM: &str = "01JAAAAAAAAAAAAAAAAAAAAAAA";
    const CHAN: &str = "01JBBBBBBBBBBBBBBBBBBBBBBB";

    fn parse(v: serde_json::Value) -> Result<NotificationSettings, String> {
        serde_json::from_value::<NotificationSettings>(v)
            .map_err(|e| e.to_string())?
            .validated()
            .map_err(|e| e.code().to_string())
    }

    #[test]
    fn validation_normalizes_and_limits() {
        let s = parse(serde_json::json!({
            "global": { "mode": "mentions" },
            "rooms": { ROOM: { "muted_until": "2030-01-01T00:00:00+01:00" }, "01JCCCCCCCCCCCCCCCCCCCCCCC": {} },
            "channels": { CHAN: { "muted_until": "forever" } }
        }))
        .unwrap();
        assert_eq!(s.global, GlobalSettings { mode: Mode::Mentions, sound: true, browser: false, push_text: false });
        assert_eq!(s.rooms.len(), 1, "empty entries are dropped");
        assert_eq!(s.rooms[ROOM].muted_until.as_deref(), Some("2029-12-31T23:00:00.000Z"));
        assert_eq!(s.channels[CHAN].muted_until.as_deref(), Some(FOREVER));
        assert_eq!(
            parse(serde_json::json!({ "rooms": { "nope": { "mode": "all" } } })),
            Err("notifications.invalid".into())
        );
        assert_eq!(
            parse(serde_json::json!({ "channels": { CHAN: { "muted_until": "soon" } } })),
            Err("notifications.invalid".into())
        );
        assert!(parse(serde_json::json!({ "global": { "mode": "loud" } })).is_err());
        assert!(parse(serde_json::json!({ "extra": 1 })).is_err(), "unknown fields are refused");
    }

    #[test]
    fn effective_settings_and_counts() {
        let s = parse(serde_json::json!({
            "global": { "mode": "all" },
            "rooms": { ROOM: { "mode": "mentions", "suppress_everyone": true } },
            "channels": { CHAN: { "mode": "nothing" } }
        }))
        .unwrap();
        let now = "2026-10-05T00:00:00.000Z";
        let room = s.effective(Some(ROOM), "01JDDDDDDDDDDDDDDDDDDDDDDD", now);
        assert_eq!(room, Effective { muted: false, mode: Mode::Mentions, suppress_everyone: true });
        assert_eq!(room.mentions(2, 5), 2);
        assert!(room.wants_hint(true, false) && !room.wants_hint(false, true) && !room.wants_hint(false, false));
        let channel = s.effective(Some(ROOM), CHAN, now);
        assert_eq!(channel.mode, Mode::Nothing);
        assert_eq!(channel.mentions(2, 5), 0);
        assert!(!channel.wants_hint(true, false));
        let dm = s.effective(None, "01JEEEEEEEEEEEEEEEEEEEEEEE", now);
        assert_eq!(dm, Effective::default());
        assert_eq!(dm.mentions(1, 1), 2);

        // Push: DMs notify unless the global mode is `nothing`; channels follow the mode.
        assert_eq!(s.push_decision(None, "01JEEEEEEEEEEEEEEEEEEEEEEE", now, false, false), Some(true));
        assert_eq!(s.push_decision(Some(ROOM), "01JDDDDDDDDDDDDDDDDDDDDDDD", now, false, false), None);
        assert_eq!(s.push_decision(Some(ROOM), "01JDDDDDDDDDDDDDDDDDDDDDDD", now, true, false), Some(true));
        assert_eq!(s.push_decision(Some(ROOM), "01JDDDDDDDDDDDDDDDDDDDDDDD", now, false, true), None, "suppressed");
        assert_eq!(s.push_decision(Some(ROOM), CHAN, now, true, false), None, "channel mode nothing");
        let all = parse(serde_json::json!({})).unwrap();
        assert_eq!(all.push_decision(Some(ROOM), CHAN, now, false, false), Some(false), "default: every message");
        assert_eq!(all.push_decision(Some(ROOM), CHAN, now, false, true), Some(true), "@everyone is a mention");
        let quiet = parse(serde_json::json!({ "global": { "mode": "nothing" }, "channels": { CHAN: { "mode": "all" } } })).unwrap();
        assert_eq!(quiet.push_decision(None, "01JEEEEEEEEEEEEEEEEEEEEEEE", now, false, false), None);
        assert_eq!(quiet.push_decision(None, CHAN, now, false, false), Some(true), "a DM's own mode wins");
        let text = parse(serde_json::json!({ "global": { "push_text": true } })).unwrap();
        assert!(text.global.push_text);
        assert!(!serde_json::to_string(&all).unwrap().contains("push_text"), "left out while off");

        let muted = parse(serde_json::json!({ "rooms": { ROOM: { "muted_until": "2026-10-06T00:00:00Z" } } })).unwrap();
        assert!(muted.effective(Some(ROOM), CHAN, now).muted, "a muted room mutes its channels");
        assert!(!muted.effective(Some(ROOM), CHAN, "2026-10-07T00:00:00.000Z").muted, "until the time passed");
        assert!(!muted.effective(Some(ROOM), CHAN, now).wants_hint(true, false));
        assert_eq!(muted.push_decision(Some(ROOM), CHAN, now, true, false), None, "muted: no push");
    }
}
