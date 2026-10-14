// SPDX-License-Identifier: AGPL-3.0-only
//! Database rows (`*Row`, internal) and API objects (public, with an OpenAPI schema).
//! Booleans are stored in the database as BIGINT 0/1, permissions as BIGINT; permissions go out as a
//! decimal string because JavaScript cannot represent 64-bit integers losslessly.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use utoipa::ToSchema;

fn b(v: i64) -> bool {
    v != 0
}

// ---------------------------------------------------------------- Users

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub domain: String,
    pub display_name: String,
    pub kind: String,
    pub owner_id: Option<String>,
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub email_verified_at: Option<String>,
    pub identity_pubkey: Option<String>,
    pub identity_reset_at: Option<String>,
    pub is_node_admin: i64,
    /// Media id of the avatar (`media` table); `avatar_animated` = it has an animated variant.
    pub avatar_blob_id: Option<String>,
    pub avatar_animated: i64,
    pub header_blob_id: Option<String>,
    pub header_animated: i64,
    /// friends | everyone_shared | everyone
    pub dm_policy: String,
    /// The status the user chose: online | dnd | invisible (presence.rs).
    pub presence_status: String,
    /// JSON `{ text, emoji, expires_at }` or NULL.
    pub custom_status: Option<String>,
    pub hide_activity: i64,
    pub created_at: String,
    pub disabled_at: Option<String>,
    /// Bots: the owner's address (APPLICATIONS.md §1.4).
    pub owner_address: Option<String>,
    /// Bots: the application ULID (local bots) or reference `<domain>/<ULID>` (remote bots).
    pub application_id: Option<String>,
    /// The account was deleted: the tombstone "Deleted user" or a deleted account row kept for
    /// the grace period.
    #[sqlx(default)]
    pub deleted_at: Option<String>,
    /// Local users: the self-declared date of birth `YYYY-MM-DD` (PROTOCOL.md §5e); never leaves the home node and is
    /// never shown to others. NULL until given.
    pub date_of_birth: Option<String>,
    /// Remote users: the `age_over_18` claim of the home node's latest federation token (1, 0 or NULL = unknown;
    /// FEDERATION.md §2.2). Never exposed.
    pub age_over_18: Option<i64>,
    /// Effective scopes of the app token (or federated bot session) this row was authenticated with; `None`
    /// outside of a bot's own request (= all scopes). Never stored.
    #[sqlx(skip)]
    pub app_scopes: Option<Vec<String>>,
}

impl UserRow {
    pub fn address(&self) -> String {
        format!("{}@{}", self.username, self.domain)
    }
    pub fn is_node_admin(&self) -> bool {
        // Bots are never node admins (APPLICATIONS.md §1.4).
        b(self.is_node_admin) && !self.is_bot()
    }
    /// Bot rules apply (every kind except `user`, `permissions::is_bot_kind`).
    pub fn is_bot(&self) -> bool {
        crate::permissions::is_bot_kind(&self.kind)
    }
    pub fn to_public(&self) -> User {
        if self.deleted_at.is_some() {
            // "Deleted user": no name, avatar or profile (clients show their own translation and no link).
            return User {
                id: self.id.clone(),
                username: self.username.clone(),
                domain: self.domain.clone(),
                address: self.address(),
                display_name: crate::legal::account::TOMBSTONE_NAME.into(),
                kind: self.kind.clone(),
                is_node_admin: false,
                owner: None,
                application_id: None,
                avatar: None,
                avatar_still: None,
                avatar_blob_id: None,
                created_at: self.created_at.clone(),
                deleted: true,
            };
        }
        User {
            deleted: false,
            id: self.id.clone(),
            username: self.username.clone(),
            domain: self.domain.clone(),
            address: self.address(),
            display_name: self.display_name.clone(),
            kind: self.kind.clone(),
            is_node_admin: self.is_node_admin(),
            owner: self.owner_address.clone().filter(|_| self.is_bot()),
            application_id: self.application_id.clone().filter(|_| self.is_bot()),
            avatar: media_url(self.avatar_blob_id.as_deref(), b(self.avatar_animated)),
            avatar_still: media_url(self.avatar_blob_id.as_deref(), false),
            avatar_blob_id: self.avatar_blob_id.clone(),
            created_at: self.created_at.clone(),
        }
    }
    /// The effective direct-message policy of this user under the node's upper bound.
    pub fn dm_policy(&self, node: crate::config::DmPolicy) -> crate::config::DmPolicy {
        crate::config::DmPolicy::parse(&self.dm_policy).min(node)
    }
    pub fn to_private(&self) -> UserPrivate {
        UserPrivate {
            user: self.to_public(),
            email: self.email.clone(),
            email_verified: self.email_verified_at.is_some(),
            has_identity_key: self.identity_pubkey.is_some(),
            has_password: self.password_hash.is_some(),
            notification_settings: None,
            auto_preview: None,
            locale: None,
            date_of_birth: None,
            age_status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub domain: String,
    /// `username@domain`
    pub address: String,
    pub display_name: String,
    /// user | bot | webhook. Clients show a BOT badge for every kind except `user` (APPLICATIONS.md §1.5).
    pub kind: String,
    pub is_node_admin: bool,
    /// Bots: the owner's address (null for users).
    #[serde(default)]
    pub owner: Option<String>,
    /// Bots: the application id (local bots) or reference `<domain>/<ULID>` (remote bots); null for users.
    #[serde(default)]
    pub application_id: Option<String>,
    /// Media id of the avatar.
    pub avatar_blob_id: Option<String>,
    /// Path of the avatar on this node (`/api/v1/media/{id}`, the animated variant if there is one), null
    /// without avatar. Clients show `avatar_still` and switch to this one on hover or while the
    /// user speaks.
    #[serde(default)]
    pub avatar: Option<String>,
    /// Path of the still image (first frame) of the avatar.
    #[serde(default)]
    pub avatar_still: Option<String>,
    pub created_at: String,
    /// A deleted account: clients show "Deleted user" without avatar, profile or link.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

/// Path of a stored image on this node: the still or, if `animated`, the animated variant.
pub fn media_url(id: Option<&str>, animated: bool) -> Option<String> {
    id.filter(|id| crate::util::is_ulid(id))
        .map(|id| if animated { format!("/api/v1/media/{id}/animated") } else { format!("/api/v1/media/{id}") })
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserPrivate {
    #[serde(flatten)]
    pub user: User,
    pub email: Option<String>,
    pub email_verified: bool,
    pub has_identity_key: bool,
    /// `false` for accounts that sign in only with SSO (no password, APPLICATIONS.md §8.3).
    #[serde(default)]
    pub has_password: bool,
    /// `GET /users/me` of local users: the notification settings (`/users/me/notification-settings`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_settings: Option<crate::notifications::NotificationSettings>,
    /// `GET /users/me` and `PATCH /users/me` of local users: load image previews automatically
    /// (`always`, `friends_and_shared` or `never`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_preview: Option<String>,
    /// `GET /users/me` and `PATCH /users/me` of local users: the language of the node's mails (a lowercase language
    /// tag such as `de`; null = English). Clients send theirs when it changes.
    #[serde(default)]
    pub locale: Option<String>,
    /// `GET /users/me` of local users only: the own date of birth `YYYY-MM-DD` (null until given; PROTOCOL.md §5e).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub date_of_birth: Option<Option<String>>,
    /// `GET /users/me` of local users only: the private age status. Never part of any other response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_status: Option<crate::age::AgeStatus>,
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub client: String,
    pub created_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub refresh_token_hash: String,
    pub prev_refresh_token_hash: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    /// Federated sessions end at this time whatever the refreshes (FEDERATION.md §2.5).
    pub max_expires_at: Option<String>,
    /// Time of the last rotation (reuse grace, PROTOCOL.md §5b).
    pub rotated_at: Option<String>,
}

// ---------------------------------------------------------------- Rooms

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rules: String,
    /// public | invite
    pub join_mode: String,
    pub owner_id: String,
    /// Media id of the room icon.
    pub icon_blob_id: Option<String>,
    pub banner_blob_id: Option<String>,
    pub created_at: String,
    /// Listed in the directory and on Discover (FEDERATION.md §7.3; public rooms only).
    #[serde(serialize_with = "int_as_bool")]
    #[schema(value_type = bool)]
    pub discoverable: i64,
    /// The icon has an animated variant (`icon`); lists show `icon_still` and animate on hover only.
    #[serde(serialize_with = "int_as_bool")]
    #[schema(value_type = bool)]
    pub icon_animated: i64,
    /// Path of the icon on this node (the animated variant if there is one), null without icon.
    #[sqlx(skip)]
    pub icon: Option<String>,
    /// Path of the still image of the icon.
    #[sqlx(skip)]
    pub icon_still: Option<String>,
    /// "No bots" zone (APPLICATIONS.md §3.5): no bot can be in the room.
    #[serde(serialize_with = "int_as_bool")]
    #[schema(value_type = bool)]
    pub no_bots: i64,
    /// Bots in encrypted channels (APPLICATIONS.md §3.5): `per_channel` (new rooms; every encrypted channel is "no
    /// bots" unless it sets `bots_allowed`) or `allowed` (rooms that existed before the setting).
    pub bots_in_encrypted_channels: String,
    /// Attachments of the room's channels are deleted after this many days (null = the node's value; a room
    /// can only shorten it).
    pub attachment_retention_days: Option<i64>,
    /// Messages of the room's channels are deleted after this many days (null = the node's value; a room can only
    /// shorten it; pinned messages and the welcome channel are exempt, PROTOCOL.md §7f).
    pub message_retention_days: Option<i64>,
    /// `none` or `adults_only` (PROTOCOL.md §5e): users below 18 never find the room in Discover and cannot join it;
    /// every channel of the room is locked for them.
    pub age_gate: String,
    /// History restore after a key reset (ENCRYPTION.md §7b): `request` (members may ask, default) or `off`.
    pub history_restore: String,
}

impl Room {
    /// Fills the icon paths from the stored ids (rows come from the database without them).
    pub fn with_icon(mut self) -> Self {
        self.icon = media_url(self.icon_blob_id.as_deref(), b(self.icon_animated));
        self.icon_still = media_url(self.icon_blob_id.as_deref(), false);
        self
    }

    pub fn is_discoverable(&self) -> bool {
        b(self.discoverable) && self.join_mode == "public"
    }
}

/// BIGINT 0/1 columns that go out as JSON booleans.
fn int_as_bool<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bool(b(*v))
}

#[derive(Debug, Clone, FromRow)]
pub struct RoleRow {
    pub id: String,
    pub room_id: String,
    pub name: String,
    pub color: Option<String>,
    pub position: i64,
    pub permissions: i64,
    pub hoist: i64,
    pub mentionable: i64,
    pub is_everyone: i64,
    /// Upload category mask (`uploads.rs`); NULL = not set.
    pub upload_categories: Option<i64>,
    /// Application reference of a role created by an installation (APPLICATIONS.md §4.2).
    pub application_id: Option<String>,
}

impl RoleRow {
    pub fn perms(&self) -> u64 {
        self.permissions as u64
    }
    pub fn to_api(&self) -> Role {
        Role {
            id: self.id.clone(),
            room_id: self.room_id.clone(),
            name: self.name.clone(),
            color: self.color.clone(),
            position: self.position,
            permissions: self.perms().to_string(),
            hoist: b(self.hoist),
            mentionable: b(self.mentionable),
            is_everyone: b(self.is_everyone),
            allowed_upload_categories: self.upload_categories.map(|c| crate::uploads::names(c as u64)),
            application_id: self.application_id.clone(),
        }
    }
    pub fn upload_categories(&self) -> Option<u64> {
        self.upload_categories.map(|c| c as u64 & crate::uploads::ALL)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub room_id: String,
    pub name: String,
    pub color: Option<String>,
    pub position: i64,
    /// u64 bitmask as a decimal string
    pub permissions: String,
    /// Shown as its own group in the member list ("display separately").
    pub hoist: bool,
    pub mentionable: bool,
    pub is_everyone: bool,
    /// Upload categories members with this role may attach (`images`, `audio`, `video`, `documents`,
    /// `archives`, `other`; protocol/PROTOCOL.md §7a). Null = not set: the member's highest role with a
    /// value decides, else `@everyone` (never null). Channel overrides allow or deny categories on top.
    #[serde(default)]
    pub allowed_upload_categories: Option<Vec<String>>,
    /// Set on a role an installation created: the application reference `<domain>/<id>` (shown as "managed
    /// by <application>" in the role editor; editable and deletable like any role, APPLICATIONS.md §4.2).
    #[serde(default)]
    pub application_id: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Category {
    pub id: String,
    pub room_id: String,
    pub name: String,
    pub position: i64,
    /// Set on default categories (`general`) so that clients localize the name; NULL after a rename.
    pub system_name: Option<String>,
    /// "No bots" for every channel of the category (APPLICATIONS.md §3.5).
    #[serde(serialize_with = "int_as_bool")]
    #[schema(value_type = bool)]
    pub no_bots: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct ChannelRow {
    pub id: String,
    pub room_id: String,
    pub category_id: Option<String>,
    pub kind: String,
    pub name: String,
    pub topic: String,
    /// Voice channels: the status line (VOICE.md §2a); `""` elsewhere.
    #[sqlx(default)]
    pub status: String,
    pub position: i64,
    pub slowmode_secs: i64,
    pub bitrate_kbps: i64,
    pub user_limit: i64,
    pub encrypted: i64,
    pub system_name: Option<String>,
    pub no_bots: i64,
    /// room ∨ category flag, read by the query.
    pub inherited_no_bots: i64,
    /// The channel admits bots although it is encrypted (`per_channel` rooms, APPLICATIONS.md §3.5).
    pub bots_allowed: i64,
    /// The room's `bots_in_encrypted_channels`, read by the query.
    pub bots_in_encrypted_channels: String,
    /// `since_join` | `days:<n>` | `all`; NULL = `since_join`.
    pub history_for_new_members: Option<String>,
    /// The channel has incoming webhooks (computed by the query; APPLICATIONS.md §6.1a).
    #[sqlx(default)]
    pub has_webhooks: i64,
    /// Threads without a message for this long are archived (PROTOCOL.md §7e).
    #[sqlx(default)]
    pub auto_archive_minutes: i64,
    /// Forum channels: the tag list as JSON `[{ id, name, emoji }]`.
    #[sqlx(default)]
    pub forum_tags: String,
    /// The channel's own age gate (`none` | `adults_only`, PROTOCOL.md §5e).
    pub age_gate: String,
    /// The room's age gate, read by the query (the channel's minimum).
    pub room_age_gate: String,
}

impl ChannelRow {
    /// The effective age gate: the stricter of the channel's and the room's (PROTOCOL.md §5e).
    pub fn age_gate_effective(&self) -> &'static str {
        crate::age::effective(&self.room_age_gate, &self.age_gate)
    }

    /// The channel is for adults only (its own gate or its room's).
    pub fn adults_only(&self) -> bool {
        self.age_gate_effective() == crate::age::GATE_ADULTS
    }

    /// Effective "no bots" flag (APPLICATIONS.md §3.5, `permissions::no_bots_effective`).
    pub fn no_bots(&self) -> bool {
        crate::permissions::no_bots_effective(&crate::permissions::NoBotsInput {
            room_no_bots: b(self.inherited_no_bots),
            category_no_bots: false,
            channel_no_bots: b(self.no_bots),
            encrypted: b(self.encrypted),
            bots_allowed: b(self.bots_allowed),
            bots_in_encrypted_channels: self.bots_in_encrypted_channels.clone(),
        })
    }

    pub fn to_api(&self) -> Channel {
        Channel {
            id: self.id.clone(),
            room_id: self.room_id.clone(),
            category_id: self.category_id.clone(),
            kind: self.kind.clone(),
            name: self.name.clone(),
            topic: self.topic.clone(),
            status: self.status.clone(),
            position: self.position,
            encrypted: b(self.encrypted),
            slowmode_secs: self.slowmode_secs,
            bitrate_kbps: self.bitrate_kbps,
            user_limit: self.user_limit,
            system_name: self.system_name.clone(),
            no_bots: b(self.no_bots),
            no_bots_effective: self.no_bots(),
            bots_allowed: b(self.bots_allowed),
            history_for_new_members: crate::history::Policy::of(self.history_for_new_members.as_deref()).to_string(),
            has_webhooks: b(self.has_webhooks),
            auto_archive_minutes: self.auto_archive_minutes,
            tags: self.tags(),
            age_gate: self.age_gate.clone(),
            age_gate_effective: self.age_gate_effective().to_string(),
        }
    }

    /// The forum tags of the channel (empty for other kinds and unreadable values).
    pub fn tags(&self) -> Vec<ForumTag> {
        if self.kind != "forum" {
            return Vec::new();
        }
        serde_json::from_str(&self.forum_tags).unwrap_or_default()
    }
}

/// A tag of a forum channel (PROTOCOL.md §7e).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ForumTag {
    pub id: String,
    /// 1–32 characters, unique in the channel ignoring case.
    pub name: String,
    /// A Unicode emoji or a custom emoji token, null without.
    #[serde(default)]
    pub emoji: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Channel {
    pub id: String,
    pub room_id: String,
    pub category_id: Option<String>,
    /// text | voice | announcement | forum | files (files channel) | system (the welcome channel)
    pub kind: String,
    pub name: String,
    pub topic: String,
    /// Voice channels: one line of plain text about what is going on (at most 128 characters, `""` = none;
    /// VOICE.md §2a), set by members with `voice_status`. Always `""` on other kinds.
    #[serde(default)]
    pub status: String,
    pub position: i64,
    pub encrypted: bool,
    pub slowmode_secs: i64,
    pub bitrate_kbps: i64,
    pub user_limit: i64,
    /// Set on default channels (`general`, `voice`) so that clients localize the name; NULL after a rename.
    pub system_name: Option<String>,
    /// The channel's own "no bots" flag (APPLICATIONS.md §3.5).
    #[serde(default)]
    pub no_bots: bool,
    /// room ∨ category ∨ channel flag, and in a `per_channel` room every encrypted channel without `bots_allowed`:
    /// bots can neither see nor join this channel (APPLICATIONS.md §3.5).
    #[serde(default)]
    pub no_bots_effective: bool,
    /// Encrypted channels of a `per_channel` room: bots may be in this channel (the `no_bots` flags still win).
    #[serde(default)]
    pub bots_allowed: bool,
    /// Encrypted channels: how much history members see from before their join and may receive keys for
    /// (`since_join`, `days:<n>` with 1 ≤ n ≤ 3650, `all`; ENCRYPTION.md §7b). Plaintext messages are always
    /// served.
    #[serde(default = "crate::history::default_policy")]
    pub history_for_new_members: String,
    /// The channel has incoming webhooks: in encrypted channels the device that commits an epoch publishes the
    /// epoch's inbox key (APPLICATIONS.md §6.1a, ENCRYPTION.md §5b); channels without webhooks skip that.
    #[serde(default)]
    pub has_webhooks: bool,
    /// Threads without a message for this many minutes are archived (60–43200, default 10080 = 7 days;
    /// PROTOCOL.md §7e).
    #[serde(default = "default_auto_archive")]
    pub auto_archive_minutes: i64,
    /// Forum channels: the tags posts can carry (at most 20); empty for other kinds.
    #[serde(default)]
    pub tags: Vec<ForumTag>,
    /// The channel's own age gate: `none` or `adults_only` (PROTOCOL.md §5e).
    #[serde(default = "default_age_gate")]
    pub age_gate: String,
    /// The gate that applies: `adults_only` when the channel's or its room's gate says so. Users below it see the
    /// channel locked: no messages, files, voice or events.
    #[serde(default = "default_age_gate")]
    pub age_gate_effective: String,
}

fn default_age_gate() -> String {
    crate::age::GATE_NONE.into()
}

fn default_auto_archive() -> i64 {
    10080
}

/// Kinds a client can create. The node itself creates one channel of kind `system` per room: the welcome
/// channel (`system_name = "welcome"`), fixed at the top, read-only, undeletable.
pub const CHANNEL_KINDS: &[&str] = &["text", "voice", "announcement", "forum", "files"];

#[derive(Debug, Clone, FromRow)]
pub struct OverrideRow {
    pub id: String,
    pub room_id: String,
    pub target_type: String,
    pub target_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub allow: i64,
    pub deny: i64,
    pub upload_allow: i64,
    pub upload_deny: i64,
}

impl OverrideRow {
    pub fn to_api(&self) -> PermissionOverride {
        PermissionOverride {
            id: self.id.clone(),
            target_type: self.target_type.clone(),
            target_id: self.target_id.clone(),
            subject_type: self.subject_type.clone(),
            subject_id: self.subject_id.clone(),
            allow: (self.allow as u64).to_string(),
            deny: (self.deny as u64).to_string(),
            upload_allow: crate::uploads::names(self.upload_allow as u64),
            upload_deny: crate::uploads::names(self.upload_deny as u64),
        }
    }
    pub fn to_eval(&self) -> crate::permissions::Override {
        use crate::permissions::{Override, SubjectType};
        Override {
            subject_type: if self.subject_type == "member" { SubjectType::Member } else { SubjectType::Role },
            subject_id: self.subject_id.clone(),
            allow: self.allow as u64,
            deny: self.deny as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PermissionOverride {
    pub id: String,
    /// category | channel
    pub target_type: String,
    pub target_id: String,
    /// role | member
    pub subject_type: String,
    pub subject_id: String,
    pub allow: String,
    pub deny: String,
    /// Upload categories allowed on top of the roles' setting (protocol/PROTOCOL.md §7a).
    #[serde(default)]
    pub upload_allow: Vec<String>,
    /// Upload categories denied.
    #[serde(default)]
    pub upload_deny: Vec<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MemberRow {
    pub room_id: String,
    pub user_id: String,
    pub nickname: Option<String>,
    pub joined_at: String,
    pub rules_accepted_at: Option<String>,
    pub timeout_until: Option<String>,
    /// Per-room avatar (a `media` row of kind `room_avatar`).
    pub avatar_media_id: Option<String>,
    pub avatar_animated: i64,
    /// Per-room bio ('' = none).
    pub bio: String,
    /// The member's identity key was reset at this time (ENCRYPTION.md §7b "History after a key reset").
    pub key_reset_at: Option<String>,
    /// A member with `restore_history` approved restoring the history from before the reset.
    pub history_restored_at: Option<String>,
}

impl MemberRow {
    pub fn is_timed_out(&self) -> bool {
        self.timeout_until.as_deref().is_some_and(|t| t > crate::util::now().as_str())
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Member {
    pub user: User,
    /// Same as `nick` (kept for older clients).
    pub nickname: Option<String>,
    pub joined_at: String,
    pub roles: Vec<String>,
    pub timeout_until: Option<String>,
    /// Per-room profile ("server profile"): the nickname in this room. Clients prefer it
    /// over the display name everywhere in the room.
    pub nick: Option<String>,
    /// Path of the per-room avatar (the animated variant if there is one), null without one. Clients
    /// prefer it over the user's avatar in this room.
    pub room_avatar: Option<String>,
    /// Path of the per-room avatar's still image.
    pub room_avatar_still: Option<String>,
    pub room_avatar_animated: bool,
    /// Per-room bio (Markdown subset, at most 512 characters), null without one.
    pub room_bio: Option<String>,
}

/// The per-room profile of a message author (room channels only; null where the author has none).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RoomProfile {
    pub nick: Option<String>,
    /// Path of the per-room avatar (animated variant if any).
    pub avatar: Option<String>,
    pub avatar_still: Option<String>,
    pub avatar_animated: bool,
}

impl MemberRow {
    /// The per-room profile, `None` when nothing is set.
    pub fn room_profile(&self) -> Option<RoomProfile> {
        if self.nickname.is_none() && self.avatar_media_id.is_none() {
            return None;
        }
        Some(RoomProfile {
            nick: self.nickname.clone(),
            avatar: media_url(self.avatar_media_id.as_deref(), b(self.avatar_animated)),
            avatar_still: media_url(self.avatar_media_id.as_deref(), false),
            avatar_animated: b(self.avatar_animated) && self.avatar_media_id.is_some(),
        })
    }
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Invite {
    pub code: String,
    pub room_id: String,
    pub creator_id: String,
    pub max_uses: i64,
    pub uses: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
    /// Direct invites only: the address the invite is bound to (FEDERATION.md §3.4).
    #[sqlx(rename = "bound_to")]
    pub user: Option<String>,
    /// A direct invite (bound to `user`, single use).
    #[sqlx(skip)]
    #[serde(default)]
    pub direct: bool,
    /// The room's invite list only: display name of the creator (`null` if the account is gone).
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Ban {
    pub id: String,
    pub room_id: Option<String>,
    /// `alice@domain` or just `domain`
    pub subject: String,
    pub reason: String,
    pub actor_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    pub id: String,
    pub room_id: Option<String>,
    pub actor_id: Option<String>,
    pub action: String,
    pub target: String,
    pub reason: String,
    pub meta: String,
    pub created_at: String,
}

impl AuditRow {
    pub fn to_api(&self) -> AuditEntry {
        AuditEntry {
            id: self.id.clone(),
            room_id: self.room_id.clone(),
            actor_id: self.actor_id.clone(),
            action: self.action.clone(),
            target: self.target.clone(),
            reason: self.reason.clone(),
            meta: serde_json::from_str(&self.meta).unwrap_or(Value::Null),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditEntry {
    pub id: String,
    pub room_id: Option<String>,
    pub actor_id: Option<String>,
    pub action: String,
    pub target: String,
    pub reason: String,
    #[schema(value_type = Object)]
    pub meta: Value,
    pub created_at: String,
}

// ---------------------------------------------------------------- Messages

#[derive(Debug, Clone, FromRow)]
pub struct MessageRow {
    pub id: String,
    pub conversation_id: String,
    pub author_id: String,
    pub author_username: String,
    pub author_domain: String,
    /// `kind` of the author (joined from `users`).
    pub author_kind: String,
    pub device_id: Option<String>,
    pub encrypted: i64,
    pub format: i64,
    pub epoch: Option<i64>,
    pub content: String,
    pub content_size: i64,
    pub reply_to_id: Option<String>,
    pub thread_id: Option<String>,
    pub mentions: String,
    pub mentions_everyone: i64,
    pub created_at: String,
    pub edited_at: Option<String>,
    pub signature: Option<String>,
    /// The author's account was deleted (joined from `users.deleted_at`).
    #[sqlx(default)]
    pub author_deleted_at: Option<String>,
    /// Messages of an incoming webhook (APPLICATIONS.md §6.1): the webhook and the name shown.
    #[sqlx(default)]
    pub webhook_id: Option<String>,
    #[sqlx(default)]
    pub webhook_name: Option<String>,
    /// Answer to a command (APPLICATIONS.md §5.7): the JSON of the envelope field `interaction`.
    #[sqlx(default)]
    pub interaction: Option<String>,
    /// Plaintext close time of a poll (PROTOCOL.md §7g), UTC.
    #[sqlx(default)]
    pub poll_closes_at: Option<String>,
}

impl MessageRow {
    pub fn to_api(&self) -> Message {
        let content = if b(self.encrypted) && self.webhook_id.is_none() {
            Value::String(self.content.clone())
        } else if b(self.encrypted) {
            // A sealed webhook message (APPLICATIONS.md §6.1a): `{ type: "webhook.sealed", epoch, sealed, sealed_by }`.
            serde_json::from_str(&self.content).unwrap_or(Value::Null)
        } else {
            serde_json::from_str(&self.content).unwrap_or(Value::Null)
        };
        Message {
            id: self.id.clone(),
            conversation_id: self.conversation_id.clone(),
            author: format!("{}@{}", self.author_username, self.author_domain),
            author_id: self.author_id.clone(),
            author_kind: self.author_kind.clone(),
            device_id: self.device_id.clone(),
            encrypted: b(self.encrypted),
            format: self.format,
            epoch: self.epoch,
            content,
            reply_to_id: self.reply_to_id.clone(),
            thread_id: self.thread_id.clone(),
            mentions: serde_json::from_str(&self.mentions).unwrap_or_default(),
            mentions_everyone: b(self.mentions_everyone),
            created_at: self.created_at.clone(),
            edited_at: self.edited_at.clone(),
            signature: self.signature.clone(),
            attachments: Vec::new(),
            reactions: Vec::new(),
            pinned: false,
            author_room_profile: None,
            reply_deleted: false,
            author_deleted: self.author_deleted_at.is_some(),
            webhook: self
                .webhook_id
                .clone()
                .map(|id| WebhookRef { id, name: self.webhook_name.clone().unwrap_or_default() }),
            interaction: self.interaction.as_deref().and_then(|j| serde_json::from_str(j).ok()),
            thread: None,
            poll_closes_at: self.poll_closes_at.clone(),
        }
    }
}

/// The summary of the thread a message started (PROTOCOL.md §7e), on the root message only.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ThreadSummary {
    pub id: String,
    pub message_count: i64,
    pub last_message_id: Option<String>,
    pub last_message_at: String,
    /// Up to three users who wrote in the thread most recently, newest first.
    pub participant_ids: Vec<String>,
    pub archived_at: Option<String>,
    pub locked: bool,
}

/// The node-set envelope field of a webhook message (APPLICATIONS.md §6.1).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct WebhookRef {
    pub id: String,
    /// The per-message `username` or the webhook's name when the message was posted.
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    /// `username@domain`
    pub author: String,
    pub author_id: String,
    /// `kind` of the author (`user`, `bot`, …), so every client can show the BOT badge (APPLICATIONS.md §1.5).
    #[serde(default = "default_author_kind")]
    pub author_kind: String,
    pub device_id: Option<String>,
    pub encrypted: bool,
    pub format: i64,
    pub epoch: Option<i64>,
    /// Plaintext: JSON content object. Encrypted: base64url ciphertext as a string; sealed webhook messages
    /// (`webhook` set, APPLICATIONS.md §6.1a): `{ "type": "webhook.sealed", "epoch", "sealed", "sealed_by" }`.
    #[schema(value_type = Value)]
    pub content: Value,
    pub reply_to_id: Option<String>,
    pub thread_id: Option<String>,
    pub mentions: Vec<String>,
    pub mentions_everyone: bool,
    pub created_at: String,
    pub edited_at: Option<String>,
    /// Plaintext messages only: device signature `base64url(nonce(16) || Ed25519 signature(64))` over
    /// the envelope fields and the content (FEDERATION.md §10.3), stored as sent by the author's
    /// device. Null for encrypted and unsigned messages. The node does not verify it; clients do.
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub reactions: Vec<Reaction>,
    #[serde(default)]
    pub pinned: bool,
    /// Plaintext close time of a poll (PROTOCOL.md §7g), null otherwise: the node refuses votes after it.
    #[serde(default)]
    pub poll_closes_at: Option<String>,
    /// Room channels: the author's per-room profile (nickname, room avatar), null without one.
    #[serde(default)]
    pub author_room_profile: Option<RoomProfile>,
    /// `reply_to_id` names a message that was deleted since (clients show "message deleted").
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reply_deleted: bool,
    /// The author's account was deleted: clients show "Deleted user" without avatar, profile or link.
    /// `content` `{"type":"system.deleted"}` means the content was deleted with the account.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub author_deleted: bool,
    /// Messages of an incoming webhook only (`author_kind = "webhook"`, `device_id` and `signature` null): set by
    /// the node, clients show this name with the WEBHOOK badge (APPLICATIONS.md §6.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookRef>,
    /// Set by the node on a message an application posted as the answer to a command (APPLICATIONS.md §5.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<InteractionRef>,
    /// On a message that started a thread: the thread's summary (PROTOCOL.md §7e). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<ThreadSummary>,
}

/// The node-set envelope field of a command answer (APPLICATIONS.md §5.7).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct InteractionRef {
    /// The interaction id.
    pub id: String,
    /// The command's name.
    pub command: String,
    /// The application reference `<domain>/<id>`.
    pub application: String,
    /// The invoker's address.
    pub user: String,
}

fn default_author_kind() -> String {
    "user".into()
}

// ---------------------------------------------------------------- Attachments

#[derive(Debug, Clone, FromRow)]
pub struct BlobRow {
    pub id: String,
    pub uploader_id: String,
    pub conversation_id: String,
    pub room_id: Option<String>,
    pub message_id: Option<String>,
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub sha256: String,
    pub created_at: String,
    /// Deleted by attachment retention: the row stays, the file is gone.
    pub expired_at: Option<String>,
    pub spoiler: i64,
}

impl BlobRow {
    pub fn to_api(&self) -> Attachment {
        Attachment {
            id: self.id.clone(),
            name: self.name.clone(),
            mime: self.mime.clone(),
            size: self.size,
            sha256: self.sha256.clone(),
            expired: self.expired_at.is_some(),
            spoiler: self.spoiler != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
    /// Base64url of the file's SHA-256
    pub sha256: String,
    /// The file was deleted by attachment retention: clients show "file expired", downloads answer 410.
    #[serde(default)]
    pub expired: bool,
    /// Plaintext messages: shown blurred until clicked; encrypted messages carry the flag
    /// inside the encrypted content.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub spoiler: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Reaction {
    pub emoji: String,
    pub count: i64,
    /// Did the requester react with it?
    pub me: bool,
}

// ---------------------------------------------------------------- Emojis

#[derive(Debug, Clone, FromRow)]
pub struct EmojiRow {
    pub id: String,
    pub room_id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub uploader_id: String,
    pub created_at: String,
    pub animated: i64,
    /// Storage id of the still variant of an animated emoji (NULL: `id` is the still).
    pub still_id: Option<String>,
}

impl EmojiRow {
    pub fn to_api(&self) -> Emoji {
        Emoji {
            id: self.id.clone(),
            room_id: self.room_id.clone(),
            name: self.name.clone(),
            mime: self.mime.clone(),
            size: self.size,
            created_at: self.created_at.clone(),
            animated: self.animated != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Emoji {
    pub id: String,
    pub room_id: String,
    /// Short name without colons, e.g. `pogchamp` for `:pogchamp:`
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub created_at: String,
    /// Animated WebP (`GET /emojis/{id}/image`); `?still=1` gives the first frame.
    #[serde(default)]
    pub animated: bool,
}

// ---------------------------------------------------------------- Account invites

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct AccountInvite {
    pub code: String,
    pub created_by: String,
    pub note: String,
    /// 0 = unlimited
    pub max_uses: i64,
    pub uses: i64,
    pub expires_at: Option<String>,
    pub created_at: String,
}
