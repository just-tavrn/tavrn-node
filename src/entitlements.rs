// SPDX-License-Identifier: AGPL-3.0-only
//! Entitlements (`protocol/ENTITLEMENTS.md`): resource limits per user and per room on
//! top of the node's fixed limits, so that operators can run plans or subscriptions without forking.
//!
//! Every key is an integer. The node default comes from the configuration; *grants* (with an optional *plan*
//! and per-key overrides, optional expiry) extend it for one user or one room. The evaluation is a pure
//! function ([`evaluate`]); [`Entitlements::load`] fetches the grants of one request once (cached for the
//! request only, no invalidation problems).
//!
//! Rules:
//! - [`Rule::Max`]: the highest value among the node default, the evaluated user's grants and the room's
//!   grants; `0` means unlimited and wins. Node admins are unlimited for user keys (what they do
//!   themselves); rooms they own follow the room rules like every other room.
//! - [`Rule::Flag`]: `0`/`1`, the highest value wins; node admins get `1` for user keys.
//! - [`Rule::ShortestNonZero`] (`attachments.retention_days`): the smallest non-zero value among the node
//!   default, the room's grants and the room's own setting (`0` = keep). A room can only shorten the node
//!   value; user grants and node admins play no part.
//!
//! Scope: user keys are evaluated for the acting user (plus the grants of the room the action happens in);
//! room keys for the room's owner plus the room's grants (an owner's plan covers the rooms they own).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{app::AppState, config::Config, error::ApiError, models::UserRow, store, util};

pub const ROOMS_MAX_OWNED: &str = "rooms.max_owned";
pub const UPLOAD_MAX_BYTES: &str = "upload.max_bytes";
pub const STORAGE_MAX_BYTES_PER_ROOM: &str = "storage.max_bytes_per_room";
pub const VOICE_MAX_PARTICIPANTS: &str = "voice.max_participants";
pub const STREAM_MAX_HEIGHT: &str = "stream.max_height";
pub const STREAM_MAX_FPS: &str = "stream.max_fps";
pub const CAMERA_MAX_HEIGHT: &str = "camera.max_height";
pub const EMOJI_MAX_PER_ROOM: &str = "emoji.max_per_room";
pub const EMOJI_MAX_PERSONAL: &str = "emoji.max_personal";
pub const SOUNDS_MAX_PER_ROOM: &str = "sounds.max_per_room";
pub const SOUNDS_MAX_PERSONAL: &str = "sounds.max_personal";
pub const ATTACHMENTS_RETENTION_DAYS: &str = "attachments.retention_days";
pub const FILES_CHANNELS_ENABLED: &str = "files_channels.enabled";
pub const FILES_CHANNELS_MAX_BYTES: &str = "files_channels.max_bytes";

/// How the values of one key combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Highest wins, `0` = unlimited (wins over everything); node admins unlimited.
    Max,
    /// `0`/`1`, highest wins; node admins `1`.
    Flag,
    /// Smallest non-zero wins (`0` = keep); only node default, room grants and the room setting count.
    ShortestNonZero,
}

/// Whose grants count for a key besides the room's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The acting user.
    User,
    /// The owner of the room.
    Room,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyDef {
    pub key: &'static str,
    pub rule: Rule,
    pub scope: Scope,
    /// Largest value a plan or grant may set (validation; also protects against overflows downstream).
    pub max: i64,
}

const TIB: i64 = 1 << 40;
const PIB: i64 = 1 << 50;

/// The registry of known keys. Plans and grants may only use these.
pub const KEYS: &[KeyDef] = &[
    KeyDef { key: ROOMS_MAX_OWNED, rule: Rule::Max, scope: Scope::User, max: 1_000_000 },
    KeyDef { key: UPLOAD_MAX_BYTES, rule: Rule::Max, scope: Scope::User, max: TIB },
    KeyDef { key: STORAGE_MAX_BYTES_PER_ROOM, rule: Rule::Max, scope: Scope::Room, max: PIB },
    KeyDef { key: VOICE_MAX_PARTICIPANTS, rule: Rule::Max, scope: Scope::Room, max: 1000 },
    KeyDef { key: STREAM_MAX_HEIGHT, rule: Rule::Max, scope: Scope::User, max: 4320 },
    KeyDef { key: STREAM_MAX_FPS, rule: Rule::Max, scope: Scope::User, max: 240 },
    KeyDef { key: CAMERA_MAX_HEIGHT, rule: Rule::Max, scope: Scope::User, max: 4320 },
    KeyDef { key: EMOJI_MAX_PER_ROOM, rule: Rule::Max, scope: Scope::Room, max: 100_000 },
    KeyDef { key: EMOJI_MAX_PERSONAL, rule: Rule::Max, scope: Scope::User, max: 100_000 },
    KeyDef { key: SOUNDS_MAX_PER_ROOM, rule: Rule::Max, scope: Scope::Room, max: 100_000 },
    KeyDef { key: SOUNDS_MAX_PERSONAL, rule: Rule::Max, scope: Scope::User, max: 100_000 },
    KeyDef { key: ATTACHMENTS_RETENTION_DAYS, rule: Rule::ShortestNonZero, scope: Scope::Room, max: 36_500 },
    KeyDef { key: FILES_CHANNELS_ENABLED, rule: Rule::Flag, scope: Scope::Room, max: 1 },
    KeyDef { key: FILES_CHANNELS_MAX_BYTES, rule: Rule::Max, scope: Scope::Room, max: PIB },
];

pub fn def(key: &str) -> Option<&'static KeyDef> {
    KEYS.iter().find(|d| d.key == key)
}

/// Values of a plan or grant: key → integer.
pub type Limits = BTreeMap<String, i64>;

fn clamp_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The node default of a key (from the `TAVRN_*` variables, `protocol/ENTITLEMENTS.md` §2).
pub fn node_default(config: &Config, key: &str) -> i64 {
    match key {
        ROOMS_MAX_OWNED => config.max_rooms_per_user.into(),
        UPLOAD_MAX_BYTES => clamp_i64(config.upload_max_bytes),
        STORAGE_MAX_BYTES_PER_ROOM => clamp_i64(config.storage_quota_per_room_bytes),
        VOICE_MAX_PARTICIPANTS => config.voice_channel_max_participants.into(),
        STREAM_MAX_HEIGHT => config.stream_max_height.into(),
        STREAM_MAX_FPS => config.stream_max_fps.into(),
        CAMERA_MAX_HEIGHT => config.camera_max_height.into(),
        EMOJI_MAX_PER_ROOM => config.emoji_max_per_room.into(),
        EMOJI_MAX_PERSONAL => config.emoji_max_personal.into(),
        SOUNDS_MAX_PER_ROOM => config.sounds_max_per_room.into(),
        SOUNDS_MAX_PERSONAL => config.sounds_max_personal.into(),
        ATTACHMENTS_RETENTION_DAYS => config.attachment_retention_days.into(),
        FILES_CHANNELS_ENABLED => i64::from(config.files_channels.on()),
        FILES_CHANNELS_MAX_BYTES => clamp_i64(config.files_channels_max_bytes),
        _ => 0,
    }
}

/// Every key with its node default.
pub fn node_defaults(config: &Config) -> Limits {
    KEYS.iter().map(|d| (d.key.to_string(), node_default(config, d.key))).collect()
}

/// Checks a JSON object of limits: known keys only, integers within `0..=max`.
pub fn parse_limits(field: &str, value: &Value) -> Result<Limits, ApiError> {
    let bad = |detail: String| ApiError::BadRequest { code: "entitlements.invalid_limits", detail };
    let Some(obj) = value.as_object() else {
        return Err(bad(format!("{field}: a JSON object of key → integer")));
    };
    let mut out = Limits::new();
    for (k, v) in obj {
        let d = def(k).ok_or_else(|| bad(format!("{field}: unknown key {k}")))?;
        let n = v.as_i64().ok_or_else(|| bad(format!("{field}.{k}: an integer")))?;
        if !(0..=d.max).contains(&n) {
            return Err(bad(format!("{field}.{k}: between 0 and {}", d.max)));
        }
        out.insert(k.clone(), n);
    }
    Ok(out)
}

/// Values stored as JSON text (plans and overrides); unknown or invalid entries are skipped, so a key
/// removed in a later version does not break the evaluation.
pub fn limits_from_text(text: &str) -> Limits {
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(text) else { return Limits::new() };
    obj.into_iter()
        .filter_map(|(k, v)| {
            let d = def(&k)?;
            let n = v.as_i64().filter(|n| (0..=d.max).contains(n))?;
            Some((k, n))
        })
        .collect()
}

/// A grant as the evaluation needs it: its kind, values (plan limits with the overrides on top) and expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    pub kind: SubjectKind,
    pub subject_id: String,
    pub values: Limits,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    User,
    Room,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Room => "room",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "room" => Some(Self::Room),
            _ => None,
        }
    }
}

/// Plan limits with the grant's overrides on top.
pub fn merge(plan: &Limits, overrides: &Limits) -> Limits {
    let mut out = plan.clone();
    out.extend(overrides.iter().map(|(k, v)| (k.clone(), *v)));
    out
}

/// A grant counts while it has no expiry or expires after `now` (RFC 3339 strings of `util::format_time`).
pub fn is_active(expires_at: Option<&str>, now: &str) -> bool {
    expires_at.is_none_or(|e| e > now)
}

/// Pure evaluation of one key (see the module documentation for the rules).
///
/// `user_grants` are the values of the evaluated user's active grants, `room_grants` those of the room's;
/// `room_setting` is the room's own retention setting (only for [`Rule::ShortestNonZero`]).
pub fn evaluate(
    def: &KeyDef,
    node_default: i64,
    admin: bool,
    user_grants: &[&Limits],
    room_grants: &[&Limits],
    room_setting: Option<i64>,
) -> i64 {
    match def.rule {
        Rule::ShortestNonZero => {
            let room = room_grants.iter().filter_map(|g| g.get(def.key).copied());
            std::iter::once(node_default).chain(room).chain(room_setting).filter(|v| *v > 0).min().unwrap_or(0)
        }
        Rule::Flag => {
            if admin {
                return 1;
            }
            let grants = user_grants.iter().chain(room_grants).filter_map(|g| g.get(def.key).copied());
            std::iter::once(node_default).chain(grants).max().unwrap_or(0).clamp(0, 1)
        }
        Rule::Max => {
            if admin {
                return 0;
            }
            let mut best = node_default;
            for v in user_grants.iter().chain(room_grants).filter_map(|g| g.get(def.key).copied()) {
                if v == 0 || best == 0 {
                    return 0;
                }
                best = best.max(v);
            }
            best
        }
    }
}

/// The evaluated subjects of one request with their active grants.
#[derive(Debug, Clone, Default)]
pub struct Entitlements {
    node: Limits,
    /// The acting user: (node admin, values of the user's active grants).
    user: Option<(bool, Vec<Limits>)>,
    /// The room's owner (room keys).
    owner: Option<(bool, Vec<Limits>)>,
    room: Vec<Limits>,
    room_setting: Option<i64>,
}

impl Entitlements {
    /// Builds the evaluation from already loaded parts (tests, admin preview).
    pub fn from_parts(
        node: Limits,
        user: Option<(bool, Vec<Limits>)>,
        owner: Option<(bool, Vec<Limits>)>,
        room: Vec<Limits>,
        room_setting: Option<i64>,
    ) -> Self {
        Self { node, user, owner, room, room_setting }
    }

    /// Loads the active grants of `user` (the acting user, may be `None`) and of `room` with its owner, in
    /// one query.
    pub async fn load(
        state: &AppState,
        user: Option<&UserRow>,
        room: Option<&crate::models::Room>,
    ) -> Result<Self, ApiError> {
        let owner = match room {
            Some(r) if user.is_some_and(|u| u.id == r.owner_id) => user.cloned(),
            Some(r) => store::users::by_id(&state.db, &r.owner_id).await?,
            None => None,
        };
        let mut users: Vec<&str> = user.iter().map(|u| u.id.as_str()).collect();
        if let Some(o) = &owner
            && !users.contains(&o.id.as_str())
        {
            users.push(&o.id);
        }
        let grants =
            store::entitlements::active_grants(&state.db, &users, room.map(|r| r.id.as_str()), &util::now()).await?;
        let of_user = |u: &UserRow| {
            let values = grants
                .iter()
                .filter(|g| g.kind == SubjectKind::User && g.subject_id == u.id)
                .map(|g| g.values.clone())
                .collect::<Vec<_>>();
            (u.is_node_admin(), values)
        };
        Ok(Self {
            node: node_defaults(&state.config),
            user: user.map(of_user),
            owner: owner.as_ref().map(of_user),
            room: grants.iter().filter(|g| g.kind == SubjectKind::Room).map(|g| g.values.clone()).collect(),
            room_setting: room.and_then(|r| r.attachment_retention_days).filter(|d| *d > 0),
        })
    }

    /// Loads the entitlements of a room (room keys: its owner and grants) without an acting user.
    pub async fn for_room(state: &AppState, room: &crate::models::Room) -> Result<Self, ApiError> {
        Self::load(state, None, Some(room)).await
    }

    /// The effective value of `key` (`0` for an unknown key).
    pub fn get(&self, key: &str) -> i64 {
        let Some(d) = def(key) else { return 0 };
        let subject = match d.scope {
            Scope::User => self.user.as_ref().or(self.owner.as_ref()),
            Scope::Room => self.owner.as_ref().or(self.user.as_ref()),
        };
        // Node admins are unlimited for what they do themselves (user keys); a room they own follows its
        // grants like any other room (an admin can grant their rooms anything explicitly).
        let (admin, user_grants) = match subject {
            Some((admin, grants)) => (*admin && d.scope == Scope::User, grants.iter().collect::<Vec<_>>()),
            None => (false, Vec::new()),
        };
        let room = self.room.iter().collect::<Vec<_>>();
        evaluate(d, self.node.get(key).copied().unwrap_or(0), admin, &user_grants, &room, self.room_setting)
    }

    /// Retention without the room's own setting: the bound the room settings show (node value and room grants).
    pub fn retention_bound(&self) -> i64 {
        let Some(d) = def(ATTACHMENTS_RETENTION_DAYS) else { return 0 };
        let room = self.room.iter().collect::<Vec<_>>();
        evaluate(d, self.node.get(d.key).copied().unwrap_or(0), false, &[], &room, None)
    }

    /// Every key with its effective value.
    pub fn all(&self) -> Limits {
        KEYS.iter().map(|d| (d.key.to_string(), self.get(d.key))).collect()
    }

    /// `upload.max_bytes` within the node's ceiling (`0` = unlimited = the ceiling).
    pub fn upload_max_bytes(&self, config: &Config) -> u64 {
        let ceiling = config.upload_ceiling();
        match u64::try_from(self.get(UPLOAD_MAX_BYTES)).unwrap_or(0) {
            0 => ceiling,
            v => v.min(ceiling),
        }
    }

    /// A count limit as `Option` (`None` = unlimited).
    pub fn limit(&self, key: &str) -> Option<i64> {
        Some(self.get(key)).filter(|v| *v > 0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn limits(pairs: &[(&str, i64)]) -> Limits {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn d(key: &str) -> &'static KeyDef {
        def(key).unwrap()
    }

    #[test]
    fn registry_has_every_planned_key_once() {
        let mut keys: Vec<&str> = KEYS.iter().map(|d| d.key).collect();
        assert_eq!(keys.len(), 14);
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 14);
        let config = Config::default();
        assert_eq!(node_default(&config, ROOMS_MAX_OWNED), 5);
        assert_eq!(node_default(&config, UPLOAD_MAX_BYTES), 25 * 1024 * 1024);
        assert_eq!(node_default(&config, EMOJI_MAX_PERSONAL), 20);
        assert_eq!(node_default(&config, SOUNDS_MAX_PERSONAL), 10);
        assert_eq!(node_default(&config, SOUNDS_MAX_PER_ROOM), 50);
        assert_eq!(node_default(&config, FILES_CHANNELS_ENABLED), 1);
        assert_eq!(node_default(&config, ATTACHMENTS_RETENTION_DAYS), 0);
        assert_eq!(node_defaults(&config).len(), 14);
    }

    #[test]
    fn max_rule_takes_the_highest_and_zero_wins() {
        let k = d(EMOJI_MAX_PER_ROOM);
        assert_eq!(evaluate(k, 100, false, &[], &[], None), 100);
        let a = limits(&[(EMOJI_MAX_PER_ROOM, 250)]);
        let b = limits(&[(EMOJI_MAX_PER_ROOM, 50)]);
        assert_eq!(evaluate(k, 100, false, &[&a], &[&b], None), 250, "a grant extends");
        assert_eq!(evaluate(k, 100, false, &[&b], &[], None), 100, "a lower grant never shrinks");
        let unlimited = limits(&[(EMOJI_MAX_PER_ROOM, 0)]);
        assert_eq!(evaluate(k, 100, false, &[&a], &[&unlimited], None), 0, "0 = unlimited wins");
        assert_eq!(evaluate(k, 0, false, &[&a], &[], None), 0, "an unlimited node default stays unlimited");
        let other = limits(&[(UPLOAD_MAX_BYTES, 1)]);
        assert_eq!(evaluate(k, 100, false, &[&other], &[], None), 100, "other keys do not count");
    }

    #[test]
    fn node_admins_are_unlimited_except_retention() {
        assert_eq!(evaluate(d(ROOMS_MAX_OWNED), 5, true, &[], &[], None), 0);
        assert_eq!(evaluate(d(FILES_CHANNELS_ENABLED), 0, true, &[], &[], None), 1);
        assert_eq!(evaluate(d(ATTACHMENTS_RETENTION_DAYS), 30, true, &[], &[], None), 30);
    }

    #[test]
    fn flag_rule_is_zero_or_one() {
        let k = d(FILES_CHANNELS_ENABLED);
        assert_eq!(evaluate(k, 0, false, &[], &[], None), 0);
        let on = limits(&[(FILES_CHANNELS_ENABLED, 1)]);
        assert_eq!(evaluate(k, 0, false, &[], &[&on], None), 1);
        let off = limits(&[(FILES_CHANNELS_ENABLED, 0)]);
        assert_eq!(evaluate(k, 1, false, &[&off], &[], None), 1, "0 is off here, not unlimited");
    }

    #[test]
    fn retention_picks_the_shortest_non_zero_and_ignores_users() {
        let k = d(ATTACHMENTS_RETENTION_DAYS);
        assert_eq!(evaluate(k, 0, false, &[], &[], None), 0, "keep forever");
        assert_eq!(evaluate(k, 0, false, &[], &[], Some(14)), 14, "a room may opt in");
        assert_eq!(evaluate(k, 30, false, &[], &[], Some(90)), 30, "a room cannot extend");
        assert_eq!(evaluate(k, 30, false, &[], &[], Some(7)), 7);
        let short = limits(&[(ATTACHMENTS_RETENTION_DAYS, 3)]);
        let keep = limits(&[(ATTACHMENTS_RETENTION_DAYS, 0)]);
        assert_eq!(evaluate(k, 30, false, &[], &[&short], None), 3, "a room grant shortens");
        assert_eq!(evaluate(k, 30, false, &[], &[&keep], None), 30, "a room grant cannot extend");
        assert_eq!(evaluate(k, 30, false, &[&short], &[], None), 30, "user grants do not count");
    }

    #[test]
    fn expiry_and_merge() {
        let now = "2026-10-06T12:00:00.000Z";
        assert!(is_active(None, now));
        assert!(is_active(Some("2026-10-06T12:00:00.001Z"), now));
        assert!(!is_active(Some(now), now));
        assert!(!is_active(Some("2026-10-01T00:00:00.000Z"), now));
        let plan = limits(&[(UPLOAD_MAX_BYTES, 100), (ROOMS_MAX_OWNED, 10)]);
        let over = limits(&[(ROOMS_MAX_OWNED, 20)]);
        assert_eq!(merge(&plan, &over), limits(&[(UPLOAD_MAX_BYTES, 100), (ROOMS_MAX_OWNED, 20)]));
    }

    #[test]
    fn limits_are_validated() {
        let ok =
            parse_limits("limits", &serde_json::json!({ "upload.max_bytes": 1024, "rooms.max_owned": 0 })).unwrap();
        assert_eq!(ok.len(), 2);
        for bad in [
            serde_json::json!({ "nope": 1 }),
            serde_json::json!({ "rooms.max_owned": -1 }),
            serde_json::json!({ "rooms.max_owned": 1.5 }),
            serde_json::json!({ "rooms.max_owned": "5" }),
            serde_json::json!({ "files_channels.enabled": 2 }),
            serde_json::json!({ "upload.max_bytes": i64::MAX }),
            serde_json::json!({ "upload.max_bytes": u64::MAX }),
            serde_json::json!([1]),
        ] {
            assert!(parse_limits("limits", &bad).is_err(), "{bad}");
        }
        assert_eq!(limits_from_text("{\"rooms.max_owned\": 3, \"gone.key\": 1, \"upload.max_bytes\": -4}").len(), 1);
        assert!(limits_from_text("garbage").is_empty());
    }

    #[test]
    fn scopes_pick_user_or_owner() {
        let node = node_defaults(&Config::default());
        let user = (false, vec![limits(&[(UPLOAD_MAX_BYTES, 100 << 20), (EMOJI_MAX_PER_ROOM, 1000)])]);
        let owner = (false, vec![limits(&[(EMOJI_MAX_PER_ROOM, 300)])]);
        let e = Entitlements::from_parts(node.clone(), Some(user.clone()), Some(owner), vec![], None);
        assert_eq!(e.get(UPLOAD_MAX_BYTES), 100 << 20, "user key: the acting user's grant");
        assert_eq!(e.get(EMOJI_MAX_PER_ROOM), 300, "room key: the owner's grant, not the actor's");
        let alone = Entitlements::from_parts(node.clone(), Some(user), None, vec![], None);
        assert_eq!(alone.get(EMOJI_MAX_PER_ROOM), 1000, "without a room the user's own grants show");
        let config = Config { upload_max_bytes_ceiling: 50 << 20, ..Config::default() };
        assert_eq!(alone.upload_max_bytes(&config), 50 << 20, "capped by the ceiling");
        let admin = Entitlements::from_parts(node.clone(), Some((true, vec![])), None, vec![], None);
        assert_eq!(admin.upload_max_bytes(&config), 50 << 20, "unlimited = the ceiling");
        assert_eq!(admin.limit(ROOMS_MAX_OWNED), None);
        let admins_room = Entitlements::from_parts(node, None, Some((true, vec![])), vec![], None);
        assert_eq!(admins_room.get(EMOJI_MAX_PER_ROOM), 100, "a room owned by an admin follows its grants");
    }
}
