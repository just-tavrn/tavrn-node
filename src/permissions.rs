// SPDX-License-Identifier: AGPL-3.0-only
//! Permissions: u64 bitmask, roles, overrides per category/channel.
//! The evaluation is a pure function, pinned by `protocol/testvectors/permissions.json`, which the
//! web client must pass as well.

use serde::{Deserialize, Serialize};

pub type Perms = u64;

macro_rules! perms {
    ($($name:ident = $bit:expr, $label:literal;)*) => {
        $(pub const $name: Perms = 1 << $bit;)*
        /// All defined permissions with bit position and name, for docs and clients.
        pub const ALL_NAMED: &[(&str, Perms)] = &[$(($label, $name)),*];
    };
}

perms! {
    VIEW_CHANNEL = 0, "view_channel";
    SEND_MESSAGES = 1, "send_messages";
    MANAGE_MESSAGES = 2, "manage_messages";
    ATTACH_FILES = 3, "attach_files";
    ADD_REACTIONS = 4, "add_reactions";
    MENTION_EVERYONE = 5, "mention_everyone";
    CREATE_THREADS = 6, "create_threads";
    MANAGE_CHANNELS = 7, "manage_channels";
    MANAGE_ROLES = 8, "manage_roles";
    MANAGE_ROOM = 9, "manage_room";
    CREATE_INVITES = 10, "create_invites";
    KICK_MEMBERS = 11, "kick_members";
    BAN_MEMBERS = 12, "ban_members";
    MODERATE_MEMBERS = 13, "moderate_members";
    PURGE = 14, "purge";
    VIEW_AUDIT_LOG = 15, "view_audit_log";
    CONNECT = 16, "connect";
    SPEAK = 17, "speak";
    STREAM = 18, "stream";
    MUTE_MEMBERS = 19, "mute_members";
    MOVE_MEMBERS = 20, "move_members";
    USE_SOUNDBOARD = 21, "use_soundboard";
    MANAGE_EMOJIS = 22, "manage_emojis";
    CHANGE_NICKNAME = 23, "change_nickname";
    MANAGE_NICKNAMES = 24, "manage_nicknames";
    PIN_MESSAGES = 25, "pin_messages";
    USE_CAMERA = 26, "use_camera";
    USE_WHITEBOARD = 27, "use_whiteboard";
    MANAGE_WHITEBOARD = 28, "manage_whiteboard";
    MANAGE_WEBHOOKS = 29, "manage_webhooks";
    PRIORITY_SPEAKER = 30, "priority_speaker";
    USE_EXTERNAL_EMOJIS = 31, "use_external_emojis";
    USE_EXTERNAL_SOUNDS = 32, "use_external_sounds";
    MANAGE_FILES = 33, "manage_files";
    READ_HISTORY = 34, "read_history";
    MANAGE_APPLICATIONS = 35, "manage_applications";
    MANAGE_THREADS = 36, "manage_threads";
    RESTORE_HISTORY = 37, "restore_history";
    VOICE_STATUS = 38, "voice_status";
    ADMINISTRATOR = 62, "administrator";
}

/// All permissions (owner, administrator).
pub const ALL: Perms = {
    let mut v = 0u64;
    let mut i = 0;
    while i < ALL_NAMED.len() {
        v |= ALL_NAMED[i].1;
        i += 1;
    }
    v
};

/// Default permissions of the `@everyone` role of a new room.
pub const DEFAULT_EVERYONE: Perms = VIEW_CHANNEL
    | SEND_MESSAGES
    | ATTACH_FILES
    | ADD_REACTIONS
    | CREATE_THREADS
    | CREATE_INVITES
    | CONNECT
    | SPEAK
    | STREAM
    | USE_CAMERA
    | USE_SOUNDBOARD
    | CHANGE_NICKNAME
    | USE_WHITEBOARD
    | USE_EXTERNAL_EMOJIS
    | USE_EXTERNAL_SOUNDS
    | READ_HISTORY;

/// Management-class permissions that can never be granted to `@everyone`, neither on the role nor by
/// an `allow` in a channel or category override (`role.everyone_restricted`, protocol/permissions.md).
pub const EVERYONE_RESTRICTED: Perms = ADMINISTRATOR
    | MANAGE_ROOM
    | MANAGE_ROLES
    | MANAGE_CHANNELS
    | VIEW_AUDIT_LOG
    | KICK_MEMBERS
    | BAN_MEMBERS
    | MODERATE_MEMBERS
    | MANAGE_EMOJIS
    | MANAGE_WHITEBOARD
    | MANAGE_WEBHOOKS
    | MANAGE_FILES
    | MOVE_MEMBERS
    | MUTE_MEMBERS
    | MANAGE_MESSAGES
    | MANAGE_NICKNAMES
    | MANAGE_APPLICATIONS
    | MANAGE_THREADS
    | RESTORE_HISTORY
    | PURGE;

/// The bits an override (category or channel) may carry: everything that means something inside a channel.
/// Room-level bits (administrator, room management, invites, kick/ban/timeout, purge, audit log, emojis,
/// nicknames, applications) are granted through roles only. `PUT /overrides` refuses other bits with
/// `permissions.not_channel_scoped`, the start-up fixup strips them from old data, and the evaluation ignores
/// them (protocol/permissions.md "Channel-scoped bits").
pub const CHANNEL_SCOPED: Perms = VIEW_CHANNEL
    | SEND_MESSAGES
    | MANAGE_MESSAGES
    | ATTACH_FILES
    | ADD_REACTIONS
    | MENTION_EVERYONE
    | CREATE_THREADS
    | MANAGE_CHANNELS
    | MANAGE_ROLES
    | CONNECT
    | SPEAK
    | STREAM
    | MUTE_MEMBERS
    | MOVE_MEMBERS
    | USE_SOUNDBOARD
    | PIN_MESSAGES
    | USE_CAMERA
    | USE_WHITEBOARD
    | MANAGE_WHITEBOARD
    | MANAGE_WEBHOOKS
    | PRIORITY_SPEAKER
    | USE_EXTERNAL_EMOJIS
    | USE_EXTERNAL_SOUNDS
    | MANAGE_FILES
    | READ_HISTORY
    | MANAGE_THREADS
    | VOICE_STATUS;

/// Permissions a member keeps while timed out.
pub const TIMEOUT_KEEPS: Perms = VIEW_CHANNEL | READ_HISTORY;

/// Always granted in a system channel (the welcome channel, the room's security log): no
/// override can hide it or its history (permissions.md "System channels").
pub const SYSTEM_CHANNEL_FORCED: Perms = VIEW_CHANNEL | READ_HISTORY;

/// Never granted in a system channel: only the node writes there. Reading, reactions and moderation (deleting
/// entries) stay possible.
pub const SYSTEM_CHANNEL_DENIED: Perms =
    SEND_MESSAGES | ATTACH_FILES | CREATE_THREADS | MENTION_EVERYONE | USE_WHITEBOARD | PIN_MESSAGES;

/// Granted in a voice channel while the member has a moved participation there (a moderator with `move_members`
/// moved them in, `VOICE.md` §7): seeing the channel, reading it and staying connected. Speaking, sending and the
/// rest follow the member's roles and overrides as usual; a timeout still strips everything but reading.
pub const MOVED_FORCED: Perms = VIEW_CHANNEL | READ_HISTORY | CONNECT;

// ---------------------------------------------------------------- bots (APPLICATIONS.md §2.4, §3.5)

/// Permission bits a bot keeps whatever the scopes of its token.
pub const BOT_ALWAYS: Perms = VIEW_CHANNEL | CHANGE_NICKNAME;

/// Scopes of app tokens and the permission bits each unlocks (APPLICATIONS.md §2.4). Scopes without bits
/// only unlock routes and events. The order is the canonical order of scope lists.
pub const SCOPES: &[(&str, Perms)] = &[
    ("messages:read", READ_HISTORY),
    (
        "messages:write",
        SEND_MESSAGES
            | ATTACH_FILES
            | ADD_REACTIONS
            | MENTION_EVERYONE
            | CREATE_THREADS
            | PIN_MESSAGES
            | USE_EXTERNAL_EMOJIS,
    ),
    ("members:read", 0),
    (
        "moderation",
        MANAGE_MESSAGES
            | KICK_MEMBERS
            | BAN_MEMBERS
            | MODERATE_MEMBERS
            | PURGE
            | VIEW_AUDIT_LOG
            | MANAGE_NICKNAMES
            | MUTE_MEMBERS
            | MOVE_MEMBERS
            | MANAGE_THREADS,
    ),
    (
        "rooms:manage",
        MANAGE_ROOM
            | MANAGE_CHANNELS
            | MANAGE_ROLES
            | CREATE_INVITES
            | MANAGE_EMOJIS
            | MANAGE_FILES
            | MANAGE_APPLICATIONS
            | VOICE_STATUS,
    ),
    ("voice", CONNECT | SPEAK | STREAM | USE_CAMERA | USE_SOUNDBOARD | USE_EXTERNAL_SOUNDS | PRIORITY_SPEAKER),
    ("whiteboard", USE_WHITEBOARD | MANAGE_WHITEBOARD),
    ("commands", 0),
    ("webhooks:manage", MANAGE_WEBHOOKS),
    ("presence", 0),
    ("dms", 0),
];

/// `true` for a known scope string.
pub fn is_scope(scope: &str) -> bool {
    SCOPES.iter().any(|(s, _)| *s == scope)
}

/// All scopes in canonical order.
pub fn all_scopes() -> Vec<String> {
    SCOPES.iter().map(|(s, _)| (*s).to_string()).collect()
}

/// The permission mask of a bot with these scopes: `BOT_ALWAYS ∪ ⋃ bits(scope)`. Unknown strings add
/// nothing. `administrator` is never part of it, so it is masked away like every bit outside the scopes.
pub fn scope_mask(scopes: &[String]) -> Perms {
    scopes
        .iter()
        .filter_map(|s| SCOPES.iter().find(|(name, _)| name == s).map(|(_, bits)| *bits))
        .fold(BOT_ALWAYS, |acc, bits| acc | bits)
}

/// `true` for accounts the bot rules apply to. Fails closed: every kind except `user` (bots, webhooks and
/// kinds this node does not know) is treated like a bot.
pub fn is_bot_kind(kind: &str) -> bool {
    kind != "user"
}

/// The bot branch of the evaluation (APPLICATIONS.md §2.4): 0 in a "no bots" zone, otherwise the evaluated
/// permissions capped by the scope mask (`None` = no token context, i.e. all scopes). For users the
/// permissions are returned unchanged.
pub fn cap_bot(perms: Perms, kind: &str, no_bots: bool, scopes: Option<&[String]>) -> Perms {
    if !is_bot_kind(kind) {
        return perms;
    }
    if no_bots {
        return 0;
    }
    let mask = match scopes {
        Some(s) => scope_mask(s),
        None => SCOPES.iter().fold(BOT_ALWAYS, |acc, (_, bits)| acc | bits),
    };
    perms & mask
}

/// Room setting `bots_in_encrypted_channels` (APPLICATIONS.md §3.5): every encrypted channel is "no
/// bots" unless the channel allows bots (`bots_allowed`). The default of new rooms.
pub const BOTS_PER_CHANNEL: &str = "per_channel";
/// Room setting `bots_in_encrypted_channels`: encrypted channels follow the `no_bots` flags only (rooms that existed
/// before the setting).
pub const BOTS_ALLOWED: &str = "allowed";
/// The values of `bots_in_encrypted_channels`.
pub const BOTS_IN_ENCRYPTED_CHANNELS: &[&str] = &[BOTS_PER_CHANNEL, BOTS_ALLOWED];

/// What the effective "no bots" flag of a channel depends on (APPLICATIONS.md §3.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoBotsInput {
    #[serde(default)]
    pub room_no_bots: bool,
    #[serde(default)]
    pub category_no_bots: bool,
    #[serde(default)]
    pub channel_no_bots: bool,
    /// The channel is end-to-end encrypted.
    #[serde(default)]
    pub encrypted: bool,
    /// The channel setting `bots_allowed`.
    #[serde(default)]
    pub bots_allowed: bool,
    /// The room setting `bots_in_encrypted_channels`; anything but `allowed` counts as `per_channel` (fail closed).
    #[serde(default)]
    pub bots_in_encrypted_channels: String,
}

/// The effective "no bots" flag of a channel: room ∨ category ∨ channel flag, and, in a room whose
/// `bots_in_encrypted_channels` is `per_channel`, every encrypted channel without `bots_allowed`. The explicit
/// flags always win; `bots_allowed` never opens a channel that a flag closes. Shared test vectors:
/// `protocol/testvectors/no_bots.json`.
pub fn no_bots_effective(input: &NoBotsInput) -> bool {
    input.room_no_bots
        || input.category_no_bots
        || input.channel_no_bots
        || (input.encrypted && !input.bots_allowed && input.bots_in_encrypted_channels != BOTS_ALLOWED)
}

pub fn has(perms: Perms, needed: Perms) -> bool {
    perms & needed == needed
}

pub fn parse(s: &str) -> Option<Perms> {
    s.parse::<u64>().ok().filter(|v| v & !ALL == 0)
}

pub fn names(perms: Perms) -> Vec<&'static str> {
    ALL_NAMED.iter().filter(|(_, bit)| perms & bit != 0).map(|(n, _)| *n).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Role,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Override {
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub allow: Perms,
    pub deny: Perms,
}

/// Everything the evaluation needs for a member in a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Input {
    pub user_id: String,
    pub is_owner: bool,
    pub everyone_role_id: String,
    pub everyone_permissions: Perms,
    /// The member's roles without `@everyone`: (role id, permissions).
    pub member_roles: Vec<(String, Perms)>,
    /// Overrides of the channel's category (empty if there is no category).
    pub category_overrides: Vec<Override>,
    /// The channel's own overrides, applied on top of the category's.
    pub channel_overrides: Vec<Override>,
    pub timed_out: bool,
    /// Account kind (`user`, `bot`, …); every kind except `user` gets the bot branch (APPLICATIONS.md §2.4).
    #[serde(default = "user_kind")]
    pub kind: String,
    /// Effective "no bots" flag of the channel (room ∨ category ∨ channel, §3.5).
    #[serde(default)]
    pub no_bots: bool,
    /// Effective scopes of the bot's token; `None` = all scopes.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// The channel is a system channel (the welcome channel): [`SYSTEM_CHANNEL_FORCED`] is added and
    /// [`SYSTEM_CHANNEL_DENIED`] removed before the bot cap.
    #[serde(default)]
    pub system_channel: bool,
    /// The member has a moved participation in this voice channel (`VOICE.md` §7 "Moved participations"): a
    /// moderator moved them in, so [`MOVED_FORCED`] is added after the overrides, whatever they deny. Not part of
    /// the protocol's test vectors (like the age gate, the node applies it around the evaluation).
    #[serde(default)]
    pub moved: bool,
}

fn user_kind() -> String {
    "user".into()
}

/// Room-wide permissions (without channel context), e.g. for "may manage roles".
pub fn room_level(is_owner: bool, everyone_permissions: Perms, member_roles: &[(String, Perms)]) -> Perms {
    if is_owner {
        return ALL;
    }
    let base = member_roles.iter().fold(everyone_permissions, |acc, (_, p)| acc | p);
    if has(base, ADMINISTRATOR) { ALL } else { base }
}

/// Effective permissions in a channel (protocol/permissions.md "Evaluation"): the role base, then the
/// category's overrides, then the channel's own on top, a neutral bit inheriting from the layer below. For bots the result is
/// capped afterwards ([`cap_bot`]): administrator and owner expand to all bits first, then the scope mask.
pub fn compute(input: &Input) -> Perms {
    let mut perms = compute_member(input);
    if input.system_channel {
        perms = (perms | SYSTEM_CHANNEL_FORCED) & !SYSTEM_CHANNEL_DENIED;
    }
    let capped = cap_bot(perms, &input.kind, input.no_bots, input.scopes.as_deref());
    if has(capped, VIEW_CHANNEL) { capped } else { 0 }
}

fn compute_member(input: &Input) -> Perms {
    if input.is_owner {
        return ALL;
    }
    let base = room_level(false, input.everyone_permissions, &input.member_roles);
    if has(base, ADMINISTRATOR) {
        return ALL;
    }
    let category = apply_overrides(base, &input.category_overrides, input);
    let mut perms = apply_overrides(category, &input.channel_overrides, input);
    // No override can hide a system channel: as if view_channel and read_history were never denied.
    if input.system_channel {
        perms |= SYSTEM_CHANNEL_FORCED;
    }
    if input.moved {
        perms |= MOVED_FORCED;
    }
    if !has(perms, VIEW_CHANNEL) {
        return 0;
    }
    if input.timed_out {
        perms &= TIMEOUT_KEEPS;
    }
    perms
}

/// One layer (the category's or the channel's overrides) on top of `perms`. Only [`CHANNEL_SCOPED`] bits of an
/// override take part; bits it neither allows nor denies keep the value of the layer below.
fn apply_overrides(mut perms: Perms, overrides: &[Override], input: &Input) -> Perms {
    let apply = |perms: Perms, allow: Perms, deny: Perms| (perms & !(deny & CHANNEL_SCOPED)) | (allow & CHANNEL_SCOPED);
    // 1. @everyone override
    if let Some(o) =
        overrides.iter().find(|o| o.subject_type == SubjectType::Role && o.subject_id == input.everyone_role_id)
    {
        perms = apply(perms, o.allow, o.deny);
    }
    // 2. Role overrides: all denies first, then all allows
    let (mut allow, mut deny) = (0u64, 0u64);
    for o in overrides.iter().filter(|o| o.subject_type == SubjectType::Role) {
        if input.member_roles.iter().any(|(id, _)| *id == o.subject_id) {
            allow |= o.allow;
            deny |= o.deny;
        }
    }
    perms = apply(perms, allow, deny);
    // 3. Member override
    if let Some(o) = overrides.iter().find(|o| o.subject_type == SubjectType::Member && o.subject_id == input.user_id) {
        perms = apply(perms, o.allow, o.deny);
    }
    perms
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        input: Input,
        expected: String,
    }

    #[test]
    fn protocol_test_vectors_pass() {
        let json = include_str!("../protocol/testvectors/permissions.json");
        let vectors: Vec<Vector> = serde_json::from_str(json).unwrap();
        assert!(vectors.len() >= 8);
        for v in vectors {
            let got = compute(&v.input);
            assert_eq!(
                got.to_string(),
                v.expected,
                "vector '{}': expected {:?}, got {:?}",
                v.name,
                names(parse(&v.expected).unwrap()),
                names(got)
            );
        }
    }

    #[test]
    fn a_moved_participation_grants_view_read_and_connect_but_nothing_else() {
        let input = |moved: bool, timed_out: bool| Input {
            user_id: "u1".into(),
            is_owner: false,
            everyone_role_id: "r0".into(),
            everyone_permissions: VIEW_CHANNEL | CONNECT | SPEAK | SEND_MESSAGES,
            member_roles: Vec::new(),
            category_overrides: Vec::new(),
            channel_overrides: vec![Override {
                subject_type: SubjectType::Role,
                subject_id: "r0".into(),
                allow: 0,
                deny: VIEW_CHANNEL | CONNECT | SEND_MESSAGES,
            }],
            timed_out,
            kind: "user".into(),
            no_bots: false,
            scopes: None,
            system_channel: false,
            moved,
        };
        assert_eq!(compute(&input(false, false)), 0, "hidden without the move");
        assert_eq!(compute(&input(true, false)), VIEW_CHANNEL | READ_HISTORY | CONNECT | SPEAK, "speak from the roles");
        assert_eq!(compute(&input(true, true)), TIMEOUT_KEEPS, "a timeout still strips connect");
        let mut bot = input(true, false);
        bot.kind = "bot".into();
        bot.no_bots = true;
        assert_eq!(compute(&bot), 0, "the bot cap still applies");
    }

    #[test]
    fn all_contains_every_named_bit_and_fits_i64() {
        for (_, bit) in ALL_NAMED {
            assert!(has(ALL, *bit));
        }
        assert!(ALL <= i64::MAX as u64);
        assert_eq!(parse("abc"), None);
        assert_eq!(parse(&(1u64 << 40).to_string()), None, "undefined bits are rejected");
        assert_eq!(parse(&ALL.to_string()), Some(ALL));
    }

    #[test]
    fn everyone_defaults_contain_nothing_restricted() {
        assert_eq!(DEFAULT_EVERYONE & EVERYONE_RESTRICTED, 0);
        // The same value is pinned in the SDK (tavrn-js, sdk/test/permissions.test.ts).
        assert_eq!(EVERYONE_RESTRICTED, 4_611_686_268_363_406_212);
        assert!(has(DEFAULT_EVERYONE, USE_WHITEBOARD));
        assert!(!has(DEFAULT_EVERYONE, MANAGE_WHITEBOARD));
        assert_eq!(names(USE_WHITEBOARD | MANAGE_WHITEBOARD), vec!["use_whiteboard", "manage_whiteboard"]);
        // History for new members: granted by default, never restricted.
        assert_eq!(READ_HISTORY, 1 << 34);
        assert!(has(DEFAULT_EVERYONE, READ_HISTORY));
        assert_eq!(EVERYONE_RESTRICTED & READ_HISTORY, 0);
        assert!(has(scope_mask(&["messages:read".to_string()]), READ_HISTORY));
    }

    #[test]
    fn scope_masks() {
        assert_eq!(scope_mask(&[]), BOT_ALWAYS);
        let write = scope_mask(&["messages:write".to_string()]);
        assert!(has(write, SEND_MESSAGES | ATTACH_FILES | VIEW_CHANNEL));
        assert!(!has(write, MANAGE_MESSAGES));
        assert_eq!(scope_mask(&["nonsense".to_string()]), BOT_ALWAYS, "unknown scopes add nothing");
        assert!(!has(scope_mask(&all_scopes()), ADMINISTRATOR), "administrator is never unlocked by a scope");
        assert_eq!(
            scope_mask(&all_scopes()) | ADMINISTRATOR | RESTORE_HISTORY,
            ALL,
            "every other bit is reachable through a scope (restore_history never is)"
        );
        assert!(is_scope("dms") && !is_scope("admin"));
    }

    #[test]
    fn bot_cap_masks_administrator_and_no_bots() {
        let scopes = vec!["messages:read".to_string()];
        assert_eq!(cap_bot(ALL, "user", true, Some(&scopes)), ALL, "users are never capped");
        assert_eq!(cap_bot(ALL, "bot", false, Some(&scopes)), BOT_ALWAYS | READ_HISTORY);
        assert_eq!(cap_bot(ALL, "bot", true, None), 0);
        assert_eq!(
            cap_bot(ALL, "webhook", false, Some(&scopes)),
            BOT_ALWAYS | READ_HISTORY,
            "unknown kinds fail closed"
        );
        assert_eq!(cap_bot(ALL, "bot", false, None), ALL & !(ADMINISTRATOR | RESTORE_HISTORY));
    }

    #[test]
    fn manage_applications_is_management_class_and_covered_by_rooms_manage() {
        assert_eq!(MANAGE_APPLICATIONS, 1 << 35);
        assert!(has(EVERYONE_RESTRICTED, MANAGE_APPLICATIONS), "never on @everyone");
        assert!(!has(DEFAULT_EVERYONE, MANAGE_APPLICATIONS));
        assert!(has(scope_mask(&["rooms:manage".to_string()]), MANAGE_APPLICATIONS));
        assert!(!has(scope_mask(&["moderation".to_string(), "commands".to_string()]), MANAGE_APPLICATIONS));
        assert_eq!(names(MANAGE_APPLICATIONS), vec!["manage_applications"]);
        assert_eq!(parse(&MANAGE_APPLICATIONS.to_string()), Some(MANAGE_APPLICATIONS));
    }

    #[test]
    fn manage_threads_is_management_class_and_covered_by_moderation() {
        assert_eq!(MANAGE_THREADS, 1 << 36);
        assert_eq!(CREATE_THREADS, 1 << 6);
        assert!(has(DEFAULT_EVERYONE, CREATE_THREADS), "everybody starts threads by default");
        assert!(has(EVERYONE_RESTRICTED, MANAGE_THREADS), "never on @everyone");
        assert!(!has(EVERYONE_RESTRICTED, CREATE_THREADS));
        assert!(!has(DEFAULT_EVERYONE, MANAGE_THREADS));
        assert!(has(scope_mask(&["moderation".to_string()]), MANAGE_THREADS));
        assert!(!has(scope_mask(&["messages:write".to_string()]), MANAGE_THREADS));
        assert!(has(scope_mask(&["messages:write".to_string()]), CREATE_THREADS));
        assert_eq!(names(MANAGE_THREADS), vec!["manage_threads"]);
        assert_eq!(parse(&MANAGE_THREADS.to_string()), Some(MANAGE_THREADS));
    }

    #[test]
    fn restore_history_is_management_class_and_never_a_bot_scope() {
        assert_eq!(RESTORE_HISTORY, 1 << 37);
        assert!(has(EVERYONE_RESTRICTED, RESTORE_HISTORY), "never on @everyone");
        assert!(!has(DEFAULT_EVERYONE, RESTORE_HISTORY));
        let every_scope: Vec<String> = SCOPES.iter().map(|(s, _)| s.to_string()).collect();
        assert!(!has(scope_mask(&every_scope), RESTORE_HISTORY), "no app-token scope covers it");
        assert!(has(ALL, RESTORE_HISTORY), "owners and administrators hold it");
        assert_eq!(names(RESTORE_HISTORY), vec!["restore_history"]);
    }

    #[derive(Deserialize)]
    struct NoBotsVector {
        name: String,
        input: NoBotsInput,
        expected: bool,
    }

    #[test]
    fn no_bots_test_vectors_pass() {
        let json = include_str!("../protocol/testvectors/no_bots.json");
        let vectors: Vec<NoBotsVector> = serde_json::from_str(json).unwrap();
        assert!(vectors.len() >= 8);
        for v in vectors {
            assert_eq!(no_bots_effective(&v.input), v.expected, "vector '{}'", v.name);
        }
    }

    #[test]
    fn channel_scoped_matches_the_protocol_table() {
        // The same value is pinned in the SDK (tavrn-js, sdk/test/permissions.test.ts).
        assert_eq!(CHANNEL_SCOPED, 377_927_696_895);
        let doc = include_str!("../protocol/permissions.md");
        let section = doc.split("## Channel-scoped bits").nth(1).unwrap().split("\n## ").next().unwrap();
        let from_doc = section
            .lines()
            .filter_map(|l| l.strip_prefix("| ")?.split(" | `").next()?.parse::<u32>().ok())
            .fold(0u64, |acc, bit| acc | (1 << bit));
        assert_eq!(from_doc, CHANNEL_SCOPED);
        for room_level in
            [ADMINISTRATOR, MANAGE_ROOM, CREATE_INVITES, KICK_MEMBERS, BAN_MEMBERS, MODERATE_MEMBERS, PURGE]
        {
            assert_eq!(CHANNEL_SCOPED & room_level, 0, "{:?}", names(room_level));
        }
        for room_level in [VIEW_AUDIT_LOG, MANAGE_EMOJIS, CHANGE_NICKNAME, MANAGE_NICKNAMES, MANAGE_APPLICATIONS] {
            assert_eq!(CHANNEL_SCOPED & room_level, 0, "{:?}", names(room_level));
        }
        assert_eq!(names(CHANNEL_SCOPED).len(), 27);
    }

    #[test]
    fn voice_status_is_a_channel_scoped_bit_of_its_own() {
        assert_eq!(VOICE_STATUS, 1 << 38);
        assert!(!has(EVERYONE_RESTRICTED, VOICE_STATUS), "a room may let everybody set the status");
        assert!(!has(DEFAULT_EVERYONE, VOICE_STATUS), "but not by default");
        assert!(has(CHANNEL_SCOPED, VOICE_STATUS), "an override can grant it alone");
        assert!(has(scope_mask(&["rooms:manage".to_string()]), VOICE_STATUS));
        assert!(
            !has(scope_mask(&["voice".to_string()]), VOICE_STATUS),
            "the voice scope joins and speaks, it does not edit"
        );
        assert_eq!(names(VOICE_STATUS), vec!["voice_status"]);
        assert_eq!(parse(&VOICE_STATUS.to_string()), Some(VOICE_STATUS));
    }

    #[test]
    fn names_roundtrip() {
        assert_eq!(names(VIEW_CHANNEL | SPEAK), vec!["view_channel", "speak"]);
    }
}
