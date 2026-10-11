// SPDX-License-Identifier: AGPL-3.0-only
//! History for new members of encrypted channels (ENCRYPTION.md §7b).
//!
//! The node is the first layer: `GET …/messages` serves encrypted messages from before a member's join only
//! as far as the channel's policy and the member's `read_history` bit allow. Members' clients share the
//! content keys of past epochs with a new member through `…/history-keys` (routes in
//! `routes/history.rs`); the node only stores and routes those shares and keeps track of members who still
//! wait for one (`history_pending`).

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use tavrn_crypto::ds::{CommitSummary, DsGroup};

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    error::ApiError,
    models::{MemberRow, UserRow},
    permissions, store, util,
    validate::bad,
};

/// Larger than every message id: "up to now" for `has_encrypted_before`.
const UNTIL_NOW: &str = "ZZZZZZZZZZZZZZZZZZZZZZZZZZ";

/// Largest `days:<n>` value (ten years).
pub const MAX_DAYS: i64 = 3650;
/// At most this many epochs per share (`epoch_to - epoch_from + 1`).
pub const MAX_EPOCHS_PER_SHARE: i64 = 1000;
/// Largest `ciphertext` of a share (characters of base64url).
pub const MAX_SHARE_BYTES: usize = 64 * 1024;
/// Shares per recipient and conversation within 24 hours.
pub const SHARES_PER_DAY: i64 = 20;
/// Shares and pending marks older than this are deleted by housekeeping.
pub const MAX_AGE_DAYS: i64 = 30;
/// Acknowledged shares are kept this long (they still count for the rate limit).
pub const ACKED_KEEP_HOURS: i64 = 24;
/// Restore shares are accepted this long after a restore was approved; decided requests are kept as long.
pub const RESTORE_VALID_DAYS: i64 = 30;
/// Requests per member, room and 24 hours.
pub const REQUESTS_PER_DAY: i64 = 5;
/// Longest request message and deny reason (characters).
pub const MAX_REQUEST_TEXT: usize = 500;
/// Values of the room setting `history_restore`.
pub const RESTORE_SETTINGS: &[&str] = &["request", "off"];
/// Channel kinds whose content a restore covers: every encrypted channel kind with stored content (voice channels
/// store nothing).
pub fn restorable_kind(kind: &str) -> bool {
    kind != "voice" && kind != "system"
}

/// The channel setting `history_for_new_members`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Members see (and get keys for) nothing from before their join, but everything since. Default.
    SinceJoin,
    /// Members see the last `n` days before their join.
    Days(i64),
    /// Members see the whole history.
    All,
}

impl Policy {
    /// Strict parsing of a value sent by a client: `since_join`, `all` or `days:<n>` with 1 ≤ n ≤ 3650
    /// (decimal digits only, no sign, no leading zero).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "since_join" => Some(Self::SinceJoin),
            "all" => Some(Self::All),
            _ => {
                let n = s.strip_prefix("days:")?;
                if n.is_empty() || n.len() > 4 || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let n: i64 = n.parse().ok()?;
                (1..=MAX_DAYS).contains(&n).then_some(Self::Days(n))
            }
        }
    }

    /// The stored value of a channel; NULL or anything unreadable is the default `since_join`.
    pub fn of(stored: Option<&str>) -> Self {
        stored.and_then(Self::parse).unwrap_or(Self::SinceJoin)
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SinceJoin => f.write_str("since_join"),
            Self::Days(n) => write!(f, "days:{n}"),
            Self::All => f.write_str("all"),
        }
    }
}

/// Serde default of `Channel::history_for_new_members`.
pub fn default_policy() -> String {
    Policy::SinceJoin.to_string()
}

/// Validates a policy value of a channel update.
pub fn validate(value: &str) -> Result<Policy, ApiError> {
    Policy::parse(value).ok_or_else(|| {
        bad(
            "channel.history_policy_invalid",
            "history_for_new_members must be since_join, all or days:<n> with 1 ≤ n ≤ 3650",
        )
    })
}

/// The oldest point in time from which a member may list encrypted messages: `None` = no limit. Without
/// `read_history` the history starts at the join whatever the policy says.
pub fn cutoff(policy: Policy, read_history: bool, joined_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
    match (read_history, policy) {
        (false, _) | (true, Policy::SinceJoin) => Some(joined_at),
        (true, Policy::Days(n)) => Some(joined_at - Duration::days(n)),
        (true, Policy::All) => None,
    }
}

/// The smallest ULID of a millisecond: message ids are ULIDs, so `id >= ulid_floor(t)` selects the
/// messages created at or after `t` (and uses the primary key).
pub fn ulid_floor(t: DateTime<Utc>) -> String {
    let ms = u64::try_from(t.timestamp_millis()).unwrap_or(0);
    ulid::Ulid::from_parts(ms, 0).to_string()
}

/// The start of a room member's window: the policy and the `read_history` bit from `joined_at`, and after a key
/// reset without an approved restore never before `key_reset_at` (ENCRYPTION.md §7b "History after a key reset").
/// `None` = no limit.
pub fn member_window(policy: Policy, read_history: bool, member: &MemberRow) -> Option<DateTime<Utc>> {
    let base = util::parse_time(&member.joined_at).and_then(|joined| cutoff(policy, read_history, joined));
    match reset_cut(member) {
        Some(reset) => Some(base.map_or(reset, |b| b.max(reset))),
        None => base,
    }
}

/// `key_reset_at` of a membership whose history was not restored.
pub fn reset_cut(member: &MemberRow) -> Option<DateTime<Utc>> {
    if member.history_restored_at.is_some() {
        return None;
    }
    member.key_reset_at.as_deref().and_then(util::parse_time)
}

/// The start of the requester's history window in a conversation, `None` = no limit:
/// - room channels: [`member_window`] of the membership (node admins who are not members are not limited; they
///   cannot decrypt anything anyway);
/// - group DMs: the requester's `joined_at` (`since_join`: members added later start there);
/// - DMs: no limit (both participants are members from the start).
///
/// Measured on message ids (`list_cutoff`) and on the records of files channels (FILES.md §8.7).
pub async fn window_start(state: &AppState, conv: &Conv, user: &UserRow) -> Result<Option<DateTime<Utc>>, ApiError> {
    match &conv.kind {
        ConvKind::Channel { access, channel } => {
            let Some(member) = &access.member else { return Ok(None) };
            Ok(member_window(
                Policy::of(channel.history_for_new_members.as_deref()),
                permissions::has(conv.perms, permissions::READ_HISTORY),
                member,
            ))
        }
        ConvKind::Direct { row, .. } if row.kind == "group" => {
            Ok(store::history::direct_joined_at(&state.db, &conv.id, &user.id)
                .await?
                .as_deref()
                .and_then(util::parse_time))
        }
        ConvKind::Direct { .. } => Ok(None),
    }
}

/// The cut for `GET …/messages` of the requester as a message id (ULID floor), or `None` ([`window_start`]).
/// Only encrypted messages are cut; plaintext messages stay readable as before.
pub async fn list_cutoff(state: &AppState, conv: &Conv, user: &UserRow) -> Result<Option<String>, ApiError> {
    Ok(window_start(state, conv, user).await?.map(ulid_floor))
}

/// The user's identity key changed without continuity (a reset, ENCRYPTION.md §9; called with the welcome
/// channel's `system.key_changed { rotated: false }`): every membership here gets `key_reset_at`, every encrypted
/// group of those rooms records the reset epoch. A reset of a local account is recorded in the reset's own
/// transaction already (`store::e2ee::reset_identity`), so this only moves the mark to the announcement; for a
/// remote user it is the record. Failures are logged (the key change already happened).
pub async fn key_reset(state: &AppState, user: &UserRow, at: &str) {
    if let Err(e) = store::history::mark_key_reset(&state.db, &user.id, at).await {
        tracing::warn!(error = %e, user = user.address(), "key reset not recorded on the memberships");
    }
}

/// `min_epoch` of a reset member (reset epoch + 1, ENCRYPTION.md §7b), `None` without a pre-reset range.
pub async fn min_epoch(state: &AppState, conversation_id: &str, user_id: &str) -> Result<Option<i64>, ApiError> {
    Ok(store::history::reset_epoch(&state.db, conversation_id, user_id).await?.map(|e| e + 1))
}

/// After an accepted commit: users who got their first leaf in the group (an external join of a user
/// without a leaf, or added users) are marked `history_pending` when they hold `view_channel` and `read_history`
/// and there are encrypted messages in their window from before this commit: from before the room join as far as
/// the policy reaches, and those posted between the room join and the device's first leaf, under every policy
/// (ENCRYPTION.md §7b; a device enters a channel's group only when it first opens the channel). Members who wait get
/// `history.pending { conversation_id, user }` so that an online member shares the keys. Best effort: a
/// failure here never fails the commit.
pub async fn after_commit(state: &AppState, conv: &Conv, committer: &UserRow, summary: &CommitSummary, before: &[u8]) {
    if let Err(e) = mark_new_members(state, conv, committer, summary, before).await {
        tracing::warn!(error = %e, "history_pending could not be updated");
    }
}

async fn mark_new_members(
    state: &AppState,
    conv: &Conv,
    committer: &UserRow,
    summary: &CommitSummary,
    before: &[u8],
) -> Result<(), ApiError> {
    let ConvKind::Channel { access, channel } = &conv.kind else { return Ok(()) };
    let policy = Policy::of(channel.history_for_new_members.as_deref());
    if !conv.encrypted {
        return Ok(());
    }
    // Users with a leaf before this commit already are in the group (a further device of theirs joins).
    let had_leaf: std::collections::HashSet<String> = DsGroup::import_state(before)
        .and_then(|g| g.roster())
        .map(|r| r.into_iter().filter_map(|e| e.identity.split_once('/').map(|(a, _)| a.to_string())).collect())
        .unwrap_or_default();
    let mut addresses: Vec<String> = Vec::new();
    if summary.external_join {
        addresses.push(committer.address());
    }
    for added in &summary.added {
        if let Some((address, _)) = added.identity.split_once('/') {
            addresses.push(address.to_string());
        }
    }
    addresses.sort();
    addresses.dedup();
    for address in addresses {
        let Some((username, domain)) = util::parse_address(&address) else { continue };
        let Some(user) = store::federation::user_by_address(&state.db, username, domain).await? else { continue };
        let member_access = match access::room_access(state, &access.room.id, &user).await {
            Ok(a) => a,
            Err(ApiError::Forbidden { .. }) => continue,
            Err(e) => return Err(e),
        };
        let Some(member) = &member_access.member else { continue };
        // After a key reset the user's old (now unattested) leaves may still be in the group: the first device
        // back counts as new, once per reset.
        let reset = member.key_reset_at.as_deref();
        if reset.is_none() && had_leaf.contains(&address) {
            continue;
        }
        let perms = access::channel_perms(state, &member_access, channel, &user.id).await?;
        if !permissions::has(perms, permissions::VIEW_CHANNEL | permissions::READ_HISTORY) {
            continue;
        }
        let marker = reset.unwrap_or(member.joined_at.as_str());
        if store::history::pending_since(&state.db, &conv.id, &user.id).await?.as_deref() == Some(marker) {
            continue; // this membership (or this reset) was handled already
        }
        // The automatic window, up to this commit: from the policy's start (under `since_join` the join), or after a
        // reset everything since the reset (never earlier, ENCRYPTION.md §7b "History after a key reset"). The same
        // window as times for the entry records of a files channel.
        let from_time = match reset.and_then(util::parse_time) {
            Some(r) => Some(r),
            None => {
                let Some(joined) = util::parse_time(&member.joined_at) else { continue };
                cutoff(policy, true, joined)
            }
        };
        let from = from_time.map(ulid_floor);
        let mut older = store::history::has_encrypted_before(&state.db, &conv.id, UNTIL_NOW, from.as_deref()).await?;
        // Files channels have entry records instead of messages (FILES.md §8.7).
        if !older && channel.kind == "files" {
            let from_time = from_time.map(util::format_time);
            older = store::files::has_records_between(&state.db, &conv.id, from_time.as_deref(), &util::now()).await?;
        }
        store::history::set_pending(&state.db, &conv.id, &user.id, marker, older).await?;
        if older {
            let min_epoch = match reset {
                Some(_) => min_epoch(state, &conv.id, &user.id).await?,
                None => None,
            };
            conv.publish(
                &state.hub,
                "history.pending",
                serde_json::json!({ "conversation_id": conv.id, "user": user.address(), "since": marker,
                                    "key_reset_at": reset, "min_epoch": min_epoch }),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn policy_parsing_is_strict() {
        assert_eq!(Policy::parse("since_join"), Some(Policy::SinceJoin));
        assert_eq!(Policy::parse("all"), Some(Policy::All));
        assert_eq!(Policy::parse("days:1"), Some(Policy::Days(1)));
        assert_eq!(Policy::parse("days:3650"), Some(Policy::Days(3650)));
        for bad in [
            "",
            "ALL",
            "days:",
            "days:0",
            "days:3651",
            "days:-1",
            "days:+5",
            "days:07",
            "days:1.5",
            "days: 3",
            "days:99999",
            "since-join",
        ] {
            assert_eq!(Policy::parse(bad), None, "{bad}");
        }
        assert_eq!(Policy::of(None), Policy::SinceJoin);
        assert_eq!(Policy::of(Some("nonsense")), Policy::SinceJoin);
        assert_eq!(Policy::of(Some("days:30")).to_string(), "days:30");
        assert!(validate("days:0").is_err());
    }

    #[test]
    fn cutoff_follows_policy_and_bit() {
        let joined = util::parse_time("2026-10-01T12:00:00.000Z").unwrap();
        assert_eq!(cutoff(Policy::SinceJoin, true, joined), Some(joined));
        assert_eq!(cutoff(Policy::All, true, joined), None);
        assert_eq!(cutoff(Policy::Days(2), true, joined), util::parse_time("2026-09-29T12:00:00.000Z"));
        // Without read_history the history starts at the join, whatever the policy.
        assert_eq!(cutoff(Policy::All, false, joined), Some(joined));
        assert_eq!(cutoff(Policy::Days(5), false, joined), Some(joined));
    }

    fn member(joined: &str, reset: Option<&str>, restored: Option<&str>) -> MemberRow {
        MemberRow {
            room_id: "r".into(),
            user_id: "u".into(),
            nickname: None,
            joined_at: joined.into(),
            rules_accepted_at: None,
            timeout_until: None,
            avatar_media_id: None,
            avatar_animated: 0,
            bio: String::new(),
            key_reset_at: reset.map(Into::into),
            history_restored_at: restored.map(Into::into),
        }
    }

    #[test]
    fn a_key_reset_moves_the_window_until_a_restore() {
        let t = |s: &str| util::parse_time(s);
        let joined = "2026-10-01T12:00:00.000Z";
        let reset = "2026-10-05T08:00:00.000Z";
        // Without a reset: the policy.
        assert_eq!(member_window(Policy::All, true, &member(joined, None, None)), None);
        assert_eq!(member_window(Policy::SinceJoin, true, &member(joined, None, None)), t(joined));
        // After a reset: never before it, whatever the policy and the bit.
        for (policy, bit) in
            [(Policy::All, true), (Policy::Days(30), true), (Policy::SinceJoin, true), (Policy::All, false)]
        {
            assert_eq!(member_window(policy, bit, &member(joined, Some(reset), None)), t(reset), "{policy} {bit}");
        }
        // An approved restore gives the normal window back.
        let restored = member(joined, Some(reset), Some("2026-10-06T00:00:00.000Z"));
        assert_eq!(member_window(Policy::All, true, &restored), None);
        assert_eq!(member_window(Policy::Days(1), true, &restored), t("2026-09-30T12:00:00.000Z"));
        assert_eq!(reset_cut(&restored), None);
        assert!(restorable_kind("text") && restorable_kind("files") && restorable_kind("forum"));
        assert!(!restorable_kind("voice") && !restorable_kind("system"));
    }

    #[test]
    fn ulid_floor_orders_with_message_ids() {
        let t = util::parse_time("2026-10-01T12:00:00.000Z").unwrap();
        let floor = ulid_floor(t);
        assert_eq!(floor.len(), 26);
        assert!(floor.ends_with("0000000000000000"));
        let same_ms = ulid::Ulid::from_parts(t.timestamp_millis() as u64, 12345).to_string();
        let earlier = ulid::Ulid::from_parts(t.timestamp_millis() as u64 - 1, u128::MAX >> 48).to_string();
        assert!(same_ms >= floor && earlier < floor);
    }
}
