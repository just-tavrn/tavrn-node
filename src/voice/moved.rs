// SPDX-License-Identifier: AGPL-3.0-only
//! Moved participations as every instance sees them (`VOICE.md` §7 "Moved participations").
//!
//! A moderator with `move_members` may move a member into a voice channel the member may neither view nor connect
//! to. From the move until the participation ends (the grant expires unused, the member leaves, is removed or joins
//! elsewhere) the member counts as a viewer of that channel with `connect` ([`crate::permissions::MOVED_FORCED`]).
//! The leader holds the participations ([`super::state::VoiceState`]); it announces each room's moved members with
//! the internal hub event [`EVENT`] (never delivered to clients, `visibility::Filter`), which also travels over the
//! cache bus. Every instance's hub keeps the last announcement per room in an [`Index`] before any connection sees
//! the event and drops the room's visibility snapshot when the set changed, so the REST routes
//! (`access::room_access`), the snapshot (`visibility.rs`) and the WebSocket fan-out of every instance agree.
//!
//! The leader repeats each room's announcement every [`REFRESH`]; an announcement is valid until its `until_ms`
//! (a few refreshes) and only while its sender is the current leader, so a crashed leader's grants lapse.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// Kind of the internal hub event that announces a room's moved members (`Scope::Room`).
pub const EVENT: &str = "voice.moved";
/// The leader repeats the announcements this often (instances that started later learn them).
pub const REFRESH: Duration = Duration::from_secs(30);
/// An announcement is valid for this long after it was made.
pub const VALID: Duration = Duration::from_secs(95);

/// Payload of [`EVENT`]: the room's moved members (user id → voice channel id) as the leader sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub room_id: String,
    /// Instance id of the leader that made it.
    pub leader: String,
    /// Unix milliseconds until which it is valid.
    pub until_ms: u64,
    pub users: BTreeMap<String, String>,
}

/// The last announcement per room on this instance.
#[derive(Default)]
pub struct Index {
    rooms: Mutex<HashMap<String, Announcement>>,
}

impl Index {
    fn rooms(&self) -> std::sync::MutexGuard<'_, HashMap<String, Announcement>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes an announcement (the data of an [`EVENT`] to `room_id`); `true` if the room's moved members changed
    /// (the caller drops the room's visibility snapshot), `false` for a mere refresh. Garbage and an announcement
    /// about another room are ignored.
    pub fn apply(&self, room_id: &str, data: &serde_json::Value) -> bool {
        let Ok(a) = serde_json::from_value::<Announcement>(data.clone()) else { return false };
        if a.room_id != room_id {
            return false;
        }
        let room_id = a.room_id.clone();
        let mut rooms = self.rooms();
        let before = rooms.get(&room_id).map(|old| (old.users.clone(), old.leader.clone()));
        let after = (!a.users.is_empty()).then(|| (a.users.clone(), a.leader.clone()));
        if a.users.is_empty() {
            rooms.remove(&room_id);
        } else {
            rooms.insert(room_id.clone(), a);
        }
        before != after
    }

    /// The valid moved members of a room (user id → channel id): announced by `leader` (the current leader, `None`:
    /// unknown, then any) and not expired at `now_ms`.
    pub fn of_room(&self, room_id: &str, leader: Option<&str>, now_ms: u64) -> HashMap<String, String> {
        let rooms = self.rooms();
        match rooms.get(room_id) {
            Some(a) if a.until_ms > now_ms && leader.is_none_or(|l| l == a.leader) => {
                a.users.iter().map(|(u, c)| (u.clone(), c.clone())).collect()
            }
            _ => HashMap::new(),
        }
    }

    /// The voice channel of `room_id` in which `user_id` has a valid moved participation.
    pub fn channel_of(&self, room_id: &str, user_id: &str, leader: Option<&str>, now_ms: u64) -> Option<String> {
        let rooms = self.rooms();
        let a = rooms.get(room_id)?;
        (a.until_ms > now_ms && leader.is_none_or(|l| l == a.leader)).then(|| a.users.get(user_id).cloned())?
    }
}

/// The channel of `room_id` in which `user_id` has a moved participation, as this instance knows it.
pub fn channel_of(state: &crate::app::AppState, room_id: &str, user_id: &str) -> Option<String> {
    let leader = state.cluster.leader_id();
    state.hub.moved().channel_of(room_id, user_id, leader.as_deref(), crate::cache::now_ms())
}

/// The moved members of `room_id` (user id → channel id), as this instance knows them.
pub fn of_room(state: &crate::app::AppState, room_id: &str) -> HashMap<String, String> {
    let leader = state.cluster.leader_id();
    state.hub.moved().of_room(room_id, leader.as_deref(), crate::cache::now_ms())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde_json::json;

    use super::*;

    fn announce(room: &str, leader: &str, until_ms: u64, users: &[(&str, &str)]) -> serde_json::Value {
        json!({ "room_id": room, "leader": leader, "until_ms": until_ms,
                "users": users.iter().map(|(u, c)| (u.to_string(), json!(c))).collect::<serde_json::Map<_, _>>() })
    }

    #[test]
    fn announcements_replace_each_other_and_report_changes() {
        let index = Index::default();
        assert!(!index.apply("r1", &announce("r1", "a", 100, &[])), "nothing known, nothing announced");
        assert!(index.apply("r1", &announce("r1", "a", 100, &[("bob", "c1")])));
        assert!(!index.apply("r1", &announce("r1", "a", 200, &[("bob", "c1")])), "a refresh changes nothing");
        assert_eq!(index.channel_of("r1", "bob", Some("a"), 150).as_deref(), Some("c1"), "the refresh extended it");
        assert!(index.apply("r1", &announce("r1", "a", 200, &[("bob", "c2")])));
        assert_eq!(index.of_room("r1", None, 0), HashMap::from([("bob".to_string(), "c2".to_string())]));
        assert!(index.apply("r1", &announce("r1", "a", 200, &[])), "the last one left");
        assert!(index.of_room("r1", None, 0).is_empty());
        assert!(!index.apply("r1", &json!({ "garbage": true })));
        assert!(!index.apply("r2", &announce("r1", "a", 200, &[("eve", "c1")])), "the room must match the scope");
        assert!(index.of_room("r1", None, 0).is_empty());
    }

    #[test]
    fn only_current_announcements_of_the_current_leader_count() {
        let index = Index::default();
        index.apply("r1", &announce("r1", "a", 100, &[("bob", "c1")]));
        assert_eq!(index.channel_of("r1", "bob", Some("a"), 99).as_deref(), Some("c1"));
        assert_eq!(index.channel_of("r1", "bob", None, 99).as_deref(), Some("c1"), "leader unknown: any");
        assert_eq!(index.channel_of("r1", "bob", Some("a"), 100), None, "expired");
        assert_eq!(index.channel_of("r1", "bob", Some("b"), 99), None, "a former leader's grants lapse");
        assert!(index.of_room("r1", Some("b"), 0).is_empty());
        assert_eq!(index.channel_of("r1", "carol", Some("a"), 0), None);
        assert_eq!(index.channel_of("r2", "bob", Some("a"), 0), None);
        // A new leader's announcement replaces the old one at once.
        assert!(index.apply("r1", &announce("r1", "b", 100, &[("bob", "c1")])));
        assert_eq!(index.channel_of("r1", "bob", Some("b"), 0).as_deref(), Some("c1"));
    }
}
