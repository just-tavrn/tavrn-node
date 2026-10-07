// SPDX-License-Identifier: AGPL-3.0-only
//! Who is in which voice channel (in memory, per node).
//!
//! The source of truth for presence is LiveKit: its webhooks (`participant_joined`/`_left`,
//! `track_published`/`_unpublished`) move participants in and out, and the reconciliation job compares
//! this state with LiveKit's room service every 30 seconds, so a lost webhook or a LiveKit crash never
//! leaves ghosts. Self state (muted, deafened) comes from the clients (`PATCH …/voice/state`), the
//! server mute from moderators.
//!
//! A `voice/join` *reserves* a slot (pending participant) for the device that got a token, so the user
//! limit holds between the token and the connection and early `PATCH …/voice/state` calls are not lost.
//! Pending participants are invisible in `voice.state` until LiveKit reports them; they expire after
//! [`PENDING_TTL`].
//!
//! A participant whose connection drops (LiveKit's `participant_left`/`_connection_aborted` without a
//! client-initiated reason, or missing in the reconciliation) is not removed at once: it stays visible as
//! [`Connection::Reconnecting`] for the grace period (`TAVRN_VOICE_RECONNECT_GRACE_SECS`). A
//! rejoin of the same identity within the grace period continues the entry (nobody appears
//! twice); a join of another device of the same user replaces the first (one voice session per user).
//! [`VoiceState::expire`] removes participants whose grace period ran out.
//!
//! Everything here is pure and synchronous; callers hold the mutex only for one call.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, Instant},
};

use serde::Serialize;

/// A pending participant that LiveKit never reported is dropped after this time.
pub const PENDING_TTL: Duration = Duration::from_secs(60);

/// Default grace period for dropped connections (`TAVRN_VOICE_RECONNECT_GRACE_SECS`).
pub const DEFAULT_RECONNECT_GRACE: Duration = Duration::from_secs(45);

/// Connection state of a visible participant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Connection {
    #[default]
    Connected,
    /// The media connection dropped; the node waits for the device to come back (grace period).
    Reconnecting,
}

/// `(room_id, channel_id)`.
pub type ChannelKey = (String, String);

/// A participant as clients see it in `voice.state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct VoiceParticipant {
    /// User address (`alice@node.example`).
    pub user: String,
    pub user_id: String,
    /// The device id (for users of other nodes: their home device id, the same as in MLS identities).
    pub device_id: String,
    /// LiveKit participant identity and MLS leaf identity: `<user>/<device_id>`.
    pub identity: String,
    /// Microphone muted by the user (or by a moderator, see `server_muted`).
    pub muted: bool,
    /// The user hears nothing (self deafen).
    pub deafened: bool,
    /// Shares a screen or window.
    pub streaming: bool,
    /// Shares the camera.
    pub camera: bool,
    /// Muted by a moderator (`mute_members`); the user cannot unmute and has no microphone grant.
    pub server_muted: bool,
    /// When LiveKit reported the participant (RFC 3339).
    pub joined_at: String,
    /// `connected`, or `reconnecting` while the node waits for a dropped device to come back. Clients treat
    /// unknown values as `connected`.
    pub connection: Connection,
}

#[derive(Debug, Clone)]
struct Entry {
    p: VoiceParticipant,
    /// Reported by LiveKit; `false` = reserved by `voice/join`, not connected yet.
    active: bool,
    since: Instant,
    /// The connection dropped at this time (visible as reconnecting until the grace period ends).
    lost: Option<Instant>,
}

impl Entry {
    fn set_lost(&mut self, lost: Option<Instant>) {
        self.lost = lost;
        self.p.connection = if lost.is_some() { Connection::Reconnecting } else { Connection::Connected };
    }
}

/// What a `voice/join` reservation changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reserved {
    /// Channels whose visible participants changed (the caller publishes `voice.state`).
    pub changed: Vec<ChannelKey>,
    /// Other devices of the same user that were replaced (the caller disconnects them in LiveKit).
    pub displaced: Vec<(ChannelKey, String)>,
}

/// Who a participant is, as resolved by the caller (from the session or the database).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Who {
    pub user: String,
    pub user_id: String,
    pub device_id: String,
    pub server_muted: bool,
}

impl Who {
    pub fn identity(&self) -> String {
        super::identity(&self.user, &self.device_id)
    }
}

/// Changes a client may make to its own state; `None` = unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelfPatch {
    pub muted: Option<bool>,
    pub deafened: Option<bool>,
    pub streaming: Option<bool>,
    pub camera: Option<bool>,
}

/// Published track sources the node tracks (`track_published`/`track_unpublished`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Screen,
    Camera,
}

#[derive(Debug)]
pub struct VoiceState {
    channels: BTreeMap<ChannelKey, Vec<Entry>>,
    grace: Duration,
}

impl Default for VoiceState {
    fn default() -> Self {
        Self::with_grace(DEFAULT_RECONNECT_GRACE)
    }
}

impl VoiceState {
    /// State with a grace period for dropped connections (zero: dropped participants leave at once).
    pub fn with_grace(grace: Duration) -> Self {
        Self { channels: BTreeMap::new(), grace }
    }

    /// The grace period for dropped connections.
    pub fn grace(&self) -> Duration {
        self.grace
    }

    /// Reserves a slot for `who` in `key` (after a successful `voice/join`). The same device is removed from
    /// every other channel first (one voice connection per device), and other devices of the same user are
    /// replaced (one voice session per user).
    pub fn reserve(&mut self, key: &ChannelKey, who: &Who, now: Instant) -> Reserved {
        let identity = who.identity();
        let mut changed = self.remove_identity_except(&identity, key);
        let mut displaced = Vec::new();
        for (k, entries) in self.channels.iter_mut() {
            let mut visible = false;
            entries.retain(|e| {
                let other_device = e.p.user_id == who.user_id && e.p.identity != identity;
                if other_device {
                    displaced.push((k.clone(), e.p.identity.clone()));
                    visible |= e.active;
                }
                !other_device
            });
            if visible && !changed.contains(k) {
                changed.push(k.clone());
            }
        }
        self.channels.retain(|_, v| !v.is_empty());
        let entries = self.channels.entry(key.clone()).or_default();
        match entries.iter_mut().find(|e| e.p.identity == identity) {
            // Rejoin of a connected (or reconnecting) device: keep it visible, refresh the reservation time.
            Some(e) => {
                e.since = now;
                e.p.server_muted = who.server_muted;
            }
            None => entries.push(Entry { p: participant(who, &identity), active: false, since: now, lost: None }),
        }
        Reserved { changed, displaced }
    }

    /// LiveKit reported the participant (`participant_joined` or reconciliation). `who` is needed when no
    /// reservation exists (e.g. a reconnect with a token LiveKit refreshed). Returns `true` if the visible
    /// participants of `key` changed.
    pub fn activate(&mut self, key: &ChannelKey, who: &Who, now: Instant) -> bool {
        let identity = who.identity();
        let entries = self.channels.entry(key.clone()).or_default();
        match entries.iter_mut().find(|e| e.p.identity == identity) {
            // Back within the grace period: the same entry continues (joined_at and flags kept).
            Some(e) if e.active => {
                let back = e.lost.is_some();
                e.set_lost(None);
                back
            }
            Some(e) => {
                e.active = true;
                e.since = now;
                e.p.joined_at = crate::util::now();
                true
            }
            None => {
                let mut p = participant(who, &identity);
                p.joined_at = crate::util::now();
                entries.push(Entry { p, active: true, since: now, lost: None });
                true
            }
        }
    }

    /// The connection of `identity` dropped without the client leaving: it stays visible as reconnecting
    /// until the grace period ends (a zero grace removes it at once). A reservation that never connected
    /// is kept until it expires. Returns `true` if the visible participants changed.
    pub fn lose(&mut self, key: &ChannelKey, identity: &str, now: Instant) -> bool {
        if self.grace.is_zero() {
            return self.remove(key, identity);
        }
        match self.entry_mut(key, identity) {
            Some(e) if e.active && e.lost.is_none() => {
                e.set_lost(Some(now));
                true
            }
            _ => false,
        }
    }

    /// Removes participants whose grace period ran out. Returns the channels whose visible state changed.
    pub fn expire(&mut self, now: Instant) -> Vec<ChannelKey> {
        let grace = self.grace;
        let mut changed = Vec::new();
        for (key, entries) in self.channels.iter_mut() {
            let before = entries.len();
            entries.retain(|e| e.lost.is_none_or(|lost| now.duration_since(lost) < grace));
            if entries.len() != before {
                changed.push(key.clone());
            }
        }
        self.channels.retain(|_, v| !v.is_empty());
        changed
    }

    /// Removes `identity` from `key` (left, removed, disconnected). Returns `true` if it was visible.
    pub fn remove(&mut self, key: &ChannelKey, identity: &str) -> bool {
        let Some(entries) = self.channels.get_mut(key) else { return false };
        let before = entries.iter().find(|e| e.p.identity == identity).map(|e| e.active);
        entries.retain(|e| e.p.identity != identity);
        if entries.is_empty() {
            self.channels.remove(key);
        }
        before.unwrap_or(false)
    }

    /// A screen share or camera track was published (`true`) or unpublished (`false`).
    pub fn set_track(&mut self, key: &ChannelKey, identity: &str, source: Source, published: bool) -> bool {
        let Some(e) = self.entry_mut(key, identity) else { return false };
        let flag = match source {
            Source::Screen => &mut e.p.streaming,
            Source::Camera => &mut e.p.camera,
        };
        let changed = *flag != published;
        *flag = published;
        changed && e.active
    }

    /// Applies a client's own state change. `None` if the device has neither a reservation nor a
    /// connection in `key`. Returns whether the visible state changed.
    pub fn update_self(&mut self, key: &ChannelKey, identity: &str, patch: SelfPatch) -> Option<bool> {
        let e = self.entry_mut(key, identity)?;
        let before = e.p.clone();
        if let Some(m) = patch.muted {
            // A server-muted participant stays muted whatever the client says.
            e.p.muted = m || e.p.server_muted;
        }
        if let Some(d) = patch.deafened {
            e.p.deafened = d;
        }
        if let Some(s) = patch.streaming {
            e.p.streaming = s;
        }
        if let Some(c) = patch.camera {
            e.p.camera = c;
        }
        Some(e.active && e.p != before)
    }

    /// Server mute (or unmute) of every device of `user_id` in the channels of `room_id`. Returns the
    /// identities per channel that are connected or reserved (to update their LiveKit permissions) and
    /// whether anything visible changed.
    pub fn set_server_muted(&mut self, room_id: &str, user_id: &str, muted: bool) -> Vec<(ChannelKey, String, bool)> {
        let mut out = Vec::new();
        for (key, entries) in self.channels.iter_mut().filter(|(k, _)| k.0 == room_id) {
            for e in entries.iter_mut().filter(|e| e.p.user_id == user_id) {
                let changed = e.p.server_muted != muted || (muted && !e.p.muted);
                e.p.server_muted = muted;
                if muted {
                    e.p.muted = true;
                }
                out.push((key.clone(), e.p.identity.clone(), changed && e.active));
            }
        }
        out
    }

    /// Visible (connected) participants of `key`, in join order.
    pub fn participants(&self, key: &ChannelKey) -> Vec<VoiceParticipant> {
        self.channels.get(key).map(|v| v.iter().filter(|e| e.active).map(|e| e.p.clone()).collect()).unwrap_or_default()
    }

    /// Connected (or reconnecting) participants plus valid reservations of other users (user limit check;
    /// the joining user's own devices are replaced, so they do not count).
    pub fn occupancy(&self, key: &ChannelKey, except_user_id: &str, now: Instant) -> usize {
        self.channels
            .get(key)
            .map(|v| {
                v.iter()
                    .filter(|e| e.p.user_id != except_user_id)
                    .filter(|e| e.active || now.duration_since(e.since) < PENDING_TTL)
                    .count()
            })
            .unwrap_or(0)
    }

    /// The device's participant in `key` (connected or reserved).
    pub fn get(&self, key: &ChannelKey, identity: &str) -> Option<VoiceParticipant> {
        self.channels.get(key)?.iter().find(|e| e.p.identity == identity).map(|e| e.p.clone())
    }

    /// Users with an entry in `key` (connected, reconnecting or reserved), each once.
    pub fn users_in(&self, key: &ChannelKey) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in self.channels.get(key).into_iter().flatten() {
            if !out.contains(&e.p.user_id) {
                out.push(e.p.user_id.clone());
            }
        }
        out
    }

    /// Every identity in `key`: connected, reconnecting or reserved.
    pub fn identities_in(&self, key: &ChannelKey) -> Vec<String> {
        self.channels.get(key).map(|v| v.iter().map(|e| e.p.identity.clone()).collect()).unwrap_or_default()
    }

    /// Visible participants of every channel, by key (the reconciliation of calls).
    pub fn keys(&self) -> Vec<ChannelKey> {
        self.channels.keys().cloned().collect()
    }

    /// Identities of `user_id` in `key` (connected or reserved).
    pub fn identities_of(&self, key: &ChannelKey, user_id: &str) -> Vec<String> {
        self.channels
            .get(key)
            .map(|v| v.iter().filter(|e| e.p.user_id == user_id).map(|e| e.p.identity.clone()).collect())
            .unwrap_or_default()
    }

    /// Removes every device of `user_id` from the channels of `room_id` (kick, ban, leave, timeout).
    /// Returns the removed identities per channel and whether the channel's visible state changed.
    pub fn remove_user(&mut self, room_id: &str, user_id: &str) -> Vec<(ChannelKey, Vec<String>, bool)> {
        let mut out = Vec::new();
        for (key, entries) in self.channels.iter_mut().filter(|(k, _)| k.0 == room_id) {
            let removed: Vec<&Entry> = entries.iter().filter(|e| e.p.user_id == user_id).collect();
            if removed.is_empty() {
                continue;
            }
            let visible = removed.iter().any(|e| e.active);
            out.push((key.clone(), removed.iter().map(|e| e.p.identity.clone()).collect(), visible));
            entries.retain(|e| e.p.user_id != user_id);
        }
        self.channels.retain(|_, v| !v.is_empty());
        out
    }

    /// Forgets a channel (deleted) and returns the identities that were in it.
    pub fn remove_channel(&mut self, key: &ChannelKey) -> Vec<String> {
        self.channels.remove(key).map(|v| v.into_iter().map(|e| e.p.identity).collect()).unwrap_or_default()
    }

    /// Forgets all channels of a room (deleted).
    pub fn remove_room(&mut self, room_id: &str) -> Vec<ChannelKey> {
        let keys: Vec<ChannelKey> = self.channels.keys().filter(|k| k.0 == room_id).cloned().collect();
        for k in &keys {
            self.channels.remove(k);
        }
        keys
    }

    /// Channels of `room_id` with at least one connected participant.
    pub fn active_channels(&self, room_id: &str) -> Vec<ChannelKey> {
        self.channels
            .iter()
            .filter(|(k, v)| k.0 == room_id && v.iter().any(|e| e.active))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Compares with what LiveKit reports (`truth`: channel → identities present in LiveKit, for every
    /// room LiveKit knows). Connected participants missing in LiveKit become reconnecting (and are removed
    /// once their grace period ran out, so crashes and lost webhooks leave no ghosts), expired reservations
    /// are dropped, reservations LiveKit knows become connected, reconnecting participants LiveKit knows
    /// again are connected. Returns the channels whose visible state changed and the identities LiveKit
    /// knows but this state does not (the caller resolves and [`activate`](Self::activate)s them).
    pub fn reconcile(
        &mut self,
        truth: &HashMap<ChannelKey, HashSet<String>>,
        now: Instant,
    ) -> (Vec<ChannelKey>, Vec<(ChannelKey, String)>) {
        let empty = HashSet::new();
        let grace = self.grace;
        let mut changed = Vec::new();
        for (key, entries) in self.channels.iter_mut() {
            let present = truth.get(key).unwrap_or(&empty);
            let mut visible_change = false;
            entries.retain(|e| {
                let keep = present.contains(&e.p.identity)
                    || (!e.active && now.duration_since(e.since) < PENDING_TTL)
                    || (e.active && !grace.is_zero() && e.lost.is_none_or(|lost| now.duration_since(lost) < grace));
                if !keep && e.active {
                    visible_change = true;
                }
                keep
            });
            for e in entries.iter_mut() {
                let here = present.contains(&e.p.identity);
                if !e.active && here {
                    e.active = true;
                    e.p.joined_at = crate::util::now();
                    visible_change = true;
                } else if e.active && here && e.lost.is_some() {
                    e.set_lost(None);
                    visible_change = true;
                } else if e.active && !here && e.lost.is_none() {
                    e.set_lost(Some(now));
                    visible_change = true;
                }
            }
            if visible_change {
                changed.push(key.clone());
            }
        }
        self.channels.retain(|_, v| !v.is_empty());
        let mut unknown = Vec::new();
        for (key, identities) in truth {
            for identity in identities {
                let known = self.channels.get(key).is_some_and(|v| v.iter().any(|e| &e.p.identity == identity));
                if !known {
                    unknown.push((key.clone(), identity.clone()));
                }
            }
        }
        (changed, unknown)
    }

    fn entry_mut(&mut self, key: &ChannelKey, identity: &str) -> Option<&mut Entry> {
        self.channels.get_mut(key)?.iter_mut().find(|e| e.p.identity == identity)
    }

    /// Removes `identity` from every channel except `keep`; returns channels whose visible state changed.
    fn remove_identity_except(&mut self, identity: &str, keep: &ChannelKey) -> Vec<ChannelKey> {
        let keys: Vec<ChannelKey> = self
            .channels
            .iter()
            .filter(|(k, v)| *k != keep && v.iter().any(|e| e.p.identity == identity))
            .map(|(k, _)| k.clone())
            .collect();
        keys.into_iter().filter(|k| self.remove(k, identity)).collect()
    }
}

fn participant(who: &Who, identity: &str) -> VoiceParticipant {
    VoiceParticipant {
        user: who.user.clone(),
        user_id: who.user_id.clone(),
        device_id: who.device_id.clone(),
        identity: identity.to_string(),
        muted: who.server_muted,
        deafened: false,
        streaming: false,
        camera: false,
        server_muted: who.server_muted,
        joined_at: String::new(),
        connection: Connection::Connected,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const DEV_A: &str = "01J00000000000000000000001";
    const DEV_B: &str = "01J00000000000000000000002";

    fn key(c: &str) -> ChannelKey {
        ("room".into(), c.into())
    }

    fn who(user: &str, device: &str) -> Who {
        Who {
            user: format!("{user}@node.example"),
            user_id: format!("id-{user}"),
            device_id: device.into(),
            server_muted: false,
        }
    }

    fn id(user: &str, device: &str) -> String {
        who(user, device).identity()
    }

    #[test]
    fn reservations_are_invisible_until_livekit_reports_them() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        assert_eq!(s.reserve(&key("c1"), &who("alice", DEV_A), now), Reserved::default());
        assert!(s.participants(&key("c1")).is_empty(), "pending participants are not shown");
        assert_eq!(s.occupancy(&key("c1"), "other", now), 1, "but they count for the user limit");
        assert!(s.activate(&key("c1"), &who("alice", DEV_A), now));
        assert!(!s.activate(&key("c1"), &who("alice", DEV_A), now), "a second join report changes nothing");
        let ps = s.participants(&key("c1"));
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].identity, "alice@node.example/01J00000000000000000000001");
        assert!(!ps[0].joined_at.is_empty());
        assert!(s.remove(&key("c1"), &id("alice", DEV_A)));
        assert!(s.participants(&key("c1")).is_empty());
        assert!(!s.remove(&key("c1"), &id("alice", DEV_A)), "removing twice is a no-op");
    }

    #[test]
    fn activation_without_reservation_creates_the_participant() {
        let mut s = VoiceState::default();
        assert!(s.activate(&key("c1"), &who("bob", DEV_B), Instant::now()));
        assert_eq!(s.participants(&key("c1"))[0].user, "bob@node.example");
    }

    #[test]
    fn one_connection_per_device_and_occupancy_excludes_the_joining_user() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        s.reserve(&key("c1"), &who("alice", DEV_A), now);
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        s.reserve(&key("c1"), &who("bob", DEV_B), now);
        assert_eq!(s.occupancy(&key("c1"), "id-alice", now), 1, "the joining user's own devices are not counted");
        assert_eq!(s.occupancy(&key("c1"), "id-carol", now), 2);
        let r = s.reserve(&key("c2"), &who("alice", DEV_A), now);
        assert_eq!(r.changed, vec![key("c1")], "joining another channel leaves the old one");
        assert!(r.displaced.is_empty(), "the same device is moved, not displaced");
        assert!(s.participants(&key("c1")).is_empty());
        assert_eq!(s.identities_of(&key("c1"), "id-bob"), vec![id("bob", DEV_B)]);
        let later = now + PENDING_TTL + Duration::from_secs(1);
        assert_eq!(s.occupancy(&key("c1"), "x", later), 0, "expired reservations do not count");
    }

    #[test]
    fn another_device_of_the_same_user_replaces_the_first() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        s.activate(&key("c1"), &who("bob", DEV_A), now);
        let r = s.reserve(&key("c2"), &who("alice", DEV_B), now);
        assert_eq!(r.displaced, vec![(key("c1"), id("alice", DEV_A))], "the old device is told to disconnect");
        assert_eq!(r.changed, vec![key("c1")]);
        let users: Vec<String> = s.participants(&key("c1")).into_iter().map(|p| p.user).collect();
        assert_eq!(users, vec!["bob@node.example"]);
        s.activate(&key("c2"), &who("alice", DEV_B), now);
        // Alice is listed once, with the new device.
        let all: Vec<String> =
            [key("c1"), key("c2")].iter().flat_map(|k| s.participants(k)).map(|p| p.identity).collect();
        assert_eq!(all.iter().filter(|i| i.starts_with("alice@")).count(), 1);
        assert!(all.contains(&id("alice", DEV_B)));
    }

    #[test]
    fn dropped_connections_reconnect_within_the_grace_period_without_duplicates() {
        let mut s = VoiceState::with_grace(Duration::from_secs(45));
        let t0 = Instant::now();
        s.reserve(&key("c1"), &who("alice", DEV_A), t0);
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        s.update_self(&key("c1"), &id("alice", DEV_A), SelfPatch { muted: Some(true), ..Default::default() });
        let joined_at = s.participants(&key("c1"))[0].joined_at.clone();
        assert!(s.lose(&key("c1"), &id("alice", DEV_A), t0));
        assert!(!s.lose(&key("c1"), &id("alice", DEV_A), t0), "losing twice changes nothing");
        let p = &s.participants(&key("c1"))[0];
        assert_eq!(p.connection, Connection::Reconnecting, "still listed, as reconnecting");
        assert_eq!(s.occupancy(&key("c1"), "x", t0), 1, "the seat is kept during the grace period");
        assert!(s.expire(t0 + Duration::from_secs(44)).is_empty());
        // The client rejoins with a new token: same identity, same entry.
        let r = s.reserve(&key("c1"), &who("alice", DEV_A), t0 + Duration::from_secs(10));
        assert!(r.changed.is_empty() && r.displaced.is_empty());
        assert_eq!(s.participants(&key("c1")).len(), 1, "never twice");
        assert!(s.activate(&key("c1"), &who("alice", DEV_A), t0 + Duration::from_secs(11)));
        let p = &s.participants(&key("c1"))[0];
        assert_eq!(p.connection, Connection::Connected);
        assert!(p.muted, "the state survives the reconnect");
        assert_eq!(p.joined_at, joined_at);
        assert!(!s.activate(&key("c1"), &who("alice", DEV_A), t0), "already connected");
    }

    #[test]
    fn the_grace_period_ends_with_a_removal() {
        let mut s = VoiceState::with_grace(Duration::from_secs(5));
        let t0 = Instant::now();
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        s.activate(&key("c1"), &who("bob", DEV_A), t0);
        // A reservation that never connected is not "lost": it simply expires later.
        s.reserve(&key("c1"), &who("carol", DEV_A), t0);
        assert!(!s.lose(&key("c1"), &id("carol", DEV_A), t0));
        s.lose(&key("c1"), &id("alice", DEV_A), t0);
        assert!(s.expire(t0 + Duration::from_secs(4)).is_empty());
        assert_eq!(s.expire(t0 + Duration::from_secs(5)), vec![key("c1")]);
        let users: Vec<String> = s.participants(&key("c1")).into_iter().map(|p| p.user).collect();
        assert_eq!(users, vec!["bob@node.example"]);
        // Without a grace period a drop removes the participant at once.
        let mut s = VoiceState::with_grace(Duration::ZERO);
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        assert!(s.lose(&key("c1"), &id("alice", DEV_A), t0));
        assert!(s.participants(&key("c1")).is_empty());
    }

    #[test]
    fn self_state_and_tracks() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        let alice = id("alice", DEV_A);
        assert_eq!(s.update_self(&key("c1"), &alice, SelfPatch::default()), None);
        s.reserve(&key("c1"), &who("alice", DEV_A), now);
        // Early state before LiveKit reports the participant is kept but not visible.
        assert_eq!(
            s.update_self(&key("c1"), &alice, SelfPatch { muted: Some(true), ..Default::default() }),
            Some(false)
        );
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        assert!(s.participants(&key("c1"))[0].muted, "the early mute survived the activation");
        let patch = SelfPatch { deafened: Some(true), streaming: Some(true), ..Default::default() };
        assert_eq!(s.update_self(&key("c1"), &alice, patch), Some(true));
        assert_eq!(s.update_self(&key("c1"), &alice, patch), Some(false), "same state again is no change");
        assert!(s.set_track(&key("c1"), &alice, Source::Camera, true));
        assert!(!s.set_track(&key("c1"), &alice, Source::Camera, true));
        assert!(s.set_track(&key("c1"), &alice, Source::Screen, false));
        let p = &s.participants(&key("c1"))[0];
        assert!(p.muted && p.deafened && p.camera && !p.streaming);
        assert!(!s.set_track(&key("c1"), "nobody/x", Source::Camera, true));
    }

    #[test]
    fn server_mute_wins_over_the_client() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        let alice = id("alice", DEV_A);
        s.reserve(&key("c1"), &who("alice", DEV_A), now);
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        let out = s.set_server_muted("room", "id-alice", true);
        assert_eq!(out, vec![(key("c1"), alice.clone(), true)]);
        assert_eq!(
            s.update_self(&key("c1"), &alice, SelfPatch { muted: Some(false), ..Default::default() }),
            Some(false)
        );
        let p = &s.participants(&key("c1"))[0];
        assert!(p.muted && p.server_muted);
        let out = s.set_server_muted("room", "id-alice", false);
        assert_eq!(out, vec![(key("c1"), alice.clone(), true)]);
        assert!(s.participants(&key("c1"))[0].muted, "unmuting by a moderator leaves the self mute to the user");
        assert!(s.set_server_muted("other-room", "id-alice", true).is_empty());
        // A reservation of a server-muted user starts muted.
        let mut muted = who("bob", DEV_B);
        muted.server_muted = true;
        s.reserve(&key("c1"), &muted, now);
        assert!(s.get(&key("c1"), &id("bob", DEV_B)).unwrap().muted);
    }

    #[test]
    fn removing_users_channels_and_rooms() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        s.activate(&key("c2"), &who("alice", DEV_B), now);
        s.activate(&key("c2"), &who("bob", DEV_A), now);
        let removed = s.remove_user("room", "id-alice");
        assert_eq!(
            removed,
            vec![(key("c1"), vec![id("alice", DEV_A)], true), (key("c2"), vec![id("alice", DEV_B)], true)]
        );
        assert_eq!(s.active_channels("room"), vec![key("c2")]);
        assert_eq!(s.remove_channel(&key("c2")), vec![id("bob", DEV_A)]);
        s.activate(&key("c3"), &who("bob", DEV_A), now);
        assert_eq!(s.remove_room("room"), vec![key("c3")]);
        assert!(s.active_channels("room").is_empty());
    }

    #[test]
    fn reconciliation_turns_missing_participants_into_reconnecting_ones_and_finds_unknown_ones() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        s.activate(&key("c1"), &who("ghost", DEV_A), now);
        s.reserve(&key("c1"), &who("pending", DEV_A), now);
        s.reserve(&key("c1"), &who("joined", DEV_A), now);
        s.activate(&key("c2"), &who("real", DEV_A), now);
        let truth: HashMap<ChannelKey, HashSet<String>> = [
            (key("c1"), [id("joined", DEV_A), id("stranger", DEV_B)].into_iter().collect()),
            (key("c2"), [id("real", DEV_A)].into_iter().collect()),
        ]
        .into_iter()
        .collect();
        let (changed, unknown) = s.reconcile(&truth, now);
        assert_eq!(changed, vec![key("c1")]);
        assert_eq!(unknown, vec![(key("c1"), id("stranger", DEV_B))]);
        let state: Vec<(String, Connection)> =
            s.participants(&key("c1")).into_iter().map(|p| (p.user, p.connection)).collect();
        assert_eq!(
            state,
            vec![
                ("ghost@node.example".to_string(), Connection::Reconnecting),
                ("joined@node.example".to_string(), Connection::Connected)
            ],
            "a missing participant gets the grace period, the reservation became visible"
        );
        assert_eq!(s.occupancy(&key("c1"), "x", now), 3, "the young reservation and the reconnecting seat are kept");
        // The ghost comes back within the grace period.
        let back: HashMap<ChannelKey, HashSet<String>> =
            [(key("c1"), [id("joined", DEV_A), id("ghost", DEV_A)].into_iter().collect())].into_iter().collect();
        let (changed, _) = s.reconcile(&back, now + Duration::from_secs(5));
        assert!(changed.contains(&key("c1")));
        assert!(s.participants(&key("c1")).iter().all(|p| p.connection == Connection::Connected));
        // Gone again; later the reservation expired without LiveKit ever seeing it and the grace ran out.
        s.reconcile(&truth, now + Duration::from_secs(10));
        let (changed, _) = s.reconcile(&truth, now + PENDING_TTL + Duration::from_secs(10));
        assert_eq!(changed, vec![key("c1")], "the ghost is removed after its grace period");
        let users: Vec<String> = s.participants(&key("c1")).into_iter().map(|p| p.user).collect();
        assert_eq!(users, vec!["joined@node.example"]);
        assert_eq!(s.occupancy(&key("c1"), "x", now), 1);
        // LiveKit lost everything (crash): everybody is reconnecting, then gone after the grace period.
        let (changed, _) = s.reconcile(&HashMap::new(), now);
        assert_eq!(changed, vec![key("c1"), key("c2")]);
        assert_eq!(s.active_channels("room").len(), 2);
        let (changed, _) = s.reconcile(&HashMap::new(), now + DEFAULT_RECONNECT_GRACE);
        assert_eq!(changed, vec![key("c1"), key("c2")]);
        assert!(s.active_channels("room").is_empty());
    }
}
