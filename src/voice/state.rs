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
//! A moderator's move ([`VoiceState::grant_move`]) leaves a single-use *move grant* for the moved user and the
//! target channel ([`MOVE_GRANT_TTL`]); it entitles the user's next join of that channel even without `connect`
//! ([`VoiceState::move_entitles`]). The first join consumes it and turns it into a *moved participation*, which
//! lasts as long as the user has an entry in that channel (a rejoin within the grace period keeps it); joining
//! another channel, leaving or being removed ends it. While a grant or moved participation exists the user counts
//! as a viewer of the channel ([`VoiceState::moved`], `voice::moved`), and the participant is shown with
//! `moved: true`.
//!
//! A device may add one *screen publisher* (VOICE.md §4b, [`VoiceState::reserve_screen`]): a second participant
//! `<identity>#screen` that only publishes the device's screen share. It is listed right after its owner with
//! `screen_of`, takes no seat ([`VoiceState::occupancy`]) and ends with its owner: every removal of the owner removes
//! it too, and one left behind by an expiry or a reconciliation is collected for the caller to remove from LiveKit
//! ([`VoiceState::take_orphans`]).
//!
//! The **session start** of a channel ([`VoiceState::session_started_at`], VOICE.md §5) is the time the first
//! participant connected to it while it was empty; it stays while anybody is connected or reconnecting, whoever
//! that is, and goes with the last participant. It lives here with the participants: a node restart restarts
//! LiveKit and drops every participant, so there is nothing to persist.
//!
//! Everything here is pure and synchronous; callers hold the mutex only for one call.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::{Duration, Instant},
};

use serde::Serialize;

/// A pending participant that LiveKit never reported is dropped after this time.
pub const PENDING_TTL: Duration = Duration::from_secs(60);

/// How long a move grant waits for the moved user's join.
pub const MOVE_GRANT_TTL: Duration = Duration::from_secs(60);

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
    /// A moderator moved the user here (`VOICE.md` §7): they may be here without `view_channel` or `connect` for as
    /// long as this participation lasts. Clients may show "moved here". Always `false` in calls; absent from older
    /// nodes (= `false`).
    #[schema(required = false)]
    pub moved: bool,
    /// Set only for a device's screen publisher (VOICE.md §4b): the identity of the device it belongs to. Clients
    /// show it as that participant's stream, not as a participant of its own. Absent for devices.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub screen_of: Option<String>,
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
    /// The device's screen publisher (VOICE.md §4b), not the device itself.
    pub screen: bool,
}

impl Who {
    pub fn identity(&self) -> String {
        let device = super::identity(&self.user, &self.device_id);
        if self.screen { super::screen_identity(&device) } else { device }
    }

    /// The device's own identity (the owner of a screen publisher).
    pub fn device_identity(&self) -> String {
        super::identity(&self.user, &self.device_id)
    }
}

/// Why a screen publisher was refused (VOICE.md §4b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenRefusal {
    /// The device has no participant in the channel.
    NoOwner,
    /// The device already has a screen publisher (connected, reconnecting or freshly reserved).
    Active,
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

/// A user's move into a channel: a grant until the first join, then the moved participation.
#[derive(Debug, Clone)]
struct Move {
    key: ChannelKey,
    /// The grant is open until then; `None` once a join consumed it.
    grant_until: Option<Instant>,
}

#[derive(Debug)]
pub struct VoiceState {
    channels: BTreeMap<ChannelKey, Vec<Entry>>,
    grace: Duration,
    /// Per user id: the user's move (one per user, a new move replaces it).
    moves: HashMap<String, Move>,
    /// Screen publishers whose owner went away in an expiry or a reconciliation, still to be removed from LiveKit.
    orphans: Vec<(ChannelKey, String)>,
    /// Per channel: when the current session began (RFC 3339), set with the first visible participant. Read through
    /// [`Self::session_started_at`], which ignores entries of channels that are empty again; those are dropped in
    /// [`Self::expire`].
    sessions: BTreeMap<ChannelKey, String>,
}

impl Default for VoiceState {
    fn default() -> Self {
        Self::with_grace(DEFAULT_RECONNECT_GRACE)
    }
}

impl VoiceState {
    /// State with a grace period for dropped connections (zero: dropped participants leave at once).
    pub fn with_grace(grace: Duration) -> Self {
        Self { channels: BTreeMap::new(), grace, moves: HashMap::new(), orphans: Vec::new(), sessions: BTreeMap::new() }
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
        let mut displaced = Vec::new();
        // The device's screen publishers elsewhere go with it (the device itself disconnects there by itself).
        let screen = super::screen_identity(&identity);
        for (k, entries) in &self.channels {
            if k != key && entries.iter().any(|e| e.p.identity == screen) {
                displaced.push((k.clone(), screen.clone()));
            }
        }
        let mut changed = self.remove_identity_except(&identity, key);
        for (k, entries) in self.channels.iter_mut() {
            let mut visible = false;
            entries.retain(|e| {
                let other_device = e.p.user_id == who.user_id && owner_of(&e.p) != identity;
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

    /// Reserves the screen publisher of `who`'s device in `key` (VOICE.md §4b; `who.screen` is set by the caller):
    /// the device must have a participant there, and no other screen publisher (connected, reconnecting or reserved
    /// within [`PENDING_TTL`]). A stale reservation is replaced.
    pub fn reserve_screen(&mut self, key: &ChannelKey, who: &Who, now: Instant) -> Result<(), ScreenRefusal> {
        let owner = who.device_identity();
        let identity = super::screen_identity(&owner);
        let entries = self.channels.get_mut(key).ok_or(ScreenRefusal::NoOwner)?;
        if !entries.iter().any(|e| e.p.identity == owner) {
            return Err(ScreenRefusal::NoOwner);
        }
        if let Some(e) = entries.iter().find(|e| e.p.identity == identity) {
            if e.active || now.duration_since(e.since) < PENDING_TTL {
                return Err(ScreenRefusal::Active);
            }
            entries.retain(|e| e.p.identity != identity);
        }
        let screen = Who { screen: true, ..who.clone() };
        place(entries, Entry { p: participant(&screen, &identity), active: false, since: now, lost: None });
        Ok(())
    }

    /// Whether `who` may be a participant of `key`: always for a device, for a screen publisher only while its
    /// device has a participant there (the caller removes a refused one from LiveKit).
    pub fn accepts(&self, key: &ChannelKey, who: &Who) -> bool {
        !who.screen || self.get(key, &who.device_identity()).is_some()
    }

    /// Screen publishers whose device went away (expiry, reconciliation), for the caller to remove from LiveKit.
    pub fn take_orphans(&mut self) -> Vec<(ChannelKey, String)> {
        std::mem::take(&mut self.orphans)
    }

    /// LiveKit reported the participant (`participant_joined` or reconciliation). `who` is needed when no
    /// reservation exists (e.g. a reconnect with a token LiveKit refreshed). Returns `true` if the visible
    /// participants of `key` changed.
    pub fn activate(&mut self, key: &ChannelKey, who: &Who, now: Instant) -> bool {
        let identity = who.identity();
        let entries = self.channels.entry(key.clone()).or_default();
        if !entries.iter().any(|e| e.active) {
            // The first participant of an empty channel starts its session (VOICE.md §5).
            self.sessions.insert(key.clone(), crate::util::now());
        }
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
                if who.screen && !entries.iter().any(|e| e.p.identity == who.device_identity()) {
                    return false;
                }
                let mut p = participant(who, &identity);
                p.joined_at = crate::util::now();
                place(entries, Entry { p, active: true, since: now, lost: None });
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
            drop_orphans(key, entries, &mut self.orphans);
            if entries.len() != before {
                changed.push(key.clone());
            }
        }
        self.channels.retain(|_, v| !v.is_empty());
        let channels = &self.channels;
        self.sessions.retain(|key, _| channels.get(key).is_some_and(|v| v.iter().any(|e| e.active)));
        changed
    }

    /// When the current session of `key` began (VOICE.md §5): the time the first participant connected to the
    /// empty channel, as long as anybody is connected or reconnecting there; `None` for an empty channel.
    pub fn session_started_at(&self, key: &ChannelKey) -> Option<String> {
        let busy = self.channels.get(key).is_some_and(|v| v.iter().any(|e| e.active));
        if busy { self.sessions.get(key).cloned() } else { None }
    }

    /// Removes `identity` from `key` (left, removed, disconnected), a device with its screen publisher. Returns
    /// `true` if anything visible went.
    pub fn remove(&mut self, key: &ChannelKey, identity: &str) -> bool {
        let Some(entries) = self.channels.get_mut(key) else { return false };
        let gone = |e: &Entry| e.p.identity == identity || e.p.screen_of.as_deref() == Some(identity);
        let visible = entries.iter().any(|e| gone(e) && e.active);
        entries.retain(|e| !gone(e));
        if entries.is_empty() {
            self.channels.remove(key);
        }
        visible
    }

    /// A screen share or camera track was published (`true`) or unpublished (`false`). A screen publisher's screen
    /// share also makes its owner stream.
    pub fn set_track(&mut self, key: &ChannelKey, identity: &str, source: Source, published: bool) -> bool {
        let Some(e) = self.entry_mut(key, identity) else { return false };
        let flag = match source {
            Source::Screen => &mut e.p.streaming,
            Source::Camera => &mut e.p.camera,
        };
        let mut changed = *flag != published && e.active;
        *flag = published;
        if let (Source::Screen, Some(owner)) = (source, e.p.screen_of.clone())
            && let Some(o) = self.entry_mut(key, &owner)
        {
            changed |= o.p.streaming != published && o.active;
            o.p.streaming = published;
        }
        changed
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
            // Screen publishers keep their grants (a server mute takes the microphone only, VOICE.md §4b).
            for e in entries.iter_mut().filter(|e| e.p.user_id == user_id && e.p.screen_of.is_none()) {
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
        self.channels
            .get(key)
            .map(|v| v.iter().filter(|e| e.active).map(|e| self.shown(key, e)).collect())
            .unwrap_or_default()
    }

    /// The participant as clients see it (with the `moved` mark).
    fn shown(&self, key: &ChannelKey, e: &Entry) -> VoiceParticipant {
        let mut p = e.p.clone();
        p.moved = self.moves.get(&p.user_id).is_some_and(|m| m.key == *key);
        p
    }

    /// Connected (or reconnecting) participants plus valid reservations of other users (user limit check;
    /// the joining user's own devices are replaced, so they do not count).
    pub fn occupancy(&self, key: &ChannelKey, except_user_id: &str, now: Instant) -> usize {
        self.channels
            .get(key)
            .map(|v| {
                v.iter()
                    .filter(|e| e.p.user_id != except_user_id && e.p.screen_of.is_none())
                    .filter(|e| e.active || now.duration_since(e.since) < PENDING_TTL)
                    .count()
            })
            .unwrap_or(0)
    }

    /// The device's participant in `key` (connected or reserved).
    pub fn get(&self, key: &ChannelKey, identity: &str) -> Option<VoiceParticipant> {
        self.channels.get(key)?.iter().find(|e| e.p.identity == identity).map(|e| self.shown(key, e))
    }

    /// A moderator moved `user_id` into `key`: a grant for the user's next join there (replaces any earlier move of
    /// the user).
    pub fn grant_move(&mut self, key: &ChannelKey, user_id: &str, now: Instant) {
        self.moves.insert(user_id.to_string(), Move { key: key.clone(), grant_until: Some(now + MOVE_GRANT_TTL) });
    }

    /// Does a move entitle `user_id` to join `key` (without `connect`)? An open grant, or the running moved
    /// participation (a rejoin after a dropped connection).
    pub fn move_entitles(&self, key: &ChannelKey, user_id: &str, now: Instant) -> bool {
        self.moves.get(user_id).is_some_and(|m| m.key == *key && self.move_lasts(user_id, m, now))
    }

    /// After a successful join of `user_id` to `key`: a grant for `key` is consumed (the moved participation goes on
    /// while the user is there); a move into another channel ends.
    pub fn joined(&mut self, key: &ChannelKey, user_id: &str) {
        match self.moves.get_mut(user_id) {
            Some(m) if m.key == *key => m.grant_until = None,
            Some(_) => {
                self.moves.remove(user_id);
            }
            None => {}
        }
    }

    /// The current moves per room (room id → user id → channel id), after dropping those that ended (grant expired
    /// or consumed and the user no longer in the channel).
    pub fn moved(&mut self, now: Instant) -> BTreeMap<String, BTreeMap<String, String>> {
        let ended: Vec<String> =
            self.moves.iter().filter(|(u, m)| !self.move_lasts(u, m, now)).map(|(u, _)| u.clone()).collect();
        for user_id in ended {
            self.moves.remove(&user_id);
        }
        let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for (user_id, m) in &self.moves {
            out.entry(m.key.0.clone()).or_default().insert(user_id.clone(), m.key.1.clone());
        }
        out
    }

    fn move_lasts(&self, user_id: &str, m: &Move, now: Instant) -> bool {
        m.grant_until.is_some_and(|until| now < until)
            || self.channels.get(&m.key).is_some_and(|v| v.iter().any(|e| e.p.user_id == user_id))
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
        let mut started = Vec::new();
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
            visible_change |= drop_orphans(key, entries, &mut self.orphans);
            let was_empty = !entries.iter().any(|e| e.active);
            for e in entries.iter_mut() {
                let here = present.contains(&e.p.identity);
                if !e.active && here {
                    if was_empty {
                        started.push(key.clone());
                    }
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
        for key in started {
            // A reservation LiveKit knows connected an empty channel: its session begins now (a channel that was
            // connected before keeps its start; `session_started_at` hides entries of channels that emptied).
            self.sessions.insert(key, crate::util::now());
        }
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

/// The device a participant belongs to: its own identity, or a screen publisher's owner.
fn owner_of(p: &VoiceParticipant) -> &str {
    p.screen_of.as_deref().unwrap_or(&p.identity)
}

/// Adds an entry: a screen publisher right after its owner (and the owner's earlier screen), anything else last.
fn place(entries: &mut Vec<Entry>, entry: Entry) {
    let at = entry.p.screen_of.as_deref().and_then(|owner| entries.iter().rposition(|e| owner_of(&e.p) == owner));
    match at {
        Some(i) => entries.insert(i + 1, entry),
        None => entries.push(entry),
    }
}

/// Drops the screen publishers of `entries` whose device has no entry any more; collects them in `orphans`.
/// Returns whether a visible one went.
fn drop_orphans(key: &ChannelKey, entries: &mut Vec<Entry>, orphans: &mut Vec<(ChannelKey, String)>) -> bool {
    let owners: HashSet<String> =
        entries.iter().filter(|e| e.p.screen_of.is_none()).map(|e| e.p.identity.clone()).collect();
    let mut visible = false;
    entries.retain(|e| match &e.p.screen_of {
        Some(owner) if !owners.contains(owner) => {
            orphans.push((key.clone(), e.p.identity.clone()));
            visible |= e.active;
            false
        }
        _ => true,
    });
    visible
}

fn participant(who: &Who, identity: &str) -> VoiceParticipant {
    VoiceParticipant {
        user: who.user.clone(),
        user_id: who.user_id.clone(),
        device_id: who.device_id.clone(),
        identity: identity.to_string(),
        // A screen publisher has no microphone (VOICE.md §4b).
        muted: who.server_muted || who.screen,
        deafened: false,
        streaming: false,
        camera: false,
        server_muted: who.server_muted,
        joined_at: String::new(),
        connection: Connection::Connected,
        moved: false,
        screen_of: who.screen.then(|| who.device_identity()),
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
            screen: false,
        }
    }

    fn screen(user: &str, device: &str) -> Who {
        Who { screen: true, ..who(user, device) }
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
    fn the_session_start_is_set_by_the_first_participant_and_cleared_with_the_last() {
        let mut s = VoiceState::with_grace(Duration::from_secs(1));
        let now = Instant::now();
        assert_eq!(s.session_started_at(&key("c1")), None, "an empty channel has no session");
        s.reserve(&key("c1"), &who("alice", DEV_A), now);
        assert_eq!(s.session_started_at(&key("c1")), None, "a reservation alone starts nothing");
        s.activate(&key("c1"), &who("alice", DEV_A), now);
        let started = s.session_started_at(&key("c1")).unwrap();
        assert!(!started.is_empty());
        // Bob joins later, Alice leaves: the session keeps its start (it is the channel's, not the first joiner's).
        s.activate(&key("c1"), &who("bob", DEV_B), now);
        assert_eq!(s.session_started_at(&key("c1")).as_deref(), Some(started.as_str()));
        assert!(s.remove(&key("c1"), &id("alice", DEV_A)));
        assert_eq!(s.session_started_at(&key("c1")).as_deref(), Some(started.as_str()), "kept while anybody is in");
        // A dropped connection keeps the session during the grace period and ends it with the expiry.
        assert!(s.lose(&key("c1"), &id("bob", DEV_B), now));
        assert_eq!(s.session_started_at(&key("c1")).as_deref(), Some(started.as_str()), "reconnecting counts");
        assert_eq!(s.expire(now + Duration::from_secs(2)), vec![key("c1")]);
        assert_eq!(s.session_started_at(&key("c1")), None, "cleared with the last participant");
        assert!(s.sessions.is_empty(), "the expiry drops the entry of an empty channel");
        // The next session gets a start of its own; another channel is independent.
        s.activate(&key("c1"), &who("bob", DEV_B), now);
        assert!(s.session_started_at(&key("c1")).is_some());
        assert_eq!(s.session_started_at(&key("c2")), None);
    }

    #[test]
    fn the_reconciliation_starts_a_session_for_a_reservation_livekit_knows() {
        let mut s = VoiceState::default();
        let now = Instant::now();
        s.reserve(&key("c1"), &who("alice", DEV_A), now);
        let truth = HashMap::from([(key("c1"), HashSet::from([id("alice", DEV_A)]))]);
        let (changed, unknown) = s.reconcile(&truth, now);
        assert_eq!((changed, unknown.len()), (vec![key("c1")], 0));
        assert!(s.session_started_at(&key("c1")).is_some(), "connected through the reconciliation");
        // A channel that empties and comes back through the reconciliation again starts anew.
        assert!(s.remove(&key("c1"), &id("alice", DEV_A)));
        assert_eq!(s.session_started_at(&key("c1")), None);
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
    fn move_grants_are_bound_to_user_and_channel_and_expire() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        s.grant_move(&key("c2"), "id-bob", t0);
        assert!(s.move_entitles(&key("c2"), "id-bob", t0));
        assert!(!s.move_entitles(&key("c1"), "id-bob", t0), "only for its channel");
        assert!(!s.move_entitles(&key("c2"), "id-carol", t0), "only for its user");
        let moved = BTreeMap::from([("room".to_string(), BTreeMap::from([("id-bob".to_string(), "c2".to_string())]))]);
        assert_eq!(s.moved(t0 + MOVE_GRANT_TTL - Duration::from_secs(1)), moved, "the grant gives a view at once");
        assert!(!s.move_entitles(&key("c2"), "id-bob", t0 + MOVE_GRANT_TTL), "expired");
        assert!(s.moved(t0 + MOVE_GRANT_TTL).is_empty(), "an unused grant ends with its time");
        // One move per user: a new one replaces the old.
        s.grant_move(&key("c2"), "id-bob", t0);
        s.grant_move(&key("c3"), "id-bob", t0);
        assert!(!s.move_entitles(&key("c2"), "id-bob", t0) && s.move_entitles(&key("c3"), "id-bob", t0));
    }

    #[test]
    fn the_first_join_consumes_the_grant_and_the_participation_lasts_while_the_user_is_there() {
        let mut s = VoiceState::with_grace(Duration::from_secs(45));
        let t0 = Instant::now();
        let later = t0 + MOVE_GRANT_TTL * 3;
        s.grant_move(&key("c2"), "id-bob", t0);
        s.reserve(&key("c2"), &who("bob", DEV_A), t0);
        s.joined(&key("c2"), "id-bob");
        s.activate(&key("c2"), &who("bob", DEV_A), t0);
        s.activate(&key("c2"), &who("alice", DEV_A), t0);
        let marks: Vec<(String, bool)> = s.participants(&key("c2")).into_iter().map(|p| (p.user, p.moved)).collect();
        assert_eq!(marks, vec![("bob@node.example".into(), true), ("alice@node.example".into(), false)]);
        assert!(s.get(&key("c2"), &id("bob", DEV_A)).unwrap().moved);
        // A dropped connection keeps it: the rejoin is entitled long after the grant's time.
        s.lose(&key("c2"), &id("bob", DEV_A), later);
        assert!(s.move_entitles(&key("c2"), "id-bob", later), "rejoin within the grace period");
        assert_eq!(s.moved(later).len(), 1);
        // Leaving ends it: no rejoin, no view.
        s.remove(&key("c2"), &id("bob", DEV_A));
        assert!(!s.move_entitles(&key("c2"), "id-bob", later));
        assert!(s.moved(later).is_empty());
        assert!(!s.move_entitles(&key("c2"), "id-bob", t0), "consumed: not even within the grant's time");
    }

    #[test]
    fn joining_another_channel_ends_a_move() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        s.grant_move(&key("c2"), "id-bob", t0);
        s.reserve(&key("c1"), &who("bob", DEV_A), t0);
        s.joined(&key("c1"), "id-bob");
        assert!(!s.move_entitles(&key("c2"), "id-bob", t0), "the grant is gone");
        assert!(s.moved(t0).is_empty());
        // From a moved participation into another channel: the reservation leaves c2, the move ends.
        s.grant_move(&key("c2"), "id-bob", t0);
        s.reserve(&key("c2"), &who("bob", DEV_A), t0);
        s.joined(&key("c2"), "id-bob");
        s.reserve(&key("c1"), &who("bob", DEV_A), t0);
        s.joined(&key("c1"), "id-bob");
        assert!(s.moved(t0).is_empty());
        assert!(!s.participants(&key("c1")).iter().any(|p| p.moved));
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
    fn a_screen_publisher_needs_its_device_and_is_one_per_device() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        assert_eq!(s.reserve_screen(&key("c1"), &screen("alice", DEV_A), t0), Err(ScreenRefusal::NoOwner));
        s.reserve(&key("c1"), &who("bob", DEV_A), t0);
        assert_eq!(
            s.reserve_screen(&key("c1"), &screen("alice", DEV_A), t0),
            Err(ScreenRefusal::NoOwner),
            "bob's device is not alice's"
        );
        s.reserve(&key("c1"), &who("alice", DEV_A), t0);
        assert_eq!(s.reserve_screen(&key("c1"), &screen("alice", DEV_A), t0), Ok(()));
        assert_eq!(s.reserve_screen(&key("c1"), &screen("alice", DEV_A), t0), Err(ScreenRefusal::Active), "reserved");
        // A reservation LiveKit never saw goes stale and may be replaced; a connected one never.
        let later = t0 + PENDING_TTL;
        assert_eq!(s.reserve_screen(&key("c1"), &screen("alice", DEV_A), later), Ok(()));
        assert!(s.activate(&key("c1"), &screen("alice", DEV_A), later));
        assert_eq!(
            s.reserve_screen(&key("c1"), &screen("alice", DEV_A), later + PENDING_TTL),
            Err(ScreenRefusal::Active)
        );
        assert_eq!(s.identities_in(&key("c1")).iter().filter(|i| i.ends_with("#screen")).count(), 1, "never twice");
    }

    #[test]
    fn a_screen_publisher_is_listed_after_its_owner_and_takes_no_seat() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        s.activate(&key("c1"), &who("bob", DEV_B), t0);
        s.reserve_screen(&key("c1"), &screen("alice", DEV_A), t0).unwrap();
        assert_eq!(s.participants(&key("c1")).len(), 2, "reserved: invisible");
        assert!(s.activate(&key("c1"), &screen("alice", DEV_A), t0));
        let ps = s.participants(&key("c1"));
        let ids: Vec<&str> = ps.iter().map(|p| p.identity.as_str()).collect();
        assert_eq!(ids, [id("alice", DEV_A), format!("{}#screen", id("alice", DEV_A)), id("bob", DEV_B)]);
        let p = &ps[1];
        assert_eq!(p.screen_of.as_deref(), Some(id("alice", DEV_A).as_str()));
        assert_eq!(
            (p.user.as_str(), p.user_id.as_str(), p.device_id.as_str()),
            ("alice@node.example", "id-alice", DEV_A)
        );
        assert!(p.muted && !p.deafened && !p.camera && !p.streaming);
        assert_eq!(ps[0].screen_of, None);
        assert_eq!(s.occupancy(&key("c1"), "x", t0), 2, "two people, not three");
        // Activated without a reservation (a reconnect with a refreshed token): placed the same way.
        let mut s2 = VoiceState::default();
        s2.activate(&key("c1"), &who("alice", DEV_A), t0);
        s2.activate(&key("c1"), &who("bob", DEV_B), t0);
        assert!(!s2.activate(&key("c1"), &screen("carol", DEV_A), t0), "no device, no screen publisher");
        assert!(!s2.accepts(&key("c1"), &screen("carol", DEV_A)));
        assert!(s2.accepts(&key("c1"), &screen("alice", DEV_A)) && s2.accepts(&key("c1"), &who("carol", DEV_A)));
        assert!(s2.activate(&key("c1"), &screen("alice", DEV_A), t0));
        assert_eq!(s2.participants(&key("c1"))[1].identity, format!("{}#screen", id("alice", DEV_A)));
    }

    #[test]
    fn the_screen_track_makes_the_owner_stream_and_a_server_mute_leaves_the_screen_alone() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        s.activate(&key("c1"), &screen("alice", DEV_A), t0);
        let scr = format!("{}#screen", id("alice", DEV_A));
        assert!(s.set_track(&key("c1"), &scr, Source::Screen, true));
        let ps = s.participants(&key("c1"));
        assert!(ps[0].streaming && ps[1].streaming);
        assert!(!s.set_track(&key("c1"), &scr, Source::Screen, true));
        assert!(s.set_track(&key("c1"), &scr, Source::Screen, false));
        assert!(s.participants(&key("c1")).iter().all(|p| !p.streaming));
        let out = s.set_server_muted("room", "id-alice", true);
        assert_eq!(out, vec![(key("c1"), id("alice", DEV_A), true)], "only the device's microphone grant changes");
    }

    #[test]
    fn a_screen_publisher_ends_with_its_owner() {
        let mut s = VoiceState::with_grace(Duration::from_secs(5));
        let t0 = Instant::now();
        let scr = format!("{}#screen", id("alice", DEV_A));
        let start = |s: &mut VoiceState| {
            s.activate(&key("c1"), &who("alice", DEV_A), t0);
            s.activate(&key("c1"), &screen("alice", DEV_A), t0);
        };
        // The owner leaves: both go.
        start(&mut s);
        assert!(s.remove(&key("c1"), &id("alice", DEV_A)));
        assert!(s.participants(&key("c1")).is_empty());
        // The screen's own leave: the owner stays.
        start(&mut s);
        assert!(s.remove(&key("c1"), &scr));
        assert_eq!(s.identities_in(&key("c1")), vec![id("alice", DEV_A)]);
        // The owner reconnects: the screen stays; its grace runs out: both go, the screen is collected for LiveKit.
        start(&mut s);
        s.lose(&key("c1"), &id("alice", DEV_A), t0);
        assert!(s.expire(t0 + Duration::from_secs(4)).is_empty());
        assert_eq!(s.participants(&key("c1")).len(), 2);
        assert!(s.take_orphans().is_empty());
        assert_eq!(s.expire(t0 + Duration::from_secs(5)), vec![key("c1")]);
        assert!(s.participants(&key("c1")).is_empty());
        assert_eq!(s.take_orphans(), vec![(key("c1"), scr.clone())]);
        assert!(s.take_orphans().is_empty());
        // The reconciliation drops an owner LiveKit lost for good the same way.
        start(&mut s);
        let only_screen: HashMap<ChannelKey, HashSet<String>> =
            [(key("c1"), [scr.clone()].into_iter().collect())].into_iter().collect();
        s.reconcile(&only_screen, t0);
        let (changed, _) = s.reconcile(&only_screen, t0 + Duration::from_secs(5));
        assert_eq!(changed, vec![key("c1")]);
        assert!(s.participants(&key("c1")).is_empty());
        assert_eq!(s.take_orphans(), vec![(key("c1"), scr.clone())]);
        // A kick or ban (all of the user's entries).
        start(&mut s);
        let removed = s.remove_user("room", "id-alice");
        assert_eq!(removed, vec![(key("c1"), vec![id("alice", DEV_A), scr.clone()], true)]);
    }

    #[test]
    fn the_screen_publisher_follows_its_device_and_leaves_with_a_replaced_device() {
        let mut s = VoiceState::default();
        let t0 = Instant::now();
        let scr = format!("{}#screen", id("alice", DEV_A));
        s.activate(&key("c1"), &who("alice", DEV_A), t0);
        s.activate(&key("c1"), &screen("alice", DEV_A), t0);
        // A rejoin of the device keeps it.
        let r = s.reserve(&key("c1"), &who("alice", DEV_A), t0);
        assert_eq!(r, Reserved::default());
        assert_eq!(s.participants(&key("c1")).len(), 2);
        // The device joins another channel: its screen publisher there is told to go too.
        let r = s.reserve(&key("c2"), &who("alice", DEV_A), t0);
        assert_eq!(r.displaced, vec![(key("c1"), scr.clone())]);
        assert_eq!(r.changed, vec![key("c1")]);
        assert!(s.participants(&key("c1")).is_empty());
        // Another device of the user replaces the device and its screen publisher.
        s.activate(&key("c2"), &who("alice", DEV_A), t0);
        s.activate(&key("c2"), &screen("alice", DEV_A), t0);
        let r = s.reserve(&key("c2"), &who("alice", DEV_B), t0);
        assert_eq!(
            r.displaced,
            vec![(key("c2"), id("alice", DEV_A)), (key("c2"), format!("{}#screen", id("alice", DEV_A)))]
        );
        assert_eq!(s.identities_in(&key("c2")), vec![id("alice", DEV_B)]);
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
