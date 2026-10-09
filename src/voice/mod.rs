// SPDX-License-Identifier: AGPL-3.0-only
//! Voice, video and screen sharing (phase 4, `protocol/VOICE.md`).
//!
//! LiveKit is the media server ([`livekit`]); the node issues its tokens ([`token`]), proxies its
//! signaling (`routes::rtc`), keeps who is in which channel ([`state`]) from LiveKit's webhooks and a
//! periodic reconciliation, and publishes that as `voice.state` events.

pub mod advertise;
pub mod livekit;
pub mod state;
pub mod token;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use livekit_api::services::room::{RoomClient, UpdateParticipantOptions};
use livekit_protocol as proto;
use serde::Serialize;
use utoipa::ToSchema;

use self::{
    livekit::{Advertise, ApiKey, LiveKitStatus},
    state::{ChannelKey, Source, VoiceParticipant, VoiceState, Who},
};
use crate::{app::AppState, config::Config, store};

/// How often the node compares its participant list with LiveKit's.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// How often participants whose reconnect grace period ran out are removed: a fifth of the grace period,
/// between one and five seconds.
pub fn sweep_interval(grace: Duration) -> Duration {
    (grace / 5).clamp(Duration::from_secs(1), Duration::from_secs(5))
}

/// Voice runtime shared by all requests: LiveKit credentials and client, process status, participants.
pub struct VoiceRuntime {
    key: Option<ApiKey>,
    rooms: Option<RoomClient>,
    status: Mutex<LiveKitStatus>,
    participants: Mutex<VoiceState>,
    /// The addresses LiveKit announces (configured literals plus resolved hostnames, [`advertise`]).
    advertise: Mutex<Advertise>,
    /// A voice setup problem for `/healthz` (e.g. no announced address could be resolved).
    problem: Mutex<Option<String>>,
    /// Asks the supervisor to restart LiveKit with the current addresses.
    restart: tokio::sync::Notify,
}

impl VoiceRuntime {
    /// Loads (or creates) the LiveKit API key when voice is enabled.
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        if !config.voice_enabled {
            return Ok(Self::disabled());
        }
        let key = livekit::load_or_create_key(&std::path::Path::new(&config.data_dir).join("keys"))?;
        let rooms =
            RoomClient::with_api_key(&format!("http://127.0.0.1:{}", config.livekit_port), &key.key, &key.secret)
                .with_request_timeout(Duration::from_secs(5));
        Ok(Self {
            key: Some(key),
            rooms: Some(rooms),
            status: Mutex::new(LiveKitStatus::Stopped),
            participants: Mutex::new(VoiceState::with_grace(Duration::from_secs(config.voice_reconnect_grace_secs))),
            advertise: Mutex::new(Advertise::from_config(config)),
            problem: Mutex::new(None),
            restart: tokio::sync::Notify::new(),
        })
    }

    fn disabled() -> Self {
        Self {
            key: None,
            rooms: None,
            status: Mutex::new(LiveKitStatus::Disabled),
            participants: Mutex::default(),
            advertise: Mutex::default(),
            problem: Mutex::new(None),
            restart: tokio::sync::Notify::new(),
        }
    }

    /// The addresses LiveKit announces and the clients add as candidates.
    pub fn advertise(&self) -> Advertise {
        self.advertise.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_advertise(&self, advertise: Advertise) {
        *self.advertise.lock().unwrap_or_else(|e| e.into_inner()) = advertise;
    }

    /// A voice setup problem (`/healthz`), if any.
    pub fn problem(&self) -> Option<String> {
        self.problem.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_problem(&self, problem: Option<String>) {
        *self.problem.lock().unwrap_or_else(|e| e.into_inner()) = problem;
    }

    /// Asks the supervisor to restart LiveKit (new announced addresses). Kept until the supervisor takes it.
    pub fn request_restart(&self) {
        self.restart.notify_one();
    }

    /// Resolves when a restart was requested.
    pub async fn restart_requested(&self) {
        self.restart.notified().await;
    }

    pub fn api_key(&self) -> Option<&ApiKey> {
        self.key.as_ref()
    }

    pub fn status(&self) -> LiveKitStatus {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_status(&self, status: LiveKitStatus) {
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = status;
    }

    /// The participant state; hold the guard only for synchronous work.
    pub fn participants(&self) -> MutexGuard<'_, VoiceState> {
        self.participants.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// LiveKit's room service (only with voice enabled).
    pub fn rooms(&self) -> Option<&RoomClient> {
        self.rooms.as_ref()
    }

    /// Verifies a LiveKit token signed with this node's secret.
    pub fn verify(&self, token: &str) -> Option<livekit_api::access_token::Claims> {
        let key = self.key.as_ref()?;
        token::verify(&key.key, &key.secret, token)
    }
}

/// LiveKit participant identity and MLS leaf identity of a device: `<user address>/<device id>`.
pub fn identity(user: &str, device_id: &str) -> String {
    format!("{user}/{device_id}")
}

/// `alice@node.example/<ulid>` → (`alice@node.example`, `<ulid>`).
pub fn parse_identity(identity: &str) -> Option<(&str, &str)> {
    let (user, device) = identity.rsplit_once('/')?;
    (crate::util::parse_address(user).is_some() && crate::util::is_ulid(device)).then_some((user, device))
}

/// LiveKit room name of a voice channel: `<room id>:<channel id>`.
pub fn room_name(key: &ChannelKey) -> String {
    format!("{}:{}", key.0, key.1)
}

pub fn parse_room_name(name: &str) -> Option<ChannelKey> {
    let (room, channel) = name.split_once(':')?;
    (crate::util::is_ulid(room) && crate::util::is_ulid(channel)).then(|| (room.to_string(), channel.to_string()))
}

/// Payload of `voice.state` and the participant lists of the voice routes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VoiceChannelState {
    pub room_id: String,
    pub channel_id: String,
    /// Current MLS epoch of the channel's group (null before the group exists). Clients derive the frame
    /// key of this epoch (`ENCRYPTION.md` §5a).
    pub epoch: Option<i64>,
    /// Connected participants in join order.
    pub participants: Vec<VoiceParticipant>,
}

/// Current state of one channel, with the MLS epoch from the database.
pub async fn channel_state(state: &AppState, key: &ChannelKey) -> VoiceChannelState {
    let participants = state.voice.participants().participants(key);
    let epoch = store::e2ee::group_epoch(&state.db, &key.1).await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read MLS epoch for voice.state");
        None
    });
    VoiceChannelState { room_id: key.0.clone(), channel_id: key.1.clone(), epoch, participants }
}

/// Publishes `voice.state` of each channel to the room's members.
pub async fn publish(state: &AppState, keys: &[ChannelKey]) {
    for key in keys {
        let data = channel_state(state, key).await;
        state.hub.room(&key.0, "voice.state", &data);
    }
}

/// Resolves a LiveKit identity to a user of this node's database (local or remote) for `room_id`.
pub async fn who(state: &AppState, room_id: &str, identity: &str) -> Option<Who> {
    let (address, device) = parse_identity(identity)?;
    let (username, domain) = crate::util::parse_address(address)?;
    let user = store::users::by_username(&state.db, username, domain).await.ok()??;
    let server_muted = store::voice::server_muted(&state.db, room_id, &user.id).await.unwrap_or(false);
    Some(Who { user: user.address(), user_id: user.id, device_id: device.to_string(), server_muted })
}

/// LiveKit room of a connection test (`POST /voice/test`, VOICE.md §10.4): `test:<random ulid>`.
pub fn test_room_name() -> String {
    format!("test:{}", crate::util::ulid())
}

pub fn is_test_room(name: &str) -> bool {
    name.strip_prefix("test:").is_some_and(crate::util::is_ulid)
}

/// A participant left LiveKit (`participant_left`/`_connection_aborted` with `reason`). Returns `true` if
/// the visible participants changed.
fn departure(participants: &mut VoiceState, key: &ChannelKey, identity: &str, reason: i32, now: Instant) -> bool {
    match proto::DisconnectReason::try_from(reason).unwrap_or(proto::DisconnectReason::UnknownReason) {
        // The client hung up (it also calls `…/leave`), or the node removed it: gone at once.
        proto::DisconnectReason::ClientInitiated
        | proto::DisconnectReason::ParticipantRemoved
        | proto::DisconnectReason::RoomDeleted => participants.remove(key, identity),
        // The same identity connected again: the new connection continues the entry.
        proto::DisconnectReason::DuplicateIdentity => false,
        // Lost connection: keep the participant as reconnecting for the grace period.
        _ => participants.lose(key, identity, now),
    }
}

/// A screen share or camera track was (un)published. Returns `true` if the visible state changed.
fn track_change(participants: &mut VoiceState, key: &ChannelKey, identity: &str, event: &proto::WebhookEvent) -> bool {
    let published = event.event == "track_published";
    match event.track.as_ref().map(|t| proto::TrackSource::try_from(t.source)) {
        Some(Ok(proto::TrackSource::ScreenShare)) => participants.set_track(key, identity, Source::Screen, published),
        Some(Ok(proto::TrackSource::Camera)) => participants.set_track(key, identity, Source::Camera, published),
        _ => false,
    }
}

/// Handles a verified LiveKit webhook. Unknown events and rooms that are neither voice channels nor calls
/// (connection tests) are ignored.
pub async fn handle_webhook(state: &AppState, event: proto::WebhookEvent) {
    let name = event.room.as_ref().map(|r| r.name.clone()).unwrap_or_default();
    if let Some(conversation_id) = crate::calls::parse_room_name(&name) {
        return handle_call_webhook(state, &conversation_id, event).await;
    }
    let Some(key) = parse_room_name(&name) else { return };
    let now = Instant::now();
    let identity = event.participant.as_ref().map(|p| p.identity.clone()).unwrap_or_default();
    let changed = match event.event.as_str() {
        "participant_joined" => match who(state, &key.0, &identity).await {
            Some(who) => state.voice.participants().activate(&key, &who, now),
            None => {
                tracing::warn!(identity, "unknown participant in LiveKit, removing");
                remove_from_livekit(state, &key, &identity).await;
                false
            }
        },
        "participant_left" | "participant_connection_aborted" => {
            let reason = event.participant.as_ref().map(|p| p.disconnect_reason).unwrap_or_default();
            departure(&mut state.voice.participants(), &key, &identity, reason, now)
        }
        "track_published" | "track_unpublished" => {
            track_change(&mut state.voice.participants(), &key, &identity, &event)
        }
        "room_finished" => !state.voice.participants().remove_channel(&key).is_empty(),
        _ => false,
    };
    if changed {
        publish(state, &[key]).await;
    }
}

/// A webhook of a call's LiveKit room (`call:<conversation id>`).
async fn handle_call_webhook(state: &AppState, conversation_id: &str, event: proto::WebhookEvent) {
    let key = crate::calls::key(conversation_id);
    let now = Instant::now();
    let identity = event.participant.as_ref().map(|p| p.identity.clone()).unwrap_or_default();
    let changed = match event.event.as_str() {
        "participant_joined" => match crate::calls::who(state, conversation_id, &identity).await {
            Some(who) if state.calls.is_active(conversation_id) => state.calls.participants().activate(&key, &who, now),
            _ => {
                tracing::warn!(identity, "unknown participant in the call, removing");
                remove_from_livekit(state, &key, &identity).await;
                false
            }
        },
        "participant_left" | "participant_connection_aborted" => {
            let reason = event.participant.as_ref().map(|p| p.disconnect_reason).unwrap_or_default();
            departure(&mut state.calls.participants(), &key, &identity, reason, now)
        }
        "track_published" | "track_unpublished" => {
            track_change(&mut state.calls.participants(), &key, &identity, &event)
        }
        "room_finished" => !state.calls.participants().remove_channel(&key).is_empty(),
        _ => false,
    };
    if changed {
        crate::calls::after_change(state, conversation_id).await;
    }
}

/// One reconciliation with LiveKit's room service: removes ghosts, adds participants whose webhook was
/// lost, in voice channels and calls. Does nothing (and keeps the state) while LiveKit is unreachable.
pub async fn reconcile_once(state: &AppState) -> anyhow::Result<()> {
    let Some(rooms) = state.voice.rooms() else { return Ok(()) };
    let mut truth: HashMap<ChannelKey, HashSet<String>> = HashMap::new();
    let mut calls: HashMap<ChannelKey, HashSet<String>> = HashMap::new();
    for room in rooms.list_rooms(Vec::new()).await? {
        let (target, key) = match (parse_room_name(&room.name), crate::calls::parse_room_name(&room.name)) {
            (Some(key), _) => (&mut truth, key),
            (None, Some(conversation_id)) => (&mut calls, crate::calls::key(&conversation_id)),
            (None, None) => continue,
        };
        let present: HashSet<String> = rooms
            .list_participants(&room.name)
            .await?
            .into_iter()
            .filter(|p| p.state != proto::participant_info::State::Disconnected as i32)
            .map(|p| p.identity)
            .collect();
        target.insert(key, present);
    }
    let (mut changed, unknown) = state.voice.participants().reconcile(&truth, Instant::now());
    for (key, identity) in unknown {
        match who(state, &key.0, &identity).await {
            Some(who) => {
                if state.voice.participants().activate(&key, &who, Instant::now()) && !changed.contains(&key) {
                    changed.push(key);
                }
            }
            None => remove_from_livekit(state, &key, &identity).await,
        }
    }
    publish(state, &changed).await;

    let (mut changed, unknown) = state.calls.participants().reconcile(&calls, Instant::now());
    for (key, identity) in unknown {
        match crate::calls::who(state, &key.1, &identity).await {
            Some(who) if state.calls.is_active(&key.1) => {
                if state.calls.participants().activate(&key, &who, Instant::now()) && !changed.contains(&key) {
                    changed.push(key);
                }
            }
            _ => remove_from_livekit(state, &key, &identity).await,
        }
    }
    for key in changed {
        crate::calls::after_change(state, &key.1).await;
    }
    Ok(())
}

/// Removes participants whose grace period ran out (and announces them as gone), in voice channels and calls.
pub async fn expire_once(state: &AppState) {
    let changed = state.voice.participants().expire(Instant::now());
    publish(state, &changed).await;
    let changed = state.calls.participants().expire(Instant::now());
    for key in changed {
        crate::calls::after_change(state, &key.1).await;
    }
}

/// Runs [`expire_once`] every [`sweep_interval`].
pub fn spawn_grace_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let grace = state.voice.participants().grace();
        let mut tick = tokio::time::interval(sweep_interval(grace));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // The participants live on the leader (several instances, `cache.rs`).
            if state.cluster.is_leader() {
                expire_once(&state).await;
            }
        }
    })
}

/// Runs [`reconcile_once`] every 30 seconds.
pub fn spawn_reconciler(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RECONCILE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // Only the leader reconciles: it holds the participants, and LiveKit's room service answers for the
            // whole LiveKit cluster from any instance.
            if !state.cluster.is_leader() {
                continue;
            }
            if let Err(e) = reconcile_once(&state).await {
                tracing::debug!(error = %e, "reconciliation with LiveKit skipped");
            }
        }
    })
}

/// Disconnects a participant in LiveKit (best effort: a participant LiveKit does not know is fine).
/// Tokens are not revoked: a token revocation would also hit a rejoin within the same second (token
/// timestamps are seconds), and a member who lost access is refused by the `/rtc` proxy anyway.
pub async fn remove_from_livekit(state: &AppState, key: &ChannelKey, identity: &str) {
    let Some(rooms) = state.voice.rooms() else { return };
    if let Err(e) = rooms.remove_participant(&room_name(key), identity).await {
        tracing::debug!(error = %e, identity, "LiveKit participant not removed (not connected?)");
    }
}

/// Grants or revokes the microphone of a connected participant (moderator mute) without a reconnect; data
/// messages and own attribute updates stay as the token granted them (`token::grants`).
pub async fn update_permission(state: &AppState, key: &ChannelKey, identity: &str, sources: token::Sources) {
    let Some(rooms) = state.voice.rooms() else { return };
    let mut can_publish_sources = Vec::new();
    if sources.microphone {
        can_publish_sources.push(proto::TrackSource::Microphone as i32);
    }
    if sources.camera {
        can_publish_sources.push(proto::TrackSource::Camera as i32);
    }
    if sources.screen {
        can_publish_sources.push(proto::TrackSource::ScreenShare as i32);
        can_publish_sources.push(proto::TrackSource::ScreenShareAudio as i32);
    }
    let permission = proto::ParticipantPermission {
        can_subscribe: true,
        can_publish: !can_publish_sources.is_empty(),
        can_publish_data: sources.data,
        can_update_metadata: sources.priority,
        can_publish_sources,
        ..Default::default()
    };
    let options = UpdateParticipantOptions { permission: Some(permission), ..Default::default() };
    if let Err(e) = rooms.update_participant(&room_name(key), identity, options).await {
        tracing::debug!(error = %e, identity, "LiveKit permissions not updated (not connected?)");
    }
}

/// On an instance that is not the leader (several instances, `cache.rs`) a voice side effect goes to the leader,
/// which holds the participants; `true` if it was handed over.
pub(crate) fn hand_to_leader(state: &AppState, effect: impl FnOnce() -> crate::cache::VoiceEffect) -> bool {
    if state.cluster.is_leader() {
        return false;
    }
    state.cluster.send(crate::cache::Message::Voice { effect: effect() });
    true
}

/// Runs a side effect another instance handed to this one (the leader).
pub async fn run_effect(state: &AppState, effect: crate::cache::VoiceEffect) {
    use crate::cache::VoiceEffect as E;
    match effect {
        E::DisconnectUser { room_id, user_id } => disconnect_user(state, &room_id, &user_id).await,
        E::CloseChannel { room_id, channel_id } => close_channel(state, &room_id, &channel_id).await,
        E::CloseRoom { room_id } => close_room(state, &room_id).await,
        E::LeaveCall { conversation_id, user_id } => crate::calls::drop_member(state, &conversation_id, &user_id).await,
    }
}

/// Removes every device of a user from the voice channels of a room (left, kicked, banned, timed out).
pub async fn disconnect_user(state: &AppState, room_id: &str, user_id: &str) {
    if hand_to_leader(state, || crate::cache::VoiceEffect::DisconnectUser {
        room_id: room_id.into(),
        user_id: user_id.into(),
    }) {
        return;
    }
    let removed = state.voice.participants().remove_user(room_id, user_id);
    let mut changed = Vec::new();
    for (key, identities, visible) in removed {
        for identity in &identities {
            remove_from_livekit(state, &key, identity).await;
        }
        if visible {
            changed.push(key);
        }
    }
    publish(state, &changed).await;
}

/// A voice channel was deleted: disconnect everybody.
pub async fn close_channel(state: &AppState, room_id: &str, channel_id: &str) {
    if hand_to_leader(state, || crate::cache::VoiceEffect::CloseChannel {
        room_id: room_id.into(),
        channel_id: channel_id.into(),
    }) {
        return;
    }
    let key = (room_id.to_string(), channel_id.to_string());
    let identities = state.voice.participants().remove_channel(&key);
    if identities.is_empty() {
        return;
    }
    if let Some(rooms) = state.voice.rooms()
        && let Err(e) = rooms.delete_room(&room_name(&key)).await
    {
        tracing::debug!(error = %e, "LiveKit room not deleted");
    }
}

/// A room was deleted: close all its voice channels.
pub async fn close_room(state: &AppState, room_id: &str) {
    if hand_to_leader(state, || crate::cache::VoiceEffect::CloseRoom { room_id: room_id.into() }) {
        return;
    }
    let keys = state.voice.participants().remove_room(room_id);
    if let Some(rooms) = state.voice.rooms() {
        for key in keys {
            if let Err(e) = rooms.delete_room(&room_name(&key)).await {
                tracing::debug!(error = %e, "LiveKit room not deleted");
            }
        }
    }
}

/// Disconnects the participants of a room's voice channels who no longer hold `view_channel` and `connect` there
/// (a role, override, membership or age change), against the current visibility snapshot (VOICE.md §4). Runs on
/// the leader, which holds the participants.
pub async fn check_access(state: &AppState, room_id: &str) {
    if !state.cluster.is_leader() {
        return;
    }
    let keys = state.voice.participants().active_channels(room_id);
    if keys.is_empty() {
        return;
    }
    let view = match crate::visibility::room(state, room_id).await {
        Ok(Some(view)) => view,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, room_id, "voice access could not be checked");
            return;
        }
    };
    let needed = crate::permissions::VIEW_CHANNEL | crate::permissions::CONNECT;
    let mut changed = Vec::new();
    for key in keys {
        let users = state.voice.participants().users_in(&key);
        for user_id in users {
            if view.perms(&key.1, &user_id).is_some_and(|p| crate::permissions::has(p, needed)) {
                continue;
            }
            let identities = state.voice.participants().identities_of(&key, &user_id);
            let mut visible = false;
            for identity in &identities {
                visible |= state.voice.participants().remove(&key, identity);
                remove_from_livekit(state, &key, identity).await;
            }
            if visible && !changed.contains(&key) {
                changed.push(key.clone());
            }
        }
    }
    publish(state, &changed).await;
}

/// How often every room with voice participants is checked even without an event (changes that come without one,
/// e.g. an age status or the node admin flag; the visibility snapshot's lifetime).
const ACCESS_SWEEP: Duration = crate::visibility::TTL;

/// Watches the events that change who may view what (`visibility::changes_visibility`) and checks the voice
/// participants of the room ([`check_access`]); every [`ACCESS_SWEEP`] all rooms with participants.
pub fn spawn_access_watcher(state: &AppState) {
    if !state.config.voice_enabled {
        return;
    }
    let mut events = state.hub.subscribe();
    let state = state.clone();
    tokio::spawn(async move {
        let mut sweep = tokio::time::interval(ACCESS_SWEEP);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        sweep.tick().await;
        loop {
            let rooms: Vec<String> = tokio::select! {
                event = events.recv() => match event {
                    Ok(ev) => match &ev.scope {
                        crate::hub::Scope::Room(room_id) if crate::visibility::changes_visibility(&ev.kind) => {
                            vec![room_id.clone()]
                        }
                        _ => continue,
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => all_voice_rooms(&state),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = sweep.tick() => all_voice_rooms(&state),
            };
            for room_id in rooms {
                check_access(&state, &room_id).await;
            }
        }
    });
}

fn all_voice_rooms(state: &AppState) -> Vec<String> {
    let mut rooms: Vec<String> = state.voice.participants().keys().into_iter().map(|k| k.0).collect();
    rooms.sort();
    rooms.dedup();
    rooms
}

/// Runs a voice side effect after the response (kick, ban, … must not wait for LiveKit).
pub fn spawn_effect<F>(state: &AppState, f: impl FnOnce(AppState) -> F + Send + 'static)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if state.config.voice_enabled {
        let state = state.clone();
        tokio::spawn(async move { f(state).await });
    }
}

/// Shared handle type in [`AppState`].
pub type SharedVoice = Arc<VoiceRuntime>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grace_sweep_runs_often_enough_but_not_too_often() {
        assert_eq!(sweep_interval(Duration::from_secs(45)), Duration::from_secs(5));
        assert_eq!(sweep_interval(Duration::from_secs(5)), Duration::from_secs(1));
        assert_eq!(sweep_interval(Duration::ZERO), Duration::from_secs(1));
        assert_eq!(sweep_interval(Duration::from_secs(10)), Duration::from_secs(2));
    }

    #[test]
    fn identities_and_room_names_round_trip_and_reject_garbage() {
        let dev = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";
        let id = identity("alice@node.example", dev);
        assert_eq!(parse_identity(&id), Some(("alice@node.example", dev)));
        for bad in ["alice@node.example", "alice/01J9ZZZZZZZZZZZZZZZZZZZZZZ", "Alice@node.example/x", "a@b/c/d"] {
            assert_eq!(parse_identity(bad), None, "{bad}");
        }
        let key: ChannelKey = ("01J9AAAAAAAAAAAAAAAAAAAAAA".into(), "01J9BBBBBBBBBBBBBBBBBBBBBB".into());
        assert_eq!(parse_room_name(&room_name(&key)), Some(key));
        for bad in ["", "x:y", "01J9AAAAAAAAAAAAAAAAAAAAAA", "01J9AAAAAAAAAAAAAAAAAAAAAA:01J9BB"] {
            assert_eq!(parse_room_name(bad), None, "{bad}");
        }
    }
}
