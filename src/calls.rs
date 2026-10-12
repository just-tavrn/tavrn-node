// SPDX-License-Identifier: AGPL-3.0-only
//! Calls in DMs and group DMs (protocol/VOICE.md §11).
//!
//! The node hosting a conversation (the creator's home node, FEDERATION.md §6.1) runs its call: a LiveKit
//! room `call:<conversation id>` with the same end-to-end encryption as voice channels, keyed by the
//! conversation's MLS group (ENCRYPTION.md §5a). Starting a call rings every other (accepted) member:
//! WebSocket `call.ring` to their connections on this node, and for members of other nodes without a
//! connection here a `notify` hint with a `call` field to their home node (FEDERATION.md §5.2), which rings
//! their devices there. Nobody answering within [`RING_TIMEOUT`] (or the callee declining a DM) ends the
//! call with a `system.call.missed` message; the last participant leaving ends it with
//! `system.call.ended { duration_secs }`. Both are plaintext system messages of the node (no user content).
//!
//! Who is connected is kept like in voice channels ([`VoiceState`], keys `("call", <conversation id>)`):
//! reservations on join, LiveKit's webhooks, the reconnect grace period and the reconciliation. Calls are
//! kept in memory only; a node restart ends them.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    error::ApiError,
    models::UserRow,
    store,
    voice::{
        self,
        state::{ChannelKey, VoiceParticipant, VoiceState, Who},
    },
};

/// Unanswered calls end (and devices stop ringing) after this time.
pub const RING_TIMEOUT: Duration = Duration::from_secs(45);
/// The `ChannelKey` namespace of call participants in [`VoiceState`].
pub const KEY_KIND: &str = "call";

/// State of a conversation's call as clients see it (`GET …/call`, `call.update`).
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct CallState {
    pub conversation_id: String,
    /// A call is running (ringing or connected).
    pub active: bool,
    /// Who started it (address).
    pub started_by: Option<String>,
    pub started_at: Option<String>,
    /// A group DM call (softer ringtone; others may join later).
    pub group: bool,
    /// Connected participants in join order.
    pub participants: Vec<VoiceParticipant>,
    /// Members whose devices are still ringing (addresses).
    pub ringing: Vec<String>,
}

impl CallState {
    pub fn idle(conversation_id: &str) -> Self {
        Self {
            conversation_id: conversation_id.to_string(),
            active: false,
            started_by: None,
            started_at: None,
            group: false,
            participants: Vec::new(),
            ringing: Vec::new(),
        }
    }
}

/// How a call ended (`call.end`, the system message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// Somebody answered; the last participant left.
    Ended,
    /// Nobody answered in time, the caller hung up first, or the callee declined.
    Missed,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::Missed => "missed",
        }
    }
}

#[derive(Debug, Clone)]
struct Call {
    started_by_id: String,
    started_by: String,
    started_at: String,
    group: bool,
    /// When somebody other than the caller connected first.
    answered_at: Option<Instant>,
    /// Members still ringing: (user id, address).
    ringing: Vec<(String, String)>,
    /// Remote members rung through their home node (told when the ringing stops).
    rung_remote: Vec<String>,
    /// Identifies this call among calls of the same conversation (timers of an earlier call do nothing).
    serial: u64,
}

/// New calls (rings) a user may start per [`RING_LIMIT_WINDOW`] (development nodes: 1000).
pub const RING_LIMIT: u32 = 10;
pub const RING_LIMIT_WINDOW: Duration = Duration::from_secs(600);

/// Calls of this node.
pub struct Calls {
    calls: Mutex<HashMap<String, Call>>,
    participants: Mutex<VoiceState>,
    serial: std::sync::atomic::AtomicU64,
    /// New calls per user (`call:<user id>`): ringing other people's devices is not a free-for-all.
    pub ring_limiter: crate::auth::RateLimiter,
}

impl Calls {
    pub fn new(grace: Duration, dev: bool) -> Self {
        Self {
            calls: Mutex::default(),
            participants: Mutex::new(VoiceState::with_grace(grace)),
            serial: 0.into(),
            ring_limiter: crate::auth::RateLimiter::new(if dev { 1000 } else { RING_LIMIT }, RING_LIMIT_WINDOW),
        }
    }

    /// The participant state of all calls (keys `("call", <conversation id>)`).
    pub fn participants(&self) -> MutexGuard<'_, VoiceState> {
        self.participants.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn calls(&self) -> MutexGuard<'_, HashMap<String, Call>> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_active(&self, conversation_id: &str) -> bool {
        self.calls().contains_key(conversation_id)
    }

    /// Conversations with a running call (for the reconciliation).
    pub fn active(&self) -> Vec<String> {
        self.calls().keys().cloned().collect()
    }

    pub fn snapshot(&self, conversation_id: &str) -> CallState {
        let key = key(conversation_id);
        let participants = self.participants().participants(&key);
        match self.calls().get(conversation_id) {
            Some(c) => CallState {
                conversation_id: conversation_id.to_string(),
                active: true,
                started_by: Some(c.started_by.clone()),
                started_at: Some(c.started_at.clone()),
                group: c.group,
                participants,
                ringing: c.ringing.iter().map(|(_, a)| a.clone()).collect(),
            },
            None => CallState::idle(conversation_id),
        }
    }

    /// Starts a call unless one is running. Returns `(serial, started)`.
    fn start(
        &self,
        conversation_id: &str,
        caller: (&str, String),
        ring: Vec<(String, String)>,
        group: bool,
    ) -> (u64, bool) {
        let mut calls = self.calls();
        if let Some(c) = calls.get(conversation_id) {
            return (c.serial, false);
        }
        let serial = self.serial.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        calls.insert(
            conversation_id.to_string(),
            Call {
                started_by_id: caller.0.to_string(),
                started_by: caller.1,
                started_at: crate::util::now(),
                group,
                answered_at: None,
                ringing: ring,
                rung_remote: Vec::new(),
                serial,
            },
        );
        (serial, true)
    }

    /// `user_id` answered or declined: it no longer rings. Returns whether anything changed.
    fn stop_ringing(&self, conversation_id: &str, user_id: &str) -> bool {
        let mut calls = self.calls();
        let Some(c) = calls.get_mut(conversation_id) else { return false };
        let before = c.ringing.len();
        c.ringing.retain(|(id, _)| id != user_id);
        before != c.ringing.len()
    }

    fn take(&self, conversation_id: &str) -> Option<Call> {
        self.calls().remove(conversation_id)
    }
}

/// `("call", <conversation id>)`.
pub fn key(conversation_id: &str) -> ChannelKey {
    (KEY_KIND.to_string(), conversation_id.to_string())
}

/// LiveKit room of a call: `call:<conversation id>`.
pub fn room_name(conversation_id: &str) -> String {
    format!("{KEY_KIND}:{conversation_id}")
}

pub fn parse_room_name(name: &str) -> Option<String> {
    let id = name.strip_prefix("call:")?;
    crate::util::is_ulid(id).then(|| id.to_string())
}

/// Members of a conversation who accepted it (message requests never ring), as user rows.
async fn active_members(state: &AppState, conversation_id: &str) -> Result<Vec<UserRow>, ApiError> {
    let ids = store::social::member_ids(&state.db, conversation_id).await?;
    let requested = store::social::requested_ids(&state.db, conversation_id).await?;
    let active: Vec<String> = ids.into_iter().filter(|id| !requested.contains(id)).collect();
    store::users::by_ids(&state.db, &active).await
}

/// Sends `kind` to every accepted member's connections on this node.
async fn to_members(state: &AppState, conversation_id: &str, kind: &str, data: Value) {
    match active_members(state, conversation_id).await {
        Ok(members) => {
            state.hub.users(members.into_iter().map(|m| m.id).collect(), kind, data);
        }
        Err(e) => tracing::warn!(error = %e, kind, "call event not sent"),
    }
}

/// Publishes `call.update` with the current state.
pub async fn publish(state: &AppState, conversation_id: &str) {
    let call = state.calls.snapshot(conversation_id);
    to_members(
        state,
        conversation_id,
        "call.update",
        json!({ "conversation_id": conversation_id, "node": state.config.domain, "call": call }),
    )
    .await;
}

/// Starts the call of a DM or group DM (or finds the running one). `members` are the accepted members.
/// How long the shared "call running" flag outlives a leader that died without ending the call.
const ACTIVE_FLAG_TTL: Duration = Duration::from_secs(12 * 3600);

/// Several instances: the calls live on the leader, but the `/rtc` proxy of every instance must know whether a
/// call runs. The leader keeps a flag per running call in the shared cache.
async fn mark_active(state: &AppState, conversation_id: &str, active: bool) {
    let cluster = &state.cluster;
    if !cluster.is_shared() {
        return;
    }
    let key = cluster.key(&format!("call:{conversation_id}"));
    let result = if active {
        cluster.cache().put(&key, "1".into(), ACTIVE_FLAG_TTL).await
    } else {
        cluster.cache().delete(&key).await
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "call flag not updated in the cache");
    }
}

/// Whether a call runs in the conversation, on whichever instance holds the calls (the leader).
pub async fn is_active_anywhere(state: &AppState, conversation_id: &str) -> bool {
    let cluster = &state.cluster;
    if !cluster.is_shared() || cluster.is_leader() {
        return state.calls.is_active(conversation_id);
    }
    matches!(cluster.cache().get(&cluster.key(&format!("call:{conversation_id}"))).await, Ok(Some(_)))
}

/// Rings everybody else; returns `true` if a new call was started.
pub async fn start(state: &AppState, conversation_id: &str, caller: &UserRow, group: bool) -> Result<bool, ApiError> {
    let mut members = Vec::new();
    for m in active_members(state, conversation_id).await? {
        // Nobody is rung by someone they blocked (or who blocked them).
        if m.id == caller.id || !store::social::blocked_either(&state.db, &m.id, &caller.id).await? {
            members.push(m);
        }
    }
    let ring: Vec<(String, String)> =
        members.iter().filter(|m| m.id != caller.id).map(|m| (m.id.clone(), m.address())).collect();
    let (serial, started) = state.calls.start(conversation_id, (&caller.id, caller.address()), ring.clone(), group);
    if !started {
        return Ok(false);
    }
    mark_active(state, conversation_id, true).await;
    let call = state.calls.snapshot(conversation_id);
    let ring_event = json!({
        "conversation_id": conversation_id, "node": state.config.domain, "from": caller.address(),
        "started_at": call.started_at, "group": group,
    });
    state.hub.users(ring.iter().map(|(id, _)| id.clone()).collect(), "call.ring", &ring_event);
    // Local members ring by web push too, also while connected (PROTOCOL.md §6d, `push::deliver_to_user`).
    for m in members.iter().filter(|m| m.id != caller.id && m.domain == state.config.domain) {
        crate::push::call(state, conversation_id, &m.id, &caller.id, group);
    }
    // Members of other nodes without a connection here ring through their home node.
    let mut rung = Vec::new();
    for m in members.iter().filter(|m| m.id != caller.id && m.domain != state.config.domain) {
        if crate::presence::is_online(state, &m.id) {
            continue;
        }
        let hint = json!({ "state": "ring", "from": caller.address(), "started_at": call.started_at, "group": group });
        if let Err(e) = crate::federation::social::call_hint(state, conversation_id, m, hint).await {
            tracing::warn!(error = %e, "call ring hint not queued");
        } else {
            rung.push(m.address());
        }
    }
    if let Some(c) = state.calls.calls().get_mut(conversation_id) {
        c.rung_remote = rung;
    }
    publish(state, conversation_id).await;
    let timer_state = state.clone();
    let id = conversation_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(RING_TIMEOUT).await;
        ring_timeout(&timer_state, &id, serial).await;
    });
    Ok(true)
}

/// The ring time of call `serial` is over: nobody rings any longer; unanswered calls end as missed.
pub async fn ring_timeout(state: &AppState, conversation_id: &str, serial: u64) {
    let (answered, remote) = {
        let mut calls = state.calls.calls();
        let Some(c) = calls.get_mut(conversation_id).filter(|c| c.serial == serial) else { return };
        c.ringing.clear();
        (c.answered_at.is_some(), std::mem::take(&mut c.rung_remote))
    };
    if answered {
        stop_remote_ringing(state, conversation_id, &remote).await;
        publish(state, conversation_id).await;
    } else {
        end(state, conversation_id, EndReason::Missed).await;
    }
}

/// Runs the ring timeout of the current call at once (integration tests).
pub async fn ring_timeout_now(state: &AppState, conversation_id: &str) {
    let serial = state.calls.calls().get(conversation_id).map(|c| c.serial);
    if let Some(serial) = serial {
        ring_timeout(state, conversation_id, serial).await;
    }
}

async fn stop_remote_ringing(state: &AppState, conversation_id: &str, addresses: &[String]) {
    for address in addresses {
        let Some((username, domain)) = crate::util::parse_address(address) else { continue };
        let Ok(Some(user)) = store::users::by_username(&state.db, username, domain).await else { continue };
        if let Err(e) =
            crate::federation::social::call_hint(state, conversation_id, &user, json!({ "state": "end" })).await
        {
            tracing::warn!(error = %e, "call end hint not queued");
        }
    }
}

/// `user` joins (answers): no longer rings. Returns whether the call exists.
pub async fn answer(state: &AppState, conversation_id: &str, user: &UserRow) -> bool {
    if !state.calls.is_active(conversation_id) {
        return false;
    }
    if state.calls.stop_ringing(conversation_id, &user.id) {
        // The user's other devices (and those on the home node) stop ringing too.
        state.hub.users(
            vec![user.id.clone()],
            "call.end",
            json!({ "conversation_id": conversation_id, "node": state.config.domain, "reason": "answered" }),
        );
        if user.domain != state.config.domain
            && let Err(e) =
                crate::federation::social::call_hint(state, conversation_id, user, json!({ "state": "end" })).await
        {
            tracing::warn!(error = %e, "call end hint not queued");
        }
        publish(state, conversation_id).await;
    }
    true
}

/// `user` declines. A DM call ends as missed; in a group the user just stops ringing (the call ends when
/// nobody is left to answer and nobody answered).
pub async fn decline(state: &AppState, conversation_id: &str, user: &UserRow) -> Result<(), ApiError> {
    if !state.calls.is_active(conversation_id) {
        return Err(not_active());
    }
    let changed = state.calls.stop_ringing(conversation_id, &user.id);
    let (group, nobody_left, answered) = {
        let calls = state.calls.calls();
        match calls.get(conversation_id) {
            Some(c) => (c.group, c.ringing.is_empty(), c.answered_at.is_some()),
            None => return Ok(()),
        }
    };
    if user.domain != state.config.domain
        && let Err(e) =
            crate::federation::social::call_hint(state, conversation_id, user, json!({ "state": "end" })).await
    {
        tracing::warn!(error = %e, "call end hint not queued");
    }
    state.hub.users(
        vec![user.id.clone()],
        "call.end",
        json!({ "conversation_id": conversation_id, "node": state.config.domain, "reason": "declined" }),
    );
    if !answered && (!group || nobody_left) {
        end(state, conversation_id, EndReason::Missed).await;
    } else if changed {
        publish(state, conversation_id).await;
    }
    Ok(())
}

/// After any change of the participants of a call: notes the first answer, publishes `call.update` and
/// ends the call once nobody is connected or reserved any more. A DM call (two people) also ends when one
/// of them hangs up after it was answered, like a phone call; a group call goes on until the last one left.
/// A dropped connection is no hang-up: the participant stays (reconnecting) for the grace period.
pub async fn after_change(state: &AppState, conversation_id: &str) {
    let key = key(conversation_id);
    let (present, users) = {
        let p = state.calls.participants();
        (p.participants(&key), p.users_in(&key))
    };
    let ended = {
        let mut calls = state.calls.calls();
        let Some(c) = calls.get_mut(conversation_id) else { return };
        if c.answered_at.is_none() && present.iter().any(|p| p.user_id != c.started_by_id) {
            c.answered_at = Some(Instant::now());
        }
        users.is_empty() || (!c.group && c.answered_at.is_some() && users.len() < 2)
    };
    if ended {
        let reason = if state.calls.calls().get(conversation_id).is_some_and(|c| c.answered_at.is_some()) {
            EndReason::Ended
        } else {
            EndReason::Missed
        };
        end(state, conversation_id, reason).await;
    } else {
        publish(state, conversation_id).await;
    }
}

/// A member left the DM or group DM (or was removed): their devices leave its running call at once (they lost
/// access, like a room member who loses `connect`); the call goes on for the others or ends as usual.
pub async fn drop_member(state: &AppState, conversation_id: &str, user_id: &str) {
    if crate::voice::hand_to_leader(state, || crate::cache::VoiceEffect::LeaveCall {
        conversation_id: conversation_id.into(),
        user_id: user_id.into(),
    }) {
        return;
    }
    if !state.calls.is_active(conversation_id) {
        return;
    }
    let key = key(conversation_id);
    let identities = state.calls.participants().identities_of(&key, user_id);
    if identities.is_empty() {
        return;
    }
    for identity in &identities {
        state.calls.participants().remove(&key, identity);
        if let Some(rooms) = state.voice.rooms()
            && let Err(e) = rooms.remove_participant(&room_name(conversation_id), identity).await
        {
            tracing::debug!(error = %e, identity, "LiveKit participant of the call not removed (not connected?)");
        }
    }
    after_change(state, conversation_id).await;
}

/// Ends a call: everybody is disconnected, the members get `call.end` and the conversation a system
/// message. Does nothing if the call is already over.
pub async fn end(state: &AppState, conversation_id: &str, reason: EndReason) {
    let Some(call) = state.calls.take(conversation_id) else { return };
    mark_active(state, conversation_id, false).await;
    let key = key(conversation_id);
    let identities = state.calls.participants().remove_channel(&key);
    if !identities.is_empty()
        && let Some(rooms) = state.voice.rooms()
        && let Err(e) = rooms.delete_room(&room_name(conversation_id)).await
    {
        tracing::debug!(error = %e, "LiveKit room of the call not deleted");
    }
    let duration_secs = call.answered_at.map(|a| a.elapsed().as_secs()).unwrap_or(0);
    let mut remote = call.rung_remote.clone();
    remote.retain(|a| call.ringing.iter().any(|(_, r)| r == a));
    stop_remote_ringing(state, conversation_id, &remote).await;
    to_members(
        state,
        conversation_id,
        "call.end",
        json!({ "conversation_id": conversation_id, "node": state.config.domain, "reason": reason.as_str(),
                "duration_secs": duration_secs }),
    )
    .await;
    publish(state, conversation_id).await;
    let data = match reason {
        EndReason::Ended => {
            json!({ "by": call.started_by, "started_at": call.started_at, "duration_secs": duration_secs })
        }
        EndReason::Missed => json!({ "by": call.started_by, "started_at": call.started_at }),
    };
    if let Err(e) = system_message(state, conversation_id, &call.started_by_id, reason, data).await {
        tracing::warn!(error = %e, "call system message not stored");
    }
}

/// `system.call.missed` / `system.call.ended` in the conversation (plaintext, written by the node).
async fn system_message(
    state: &AppState,
    conversation_id: &str,
    author_id: &str,
    reason: EndReason,
    mut data: Value,
) -> Result<(), ApiError> {
    let kind = match reason {
        EndReason::Ended => "system.call.ended",
        EndReason::Missed => "system.call.missed",
    };
    if let Value::Object(obj) = &mut data {
        obj.insert("type".into(), Value::String(kind.into()));
    }
    let content = data.to_string();
    let id = crate::util::ulid();
    store::messages::insert(
        &state.db,
        store::messages::NewMessage {
            id: &id,
            conversation_id,
            author_id,
            device_id: None,
            encrypted: false,
            format: 1,
            epoch: None,
            content: &content,
            reply_to_id: None,
            thread_id: None,
            mentions: &[],
            mentions_everyone: false,
            signature: None,
        },
    )
    .await?;
    let Some(author) = store::users::by_id(&state.db, author_id).await? else { return Ok(()) };
    let conv = crate::access::conversation(state, conversation_id, &author).await?;
    let message = crate::routes::messages::enrich_one(state, author_id, &id).await?;
    conv.publish(&state.hub, "message.create", &message);
    crate::federation::social::notify_members(state, &conv, &message, author_id).await;
    Ok(())
}

pub fn not_active() -> ApiError {
    ApiError::Conflict {
        code: "call.not_active",
        detail: "No call is running in this conversation".into(),
        meta: Value::Null,
    }
}

/// Resolves a LiveKit identity of a call to a member (local or remote user known to this node).
pub async fn who(state: &AppState, conversation_id: &str, identity: &str) -> Option<Who> {
    let (address, device) = voice::parse_identity(identity)?;
    let (username, domain) = crate::util::parse_address(address)?;
    let user = store::users::by_username(&state.db, username, domain).await.ok()??;
    let members = store::social::member_ids(&state.db, conversation_id).await.ok()?;
    let requested = store::social::requested_ids(&state.db, conversation_id).await.ok()?;
    (members.contains(&user.id) && !requested.contains(&user.id)).then(|| Who {
        user: user.address(),
        user_id: user.id,
        device_id: device.to_string(),
        server_muted: false,
        screen: voice::screen_owner(identity).is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_names_round_trip_and_never_look_like_channels() {
        let id = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";
        assert_eq!(room_name(id), format!("call:{id}"));
        assert_eq!(parse_room_name(&room_name(id)).as_deref(), Some(id));
        assert_eq!(voice::parse_room_name(&room_name(id)), None, "voice channel code ignores calls");
        for bad in ["", "call:", "call:x", "test:01J9ZZZZZZZZZZZZZZZZZZZZZZ", "01J9ZZZZZZZZZZZZZZZZZZZZZZ"] {
            assert_eq!(parse_room_name(bad), None, "{bad}");
        }
        assert_eq!(key(id), ("call".to_string(), id.to_string()));
        assert_eq!(voice::room_name(&key(id)), room_name(id), "LiveKit removals use the same room name");
    }

    #[test]
    fn calls_start_once_and_track_who_still_rings() {
        let calls = Calls::new(Duration::from_secs(5), false);
        let caller = || ("u1", "alice@n.example".to_string());
        let ring =
            vec![("u2".to_string(), "bob@n.example".to_string()), ("u3".to_string(), "carol@n.example".to_string())];
        let (serial, started) = calls.start("c1", caller(), ring.clone(), true);
        assert!(started && calls.is_active("c1"));
        assert_eq!(calls.start("c1", caller(), ring, true), (serial, false), "a running call is joined, not restarted");
        let s = calls.snapshot("c1");
        assert!(s.active && s.group);
        assert_eq!(s.started_by.as_deref(), Some("alice@n.example"));
        assert_eq!(s.ringing, vec!["bob@n.example", "carol@n.example"]);
        assert!(calls.stop_ringing("c1", "u2"));
        assert!(!calls.stop_ringing("c1", "u2"));
        assert_eq!(calls.snapshot("c1").ringing, vec!["carol@n.example"]);
        assert!(calls.take("c1").is_some());
        assert_eq!(calls.snapshot("c1"), CallState::idle("c1"));
        assert_eq!(EndReason::Missed.as_str(), "missed");
    }

    #[test]
    fn new_calls_are_rate_limited_per_user() {
        let calls = Calls::new(Duration::from_secs(5), false);
        for _ in 0..RING_LIMIT {
            assert!(calls.ring_limiter.check("call:u1").is_ok());
        }
        assert!(calls.ring_limiter.check("call:u1").is_err());
        assert!(calls.ring_limiter.check("call:u2").is_ok(), "per user");
        let dev = Calls::new(Duration::from_secs(5), true);
        for _ in 0..100 {
            assert!(dev.ring_limiter.check("call:u1").is_ok());
        }
    }
}
