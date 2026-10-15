// SPDX-License-Identifier: AGPL-3.0-only
//! Presence (PROTOCOL.md §6): status, custom status and activity of the users with a
//! session on this node.
//!
//! Every node keeps the presence of the users connected to it: the client pushes its state to every node
//! it has a session on (its home node and, through federated sessions, the nodes hosting its rooms and
//! conversations), so a node never learns presence of a user who has no session there and nodes never
//! forward presence to each other. A user is online while at least one WebSocket of theirs is open here.
//!
//! - The chosen status (`online`, `dnd`, `invisible`) and the custom status belong to the account and are
//!   stored (`users.presence_status`, `users.custom_status`); `idle` and the activity are per device and
//!   live in memory. The effective status: `offline` without a connection, else `dnd`/`invisible` as
//!   chosen, else `idle` when every connected device is idle, else `online`.
//! - Others see `invisible` as `offline`, never see the activity of a user who hides it, and only see
//!   the presence at all as friends, as co-members of a room the user did not hide their presence in, or
//!   as members of a shared DM or group DM; blocks hide it in both directions.
//! - `presence.update` events are batched: at most one per user and second, carrying the state at the
//!   time of sending; the user's own connections get the unfiltered view.
//! - With several instances (`crate::cache`) each instance announces the open connections per device of its
//!   users and every idle/activity change on the cache bus; every instance keeps that replica next to its own
//!   connections, so a user counts as online (and idle, and doing something) wherever the WebSocket is. The
//!   instance where something changed sends the `presence.update`.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;

use crate::{app::AppState, error::ApiError, models::UserRow, store, util, validate::bad};

/// At most one `presence.update` per user within this interval.
pub const BATCH_INTERVAL: Duration = Duration::from_secs(1);
pub const CUSTOM_TEXT_MAX: usize = 128;
pub const ACTIVITY_TEXT_MAX: usize = 128;
/// Statuses a client may set; `idle` applies to the sending device only.
pub const STATUSES: &[&str] = &["online", "idle", "dnd", "invisible"];
pub const ACTIVITY_TYPES: &[&str] = &["playing", "listening", "watching", "streaming", "competing"];
/// Custom statuses expire at most this far ahead.
pub const CUSTOM_MAX_SECS: i64 = 30 * 24 * 3600;

/// A custom status: text with an optional emoji and expiry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct CustomStatus {
    /// At most 128 characters (may be empty when an emoji is set).
    pub text: String,
    /// One emoji (Unicode) or `:name:` of a custom emoji, at most 32 characters.
    #[serde(default)]
    pub emoji: Option<String>,
    /// RFC 3339; the status disappears afterwards.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// What a user is doing, shown under the name ("Playing …"). Set by the user or a client integration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Activity {
    /// playing | listening | watching | streaming | competing
    #[serde(rename = "type")]
    pub kind: String,
    /// Title, at most 128 characters.
    pub name: String,
    #[serde(default)]
    pub details: Option<String>,
    /// RFC 3339; defaults to the time it was set.
    #[serde(default)]
    pub started_at: Option<String>,
    /// Second line, e.g. "In a party (2 of 4)", at most 128 characters (APPLICATIONS.md §7.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// RFC 3339, after `started_at` (a countdown); null for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    /// The application that reported the activity through the local activity bridge (§7.3); clients show
    /// "via <name>". The node checks the format only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ActivityApplication>,
}

/// The application behind an activity (APPLICATIONS.md §7.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ActivityApplication {
    /// Application reference `<domain>/<id>`.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The application's name, at most 128 characters.
    pub name: String,
}

/// The presence of a user as others see it (`presence.update`, `GET /presence`).
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct Presence {
    pub user_id: String,
    /// `username@domain`
    pub user: String,
    /// online | idle | dnd | offline (the user's own connections may also see `invisible`)
    pub status: String,
    pub custom_status: Option<CustomStatus>,
    pub activity: Option<Activity>,
}

#[derive(Debug, Default)]
struct DeviceState {
    connections: usize,
    idle: bool,
    activity: Option<Activity>,
}

#[derive(Debug, Default)]
struct UserState {
    devices: HashMap<String, DeviceState>,
    last_sent: Option<Instant>,
    pending: bool,
    last_public: Option<Presence>,
}

/// Open connections per device of the users of one other instance: user id → device id → count.
type RemoteUsers = HashMap<String, HashMap<String, usize>>;

/// In-memory presence of the users connected to this node.
#[derive(Default)]
pub struct Registry {
    users: Mutex<HashMap<String, UserState>>,
    /// The connections of the other instances (instance id → users), from the cache bus.
    remote: Mutex<HashMap<String, RemoteUsers>>,
    /// Set when several instances share state: changes are announced on the bus.
    cluster: Option<std::sync::Arc<crate::cache::Cluster>>,
}

/// Keeps a device counted as connected while a WebSocket of it is open.
pub struct Connection {
    state: AppState,
    user_id: String,
    device_id: String,
}

impl Drop for Connection {
    fn drop(&mut self) {
        let registry = &self.state.presence;
        {
            let remote_open = registry.remote_devices(&self.user_id).contains_key(&self.device_id);
            let mut users = registry.lock();
            let Some(user) = users.get_mut(&self.user_id) else { return };
            if let Some(device) = user.devices.get_mut(&self.device_id) {
                device.connections = device.connections.saturating_sub(1);
                if device.connections == 0 && !remote_open {
                    // Idle state and activity belong to the open session of the device.
                    user.devices.remove(&self.device_id);
                }
            }
        }
        registry.announce_connections(&self.user_id);
        changed(&self.state, &self.user_id);
    }
}

/// The effective status from the chosen one and the connected devices.
pub fn effective_status(chosen: &str, connected: bool, all_idle: bool) -> &'static str {
    if !connected {
        return "offline";
    }
    match chosen {
        "dnd" => "dnd",
        "invisible" => "invisible",
        _ if all_idle => "idle",
        _ => "online",
    }
}

/// A custom status unless it expired.
pub fn current_custom(json: Option<&str>) -> Option<CustomStatus> {
    let status: CustomStatus = serde_json::from_str(json?).ok()?;
    match status.expires_at.as_deref().and_then(util::parse_time) {
        Some(t) if t <= chrono::Utc::now() => None,
        _ => Some(status),
    }
}

impl Registry {
    /// A registry that announces its changes on the bus when the instance shares state with others.
    pub fn new(cluster: &std::sync::Arc<crate::cache::Cluster>) -> Self {
        Self { cluster: cluster.is_shared().then(|| cluster.clone()), ..Self::default() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, UserState>> {
        self.users.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn remote_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RemoteUsers>> {
        self.remote.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Devices of `user_id` with a connection on another instance (device id → connections).
    fn remote_devices(&self, user_id: &str) -> HashMap<String, usize> {
        let mut out: HashMap<String, usize> = HashMap::new();
        for users in self.remote_lock().values() {
            for (device, n) in users.get(user_id).into_iter().flatten().filter(|(_, n)| **n > 0) {
                *out.entry(device.clone()).or_default() += n;
            }
        }
        out
    }

    /// `true` while the user has a connection on another instance.
    pub fn remote_online(&self, user_id: &str) -> bool {
        self.remote_lock().values().any(|users| users.get(user_id).is_some_and(|d| d.values().any(|n| *n > 0)))
    }

    /// Tells the other instances the open connections per device of `user_id` here.
    fn announce_connections(&self, user_id: &str) {
        let Some(cluster) = &self.cluster else { return };
        let devices: HashMap<String, usize> = self
            .lock()
            .get(user_id)
            .map(|u| {
                u.devices.iter().filter(|(_, d)| d.connections > 0).map(|(k, d)| (k.clone(), d.connections)).collect()
            })
            .unwrap_or_default();
        cluster.send(crate::cache::Message::PresenceConn { user: user_id.to_string(), devices });
    }

    /// Tells the other instances the idle flag and activity of a device.
    fn announce_attributes(&self, user_id: &str, device_id: &str) {
        let Some(cluster) = &self.cluster else { return };
        let (idle, activity) = self
            .lock()
            .get(user_id)
            .and_then(|u| u.devices.get(device_id))
            .map(|d| (d.idle, d.activity.clone()))
            .unwrap_or_default();
        cluster.send(crate::cache::Message::PresenceAttrs {
            user: user_id.to_string(),
            device: device_id.to_string(),
            idle,
            activity,
        });
    }

    /// Counts a WebSocket of `device_id` until the returned guard is dropped.
    pub fn connect(state: &AppState, user_id: &str, device_id: &str) -> Connection {
        state
            .presence
            .lock()
            .entry(user_id.to_string())
            .or_default()
            .devices
            .entry(device_id.to_string())
            .or_default()
            .connections += 1;
        state.presence.announce_connections(user_id);
        changed(state, user_id);
        Connection { state: state.clone(), user_id: user_id.to_string(), device_id: device_id.to_string() }
    }

    /// Marks the device idle (or active again). Devices without a connection keep the value for when
    /// they connect.
    pub fn set_idle(&self, user_id: &str, device_id: &str, idle: bool) {
        self.lock().entry(user_id.into()).or_default().devices.entry(device_id.into()).or_default().idle = idle;
        self.announce_attributes(user_id, device_id);
    }

    pub fn set_activity(&self, user_id: &str, device_id: &str, activity: Option<Activity>) {
        self.lock().entry(user_id.into()).or_default().devices.entry(device_id.into()).or_default().activity = activity;
        self.announce_attributes(user_id, device_id);
    }

    /// `(connected, all connected devices idle, newest activity, this device idle)`, over the connections of
    /// every instance (idle flags and activities are replicated to all of them).
    fn snapshot(&self, user_id: &str, device_id: Option<&str>) -> (bool, bool, Option<Activity>, bool) {
        let remote = self.remote_devices(user_id);
        let users = self.lock();
        let no_state = DeviceState::default();
        let user = users.get(user_id);
        let devices = user.map(|u| &u.devices);
        let mut connected: Vec<&DeviceState> = devices
            .into_iter()
            .flatten()
            .filter(|(id, d)| d.connections > 0 || remote.contains_key(*id))
            .map(|(_, d)| d)
            .collect();
        // Devices connected elsewhere whose idle flag and activity this instance never heard of.
        for id in remote.keys() {
            if !devices.is_some_and(|d| d.contains_key(id)) {
                connected.push(&no_state);
            }
        }
        let activity =
            connected.iter().filter_map(|d| d.activity.clone()).max_by(|a, b| a.started_at.cmp(&b.started_at));
        let this_idle = device_id.and_then(|d| devices.and_then(|ds| ds.get(d))).is_some_and(|d| d.idle);
        (!connected.is_empty(), !connected.is_empty() && connected.iter().all(|d| d.idle), activity, this_idle)
    }

    /// Forces the next update to be sent to the whole audience even if nothing changed.
    pub fn forget_public(&self, user_id: &str) {
        if let Some(user) = self.lock().get_mut(user_id) {
            user.last_public = None;
        }
    }

    /// Devices with at least one open connection on this instance (metrics).
    pub fn connected_devices(&self) -> usize {
        self.lock().values().map(|u| u.devices.values().filter(|d| d.connections > 0).count()).sum()
    }

    /// Users with at least one open connection (on any instance).
    pub fn online_ids(&self) -> Vec<String> {
        let mut ids: std::collections::HashSet<String> = self
            .lock()
            .iter()
            .filter(|(_, u)| u.devices.values().any(|d| d.connections > 0))
            .map(|(id, _)| id.clone())
            .collect();
        for users in self.remote_lock().values() {
            ids.extend(users.iter().filter(|(_, d)| d.values().any(|n| *n > 0)).map(|(id, _)| id.clone()));
        }
        ids.into_iter().collect()
    }
}

/// `true` while the user has an open WebSocket on any instance of this node.
pub fn is_online(state: &AppState, user_id: &str) -> bool {
    state.hub.is_online(user_id) || state.presence.remote_online(user_id)
}

// ---------------------------------------------------------------- replication between instances

/// Everything this instance knows first-hand: its connected users with their devices.
pub fn sync_message(state: &AppState) -> crate::cache::Message {
    let users = state
        .presence
        .lock()
        .iter()
        .filter_map(|(id, u)| {
            let devices: HashMap<String, crate::cache::DeviceSync> = u
                .devices
                .iter()
                .filter(|(_, d)| d.connections > 0)
                .map(|(k, d)| {
                    let sync = crate::cache::DeviceSync {
                        connections: d.connections,
                        idle: d.idle,
                        activity: d.activity.clone(),
                    };
                    (k.clone(), sync)
                })
                .collect();
            (!devices.is_empty()).then(|| (id.clone(), devices))
        })
        .collect();
    crate::cache::Message::PresenceSync { users }
}

/// Drops idle flags and activities of devices no instance has a connection of any more.
fn drop_disconnected(state: &AppState, user_id: &str) {
    let remote = state.presence.remote_devices(user_id);
    let mut users = state.presence.lock();
    if let Some(user) = users.get_mut(user_id) {
        user.devices.retain(|id, d| d.connections > 0 || remote.contains_key(id));
    }
}

/// [`crate::cache::Message::PresenceConn`] of instance `from`.
pub fn apply_connections(state: &AppState, from: &str, user_id: &str, devices: HashMap<String, usize>) {
    let devices: HashMap<String, usize> = devices.into_iter().filter(|(_, n)| *n > 0).collect();
    let gone = {
        let mut remote = state.presence.remote_lock();
        let users = remote.entry(from.to_string()).or_default();
        let before: Vec<String> = users.get(user_id).map(|d| d.keys().cloned().collect()).unwrap_or_default();
        let gone = before.iter().any(|d| !devices.contains_key(d));
        if devices.is_empty() {
            users.remove(user_id);
        } else {
            users.insert(user_id.to_string(), devices);
        }
        gone
    };
    if gone {
        drop_disconnected(state, user_id);
    }
}

/// [`crate::cache::Message::PresenceSync`] of instance `from`: replaces everything known about it.
pub fn apply_sync(state: &AppState, from: &str, users: HashMap<String, HashMap<String, crate::cache::DeviceSync>>) {
    let mut counts: RemoteUsers = HashMap::new();
    for (user_id, devices) in &users {
        for (device_id, d) in devices {
            apply_attributes(state, user_id, device_id, d.idle, d.activity.clone());
            counts.entry(user_id.clone()).or_default().insert(device_id.clone(), d.connections);
        }
    }
    let previous = state.presence.remote_lock().insert(from.to_string(), counts).unwrap_or_default();
    for user_id in previous.keys().filter(|u| !users.contains_key(*u)) {
        drop_disconnected(state, user_id);
    }
}

/// [`crate::cache::Message::PresenceAttrs`]: the device's idle flag and activity as set on another instance.
pub fn apply_attributes(state: &AppState, user_id: &str, device_id: &str, idle: bool, activity: Option<Activity>) {
    let mut users = state.presence.lock();
    let device = users.entry(user_id.into()).or_default().devices.entry(device_id.into()).or_default();
    device.idle = idle;
    device.activity = activity;
}

/// An instance went away (shutdown or silence): its connections no longer count. The leader tells the audiences.
pub fn forget_instance(state: &AppState, instance: &str) {
    let Some(users) = state.presence.remote_lock().remove(instance) else { return };
    for user_id in users.keys() {
        drop_disconnected(state, user_id);
        if state.cluster.is_leader() {
            changed(state, user_id);
        }
    }
}

/// The presence of `user` as seen by the user (`own`) or by others.
pub fn view(state: &AppState, user: &UserRow, own: bool) -> Presence {
    let (connected, all_idle, activity, _) = state.presence.snapshot(&user.id, None);
    let status = effective_status(&user.presence_status, connected, all_idle);
    let hidden = !own && (status == "invisible" || status == "offline");
    Presence {
        user_id: user.id.clone(),
        user: user.address(),
        status: if hidden { "offline" } else { status }.to_string(),
        custom_status: if hidden { None } else { current_custom(user.custom_status.as_deref()) },
        activity: if hidden || (!own && user.hide_activity != 0) { None } else { activity },
    }
}

/// The user's own presence with the chosen status and this device's idle flag.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MyPresence {
    /// The chosen status: online | dnd | invisible
    pub status: String,
    /// What others see (`invisible` shown as such here): online | idle | dnd | invisible | offline
    pub effective: String,
    /// This device reported itself idle.
    pub idle: bool,
    pub custom_status: Option<CustomStatus>,
    pub activity: Option<Activity>,
    pub hide_activity: bool,
}

pub fn my_view(state: &AppState, user: &UserRow, device_id: &str) -> MyPresence {
    let (connected, all_idle, activity, this_idle) = state.presence.snapshot(&user.id, Some(device_id));
    MyPresence {
        status: user.presence_status.clone(),
        effective: effective_status(&user.presence_status, connected, all_idle).into(),
        idle: this_idle,
        custom_status: current_custom(user.custom_status.as_deref()),
        activity,
        hide_activity: user.hide_activity != 0,
    }
}

/// Users who may see the presence of `user_id`: friends, co-members of rooms in which the user does not
/// hide their presence, members of shared active DMs and group DMs; never blocked or blocking users.
const AUDIENCE: &str = "SELECT a.id FROM (
        SELECT friend_id AS id FROM friends WHERE user_id = $1
        UNION SELECT m2.user_id AS id FROM room_members m1 JOIN room_members m2 ON m2.room_id = m1.room_id
              WHERE m1.user_id = $1 AND m1.hide_presence = 0
        UNION SELECT c2.user_id AS id FROM conversation_members c1
              JOIN conversation_members c2 ON c2.conversation_id = c1.conversation_id
              WHERE c1.user_id = $1 AND c1.state = 'active' AND c2.state = 'active'
    ) a
    WHERE a.id <> $1
      AND a.id NOT IN (SELECT blocked_id FROM user_blocks WHERE user_id = $1)
      AND a.id NOT IN (SELECT user_id FROM user_blocks WHERE blocked_id = $1)";

/// Users whose presence `viewer_id` may see (the reverse direction of [`AUDIENCE`]).
const VISIBLE: &str = "SELECT a.id FROM (
        SELECT friend_id AS id FROM friends WHERE user_id = $1
        UNION SELECT m2.user_id AS id FROM room_members m1 JOIN room_members m2 ON m2.room_id = m1.room_id
              WHERE m1.user_id = $1 AND m2.hide_presence = 0
        UNION SELECT c2.user_id AS id FROM conversation_members c1
              JOIN conversation_members c2 ON c2.conversation_id = c1.conversation_id
              WHERE c1.user_id = $1 AND c1.state = 'active' AND c2.state = 'active'
    ) a
    WHERE a.id <> $1
      AND a.id NOT IN (SELECT blocked_id FROM user_blocks WHERE user_id = $1)
      AND a.id NOT IN (SELECT user_id FROM user_blocks WHERE blocked_id = $1)";

async fn ids(state: &AppState, sql: &str, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(sql).bind(user_id).fetch_all(&state.db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

/// Presences of the online users the viewer may see (`GET /presence`).
pub async fn visible_to(state: &AppState, viewer_id: &str) -> Result<Vec<Presence>, ApiError> {
    let online: std::collections::HashSet<String> = state.presence.online_ids().into_iter().collect();
    let visible: Vec<String> =
        ids(state, VISIBLE, viewer_id).await?.into_iter().filter(|id| online.contains(id)).collect();
    let mut out: Vec<Presence> = store::users::by_ids(&state.db, &visible)
        .await?
        .iter()
        .map(|user| view(state, user, false))
        .filter(|p| p.status != "offline")
        .collect();
    out.sort_by(|a, b| a.user.cmp(&b.user));
    Ok(out)
}

/// Schedules the batched `presence.update` of `user_id` (at most one per [`BATCH_INTERVAL`]).
pub fn changed(state: &AppState, user_id: &str) {
    let wait = {
        let mut users = state.presence.lock();
        let user = users.entry(user_id.to_string()).or_default();
        if user.pending {
            return;
        }
        user.pending = true;
        user.last_sent.map(|t| BATCH_INTERVAL.saturating_sub(t.elapsed())).unwrap_or_default()
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let state = state.clone();
    let user_id = user_id.to_string();
    runtime.spawn(async move {
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        {
            let mut users = state.presence.lock();
            let user = users.entry(user_id.clone()).or_default();
            user.pending = false;
            user.last_sent = Some(Instant::now());
        }
        if let Err(e) = emit(&state, &user_id).await {
            tracing::warn!(error = %e, "presence update not sent");
        }
    });
}

async fn emit(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    let Some(user) = store::users::by_id(&state.db, user_id).await? else { return Ok(()) };
    state.hub.users(vec![user.id.clone()], "presence.update", view(state, &user, true));
    let public = view(state, &user, false);
    let unchanged = {
        let mut users = state.presence.lock();
        let entry = users.entry(user_id.to_string()).or_default();
        let unchanged = entry.last_public.as_ref() == Some(&public);
        entry.last_public = Some(public.clone());
        // Forget users that went away entirely, after telling the others.
        if entry.devices.is_empty() && public.status == "offline" && !entry.pending {
            users.remove(user_id);
        }
        unchanged
    };
    if unchanged {
        return Ok(());
    }
    let audience: Vec<String> =
        ids(state, AUDIENCE, user_id).await?.into_iter().filter(|id| is_online(state, id)).collect();
    if !audience.is_empty() {
        state.hub.users(audience, "presence.update", &public);
    }
    Ok(())
}

/// After a block: both users see each other offline from now on (no further updates reach them).
pub fn hide_between(state: &AppState, a: &UserRow, b: &UserRow) {
    for (from, to) in [(a, b), (b, a)] {
        let offline = Presence {
            user_id: from.id.clone(),
            user: from.address(),
            status: "offline".into(),
            custom_status: None,
            activity: None,
        };
        state.hub.users(vec![to.id.clone()], "presence.update", offline);
    }
}

// ---------------------------------------------------------------- validation

fn optional_text(field: &'static str, v: Option<&str>, max: usize) -> Result<Option<String>, ApiError> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if s.chars().count() <= max && !s.chars().any(char::is_control) => Ok(Some(s.to_string())),
        Some(_) => {
            Err(bad("presence.invalid", format!("{field}: at most {max} characters without control characters")))
        }
    }
}

pub fn validate_status(status: &str) -> Result<&'static str, ApiError> {
    STATUSES
        .iter()
        .find(|s| **s == status)
        .copied()
        .ok_or_else(|| bad("presence.status_invalid", format!("status: allowed are {}", STATUSES.join(", "))))
}

pub fn validate_custom(c: &CustomStatus) -> Result<CustomStatus, ApiError> {
    let text = optional_text("text", Some(&c.text), CUSTOM_TEXT_MAX)?.unwrap_or_default();
    let emoji = optional_text("emoji", c.emoji.as_deref(), 32)?;
    if text.is_empty() && emoji.is_none() {
        return Err(bad("presence.invalid", "Provide a text or an emoji"));
    }
    let expires_at = match c.expires_at.as_deref() {
        None => None,
        Some(s) => {
            let t = util::parse_time(s).ok_or_else(|| bad("presence.invalid", "expires_at: RFC 3339 expected"))?;
            let now = chrono::Utc::now();
            if t <= now || t > now + chrono::Duration::seconds(CUSTOM_MAX_SECS) {
                return Err(bad("presence.invalid", "expires_at: in the future, at most 30 days ahead"));
            }
            Some(util::format_time(t))
        }
    };
    Ok(CustomStatus { text, emoji, expires_at })
}

/// Furthest `ends_at` accepted (a countdown of at most a week).
pub const ACTIVITY_MAX_DURATION_SECS: i64 = 7 * 24 * 3600;

pub fn validate_activity(a: &Activity) -> Result<Activity, ApiError> {
    if !ACTIVITY_TYPES.contains(&a.kind.as_str()) {
        return Err(bad("presence.activity_invalid", format!("type: allowed are {}", ACTIVITY_TYPES.join(", "))));
    }
    let name = optional_text("name", Some(&a.name), ACTIVITY_TEXT_MAX)?
        .ok_or_else(|| bad("presence.activity_invalid", "name missing"))?;
    let details = optional_text("details", a.details.as_deref(), ACTIVITY_TEXT_MAX)?;
    let invalid = |detail: &str| bad("presence.activity_invalid", detail.to_string());
    let state = optional_text("state", a.state.as_deref(), ACTIVITY_TEXT_MAX)
        .map_err(|_| invalid("state: at most 128 characters without control characters"))?;
    let now = chrono::Utc::now();
    let started = match a.started_at.as_deref() {
        None => now,
        Some(s) => match util::parse_time(s) {
            Some(t) if t <= now + chrono::Duration::seconds(60) => t,
            _ => return Err(bad("presence.activity_invalid", "started_at: RFC 3339, not in the future")),
        },
    };
    let ends_at = match a.ends_at.as_deref() {
        None => None,
        Some(s) => match util::parse_time(s) {
            Some(t) if t > started && t <= now + chrono::Duration::seconds(ACTIVITY_MAX_DURATION_SECS) => {
                Some(util::format_time(t))
            }
            _ => return Err(invalid("ends_at: RFC 3339 after started_at, at most 7 days ahead")),
        },
    };
    let application = match &a.application {
        None => None,
        Some(app) => {
            let reference = app.reference.trim();
            let valid_ref = reference.len() <= 300
                && reference
                    .rsplit_once('/')
                    .is_some_and(|(d, id)| util::valid_domain(&d.to_lowercase()) && util::is_ulid(id));
            let app_name = optional_text("application.name", Some(&app.name), ACTIVITY_TEXT_MAX)
                .ok()
                .flatten()
                .ok_or_else(|| invalid("application.name: 1–128 characters"))?;
            if !valid_ref {
                return Err(invalid("application.ref: <domain>/<id>"));
            }
            let (domain, id) = reference.rsplit_once('/').unwrap_or_default();
            Some(ActivityApplication { reference: format!("{}/{id}", domain.to_lowercase()), name: app_name })
        }
    };
    Ok(Activity {
        kind: a.kind.clone(),
        name,
        details,
        started_at: Some(util::format_time(started)),
        state,
        ends_at,
        application,
    })
}

/// Stores the chosen status and/or custom status (`Some(None)` clears it).
pub async fn store_choice(
    state: &AppState,
    user_id: &str,
    status: Option<&str>,
    custom: Option<Option<&CustomStatus>>,
) -> Result<(), ApiError> {
    if let Some(status) = status {
        sqlx::query("UPDATE users SET presence_status = $1 WHERE id = $2")
            .bind(status)
            .bind(user_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(custom) = custom {
        let json = custom.map(|c| serde_json::to_string(c).unwrap_or_default());
        sqlx::query("UPDATE users SET custom_status = $1 WHERE id = $2")
            .bind(json)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        // Others must see the status disappear when it expires.
        if let Some(t) = custom.and_then(|c| c.expires_at.as_deref()).and_then(util::parse_time) {
            let wait = (t - chrono::Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(50);
            let (state, user_id) = (state.clone(), user_id.to_string());
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                changed(&state, &user_id);
            });
        }
    }
    Ok(())
}

/// Hides (or shows) the user's presence for the other members of one room.
pub async fn set_room_hidden(state: &AppState, room_id: &str, user_id: &str, hidden: bool) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET hide_presence = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(hidden as i64)
        .bind(room_id)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn room_hidden(state: &AppState, room_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT hide_presence FROM room_members WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|r| r.try_get::<i64, _>("hide_presence")).transpose()?.unwrap_or(0) != 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn effective_status_rules() {
        assert_eq!(effective_status("online", false, false), "offline");
        assert_eq!(effective_status("dnd", false, false), "offline");
        assert_eq!(effective_status("online", true, false), "online");
        assert_eq!(effective_status("online", true, true), "idle");
        assert_eq!(effective_status("dnd", true, true), "dnd", "dnd wins over idle");
        assert_eq!(effective_status("invisible", true, false), "invisible");
    }

    #[test]
    fn custom_statuses_expire_and_are_validated() {
        let past = serde_json::json!({ "text": "brb", "expires_at": "2000-01-01T00:00:00Z" }).to_string();
        assert_eq!(current_custom(Some(&past)), None);
        let open = serde_json::json!({ "text": "brb", "emoji": "☕" }).to_string();
        assert_eq!(current_custom(Some(&open)).unwrap().emoji.as_deref(), Some("☕"));
        assert_eq!(current_custom(Some("garbage")), None);

        let c =
            |text: &str, expires: Option<String>| CustomStatus { text: text.into(), emoji: None, expires_at: expires };
        assert!(validate_custom(&c("in a raid", None)).is_ok());
        assert_eq!(validate_custom(&c(&"x".repeat(129), None)).unwrap_err().code(), "presence.invalid");
        assert_eq!(validate_custom(&c("", None)).unwrap_err().code(), "presence.invalid");
        assert_eq!(validate_custom(&c("a\u{0}b", None)).unwrap_err().code(), "presence.invalid");
        let soon = util::in_seconds(600);
        assert_eq!(validate_custom(&c("x", Some(soon))).unwrap().text, "x");
        assert!(validate_custom(&c("x", Some("2000-01-01T00:00:00Z".into()))).is_err());
        assert!(validate_custom(&c("x", Some(util::in_seconds(CUSTOM_MAX_SECS + 3600)))).is_err());
    }

    #[test]
    fn activities_and_statuses_are_validated() {
        let a = |kind: &str, name: &str| Activity {
            kind: kind.into(),
            name: name.into(),
            details: None,
            started_at: None,
            state: None,
            ends_at: None,
            application: None,
        };
        let ok = validate_activity(&a("playing", "Factorio")).unwrap();
        assert!(ok.started_at.is_some());
        assert_eq!(validate_activity(&a("hacking", "x")).unwrap_err().code(), "presence.activity_invalid");
        assert_eq!(validate_activity(&a("playing", " ")).unwrap_err().code(), "presence.activity_invalid");
        let future = Activity { started_at: Some(util::in_seconds(3600)), ..a("playing", "x") };
        assert_eq!(validate_activity(&future).unwrap_err().code(), "presence.activity_invalid");
        // Rich presence fields (APPLICATIONS.md §7.2).
        let start = util::in_seconds(-60);
        let rich = Activity {
            state: Some("In a party (2 of 4)".into()),
            started_at: Some(start.clone()),
            ends_at: Some(util::in_seconds(600)),
            application: Some(ActivityApplication {
                reference: format!("Games.Example/{}", util::ulid()),
                name: "Space Miners".into(),
            }),
            ..a("playing", "Space Miners")
        };
        let ok = validate_activity(&rich).unwrap();
        assert_eq!(ok.state.as_deref(), Some("In a party (2 of 4)"));
        let reference = ok.application.unwrap().reference;
        assert!(reference.starts_with("games.example/") && util::is_ulid(reference.rsplit_once('/').unwrap().1));
        let bad_cases = [
            Activity { state: Some("x".repeat(129)), ..rich.clone() },
            Activity { state: Some("a\u{7}b".into()), ..rich.clone() },
            Activity { ends_at: Some(util::in_seconds(-3600)), ..rich.clone() },
            Activity { ends_at: Some("tomorrow".into()), ..rich.clone() },
            Activity { ends_at: Some(util::in_seconds(8 * 24 * 3600)), ..rich.clone() },
            Activity {
                application: Some(ActivityApplication { reference: "nope".into(), name: "x".into() }),
                ..rich.clone()
            },
            Activity {
                application: Some(ActivityApplication {
                    reference: format!("a.test/{}", util::ulid()),
                    name: " ".into(),
                }),
                ..rich.clone()
            },
            Activity {
                application: Some(ActivityApplication {
                    reference: format!("a.test/{}", util::ulid()),
                    name: "x".repeat(129),
                }),
                ..rich.clone()
            },
        ];
        for bad in bad_cases {
            assert_eq!(validate_activity(&bad).unwrap_err().code(), "presence.activity_invalid", "{bad:?}");
        }
        assert_eq!(validate_status("dnd").unwrap(), "dnd");
        assert_eq!(validate_status("busy").unwrap_err().code(), "presence.status_invalid");
    }
}
