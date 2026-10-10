// SPDX-License-Identifier: AGPL-3.0-only
//! Real-time distributor: events are broadcast process-wide to all WebSocket connections; each
//! connection filters by scope (room membership, users).
//!
//! With several instances (`crate::cache`) every event is also handed to the cache bus, serialized once, and the
//! other instances [`Hub::inject`] it into their own broadcast: a WebSocket on any instance gets every event.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::extract::ws::Utf8Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};

use crate::util::ulid;

/// `kind` of the local event that tells every connection to resync (`{"op":"resync"}`), see [`Hub::resync_all`].
pub const RESYNC_KIND: &str = "resync";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "to", content = "ids", rename_all = "snake_case")]
pub enum Scope {
    /// All members of a room.
    Room(String),
    /// Exactly these users.
    Users(Vec<String>),
    /// Exactly these devices (device ids), e.g. MLS Welcomes for added devices.
    Devices(Vec<String>),
    /// These users except one device (local device id): ephemeral events skip the sending connection.
    UsersExceptDevice { users: Vec<String>, device: String },
    /// Every connection of this instance (only the local resync hint, never sent over the bus).
    All,
    /// Exactly one WebSocket connection (a bot's receiving connection, APPLICATIONS.md §5.6).
    Connection(u64),
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub data: Value,
    #[serde(skip)]
    pub scope: Scope,
    /// The WebSocket frame `{"op":"event","id":…,"type":…,"data":…}`, serialized once in [`Hub::publish`]
    /// and shared by every connection that delivers it (a clone only bumps a reference count).
    #[serde(skip)]
    pub frame: Utf8Bytes,
}

/// Borrowed view of an event as sent to clients (serializes `data` without cloning it).
#[derive(Serialize)]
struct Frame<'a> {
    op: &'static str,
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    data: &'a Value,
}

impl Event {
    fn new(id: String, kind: &str, data: Value, scope: Scope) -> Self {
        // Serializing a `Value` cannot fail (string keys only); fall back to a resync just in case.
        let frame = serde_json::to_string(&Frame { op: "event", id: &id, kind, data: &data })
            .unwrap_or_else(|_| String::from(r#"{"op":"resync"}"#));
        Self { id, kind: kind.to_string(), data, scope, frame: frame.into() }
    }
}

#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<Arc<Event>>,
    /// Open WebSocket connections per user id (for `notify` hints to remote members, FEDERATION.md §5.2).
    online: Arc<Mutex<HashMap<String, usize>>>,
    /// The cache bus of a node with several instances (`None` standalone).
    bus: Option<mpsc::UnboundedSender<crate::cache::Outbound>>,
    /// Who may view which room channel (`crate::visibility`), dropped per room by the events that change it.
    visibility: Arc<crate::visibility::Cache>,
    /// The moved voice participations per room as the leader announced them (`crate::voice::moved`).
    moved: Arc<crate::voice::moved::Index>,
}

/// Counts one open WebSocket of a user while it lives.
pub struct Presence {
    online: Arc<Mutex<HashMap<String, usize>>>,
    user_id: String,
}

impl Drop for Presence {
    fn drop(&mut self) {
        let mut online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = online.get_mut(&self.user_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                online.remove(&self.user_id);
            }
        }
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        Self::with_bus(None)
    }

    /// A hub that also hands every event to the cache bus (several instances).
    pub fn with_bus(bus: Option<mpsc::UnboundedSender<crate::cache::Outbound>>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { tx, online: Arc::default(), bus, visibility: Arc::default(), moved: Arc::default() }
    }

    /// The channel visibility snapshots of this instance (`crate::visibility`).
    pub fn visibility(&self) -> &crate::visibility::Cache {
        &self.visibility
    }

    /// The moved voice participations of this instance's rooms (`crate::voice::moved`).
    pub fn moved(&self) -> &crate::voice::moved::Index {
        &self.moved
    }

    /// A room event that changes roles, overrides, channels or membership drops the room's visibility snapshot
    /// before any connection receives it: the events after it are checked against the new state. An announcement of
    /// the room's moved voice participations is taken first and drops the snapshot when the set changed.
    fn invalidate(&self, kind: &str, scope: &Scope, data: &Value) {
        let Scope::Room(room_id) = scope else { return };
        if kind == crate::voice::moved::EVENT {
            if self.moved.apply(room_id, data) {
                self.visibility.invalidate(room_id);
            }
        } else if crate::visibility::changes_visibility(kind) {
            self.visibility.invalidate(room_id);
        }
    }

    /// Registers an open WebSocket of `user_id` until the returned guard is dropped.
    pub fn connect(&self, user_id: &str) -> Presence {
        *self.online.lock().unwrap_or_else(|e| e.into_inner()).entry(user_id.to_string()).or_insert(0) += 1;
        Presence { online: self.online.clone(), user_id: user_id.to_string() }
    }

    /// Open WebSocket connections of users on this instance (metrics).
    pub fn connections(&self) -> usize {
        self.online.lock().unwrap_or_else(|e| e.into_inner()).values().sum()
    }

    /// `true` while the user has at least one open WebSocket on this node.
    /// Open WebSocket connections of `user_id` on this instance.
    pub fn connections_of(&self, user_id: &str) -> usize {
        self.online.lock().unwrap_or_else(|e| e.into_inner()).get(user_id).copied().unwrap_or(0)
    }

    pub fn is_online(&self, user_id: &str) -> bool {
        self.online.lock().unwrap_or_else(|e| e.into_inner()).get(user_id).is_some_and(|n| *n > 0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.tx.subscribe()
    }

    pub fn publish(&self, kind: &str, scope: Scope, data: impl Serialize) -> String {
        let id = ulid();
        let event = Arc::new(Event::new(id.clone(), kind, serde_json::to_value(data).unwrap_or(Value::Null), scope));
        self.invalidate(kind, &event.scope, &event.data);
        // Connection ids are per instance: a single-connection event never travels over the bus.
        if let Some(bus) = &self.bus
            && !matches!(event.scope, Scope::Connection(_))
        {
            let _ = bus.send(crate::cache::Outbound::Event(event.clone()));
        }
        // No receiver is not an error (nobody connected).
        let _ = self.tx.send(event);
        id
    }

    /// An event another instance published (its frame as that instance serialized it).
    pub fn inject(&self, id: String, kind: String, scope: Scope, frame: String) {
        if matches!(scope, Scope::All | Scope::Connection(_)) {
            return;
        }
        #[derive(serde::Deserialize)]
        struct Data {
            #[serde(default)]
            data: Value,
        }
        let data = serde_json::from_str::<Data>(&frame).map(|d| d.data).unwrap_or(Value::Null);
        self.invalidate(&kind, &scope, &data);
        let _ = self.tx.send(Arc::new(Event { id, kind, data, scope, frame: frame.into() }));
    }

    /// Tells every connection of this instance to reload its state (`{"op":"resync"}`): events may have been lost.
    pub fn resync_all(&self) {
        let event = Event {
            id: ulid(),
            kind: RESYNC_KIND.into(),
            data: Value::Null,
            scope: Scope::All,
            frame: r#"{"op":"resync"}"#.into(),
        };
        let _ = self.tx.send(Arc::new(event));
    }

    pub fn room(&self, room_id: &str, kind: &str, data: impl Serialize) -> String {
        self.publish(kind, Scope::Room(room_id.to_string()), data)
    }

    pub fn users(&self, user_ids: Vec<String>, kind: &str, data: impl Serialize) -> String {
        self.publish(kind, Scope::Users(user_ids), data)
    }

    pub fn devices(&self, device_ids: Vec<String>, kind: &str, data: impl Serialize) -> String {
        self.publish(kind, Scope::Devices(device_ids), data)
    }

    /// To `user_ids` except the device `except_device` (a local device id).
    pub fn users_except_device(
        &self,
        user_ids: Vec<String>,
        except_device: &str,
        kind: &str,
        data: impl Serialize,
    ) -> String {
        self.publish(kind, Scope::UsersExceptDevice { users: user_ids, device: except_device.to_string() }, data)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn events_reach_subscribers_in_order() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        let a = hub.room("r1", "message.create", serde_json::json!({ "id": "m1" }));
        let b = hub.users(vec!["u1".into()], "friend.request", serde_json::json!({}));
        let e1 = rx.recv().await.unwrap();
        let e2 = rx.recv().await.unwrap();
        assert_eq!(e1.id, a);
        assert_eq!(e1.kind, "message.create");
        assert!(matches!(e1.scope, Scope::Room(ref r) if r == "r1"));
        assert_eq!(e2.id, b);
        assert!(a < b, "event ids sort by time");
    }

    #[tokio::test]
    async fn frame_is_serialized_once_and_shared() {
        let hub = Hub::new();
        let mut rx1 = hub.subscribe();
        let mut rx2 = hub.subscribe();
        let data =
            serde_json::json!({ "id": "m1", "content": { "type": "text", "body": "hi \"there\" <b>" }, "n": [1, 2] });
        let id = hub.devices(vec!["d1".into()], "message.create", data.clone());
        let a = rx1.recv().await.unwrap();
        let b = rx2.recv().await.unwrap();
        // The frame is exactly what clients used to get from `json!({ op, id, type, data })`.
        let frame: Value = serde_json::from_str(&a.frame).unwrap();
        assert_eq!(frame, serde_json::json!({ "op": "event", "id": id, "type": "message.create", "data": data }));
        // Both subscribers share one allocation: no serialization per connection.
        assert_eq!(a.frame.as_ptr(), b.frame.as_ptr());
        assert!(matches!(&a.scope, Scope::Devices(d) if d == &["d1".to_string()]));
    }

    #[tokio::test]
    async fn events_go_to_the_bus_and_injected_ones_stay_local() {
        let (tx, mut bus) = mpsc::unbounded_channel();
        let hub = Hub::with_bus(Some(tx));
        let mut rx = hub.subscribe();
        let id = hub.users(vec!["u1".into()], "friend.request", serde_json::json!({ "x": 1 }));
        let sent = match bus.recv().await.unwrap() {
            crate::cache::Outbound::Event(e) => e,
            crate::cache::Outbound::Message(_) => unreachable!("an event"),
        };
        assert_eq!(sent.id, id);
        assert_eq!(rx.recv().await.unwrap().id, id);
        // Another instance's event reaches the local connections with its data, but not the bus again.
        let frame = sent.frame.as_str().to_string();
        hub.inject("e2".into(), "friend.request".into(), Scope::Users(vec!["u1".into()]), frame.clone());
        let injected = rx.recv().await.unwrap();
        assert_eq!((injected.id.as_str(), injected.frame.as_str()), ("e2", frame.as_str()));
        assert_eq!(injected.data, serde_json::json!({ "x": 1 }));
        assert!(bus.try_recv().is_err());
        hub.resync_all();
        let r = rx.recv().await.unwrap();
        assert_eq!((r.kind.as_str(), r.frame.as_str(), &r.scope), (RESYNC_KIND, r#"{"op":"resync"}"#, &Scope::All));
        assert!(bus.try_recv().is_err(), "the resync hint is local");
    }

    #[test]
    fn scopes_serialize_for_the_bus() {
        for s in [
            Scope::Room("r".into()),
            Scope::Users(vec!["a".into()]),
            Scope::Devices(vec![]),
            Scope::UsersExceptDevice { users: vec!["a".into()], device: "d".into() },
        ] {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(serde_json::from_str::<Scope>(&json).unwrap(), s);
        }
    }

    #[test]
    fn presence_counts_open_connections() {
        let hub = Hub::new();
        assert!(!hub.is_online("u1"));
        let first = hub.connect("u1");
        let second = hub.connect("u1");
        assert!(hub.is_online("u1"));
        assert!(!hub.is_online("u2"));
        drop(first);
        assert!(hub.is_online("u1"), "one connection is still open");
        drop(second);
        assert!(!hub.is_online("u1"));
    }
}
