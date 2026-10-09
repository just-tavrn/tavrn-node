// SPDX-License-Identifier: AGPL-3.0-only
//! Who may view a room channel, for everything the node fans out per room (PROTOCOL.md §6, FEDERATION.md §5.2,
//! §6d): the WebSocket events of a channel (messages, reactions, pins, typing, threads, voice, files, MLS, …), the
//! `notify` hints to other nodes, web push and the whiteboard's audience reach only the room members with
//! `view_channel` in it at delivery time. The room's metadata events (`room.*`, `channel.*`, `category.*`,
//! `role.*`, `member.*`, `override.*`, …) still reach every member.
//!
//! The permissions are evaluated with [`access::channel_perms_with`], the same function the REST routes use, over a
//! snapshot of the room (roles, overrides, channels, members) that is loaded once and shared by every connection:
//! a channel's viewers are computed once (on the first event that needs them) and then only looked up. The
//! [`Hub`](crate::hub::Hub) drops a room's snapshot synchronously when it publishes (or receives from another
//! instance) an event that can change who views what ([`changes_visibility`]), before any connection sees that
//! event, so the next event of the room is checked against the new state. A snapshot also expires after [`TTL`]
//! (changes without an event, e.g. the node admin flag).

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde_json::Value;

use crate::{
    access,
    app::AppState,
    error::ApiError,
    models::{ChannelRow, MemberRow, OverrideRow, RoleRow, Room, UserRow},
    permissions, store,
};

/// A room snapshot is reloaded after this long even without a change event.
pub const TTL: Duration = Duration::from_secs(60);
/// Rooms whose snapshot is kept at once (beyond, expired ones are dropped first, then all).
const MAX_ROOMS: usize = 4096;

/// Event kinds of the room itself: they reach every member, whatever channel they name.
const METADATA_PREFIXES: &[&str] =
    &["room.", "channel.", "category.", "role.", "member.", "override.", "emoji.", "soundboard.", "commands.", "user."];
/// Event kinds after which the room's snapshot is stale (roles, overrides, channels, membership, room settings).
const CHANGING_PREFIXES: &[&str] = &["room.", "channel.", "category.", "role.", "member.", "override."];

/// Is `kind` a metadata event of the room (delivered to every member)?
pub fn is_metadata(kind: &str) -> bool {
    METADATA_PREFIXES.iter().any(|p| kind.starts_with(p))
}

/// Can an event of `kind` change who may view which channel of its room?
pub fn changes_visibility(kind: &str) -> bool {
    CHANGING_PREFIXES.iter().any(|p| kind.starts_with(p))
}

/// The channels a room event is about.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Refs<'a> {
    /// `conversation_id`, `channel_id` and those of an embedded `thread` or `message`: the event is about each of
    /// them, so the recipient must be able to view all of them.
    pub each: Vec<&'a str>,
    /// `conversation_ids` (a purge over several channels): the recipient must be able to view one of them.
    pub any: Vec<&'a str>,
}

impl Refs<'_> {
    pub fn is_empty(&self) -> bool {
        self.each.is_empty() && self.any.is_empty()
    }
}

/// The channel ids an event's data refers to.
pub fn refs(data: &Value) -> Refs<'_> {
    let mut refs = Refs::default();
    for object in [Some(data), data.get("thread"), data.get("message")].into_iter().flatten() {
        for key in ["conversation_id", "channel_id"] {
            if let Some(id) = object.get(key).and_then(Value::as_str) {
                refs.each.push(id);
            }
        }
    }
    if let Some(list) = data.get("conversation_ids").and_then(Value::as_array) {
        refs.any.extend(list.iter().filter_map(Value::as_str));
    }
    refs
}

/// An event about `refs` is delivered when the recipient can view every channel of `each` and, if `any` is given,
/// one of `any`.
pub fn may_see(refs: &Refs<'_>, can_view: impl Fn(&str) -> bool) -> bool {
    refs.each.iter().all(|c| can_view(c)) && (refs.any.is_empty() || refs.any.iter().any(|c| can_view(c)))
}

/// A member of the room as the snapshot holds it.
pub struct Member {
    pub member: MemberRow,
    /// Role ids without @everyone.
    pub role_ids: Vec<String>,
    pub user: UserRow,
}

/// A snapshot of one room: everything the permission evaluation needs, and the viewers per channel, each computed
/// on first use.
pub struct RoomView {
    pub room: Room,
    roles: Vec<RoleRow>,
    channels: HashMap<String, ChannelRow>,
    overrides: Vec<OverrideRow>,
    members: HashMap<String, Member>,
    viewers: HashMap<String, OnceLock<HashSet<String>>>,
}

impl RoomView {
    pub fn channel(&self, channel_id: &str) -> Option<&ChannelRow> {
        self.channels.get(channel_id)
    }

    pub fn member(&self, user_id: &str) -> Option<&Member> {
        self.members.get(user_id)
    }

    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    /// User ids of the members who may view the channel (empty for an id that is no channel of this room).
    pub fn viewers(&self, channel_id: &str) -> &HashSet<String> {
        static NONE: OnceLock<HashSet<String>> = OnceLock::new();
        match (self.viewers.get(channel_id), self.channels.get(channel_id)) {
            (Some(cell), Some(channel)) => cell.get_or_init(|| self.compute(channel)),
            _ => NONE.get_or_init(HashSet::new),
        }
    }

    pub fn can_view(&self, channel_id: &str, user_id: &str) -> bool {
        self.viewers(channel_id).contains(user_id)
    }

    /// Is an event about `refs` delivered to `user_id` ([`may_see`])?
    pub fn may_see(&self, refs: &Refs<'_>, user_id: &str) -> bool {
        may_see(refs, |c| self.can_view(c, user_id))
    }

    fn compute(&self, channel: &ChannelRow) -> HashSet<String> {
        // Only this channel's and its category's overrides take part.
        let overrides: Vec<OverrideRow> = self
            .overrides
            .iter()
            .filter(|o| {
                (o.target_type == "channel" && o.target_id == channel.id)
                    || (o.target_type == "category" && channel.category_id.as_deref() == Some(o.target_id.as_str()))
            })
            .cloned()
            .collect();
        let mut viewers = HashSet::new();
        for (user_id, m) in &self.members {
            let access = match access::member_access(
                self.room.clone(),
                &self.roles,
                Some(m.member.clone()),
                &m.role_ids,
                &m.user,
            ) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let perms = access::channel_perms_with(&access, channel, &overrides, user_id);
            if permissions::has(perms, permissions::VIEW_CHANNEL) {
                viewers.insert(user_id.clone());
            }
        }
        viewers
    }
}

async fn load(state: &AppState, room_id: &str) -> Result<Option<Arc<RoomView>>, ApiError> {
    let db = &state.db;
    let Some(room) = store::rooms::room_by_id(db, room_id).await? else { return Ok(None) };
    let roles = store::rooms::roles(db, room_id).await?;
    let channels: HashMap<String, ChannelRow> =
        store::rooms::channels(db, room_id).await?.into_iter().map(|c| (c.id.clone(), c)).collect();
    let overrides = store::rooms::overrides_of_room(db, room_id).await?;
    let mut users: HashMap<String, UserRow> =
        store::users::members_of_room(db, room_id).await?.into_iter().map(|u| (u.id.clone(), u)).collect();
    let members = store::rooms::members_with_roles(db, room_id)
        .await?
        .into_iter()
        .filter_map(|(member, role_ids)| {
            let user = users.remove(&member.user_id)?;
            Some((member.user_id.clone(), Member { member, role_ids, user }))
        })
        .collect();
    let viewers = channels.keys().map(|id| (id.clone(), OnceLock::new())).collect();
    Ok(Some(Arc::new(RoomView { room, roles, channels, overrides, members, viewers })))
}

/// One loaded (or loading) snapshot of a room.
pub struct Slot {
    created: Instant,
    stale: AtomicBool,
    view: tokio::sync::OnceCell<Option<Arc<RoomView>>>,
}

impl Slot {
    fn current(&self, now: Instant) -> bool {
        !self.stale.load(Ordering::Acquire) && now.duration_since(self.created) < TTL
    }
}

/// The snapshots of this instance's rooms (lives in the [`Hub`](crate::hub::Hub), which invalidates them).
#[derive(Default)]
pub struct Cache {
    rooms: Mutex<HashMap<String, Arc<Slot>>>,
}

impl Cache {
    fn rooms(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Slot>>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drops the room's snapshot: the next check loads the current state.
    pub fn invalidate(&self, room_id: &str) {
        if let Some(slot) = self.rooms().remove(room_id) {
            slot.stale.store(true, Ordering::Release);
        }
    }

    pub(crate) fn slot(&self, room_id: &str, now: Instant) -> Arc<Slot> {
        let mut rooms = self.rooms();
        if let Some(slot) = rooms.get(room_id)
            && slot.current(now)
        {
            return slot.clone();
        }
        if rooms.len() >= MAX_ROOMS {
            rooms.retain(|_, s| s.current(now));
            if rooms.len() >= MAX_ROOMS {
                rooms.clear();
            }
        }
        let slot = Arc::new(Slot { created: now, stale: AtomicBool::new(false), view: tokio::sync::OnceCell::new() });
        rooms.insert(room_id.to_string(), slot.clone());
        slot
    }
}

async fn view_of(state: &AppState, slot: &Slot, room_id: &str) -> Result<Option<Arc<RoomView>>, ApiError> {
    slot.view.get_or_try_init(|| load(state, room_id)).await.cloned()
}

/// The current snapshot of a room (`None`: the room does not exist).
pub async fn room(state: &AppState, room_id: &str) -> Result<Option<Arc<RoomView>>, ApiError> {
    let slot = state.hub.visibility().slot(room_id, Instant::now());
    view_of(state, &slot, room_id).await
}

/// May `user_id` view the channel `channel_id` of the room? `false` for unknown rooms and channels and when the
/// room cannot be loaded (logged).
pub async fn can_view(state: &AppState, room_id: &str, channel_id: &str, user_id: &str) -> bool {
    match room(state, room_id).await {
        Ok(view) => view.is_some_and(|v| v.can_view(channel_id, user_id)),
        Err(e) => {
            tracing::warn!(error = %e, room_id, "channel visibility could not be determined");
            false
        }
    }
}

/// The visibility check of one WebSocket connection: remembers the snapshot of each of its rooms, so a delivery
/// takes no lock as long as the snapshot is current.
#[derive(Default)]
pub struct Filter {
    slots: HashMap<String, Arc<Slot>>,
}

impl Filter {
    /// Is a room event of `kind` with `data` delivered to `user_id`? Metadata and events about no channel: always;
    /// channel events: when the user may view the channel(s). Fails closed when the room cannot be loaded.
    pub async fn delivers(&mut self, state: &AppState, room_id: &str, kind: &str, data: &Value, user_id: &str) -> bool {
        if is_metadata(kind) {
            return true;
        }
        let refs = refs(data);
        if refs.is_empty() {
            return true;
        }
        let now = Instant::now();
        let slot = match self.slots.get(room_id) {
            Some(slot) if slot.current(now) => slot.clone(),
            _ => {
                let slot = state.hub.visibility().slot(room_id, now);
                self.slots.insert(room_id.to_string(), slot.clone());
                slot
            }
        };
        match view_of(state, &slot, room_id).await {
            Ok(view) => view.is_some_and(|v| v.may_see(&refs, user_id)),
            Err(e) => {
                tracing::warn!(error = %e, room_id, "channel visibility could not be determined, event dropped");
                false
            }
        }
    }

    /// Forgets a room the connection left.
    pub fn forget(&mut self, room_id: &str) {
        self.slots.remove(room_id);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_hub_drops_a_room_s_snapshot_with_the_events_that_change_it() {
        let hub = crate::hub::Hub::new();
        let now = Instant::now();
        let r1 = hub.visibility().slot("r1", now);
        let r2 = hub.visibility().slot("r2", now);
        assert!(Arc::ptr_eq(&r1, &hub.visibility().slot("r1", now)), "shared while current");
        hub.room("r1", "message.create", json!({ "conversation_id": "c" }));
        hub.users(vec!["u".into()], "member.join", json!({}));
        assert!(r1.current(now), "messages and user events change nothing");
        hub.room("r1", "override.update", json!({ "room_id": "r1" }));
        assert!(!r1.current(now), "a connection holding the old snapshot sees that it is stale");
        assert!(!Arc::ptr_eq(&r1, &hub.visibility().slot("r1", now)), "the next check loads anew");
        assert!(r2.current(now), "other rooms keep theirs");
        hub.inject("e".into(), "member.leave".into(), crate::hub::Scope::Room("r2".into()), "{}".into());
        assert!(!r2.current(now), "events of other instances too");
        assert!(!r2.current(now + TTL) && !hub.visibility().slot("r3", now).current(now + TTL), "expiry");
    }

    #[test]
    fn events_name_their_channels() {
        let r = |v: &Value| {
            let r = refs(v);
            (
                r.each.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                r.any.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(r(&json!({ "conversation_id": "c1", "id": "m1" })).0, ["c1"]);
        assert_eq!(r(&json!({ "room_id": "r", "channel_id": "c2", "user_id": "u" })).0, ["c2"]);
        assert_eq!(r(&json!({ "room_id": "r", "thread": { "channel_id": "c3" } })).0, ["c3"]);
        assert_eq!(r(&json!({ "message": { "conversation_id": "c6" } })).0, ["c6"]);
        assert_eq!(r(&json!({ "room_id": "r", "conversation_ids": ["c4", "c5"] })).1, ["c4", "c5"]);
        assert!(refs(&json!({ "room_id": "r", "user": {} })).is_empty());
    }

    #[test]
    fn every_named_channel_or_one_of_a_list_must_be_viewable() {
        let visible = |c: &str| c.starts_with("open");
        let check = |each: &[&str], any: &[&str]| may_see(&Refs { each: each.to_vec(), any: any.to_vec() }, visible);
        assert!(check(&[], &[]));
        assert!(check(&["open1"], &[]));
        assert!(check(&["open1", "open2"], &[]));
        assert!(!check(&["open1", "secret"], &[]));
        assert!(!check(&["secret"], &[]));
        assert!(check(&[], &["secret", "open1"]), "a purge over several channels: one is enough");
        assert!(!check(&[], &["secret", "hidden"]));
        assert!(!check(&["secret"], &["open1"]));
    }

    #[test]
    fn metadata_and_changes() {
        for kind in
            ["room.update", "channel.update", "category.delete", "role.create", "member.join", "override.update"]
        {
            assert!(is_metadata(kind) && changes_visibility(kind), "{kind}");
        }
        for kind in ["emoji.update", "soundboard.update", "commands.update", "user.update", "user.deleted"] {
            assert!(is_metadata(kind) && !changes_visibility(kind), "{kind}");
        }
        for kind in
            ["message.create", "message.purge", "typing", "thread.create", "voice.state", "files.update", "mls.commit"]
        {
            assert!(!is_metadata(kind) && !changes_visibility(kind), "{kind}");
        }
    }
}
