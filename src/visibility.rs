// SPDX-License-Identifier: AGPL-3.0-only
//! Who may view a room channel, for everything the node fans out per room (PROTOCOL.md §6, FEDERATION.md §5.2,
//! §6d): the WebSocket events of a channel (messages, reactions, pins, typing, threads, voice, files, MLS, …), the
//! `notify` hints to other nodes, web push and the whiteboard's audience reach only the room members with
//! `view_channel` in it at delivery time.
//!
//! The metadata of a private channel follows the same audience (PROTOCOL.md §6 "Audiences"): `channel.*` and
//! `override.update` of a channel reach the members to whom the channel is listed (`view_channel` without the age
//! gate, as in `GET /rooms/{id}`), `category.*` and a category's `override.update` the members to whom the
//! category is listed (one of its channels is, or they manage channels). The other metadata events (`room.*`,
//! `role.*`, `member.*`, `emoji.*`, …) reach every member. Each connection remembers what its user knows of each
//! room ([`Known`]); after an event that changes visibility it compares, and sends `channel.create` (with the
//! `category.create` of a category the user did not know) for channels the user gained and `channel.delete` /
//! `category.delete` with `hidden: true` for those they lost.
//!
//! The permissions are evaluated with [`access::channel_perms_with`], the same function the REST routes use, over a
//! snapshot of the room (roles, overrides, channels, categories, members) that is loaded once and shared by every
//! connection: a channel's viewers are computed once (on the first event that needs them) and then only looked up.
//! The [`Hub`](crate::hub::Hub) drops a room's snapshot synchronously when it publishes (or receives from another
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
    models::{Category, ChannelRow, MemberRow, OverrideRow, RoleRow, Room, UserRow},
    permissions, store,
};

/// A room snapshot is reloaded after this long even without a change event.
pub const TTL: Duration = Duration::from_secs(60);
/// Rooms whose snapshot is kept at once (beyond, expired ones are dropped first, then all).
const MAX_ROOMS: usize = 4096;

/// Event kinds of the room itself: not about a channel's content (their audience: [`Filter::deliver`]).
const METADATA_PREFIXES: &[&str] =
    &["room.", "channel.", "category.", "role.", "member.", "override.", "emoji.", "soundboard.", "commands.", "user."];
/// Event kinds after which the room's snapshot is stale (roles, overrides, channels, membership, room settings).
const CHANGING_PREFIXES: &[&str] = &["room.", "channel.", "category.", "role.", "member.", "override."];

/// Is `kind` a metadata event of the room (not filtered by the channels its data names)?
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
    /// Passes `adults_only` gates (`age::is_adult`): below a channel's gate the member cannot view it (§5e).
    pub adult: bool,
    /// The voice channel of the member's moved participation (`voice::moved`): they view it while it lasts.
    pub moved: Option<String>,
}

/// A snapshot of one room: everything the permission evaluation needs, and the viewers per channel, each computed
/// on first use.
pub struct RoomView {
    pub room: Room,
    roles: Arc<Vec<RoleRow>>,
    channels: HashMap<String, ChannelRow>,
    categories: HashMap<String, Category>,
    overrides: Vec<OverrideRow>,
    members: HashMap<String, Member>,
    viewers: HashMap<String, OnceLock<HashSet<String>>>,
    /// Per channel the members to whom it is listed: viewers when the age gate is left aside (PROTOCOL.md §5e).
    listers: HashMap<String, OnceLock<HashSet<String>>>,
    /// Members with `manage_channels` room-wide: every category is listed to them.
    managers: OnceLock<HashSet<String>>,
}

/// What a member knows of a room: the channels and categories listed to them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Known {
    pub channels: HashSet<String>,
    pub categories: HashSet<String>,
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
            (Some(cell), Some(channel)) => cell.get_or_init(|| self.compute(channel, false)),
            _ => NONE.get_or_init(HashSet::new),
        }
    }

    /// User ids of the members to whom the channel is listed (its viewers, age gate aside).
    pub fn listers(&self, channel_id: &str) -> &HashSet<String> {
        static NONE: OnceLock<HashSet<String>> = OnceLock::new();
        match (self.listers.get(channel_id), self.channels.get(channel_id)) {
            (Some(cell), Some(channel)) => cell.get_or_init(|| self.compute(channel, true)),
            _ => NONE.get_or_init(HashSet::new),
        }
    }

    /// The channels and categories listed to `user_id` (as in `GET /rooms/{id}`).
    pub fn known_by(&self, user_id: &str) -> Known {
        let channels: HashSet<String> =
            self.channels.keys().filter(|c| self.listers(c).contains(user_id)).cloned().collect();
        let manager = self.managers.get_or_init(|| {
            self.members.keys().filter(|u| self.holds(u, permissions::MANAGE_CHANNELS)).cloned().collect()
        });
        let categories = if manager.contains(user_id) {
            self.categories.keys().cloned().collect()
        } else {
            channels.iter().filter_map(|c| self.channels.get(c)?.category_id.clone()).collect()
        };
        Known { channels, categories }
    }

    pub fn category(&self, category_id: &str) -> Option<&Category> {
        self.categories.get(category_id)
    }

    pub fn can_view(&self, channel_id: &str, user_id: &str) -> bool {
        self.viewers(channel_id).contains(user_id)
    }

    /// Is an event about `refs` delivered to `user_id` ([`may_see`])?
    pub fn may_see(&self, refs: &Refs<'_>, user_id: &str) -> bool {
        may_see(refs, |c| self.can_view(c, user_id))
    }

    /// The room's overrides (every target).
    pub fn overrides(&self) -> &[OverrideRow] {
        &self.overrides
    }

    /// The id of the room's `@everyone` role.
    pub fn everyone_id(&self) -> Option<&str> {
        self.roles.iter().find(|r| r.is_everyone != 0).map(|r| r.id.as_str())
    }

    /// The channels of the room.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelRow> {
        self.channels.values()
    }

    /// Every member's permissions in `channel` as if the room's overrides were `overrides` (the channel's and its
    /// category's take part): the evaluation of the REST routes, for a planned change (`routes::channels`).
    pub fn perms_with(&self, channel: &ChannelRow, overrides: &[OverrideRow]) -> HashMap<String, permissions::Perms> {
        // Only this channel's and its category's overrides take part.
        let overrides: Vec<OverrideRow> = overrides
            .iter()
            .filter(|o| {
                (o.target_type == "channel" && o.target_id == channel.id)
                    || (o.target_type == "category" && channel.category_id.as_deref() == Some(o.target_id.as_str()))
            })
            .cloned()
            .collect();
        self.members
            .keys()
            .filter_map(|user_id| Some((user_id.clone(), self.member_perms_with(channel, &overrides, user_id, false)?)))
            .collect()
    }

    /// A member's permissions in a channel of the room (`None`: no member, or no such channel).
    pub fn perms(&self, channel_id: &str, user_id: &str) -> Option<permissions::Perms> {
        self.member_perms_with(self.channels.get(channel_id)?, &self.overrides, user_id, false)
    }

    /// The channel `channel_id` as a conversation of the member `user` (the requester's own row: its kind, scopes and
    /// node admin flag count), evaluated on the snapshot with the REST routes' rules (`access::conversation`):
    /// `None` when `user` is no member of the snapshot or the channel is not in it (the caller asks the database).
    pub fn conversation(&self, channel_id: &str, user: &UserRow) -> Option<Result<access::Conv, ApiError>> {
        let channel = self.channels.get(channel_id)?.clone();
        let m = self.members.get(&user.id)?;
        let access = match access::member_access(
            self.room.clone(),
            &self.roles,
            Some(m.member.clone()),
            &m.role_ids,
            user,
            m.adult,
            m.moved.clone(),
        ) {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };
        if let Err(e) = access::require_age(&access, &channel) {
            return Some(Err(e));
        }
        let perms = access::channel_perms_with(&access, &channel, &self.overrides, &user.id);
        Some(Ok(access::Conv {
            id: channel.id.clone(),
            encrypted: channel.encrypted != 0,
            perms,
            kind: access::ConvKind::Channel { access: Box::new(access), channel },
        }))
    }

    /// Does the member hold `bits` room-wide (roles only, no channel)?
    pub fn holds(&self, user_id: &str, bits: permissions::Perms) -> bool {
        self.access(user_id).is_some_and(|a| permissions::has(a.room_perms, bits))
    }

    fn access(&self, user_id: &str) -> Option<access::RoomAccess> {
        let m = self.members.get(user_id)?;
        access::member_access(
            self.room.clone(),
            &self.roles,
            Some(m.member.clone()),
            &m.role_ids,
            &m.user,
            m.adult,
            m.moved.clone(),
        )
        .ok()
    }

    /// `ignore_age`: as if the member passed every age gate (the channel is listed below the gate, §5e).
    fn member_perms_with(
        &self,
        channel: &ChannelRow,
        overrides: &[OverrideRow],
        user_id: &str,
        ignore_age: bool,
    ) -> Option<permissions::Perms> {
        let mut access = self.access(user_id)?;
        access.adult |= ignore_age;
        Some(access::channel_perms_with(&access, channel, overrides, user_id))
    }

    fn compute(&self, channel: &ChannelRow, ignore_age: bool) -> HashSet<String> {
        let overrides: Vec<OverrideRow> = self
            .overrides
            .iter()
            .filter(|o| {
                (o.target_type == "channel" && o.target_id == channel.id)
                    || (o.target_type == "category" && channel.category_id.as_deref() == Some(o.target_id.as_str()))
            })
            .cloned()
            .collect();
        self.members
            .keys()
            .filter(|user_id| {
                self.member_perms_with(channel, &overrides, user_id, ignore_age)
                    .is_some_and(|perms| permissions::has(perms, permissions::VIEW_CHANNEL))
            })
            .cloned()
            .collect()
    }
}

/// Loads the room's current state from the database (no cache).
pub async fn load(state: &AppState, room_id: &str) -> Result<Option<Arc<RoomView>>, ApiError> {
    let db = &state.db;
    let Some(room) = store::rooms::room_by_id(db, room_id).await? else { return Ok(None) };
    let roles = Arc::new(store::rooms::roles(db, room_id).await?);
    let channels: HashMap<String, ChannelRow> =
        store::rooms::channels(db, room_id).await?.into_iter().map(|c| (c.id.clone(), c)).collect();
    let overrides = store::rooms::overrides_of_room(db, room_id).await?;
    let mut users: HashMap<String, UserRow> =
        store::users::members_of_room(db, room_id).await?.into_iter().map(|u| (u.id.clone(), u)).collect();
    let mut moved = crate::voice::moved::of_room(state, room_id);
    let mut members = HashMap::new();
    for (member, role_ids) in store::rooms::members_with_roles(db, room_id).await? {
        let Some(user) = users.remove(&member.user_id) else { continue };
        let adult = crate::age::is_adult(state, &user).await?;
        let moved = moved.remove(&member.user_id);
        members.insert(member.user_id.clone(), Member { member, role_ids, user, adult, moved });
    }
    let categories = store::rooms::categories(db, room_id).await?.into_iter().map(|c| (c.id.clone(), c)).collect();
    let viewers = channels.keys().map(|id| (id.clone(), OnceLock::new())).collect();
    let listers = channels.keys().map(|id| (id.clone(), OnceLock::new())).collect();
    Ok(Some(Arc::new(RoomView {
        room,
        roles,
        channels,
        categories,
        overrides,
        members,
        viewers,
        listers,
        managers: OnceLock::new(),
    })))
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
/// takes no lock as long as the snapshot is current, and what its user knows of each room ([`Known`]).
#[derive(Default)]
pub struct Filter {
    slots: HashMap<String, Arc<Slot>>,
    known: HashMap<String, Known>,
}

/// What a connection sends for one room event: first `before` (frames the connection makes itself: channels and
/// categories the user gained or lost), then the event when `event`, then `after` (the channels gained in the
/// category a `category.create` creates, which must follow it).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    pub before: Vec<String>,
    pub event: bool,
    pub after: Vec<String>,
}

impl Delivery {
    fn event(event: bool) -> Self {
        Self { before: Vec::new(), event, after: Vec::new() }
    }
}

/// The metadata events whose audience is a channel's or category's (`None`: every member).
enum Target<'a> {
    Channel(&'a str),
    Category(&'a str),
}

fn target<'a>(kind: &str, data: &'a Value) -> Option<Target<'a>> {
    let id = || data.get("id").and_then(Value::as_str);
    match kind {
        _ if kind.starts_with("channel.") => id().map(Target::Channel),
        _ if kind.starts_with("category.") => id().map(Target::Category),
        "override.update" => {
            let id = data.get("target_id").and_then(Value::as_str)?;
            match data.get("target_type").and_then(Value::as_str)? {
                "category" => Some(Target::Category(id)),
                _ => Some(Target::Channel(id)),
            }
        }
        _ => None,
    }
}

/// A WebSocket frame made by the connection itself, shaped like the hub's (`{"op":"event",…}`).
fn frame(kind: &str, data: Value) -> String {
    serde_json::json!({ "op": "event", "id": crate::util::ulid(), "type": kind, "data": data }).to_string()
}

/// The frames that tell a member what they gained and lost between `old` and `new` (`skip`: the channel or
/// category the event itself creates or deletes): `category.create` before the first channel of a category the
/// member did not know, `channel.create` in channel order, then `channel.delete` and `category.delete` with
/// `hidden: true`. The channels gained in the skipped category come second: they follow the event that creates
/// it (a lagging connection already sees them when it delivers the `category.create`).
fn changes(view: &RoomView, old: &Known, new: &Known, skip: Option<&str>) -> (Vec<String>, Vec<String>) {
    let room_id = view.room.id.as_str();
    let not_skipped = |id: &&String| skip != Some(id.as_str());
    let mut gained_categories: Vec<&String> = new.categories.difference(&old.categories).filter(not_skipped).collect();
    gained_categories.sort();
    let mut gained: Vec<&ChannelRow> =
        new.channels.difference(&old.channels).filter(not_skipped).filter_map(|c| view.channel(c)).collect();
    gained.sort_by(|a, b| (a.position, &a.id).cmp(&(b.position, &b.id)));
    let mut frames = Vec::new();
    let mut announced = HashSet::new();
    let mut category = |id: &str, frames: &mut Vec<String>| {
        if gained_categories.iter().any(|c| c.as_str() == id)
            && announced.insert(id.to_string())
            && let Some(category) = view.category(id)
        {
            frames.push(frame("category.create", serde_json::to_value(category).unwrap_or_default()));
        }
    };
    let mut after = Vec::new();
    for channel in gained {
        let created = frame("channel.create", serde_json::to_value(channel.to_api()).unwrap_or_default());
        match channel.category_id.as_deref() {
            Some(id) if skip == Some(id) => after.push(created),
            Some(id) => {
                category(id, &mut frames);
                frames.push(created);
            }
            None => frames.push(created),
        }
    }
    for id in &gained_categories {
        category(id, &mut frames);
    }
    let mut lost: Vec<&String> = old.channels.difference(&new.channels).filter(not_skipped).collect();
    lost.sort();
    for id in lost {
        frames.push(frame("channel.delete", serde_json::json!({ "room_id": room_id, "id": id, "hidden": true })));
    }
    let mut lost: Vec<&String> = old.categories.difference(&new.categories).filter(not_skipped).collect();
    lost.sort();
    for id in lost {
        frames.push(frame("category.delete", serde_json::json!({ "room_id": room_id, "id": id, "hidden": true })));
    }
    (frames, after)
}

impl Filter {
    async fn view(&mut self, state: &AppState, room_id: &str) -> Result<Option<Arc<RoomView>>, ApiError> {
        let now = Instant::now();
        let slot = match self.slots.get(room_id) {
            Some(slot) if slot.current(now) => slot.clone(),
            _ => {
                let slot = state.hub.visibility().slot(room_id, now);
                self.slots.insert(room_id.to_string(), slot.clone());
                slot
            }
        };
        view_of(state, &slot, room_id).await
    }

    /// Remembers what `user_id` knows of each room (at the start of a connection, before its first event).
    pub async fn know(&mut self, state: &AppState, room_ids: impl IntoIterator<Item = &String>, user_id: &str) {
        for room_id in room_ids {
            match self.view(state, room_id).await {
                Ok(Some(view)) => {
                    self.known.insert(room_id.clone(), view.known_by(user_id));
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, room_id, "channel visibility could not be determined"),
            }
        }
    }

    /// What a room event of `kind` with `data` becomes for `user_id`. Channel events: delivered when the user may
    /// view the channel(s). Metadata of a channel or category: delivered when it is listed to the user (before the
    /// event for a deletion). Other metadata and events about no channel: always. After an event that changes
    /// visibility, the frames for what the user gained or lost come first. Fails closed when the room cannot be
    /// loaded.
    pub async fn deliver(
        &mut self,
        state: &AppState,
        room_id: &str,
        kind: &str,
        data: &Value,
        user_id: &str,
    ) -> Delivery {
        // The leader's announcement of moved voice participations (`voice::moved`): internal, never delivered, but
        // what the user gained or lost through it (a moved member's voice channel) comes as usual.
        let internal = kind == crate::voice::moved::EVENT;
        if !internal && !is_metadata(kind) {
            let refs = refs(data);
            if refs.is_empty() {
                return Delivery::event(true);
            }
            return match self.view(state, room_id).await {
                Ok(view) => Delivery::event(view.is_some_and(|v| v.may_see(&refs, user_id))),
                Err(e) => {
                    tracing::warn!(error = %e, room_id, "channel visibility could not be determined, event dropped");
                    Delivery::event(false)
                }
            };
        }
        if !internal && !changes_visibility(kind) {
            return Delivery::event(true);
        }
        let target = if internal { None } else { target(kind, data) };
        let view = match self.view(state, room_id).await {
            Ok(Some(view)) => view,
            Ok(None) => {
                self.known.remove(room_id);
                return Delivery::event(!internal && (target.is_none() || kind.ends_with(".delete")));
            }
            Err(e) => {
                tracing::warn!(error = %e, room_id, "channel visibility could not be determined, event dropped");
                return Delivery::event(!internal && target.is_none());
            }
        };
        let new = view.known_by(user_id);
        let old = self.known.insert(room_id.to_string(), new.clone());
        let deleted = kind.ends_with(".delete") && !kind.starts_with("override.");
        let (skip, event) = match target {
            None => (None, !internal),
            Some(Target::Channel(id)) if deleted => (Some(id), old.as_ref().is_none_or(|o| o.channels.contains(id))),
            Some(Target::Category(id)) if deleted => (Some(id), old.as_ref().is_none_or(|o| o.categories.contains(id))),
            // A creation the user already knows of (told as gained by an earlier event of a lagging connection,
            // or in its starting snapshot) is not sent again, as a deletion they no longer know of is not.
            Some(Target::Channel(id)) if kind.ends_with(".create") => {
                (Some(id), new.channels.contains(id) && old.as_ref().is_none_or(|o| !o.channels.contains(id)))
            }
            Some(Target::Category(id)) if kind.ends_with(".create") => {
                (Some(id), new.categories.contains(id) && old.as_ref().is_none_or(|o| !o.categories.contains(id)))
            }
            Some(Target::Channel(id)) => (None, new.channels.contains(id)),
            Some(Target::Category(id)) => (None, new.categories.contains(id)),
        };
        let (before, after) = match &old {
            Some(old) if *old != new => changes(&view, old, &new, skip),
            _ => (Vec::new(), Vec::new()),
        };
        Delivery { before, event, after }
    }

    /// Forgets a room the connection left.
    pub fn forget(&mut self, room_id: &str) {
        self.slots.remove(room_id);
        self.known.remove(room_id);
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
