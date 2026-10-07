// SPDX-License-Identifier: AGPL-3.0-only
//! Threads, forum posts and announcement channels (PROTOCOL.md §7e).
//!
//! A thread is a sub-conversation inside a room channel: its messages are messages of the channel with
//! `thread_id`, so an encrypted channel's threads use the channel's MLS group and the node never needs new keys.
//! Titles in encrypted channels are content-format ciphertext. This module holds the API objects, the checks
//! shared by the thread routes and the message routes, and the auto-archive job.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    error::ApiError,
    models::{ChannelRow, ForumTag, Message, MessageRow, ThreadSummary, UserRow},
    permissions as p, store,
    store::threads::{CountScope, ThreadRow},
    util,
    validate::bad,
};

/// Channel kinds with threads.
pub const THREAD_KINDS: &[&str] = &["text", "announcement", "forum"];
pub const MAX_TITLE_CHARS: usize = 100;
/// Longest title ciphertext (a 100-character title is well below 1 KiB of base64url).
pub const MAX_TITLE_CIPHERTEXT: usize = 2048;
pub const MAX_CHANNEL_TAGS: usize = 20;
pub const MAX_TAG_NAME_CHARS: usize = 32;
pub const MAX_POST_TAGS: usize = 5;
pub const DEFAULT_AUTO_ARCHIVE_MINUTES: i64 = 10080;
pub const MIN_AUTO_ARCHIVE_MINUTES: i64 = 60;
pub const MAX_AUTO_ARCHIVE_MINUTES: i64 = 43200;
/// Followed threads listed per room.
pub const MAX_FOLLOWED: i64 = 200;
/// Threads archived per auto-archive batch.
const ARCHIVE_BATCH: i64 = 500;

/// The requester's state in a thread.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct ThreadUserState {
    pub following: bool,
    pub last_read_message_id: Option<String>,
    /// Messages of others after the marker, at most 999; 0 for threads the user does not follow.
    pub unread_count: i64,
    /// Of those, mentions of the user, one of their roles or @everyone (notification settings applied).
    pub mention_count: i64,
}

/// A thread (PROTOCOL.md §7e).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Thread {
    pub id: String,
    pub room_id: String,
    pub channel_id: String,
    /// The channel message the thread was started from; null for standalone threads and forum posts.
    pub root_message_id: Option<String>,
    /// The root message was deleted (the thread stays).
    pub root_deleted: bool,
    /// The title is ciphertext (content format 1 of `{ "type": "thread.title", "body" }`, ENCRYPTION.md §5.2).
    pub encrypted: bool,
    /// 1–100 characters; ciphertext when `encrypted`.
    pub title: String,
    /// The epoch of an encrypted title (null for plaintext).
    pub title_epoch: Option<i64>,
    /// Who set the title (author of the title ciphertext).
    pub title_author: String,
    /// The device that set the title (verifies the ciphertext's signature).
    pub title_device_id: Option<String>,
    /// Forum posts: tag ids of the channel.
    pub tags: Vec<String>,
    /// Address of the creator.
    pub created_by: String,
    pub created_by_id: String,
    pub created_at: String,
    pub last_message_id: Option<String>,
    pub last_message_at: String,
    /// Messages in the thread (the root not included).
    pub message_count: i64,
    /// Up to three users who wrote in the thread most recently, newest first.
    pub participant_ids: Vec<String>,
    pub archived_at: Option<String>,
    /// Only members with `manage_threads` write in a locked thread.
    pub locked: bool,
    /// The requester's state (absent in events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub me: Option<ThreadUserState>,
    /// Text threads: the root message as the requester may see it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_message: Option<Message>,
    /// Forum posts: the first message of the thread as the requester may see it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_message: Option<Message>,
}

/// The requester's per-thread read state (`PUT /threads/{id}/read`, event `thread.read`).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ThreadReadState {
    pub thread_id: String,
    pub channel_id: String,
    pub room_id: String,
    pub following: bool,
    pub last_read_message_id: Option<String>,
    pub unread_count: i64,
    pub mention_count: i64,
}

impl ThreadRow {
    fn to_base(&self, channel_tags: &HashSet<String>, participants: Vec<String>) -> Thread {
        Thread {
            id: self.id.clone(),
            room_id: self.room_id.clone(),
            channel_id: self.channel_id.clone(),
            root_message_id: self.root_message_id.clone(),
            root_deleted: false,
            encrypted: self.title_epoch.is_some(),
            title: self.title.clone(),
            title_epoch: self.title_epoch,
            title_author: format!("{}@{}", self.title_author_username, self.title_author_domain),
            title_device_id: self.title_device_id.clone(),
            tags: self.tag_ids().into_iter().filter(|t| channel_tags.contains(t)).collect(),
            created_by: format!("{}@{}", self.created_by_username, self.created_by_domain),
            created_by_id: self.created_by.clone(),
            created_at: self.created_at.clone(),
            last_message_id: self.last_message_id.clone(),
            last_message_at: self.last_message_at.clone(),
            message_count: self.message_count,
            participant_ids: participants,
            archived_at: self.archived_at.clone(),
            locked: self.is_locked(),
            me: None,
            root_message: None,
            first_message: None,
        }
    }

    fn summary(&self, participants: Vec<String>) -> ThreadSummary {
        ThreadSummary {
            id: self.id.clone(),
            message_count: self.message_count,
            last_message_id: self.last_message_id.clone(),
            last_message_at: self.last_message_at.clone(),
            participant_ids: participants,
            archived_at: self.archived_at.clone(),
            locked: self.is_locked(),
        }
    }
}

fn tag_set(channel: &ChannelRow) -> HashSet<String> {
    channel.tags().into_iter().map(|t| t.id).collect()
}

pub fn not_found() -> ApiError {
    access::not_found("Thread", "thread.not_found")
}

/// The channel row of a channel conversation.
pub fn channel_of(conv: &Conv) -> Option<&ChannelRow> {
    match &conv.kind {
        ConvKind::Channel { channel, .. } => Some(channel),
        ConvKind::Direct { .. } => None,
    }
}

/// A thread with the requester's view of its channel. Unknown threads and threads of channels the requester cannot
/// view are `404 thread.not_found`; non-members of the room get `403 room.not_member`.
pub struct ThreadAccess {
    pub row: ThreadRow,
    pub conv: Conv,
}

impl ThreadAccess {
    /// The thread's channel (always a room channel, see [`load`]).
    pub fn channel(&self) -> Result<&ChannelRow, ApiError> {
        channel_of(&self.conv).ok_or_else(not_found)
    }

    /// The thread's creator or `manage_threads`.
    pub fn may_manage(&self, user_id: &str) -> bool {
        self.row.created_by == user_id || p::has(self.conv.perms, p::MANAGE_THREADS)
    }
}

pub async fn load(state: &AppState, thread_id: &str, user: &UserRow) -> Result<ThreadAccess, ApiError> {
    if !util::is_ulid(thread_id) {
        return Err(not_found());
    }
    let row = store::threads::by_id(&state.db, &thread_id.to_ascii_uppercase()).await?.ok_or_else(not_found)?;
    let conv = access::channel_conversation(state, &row.room_id, &row.channel_id, user).await?;
    if !p::has(conv.perms, p::VIEW_CHANNEL) {
        return Err(not_found());
    }
    Ok(ThreadAccess { row, conv })
}

/// A thread of `conv` named by a message request (`thread_id`): `404 thread.not_found` for DMs and threads of other
/// channels.
pub async fn of_conversation(state: &AppState, conv: &Conv, thread_id: &str) -> Result<ThreadRow, ApiError> {
    if channel_of(conv).is_none() || !util::is_ulid(thread_id) {
        return Err(not_found());
    }
    match store::threads::by_id(&state.db, &thread_id.to_ascii_uppercase()).await? {
        Some(t) if t.channel_id == conv.id => Ok(t),
        _ => Err(not_found()),
    }
}

/// What writing a message into `conv` needs besides `send_messages` (PROTOCOL.md §7e): channel messages of forum
/// channels are refused, those of announcement channels need `manage_messages`; thread messages need
/// `create_threads` in text and announcement channels and `manage_threads` in locked threads.
pub fn check_write(conv: &Conv, thread: Option<&ThreadRow>) -> Result<(), ApiError> {
    let Some(channel) = channel_of(conv) else { return Ok(()) };
    match (channel.kind.as_str(), thread) {
        ("forum", None) => Err(bad("message.thread_required", "Forum channels take posts only: write in a thread")),
        ("announcement", None) if !p::has(conv.perms, p::MANAGE_MESSAGES) => Err(ApiError::Forbidden {
            code: "message.announcement_forbidden",
            detail: "Only moderators post in announcement channels; reply in a thread instead".into(),
        }),
        (_, None) => Ok(()),
        (kind, Some(t)) => {
            if kind != "forum" && !p::has(conv.perms, p::CREATE_THREADS) {
                return Err(ApiError::Forbidden {
                    code: "thread.reply_forbidden",
                    detail: "Missing permission: Create threads".into(),
                });
            }
            if t.is_locked() && !p::has(conv.perms, p::MANAGE_THREADS) {
                return Err(ApiError::Forbidden { code: "thread.locked", detail: "This thread is locked".into() });
            }
            Ok(())
        }
    }
}

/// A title as sent: plaintext in unencrypted channels (trimmed, 1–100 characters, one line), content-format
/// ciphertext in encrypted ones (checked like message content). Returns the stored text and epoch.
pub async fn check_title(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    title: &Value,
    epoch: Option<i64>,
) -> Result<(String, Option<i64>), ApiError> {
    let invalid = |detail: &str| bad("thread.title_invalid", detail.to_string());
    let Value::String(title) = title else { return Err(invalid("title must be a string")) };
    if conv.encrypted {
        let base64url = !title.is_empty()
            && title.len() <= MAX_TITLE_CIPHERTEXT
            && title.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !base64url || tavrn_crypto::content_header(title).is_err() {
            return Err(invalid("This channel is encrypted: the title must be encrypted content (format 1)"));
        }
        let epoch = crate::routes::messages::check_ciphertext(state, auth, &conv.id, title, epoch).await?;
        return Ok((title.clone(), Some(epoch)));
    }
    if epoch.is_some() {
        return Err(invalid("This channel is not encrypted: the title is plaintext without an epoch"));
    }
    let t = title.trim();
    let n = t.chars().count();
    if n == 0 || n > MAX_TITLE_CHARS || t.chars().any(char::is_control) {
        return Err(invalid("title: 1 to 100 characters on one line"));
    }
    Ok((t.to_string(), None))
}

/// Tags of a post: at most 5 distinct ids of the channel's tags.
pub fn check_post_tags(channel: &ChannelRow, tags: &[String]) -> Result<Vec<String>, ApiError> {
    let invalid = || bad("thread.tags_invalid", "tags: at most 5 tags of this forum channel");
    if channel.kind != "forum" {
        return if tags.is_empty() {
            Ok(Vec::new())
        } else {
            Err(bad("thread.tags_invalid", "Only forum posts have tags"))
        };
    }
    let known = tag_set(channel);
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.to_ascii_uppercase();
        if !known.contains(&t) {
            return Err(invalid());
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    if tags.len() > MAX_POST_TAGS {
        return Err(invalid());
    }
    Ok(out)
}

/// A tag entry of `PATCH …/channels/{id} { tags }`.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
pub struct TagInput {
    /// Keep this existing tag (absent: a new tag).
    pub id: Option<String>,
    pub name: String,
    pub emoji: Option<String>,
}

/// The new tag list of a forum channel: at most 20, names 1–32 characters unique ignoring case, emoji a Unicode emoji
/// or a custom emoji token, ids of existing tags only.
pub fn check_channel_tags(channel: &ChannelRow, input: &[TagInput]) -> Result<Vec<ForumTag>, ApiError> {
    let invalid = |detail: &str| bad("channel.tags_invalid", detail.to_string());
    if channel.kind != "forum" {
        return Err(invalid("Only forum channels have tags"));
    }
    if input.len() > MAX_CHANNEL_TAGS {
        return Err(invalid("At most 20 tags"));
    }
    let existing = tag_set(channel);
    let mut names = HashSet::new();
    let mut out = Vec::with_capacity(input.len());
    for t in input {
        let name = t.name.trim();
        let n = name.chars().count();
        if n == 0 || n > MAX_TAG_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(invalid("Tag names: 1 to 32 characters"));
        }
        if !names.insert(name.to_lowercase()) {
            return Err(invalid("Tag names must be unique"));
        }
        let emoji = match t.emoji.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(e) if crate::emoji::valid_reaction(e) => Some(e.to_string()),
            Some(_) => return Err(invalid("Tag emoji: a Unicode emoji or a custom emoji")),
        };
        let id = match &t.id {
            Some(id) if existing.contains(&id.to_ascii_uppercase()) => id.to_ascii_uppercase(),
            Some(_) => return Err(invalid("Unknown tag id")),
            None => util::ulid(),
        };
        out.push(ForumTag { id, name: name.to_string(), emoji });
    }
    Ok(out)
}

/// The thread summaries of root messages among `rows` (one query per page, plus one for participants).
pub async fn summaries(state: &AppState, rows: &[MessageRow]) -> Result<HashMap<String, ThreadSummary>, ApiError> {
    let ids: Vec<String> = rows.iter().filter(|r| r.thread_id.is_none()).map(|r| r.id.clone()).collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let threads = store::threads::by_roots(&state.db, &ids).await?;
    if threads.is_empty() {
        return Ok(HashMap::new());
    }
    let thread_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
    let mut participants = store::threads::participants(&state.db, &thread_ids).await?;
    Ok(threads
        .into_iter()
        .filter_map(|t| {
            let root = t.root_message_id.clone()?;
            let p = participants.remove(&t.id).unwrap_or_default();
            Some((root, t.summary(p)))
        })
        .collect())
}

/// The mention and unread counts of followed threads with the user's notification settings applied.
async fn read_counts(
    state: &AppState,
    user: &UserRow,
    conv: &Conv,
    thread_ids: &[String],
) -> Result<HashMap<String, (i64, i64)>, ApiError> {
    let ConvKind::Channel { access, .. } = &conv.kind else { return Ok(HashMap::new()) };
    let role_ids: Vec<String> = access.member_roles.iter().map(|r| r.id.clone()).collect();
    let counts = store::threads::followed_counts(
        &state.db,
        &user.id,
        &user.address(),
        &role_ids,
        CountScope::Threads(thread_ids),
    )
    .await?;
    if counts.is_empty() {
        return Ok(HashMap::new());
    }
    let settings = if user.domain == state.config.domain {
        Some(crate::notifications::load(&state.db, &user.id).await?)
    } else {
        None
    };
    let now = util::now();
    let effective = settings.map(|s| s.effective(Some(&access.room.id), &conv.id, &now)).unwrap_or_default();
    Ok(counts
        .into_iter()
        .map(|c| {
            let unread = if effective.muted { 0 } else { c.unread.min(store::messages::UNREAD_CAP) };
            let mentions = effective.mentions(c.direct, c.everyone).min(store::messages::UNREAD_CAP);
            (c.thread_id, (unread, mentions))
        })
        .collect())
}

/// The API objects of threads of one channel for `user` (state, root and first messages through the history cut).
pub async fn to_api(
    state: &AppState,
    user: &UserRow,
    conv: &Conv,
    rows: Vec<ThreadRow>,
) -> Result<Vec<Thread>, ApiError> {
    let Some(channel) = channel_of(conv) else { return Ok(Vec::new()) };
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let tags = tag_set(channel);
    let ids: Vec<String> = rows.iter().map(|t| t.id.clone()).collect();
    let mut participants = store::threads::participants(&state.db, &ids).await?;
    let members = store::threads::members(&state.db, &user.id, &ids).await?;
    let counts = read_counts(state, user, conv, &ids).await?;

    // Root messages (text threads) and first messages (forum posts), as the requester may see them.
    let roots: Vec<String> = rows.iter().filter_map(|t| t.root_message_id.clone()).collect();
    let existing =
        if roots.is_empty() { HashSet::new() } else { store::blobs::existing_messages(&state.db, &roots).await? };
    let firsts =
        if channel.kind == "forum" { store::threads::first_messages(&state.db, &ids).await? } else { HashMap::new() };
    let wanted: Vec<String> = roots.iter().chain(firsts.values()).cloned().collect();
    let cut = crate::history::list_cutoff(state, conv, user).await?;
    let mut messages: HashMap<String, Message> = HashMap::new();
    if !wanted.is_empty() {
        let visible: Vec<MessageRow> = store::messages::by_ids(&state.db, &wanted)
            .await?
            .into_iter()
            .filter(|m| {
                m.conversation_id == conv.id && (m.encrypted == 0 || cut.as_deref().is_none_or(|c| m.id.as_str() >= c))
            })
            .collect();
        for m in crate::routes::messages::enrich(state, &user.id, &visible).await? {
            messages.insert(m.id.clone(), m);
        }
    }

    Ok(rows
        .into_iter()
        .map(|row| {
            let mut t = row.to_base(&tags, participants.remove(&row.id).unwrap_or_default());
            t.root_deleted = row.root_message_id.as_ref().is_some_and(|r| !existing.contains(r));
            t.root_message = row.root_message_id.as_ref().and_then(|r| messages.get(r).cloned());
            t.first_message = firsts.get(&row.id).and_then(|f| messages.get(f).cloned());
            let member = members.get(&row.id).cloned().unwrap_or_default();
            let (unread, mentions) =
                if member.following { counts.get(&row.id).copied().unwrap_or((0, 0)) } else { (0, 0) };
            t.me = Some(ThreadUserState {
                following: member.following,
                last_read_message_id: member.last_read_message_id,
                unread_count: unread,
                mention_count: mentions,
            });
            t
        })
        .collect())
}

/// One thread for `user`.
pub async fn one(state: &AppState, user: &UserRow, t: ThreadAccess) -> Result<Thread, ApiError> {
    to_api(state, user, &t.conv, vec![t.row]).await?.into_iter().next().ok_or_else(not_found)
}

/// A thread as events carry it: without the per-user state and the embedded messages.
pub async fn for_event(state: &AppState, id: &str) -> Result<Option<Thread>, ApiError> {
    let Some(row) = store::threads::by_id(&state.db, id).await? else { return Ok(None) };
    let tags = match store::rooms::channel_by_id(&state.db, &row.channel_id).await? {
        Some(c) => tag_set(&c),
        None => return Ok(None),
    };
    let participants = store::threads::participants(&state.db, std::slice::from_ref(&row.id))
        .await?
        .remove(&row.id)
        .unwrap_or_default();
    Ok(Some(row.to_base(&tags, participants)))
}

/// Publishes `thread.create` or `thread.update` with the current state of the thread.
pub async fn publish(state: &AppState, kind: &str, id: &str) -> Result<(), ApiError> {
    if let Some(thread) = for_event(state, id).await? {
        let room_id = thread.room_id.clone();
        state.hub.room(&room_id, kind, json!({ "room_id": room_id, "thread": thread }));
    }
    Ok(())
}

/// The per-thread read state of `user`.
pub async fn read_state(state: &AppState, user: &UserRow, t: &ThreadAccess) -> Result<ThreadReadState, ApiError> {
    let ids = vec![t.row.id.clone()];
    let member = store::threads::members(&state.db, &user.id, &ids).await?.remove(&t.row.id).unwrap_or_default();
    let (unread, mentions) = if member.following {
        read_counts(state, user, &t.conv, &ids).await?.get(&t.row.id).copied().unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    Ok(ThreadReadState {
        thread_id: t.row.id.clone(),
        channel_id: t.row.channel_id.clone(),
        room_id: t.row.room_id.clone(),
        following: member.following,
        last_read_message_id: member.last_read_message_id,
        unread_count: unread,
        mention_count: mentions,
    })
}

/// The followed threads of `user` in a room, in channels they can view (`GET /rooms/{id}/followed-threads`).
pub async fn followed(
    state: &AppState,
    user: &UserRow,
    room: &access::RoomAccess,
) -> Result<Vec<ThreadReadState>, ApiError> {
    if room.member.is_none() {
        return Ok(Vec::new());
    }
    let rows = store::threads::followed_in_room(&state.db, &user.id, &room.room.id, MAX_FOLLOWED).await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let channels = store::rooms::channels(&state.db, &room.room.id).await?;
    let overrides = store::rooms::overrides_of_room(&state.db, &room.room.id).await?;
    let visible: HashSet<String> = channels
        .iter()
        .filter(|c| p::has(access::channel_perms_with(room, c, &overrides, &user.id), p::VIEW_CHANNEL))
        .map(|c| c.id.clone())
        .collect();
    let rows: Vec<ThreadRow> = rows.into_iter().filter(|t| visible.contains(&t.channel_id)).collect();
    let ids: Vec<String> = rows.iter().map(|t| t.id.clone()).collect();
    let members = store::threads::members(&state.db, &user.id, &ids).await?;
    let role_ids: Vec<String> = room.member_roles.iter().map(|r| r.id.clone()).collect();
    let counts: HashMap<String, store::threads::Counts> =
        store::threads::followed_counts(&state.db, &user.id, &user.address(), &role_ids, CountScope::Threads(&ids))
            .await?
            .into_iter()
            .map(|c| (c.thread_id.clone(), c))
            .collect();
    let settings = if user.domain == state.config.domain {
        Some(crate::notifications::load(&state.db, &user.id).await?)
    } else {
        None
    };
    let now = util::now();
    Ok(rows
        .into_iter()
        .map(|t| {
            let effective =
                settings.as_ref().map(|s| s.effective(Some(&t.room_id), &t.channel_id, &now)).unwrap_or_default();
            let c = counts.get(&t.id).cloned().unwrap_or_default();
            ThreadReadState {
                following: true,
                last_read_message_id: members.get(&t.id).and_then(|m| m.last_read_message_id.clone()),
                unread_count: if effective.muted { 0 } else { c.unread.min(store::messages::UNREAD_CAP) },
                mention_count: effective.mentions(c.direct, c.everyone).min(store::messages::UNREAD_CAP),
                thread_id: t.id,
                channel_id: t.channel_id,
                room_id: t.room_id,
            }
        })
        .collect())
}

/// Sends `thread.read` to the user's connections.
pub fn publish_read(state: &AppState, user_id: &str, read: &ThreadReadState) {
    state.hub.users(vec![user_id.to_string()], "thread.read", read);
}

/// After a message was written into a thread: counters and activity, the author follows (and has read up to the
/// message), and `thread.update`.
pub async fn after_message(state: &AppState, thread_id: &str, message: &Message) -> Result<(), ApiError> {
    store::threads::record_message(&state.db, thread_id, &message.id, &message.created_at).await?;
    if store::threads::follow(&state.db, thread_id, &message.author_id, Some(&message.id)).await?
        && let Some(t) = store::threads::by_id(&state.db, thread_id).await?
    {
        let read = ThreadReadState {
            thread_id: t.id.clone(),
            channel_id: t.channel_id.clone(),
            room_id: t.room_id.clone(),
            following: true,
            last_read_message_id: Some(message.id.clone()),
            unread_count: 0,
            mention_count: 0,
        };
        publish_read(state, &message.author_id, &read);
    }
    publish(state, "thread.update", thread_id).await
}

/// Archives the threads whose last activity is older than their channel's `auto_archive_minutes`
/// (hourly housekeeping). Returns the number of archived threads.
pub async fn auto_archive(state: &AppState, now: DateTime<Utc>) -> Result<u64, ApiError> {
    let at = util::format_time(now);
    let mut archived = 0;
    for minutes in store::threads::archive_settings_in_use(&state.db).await? {
        let cutoff = util::format_time(now - chrono::Duration::minutes(minutes.max(MIN_AUTO_ARCHIVE_MINUTES)));
        loop {
            let idle = store::threads::idle(&state.db, minutes, &cutoff, ARCHIVE_BATCH).await?;
            for t in &idle {
                store::threads::update(
                    &state.db,
                    &t.id,
                    store::threads::Update { archived_at: Some(Some(&at)), ..Default::default() },
                )
                .await?;
                publish(state, "thread.update", &t.id).await?;
                archived += 1;
            }
            if (idle.len() as i64) < ARCHIVE_BATCH {
                break;
            }
        }
    }
    Ok(archived)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn forum(tags: &str) -> ChannelRow {
        ChannelRow {
            id: "C".into(),
            room_id: "R".into(),
            category_id: None,
            kind: "forum".into(),
            name: "f".into(),
            topic: String::new(),
            position: 0,
            sync_with_category: 1,
            slowmode_secs: 0,
            bitrate_kbps: 64,
            user_limit: 0,
            encrypted: 0,
            system_name: None,
            no_bots: 0,
            inherited_no_bots: 0,
            bots_allowed: 0,
            bots_in_encrypted_channels: "per_channel".into(),
            history_for_new_members: None,
            has_webhooks: 0,
            auto_archive_minutes: DEFAULT_AUTO_ARCHIVE_MINUTES,
            forum_tags: tags.into(),
        }
    }

    fn input(id: Option<&str>, name: &str, emoji: Option<&str>) -> TagInput {
        TagInput { id: id.map(str::to_string), name: name.into(), emoji: emoji.map(str::to_string) }
    }

    #[test]
    fn channel_tags_are_validated() {
        let id = util::ulid();
        let ch = forum(&json!([{ "id": id, "name": "Old", "emoji": null }]).to_string());
        let tags =
            check_channel_tags(&ch, &[input(Some(&id.to_lowercase()), " Kept ", None), input(None, "New", Some("🐛"))])
                .unwrap();
        assert_eq!(tags[0], ForumTag { id: id.clone(), name: "Kept".into(), emoji: None });
        assert_eq!(tags[1].emoji.as_deref(), Some("🐛"));
        assert!(util::is_ulid(&tags[1].id));
        let code = |i: &[TagInput]| check_channel_tags(&ch, i).unwrap_err().code().to_string();
        assert_eq!(code(&[input(None, "a", None), input(None, "A", None)]), "channel.tags_invalid");
        assert_eq!(code(&[input(None, "", None)]), "channel.tags_invalid");
        assert_eq!(code(&[input(None, &"x".repeat(33), None)]), "channel.tags_invalid");
        assert_eq!(code(&[input(None, "x", Some("two words"))]), "channel.tags_invalid");
        assert_eq!(code(&[input(Some(&util::ulid()), "x", None)]), "channel.tags_invalid");
        let many: Vec<TagInput> = (0..21).map(|i| input(None, &format!("t{i}"), None)).collect();
        assert_eq!(code(&many), "channel.tags_invalid");
        let mut text = forum("[]");
        text.kind = "text".into();
        assert_eq!(check_channel_tags(&text, &[]).unwrap_err().code(), "channel.tags_invalid");
    }

    #[test]
    fn post_tags_are_ids_of_the_channel() {
        let ids: Vec<String> = (0..6).map(|_| util::ulid()).collect();
        let list: Vec<Value> = ids.iter().map(|id| json!({ "id": id, "name": id })).collect();
        let ch = forum(&Value::Array(list).to_string());
        assert_eq!(check_post_tags(&ch, &[ids[0].to_lowercase(), ids[0].clone()]).unwrap(), vec![ids[0].clone()]);
        assert_eq!(check_post_tags(&ch, &[util::ulid()]).unwrap_err().code(), "thread.tags_invalid");
        assert_eq!(check_post_tags(&ch, &ids).unwrap_err().code(), "thread.tags_invalid", "at most 5");
        let mut text = forum("[]");
        text.kind = "text".into();
        assert!(check_post_tags(&text, &[]).unwrap().is_empty());
        assert_eq!(check_post_tags(&text, &[ids[0].clone()]).unwrap_err().code(), "thread.tags_invalid");
        // Unreadable stored tags count as none.
        assert!(forum("not json").tags().is_empty());
    }
}
