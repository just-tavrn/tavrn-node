// SPDX-License-Identifier: AGPL-3.0-only
//! Threads, forum posts and announcement channels (PROTOCOL.md §7e): start, list, read, change and delete
//! threads, follow them and move their read markers. Thread messages themselves go through the message routes
//! (`thread_id`, `?thread=`).

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    permissions as p,
    routes::messages::CreateMessageRequest,
    store::{
        self,
        threads::{Archived, ListFilter, NewThread, Sort, Title},
    },
    threads::{self as th, Thread, ThreadReadState},
    util,
    validate::{self, bad},
};

pub fn routes() -> Router<AppState> {
    // Titles, tags and a first message (at most 64 KiB of content) fit well into this.
    let body = || DefaultBodyLimit::max(crate::routes::messages::MAX_CONTENT_BYTES + 16 * 1024);
    Router::new()
        .route("/rooms/{room_id}/channels/{channel_id}/threads", get(list_threads).post(create_thread).layer(body()))
        .route("/rooms/{room_id}/followed-threads", get(followed_threads))
        .route(
            "/threads/{thread_id}",
            get(get_thread).patch(update_thread).delete(delete_thread).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/threads/{thread_id}/read", put(mark_read).layer(DefaultBodyLimit::max(4 * 1024)))
        .route("/threads/{thread_id}/follow", post(follow).delete(unfollow))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        create_thread,
        list_threads,
        get_thread,
        update_thread,
        delete_thread,
        mark_read,
        follow,
        unfollow,
        followed_threads
    ),
    components(schemas(
        Thread,
        th::ThreadUserState,
        ThreadReadState,
        ThreadList,
        FollowedThreads,
        CreateThreadRequest,
        UpdateThreadRequest,
        ThreadReadRequest,
        th::TagInput
    ))
)]
pub struct ThreadsApi;

#[derive(Deserialize, ToSchema)]
pub struct CreateThreadRequest {
    /// The thread id chosen by the client, so the first message's signature can cover `thread_id`: a ULID in its
    /// canonical form (uppercase) whose time is within 10 minutes of the node's clock. Without it the node picks one.
    pub id: Option<String>,
    /// 1–100 characters; in encrypted channels content-format ciphertext of `{ "type": "thread.title", "body" }`.
    #[schema(value_type = String)]
    pub title: Value,
    /// Encrypted channels: the epoch of the title ciphertext.
    pub title_epoch: Option<i64>,
    /// Text and announcement channels: the channel message the thread starts from.
    pub root_message_id: Option<String>,
    /// Forum posts: at most 5 tag ids of the channel.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The thread's first message (required for forum posts), like `POST …/messages`.
    pub message: Option<CreateMessageRequest>,
}

/// Start a thread (`send_messages` and `create_threads`) or, in a forum channel, a post (`send_messages`).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/threads", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = CreateThreadRequest,
    responses((status = 201, body = Thread), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
              (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)),
    description = "Starts a thread inside a text or announcement channel (from a root message of the channel or standalone, `send_messages` and `create_threads`) or a post in a forum channel (title, tags and the first message in one request, `send_messages`). In encrypted channels the title is ciphertext. The client may choose the thread id (`id`, a canonical ULID of about now) so the first message's signature covers its `thread_id` (`400 thread.id_invalid`, `409 thread.id_taken`). The creator follows the thread; `thread.create` and then `message.create` for the first message are sent to the room.")]
pub async fn create_thread(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<CreateThreadRequest>,
) -> Result<(StatusCode, Json<Thread>), ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    let channel = th::channel_of(&conv).ok_or_else(th::not_found)?.clone();
    if !th::THREAD_KINDS.contains(&channel.kind.as_str()) {
        return Err(bad("thread.unsupported_channel", "Threads exist in text, announcement and forum channels only"));
    }
    conv.require_entitled()?;
    let forum = channel.kind == "forum";
    if forum {
        conv.require(p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
        if req.message.is_none() {
            return Err(bad("thread.message_required", "A forum post needs its first message"));
        }
        if req.root_message_id.is_some() {
            return Err(bad("thread.root_invalid", "Forum posts start without a root message"));
        }
    } else {
        // Like replies: a thread needs what writing in the channel needs, plus create_threads.
        conv.require(p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
        conv.require(p::CREATE_THREADS, "thread.create_forbidden", "Create threads")?;
    }
    state.thread_limiter.check_all(&[format!("thread:{}", auth.user.id)])?;
    let tags = th::check_post_tags(&channel, &req.tags)?;
    let root = match &req.root_message_id {
        Some(r) => {
            let invalid =
                || bad("thread.root_invalid", "The root must be a message of this channel outside any thread");
            let r = r.to_ascii_uppercase();
            if !util::is_ulid(&r) {
                return Err(invalid());
            }
            match store::messages::by_id(&state.db, &r).await? {
                Some(m) if m.conversation_id == conv.id && m.thread_id.is_none() => {}
                _ => return Err(invalid()),
            }
            if let Some(existing) = store::threads::id_by_root(&state.db, &r).await? {
                return Err(exists(&existing));
            }
            Some(r)
        }
        None => None,
    };
    let (title, title_epoch) = th::check_title(&state, &auth, &conv, &req.title, req.title_epoch).await?;
    let id = match req.id.as_deref() {
        Some(id) => {
            check_client_id(id, chrono::Utc::now())?;
            if store::threads::by_id(&state.db, id).await?.is_some() {
                return Err(id_taken());
            }
            id.to_string()
        }
        None => util::ulid(),
    };
    let inserted = store::threads::insert(
        &state.db,
        NewThread {
            id: &id,
            channel_id: &conv.id,
            root_message_id: root.as_deref(),
            title: Title {
                text: &title,
                epoch: title_epoch,
                author_id: &auth.user.id,
                device_id: title_epoch.map(|_| auth.public_device_id()),
            },
            tags: &tags,
            created_by: &auth.user.id,
        },
    )
    .await?;
    if !inserted {
        // Another request started a thread on the same root in between, or took the client's id.
        let existing = match root.as_deref() {
            Some(r) => store::threads::id_by_root(&state.db, r).await?,
            None => None,
        };
        return Err(existing.map_or_else(id_taken, |e| exists(&e)));
    }
    store::threads::follow(&state.db, &id, &auth.user.id, None).await?;
    th::publish(&state, "thread.create", &id).await?;
    if let Some(mut message) = req.message {
        message.thread_id = Some(id.clone());
        if let Err(e) = crate::routes::messages::create_in(&state, &auth, &conv, message).await {
            // The thread goes with its failed first message.
            store::threads::delete(&state.db, &id).await?;
            state.hub.room(&room_id, "thread.delete", json!({ "room_id": room_id, "channel_id": conv.id, "id": id }));
            return Err(e);
        }
    }
    let row = store::threads::by_id(&state.db, &id).await?.ok_or_else(th::not_found)?;
    let thread = th::one(&state, &auth.user, th::ThreadAccess { row, conv }).await?;
    Ok((StatusCode::CREATED, Json(thread)))
}

/// Largest distance between the time of a client-chosen thread id and the node's clock.
const CLIENT_ID_SKEW_MINUTES: i64 = 10;

/// A client-chosen thread id (PROTOCOL.md §7e): the canonical ULID string (the first message's signature covers it
/// exactly), its time near the node's clock (it orders the threads by creation).
fn check_client_id(id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<(), ApiError> {
    let invalid = || bad("thread.id_invalid", "id: a canonical (uppercase) ULID of about now");
    let parsed = ulid::Ulid::from_string(id).map_err(|_| invalid())?;
    if parsed.to_string() != id {
        return Err(invalid());
    }
    let skew = (now.timestamp_millis() - parsed.timestamp_ms() as i64).abs();
    if skew > CLIENT_ID_SKEW_MINUTES * 60_000 {
        return Err(invalid());
    }
    Ok(())
}

fn id_taken() -> ApiError {
    ApiError::conflict("thread.id_taken", "A thread with this id exists; pick another id")
}

fn exists(thread_id: &str) -> ApiError {
    ApiError::Conflict {
        code: "thread.exists",
        detail: "This message already started a thread".into(),
        meta: json!({ "thread_id": thread_id }),
    }
}

#[derive(Deserialize, IntoParams)]
pub struct ListThreadsQuery {
    /// `false` (default: active threads), `true` (archived only) or `all`.
    pub archived: Option<String>,
    /// Forum posts carrying this tag id.
    pub tag: Option<String>,
    /// `activity` (default, the newest last message first) or `created` (newest first).
    pub sort: Option<String>,
    /// The id of the last thread of the previous page.
    pub before: Option<String>,
    /// 1–50 (default 25).
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ThreadList {
    pub items: Vec<Thread>,
    /// `before` of the next page; null on the last page.
    pub next: Option<String>,
}

/// List a channel's threads (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/threads", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ListThreadsQuery),
    responses((status = 200, body = ThreadList), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Pages the threads of a channel: active ones by default, archived ones with `archived=true` (or both with `all`), the newest activity first (`sort=activity`) or the newest threads first (`sort=created`), forum posts filtered by `tag`. Each thread carries the requester's follow and unread state, the root message (text threads) or the first message (forum posts).")]
pub async fn list_threads(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<ListThreadsQuery>,
) -> Result<Json<ThreadList>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    let channel = th::channel_of(&conv).ok_or_else(th::not_found)?;
    if !th::THREAD_KINDS.contains(&channel.kind.as_str()) {
        return Err(bad("thread.unsupported_channel", "Threads exist in text, announcement and forum channels only"));
    }
    let invalid = |detail: &str| bad("thread.filter_invalid", detail.to_string());
    let archived = match q.archived.as_deref() {
        None | Some("false") => Archived::Active,
        Some("true") => Archived::Archived,
        Some("all") => Archived::All,
        Some(_) => return Err(invalid("archived: false, true or all")),
    };
    let sort = match q.sort.as_deref() {
        None | Some("activity") => Sort::Activity,
        Some("created") => Sort::Created,
        Some(_) => return Err(invalid("sort: activity or created")),
    };
    let tag = match q.tag.as_deref() {
        None => None,
        Some(t) if util::is_ulid(t) => Some(t.to_ascii_uppercase()),
        Some(_) => return Err(invalid("tag: a tag id")),
    };
    let before = match q.before.as_deref() {
        None => None,
        Some(b) => {
            validate::ulid("before", b)?;
            match store::threads::by_id(&state.db, &b.to_ascii_uppercase()).await? {
                Some(t) if t.channel_id == conv.id => Some(t),
                _ => return Err(invalid("before: a thread of this channel")),
            }
        }
    };
    let limit = validate::limit(q.limit, 25, 50);
    let mut rows = store::threads::list(
        &state.db,
        ListFilter {
            channel_id: &conv.id,
            archived,
            tag: tag.as_deref(),
            sort,
            before: before.as_ref(),
            limit: limit + 1,
        },
    )
    .await?;
    let more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next = if more { rows.last().map(|t| t.id.clone()) } else { None };
    let items = th::to_api(&state, &auth.user, &conv, rows).await?;
    Ok(Json(ThreadList { items, next }))
}

/// Get a thread (`view_channel`).
#[utoipa::path(get, path = "/api/v1/threads/{thread_id}", security(("bearer" = [])), params(("thread_id" = String, Path)),
    responses((status = 200, body = Thread), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Returns one thread with the requester's state and its root or first message. Threads of channels the requester cannot view are `404 thread.not_found`.")]
pub async fn get_thread(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
) -> Result<Json<Thread>, ApiError> {
    let t = th::load(&state, &thread_id, &auth.user).await?;
    Ok(Json(th::one(&state, &auth.user, t).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateThreadRequest {
    /// New title (ciphertext with `title_epoch` in encrypted channels).
    #[schema(value_type = Option<String>)]
    pub title: Option<Value>,
    pub title_epoch: Option<i64>,
    /// Forum posts: the new tag ids.
    pub tags: Option<Vec<String>>,
    pub archived: Option<bool>,
    pub locked: Option<bool>,
}

/// Rename, retag, archive or lock a thread (its creator or `manage_threads`).
#[utoipa::path(patch, path = "/api/v1/threads/{thread_id}", security(("bearer" = [])), params(("thread_id" = String, Path)),
    request_body = UpdateThreadRequest,
    responses((status = 200, body = Thread), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Changes the title, the tags (forum posts), the archive or the lock state of a thread. The thread's creator or a member with `manage_threads` may do so; changes by others are audit-logged (`thread.update`). The room gets `thread.update`.")]
pub async fn update_thread(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
    ApiJson(req): ApiJson<UpdateThreadRequest>,
) -> Result<Json<Thread>, ApiError> {
    let t = th::load(&state, &thread_id, &auth.user).await?;
    t.conv.require_entitled()?;
    if !t.may_manage(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "thread.manage_forbidden",
            detail: "Only the thread's creator or members with manage_threads change it".into(),
        });
    }
    // The creator changes the thread like an own message: with `send_messages` (gone in a timeout).
    if !p::has(t.conv.perms, p::MANAGE_THREADS) {
        t.conv.require(p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
    }
    let title = match &req.title {
        Some(title) => Some(th::check_title(&state, &auth, &t.conv, title, req.title_epoch).await?),
        None => None,
    };
    let tags = match req.tags.as_deref() {
        Some(tags) => Some(th::check_post_tags(t.channel()?, tags)?),
        None => None,
    };
    let now = util::now();
    let archived_at = match req.archived {
        Some(true) if t.row.archived_at.is_none() => Some(Some(now.as_str())),
        Some(false) if t.row.archived_at.is_some() => Some(None),
        _ => None,
    };
    store::threads::update(
        &state.db,
        &t.row.id,
        store::threads::Update {
            title: title.as_ref().map(|(text, epoch)| Title {
                text,
                epoch: *epoch,
                author_id: &auth.user.id,
                device_id: epoch.map(|_| auth.public_device_id()),
            }),
            tags: tags.as_deref(),
            archived_at,
            locked: req.locked,
        },
    )
    .await?;
    if t.row.created_by != auth.user.id {
        store::rooms::audit(
            &state.db,
            Some(&t.row.room_id),
            Some(&auth.user.id),
            "thread.update",
            &t.row.id,
            "",
            json!({ "channel_id": t.row.channel_id, "title": title.is_some(), "tags": tags, "archived": req.archived, "locked": req.locked }),
        )
        .await?;
    }
    th::publish(&state, "thread.update", &t.row.id).await?;
    let t = th::load(&state, &t.row.id, &auth.user).await?;
    Ok(Json(th::one(&state, &auth.user, t).await?))
}

/// Delete a thread with its messages (its creator while it holds only their messages, otherwise `manage_threads`).
#[utoipa::path(delete, path = "/api/v1/threads/{thread_id}", security(("bearer" = [])), params(("thread_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Deletes the thread with all its messages and their uploads permanently; the root message stays in the channel. The creator may delete a thread holding only their own messages, otherwise `manage_threads` is needed. Audit-logged as `thread.delete`; the room gets `thread.delete`.")]
pub async fn delete_thread(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let t = th::load(&state, &thread_id, &auth.user).await?;
    t.conv.require_entitled()?;
    let moderator = p::has(t.conv.perms, p::MANAGE_THREADS);
    let own = t.row.created_by == auth.user.id
        && store::threads::foreign_messages(&state.db, &t.row.id, &auth.user.id).await? == 0;
    if !moderator && !own {
        return Err(ApiError::Forbidden {
            code: "thread.delete_forbidden",
            detail: "Deleting other people's messages with a thread needs manage_threads".into(),
        });
    }
    let blobs = store::blobs::ids_for_messages(&state.db, "thread_id = $1", std::slice::from_ref(&t.row.id)).await?;
    let deleted = store::threads::delete(&state.db, &t.row.id).await?;
    for id in &blobs {
        state.storage.delete(id).await;
    }
    store::rooms::audit(
        &state.db,
        Some(&t.row.room_id),
        Some(&auth.user.id),
        "thread.delete",
        &t.row.id,
        "",
        json!({ "channel_id": t.row.channel_id, "created_by": t.row.created_by, "deleted": deleted }),
    )
    .await?;
    state.hub.room(
        &t.row.room_id,
        "thread.delete",
        json!({ "room_id": t.row.room_id, "channel_id": t.row.channel_id, "id": t.row.id }),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct ThreadReadRequest {
    /// Newest message of the thread the user has seen; the marker never moves backwards.
    pub last_read_message_id: String,
}

/// Move the per-thread read marker (members with `view_channel`).
#[utoipa::path(put, path = "/api/v1/threads/{thread_id}/read", security(("bearer" = [])), params(("thread_id" = String, Path)),
    request_body = ThreadReadRequest,
    responses((status = 200, body = ThreadReadState), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
              (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)),
    description = "Moves the requester's read marker of a thread forward (never backwards); the message must belong to the thread. The user's connections get `thread.read`.")]
pub async fn mark_read(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
    ApiJson(req): ApiJson<ThreadReadRequest>,
) -> Result<Json<ThreadReadState>, ApiError> {
    state.read_limiter.check_all(&[format!("read:{}", auth.user.id)])?;
    let t = th::load(&state, &thread_id, &auth.user).await?;
    t.conv.require_entitled()?;
    validate::ulid("last_read_message_id", &req.last_read_message_id)?;
    let message_id = req.last_read_message_id.to_ascii_uppercase();
    match store::messages::by_id(&state.db, &message_id).await? {
        Some(m) if m.thread_id.as_deref() == Some(t.row.id.as_str()) => {}
        _ => return Err(access::not_found("Message", "message.not_found")),
    }
    let (_, moved) = store::threads::advance_marker(&state.db, &t.row.id, &auth.user.id, &message_id).await?;
    let read = th::read_state(&state, &auth.user, &t).await?;
    if moved {
        th::publish_read(&state, &auth.user.id, &read);
    }
    Ok(Json(read))
}

/// Follow a thread.
#[utoipa::path(post, path = "/api/v1/threads/{thread_id}/follow", security(("bearer" = [])), params(("thread_id" = String, Path)),
    responses((status = 200, body = ThreadReadState), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Follows a thread: its messages count towards the user's unread counts and notifications from now on. The user's connections get `thread.read`.")]
pub async fn follow(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
) -> Result<Json<ThreadReadState>, ApiError> {
    let t = th::load(&state, &thread_id, &auth.user).await?;
    t.conv.require_entitled()?;
    let changed = store::threads::follow(&state.db, &t.row.id, &auth.user.id, t.row.last_message_id.as_deref()).await?;
    let read = th::read_state(&state, &auth.user, &t).await?;
    if changed {
        th::publish_read(&state, &auth.user.id, &read);
    }
    Ok(Json(read))
}

/// Stop following a thread.
#[utoipa::path(delete, path = "/api/v1/threads/{thread_id}/follow", security(("bearer" = [])), params(("thread_id" = String, Path)),
    responses((status = 200, body = ThreadReadState), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Stops following a thread: it no longer counts towards unread counts and notifications. The user's connections get `thread.read`.")]
pub async fn unfollow(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<String>,
) -> Result<Json<ThreadReadState>, ApiError> {
    let t = th::load(&state, &thread_id, &auth.user).await?;
    let changed = store::threads::unfollow(&state.db, &t.row.id, &auth.user.id).await?;
    let read = th::read_state(&state, &auth.user, &t).await?;
    if changed {
        th::publish_read(&state, &auth.user.id, &read);
    }
    Ok(Json(read))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FollowedThreads {
    pub items: Vec<ThreadReadState>,
}

/// The requester's followed threads in a room.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/followed-threads", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = FollowedThreads), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)),
    description = "Lists the threads the requester follows in channels of the room they can view, the most recent activity first (at most 200), with their read markers and unread and mention counts.")]
pub async fn followed_threads(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<FollowedThreads>, ApiError> {
    let room = access::room_access(&state, &room_id, &auth.user).await?;
    Ok(Json(FollowedThreads { items: th::followed(&state, &auth.user, &room).await? }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn client_chosen_ids_are_canonical_ulids_of_about_now() {
        let now = chrono::Utc::now();
        let at = |offset_minutes: i64| {
            let ms = (now + chrono::Duration::minutes(offset_minutes)).timestamp_millis() as u64;
            ulid::Ulid::from_parts(ms, 42).to_string()
        };
        assert!(check_client_id(&at(0), now).is_ok());
        assert!(check_client_id(&at(-9), now).is_ok() && check_client_id(&at(9), now).is_ok(), "clock skew");
        for bad in [at(-11), at(11), at(0).to_lowercase(), "nope".into(), format!("{}0", at(0)), String::new()] {
            assert_eq!(check_client_id(&bad, now).unwrap_err().code(), "thread.id_invalid", "{bad}");
        }
    }
}
