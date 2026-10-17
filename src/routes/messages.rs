// SPDX-License-Identifier: AGPL-3.0-only
//! Messages in channels, DMs and group DMs: read, send, edit, delete; auto-moderation against spam.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    e2ee,
    error::{ApiError, ApiJson, ApiQuery as Query, ProblemDetails},
    models::{Channel, ChannelRow, Message, MessageRow, UserRow},
    permissions as p, store,
    store::messages::NewMessage,
    util::{self, now},
    validate::{self, bad},
};

pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
pub const MAX_TEXT_CHARS: usize = 4000;
pub const MAX_MENTIONS: usize = 50;
pub const AUTOMOD_WINDOW_SECS: i64 = 5;

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
    pub after: Option<String>,
    /// The page around this message (jump to a search result): up to `limit / 2` newer messages, the message
    /// itself and older ones, newest first. Not combinable with `before`, `after` or `epoch`; `404
    /// message.not_found` if the message is not in this conversation or not visible to the caller.
    pub around: Option<String>,
    /// Only encrypted messages of this MLS epoch (used to check shared history keys, ENCRYPTION.md §7b). Lists
    /// the messages of the whole channel, threads included.
    pub epoch: Option<i64>,
    /// Page this thread of the channel (PROTOCOL.md §7e); without it the channel's list leaves thread messages out.
    pub thread: Option<String>,
    /// `all`: the channel's messages including those of its threads (clients syncing their local search index).
    pub threads: Option<String>,
}

/// Adds attachments, reactions and pin status for the requester to messages.
pub async fn enrich(state: &AppState, user_id: &str, rows: &[MessageRow]) -> Result<Vec<Message>, ApiError> {
    // A constant number of queries per page (no N+1): reactions, attachments, and pins per conversation.
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let mut reactions = store::blobs::reactions_for(&state.db, &ids, user_id).await?;
    let mut attachments = store::blobs::by_messages(&state.db, &ids).await?;
    let mut by_conversation: std::collections::HashMap<&str, Vec<String>> = std::collections::HashMap::new();
    for row in rows {
        by_conversation.entry(row.conversation_id.as_str()).or_default().push(row.id.clone());
    }
    let mut pinned: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (conversation_id, ids) in &by_conversation {
        pinned.extend(store::blobs::pinned_among(&state.db, conversation_id, ids).await?);
    }
    // Per-room profiles of the authors (room channels): one query per page.
    let conversations: Vec<String> = by_conversation.keys().map(|c| c.to_string()).collect();
    let mut authors: Vec<String> = rows.iter().map(|r| r.author_id.clone()).collect();
    authors.sort();
    authors.dedup();
    let profiles: std::collections::HashMap<(String, String), crate::models::RoomProfile> =
        store::rooms::author_profiles(&state.db, &conversations, &authors)
            .await?
            .into_iter()
            .filter_map(|(c, m)| m.room_profile().map(|p| ((c, m.user_id), p)))
            .collect();
    let replies: Vec<String> = rows.iter().filter_map(|r| r.reply_to_id.clone()).collect();
    let originals = if replies.is_empty() {
        Default::default()
    } else {
        store::blobs::existing_messages(&state.db, &replies).await?
    };
    // Messages that started a thread carry its summary (PROTOCOL.md §7e).
    let mut threads = crate::threads::summaries(state, rows).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut m = row.to_api();
        m.thread = threads.remove(&row.id);
        m.reply_deleted = row.reply_to_id.as_ref().is_some_and(|r| !originals.contains(r));
        m.author_room_profile = profiles.get(&(row.conversation_id.clone(), row.author_id.clone())).cloned();
        m.attachments = attachments.remove(&row.id).unwrap_or_default().iter().map(|b| b.to_api()).collect();
        m.reactions = reactions
            .remove(&row.id)
            .unwrap_or_default()
            .into_iter()
            .map(|(emoji, count, me)| crate::models::Reaction { emoji, count, me })
            .collect();
        m.pinned = pinned.contains(&row.id);
        out.push(m);
    }
    Ok(out)
}

/// A message of `conv` the caller may read: `view_channel` and, for encrypted messages, the history window of
/// ENCRYPTION.md §7b (`404 message.not_found` outside it, as for a page of messages).
pub async fn readable(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    message_id: &str,
) -> Result<MessageRow, ApiError> {
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    access::message(state, &auth.user, conv, message_id, access::Window::Apply).await
}

pub async fn enrich_one(state: &AppState, user_id: &str, message_id: &str) -> Result<Message, ApiError> {
    let row = store::messages::by_id(&state.db, message_id)
        .await?
        .ok_or_else(|| access::not_found("Message", "message.not_found"))?;
    enrich(state, user_id, std::slice::from_ref(&row))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| access::not_found("Message", "message.not_found"))
}

/// Messages of a channel, newest first (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ListQuery), responses((status = 200, body = Vec<Message>), (status = 403, body = ProblemDetails)))]
pub async fn list_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Message>>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    list_in(&state, &auth, &conv, q).await
}

/// Messages of any conversation (channel, DM, group DM), newest first.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/messages", security(("bearer" = [])), params(("conversation_id" = String, Path), ListQuery), responses((status = 200, body = Vec<Message>), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_conversation_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Message>>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    list_in(&state, &auth, &conv, q).await
}

async fn list_in(state: &AppState, auth: &AuthUser, conv: &Conv, q: ListQuery) -> Result<Json<Vec<Message>>, ApiError> {
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    // Paging cursors are message ids (ULIDs).
    for (field, cursor) in [("before", &q.before), ("after", &q.after), ("around", &q.around)] {
        if let Some(c) = cursor {
            validate::ulid(field, c)?;
        }
    }
    if q.around.is_some() && (q.before.is_some() || q.after.is_some() || q.epoch.is_some()) {
        return Err(bad("message.cursor_conflict", "around cannot be combined with before, after or epoch"));
    }
    if q.epoch.is_some_and(|e| e < 0) {
        return Err(bad("message.epoch_invalid", "epoch must not be negative"));
    }
    // The channel's own messages, one thread, or (key checks by epoch) everything.
    let thread = match &q.thread {
        Some(t) => Some(crate::threads::of_conversation(state, conv, t).await?.id),
        None => None,
    };
    let all = match q.threads.as_deref() {
        None => false,
        Some("all") if thread.is_none() => true,
        Some(_) => return Err(bad("thread.filter_invalid", "threads: only `all`, and not together with thread")),
    };
    let filter = match (&thread, q.epoch.is_some() || all) {
        (Some(t), _) => store::messages::ThreadFilter::Thread(t),
        (None, true) => store::messages::ThreadFilter::Any,
        (None, false) => store::messages::ThreadFilter::Channel,
    };
    // Encrypted history from before the join only as far as the channel's policy allows (§7b).
    let cut = crate::history::list_cutoff(state, conv, &auth.user).await?;
    if let Some(target) = &q.around {
        let target = target.to_ascii_uppercase();
        let visible = store::messages::by_id(&state.db, &target).await?.is_some_and(|m| {
            m.conversation_id == conv.id
                && m.thread_id == thread
                && (m.encrypted == 0 || cut.as_deref().is_none_or(|c| m.id.as_str() >= c))
        });
        if !visible {
            return Err(access::not_found("Message", "message.not_found"));
        }
        let rows = store::messages::list_around(
            &state.db,
            &conv.id,
            &target,
            validate::limit(q.limit, 50, 100),
            cut.as_deref(),
            filter,
        )
        .await?;
        return Ok(Json(enrich(state, &auth.user.id, &rows).await?));
    }
    let rows = store::messages::list(
        &state.db,
        &conv.id,
        validate::limit(q.limit, 50, 100),
        q.before.as_deref(),
        q.after.as_deref(),
        cut.as_deref(),
        q.epoch,
        filter,
    )
    .await?;
    Ok(Json(enrich(state, &auth.user.id, &rows).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMessageRequest {
    /// Plaintext: content object (`{"type":"text","body":"…"}`); encrypted: base64url string.
    #[schema(value_type = Value)]
    pub content: Value,
    /// IDs of previously uploaded blobs of this channel (at most 10).
    #[serde(default)]
    pub attachments: Vec<String>,
    /// Plaintext only: the attachments (a subset of `attachments`) shown as spoilers.
    /// Encrypted messages carry `spoiler: true` in the attachment entries of the encrypted content.
    #[serde(default)]
    pub spoilers: Vec<String>,
    pub reply_to_id: Option<String>,
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default)]
    pub mentions_everyone: bool,
    /// MLS epoch (encrypted only)
    pub epoch: Option<i64>,
    /// Plaintext only: device signature `base64url(nonce(16) || Ed25519 signature(64))` (FEDERATION.md
    /// §10.3). Rejected in encrypted conversations; mentions must then be sent normalized (lowercase,
    /// without duplicates) because the node stores them as signed.
    pub signature: Option<String>,
    /// Write into this thread of the channel (PROTOCOL.md §7e): needs `create_threads` in text and announcement
    /// channels, `manage_threads` in a locked thread; an archived thread reopens.
    pub thread_id: Option<String>,
    /// Close time of a poll (PROTOCOL.md §7g): RFC 3339 with an offset, 1 minute to 1 year ahead, any content. Needs
    /// `create_polls`; the node refuses votes after it.
    pub poll_closes_at: Option<String>,
}

pub(crate) struct Validated {
    pub(crate) content: String,
    pub(crate) mentions: Vec<String>,
}

/// Checks content against the conversation's encryption mode and the size/format rules.
pub(crate) fn validate_content(
    gif_hosts: &[&str],
    encrypted: bool,
    content: &Value,
    mentions: &[String],
) -> Result<Validated, ApiError> {
    let serialized = match (encrypted, content) {
        (true, Value::String(s)) => {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err(bad("message.ciphertext_invalid", "Ciphertext must be base64url"));
            }
            s.clone()
        }
        (true, _) => {
            return Err(bad("message.encryption_mismatch", "This channel is encrypted; plaintext is not accepted"));
        }
        (false, Value::String(_)) => {
            return Err(bad("message.encryption_mismatch", "This channel is unencrypted; ciphertext is not accepted"));
        }
        (false, Value::Object(obj)) => {
            let kind = obj
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("message.type_missing", "content.type is missing"))?;
            if kind == "text" || kind == "action" {
                let body = obj
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("message.body_missing", "content.body is missing"))?;
                let n = body.trim().chars().count();
                let gif = obj.get("gif");
                // Embeds (APPLICATIONS.md §6.4): only in `text`; the body may then be empty.
                let embeds = obj.get("embeds").filter(|e| !e.is_null());
                if let Some(embeds) = embeds {
                    if kind != "text" {
                        return Err(bad("message.embeds_invalid", "Only text content carries embeds"));
                    }
                    crate::embeds::validate(embeds)?;
                }
                let has_embeds = embeds.and_then(Value::as_array).is_some_and(|e| !e.is_empty());
                // Components (APPLICATIONS.md §5.10.1): only in `text`; who may send them is checked by the caller.
                if let Some(components) = obj.get("components").filter(|c| !c.is_null()) {
                    if kind != "text" {
                        return Err(crate::components::invalid("components", "Only text content carries components"));
                    }
                    crate::components::validate(components)?;
                }
                let has_rows = crate::components::has_rows(content);
                if (n == 0 && gif.is_none() && !has_embeds && !has_rows) || n > MAX_TEXT_CHARS {
                    return Err(bad("message.body_length", format!("Text: 1 to {MAX_TEXT_CHARS} characters")));
                }
                if let Some(preview) = obj.get("preview") {
                    validate_preview(preview)?;
                }
                if let Some(gif) = gif {
                    let url = gif.get("url").and_then(Value::as_str).unwrap_or("");
                    let preview = gif.get("preview_url").and_then(Value::as_str).unwrap_or(url);
                    if !crate::gifs::valid_gif_url(url, gif_hosts) || !crate::gifs::valid_gif_url(preview, gif_hosts) {
                        return Err(bad("message.gif_invalid", "GIF URL is not from the configured provider"));
                    }
                }
            } else if kind == crate::polls::POLL_TYPE {
                crate::polls::validate_poll(obj)?;
            } else if kind.starts_with("system.")
                || kind == crate::polls::VOTE_TYPE
                || kind == crate::components::COMPONENT_VALUES_TYPE
                || kind == crate::components::MODAL_VALUES_TYPE
            {
                return Err(bad("message.type_reserved", "System messages and poll votes cannot be sent as messages"));
            }
            serde_json::to_string(content).map_err(|e| ApiError::Internal(e.into()))?
        }
        (false, _) => return Err(bad("message.content_invalid", "content must be an object")),
    };
    if serialized.len() > MAX_CONTENT_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "message.too_large",
            detail: format!("Message at most {} KB", MAX_CONTENT_BYTES / 1024),
            meta: serde_json::json!({ "max_bytes": MAX_CONTENT_BYTES }),
        });
    }
    if mentions.len() > MAX_MENTIONS {
        return Err(bad("message.too_many_mentions", format!("At most {MAX_MENTIONS} mentions")));
    }
    let mut clean = Vec::new();
    for m in mentions {
        let m = normalize_mention(m).ok_or_else(|| bad("message.mention_invalid", format!("Invalid mention: {m}")))?;
        if !clean.contains(&m) {
            clean.push(m);
        }
    }
    Ok(Validated { content: serialized, mentions: clean })
}

/// The sender-generated link preview of a plaintext message (PROTOCOL.md §7): an
/// http(s) URL, short texts and an optional inline raster image as a data URL. Readers sanitize it again
/// (encrypted content never passes here); this keeps plaintext channels from storing anything else.
fn validate_preview(preview: &Value) -> Result<(), ApiError> {
    let invalid = || {
        bad(
            "message.preview_invalid",
            "preview: url (http/https), title, description, site, image (data:image/webp|png|jpeg)",
        )
    };
    let obj = preview.as_object().ok_or_else(invalid)?;
    let text = |key: &str, max: usize| {
        let rules = crate::validate::TextRules { min: 0, max, trim: false, controls: true };
        crate::validate::json_text(obj.get(key), rules).is_ok()
    };
    let url = obj.get("url").and_then(Value::as_str).ok_or_else(invalid)?;
    let url_ok = url.len() <= 2048 && (url.starts_with("https://") || url.starts_with("http://"));
    let image_ok = match obj.get("image") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => {
            s.len() <= 60 * 1024
                && ["data:image/webp;base64,", "data:image/png;base64,", "data:image/jpeg;base64,"]
                    .iter()
                    .any(|p| s.starts_with(p))
        }
        Some(_) => false,
    };
    if !url_ok || !image_ok || !text("title", 300) || !text("description", 500) || !text("site", 200) {
        return Err(invalid());
    }
    Ok(())
}

/// A mention entry: a user address (lowercase) or a role (`role:<id>`, the id in canonical uppercase).
fn normalize_mention(m: &str) -> Option<String> {
    let m = m.trim();
    match m.get(..5).filter(|p| p.eq_ignore_ascii_case("role:")) {
        Some(_) => {
            let id = &m[5..];
            util::is_ulid(id).then(|| store::messages::role_mention(id))
        }
        None => {
            let m = m.to_lowercase();
            util::parse_address(&m).is_some().then_some(m)
        }
    }
}

/// Custom emoji tokens of a plaintext body against `use_external_emojis`. Encrypted bodies
/// are invisible to the node; clients enforce the same rule there.
async fn check_body_emojis(state: &AppState, conv: &Conv, content: &Value) -> Result<(), ApiError> {
    let body = content.get("body").and_then(Value::as_str).unwrap_or("");
    let refs = crate::emoji::tokens(body);
    crate::emoji::check_external(state, conv, &refs).await
}

/// Role mentions (`role:<id>`): only in room channels, only roles of the room, and roles that are not
/// mentionable only with `mention_everyone`.
pub(crate) fn check_role_mentions(conv: &Conv, mentions: &[String]) -> Result<(), ApiError> {
    let roles: Vec<&str> = mentions.iter().filter_map(|m| m.strip_prefix("role:")).collect();
    if roles.is_empty() {
        return Ok(());
    }
    let ConvKind::Channel { access, .. } = &conv.kind else {
        return Err(bad("message.mention_invalid", "Roles can only be mentioned in room channels"));
    };
    let room_roles = &access.roles;
    for id in roles {
        let role = room_roles
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(id) && r.is_everyone == 0)
            .ok_or_else(|| bad("message.mention_invalid", format!("Unknown role {id}")))?;
        if role.mentionable == 0 && !p::has(conv.perms, p::MENTION_EVERYONE) {
            return Err(ApiError::Forbidden {
                code: "message.mention_role_forbidden",
                detail: format!("The role {} cannot be mentioned (needs mention_everyone)", role.name),
            });
        }
    }
    Ok(())
}

/// Device signature of a plaintext message (FEDERATION.md §10.3). The node cannot verify it (it does
/// not know every device key), so it only checks the place and the format and then stores it together
/// with the covered fields unchanged. Because the signature covers `mentions` in envelope order, a
/// signed message must send them already normalized; the node never rewrites signed fields.
fn validate_signature(
    encrypted: bool,
    signature: Option<&str>,
    sent_mentions: &[String],
    stored_mentions: &[String],
) -> Result<Option<String>, ApiError> {
    let Some(signature) = signature else {
        return Ok(None);
    };
    if encrypted {
        return Err(bad(
            "message.signature_invalid",
            "Only plaintext messages carry a signature field (encrypted content is signed inside)",
        ));
    }
    if tavrn_crypto::PlaintextSignature::parse(signature).is_err() {
        return Err(bad("message.signature_invalid", "signature must be base64url (no padding) of 80 bytes"));
    }
    if sent_mentions != stored_mentions {
        return Err(bad(
            "message.mention_invalid",
            "Signed messages must send mentions lowercase, trimmed and without duplicates",
        ));
    }
    Ok(Some(signature.to_owned()))
}

/// How long after a commit content under the epoch it ended is still accepted (ENCRYPTION.md §5.3).
pub const PREVIOUS_EPOCH_GRACE_SECS: i64 = 60;

/// Node checks for encrypted content (ENCRYPTION.md §5.3): header, epoch equal to the envelope
/// epoch, the group's current epoch (or the previous one within [`PREVIOUS_EPOCH_GRACE_SECS`] of the
/// commit that ended it), sending device attested. Returns the epoch.
pub(crate) async fn check_ciphertext(
    state: &AppState,
    auth: &AuthUser,
    conversation_id: &str,
    content: &str,
    epoch: Option<i64>,
) -> Result<i64, ApiError> {
    let header = tavrn_crypto::content_header(content)
        .map_err(|_| bad("message.ciphertext_invalid", "Not valid encrypted content (format 1)"))?;
    let epoch = epoch
        .filter(|e| *e >= 0 && *e as u64 == header.epoch)
        .ok_or_else(|| bad("message.epoch_mismatch", "epoch must match the epoch in the encrypted content"))?;
    let Some((current, since)) = store::e2ee::group_epoch_since(&state.db, conversation_id).await? else {
        return Err(bad("message.epoch_unknown", "The node does not know this epoch (yet)"));
    };
    if epoch > current {
        return Err(bad("message.epoch_unknown", "The node does not know this epoch (yet)"));
    }
    let in_grace = || {
        util::parse_time(&since)
            .is_some_and(|t| chrono::Utc::now() - t <= chrono::Duration::seconds(PREVIOUS_EPOCH_GRACE_SECS))
    };
    if epoch < current && !(epoch == current - 1 && in_grace()) {
        return Err(ApiError::Conflict {
            code: "mls.epoch_stale",
            detail: "The group has moved on: process the missing commits and encrypt again".into(),
            meta: serde_json::json!({ "epoch": current }),
        });
    }
    e2ee::attested_session_key(state, auth).await?;
    Ok(epoch)
}

pub(crate) fn gif_hosts(state: &AppState) -> &'static [&'static str] {
    state.gifs.as_ref().map(|g| g.allowed_hosts()).unwrap_or(&[])
}

/// System message (e.g. encryption toggled). Always plaintext, even in encrypted channels, because it
/// comes from the node and carries no user content.
pub async fn system_message(
    state: &AppState,
    channel: &Channel,
    actor: &UserRow,
    kind: &str,
    mut data: Value,
) -> Result<Message, ApiError> {
    if let Value::Object(obj) = &mut data {
        obj.insert("type".into(), Value::String(kind.into()));
    }
    let content = data.to_string();
    let id = util::ulid();
    let row = store::messages::insert(
        &state.db,
        NewMessage {
            id: &id,
            conversation_id: &channel.id,
            author_id: &actor.id,
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
    Ok(row.to_api())
}

/// Send a message (`send_messages`; `mention_everyone` for @everyone).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = CreateMessageRequest,
    responses((status = 201, body = Message), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<CreateMessageRequest>,
) -> Result<(StatusCode, Json<Message>), ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    create_in(&state, &auth, &conv, req).await
}

/// Send a message to any conversation. DMs and group DMs only accept encrypted content.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/messages", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = CreateMessageRequest,
    responses((status = 201, body = Message), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create_conversation_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<CreateMessageRequest>,
) -> Result<(StatusCode, Json<Message>), ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    create_in(&state, &auth, &conv, req).await
}

/// Blocked users cannot write in a 1:1 DM.
pub(crate) async fn check_not_blocked(state: &AppState, auth: &AuthUser, conv: &Conv) -> Result<(), ApiError> {
    if let ConvKind::Direct { row, member_ids, .. } = &conv.kind
        && row.kind == "dm"
    {
        for other in member_ids.iter().filter(|m| *m != &auth.user.id) {
            if store::social::blocked_either(&state.db, &auth.user.id, other).await? {
                return Err(ApiError::Forbidden {
                    code: "dm.blocked",
                    detail: "Messages to this person are not possible".into(),
                });
            }
        }
    }
    Ok(())
}

/// Every write into a DM or group DM besides messages (reactions, pins, uploads, renaming, adding members) needs what
/// a message needs there (PROTOCOL.md §8a): no block between the two people of a DM, and an accepted request.
pub(crate) async fn check_direct_write(state: &AppState, auth: &AuthUser, conv: &Conv) -> Result<(), ApiError> {
    check_not_blocked(state, auth, conv).await?;
    if conv.is_request_for(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "conversation.request_pending",
            detail: "Accept the message request first, then reply".into(),
        });
    }
    Ok(())
}

/// Where a message may be written, whoever writes it (the message routes, a bot's interaction reply or follow-up):
/// a member of a text channel, no block between the members of a DM, no pending message request, `view_channel`
/// and `send_messages`.
pub(crate) async fn check_writable(state: &AppState, auth: &AuthUser, conv: &Conv) -> Result<(), ApiError> {
    if let ConvKind::Channel { access, channel } = &conv.kind {
        if access.member.is_none() {
            return Err(ApiError::Forbidden { code: "room.not_member", detail: "Only members can write".into() });
        }
        if channel.kind == "voice" {
            return Err(bad("channel.no_text", "Voice channels have no text area in this version"));
        }
        if channel.kind == "files" {
            return Err(bad("channel.no_text", "Files channels have no messages"));
        }
        if channel.kind == "system" {
            return Err(ApiError::Forbidden {
                code: "channel.read_only",
                detail: "Only the node writes in the welcome channel".into(),
            });
        }
    }
    check_not_blocked(state, auth, conv).await?;
    if conv.is_request_for(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "conversation.request_pending",
            detail: "Accept the message request first, then reply".into(),
        });
    }
    conv.require(p::VIEW_CHANNEL | p::SEND_MESSAGES, "message.send_forbidden", "Send messages")
}

/// The channel's slowmode for a stored message of `user_id` (members with `manage_messages` are exempt).
pub(crate) async fn check_slowmode(state: &AppState, conv: &Conv, perms: u64, user_id: &str) -> Result<(), ApiError> {
    if let ConvKind::Channel { channel, .. } = &conv.kind
        && channel.slowmode_secs > 0
        && !p::has(perms, p::MANAGE_MESSAGES)
        && let Some(last) = store::messages::last_created_by_author(&state.db, &conv.id, user_id).await?
        && let Some(last_t) = util::parse_time(&last)
    {
        let elapsed = (chrono::Utc::now() - last_t).num_seconds();
        if elapsed < channel.slowmode_secs {
            return Err(ApiError::RateLimited { retry_after_secs: (channel.slowmode_secs - elapsed) as u32 });
        }
    }
    Ok(())
}

/// Writes a message into `conv` or one of its threads.
pub(crate) async fn create_in(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    req: CreateMessageRequest,
) -> Result<(StatusCode, Json<Message>), ApiError> {
    // Bots: 5 messages per 5 seconds and conversation (APPLICATIONS.md §2.7).
    if auth.user.is_bot() {
        state.bot_message_limiter.check_all(&[format!("bot-msg:{}:{}", auth.user.id, conv.id)])?;
    }
    check_writable(state, auth, conv).await?;
    let perms = conv.perms;
    // Threads, forum and announcement channels (PROTOCOL.md §7e).
    let thread = match &req.thread_id {
        Some(t) => Some(crate::threads::of_conversation(state, conv, t).await?),
        None => None,
    };
    crate::threads::check_write(conv, thread.as_ref())?;
    if req.mentions_everyone {
        conv.require(p::MENTION_EVERYONE, "message.mention_everyone_forbidden", "Mention @everyone")?;
    }
    check_slowmode(state, conv, perms, &auth.user.id).await?;
    if let Some(reply) = &req.reply_to_id {
        match store::messages::by_id(&state.db, reply).await? {
            Some(m) if m.conversation_id == conv.id => {}
            _ => {
                return Err(bad("message.reply_target_missing", "The message being replied to does not exist"));
            }
        }
    }
    if req.attachments.len() > 10 {
        return Err(bad("message.too_many_attachments", "At most 10 attachments per message"));
    }
    if !req.attachments.is_empty() {
        conv.require(p::ATTACH_FILES, "upload.forbidden", "Attach files")?;
        for a in &req.attachments {
            validate::ulid("attachments", a)?;
        }
    }
    // `TAVRN_DEV_MISBEHAVE=plaintext_ok`: a development node that breaks the protocol on purpose
    // (conformance tests, FEDERATION.md §9.1 `msg.plaintext`) takes plaintext in encrypted channels.
    let encrypted = conv.encrypted && !(state.config.misbehaves("plaintext_ok") && req.content.is_object());
    let v = validate_content(gif_hosts(state), encrypted, &req.content, &req.mentions)?;
    // Components only on bots' messages (APPLICATIONS.md §5.10.1); encrypted content is the clients' business.
    if !encrypted {
        crate::components::refuse_unless_bot(&req.content, auth.user.is_bot())?;
    }
    check_role_mentions(conv, &v.mentions)?;
    if !encrypted {
        check_body_emojis(state, conv, &req.content).await?;
    }
    // Polls (PROTOCOL.md §7g): `create_polls` where the node sees a poll (plaintext) or a close time.
    if (!encrypted && is_poll(&req.content)) || req.poll_closes_at.is_some() {
        conv.require(p::CREATE_POLLS, "message.poll_forbidden", "Create polls")?;
    }
    let closes_at =
        req.poll_closes_at.as_deref().map(|c| crate::polls::closes_at_for_create(c, chrono::Utc::now())).transpose()?;
    if req.spoilers.iter().any(|s| !req.attachments.contains(s)) {
        return Err(bad("message.spoiler_invalid", "spoilers must name attachments of this message"));
    }
    if encrypted && !req.spoilers.is_empty() {
        return Err(bad("message.spoiler_invalid", "Encrypted messages carry spoilers inside the encrypted content"));
    }
    let signature = validate_signature(encrypted, req.signature.as_deref(), &req.mentions, &v.mentions)?;
    // Content rules of unencrypted conversations (MODERATION.md §2.2): text and the attachments' file names.
    let hit = if encrypted {
        None
    } else {
        let mut names = Vec::new();
        for a in &req.attachments {
            if let Some(b) = store::blobs::by_id(&state.db, a).await?.filter(|b| b.conversation_id == conv.id) {
                names.push(b.name);
            }
        }
        crate::automod::evaluate(state, conv, &req.content, &names).await?
    };
    if let Some(h) = hit.as_ref().filter(|h| h.blocks()) {
        return Err(crate::automod::blocked(state, conv, &auth.user, h).await);
    }
    let epoch =
        if encrypted { Some(check_ciphertext(state, auth, &conv.id, &v.content, req.epoch).await?) } else { None };
    let id = util::ulid();
    // The message, its attachments, spoilers and poll close time are written together or not at all: a failure
    // halfway would leave a message nobody was told about. The transaction rolls back when dropped.
    let mut tx = state.db.begin().await?;
    store::messages::insert_on(
        &mut tx,
        &NewMessage {
            id: &id,
            conversation_id: &conv.id,
            author_id: &auth.user.id,
            device_id: Some(auth.public_device_id()),
            encrypted: conv.encrypted,
            format: 1,
            epoch,
            content: &v.content,
            reply_to_id: req.reply_to_id.as_deref(),
            thread_id: thread.as_ref().map(|t| t.id.as_str()),
            mentions: &v.mentions,
            mentions_everyone: req.mentions_everyone,
            signature: signature.as_deref(),
        },
    )
    .await?;
    if !req.attachments.is_empty() {
        let bound = store::blobs::bind_to_message_on(&mut tx, &req.attachments, &id, &auth.user.id, &conv.id).await?;
        if bound.len() != req.attachments.len() {
            tx.rollback().await?;
            return Err(bad(
                "message.attachment_invalid",
                "An attachment does not belong to you or to this channel, or was already used",
            ));
        }
        if !req.spoilers.is_empty() {
            store::blobs::mark_spoilers_on(&mut tx, &id, &req.spoilers).await?;
        }
    }
    if let Some(closes_at) = &closes_at {
        store::polls::set_closes_at_on(&mut tx, &id, closes_at).await?;
    }
    tx.commit().await?;
    let message = enrich_one(state, &auth.user.id, &id).await?;
    // `delete` and `timeout` rules: accepted, but never shown to anyone else.
    if let Some(h) = &hit {
        crate::automod::remove(state, conv, &auth.user, h, &id).await?;
        return Ok((StatusCode::CREATED, Json(message)));
    }
    if let ConvKind::Channel { access, channel } = &conv.kind
        && let Some(alert) = automod_check(state, access, channel, &auth.user).await?
    {
        return Err(alert);
    }
    if let Some(t) = &thread {
        crate::threads::after_message(state, &t.id, &message).await?;
    }
    conv.publish_recorded(state, "message.create", message.for_broadcast()).await;
    crate::federation::social::notify_members(state, conv, &message, &auth.user.id).await;
    // Plaintext channel messages go into the node's search index (with their file names), after delivery.
    if !conv.encrypted {
        crate::search::index(state, &message, matches!(conv.kind, ConvKind::Channel { .. })).await;
    }
    Ok((StatusCode::CREATED, Json(message)))
}

/// Detects message floods from metadata (works with E2EE too): deletes the burst, sets a timeout and
/// informs moderators and node admins.
pub(crate) async fn automod_check(
    state: &AppState,
    access: &access::RoomAccess,
    channel: &ChannelRow,
    user: &UserRow,
) -> Result<Option<ApiError>, ApiError> {
    let limit = i64::from(state.config.automod_burst_limit);
    if limit == 0 || access.is_owner || access.is_node_admin || access.has(p::MODERATE_MEMBERS) {
        return Ok(None);
    }
    let since = util::format_time(chrono::Utc::now() - chrono::Duration::seconds(AUTOMOD_WINDOW_SECS));
    let recent = store::messages::count_recent_by_author(&state.db, &channel.id, &user.id, &since).await?;
    if recent <= limit {
        return Ok(None);
    }
    let filter = store::messages::PurgeFilter {
        conversation_ids: vec![channel.id.clone()],
        author_id: Some(user.id.clone()),
        from: Some(since.clone()),
        to: None,
    };
    // The burst goes with its files (uploads attached to the deleted messages).
    let deleted = purge_with_blobs(state, &filter).await?;
    let minutes = i64::from(state.config.automod_timeout_minutes);
    let until = (minutes > 0).then(|| util::in_seconds(minutes * 60));
    if until.is_some() {
        crate::routes::rooms::set_timeout_announced(state, &access.room.id, &user.id, until.as_deref()).await?;
    }
    store::rooms::audit(&state.db, Some(&access.room.id), None, "automod.spam", &user.address(), "Message flood", serde_json::json!({ "channel_id": channel.id, "deleted": deleted, "window_secs": AUTOMOD_WINDOW_SECS, "timeout_minutes": minutes })).await?;
    state.hub.room(&access.room.id, "message.purge", serde_json::json!({ "room_id": access.room.id, "conversation_ids": [channel.id], "author_id": user.id, "from": since, "to": Value::Null, "deleted": deleted }));
    let mut recipients = store::rooms::moderator_ids(&state.db, &access.room.id).await?;
    recipients.retain(|r| r != &user.id);
    state.hub.users(
        recipients,
        "moderation.alert",
        serde_json::json!({
            "room_id": access.room.id, "channel_id": channel.id, "user": user.to_public(), "kind": "spam",
            "deleted": deleted, "timeout_until": until, "at": now()
        }),
    );
    tracing::warn!(room = access.room.id, user = user.address(), deleted, "Auto-moderation: message flood");
    Ok(Some(ApiError::Forbidden {
        code: "automod.spam",
        detail: format!(
            "Too many messages in a short time. {deleted} messages were removed and you are temporarily muted."
        ),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct EditMessageRequest {
    /// The new content; absent when the request only closes a poll early (`poll_closes_at`).
    #[serde(default)]
    #[schema(value_type = Option<Value>)]
    pub content: Option<Value>,
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default)]
    pub mentions_everyone: bool,
    /// MLS epoch (encrypted only; edits use the current epoch)
    pub epoch: Option<i64>,
    /// Plaintext only: device signature `base64url(nonce(16) || Ed25519 signature(64))` (FEDERATION.md
    /// §10.3). Rejected in encrypted conversations; mentions must then be sent normalized (lowercase,
    /// without duplicates) because the node stores them as signed.
    pub signature: Option<String>,
    /// Close a poll early (PROTOCOL.md §7g): a time not after the node's clock closes it now (also a poll without a
    /// close time); a later time only moves an existing close time earlier. Without `content` the author or a member
    /// with `manage_messages` may send it; a close time never moves later and a poll without one never gets a future
    /// one.
    pub poll_closes_at: Option<String>,
}

/// Edit an own message.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path)), request_body = EditMessageRequest, responses((status = 200, body = Message), (status = 409, body = ProblemDetails)))]
pub async fn edit_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id)): Path<(String, String, String)>,
    ApiJson(req): ApiJson<EditMessageRequest>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    edit_in(&state, &auth, &conv, &message_id, req).await
}

/// Edit an own message in any conversation.
#[utoipa::path(patch, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path)), request_body = EditMessageRequest, responses((status = 200, body = Message), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn edit_conversation_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<EditMessageRequest>,
) -> Result<Json<Message>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    edit_in(&state, &auth, &conv, &message_id, req).await
}

/// Is this plaintext content object a poll (PROTOCOL.md §7g)?
fn is_poll(content: &Value) -> bool {
    content.get("type").and_then(Value::as_str) == Some(crate::polls::POLL_TYPE)
}

/// `PATCH …/messages/{id} { poll_closes_at }` without content: closes a poll early (PROTOCOL.md §7g).
async fn close_poll(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    existing: &MessageRow,
    closes_at: &str,
) -> Result<Json<Message>, ApiError> {
    let own = existing.author_id == auth.user.id;
    if !own && !p::has(conv.perms, p::MANAGE_MESSAGES) {
        return Err(ApiError::Forbidden {
            code: "message.not_author",
            detail: "Only the author or a member with manage_messages closes a poll".into(),
        });
    }
    // A timeout limits writing (permissions.md step 5), closing a poll too.
    if let ConvKind::Channel { access, .. } = &conv.kind
        && !access.is_owner
        && !access.is_node_admin
        && access.member.as_ref().is_some_and(crate::models::MemberRow::is_timed_out)
    {
        return Err(ApiError::Forbidden {
            code: "member.timed_out",
            detail: "Members in timeout cannot close polls".into(),
        });
    }
    let stored = crate::polls::closes_at_for_close(closes_at, existing.poll_closes_at.as_deref(), chrono::Utc::now())?;
    store::polls::set_closes_at(&state.db, &existing.id, &stored).await?;
    if !own && let Some(room_id) = conv.room_id() {
        store::rooms::audit(
            &state.db,
            Some(room_id),
            Some(&auth.user.id),
            "message.poll_close",
            &existing.id,
            "",
            serde_json::json!({ "channel_id": conv.id, "author_id": existing.author_id, "poll_closes_at": stored }),
        )
        .await?;
    }
    let message = enrich_one(state, &auth.user.id, &existing.id).await?;
    conv.publish_recorded(state, "message.update", message.for_broadcast()).await;
    Ok(Json(message))
}

pub(crate) async fn edit_in(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    message_id: &str,
    req: EditMessageRequest,
) -> Result<Json<Message>, ApiError> {
    let Some(content) = req.content.as_ref() else {
        let Some(closes_at) = req.poll_closes_at.as_deref() else {
            return Err(bad("message.content_missing", "content is missing (or poll_closes_at to close a poll)"));
        };
        conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
        let existing = access::message(state, &auth.user, conv, message_id, access::Window::Ignore).await?;
        return close_poll(state, auth, conv, &existing, closes_at).await;
    };
    conv.require(p::VIEW_CHANNEL | p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
    let existing = access::message(state, &auth.user, conv, message_id, access::Window::Ignore).await?;
    let canonical = existing.id.clone();
    let message_id = canonical.as_str();
    if existing.author_id != auth.user.id {
        return Err(ApiError::Forbidden {
            code: "message.not_author",
            detail: "Only own messages can be edited".into(),
        });
    }
    if existing.content.starts_with("{\"type\":\"system.") || existing.device_id.is_none() {
        return Err(bad("message.system_immutable", "System messages cannot be edited"));
    }
    if req.mentions_everyone {
        conv.require(p::MENTION_EVERYONE, "message.mention_everyone_forbidden", "Mention @everyone")?;
    }
    check_not_blocked(state, auth, conv).await?;
    let v = validate_content(gif_hosts(state), conv.encrypted, content, &req.mentions)?;
    check_role_mentions(conv, &v.mentions)?;
    if !conv.encrypted {
        crate::components::refuse_unless_bot(content, auth.user.is_bot())?;
        check_body_emojis(state, conv, content).await?;
        // Polls cannot be edited, and no message becomes one by an edit (PROTOCOL.md §7g).
        let was_poll =
            existing.encrypted == 0 && serde_json::from_str::<Value>(&existing.content).is_ok_and(|c| is_poll(&c));
        if was_poll || is_poll(content) {
            return Err(bad("message.poll_immutable", "Polls cannot be edited"));
        }
    }
    let closes_at = match req.poll_closes_at.as_deref() {
        Some(c) => Some(crate::polls::closes_at_for_close(c, existing.poll_closes_at.as_deref(), chrono::Utc::now())?),
        None => None,
    };
    let signature = validate_signature(conv.encrypted, req.signature.as_deref(), &req.mentions, &v.mentions)?;
    let hit = if conv.encrypted {
        None
    } else {
        let names: Vec<String> =
            store::blobs::by_message(&state.db, message_id).await?.into_iter().map(|b| b.name).collect();
        crate::automod::evaluate(state, conv, content, &names).await?
    };
    if let Some(h) = hit.as_ref().filter(|h| h.blocks()) {
        return Err(crate::automod::blocked(state, conv, &auth.user, h).await);
    }
    let epoch =
        if conv.encrypted { Some(check_ciphertext(state, auth, &conv.id, &v.content, req.epoch).await?) } else { None };
    store::messages::update_content(
        &state.db,
        store::messages::ContentUpdate {
            id: message_id,
            content: &v.content,
            mentions: &v.mentions,
            mentions_everyone: req.mentions_everyone,
            device_id: auth.public_device_id(),
            epoch,
            signature: signature.as_deref(),
        },
    )
    .await?;
    if let Some(closes_at) = &closes_at {
        store::polls::set_closes_at(&state.db, message_id, closes_at).await?;
    }
    let message = enrich_one(state, &auth.user.id, message_id).await?;
    if let Some(h) = &hit {
        crate::automod::remove(state, conv, &auth.user, h, message_id).await?;
        return Ok(Json(message));
    }
    conv.publish_recorded(state, "message.update", message.for_broadcast()).await;
    if !conv.encrypted {
        crate::search::index(state, &message, matches!(conv.kind, ConvKind::Channel { .. })).await;
    }
    Ok(Json(message))
}

/// Permanently delete a message: own ones always, others' with `manage_messages`.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("channel_id" = String, Path), ("message_id" = String, Path)), responses((status = 204), (status = 403, body = ProblemDetails)))]
pub async fn delete_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, message_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let conv = access::channel_conversation(&state, &room_id, &channel_id, &auth.user).await?;
    delete_in(&state, &auth, &conv, &message_id).await
}

/// Delete a message in any conversation (own messages; others' with `manage_messages`).
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("message_id" = String, Path)), responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_conversation_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    delete_in(&state, &auth, &conv, &message_id).await
}

async fn delete_in(state: &AppState, auth: &AuthUser, conv: &Conv, message_id: &str) -> Result<StatusCode, ApiError> {
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    let existing = access::message(state, &auth.user, conv, message_id, access::Window::Ignore).await?;
    let message_id = existing.id.as_str();
    // The welcome channel is the room's security log: nobody deletes its entries (MODERATION.md §3).
    if let ConvKind::Channel { channel, .. } = &conv.kind
        && channel.kind == "system"
    {
        return Err(ApiError::Forbidden {
            code: "message.system_protected",
            detail: "Entries of the welcome channel cannot be deleted".into(),
        });
    }
    // Nor the security notices in a channel, not even by the bot they name (APPLICATIONS.md §3.6).
    if existing.notice != 0 {
        return Err(ApiError::Forbidden {
            code: "message.system_protected",
            detail: "Security notices cannot be deleted".into(),
        });
    }
    let own = existing.author_id == auth.user.id;
    if !own {
        conv.require(p::MANAGE_MESSAGES, "message.delete_forbidden", "Manage messages")?;
    }
    let blobs = store::blobs::by_message(&state.db, message_id).await?;
    store::messages::delete(&state.db, message_id).await?;
    for b in &blobs {
        state.storage.delete(&b.id).await;
    }
    if let Some(thread_id) = &existing.thread_id {
        store::threads::recount(&state.db, std::slice::from_ref(thread_id)).await?;
        crate::threads::publish(state, "thread.update", thread_id).await?;
    }
    if !own && let Some(room_id) = conv.room_id() {
        store::rooms::audit(
            &state.db,
            Some(room_id),
            Some(&auth.user.id),
            "message.delete",
            message_id,
            "",
            serde_json::json!({ "channel_id": conv.id, "author_id": existing.author_id }),
        )
        .await?;
    }
    conv.publish_recorded(
        state,
        "message.delete",
        serde_json::json!({ "room_id": conv.room_id(), "conversation_id": conv.id, "id": message_id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Bulk deletion including the files of the affected messages.
pub async fn purge_with_blobs(state: &AppState, filter: &store::messages::PurgeFilter) -> Result<i64, ApiError> {
    let (where_sql, binds) = store::messages::purge_where(filter);
    let (blob_ids, threads) = if where_sql.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (
            store::blobs::ids_for_messages(&state.db, &where_sql, &binds).await?,
            store::threads::ids_for_messages(&state.db, &where_sql, &binds).await?,
        )
    };
    let deleted = store::messages::purge(&state.db, filter).await?;
    for id in &blob_ids {
        state.storage.delete(id).await;
    }
    // The threads the purge touched count their messages again (PROTOCOL.md §7e).
    store::threads::recount(&state.db, &threads).await?;
    for id in &threads {
        crate::threads::publish(state, "thread.update", id).await?;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_rules() {
        let ok = validate_content(
            &["media.giphy.com"],
            false,
            &serde_json::json!({ "type": "text", "body": "hi" }),
            &["bob@x.example".into()],
        );
        assert_eq!(ok.map(|v| v.mentions).map_err(|e| e.code().to_string()), Ok(vec!["bob@x.example".to_string()]));
        let codes = |v: Value, m: &[String]| {
            validate_content(&["media.giphy.com"], false, &v, m).map(|_| ()).map_err(|e| e.code().to_string())
        };
        assert_eq!(codes(serde_json::json!({ "type": "text", "body": "" }), &[]), Err("message.body_length".into()));
        assert_eq!(codes(serde_json::json!({ "type": "action", "body": "" }), &[]), Err("message.body_length".into()));
        assert_eq!(codes(serde_json::json!({ "type": "action", "body": "waves" }), &[]), Ok(()));
        let role = validate_content(
            &[],
            false,
            &serde_json::json!({ "type": "text", "body": "hi" }),
            &["ROLE:01jaaaaaaaaaaaaaaaaaaaaaaa".into(), "Bob@X.example".into()],
        )
        .map(|v| v.mentions)
        .map_err(|e| e.code().to_string());
        assert_eq!(role, Ok(vec!["role:01JAAAAAAAAAAAAAAAAAAAAAAA".to_string(), "bob@x.example".to_string()]));
        assert_eq!(
            codes(serde_json::json!({ "type": "text", "body": "x" }), &["role:nope".into()]),
            Err("message.mention_invalid".into())
        );
        assert_eq!(codes(serde_json::json!({ "body": "x" }), &[]), Err("message.type_missing".into()));
        assert_eq!(codes(serde_json::json!({ "type": "system.join" }), &[]), Err("message.type_reserved".into()));
        assert_eq!(codes(Value::String("Y2lwaGVy".into()), &[]), Err("message.encryption_mismatch".into()));
        assert_eq!(
            codes(serde_json::json!({ "type": "text", "body": "x" }), &["not-valid".into()]),
            Err("message.mention_invalid".into())
        );
        assert_eq!(
            codes(serde_json::json!({ "type": "text", "body": "a".repeat(4001) }), &[]),
            Err("message.body_length".into())
        );
        assert_eq!(
            codes(serde_json::json!({ "type": "custom", "blob": "x".repeat(70_000) }), &[]),
            Err("message.too_large".into())
        );
    }

    #[test]
    fn signature_rules() {
        let sig = tavrn_crypto::PlaintextSignature { nonce: [1; 16], signature: [2; 64] }.to_base64url();
        let m = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let code = |encrypted, s: Option<&str>, sent: &[String], stored: &[String]| {
            validate_signature(encrypted, s, sent, stored).map_err(|e| e.code().to_string())
        };
        assert_eq!(code(false, None, &[], &[]), Ok(None));
        assert_eq!(code(true, None, &[], &[]), Ok(None));
        assert_eq!(code(false, Some(&sig), &[], &[]), Ok(Some(sig.clone())));
        let ok = m(&["bob@x.example"]);
        assert_eq!(code(false, Some(&sig), &ok, &ok), Ok(Some(sig.clone())));
        assert_eq!(code(true, Some(&sig), &[], &[]), Err("message.signature_invalid".into()));
        for bad in [
            "",
            "abc",
            &sig[..106],
            &format!("{sig}A"),
            &format!("{}=", &sig[..106]),
            &sig.replace(|c: char| c.is_ascii_digit(), "+"),
        ] {
            if bad != sig {
                assert_eq!(code(false, Some(bad), &[], &[]), Err("message.signature_invalid".into()), "{bad}");
            }
        }
        // Signed mentions are stored exactly as sent: normalization would break the signature.
        assert_eq!(code(false, Some(&sig), &m(&["Bob@x.example"]), &ok), Err("message.mention_invalid".into()));
        assert_eq!(
            code(false, Some(&sig), &m(&["bob@x.example", "bob@x.example"]), &ok),
            Err("message.mention_invalid".into())
        );
    }

    #[test]
    fn link_previews_are_checked() {
        let code = |preview: Value| {
            validate_content(
                &[],
                false,
                &serde_json::json!({ "type": "text", "body": "https://a.example", "preview": preview }),
                &[],
            )
            .map(|_| ())
            .map_err(|e| e.code().to_string())
        };
        let ok = serde_json::json!({ "url": "https://a.example", "title": "T", "description": "D", "site": "a", "image": "data:image/webp;base64,AAAA" });
        assert_eq!(code(ok), Ok(()));
        assert_eq!(code(serde_json::json!({ "url": "http://a.example" })), Ok(()));
        let bad = "message.preview_invalid".to_string();
        assert_eq!(code(serde_json::json!("https://a.example")), Err(bad.clone()));
        assert_eq!(code(serde_json::json!({ "url": "javascript:alert(1)" })), Err(bad.clone()));
        assert_eq!(
            code(serde_json::json!({ "url": "https://a.example", "image": "https://tracker.example/p.gif" })),
            Err(bad.clone())
        );
        assert_eq!(
            code(serde_json::json!({ "url": "https://a.example", "image": "data:image/svg+xml;base64,AAAA" })),
            Err(bad.clone())
        );
        assert_eq!(code(serde_json::json!({ "url": "https://a.example", "title": "x".repeat(301) })), Err(bad.clone()));
        assert_eq!(code(serde_json::json!({ "url": "https://a.example", "title": 5 })), Err(bad));
    }

    #[test]
    fn embeds_are_part_of_the_plaintext_rules() {
        let code = |v: Value| validate_content(&[], false, &v, &[]).map(|_| ()).map_err(|e| e.code().to_string());
        let embed = serde_json::json!([{ "title": "Build", "color": 3066993 }]);
        assert_eq!(
            code(serde_json::json!({ "type": "text", "body": "", "embeds": embed })),
            Ok(()),
            "empty body with embeds"
        );
        assert_eq!(
            code(serde_json::json!({ "type": "text", "body": "", "embeds": [] })),
            Err("message.body_length".into())
        );
        assert_eq!(
            code(
                serde_json::json!({ "type": "text", "body": "x", "embeds": [{ "title": "x", "url": "http://a.example" }] })
            ),
            Err("message.embeds_invalid".into())
        );
        assert_eq!(
            code(serde_json::json!({ "type": "action", "body": "x", "embeds": embed })),
            Err("message.embeds_invalid".into())
        );
    }

    #[test]
    fn ciphertext_rules() {
        let codes = |v: Value| validate_content(&[], true, &v, &[]).map(|_| ()).map_err(|e| e.code().to_string());
        assert_eq!(codes(Value::String("Y2lwaGVy_-".into())), Ok(()));
        assert_eq!(codes(Value::String("not base64url!".into())), Err("message.ciphertext_invalid".into()));
        assert_eq!(
            codes(serde_json::json!({ "type": "text", "body": "plaintext" })),
            Err("message.encryption_mismatch".into())
        );
    }
}
