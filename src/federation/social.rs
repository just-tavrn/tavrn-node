// SPDX-License-Identifier: AGPL-3.0-only
//! Friends, invitations and push hints across nodes (FEDERATION.md §4, §5.2, §6).
//!
//! Sending: [`friend`] (`friend.request` / `friend.accept` / `friend.remove`), [`invite_to_room`]
//! (`room.invite`, or the local invite list for local invitees), [`invite_to_conversation`]
//! (`conversation.invite`) and [`notify_members`] (`notify` hints to the home nodes of remote members
//! who have no WebSocket here).
//!
//! Receiving ([`parse`] and [`handle`], called by the inbox after its authority checks): invitations go
//! to the recipient's invite list unless the recipient blocked the inviter (and, for conversations,
//! unless this node's `dm_policy` refuses the inviter); friend messages are applied in `at` order per
//! pair (§5.4); `notify` is stored for push and forwarded as WS `notify`; `ban.notify` is information
//! only (WS `ban.notify`).

use serde_json::{Value, json};

use super::outbox;
use crate::{
    access::{Conv, ConvKind},
    app::AppState,
    config::DmPolicy,
    error::ApiError,
    models::{Invite, Message, Room, UserRow},
    store::{self, invites::NewUserInvite, social::ConversationRow},
    util,
};

/// Room and conversation invitations expire after this time (§3.4).
pub const INVITE_TTL_SECS: i64 = 7 * 24 * 3600;
pub const MAX_CONVERSATION_MEMBERS: usize = 50;

fn invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

// ---------------------------------------------------------------- sending

/// Queues a notification from `from` (an address or this node's domain) to a user of another node.
async fn send(state: &AppState, from: &str, to: &UserRow, kind: &str, payload: Value) -> Result<(), ApiError> {
    if to.domain == state.config.domain {
        return Ok(());
    }
    outbox::enqueue(state, &to.domain, kind, from, &to.address(), payload).await?;
    Ok(())
}

/// `friend.request` / `friend.accept` / `friend.remove` from a local user to a remote user.
pub async fn friend(
    state: &AppState,
    local: &UserRow,
    remote: &UserRow,
    kind: &str,
    request_id: Option<&str>,
) -> Result<(), ApiError> {
    send(state, &local.address(), remote, kind, json!({ "request_id": request_id })).await
}

/// `friend.request` with the requester's optional message (≤ 256 characters).
pub async fn friend_request_to(
    state: &AppState,
    local: &UserRow,
    remote: &UserRow,
    request_id: &str,
    message: Option<&str>,
) -> Result<(), ApiError> {
    send(state, &local.address(), remote, "friend.request", json!({ "request_id": request_id, "message": message }))
        .await
}

/// Stores an invitation in a local user's invite list and pushes it over the WebSocket.
#[allow(clippy::too_many_arguments)]
async fn store_invite(
    state: &AppState,
    user: &UserRow,
    kind: &str,
    node: &str,
    target_id: &str,
    summary: &Value,
    inviter: &str,
    invite_code: Option<&str>,
    expires_at: &str,
) -> Result<(), ApiError> {
    let row = store::invites::put(
        &state.db,
        NewUserInvite {
            user_id: &user.id,
            kind,
            node,
            target_id,
            summary: &summary.to_string(),
            inviter,
            invite_code,
            expires_at,
        },
    )
    .await?;
    let event = if kind == "room" { "room.invite" } else { "conversation.invite" };
    state.hub.users(vec![user.id.clone()], event, json!({ "invite": crate::routes::invites::view(&row) }));
    Ok(())
}

/// The room summary of a `room.invite` (§5.2). `icon_url` stays null: clients never load images from
/// other nodes.
pub fn room_summary(node: &str, room: &Room, member_count: i64) -> Value {
    json!({
        "node": node, "id": room.id, "name": room.name, "description": room.description,
        "icon_url": null, "member_count": member_count,
    })
}

/// Delivers a direct invite: into the invite list of a local invitee, or as `room.invite` to the home
/// node of a remote invitee.
pub async fn invite_to_room(
    state: &AppState,
    inviter: &UserRow,
    invitee: &UserRow,
    room: &Room,
    invite: &Invite,
) -> Result<(), ApiError> {
    let node = &state.config.domain;
    let summary = room_summary(node, room, store::rooms::member_count(&state.db, &room.id).await?);
    let expires_at = invite.expires_at.clone().unwrap_or_else(|| util::in_seconds(INVITE_TTL_SECS));
    if invitee.domain == *node {
        if store::social::has_blocked(&state.db, &invitee.id, &inviter.id).await? {
            return Ok(());
        }
        return store_invite(
            state,
            invitee,
            "room",
            node,
            &room.id,
            &summary,
            &inviter.address(),
            Some(&invite.code),
            &expires_at,
        )
        .await;
    }
    let payload = json!({ "room": summary, "invite_code": invite.code, "expires_at": expires_at });
    send(state, &inviter.address(), invitee, "room.invite", payload).await
}

/// `conversation.invite` to the home nodes of the remote users among `invitees`. Invitees whose
/// membership is a message request get `requested: true` and the rooms of this node they share with the
/// inviter (`shared_rooms`, this node vouches only for its own rooms); their home node decides by the
/// recipient's setting whether the request is shown or dropped (FEDERATION.md §6.1).
pub async fn invite_to_conversation(
    state: &AppState,
    inviter: &UserRow,
    conversation: &ConversationRow,
    invitees: &[UserRow],
) -> Result<(), ApiError> {
    let member_ids = store::social::member_ids(&state.db, &conversation.id).await?;
    let requested = store::social::requested_ids(&state.db, &conversation.id).await?;
    let members: Vec<String> =
        store::users::by_ids(&state.db, &member_ids).await?.iter().map(UserRow::address).collect();
    for invitee in invitees.iter().filter(|u| u.domain != state.config.domain) {
        let is_request = requested.contains(&invitee.id);
        let shared: Vec<Value> = if is_request {
            store::rooms::shared_rooms(&state.db, &inviter.id, &invitee.id)
                .await?
                .into_iter()
                .take(MAX_SHARED_ROOMS)
                .map(|(id, name)| json!({ "node": state.config.domain, "id": id, "name": name }))
                .collect()
        } else {
            Vec::new()
        };
        let payload = json!({ "conversation": {
            "node": state.config.domain, "id": conversation.id, "kind": conversation.kind,
            "name": conversation.name, "members": members,
        }, "requested": is_request, "shared_rooms": shared });
        send(state, &inviter.address(), invitee, "conversation.invite", payload).await?;
    }
    Ok(())
}

/// Shared rooms listed in a message request.
pub const MAX_SHARED_ROOMS: usize = 10;

/// `notify` hints (§5.2) for a new message: to the home nodes of remote members without an open
/// WebSocket on this node, for DMs and group DMs and for mentions in channels, coalesced to one per
/// conversation and member per minute. Never carries content, author or message id. Failures are logged.
///
/// Every path that creates a message calls this, so it also counts the message (`metrics.rs`) and queues the web
/// pushes of local members (`push.rs`, never blocks).
pub async fn notify_members(state: &AppState, conv: &Conv, message: &Message, author_id: &str) {
    state.metrics.message(message.encrypted);
    crate::push::message(state, message, author_id, matches!(conv.kind, ConvKind::Direct { .. }));
    if !state.config.federation_enabled {
        return;
    }
    if let Err(e) = notify_inner(state, conv, message, author_id).await {
        tracing::warn!(error = %e, "notify hints not queued");
    }
}

/// Does the message mention the user by address or by one of their roles (`role:<id>`)?
fn direct_mention(message: &Message, user: &UserRow, role_ids: &[String]) -> bool {
    message.mentions_user(&user.address(), role_ids)
}

async fn notify_inner(state: &AppState, conv: &Conv, message: &Message, author_id: &str) -> Result<(), ApiError> {
    let own = &state.config.domain;
    let (candidates, room_id) = match &conv.kind {
        // Message requests raise no notifications until they are accepted.
        ConvKind::Direct { member_ids, requested, .. } => {
            let active: Vec<String> = member_ids.iter().filter(|m| !requested.contains(m)).cloned().collect();
            (store::users::by_ids(&state.db, &active).await?.into_iter().map(|u| (u, Vec::new())).collect(), None)
        }
        ConvKind::Channel { access, .. } => {
            let mut users = Vec::new();
            // Thread messages (PROTOCOL.md §7e) reach the thread's followers (every message; their home node applies
            // their settings) and the users they mention directly; `@everyone` inside a thread reaches followers only.
            // Never members who cannot view the channel (PROTOCOL.md §6), whatever they follow or are mentioned in.
            let followers: Option<Vec<String>> = match &message.thread_id {
                Some(t) => Some(store::threads::follower_ids(&state.db, t).await?),
                None => None,
            };
            if followers.as_ref().is_some_and(|f| !f.is_empty())
                || message.mentions_everyone
                || !message.mentions.is_empty()
            {
                let Some(view) = crate::visibility::room(state, &access.room.id).await? else { return Ok(()) };
                let viewers = view.viewers(&conv.id);
                for member in view.members().filter(|m| m.user.domain != *own && viewers.contains(&m.user.id)) {
                    let (u, roles) = (&member.user, &member.role_ids);
                    let wanted = match &followers {
                        Some(f) => f.contains(&u.id) || direct_mention(message, u, roles),
                        None => message.mentions_everyone || direct_mention(message, u, roles),
                    };
                    if wanted {
                        users.push((u.clone(), roles.clone()));
                    }
                }
            }
            (users, Some(access.room.id.clone()))
        }
    };
    let candidates: Vec<(UserRow, Vec<String>)> = candidates
        .into_iter()
        .filter(|(user, _)| user.id != author_id && user.domain != *own && !crate::presence::is_online(state, &user.id))
        .collect();
    let keys: Vec<String> = candidates.iter().map(|(user, _)| format!("{}|{}", user.id, conv.id)).collect();
    let passed = state.notify_limiter.check_many(&keys).await;
    let mut hints = Vec::new();
    for ((user, roles), ok) in candidates.into_iter().zip(passed) {
        if !ok {
            continue;
        }
        // `mention`: the user or one of their roles is mentioned, or @everyone; `everyone`: only @everyone
        // (the home node applies the user's "suppress @everyone" setting with it).
        let direct = direct_mention(message, &user, &roles);
        let mention = direct || message.mentions_everyone;
        let everyone = message.mentions_everyone && !direct;
        let payload = json!({ "node": own, "conversation_id": conv.id, "room_id": room_id, "mention": mention, "everyone": everyone });
        hints.push((user.domain.clone(), user.address(), payload));
    }
    // One statement for all of them (an @everyone in a room with many remote members).
    outbox::enqueue_many(state, "notify", own, hints).await
}

// ---------------------------------------------------------------- receiving

/// A validated payload of a type handled here.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    RoomInvite {
        room: Value,
        room_id: String,
        invite_code: String,
        expires_at: String,
    },
    ConversationInvite {
        conversation: Value,
        conversation_id: String,
        kind: String,
        members: Vec<String>,
        /// A message request (the inviter is not a friend on the hosting node).
        requested: bool,
        /// Rooms of the sending node shared by inviter and recipient: `{ node, id, name }`.
        shared_rooms: Vec<Value>,
    },
    FriendRequest {
        request_id: String,
        message: Option<String>,
    },
    FriendAccept,
    FriendRemove {
        request_id: Option<String>,
    },
    Notify {
        conversation_id: String,
        room_id: Option<String>,
        mention: bool,
        /// The mention is only `@everyone` (optional field; older nodes do not send it).
        everyone: bool,
        /// A ring hint of a call (VOICE.md §11): the recipient's devices ring or stop ringing.
        call: Option<CallHint>,
    },
    BanNotify {
        room: Value,
        scope: String,
    },
}

/// The `call` field of a `notify` hint (VOICE.md §11.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallHint {
    /// A call started: ring the recipient's devices.
    Ring { from: String, started_at: String, group: bool },
    /// The call was answered elsewhere, declined, or ended: stop ringing.
    End,
}

fn parse_call_hint(v: &Value) -> Result<CallHint, ApiError> {
    match string(v, "state") {
        Some("ring") => {
            let from = string(v, "from")
                .filter(|a| util::parse_address(a).is_some())
                .ok_or_else(|| invalid("call.from is not an address"))?;
            let started_at = string(v, "started_at")
                .and_then(util::parse_time)
                .map(util::format_time)
                .ok_or_else(|| invalid("invalid call.started_at"))?;
            let group = v.get("group").and_then(Value::as_bool).unwrap_or(false);
            Ok(CallHint::Ring { from: from.to_string(), started_at, group })
        }
        Some("end") => Ok(CallHint::End),
        _ => Err(invalid("call.state must be ring or end")),
    }
}

/// A `notify` hint carrying only a call state (`ring` or `end`) to a remote member's home node. Not
/// coalesced: rings are rare (one per started call) and must arrive at once.
pub async fn call_hint(state: &AppState, conversation_id: &str, to: &UserRow, call: Value) -> Result<(), ApiError> {
    if !state.config.federation_enabled {
        return Ok(());
    }
    let own = &state.config.domain;
    let payload =
        json!({ "node": own, "conversation_id": conversation_id, "room_id": null, "mention": false, "call": call });
    send(state, own, to, "notify", payload).await
}

fn string<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn ulid_field(v: &Value, key: &str) -> Result<String, ApiError> {
    string(v, key).filter(|s| util::is_ulid(s)).map(String::from).ok_or_else(|| invalid(&format!("invalid {key}")))
}

fn short_text(v: &Value, key: &str, max: usize, required: bool) -> Result<Option<String>, ApiError> {
    match v.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(s)) => {
            let t = crate::validate::text(key, s, usize::from(required), max)
                .map_err(|_| invalid(&format!("invalid {key}")))?;
            Ok(Some(t))
        }
        _ => Err(invalid(&format!("invalid {key}"))),
    }
}

/// Validates the payload of `kind` sent by `iss`. `None` for types not handled here.
pub fn parse(kind: &str, iss: &str, payload: &Value) -> Result<Option<Incoming>, ApiError> {
    let request_id = || ulid_field(payload, "request_id");
    Ok(Some(match kind {
        "friend.request" => {
            Incoming::FriendRequest { request_id: request_id()?, message: short_text(payload, "message", 256, false)? }
        }
        "friend.accept" => {
            request_id()?;
            Incoming::FriendAccept
        }
        "friend.remove" => Incoming::FriendRemove {
            request_id: match payload.get("request_id") {
                None | Some(Value::Null) => None,
                Some(_) => Some(request_id()?),
            },
        },
        "room.invite" => {
            let room = payload.get("room").ok_or_else(|| invalid("room missing"))?;
            if string(room, "node") != Some(iss) {
                return Err(invalid("room.node is not the sender"));
            }
            let room_id = ulid_field(room, "id")?;
            let name = short_text(room, "name", 100, true)?;
            let description = short_text(room, "description", 1000, false)?;
            let member_count = room.get("member_count").and_then(Value::as_i64).filter(|n| *n >= 0).unwrap_or(0);
            let invite_code = string(payload, "invite_code")
                .filter(|c| {
                    (1..=64).contains(&c.len())
                        && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                })
                .ok_or_else(|| invalid("invalid invite_code"))?
                .to_string();
            let latest = chrono::Utc::now() + chrono::Duration::seconds(INVITE_TTL_SECS);
            let expires = string(payload, "expires_at")
                .and_then(util::parse_time)
                .filter(|t| *t > chrono::Utc::now())
                .ok_or_else(|| invalid("invalid expires_at"))?;
            Incoming::RoomInvite {
                room: json!({ "node": iss, "id": room_id, "name": name, "description": description.unwrap_or_default(),
                              "icon_url": null, "member_count": member_count }),
                room_id,
                invite_code,
                expires_at: util::format_time(expires.min(latest)),
            }
        }
        "conversation.invite" => {
            let c = payload.get("conversation").ok_or_else(|| invalid("conversation missing"))?;
            if string(c, "node") != Some(iss) {
                return Err(invalid("conversation.node is not the sender"));
            }
            let conversation_id = ulid_field(c, "id")?;
            let kind =
                string(c, "kind").filter(|k| matches!(*k, "dm" | "group")).ok_or_else(|| invalid("invalid kind"))?;
            let name = short_text(c, "name", 100, false)?;
            let list = c.get("members").and_then(Value::as_array).ok_or_else(|| invalid("invalid members"))?;
            if list.is_empty() || list.len() > MAX_CONVERSATION_MEMBERS {
                return Err(invalid("invalid members"));
            }
            let mut members = Vec::new();
            for m in list {
                let address = m
                    .as_str()
                    .filter(|a| util::parse_address(a).is_some())
                    .ok_or_else(|| invalid("invalid members"))?;
                if !members.iter().any(|x: &String| x == address) {
                    members.push(address.to_string());
                }
            }
            let requested = payload.get("requested").and_then(Value::as_bool).unwrap_or(false);
            let mut shared_rooms = Vec::new();
            for r in payload.get("shared_rooms").and_then(Value::as_array).into_iter().flatten().take(MAX_SHARED_ROOMS)
            {
                // A node vouches only for its own rooms.
                if string(r, "node") != Some(iss) {
                    continue;
                }
                let id = ulid_field(r, "id")?;
                let name = short_text(r, "name", 100, true)?;
                shared_rooms.push(json!({ "node": iss, "id": id, "name": name }));
            }
            Incoming::ConversationInvite {
                conversation: json!({ "node": iss, "id": conversation_id, "kind": kind, "name": name, "members": members,
                                      "requested": requested, "shared_rooms": shared_rooms }),
                conversation_id,
                kind: kind.to_string(),
                members,
                requested,
                shared_rooms,
            }
        }
        "notify" => {
            if string(payload, "node") != Some(iss) {
                return Err(invalid("node is not the sender"));
            }
            let room_id = match payload.get("room_id") {
                None | Some(Value::Null) => None,
                Some(_) => Some(ulid_field(payload, "room_id")?),
            };
            let call = match payload.get("call") {
                None | Some(Value::Null) => None,
                Some(c) => Some(parse_call_hint(c)?),
            };
            Incoming::Notify {
                conversation_id: ulid_field(payload, "conversation_id")?,
                room_id,
                mention: payload.get("mention").and_then(Value::as_bool).unwrap_or(false),
                everyone: payload.get("everyone").and_then(Value::as_bool).unwrap_or(false),
                call,
            }
        }
        "ban.notify" => {
            let room = payload.get("room").ok_or_else(|| invalid("room missing"))?;
            if string(room, "node") != Some(iss) {
                return Err(invalid("room.node is not the sender"));
            }
            let id = ulid_field(room, "id")?;
            let name = short_text(room, "name", 100, false)?;
            let scope = string(payload, "scope")
                .filter(|s| matches!(*s, "room" | "node"))
                .ok_or_else(|| invalid("invalid scope"))?;
            Incoming::BanNotify { room: json!({ "node": iss, "id": id, "name": name }), scope: scope.to_string() }
        }
        _ => return Ok(None),
    }))
}

/// Handles a validated message for the local user `to`. `from` passed the authority rules of §5.2.
pub async fn handle(
    state: &AppState,
    iss: &str,
    from: &str,
    to: &UserRow,
    at: &str,
    incoming: Incoming,
) -> Result<&'static str, ApiError> {
    match incoming {
        Incoming::RoomInvite { room, room_id, invite_code, expires_at } => {
            if !vouches(state, iss, from).await? {
                return Err(not_vouched("inviter"));
            }
            if inviter_blocked(state, to, from).await? {
                return Ok("blocked");
            }
            if state.room_invite_inbox_limiter.check(&format!("{iss}|{}", to.id)).is_err() {
                return Ok("rate_limited");
            }
            let mut room = room;
            if third_party(state, iss, from) {
                room["via"] = json!(iss);
            }
            store_invite(state, to, "room", iss, &room_id, &room, from, Some(&invite_code), &expires_at).await?;
            Ok("stored")
        }
        Incoming::ConversationInvite { mut conversation, conversation_id, kind, members, requested, shared_rooms } => {
            if !members.iter().any(|m| *m == to.address()) || !members.iter().any(|m| m == from) {
                return Err(invalid("inviter and recipient must be members"));
            }
            // A DM lives on its initiator's home node (§6.1); only group members of other nodes may invite.
            if kind == "dm" && util::parse_address(from).is_none_or(|(_, d)| d != iss) {
                return Err(invalid("only the inviter's node invites to direct messages"));
            }
            if !vouches(state, iss, from).await? {
                return Err(not_vouched("inviter"));
            }
            if inviter_blocked(state, to, from).await? {
                return Ok("blocked");
            }
            if state.room_invite_inbox_limiter.check(&format!("conversation|{iss}|{}", to.id)).is_err() {
                return Ok("rate_limited");
            }
            // The recipient's home node decides: friends always, others by the recipient's
            // setting under this node's bound; shared rooms are those of this node and those the hosting
            // node vouches for.
            // An inviter of a third node is only named by the sending node, which cannot vouch for them: a
            // stranger whatever the relationship here, and the invitation names the node it came through.
            let unverified = third_party(state, iss, from);
            let inviter = if unverified { None } else { known(state, from).await? };
            if unverified {
                conversation["via"] = json!(iss);
            }
            let friends = match &inviter {
                Some(inviter) => store::social::are_friends(&state.db, &to.id, &inviter.id).await?,
                None => false,
            };
            if !friends {
                let shared_here = match &inviter {
                    Some(inviter) => !store::rooms::shared_rooms(&state.db, &to.id, &inviter.id).await?.is_empty(),
                    None => false,
                };
                let allowed = match to.dm_policy(state.config.dm_policy) {
                    DmPolicy::Friends => false,
                    DmPolicy::EveryoneShared => shared_here || !shared_rooms.is_empty(),
                    DmPolicy::Everyone => true,
                };
                if !allowed {
                    return Ok("dm_policy");
                }
            }
            // A conversation of a non-friend is always a request here, whatever the hosting node said.
            conversation["requested"] = Value::Bool(requested || !friends);
            let expires_at = util::in_seconds(INVITE_TTL_SECS);
            store_invite(state, to, "conversation", iss, &conversation_id, &conversation, from, None, &expires_at)
                .await?;
            Ok("stored")
        }
        Incoming::FriendRequest { request_id, message } => {
            friend_request(state, from, to, at, &request_id, message.as_deref()).await
        }
        Incoming::FriendAccept => friend_accept(state, from, to, at).await,
        Incoming::FriendRemove { request_id } => friend_remove(state, from, to, at, request_id.as_deref()).await,
        Incoming::Notify { conversation_id, call: Some(call), .. } => {
            if let CallHint::Ring { from, .. } = &call
                && !vouches(state, iss, from).await?
            {
                return Err(not_vouched("caller"));
            }
            // Hints only from a node the user signed in on (a member of something there).
            if !present_on(state, Some(to), iss).await? {
                return Ok("not_member");
            }
            // Ring hints are forwarded live only (a ring that arrives after the ring time is dropped).
            match call {
                CallHint::Ring { from, started_at, group } => {
                    let fresh = util::parse_time(&started_at).is_some_and(|t| {
                        let age = chrono::Utc::now() - t;
                        age < chrono::Duration::seconds(crate::calls::RING_TIMEOUT.as_secs() as i64)
                            && age > chrono::Duration::seconds(-300)
                    });
                    if !fresh {
                        return Ok("stale");
                    }
                    // A caller the recipient blocked does not ring (known remote users only).
                    if let Some((name, domain)) = util::parse_address(&from)
                        && let Some(caller) = store::users::by_username(&state.db, name, domain).await?
                        && store::social::blocked_either(&state.db, &to.id, &caller.id).await?
                    {
                        return Ok("blocked");
                    }
                    // A caller of a third node is named by the hosting node only: the ring says so (`via`).
                    let via = third_party(state, iss, &from).then_some(iss);
                    state.hub.users(
                        vec![to.id.clone()],
                        "call.ring",
                        json!({ "conversation_id": conversation_id, "node": iss, "from": from,
                                "started_at": started_at, "group": group, "via": via }),
                    );
                    // The ring also goes out by web push, also while connected (PROTOCOL.md §6d).
                    let settings = crate::notifications::load(&state.db, &to.id).await?;
                    let effective = settings.effective(None, &conversation_id, &util::now());
                    if !effective.muted && effective.mode != crate::notifications::Mode::Nothing {
                        crate::push::hint(
                            state,
                            &to.id,
                            iss,
                            &conversation_id,
                            None,
                            false,
                            Some((&from, via.is_some())),
                        );
                    }
                }
                CallHint::End => {
                    state.hub.users(
                        vec![to.id.clone()],
                        "call.end",
                        json!({ "conversation_id": conversation_id, "node": iss, "reason": "ended" }),
                    );
                }
            }
            Ok("handled")
        }
        Incoming::Notify { conversation_id, room_id, mention, everyone, call: None } => {
            // Hints only from a node the user signed in on (a member of something there).
            if !present_on(state, Some(to), iss).await? {
                return Ok("not_member");
            }
            // The user's notification settings decide (muted, mode, suppress @everyone): a hint they do not
            // want is neither stored nor forwarded.
            let settings = crate::notifications::load(&state.db, &to.id).await?;
            let effective = settings.effective(room_id.as_deref(), &conversation_id, &util::now());
            if !effective.wants_hint(mention && !everyone, everyone) {
                return Ok("muted");
            }
            let mention = mention && (!everyone || !effective.suppress_everyone);
            store::invites::add_hint(&state.db, &to.id, iss, &conversation_id, room_id.as_deref(), mention).await?;
            // Without a connection here the user gets a web push (PROTOCOL.md §6d; the hint is already coalesced
            // per conversation by the sending node, the push limits apply on top).
            crate::push::hint(state, &to.id, iss, &conversation_id, room_id.as_deref(), mention, None);
            state.hub.users(
                vec![to.id.clone()],
                "notify",
                json!({ "node": iss, "conversation_id": conversation_id, "room_id": room_id, "mention": mention }),
            );
            Ok("stored")
        }
        Incoming::BanNotify { room, scope } => {
            // Only from a node the user signed in on: nobody else can have banned them there.
            if !present_on(state, Some(to), iss).await? {
                return Ok("not_member");
            }
            state.hub.users(vec![to.id.clone()], "ban.notify", json!({ "room": room, "scope": scope }));
            Ok("handled")
        }
    }
}

/// May node `iss` speak for `address` (an inviter, caller or claim requester it names)? Users of `iss` itself and
/// of third nodes: yes (they act there through federated sessions, which this node cannot see). Users of this node:
/// only if they signed in on `iss` (federation targets, §2.4) — otherwise `iss` claims something about them that
/// cannot have happened.
pub async fn vouches(state: &AppState, iss: &str, address: &str) -> Result<bool, ApiError> {
    let Some((name, domain)) = util::parse_address(address) else { return Ok(false) };
    if domain != state.config.domain {
        return Ok(true);
    }
    present_on(state, store::users::by_username(&state.db, name, domain).await?.as_ref(), iss).await
}

/// Is `address` a user of a third node, neither of the sending node `iss` nor of this one? `iss` can name such a
/// user (a member of a group it hosts) but cannot vouch for them: their identity is unverified here.
fn third_party(state: &AppState, iss: &str, address: &str) -> bool {
    util::parse_address(address).is_none_or(|(_, domain)| domain != iss && domain != state.config.domain)
}

/// Has the local user signed in on `node` (a member of something there)?
async fn present_on(state: &AppState, user: Option<&UserRow>, node: &str) -> Result<bool, ApiError> {
    let Some(user) = user else { return Ok(false) };
    Ok(store::federation::target_domains(&state.db, &user.id).await?.iter().any(|t| t == node))
}

fn not_vouched(what: &str) -> ApiError {
    invalid(&format!("the {what} has no session on the sending node"))
}

/// The user row of an address this node already knows (no network).
async fn known(state: &AppState, address: &str) -> Result<Option<UserRow>, ApiError> {
    match util::parse_address(address) {
        Some((name, domain)) => store::federation::user_by_address(&state.db, name, domain).await,
        None => Ok(None),
    }
}

/// Has `to` blocked the inviter (or the inviter `to`)?
async fn inviter_blocked(state: &AppState, to: &UserRow, inviter: &str) -> Result<bool, ApiError> {
    match known(state, inviter).await? {
        Some(u) => store::social::blocked_either(&state.db, &to.id, &u.id).await,
        None => Ok(false),
    }
}

/// The remote sender of a friend message if the message is newer than the last applied one of the pair
/// (§5.4). A request creates the sender as a stub; accepts and removals of unknown senders are ignored.
async fn friend_sender(
    state: &AppState,
    from: &str,
    to: &UserRow,
    at: &str,
    create: bool,
) -> Result<Option<UserRow>, ApiError> {
    let Some((name, domain)) = util::parse_address(from) else { return Err(invalid("invalid from")) };
    let remote = if create {
        super::remote::ensure_remote_user(state, name, domain, "user", None).await?
    } else {
        match store::federation::user_by_address(&state.db, name, domain).await? {
            Some(u) => u,
            None => return Ok(None),
        }
    };
    let at = util::parse_time(at).map(util::format_time).ok_or_else(|| invalid("invalid at"))?;
    if !store::social::friend_sync_apply(&state.db, &to.id, &remote.id, &at).await? {
        return Ok(None);
    }
    Ok(Some(remote))
}

fn friend_events(state: &AppState, local: &UserRow, remote: &UserRow, since: &str) {
    state.hub.users(vec![local.id.clone()], "friend.accept", json!({ "user": remote.to_public(), "since": since }));
}

async fn friend_request(
    state: &AppState,
    from: &str,
    to: &UserRow,
    at: &str,
    request_id: &str,
    message: Option<&str>,
) -> Result<&'static str, ApiError> {
    let Some(remote) = friend_sender(state, from, to, at, true).await? else { return Ok("stale") };
    super::remote::refresh_profile(state, &remote, None).await?;
    if store::social::blocked_either(&state.db, &to.id, &remote.id).await? {
        return Ok("blocked");
    }
    if store::social::are_friends(&state.db, &to.id, &remote.id).await? {
        friend(state, to, &remote, "friend.accept", Some(request_id)).await?;
        return Ok("already_friends");
    }
    if store::social::request_between(&state.db, &to.id, &remote.id).await?.is_some() {
        // Crossing requests: both become friends (§6.2).
        let since = store::social::add_friendship(&state.db, &to.id, &remote.id).await?;
        friend_events(state, to, &remote, &since);
        friend(state, to, &remote, "friend.accept", Some(request_id)).await?;
        return Ok("accepted");
    }
    let row = match store::social::request_between(&state.db, &remote.id, &to.id).await? {
        Some(existing) => {
            store::social::set_remote_request_id(&state.db, &existing.id, request_id).await?;
            existing
        }
        None => {
            match store::social::create_request_with(&state.db, &remote.id, &to.id, Some(request_id), message).await? {
                Some(row) => row,
                None => return Ok("duplicate"),
            }
        }
    };
    let view = crate::routes::friends::request_view(&row, &to.id, &remote);
    state.hub.users(vec![to.id.clone()], "friend.request", json!({ "request": view }));
    Ok("stored")
}

/// The accept names our request id; a request between the two is enough (there is at most one).
async fn friend_accept(state: &AppState, from: &str, to: &UserRow, at: &str) -> Result<&'static str, ApiError> {
    let Some(remote) = friend_sender(state, from, to, at, false).await? else { return Ok("ignored") };
    if store::social::request_between(&state.db, &to.id, &remote.id).await?.is_some() {
        let since = store::social::add_friendship(&state.db, &to.id, &remote.id).await?;
        friend_events(state, to, &remote, &since);
        return Ok("accepted");
    }
    if store::social::are_friends(&state.db, &to.id, &remote.id).await? {
        return Ok("already_friends");
    }
    // No request here (withdrawn meanwhile): tell the other node that there is no friendship.
    friend(state, to, &remote, "friend.remove", None).await?;
    Ok("no_request")
}

async fn friend_remove(
    state: &AppState,
    from: &str,
    to: &UserRow,
    at: &str,
    request_id: Option<&str>,
) -> Result<&'static str, ApiError> {
    let Some(remote) = friend_sender(state, from, to, at, false).await? else { return Ok("ignored") };
    match request_id {
        None => {
            if store::social::remove_friendship(&state.db, &to.id, &remote.id).await? {
                state.hub.users(
                    vec![to.id.clone()],
                    "friend.remove",
                    json!({ "request_id": null, "user": remote.to_public() }),
                );
            }
        }
        Some(rid) => {
            for row in store::social::delete_requests_by_ref(&state.db, &to.id, &remote.id, rid).await? {
                state.hub.users(
                    vec![to.id.clone()],
                    "friend.remove",
                    json!({ "request_id": row.id, "user": remote.to_public() }),
                );
            }
        }
    }
    Ok("handled")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    const ISS: &str = "b.example";

    fn room_invite() -> Value {
        json!({
            "room": { "node": ISS, "id": util::ulid(), "name": " Lobby ", "description": "d",
                      "icon_url": "https://tracker.example/pixel.png", "member_count": 3 },
            "invite_code": "aB3_-x", "expires_at": util::in_seconds(30 * 24 * 3600),
        })
    }

    fn code(r: Result<Option<Incoming>, ApiError>) -> String {
        r.unwrap_err().code().to_string()
    }

    #[test]
    fn room_invites_are_normalized() {
        let Some(Incoming::RoomInvite { room, expires_at, invite_code, .. }) =
            parse("room.invite", ISS, &room_invite()).unwrap()
        else {
            panic!("room invite expected")
        };
        assert_eq!(room["name"], "Lobby");
        assert_eq!(room["icon_url"], Value::Null, "foreign image URLs are never stored");
        assert_eq!(invite_code, "aB3_-x");
        let latest = chrono::Utc::now() + chrono::Duration::seconds(INVITE_TTL_SECS + 5);
        assert!(util::parse_time(&expires_at).unwrap() < latest, "expiry capped to 7 days");
    }

    #[test]
    fn malformed_invitations_are_refused() {
        let mutate = |f: &dyn Fn(&mut Value)| {
            let mut v = room_invite();
            f(&mut v);
            code(parse("room.invite", ISS, &v))
        };
        for case in [
            mutate(&|v| v["room"]["node"] = json!("c.example")),
            mutate(&|v| v["room"]["id"] = json!("../../x")),
            mutate(&|v| v["room"]["name"] = json!("")),
            mutate(&|v| v["room"]["name"] = json!("x".repeat(101))),
            mutate(&|v| v["invite_code"] = json!("a/b")),
            mutate(&|v| v["invite_code"] = json!("a".repeat(65))),
            mutate(&|v| v["expires_at"] = json!(util::in_seconds(-10))),
            mutate(&|v| v["expires_at"] = json!("soon")),
        ] {
            assert_eq!(case, "federation.envelope_invalid");
        }
        let conv = |members: Value| json!({ "conversation": { "node": ISS, "id": util::ulid(), "kind": "group", "members": members } });
        assert!(parse("conversation.invite", ISS, &conv(json!(["al@a.example", "bo@b.example"]))).is_ok());
        assert_eq!(code(parse("conversation.invite", ISS, &conv(json!([])))), "federation.envelope_invalid");
        assert_eq!(code(parse("conversation.invite", ISS, &conv(json!(["no name"])))), "federation.envelope_invalid");
        let many: Vec<String> = (0..51).map(|i| format!("u{i}@a.example")).collect();
        assert_eq!(code(parse("conversation.invite", ISS, &conv(json!(many)))), "federation.envelope_invalid");
        let mut wrong_kind = conv(json!(["al@a.example"]));
        wrong_kind["conversation"]["kind"] = json!("channel");
        assert_eq!(code(parse("conversation.invite", ISS, &wrong_kind)), "federation.envelope_invalid");
    }

    #[test]
    fn friend_notify_and_ban_payloads() {
        let id = util::ulid();
        assert_eq!(
            parse("friend.remove", ISS, &json!({ "request_id": null })).unwrap(),
            Some(Incoming::FriendRemove { request_id: None })
        );
        assert_eq!(
            parse("friend.remove", ISS, &json!({ "request_id": id })).unwrap(),
            Some(Incoming::FriendRemove { request_id: Some(id.clone()) })
        );
        assert_eq!(code(parse("friend.accept", ISS, &json!({}))), "federation.envelope_invalid");
        let notify = json!({ "node": ISS, "conversation_id": id, "room_id": null, "mention": true });
        assert_eq!(
            parse("notify", ISS, &notify).unwrap(),
            Some(Incoming::Notify {
                conversation_id: id.clone(),
                room_id: None,
                mention: true,
                everyone: false,
                call: None
            })
        );
        // Call hints (VOICE.md §11.3): ring with caller and start time, or stop ringing.
        let mut ring = notify.clone();
        ring["call"] =
            json!({ "state": "ring", "from": "alice@a.example", "started_at": "2026-10-05T10:00:00Z", "group": true });
        assert_eq!(
            parse("notify", ISS, &ring).unwrap(),
            Some(Incoming::Notify {
                conversation_id: id.clone(),
                room_id: None,
                mention: true,
                everyone: false,
                call: Some(CallHint::Ring {
                    from: "alice@a.example".into(),
                    started_at: "2026-10-05T10:00:00.000Z".into(),
                    group: true
                }),
            })
        );
        ring["call"] = json!({ "state": "end" });
        assert!(matches!(
            parse("notify", ISS, &ring).unwrap(),
            Some(Incoming::Notify { call: Some(CallHint::End), .. })
        ));
        for bad in [
            json!({ "state": "ring", "from": "not an address", "started_at": "2026-10-05T10:00:00Z" }),
            json!({ "state": "ring", "from": "alice@a.example", "started_at": "yesterday" }),
            json!({ "state": "hangup" }),
            json!("ring"),
        ] {
            ring["call"] = bad;
            assert_eq!(code(parse("notify", ISS, &ring)), "federation.envelope_invalid");
        }
        let mut foreign = notify.clone();
        foreign["node"] = json!("c.example");
        assert_eq!(code(parse("notify", ISS, &foreign)), "federation.envelope_invalid");
        let ban = json!({ "room": { "node": ISS, "id": id, "name": "R" }, "scope": "everywhere" });
        assert_eq!(code(parse("ban.notify", ISS, &ban)), "federation.envelope_invalid");
        assert_eq!(parse("node.announce", ISS, &json!({})).unwrap(), None);
    }
}
