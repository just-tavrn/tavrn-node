// SPDX-License-Identifier: AGPL-3.0-only
//! WebSocket `/api/v1/ws`: hello with a token, then events filtered by membership.

use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::{
    app::AppState,
    auth::{self, AuthUser},
    error::ApiError,
    hub::Scope,
    store,
};

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
pub const CLOSE_RESTART: u16 = 4000;
pub const CLOSE_AUTH: u16 = 4001;
pub const CLOSE_PROTOCOL: u16 = 4002;
/// Typing operations of one connection closer together than this are dropped (clients send every 3 s).
pub const TYPING_MIN_INTERVAL: Duration = Duration::from_millis(1000);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum ClientOp {
    Hello {
        token: String,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default)]
        last_event_id: Option<String>,
    },
    Pong,
    /// Room channels: `room_id` + `channel_id`; DMs and group DMs: `conversation_id`.
    Typing {
        #[serde(default)]
        room_id: Option<String>,
        #[serde(default)]
        channel_id: Option<String>,
        #[serde(default)]
        conversation_id: Option<String>,
    },
    Ack {
        conversation_id: String,
        message_id: String,
    },
}

pub async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(64 * 1024).on_upgrade(move |socket| run(state, socket))
}

async fn close(mut socket: WebSocket, code: u16, reason: &str) {
    let _ = socket.send(WsMessage::Close(Some(axum::extract::ws::CloseFrame { code, reason: reason.into() }))).await;
}

async fn run(state: AppState, mut socket: WebSocket) {
    // 1. Wait for the hello with the token.
    let hello = tokio::time::timeout(HELLO_TIMEOUT, socket.recv()).await;
    let Ok(Some(Ok(WsMessage::Text(text)))) = hello else {
        return close(socket, CLOSE_PROTOCOL, "hello expected").await;
    };
    let Ok(ClientOp::Hello { token, capabilities, last_event_id }) = serde_json::from_str::<ClientOp>(&text) else {
        return close(socket, CLOSE_PROTOCOL, "hello expected").await;
    };
    // The close reason carries the error code (`auth.token_expired`, …): clients refresh and reconnect.
    let auth = match auth::authenticate(&state, &token).await {
        Ok(a) => a,
        Err(ApiError::Unauthorized { code }) => return close(socket, CLOSE_AUTH, code).await,
        Err(_) => return close(socket, CLOSE_AUTH, "auth.token_invalid").await,
    };
    // Terms not accepted (`TAVRN_LEGAL_TERMS_MODE=require`): no events either; the client reconnects after accepting.
    if crate::legal::documents::check_required(&state, &auth.user, None).await.is_err() {
        return close(socket, CLOSE_PROTOCOL, "legal.terms_required").await;
    }
    let mut rooms: HashSet<String> = match store::rooms::rooms_of_user(&state.db, &auth.user.id).await {
        Ok(r) => r.into_iter().map(|r| r.id).collect(),
        Err(_) => return close(socket, CLOSE_RESTART, "datenbank").await,
    };
    let mut rx = state.hub.subscribe();
    let _presence = state.hub.connect(&auth.user.id);
    let _status = crate::presence::Registry::connect(&state, &auth.user.id, &auth.device_id);
    // App tokens (APPLICATIONS.md §2.6): at most two connections per token, events filtered by scope,
    // the connection ends with the token.
    let registration = auth.app.as_ref().and_then(|a| a.token_id.as_deref()).map(|t| state.app_connections.register(t));
    let replaced = registration.as_ref().map(|r| r.replaced.clone()).unwrap_or_else(|| Arc::new(Notify::new()));
    let scopes: Option<Vec<String>> =
        auth.user.is_bot().then(|| auth.app.as_ref().map(|a| a.scopes.clone()).unwrap_or_default());
    // Bots whose token has the `commands` scope receive invocations (APPLICATIONS.md §5.6), one connection each.
    let receiver = scopes
        .as_ref()
        .filter(|s| s.iter().any(|x| x == "commands"))
        .map(|_| state.interactions.register(&auth.user.id, &auth.device_id));
    let connection_id = receiver.as_ref().map(|r| r.id);
    let token_expiry = auth.app.as_ref().and_then(|a| a.expires_at).map(|exp| {
        let secs = u64::try_from(exp - crate::jwt::now_unix()).unwrap_or(0);
        tokio::time::Instant::now() + Duration::from_secs(secs)
    });
    let expired = async move {
        match token_expiry {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(expired);
    let session_id = crate::util::ulid();
    let mut ready = json!({ "op": "ready", "session_id": session_id, "user": auth.user.to_public(), "capabilities": crate::app::capabilities(&state.config), "client_capabilities": capabilities });
    if let Some(app) = &auth.app {
        ready["application_id"] = json!(app.application_id);
    }
    if socket.send(WsMessage::Text(ready.to_string().into())).await.is_err() {
        return;
    }
    // No ring buffer: a `last_event_id` always leads to a resync. With several instances this is also what
    // keeps a reconnect to another instance correct (its events since then are not known here, docs/SCALING.md).
    if last_event_id.is_some()
        && socket.send(WsMessage::Text(json!({ "op": "resync" }).to_string().into())).await.is_err()
    {
        return;
    }

    let (mut sink, mut stream) = socket.split();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut missed_pongs = 0u8;
    let mut last_typing: Option<tokio::time::Instant> = None;

    loop {
        tokio::select! {
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        match serde_json::from_str::<ClientOp>(&text) {
                            Ok(ClientOp::Pong) => missed_pongs = 0,
                            Ok(ClientOp::Typing { .. } | ClientOp::Ack { .. }) if !may_write(scopes.as_deref()) => {}
                            Ok(ClientOp::Typing { room_id, channel_id, conversation_id }) => {
                                let now = tokio::time::Instant::now();
                                if last_typing.is_some_and(|t| now.duration_since(t) < TYPING_MIN_INTERVAL) {
                                    continue;
                                }
                                last_typing = Some(now);
                                typing(&state, &auth, &rooms, room_id, channel_id, conversation_id).await;
                            }
                            Ok(ClientOp::Ack { conversation_id, message_id }) => {
                                if let Err(e) = crate::routes::read::advance(&state, &auth.user, &conversation_id, &message_id).await {
                                    tracing::debug!(error = %e, "read marker could not be set");
                                }
                            }
                            Ok(ClientOp::Hello { .. }) | Err(_) => {}
                        }
                    }
                    Some(Ok(WsMessage::Pong(_))) => missed_pongs = 0,
                    Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(ev) if ev.scope == Scope::All => {
                        // The local resync hint (cache bus disrupted, `Hub::resync_all`): every connection, bots too.
                        if sink.send(WsMessage::Text(ev.frame.clone())).await.is_err() {
                            break;
                        }
                    }
                    Ok(ev) => {
                        track_membership(&ev.kind, &ev.data, &auth, &mut rooms);
                        if let Some(s) = &scopes
                            && !crate::applications::event_allowed(&ev.kind, &ev.data, s)
                        {
                            continue;
                        }
                        let relevant = match &ev.scope {
                            Scope::Room(r) => rooms.contains(r),
                            Scope::Users(u) => u.contains(&auth.user.id),
                            Scope::Devices(d) => d.contains(&auth.device_id),
                            Scope::UsersExceptDevice { users, device } => {
                                users.contains(&auth.user.id) && device != &auth.device_id
                            }
                            Scope::All => true,
                            Scope::Connection(id) => connection_id == Some(*id),
                        };
                        if relevant && ev.kind == crate::federation::inbox::SESSION_REVOKED_EVENT {
                            // The session of this device was revoked (FEDERATION.md §2.9).
                            let frame = axum::extract::ws::CloseFrame { code: CLOSE_AUTH, reason: "session revoked".into() };
                            let _ = sink.send(WsMessage::Close(Some(frame))).await;
                            break;
                        }
                        // Serialized once in `Hub::publish`; this clone only bumps a reference count.
                        if relevant && sink.send(WsMessage::Text(ev.frame.clone())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(user = auth.user.address(), n, "WebSocket lagging behind, resync");
                        if sink.send(WsMessage::Text(json!({ "op": "resync" }).to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            () = replaced.notified() => {
                let frame = axum::extract::ws::CloseFrame { code: crate::applications::CLOSE_REPLACED, reason: "replaced".into() };
                let _ = sink.send(WsMessage::Close(Some(frame))).await;
                break;
            }
            () = &mut expired => {
                let frame = axum::extract::ws::CloseFrame { code: CLOSE_AUTH, reason: "token expired".into() };
                let _ = sink.send(WsMessage::Close(Some(frame))).await;
                break;
            }
            _ = ping.tick() => {
                missed_pongs += 1;
                if missed_pongs > 2 || sink.send(WsMessage::Text(json!({ "op": "ping" }).to_string().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Typing and read markers need `messages:write` for bots (APPLICATIONS.md §2.4); users always may.
fn may_write(scopes: Option<&[String]>) -> bool {
    scopes.is_none_or(|s| s.iter().any(|x| x == "messages:write"))
}

/// Forwards a typing notice: room channels to the room members (the connection must be a member),
/// DMs and group DMs to their members (the sender must be one).
async fn typing(
    state: &AppState,
    auth: &AuthUser,
    rooms: &HashSet<String>,
    room_id: Option<String>,
    channel_id: Option<String>,
    conversation_id: Option<String>,
) {
    match (room_id, channel_id, conversation_id) {
        (Some(room_id), Some(channel_id), _) if rooms.contains(&room_id) => {
            state.hub.room(
                &room_id,
                "typing",
                json!({ "room_id": room_id, "channel_id": channel_id, "user_id": auth.user.id }),
            );
        }
        (None, None, Some(conversation_id)) if crate::util::is_ulid(&conversation_id) => {
            match store::social::member_ids(&state.db, &conversation_id).await {
                Ok(members) if members.contains(&auth.user.id) => {
                    state.hub.users(
                        members,
                        "typing",
                        json!({ "conversation_id": conversation_id, "user_id": auth.user.id }),
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "typing notice not deliverable"),
            }
        }
        _ => {}
    }
}

/// Keeps the connection's room membership up to date from its own join/leave events.
fn track_membership(kind: &str, data: &Value, auth: &AuthUser, rooms: &mut HashSet<String>) {
    let room_id = data.get("room_id").and_then(Value::as_str).or_else(|| data.get("id").and_then(Value::as_str));
    let Some(room_id) = room_id else { return };
    match kind {
        "member.join" if data.pointer("/user/id").and_then(Value::as_str) == Some(auth.user.id.as_str()) => {
            rooms.insert(room_id.to_string());
        }
        "member.leave" if data.get("user_id").and_then(Value::as_str) == Some(auth.user.id.as_str()) => {
            rooms.remove(room_id);
        }
        "room.delete" => {
            rooms.remove(room_id);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> AuthUser {
        AuthUser {
            user: crate::models::UserRow {
                id: "u1".into(),
                username: "a".into(),
                domain: "d".into(),
                display_name: "A".into(),
                kind: "user".into(),
                owner_id: None,
                password_hash: None,
                email: None,
                email_verified_at: None,
                identity_pubkey: None,
                identity_reset_at: None,
                is_node_admin: 0,
                avatar_blob_id: None,
                avatar_animated: 0,
                header_blob_id: None,
                header_animated: 0,
                dm_policy: "everyone_shared".into(),
                presence_status: "online".into(),
                custom_status: None,
                hide_activity: 0,
                created_at: String::new(),
                disabled_at: None,
                owner_address: None,
                application_id: None,
                deleted_at: None,
                app_scopes: None,
            },
            device_id: "dev".into(),
            home_device_id: None,
            app: None,
        }
    }

    #[test]
    fn membership_tracking() {
        let a = auth();
        let mut rooms = HashSet::new();
        track_membership("member.join", &json!({ "room_id": "r1", "user": { "id": "u1" } }), &a, &mut rooms);
        assert!(rooms.contains("r1"));
        track_membership("member.join", &json!({ "room_id": "r2", "user": { "id": "u9" } }), &a, &mut rooms);
        assert!(!rooms.contains("r2"), "other users' joins change nothing");
        track_membership("member.leave", &json!({ "room_id": "r1", "user_id": "u1" }), &a, &mut rooms);
        assert!(!rooms.contains("r1"));
        rooms.insert("r3".into());
        track_membership("room.delete", &json!({ "id": "r3" }), &a, &mut rooms);
        assert!(rooms.is_empty());
    }
}
