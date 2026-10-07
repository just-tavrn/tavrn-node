// SPDX-License-Identifier: AGPL-3.0-only
//! `/rtc`: LiveKit's signaling, proxied by the node.
//!
//! LiveKit listens on 127.0.0.1 only. Clients reach it through the node's own domain: the WebSocket at
//! `/rtc` (`/rtc/v1` for newer SDKs) and the HTTP check `/rtc/validate` (`/rtc/v1/validate`). Before
//! anything is forwarded the node verifies the LiveKit token itself (signature with the node's secret,
//! issuer, expiry) and re-checks that its holder may still connect to the channel (member, not banned,
//! `connect`), so a kicked member's unexpired token is worthless; for calls, that the holder is an accepted
//! member of the conversation while its call runs; connection-test tokens only reach their empty room. Nothing else of LiveKit (room service,
//! other paths) is reachable from outside.

use std::{collections::HashMap, time::Duration};

use axum::{
    body::Body,
    extract::{FromRequestParts, Query, Request, State, WebSocketUpgrade, ws},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{self, protocol::WebSocketConfig};

use crate::{access, app::AppState, error::ApiError, permissions as p, store, voice};

/// LiveKit's signaling messages are at most a few MB (its own limit is 2 MiB).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// Sub-paths of `/rtc` that are forwarded.
const PATHS: &[&str] = &["", "/v1", "/validate", "/v1/validate"];

fn token_invalid() -> ApiError {
    ApiError::Unauthorized { code: "voice.token_invalid" }
}

fn forbidden() -> ApiError {
    ApiError::Forbidden {
        code: "voice.connect_forbidden",
        detail: "This voice channel access is not (or no longer) valid".into(),
    }
}

fn unavailable() -> ApiError {
    ApiError::BadGateway { code: "voice.unavailable", detail: "The voice server is unreachable".into() }
}

/// `GET /rtc`, `/rtc/{*rest}`: WebSocket or HTTP, after the token check.
pub async fn proxy(State(state): State<AppState>, req: Request) -> Result<Response, ApiError> {
    if !state.config.voice_enabled {
        return Err(ApiError::Unavailable {
            code: "voice.disabled",
            detail: "Voice channels are switched off on this node".into(),
        });
    }
    let path = req.uri().path().to_string();
    let suffix = path.strip_prefix("/rtc").unwrap_or("/invalid");
    if !PATHS.contains(&suffix) {
        return Err(ApiError::NotFound { code: "route.not_found", what: "Pfad".into() });
    }
    let query = req.uri().query().unwrap_or("").to_string();
    let token = Query::<HashMap<String, String>>::try_from_uri(req.uri())
        .ok()
        .and_then(|q| q.0.get("access_token").cloned())
        .or_else(|| crate::auth::bearer(req.headers()).map(String::from))
        .ok_or_else(token_invalid)?;
    authorize(&state, &token).await?;

    let upstream_path = if query.is_empty() { path.clone() } else { format!("{path}?{query}") };
    let port = state.config.livekit_port;
    let wants_ws = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if wants_ws {
        let (mut parts, _) = req.into_parts();
        let upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &state).await.map_err(|_| {
            ApiError::BadRequest { code: "voice.websocket_invalid", detail: "Invalid WebSocket handshake".into() }
        })?;
        let upstream = connect_upstream(&format!("ws://127.0.0.1:{port}{upstream_path}")).await?;
        Ok(upgrade.max_message_size(MAX_MESSAGE).on_upgrade(move |socket| pump(socket, upstream)))
    } else {
        forward_http(&format!("http://127.0.0.1:{port}{upstream_path}")).await
    }
}

/// Token signed by this node (or refreshed by its LiveKit), and its holder may still connect.
async fn authorize(state: &AppState, token: &str) -> Result<(), ApiError> {
    let claims = state.voice.verify(token).ok_or_else(token_invalid)?;
    if !claims.video.room_join {
        return Err(token_invalid());
    }
    let (address, _) = voice::parse_identity(&claims.sub).ok_or_else(token_invalid)?;
    let (username, domain) = crate::util::parse_address(address).ok_or_else(token_invalid)?;
    let user = store::users::by_username(&state.db, username, domain).await?.ok_or_else(forbidden)?;
    if user.disabled_at.is_some() {
        return Err(forbidden());
    }
    // A connection test (VOICE.md §10.4): an empty hidden room, the token cannot publish anything.
    if voice::is_test_room(&claims.video.room) {
        return Ok(());
    }
    // A call (VOICE.md §11): an accepted member of the conversation while its call runs.
    if let Some(conversation_id) = crate::calls::parse_room_name(&claims.video.room) {
        return match crate::calls::who(state, &conversation_id, &claims.sub).await {
            Some(_) if crate::calls::is_active_anywhere(state, &conversation_id).await => Ok(()),
            _ => Err(forbidden()),
        };
    }
    let key = voice::parse_room_name(&claims.video.room).ok_or_else(token_invalid)?;
    let access = match access::room_access(state, &key.0, &user).await {
        Ok(a) if a.member.is_some() => a,
        Ok(_) | Err(ApiError::Forbidden { .. } | ApiError::NotFound { .. }) => return Err(forbidden()),
        Err(e) => return Err(e),
    };
    let channel = match access::channel_in_room(state, &key.0, &key.1).await {
        Ok(c) if c.kind == "voice" => c,
        Ok(_) | Err(ApiError::NotFound { .. }) => return Err(forbidden()),
        Err(e) => return Err(e),
    };
    let perms = access::channel_perms(state, &access, &channel, &user.id).await?;
    if !p::has(perms, p::CONNECT)
        || store::rooms::is_banned(&state.db, Some(&key.0), &user.address(), &user.domain).await?
    {
        return Err(forbidden());
    }
    Ok(())
}

type Upstream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_upstream(url: &str) -> Result<Upstream, ApiError> {
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    match tokio::time::timeout(UPSTREAM_TIMEOUT, tokio_tungstenite::connect_async_with_config(url, Some(config), true))
        .await
    {
        Ok(Ok((stream, _))) => Ok(stream),
        // LiveKit refused (e.g. 401 for a token it does not accept, 404 for an unknown room): pass it on.
        Ok(Err(tungstenite::Error::Http(resp))) => {
            let status = resp.status();
            let body = resp.into_body().unwrap_or_default();
            Err(ApiError::Forbidden {
                code: if status == StatusCode::UNAUTHORIZED { "voice.token_invalid" } else { "voice.connect_refused" },
                detail: String::from_utf8_lossy(&body[..body.len().min(512)]).trim().to_string(),
            })
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "LiveKit signaling unreachable");
            Err(unavailable())
        }
        Err(_) => Err(unavailable()),
    }
}

async fn forward_http(url: &str) -> Result<Response, ApiError> {
    let client =
        reqwest::Client::builder().timeout(UPSTREAM_TIMEOUT).build().map_err(|e| ApiError::Internal(e.into()))?;
    let resp = client.get(url).send().await.map_err(|e| {
        tracing::warn!(error = %e, "LiveKit unreachable");
        unavailable()
    })?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.map_err(|_| unavailable())?;
    let body = body.slice(..body.len().min(64 * 1024));
    let mut out = Response::new(Body::from(body));
    *out.status_mut() = status;
    out.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    Ok(out.into_response())
}

/// Copies messages both ways until one side closes.
async fn pump(client: ws::WebSocket, upstream: Upstream) {
    let (mut client_tx, mut client_rx) = client.split();
    let (mut up_tx, mut up_rx) = upstream.split();
    let to_upstream = async {
        while let Some(Ok(msg)) = client_rx.next().await {
            let closing = matches!(msg, ws::Message::Close(_));
            if up_tx.send(to_tungstenite(msg)).await.is_err() || closing {
                break;
            }
        }
        let _ = up_tx.close().await;
    };
    let to_client = async {
        while let Some(Ok(msg)) = up_rx.next().await {
            let Some(msg) = to_axum(msg) else { continue };
            let closing = matches!(msg, ws::Message::Close(_));
            if client_tx.send(msg).await.is_err() || closing {
                break;
            }
        }
        let _ = client_tx.close().await;
    };
    // Whichever side ends first ends the proxy; dropping the other half closes its connection.
    tokio::select! {
        () = to_upstream => {}
        () = to_client => {}
    }
}

fn to_tungstenite(msg: ws::Message) -> tungstenite::Message {
    match msg {
        ws::Message::Text(t) => tungstenite::Message::Text(t.as_str().into()),
        ws::Message::Binary(b) => tungstenite::Message::Binary(b),
        ws::Message::Ping(b) => tungstenite::Message::Ping(b),
        ws::Message::Pong(b) => tungstenite::Message::Pong(b),
        ws::Message::Close(frame) => tungstenite::Message::Close(
            frame.map(|f| tungstenite::protocol::CloseFrame { code: f.code.into(), reason: f.reason.as_str().into() }),
        ),
    }
}

fn to_axum(msg: tungstenite::Message) -> Option<ws::Message> {
    Some(match msg {
        tungstenite::Message::Text(t) => ws::Message::Text(t.as_str().into()),
        tungstenite::Message::Binary(b) => ws::Message::Binary(b),
        tungstenite::Message::Ping(b) => ws::Message::Ping(b),
        tungstenite::Message::Pong(b) => ws::Message::Pong(b),
        tungstenite::Message::Close(frame) => {
            ws::Message::Close(frame.map(|f| ws::CloseFrame { code: f.code.into(), reason: f.reason.as_str().into() }))
        }
        tungstenite::Message::Frame(_) => return None,
    })
}
