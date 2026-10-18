// SPDX-License-Identifier: AGPL-3.0-only
//! `/rtc`: LiveKit's signaling, proxied by the node.
//!
//! LiveKit listens on 127.0.0.1 only. Clients reach it through the node's own domain: the WebSocket at
//! `/rtc` (`/rtc/v1` for newer SDKs) and the HTTP check `/rtc/validate` (`/rtc/v1/validate`). Before
//! anything is forwarded the node verifies the LiveKit token itself (signature with the node's secret,
//! issuer, expiry) and re-checks that its holder may still connect to the channel (member, not banned,
//! `connect`), so a kicked member's unexpired token is worthless; for calls, that the holder is an accepted
//! member of the conversation while its call runs; connection-test tokens only reach their empty room. Nothing else of LiveKit (room service,
//! other paths) is reachable from outside. The token may come as the `access_token` query parameter (livekit-client) or
//! as `Authorization: Bearer` (LiveKit's Rust SDK, the desktop app's native voice engine); either way the checked token
//! is handed on to LiveKit as a bearer header.

use std::{collections::HashMap, sync::OnceLock, time::Duration};

use axum::{
    body::Body,
    extract::{FromRequestParts, Query, Request, State, WebSocketUpgrade, ws},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use livekit_protocol as proto;
use prost::Message as _;
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
        return Err(ApiError::NotFound { code: "route.not_found", what: "Path".into() });
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
        let context =
            state.voice.verify(&token).and_then(|c| voice::parse_room_name(&c.video.room).map(|key| (key, c.sub)));
        // Invalidate the previous connection BEFORE an SFU reconnect can deliver media or a delayed
        // webhook. Only a fresh verified participant join can establish new whisper capabilities.
        if let Some((key, identity)) = &context {
            voice::whisper::invalidate_checked(&state, key, identity).await?;
        }
        let upstream = connect_upstream(&format!("ws://127.0.0.1:{port}{upstream_path}"), &token).await?;
        Ok(upgrade.max_message_size(MAX_MESSAGE).max_frame_size(MAX_MESSAGE).on_upgrade(move |socket| async move {
            if let Some((key, identity)) = context {
                guarded_pump(socket, upstream, state, key, identity).await;
            } else {
                pump(socket, upstream).await;
            }
        }))
    } else {
        forward_http(&format!("http://127.0.0.1:{port}{upstream_path}"), &token).await
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

/// The checked token as LiveKit's bearer header (the query parameter, if any, is passed on as well).
fn bearer(token: &str) -> Result<HeaderValue, ApiError> {
    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| token_invalid())
}

async fn connect_upstream(url: &str, token: &str) -> Result<Upstream, ApiError> {
    use tungstenite::client::IntoClientRequest;
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let mut request = url.into_client_request().map_err(|_| unavailable())?;
    request.headers_mut().insert(header::AUTHORIZATION, bearer(token)?);
    match tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(request, Some(config), true),
    )
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

/// One HTTP client for `/rtc/validate`, so its connections to the local LiveKit are kept and reused (a client per
/// request built a new connection pool, and a new TCP connection, every time).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::Client::builder().timeout(UPSTREAM_TIMEOUT).build().unwrap_or_default())
}

async fn forward_http(url: &str, token: &str) -> Result<Response, ApiError> {
    let resp = http_client().get(url).header(header::AUTHORIZATION, bearer(token)?).send().await.map_err(|e| {
        // Without the URL: its query may carry the client's `access_token`.
        tracing::warn!(error = %e.without_url(), "LiveKit unreachable");
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

/// Whisper publishers cannot widen the SFU's subscription permissions or resume a publication
/// under an expired/revoked authorization. Binary protobuf is required for room signaling.
async fn guarded_pump(
    mut client: ws::WebSocket,
    mut upstream: Upstream,
    state: AppState,
    key: voice::state::ChannelKey,
    identity: String,
) {
    let mut active: Option<(String, String)> = None; // authorization id, track SID (empty until acknowledged)
    let mut must_remove = false;
    let mut acl = WhisperAcl::default();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            message = client.next() => {
                let Some(Ok(mut message)) = message else { break };
                if let ws::Message::Binary(bytes) = &message {
                    let Ok(mut request) = proto::SignalRequest::decode(bytes.clone()) else { break };
                    match &mut request.message {
                        Some(proto::signal_request::Message::AddTrack(track)) if track.name.starts_with("whisper") => {
                            let Some(id) = track.name.strip_prefix("whisper:") else { break };
                            if active.is_some() || track.source != proto::TrackSource::Microphone as i32
                                || track.encryption != proto::encryption::Type::Gcm as i32 || !track.sid.is_empty() { break; }
                            let Ok(session) = voice::whisper::authorized(&state, &key, &identity, id).await else { break };
                            // Applied on the same ordered signaling connection BEFORE AddTrack: no default-all
                            // subscription window exists, even for an unmuted hostile publisher.
                            if upstream.send(acl.frame(Some(&session.recipients))).await.is_err() { break; }
                            active = Some((id.to_string(), String::new()));
                        }
                        Some(proto::signal_request::Message::SubscriptionPermission(_)) => {
                            // Ordinary tracks are public to every permitted listener. A renamed mic
                            // plus a private client ACL can never bypass initiation authorization.
                            let session = if let Some((id, _)) = &active {
                                let Ok(session) = voice::whisper::authorized(&state, &key, &identity, id).await else { break };
                                Some(session)
                            } else { None };
                            request.message = Some(proto::signal_request::Message::SubscriptionPermission(acl.permissions(session.as_ref().map(|s| s.recipients.as_slice()))));
                        }
                        Some(proto::signal_request::Message::SyncState(sync)) => {
                            if active.is_some() || sync.publish_tracks.iter().any(|p| p.track.as_ref().is_some_and(|t| t.name.starts_with("whisper"))) { must_remove = true; break; }
                        }
                        // A publisher cannot add alternate codecs to an existing whisper SID under another name.
                        Some(proto::signal_request::Message::AddTrack(track)) if active.as_ref().is_some_and(|(_, sid)| !sid.is_empty() && track.sid == *sid) => { break; }
                        _ => {}
                    }
                    message = ws::Message::Binary(request.encode_to_vec().into());
                } else if matches!(message, ws::Message::Text(_)) { break; }
                let closing = matches!(message, ws::Message::Close(_));
                if upstream.send(to_tungstenite(message)).await.is_err() || closing { break; }
            }
            message = upstream.next() => {
                let Some(Ok(message)) = message else { break };
                if let tungstenite::Message::Binary(bytes) = &message
                    && let Ok(response) = proto::SignalResponse::decode(bytes.clone()) {
                        let mut changed = false;
                        match response.message {
                            Some(proto::signal_response::Message::Join(join)) => {
                                for participant in &join.other_participants { acl.participant(participant); }
                                if let Some(own) = join.participant {
                                    // Never resume a whisper from a previous signaling connection.
                                    if own.tracks.iter().any(|t| t.name.starts_with("whisper")) { must_remove = true; break; }
                                    acl.ordinary.extend(own.tracks.into_iter().map(|t| t.sid));
                                }
                                changed = true;
                            }
                            Some(proto::signal_response::Message::Update(update)) => {
                                for participant in &update.participants { acl.participant(participant); }
                                changed = true;
                            }
                            Some(proto::signal_response::Message::TrackPublished(published)) => {
                                if let Some(track) = published.track {
                                    if track.name.starts_with("whisper") {
                                        let Some((id, sid)) = &mut active else { break };
                                        if track.name != format!("whisper:{id}") { break; }
                                        *sid = track.sid;
                                    } else { acl.ordinary.insert(track.sid); }
                                    changed = true;
                                }
                            }
                            Some(proto::signal_response::Message::TrackUnpublished(unpublished)) => {
                                if active.as_ref().is_some_and(|(_, sid)| !sid.is_empty() && *sid == unpublished.track_sid) {
                                    // SFU confirmed removal. Only now may normal subscriptions resume.
                                    active = None;
                                }
                                acl.ordinary.remove(&unpublished.track_sid);
                                changed = true;
                            }
                            _ => {}
                        }
                        if changed {
                            let session = if let Some((id, _)) = &active {
                                let Ok(session) = voice::whisper::authorized(&state, &key, &identity, id).await else { break };
                                Some(session)
                            } else { None };
                            // A new ordinary camera/microphone is granted to outsiders by SID before
                            // forwarding publication ACK; unknown/new whisper SIDs stay deny-default.
                            if upstream.send(acl.frame(session.as_ref().map(|s| s.recipients.as_slice()))).await.is_err() { break; }
                        }
                }
                let Some(message) = to_axum(message) else { continue };
                let closing = matches!(message, ws::Message::Close(_));
                if client.send(message).await.is_err() || closing { break; }
            }
            _ = interval.tick(), if active.is_some() => {
                if let Some((id, _)) = &active
                    && voice::whisper::authorized(&state, &key, &identity, id).await.is_err() { break; }
            }
        }
    }
    let _ = client.close().await;
    let _ = upstream.close(None).await;
    if active.is_some() || must_remove {
        // Closing signaling alone leaves media alive during LiveKit's reconnect grace period.
        voice::remove_from_livekit(&state, &key, &identity).await;
    }
}

#[derive(Default)]
struct WhisperAcl {
    participants: std::collections::BTreeSet<String>,
    ordinary: std::collections::BTreeSet<String>,
}
impl WhisperAcl {
    fn participant(&mut self, participant: &proto::ParticipantInfo) {
        if participant.state == proto::participant_info::State::Disconnected as i32 {
            self.participants.remove(&participant.identity);
        } else {
            self.participants.insert(participant.identity.clone());
        }
    }
    fn permissions(&self, recipients: Option<&[String]>) -> proto::SubscriptionPermission {
        let Some(recipients) = recipients else {
            return proto::SubscriptionPermission { all_participants: true, ..Default::default() };
        };
        let identities: std::collections::BTreeSet<_> = self.participants.iter().chain(recipients.iter()).collect();
        proto::SubscriptionPermission {
            all_participants: false,
            track_permissions: identities
                .into_iter()
                .map(|identity| {
                    let selected = recipients.contains(identity);
                    proto::TrackPermission {
                        participant_identity: identity.clone(),
                        all_tracks: selected,
                        track_sids: if selected { vec![] } else { self.ordinary.iter().cloned().collect() },
                        ..Default::default()
                    }
                })
                .collect(),
        }
    }
    fn frame(&self, recipients: Option<&[String]>) -> tungstenite::Message {
        tungstenite::Message::Binary(
            proto::SignalRequest {
                message: Some(proto::signal_request::Message::SubscriptionPermission(self.permissions(recipients))),
            }
            .encode_to_vec()
            .into(),
        )
    }
}

#[cfg(test)]
mod whisper_acl_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn ordinary_tracks_remain_public_and_only_whisper_is_selective() {
        let mut acl = WhisperAcl::default();
        acl.participants.extend(["bob".into(), "carol".into()]);
        acl.ordinary.insert("TR_microphone".into());
        let recipients = vec!["bob".into()];
        let permission = acl.permissions(Some(&recipients));
        let carol = permission.track_permissions.iter().find(|p| p.participant_identity == "carol").unwrap();
        assert!(!carol.all_tracks);
        assert_eq!(carol.track_sids, vec!["TR_microphone"]);
        assert!(permission.track_permissions.iter().find(|p| p.participant_identity == "bob").unwrap().all_tracks);
        acl.ordinary.insert("TR_new_camera".into());
        let permission = acl.permissions(Some(&recipients));
        let carol = permission.track_permissions.iter().find(|p| p.participant_identity == "carol").unwrap();
        assert!(carol.track_sids.contains(&"TR_new_camera".into()));
        assert!(!carol.track_sids.contains(&"TR_whisper".into()));
        assert!(acl.permissions(None).all_participants, "client private ACL cannot hide renamed ordinary mic");
        acl.participants.insert("dave".into());
        let permission = acl.permissions(Some(&recipients));
        assert!(!permission.track_permissions.iter().find(|p| p.participant_identity == "dave").unwrap().all_tracks);
    }
}
