// SPDX-License-Identifier: AGPL-3.0-only
//! Requests whose state lives on the leader (voice channels, calls, whiteboard sessions and the LiveKit
//! webhook) are relayed to it by every other instance, so the load balancer may send any request anywhere.
//!
//! The relay is a plain HTTP request to the leader's relay address (`TAVRN_INSTANCE_URL`, announced in its
//! heartbeat) with the original method, path, headers and body, plus `X-Forwarded-For` extended by the address
//! this instance saw (the leader resolves the client address through `TAVRN_TRUSTED_PROXIES` as usual) and
//! `Tavrn-Relayed: <instance id>`, which stops a second hop. Standalone, on the leader, for an already relayed
//! request or while no leader is known the request is served locally. A leader that does not answer gives
//! `503 node.leader_unavailable` with `Retry-After`.
//!
//! Interaction callbacks and follow-ups (`/interactions/{id}/callback|messages`, APPLICATIONS.md §5.7) go the same
//! way to the instance that owns the pending interaction (recorded in the cache by `interactions::invoke`), unless it
//! is pending here. An owner that does not answer gives `503 interaction.owner_unavailable`.

use std::{net::SocketAddr, sync::OnceLock, time::Duration};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{app::AppState, error::ApiError};

pub const HEADER: &str = "tavrn-relayed";
/// Bodies of the relayed routes are small (ephemeral events ≤ 80 KiB, webhooks, JSON).
const MAX_BODY: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

/// `true` for the API paths whose state the leader holds.
pub fn leader_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/v1/") else { return false };
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        ["voice", "webhook"] => true,
        // GET /rooms/{id}/voice, POST /rooms/{id}/voice/move-all
        ["rooms", _, "voice", ..] => true,
        // join, leave, state, members/{address}/(mute|disconnect|move)
        ["rooms", _, "channels", _, "voice", ..] => true,
        ["rooms", _, "channels", _, "soundboard", "play"] => true,
        // GET …/call, …/call/(start|join|leave|decline|state)
        ["conversations", _, "call", ..] => true,
        ["conversations", _, "ephemeral" | "whiteboard"] => true,
        _ => false,
    }
}

/// The interaction id of a callback or follow-up path.
pub fn interaction_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/api/v1/interactions/")?;
    let (id, tail) = rest.split_once('/')?;
    (matches!(tail, "callback" | "messages") && !id.is_empty() && id.len() <= 64).then_some(id)
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_default()
    })
}

fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn unavailable() -> Response {
    ApiError::Pending {
        code: "node.leader_unavailable",
        detail: "The instance holding voice and whiteboard state does not answer; try again shortly".into(),
        retry_after_secs: 2,
    }
    .into_response()
}

/// Axum middleware on the whole router: relays [`leader_path`] requests to the leader and interaction callbacks to
/// the instance owning the interaction.
pub async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let cluster = &state.cluster;
    if !cluster.is_shared() || req.headers().contains_key(HEADER) {
        return next.run(req).await;
    }
    if let Some(id) = interaction_path(req.uri().path()) {
        if state.interactions.contains(id) {
            return next.run(req).await;
        }
        let key = cluster.key(&crate::interactions::owner_key(id));
        let owner = cluster.cache().get(&key).await.ok().flatten();
        let Some(url) = owner.as_deref().and_then(|o| cluster.peer_url(o)) else {
            // Unknown, expired or owned by this instance: the handler answers (404 / 410).
            return next.run(req).await;
        };
        return forward(&state, req, &url, owner_unavailable).await;
    }
    if cluster.is_leader() || !leader_path(req.uri().path()) {
        return next.run(req).await;
    }
    let Some(leader) = cluster.leader_url() else {
        tracing::debug!(path = req.uri().path(), "no leader known, serving locally");
        return next.run(req).await;
    };
    forward(&state, req, &leader, unavailable).await
}

fn owner_unavailable() -> Response {
    ApiError::Pending {
        code: "interaction.owner_unavailable",
        detail: "The instance holding this interaction does not answer; try again shortly".into(),
        retry_after_secs: 2,
    }
    .into_response()
}

/// Sends the request to the instance at `target` and returns its answer (`failed()` when it does not answer).
async fn forward(state: &AppState, req: Request, target: &str, failed: fn() -> Response) -> Response {
    let cluster = &state.cluster;
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let (parts, body) = req.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if !hop_by_hop(name) && name.as_str() != "x-forwarded-for" {
            headers.append(name.clone(), value.clone());
        }
    }
    // Extend the chain as a proxy does: the target then sees this instance as the last hop.
    let mut chain: Vec<String> =
        parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).map(String::from).collect();
    if let Some(ip) = peer {
        chain.push(ip.to_string());
    }
    if let Ok(v) = HeaderValue::from_str(&chain.join(", "))
        && !chain.is_empty()
    {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&cluster.instance_id) {
        headers.insert(HeaderName::from_static(HEADER), v);
    }
    let response =
        client().request(parts.method.clone(), format!("{target}{path}")).headers(headers).body(body).send().await;
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, target = %target, path = parts.uri.path(), "relay to another instance failed");
            return failed();
        }
    };
    let status = response.status();
    let mut out_headers = HeaderMap::new();
    for (name, value) in response.headers() {
        if !hop_by_hop(name) {
            out_headers.append(name.clone(), value.clone());
        }
    }
    let Ok(bytes) = response.bytes().await else { return failed() };
    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    *out.headers_mut() = out_headers;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_paths() {
        let r = "01J9AAAAAAAAAAAAAAAAAAAAAA";
        for p in [
            "/api/v1/voice/webhook".to_string(),
            format!("/api/v1/rooms/{r}/voice"),
            format!("/api/v1/rooms/{r}/voice/move-all"),
            format!("/api/v1/rooms/{r}/channels/{r}/voice/join"),
            format!("/api/v1/rooms/{r}/channels/{r}/voice/members/a@b.test/mute"),
            format!("/api/v1/rooms/{r}/channels/{r}/soundboard/play"),
            format!("/api/v1/conversations/{r}/call"),
            format!("/api/v1/conversations/{r}/call/start"),
            format!("/api/v1/conversations/{r}/ephemeral"),
            format!("/api/v1/conversations/{r}/whiteboard"),
        ] {
            assert!(leader_path(&p), "{p}");
        }
        for p in [
            "/api/v1/voice/test".to_string(),
            "/rtc".into(),
            "/api/v1/ws".into(),
            format!("/api/v1/rooms/{r}/soundboard"),
            format!("/api/v1/rooms/{r}/channels/{r}/messages"),
            format!("/api/v1/conversations/{r}/messages"),
            "/voice/webhook".into(),
            "/api/v1/users/me/whiteboards".into(),
        ] {
            assert!(!leader_path(&p), "{p}");
        }
    }

    #[test]
    fn interaction_paths() {
        let r = "01J9AAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(interaction_path(&format!("/api/v1/interactions/{r}/callback")), Some(r));
        assert_eq!(interaction_path(&format!("/api/v1/interactions/{r}/messages")), Some(r));
        for p in [
            format!("/api/v1/interactions/{r}"),
            format!("/api/v1/interactions/{r}/other"),
            "/api/v1/interactions//callback".to_string(),
            format!("/api/v1/conversations/{r}/interactions"),
            format!("/api/v1/interactions/{}/callback", "x".repeat(65)),
        ] {
            assert_eq!(interaction_path(&p), None, "{p}");
        }
    }
}
