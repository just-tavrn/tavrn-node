// SPDX-License-Identifier: AGPL-3.0-only
//! Signing in with an account of this node on the web client of another node (FEDERATION.md §8).
//!
//! **Connect flow** (passkeys, login captcha and later SSO cannot run cross-origin): the visiting web
//! client redirects to this node's web client (`/connect?origin=…&state=…&code_challenge=…`), the user
//! signs in there and confirms; this node's client asks for a one-time code bound to the visiting
//! origin, the PKCE challenge (S256) and the confirming device (`POST /auth/connect/code`), then
//! redirects back with the code. The visiting client exchanges code and verifier for a session of a
//! new device (`POST /auth/connect/token`). Codes are single use, live 2 minutes and are kept in
//! memory only (a restart simply invalidates them); only their SHA-256 is stored.
//!
//! Also here: `GET /federation/peer/{domain}`, the discovery document of another node through this
//! node's federation client, for browsers that cannot fetch it directly.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::{AuthUser, ClientIp},
    error::{ApiError, ApiJson, ProblemDetails},
    federation::{self, guard::local_only},
    routes::auth::{AuthResponse, client_header, device_name},
    second_factor, store, util,
};

/// Lifetime of a connect code (§8).
pub const CODE_TTL_SECS: u64 = 120;
/// Upper bound of pending codes in memory (protects against floods; expired ones are pruned first).
pub const MAX_PENDING: usize = 10_000;

/// A pending code, keyed by the SHA-256 of the code.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    user_id: String,
    /// The device whose session confirmed the sign-in; it must still be signed in at the exchange.
    device_id: String,
    origin: String,
    challenge: String,
    device_name: String,
    /// In memory only; in the shared cache the entry's TTL expires it.
    #[serde(skip, default = "Instant::now")]
    expires: Instant,
}

/// Pending connect codes: in memory, or sealed in the shared cache when several instances serve the node (the
/// exchange may reach another instance than the one that issued the code).
#[derive(Default)]
pub struct ConnectCodes {
    pending: Mutex<HashMap<String, Pending>>,
    cluster: Option<std::sync::Arc<crate::cache::Cluster>>,
}

impl ConnectCodes {
    pub fn new(cluster: &std::sync::Arc<crate::cache::Cluster>) -> Self {
        Self { cluster: cluster.is_shared().then(|| cluster.clone()), ..Self::default() }
    }

    async fn insert(&self, code_hash: String, pending: Pending) -> Result<(), ApiError> {
        if let Some(cluster) = &self.cluster {
            let ttl = Duration::from_secs(CODE_TTL_SECS);
            return cluster
                .put_sealed(&format!("connect:{code_hash}"), &pending, ttl)
                .await
                .map_err(crate::cache::unavailable);
        }
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        map.retain(|_, p| p.expires > now);
        if map.len() >= MAX_PENDING {
            return Err(ApiError::Unavailable {
                code: "connect.busy",
                detail: "Too many pending sign-ins, please try again shortly".into(),
            });
        }
        map.insert(code_hash, pending);
        Ok(())
    }

    /// Removes and returns the code (single use, also when the exchange fails afterwards).
    async fn take(&self, code_hash: &str) -> Result<Option<Pending>, ApiError> {
        if let Some(cluster) = &self.cluster {
            return cluster.take_sealed(&format!("connect:{code_hash}")).await.map_err(crate::cache::unavailable);
        }
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map.remove(code_hash).filter(|p| p.expires > Instant::now()))
    }
}

fn origin_invalid() -> ApiError {
    ApiError::BadRequest {
        code: "connect.origin_invalid",
        detail: "Invalid origin: expected https://<domain> (http:// only in development mode)".into(),
    }
}

fn code_invalid() -> ApiError {
    ApiError::BadRequest { code: "connect.code_invalid", detail: "Code invalid, expired or already used".into() }
}

/// A web origin the code may be bound to: `https://<valid node domain>` without port, path, query or
/// user info. With `--dev` also `http://<host>[:port]` (local development and tests).
pub fn valid_origin(origin: &str, dev: bool) -> bool {
    if origin.len() > 300 || origin.ends_with('/') {
        return false;
    }
    if let Some(host) = origin.strip_prefix("https://") {
        return federation::valid_node_domain(host)
            || (dev && host.split_once(':').is_some_and(|(h, p)| util::valid_domain(h) && valid_port(p)));
    }
    if !dev {
        return false;
    }
    let Some(rest) = origin.strip_prefix("http://") else { return false };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    (util::valid_domain(host) || host == "127.0.0.1") && port.is_none_or(valid_port)
}

fn valid_port(p: &str) -> bool {
    !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|n| n > 0)
}

/// RFC 7636: 43–128 characters of `[A-Za-z0-9-._~]`.
pub fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len()) && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

/// An S256 challenge: base64url (no padding) of 32 bytes.
pub fn valid_challenge(c: &str) -> bool {
    c.len() == 43 && URL_SAFE_NO_PAD.decode(c).is_ok_and(|b| b.len() == 32)
}

/// `BASE64URL(SHA-256(verifier))`.
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[derive(Deserialize, ToSchema)]
pub struct ConnectCodeRequest {
    /// Origin of the visiting web client, e.g. `https://visited.example`.
    pub origin: String,
    /// `BASE64URL(SHA-256(code_verifier))` (PKCE, S256).
    pub code_challenge: String,
    /// Name of the new device the exchange creates (default: "Browser on <origin host>").
    pub device_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ConnectCodeResponse {
    /// One-time code for `POST /auth/connect/token` (single use).
    pub code: String,
    pub expires_in: u64,
}

/// One-time code for the web client of another node (connect flow, FEDERATION.md §8). Needs a full
/// session of a local user; remote users get `federation.local_only`.
#[utoipa::path(post, path = "/api/v1/auth/connect/code", security(("bearer" = [])), request_body = ConnectCodeRequest,
    responses((status = 200, body = ConnectCodeResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn connect_code(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<ConnectCodeRequest>,
) -> Result<Json<ConnectCodeResponse>, ApiError> {
    if auth.is_remote() {
        return Err(local_only());
    }
    let origin = req.origin.trim();
    if !valid_origin(origin, state.config.dev) {
        return Err(origin_invalid());
    }
    if !valid_challenge(req.code_challenge.trim()) {
        return Err(ApiError::BadRequest {
            code: "connect.challenge_invalid",
            detail: "code_challenge: expected BASE64URL(SHA-256(code_verifier))".into(),
        });
    }
    state.federation_token_limiter.check_all(&[format!("connect:{}", auth.device_id)]).await?;
    let host = origin.split_once("://").map(|(_, h)| h).unwrap_or(origin);
    let code = util::random_token(32);
    state
        .connect_codes
        .insert(
            util::sha256_b64(&code),
            Pending {
                user_id: auth.user.id.clone(),
                device_id: auth.device_id.clone(),
                origin: origin.to_string(),
                challenge: req.code_challenge.trim().to_string(),
                device_name: device_name(req.device_name.as_deref(), &format!("Browser ({host})")),
                expires: Instant::now() + Duration::from_secs(CODE_TTL_SECS),
            },
        )
        .await?;
    tracing::info!(origin, device = auth.device_id, "connect code issued");
    Ok(Json(ConnectCodeResponse { code, expires_in: CODE_TTL_SECS }))
}

#[derive(Deserialize, ToSchema)]
pub struct ConnectTokenRequest {
    pub code: String,
    /// The PKCE verifier whose S256 hash was sent as `code_challenge`.
    pub code_verifier: String,
    /// Proof that the visiting browser holds a device of this account (`POST /auth/device-nonce`, ENCRYPTION.md
    /// §3.4): the session continues that device instead of creating a new one, like a normal login.
    #[serde(default)]
    pub device: Option<crate::device_proof::DeviceProof>,
}

/// Exchanges a connect code for a session (FEDERATION.md §8): of a new device, or of the device the request
/// proves to hold (`device`, ENCRYPTION.md §3.4). No authentication: the code, the PKCE verifier and the request's
/// `Origin` (must equal the bound origin) prove it. Every failure is `connect.code_invalid`, and the code is spent by
/// the first attempt; a refused device proof only means a new device.
#[utoipa::path(post, path = "/api/v1/auth/connect/token", request_body = ConnectTokenRequest,
    responses((status = 200, body = AuthResponse), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn connect_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<ConnectTokenRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    state.login_limiter.check_all(&[format!("connect-ip:{ip}")]).await?;
    let code = req.code.trim();
    if code.is_empty() || code.len() > 128 {
        return Err(code_invalid());
    }
    let pending = state.connect_codes.take(&util::sha256_b64(code)).await?.ok_or_else(code_invalid)?;
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("");
    let verifier_ok = valid_verifier(&req.code_verifier)
        && bool::from(s256(&req.code_verifier).as_bytes().ct_eq(pending.challenge.as_bytes()));
    if origin != pending.origin || !verifier_ok {
        tracing::warn!(origin, bound = pending.origin, verifier_ok, "connect code refused");
        return Err(code_invalid());
    }
    let user = store::users::by_id(&state.db, &pending.user_id)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .ok_or_else(code_invalid)?;
    if !store::home::device_has_live_session(&state.db, &pending.device_id).await? {
        return Err(code_invalid());
    }
    let reuse = crate::device_proof::verify_opt(&state, &user, req.device.as_ref()).await?;
    let session =
        second_factor::start_session(&state, &user, &pending.device_name, &client_header(&headers), reuse.as_deref())
            .await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&user.id),
        "user.connect",
        &user.address(),
        &pending.origin,
        serde_json::json!({ "ip": ip, "device": session.tokens.device_id }),
    )
    .await?;
    tracing::info!(origin = pending.origin, device = session.tokens.device_id, "connect code exchanged");
    Ok(Json(session))
}

/// Checks of the public peer lookups (`/federation/peer/{domain}`, `/federation/resolve/{domain}`): federation
/// on, a node domain other than this node's, and the per-IP rate limit (shared by both routes). Returns the
/// normalized domain.
pub async fn peer_lookup(state: &AppState, ip: &str, domain: &str) -> Result<String, ApiError> {
    if !state.config.federation_enabled {
        return Err(federation::disabled());
    }
    let domain = domain.trim().to_lowercase();
    if !federation::valid_node_domain(&domain) {
        return Err(ApiError::BadRequest {
            code: "federation.domain_invalid",
            detail: "Not a valid node domain (e.g. community.example)".into(),
        });
    }
    if domain == state.config.domain {
        return Err(ApiError::BadRequest {
            code: "federation.target_self",
            detail: "This node's own document is at /.well-known/tavrn".into(),
        });
    }
    state.login_limiter.check_all(&[format!("peer-ip:{ip}")]).await?;
    Ok(domain)
}

/// The discovery document of another node as this node fetched and validated it (FEDERATION.md §1.4),
/// for web clients that cannot load `https://<domain>/.well-known/tavrn` themselves. Public; the node's
/// federation client applies its SSRF rules, the domain policy and the document cache.
#[utoipa::path(get, path = "/api/v1/federation/peer/{domain}", params(("domain" = String, Path)),
    responses((status = 200, body = crate::routes::wellknown::WellKnown), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn peer_document(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(domain): Path<String>,
) -> Result<Response, ApiError> {
    let domain = peer_lookup(&state, &ip, &domain).await?;
    federation::discovery::document(&state, &domain).await?;
    let raw = store::federation::peer(&state.db, &domain)
        .await?
        .map(|row| row.document)
        .ok_or_else(|| federation::discovery::peer_invalid(&domain, "not in the cache"))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|_| federation::discovery::peer_invalid(&domain, "not JSON"))?;
    let mut resp = Json(doc).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn origins() {
        for ok in ["https://visited.example", "https://a-b.c.example"] {
            assert!(valid_origin(ok, false), "{ok}");
            assert!(valid_origin(ok, true), "{ok}");
        }
        for bad in [
            "",
            "visited.example",
            "http://visited.example",
            "https://visited.example/",
            "https://visited.example/path",
            "https://visited.example:8443",
            "https://user@visited.example",
            "https://localhost",
            "https://127.0.0.1",
            "https://visited.example?x=1",
            "javascript:alert(1)",
            "https://VISITED.example",
        ] {
            assert!(!valid_origin(bad, false), "{bad}");
        }
        for dev_ok in [
            "http://localhost:5173",
            "http://b.test:5274",
            "http://127.0.0.1:5173",
            "http://localhost",
            "https://b.test:8443",
        ] {
            assert!(valid_origin(dev_ok, true), "{dev_ok}");
            assert!(!valid_origin(dev_ok, false), "{dev_ok}");
        }
        for dev_bad in
            ["http://localhost:0", "http://localhost:99999", "http://localhost:", "http://a.test:80/x", "ftp://a.test"]
        {
            assert!(!valid_origin(dev_bad, true), "{dev_bad}");
        }
    }

    #[test]
    fn pkce_s256() {
        // RFC 7636, appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(s256(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(valid_verifier(verifier));
        assert!(valid_challenge(&s256(verifier)));
        assert!(!valid_verifier("short"));
        assert!(!valid_verifier(&"a".repeat(129)));
        assert!(!valid_verifier(&format!("{}+", "a".repeat(43))));
        assert!(!valid_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"));
        assert!(!valid_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="));
    }

    #[tokio::test]
    async fn codes_are_single_use_and_expire() {
        let codes = ConnectCodes::default();
        let pending = |secs: u64| Pending {
            user_id: "u".into(),
            device_id: "d".into(),
            origin: "https://v.example".into(),
            challenge: "c".into(),
            device_name: "n".into(),
            expires: Instant::now() + Duration::from_secs(secs),
        };
        codes.insert("h1".into(), pending(60)).await.unwrap();
        assert!(codes.take("h1").await.unwrap().is_some());
        assert!(codes.take("h1").await.unwrap().is_none(), "single use");
        codes.insert("h2".into(), pending(0)).await.unwrap();
        assert!(codes.take("h2").await.unwrap().is_none(), "expired");
    }

    #[tokio::test]
    async fn codes_issued_on_one_instance_are_taken_on_another() {
        let cache: std::sync::Arc<dyn crate::cache::Cache> =
            std::sync::Arc::new(crate::cache::memory::InProcess::default());
        let cluster = |id: &str| {
            std::sync::Arc::new(crate::cache::Cluster::shared_with("n.test", id, cache.clone(), &[3; 32], ""))
        };
        let (a, b) = (ConnectCodes::new(&cluster("a")), ConnectCodes::new(&cluster("b")));
        let pending = Pending {
            user_id: "u".into(),
            device_id: "d".into(),
            origin: "https://v.example".into(),
            challenge: "c".into(),
            device_name: "n".into(),
            expires: Instant::now(),
        };
        a.insert("h".into(), pending).await.unwrap();
        let taken = b.take("h").await.unwrap().unwrap();
        assert_eq!((taken.user_id.as_str(), taken.origin.as_str()), ("u", "https://v.example"));
        assert!(a.take("h").await.unwrap().is_none(), "single use across instances");
    }
}
