// SPDX-License-Identifier: AGPL-3.0-only
//! Single sign-on via OpenID Connect (APPLICATIONS.md §8).
//!
//! A small authorization code flow with PKCE implemented on reqwest instead of the `openidconnect` crate:
//! the node needs one provider, one flow and exact control over the outbound requests (no redirects, size
//! and time caps, issuer pinning), which is a few hundred lines; the ID token signature is verified with
//! jsonwebtoken's RustCrypto verifiers (`idtoken.rs`).
//!
//! - **Discovery and JWKS** are fetched lazily and cached for an hour; an unknown `kid` triggers one JWKS
//!   refetch (at most every [`JWKS_REFETCH_MIN`]). An unreachable provider never stops the node: SSO answers
//!   `502 sso.idp_unreachable`, everything else works.
//! - **Provider requests** need `https://` (`http://` only with `--dev`) and verified TLS, follow no
//!   redirects, are capped at [`MAX_RESPONSE_BYTES`] and [`HTTP_TIMEOUT`]. Private addresses are allowed: the
//!   operator configured the provider.
//! - **Flow state** lives in memory like the connect codes (FEDERATION.md §8): the provider `state` (10
//!   minutes, single use) with nonce, the node's PKCE verifier and the client's challenge; after the callback
//!   a one-time code (60 s, single use, bound to the client's challenge) carries the verified identity to
//!   `POST /auth/oidc/token`. Linking, provisioning, the group sync and the session happen only at that
//!   exchange, in the browser that started the flow, so a callback URL replayed in another browser does
//!   nothing (login and linking CSRF).
//! - With several instances (`TAVRN_CACHE_URL`) the callback and the exchange may reach other instances than
//!   the start: the provider `state` and the one-time code are then kept in the shared cache instead, sealed
//!   with a key derived from `secrets.key` (`cache::Cluster::put_sealed`) and taken atomically (single use).
//! - Nothing secret is logged or kept: the client secret, codes, ID and access tokens stay in memory for
//!   the duration of one request.

pub mod account;
pub mod groups;
pub mod idtoken;

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, jwk::Jwk};
use reqwest::{Url, header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::{
    app::SOFTWARE_VERSION,
    auth::RateLimiter,
    config::{Config, OidcGroupSync},
    error::ApiError,
    util,
};

/// Capability announced while an issuer is configured (APPLICATIONS.md §10.1).
pub const CAPABILITY: &str = "sso.oidc";
pub const STATE_TTL: Duration = Duration::from_secs(600);
pub const CODE_TTL: Duration = Duration::from_secs(60);
pub const REAUTH_TTL: Duration = Duration::from_secs(300);
pub const CACHE_TTL: Duration = Duration::from_secs(3600);
/// Minimum distance between two JWKS fetches after unknown `kid`s (0 in development mode).
pub const JWKS_REFETCH_MIN: Duration = Duration::from_secs(10);
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Pending logins, codes and reauth tokens in memory at most (each).
pub const MAX_PENDING: usize = 10_000;
/// Default button text; the client shows its own translation when the operator set none.
pub const DEFAULT_LABEL: &str = "Sign in with SSO";

/// What a flow is for (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    /// Sign in (or create the account on the first login).
    Login,
    /// Link the provider identity to the signed-in account.
    Link,
    /// Confirm an identity reset of an SSO account by a fresh provider login.
    Reauth,
}

/// SSO settings derived from the configuration (validated at start).
#[derive(Debug)]
pub struct Settings {
    pub issuer: String,
    pub client_id: String,
    client_secret: Option<Zeroizing<String>>,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub display_name_claim: String,
    pub groups_claim: String,
    /// Operator's button text; `None` = the client's default.
    pub label: Option<String>,
    pub only: bool,
    pub auto_provision: bool,
    /// The fixed map of `TAVRN_OIDC_GROUP_MAP` (the admin API cannot change it then).
    pub group_map: Option<groups::GroupMap>,
    pub group_sync: OidcGroupSync,
    pub session_days: u32,
    /// `<public url>/api/v1/auth/oidc/callback`, registered at the provider; never taken from a request.
    pub redirect_uri: String,
    /// The node's web origin (`PROTOCOL.md` §2); the callback always redirects to `<web>/sso/callback`.
    pub web_origin: String,
    allow_http: bool,
}

impl Settings {
    pub fn session_secs(&self) -> i64 {
        i64::from(self.session_days) * 24 * 3600
    }
}

/// Why an SSO step failed; becomes an `error=<code>` on the callback redirect or a Problem Details answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoError {
    StateInvalid,
    /// The provider could not be reached or answered something unusable.
    Unreachable,
    /// The provider answered with an OAuth error (`error`, sanitized).
    IdpError(String),
    /// The ID token (or UserInfo) failed a check; the reason is logged, never sent.
    TokenInvalid(&'static str),
}

impl SsoError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::StateInvalid => "sso.state_invalid",
            Self::Unreachable => "sso.idp_unreachable",
            Self::IdpError(_) => "sso.idp_error",
            Self::TokenInvalid(_) => "sso.token_invalid",
        }
    }

    pub fn to_api(&self) -> ApiError {
        match self {
            Self::StateInvalid => ApiError::BadRequest {
                code: "sso.state_invalid",
                detail: "Login state invalid, expired or already used".into(),
            },
            Self::Unreachable => ApiError::BadGateway {
                code: "sso.idp_unreachable",
                detail: "The identity provider is not reachable".into(),
            },
            Self::IdpError(e) => {
                ApiError::BadGateway { code: "sso.idp_error", detail: format!("The identity provider answered: {e}") }
            }
            Self::TokenInvalid(_) => ApiError::BadGateway {
                code: "sso.token_invalid",
                detail: "The identity provider's token failed a check".into(),
            },
        }
    }
}

pub fn disabled() -> ApiError {
    ApiError::NotFound { code: "sso.disabled", what: "Single sign-on".into() }
}

/// The provider's discovery document (the fields the node uses).
#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// Discovery and JWKS of the provider, cached.
#[derive(Debug, Clone)]
pub struct Provider {
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Option<Url>,
    jwks_uri: Url,
    end_session_endpoint: Option<Url>,
    algorithms: Vec<Algorithm>,
    /// `client_secret_basic` (the default of RFC 8414) or `client_secret_post`.
    auth_basic: bool,
    keys: Vec<Jwk>,
    fetched: Instant,
    jwks_fetched: Instant,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingLogin {
    purpose: Purpose,
    user_id: Option<String>,
    nonce: String,
    verifier: Zeroizing<String>,
    client_challenge: String,
    client_state: String,
    device_name: String,
    started_unix: i64,
    /// In memory only; in the shared cache the entry's TTL expires it.
    #[serde(skip, default = "far_future")]
    expires: Instant,
}

/// The expiry of an entry taken from the shared cache (its TTL already applied there).
fn far_future() -> Instant {
    Instant::now() + STATE_TTL
}

/// The identity a callback verified, waiting for the client's exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub subject: String,
    /// ID token claims, completed by UserInfo where the ID token lacks a claim.
    pub claims: Map<String, Value>,
    pub groups: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCode {
    pub purpose: Purpose,
    pub user_id: Option<String>,
    client_challenge: String,
    pub device_name: String,
    pub identity: VerifiedIdentity,
    #[serde(skip, default = "far_future")]
    expires: Instant,
}

/// The SSO service of a node with a configured issuer.
pub struct Oidc {
    pub settings: Settings,
    http: reqwest::Client,
    provider: tokio::sync::Mutex<Option<Arc<Provider>>>,
    pending: Mutex<HashMap<String, PendingLogin>>,
    codes: Mutex<HashMap<String, PendingCode>>,
    reauth: Mutex<HashMap<String, (String, Instant)>>,
    /// `POST /auth/oidc/start` per client IP (20 per minute in production).
    pub start_limiter: RateLimiter,
    /// `POST /auth/oidc/token` per client IP (10 per minute in production).
    pub token_limiter: RateLimiter,
    /// Set when several instances serve the node: flow state and codes live in the shared cache.
    cluster: Option<Arc<crate::cache::Cluster>>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc").field("issuer", &self.settings.issuer).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Oidc {
    /// `None` without `TAVRN_OIDC_ISSUER`. Reads the client secret (file) once.
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let Some(issuer) = config.oidc_issuer() else { return Ok(None) };
        let client_secret = match config.oidc_client_secret_file.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            Some(path) => {
                let s = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("TAVRN_OIDC_CLIENT_SECRET_FILE '{path}' cannot be read: {e}"))?;
                Some(Zeroizing::new(s.trim().to_string()))
            }
            None => config.oidc_client_secret.as_deref().map(|s| Zeroizing::new(s.trim().to_string())),
        }
        .filter(|s| !s.is_empty());
        let group_map = match config.oidc_group_map.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
            Some(json) => Some(groups::parse(json).map_err(|e| anyhow::anyhow!("TAVRN_OIDC_GROUP_MAP: {e}"))?),
            None => None,
        };
        let allow_http = config.dev;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .https_only(!allow_http)
            .no_proxy()
            .user_agent(format!("tavrn-node/{SOFTWARE_VERSION} (+{})", config.public_url()))
            .build()?;
        let limit = |prod: u32| RateLimiter::new(if config.dev { 1000 } else { prod }, Duration::from_secs(60));
        if config.oidc_only && config.admin_users().is_empty() {
            tracing::warn!(
                "TAVRN_OIDC_ONLY=true without TAVRN_ADMIN_USERS: nobody can sign in with a password while the identity provider is down"
            );
        }
        let label = config.oidc_button_label.as_deref().map(str::trim).filter(|l| !l.is_empty()).map(String::from);
        Ok(Some(Self {
            settings: Settings {
                issuer: issuer.to_string(),
                client_id: config.oidc_client_id.as_deref().unwrap_or("").trim().to_string(),
                client_secret,
                scopes: config.oidc_scopes(),
                username_claim: config.oidc_username_claim.trim().to_string(),
                display_name_claim: config.oidc_display_name_claim.trim().to_string(),
                groups_claim: config.oidc_groups_claim.trim().to_string(),
                label,
                only: config.oidc_only,
                auto_provision: config.oidc_auto_provision,
                group_map,
                group_sync: config.oidc_group_sync,
                session_days: config.oidc_session_days,
                redirect_uri: format!("{}/api/v1/auth/oidc/callback", config.public_url()),
                web_origin: config.webauthn_origin(),
                allow_http,
            },
            http,
            provider: tokio::sync::Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            reauth: Mutex::new(HashMap::new()),
            start_limiter: limit(20),
            token_limiter: limit(10),
            cluster: None,
        }))
    }

    /// Keeps flow state and codes in the shared cache when the instance shares state with others.
    pub fn with_cluster(mut self, cluster: &Arc<crate::cache::Cluster>) -> Self {
        self.cluster = cluster.is_shared().then(|| cluster.clone());
        self
    }

    // ------------------------------------------------------------ provider requests

    /// A provider URL from discovery: `https://` (`http://` with `--dev`), a host, no user info.
    fn check_url(&self, raw: &str) -> Result<Url, SsoError> {
        let url = Url::parse(raw).map_err(|_| SsoError::Unreachable)?;
        let scheme_ok = url.scheme() == "https" || (self.settings.allow_http && url.scheme() == "http");
        if !scheme_ok || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
            tracing::warn!(url = raw, "SSO: provider URL refused (https only, no user info)");
            return Err(SsoError::Unreachable);
        }
        Ok(url)
    }

    /// Reads a JSON body of at most [`MAX_RESPONSE_BYTES`].
    async fn read_json(mut response: reqwest::Response) -> Result<Value, SsoError> {
        if response.content_length().is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
            return Err(SsoError::Unreachable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| SsoError::Unreachable)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(SsoError::Unreachable);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| SsoError::Unreachable)
    }

    async fn get_json(&self, url: Url) -> Result<Value, SsoError> {
        let response =
            self.http.get(url.clone()).header(header::ACCEPT, "application/json").send().await.map_err(|e| {
                tracing::warn!(url = %url, error = %e, "SSO: provider request failed");
                SsoError::Unreachable
            })?;
        if !response.status().is_success() {
            tracing::warn!(url = %url, status = %response.status(), "SSO: provider answered with an error status");
            return Err(SsoError::Unreachable);
        }
        Self::read_json(response).await
    }

    async fn fetch_jwks(&self, uri: &Url) -> Result<Vec<Jwk>, SsoError> {
        let keys = idtoken::parse_jwks(&self.get_json(uri.clone()).await?);
        if keys.is_empty() {
            tracing::warn!("SSO: the provider's JWKS has no usable key");
            return Err(SsoError::Unreachable);
        }
        Ok(keys)
    }

    async fn discover(&self) -> Result<Provider, SsoError> {
        let url = self
            .check_url(&format!("{}/.well-known/openid-configuration", self.settings.issuer.trim_end_matches('/')))?;
        let doc: Discovery = serde_json::from_value(self.get_json(url).await?).map_err(|_| SsoError::Unreachable)?;
        // Issuer pinning: the document must belong to exactly the configured issuer.
        if doc.issuer != self.settings.issuer {
            tracing::warn!(announced = doc.issuer, "SSO: discovery issuer differs from TAVRN_OIDC_ISSUER");
            return Err(SsoError::Unreachable);
        }
        if doc.code_challenge_methods_supported.as_ref().is_some_and(|m| !m.iter().any(|m| m == "S256")) {
            tracing::warn!("SSO: the provider does not announce PKCE S256");
            return Err(SsoError::Unreachable);
        }
        let announced: Vec<Algorithm> = if doc.id_token_signing_alg_values_supported.is_empty() {
            vec![Algorithm::RS256]
        } else {
            doc.id_token_signing_alg_values_supported.iter().filter_map(|a| idtoken::allowed_alg(a)).collect()
        };
        if announced.is_empty() {
            tracing::warn!("SSO: the provider announces no allowed ID token algorithm (RS256, PS256, ES256, EdDSA)");
            return Err(SsoError::Unreachable);
        }
        let methods = &doc.token_endpoint_auth_methods_supported;
        let auth_basic = methods.is_empty() || methods.iter().any(|m| m == "client_secret_basic");
        let jwks_uri = self.check_url(&doc.jwks_uri)?;
        let keys = self.fetch_jwks(&jwks_uri).await?;
        let optional = |u: Option<String>| -> Result<Option<Url>, SsoError> {
            u.filter(|s| !s.is_empty()).map(|s| self.check_url(&s)).transpose()
        };
        let now = Instant::now();
        Ok(Provider {
            authorization_endpoint: self.check_url(&doc.authorization_endpoint)?,
            token_endpoint: self.check_url(&doc.token_endpoint)?,
            userinfo_endpoint: optional(doc.userinfo_endpoint)?,
            end_session_endpoint: optional(doc.end_session_endpoint)?,
            jwks_uri,
            algorithms: announced,
            auth_basic,
            keys,
            fetched: now,
            jwks_fetched: now,
        })
    }

    /// The cached provider document, fetched when missing or older than [`CACHE_TTL`].
    pub async fn provider(&self) -> Result<Arc<Provider>, SsoError> {
        let mut cached = self.provider.lock().await;
        if let Some(p) = cached.as_ref().filter(|p| p.fetched.elapsed() < CACHE_TTL) {
            return Ok(p.clone());
        }
        let fresh = Arc::new(self.discover().await?);
        *cached = Some(fresh.clone());
        Ok(fresh)
    }

    /// One JWKS refetch after an unknown `kid` (not more often than [`JWKS_REFETCH_MIN`]).
    async fn refresh_keys(&self, seen: &Provider) -> Result<Option<Arc<Provider>>, SsoError> {
        let mut cached = self.provider.lock().await;
        let current = cached.clone().unwrap_or_else(|| Arc::new(seen.clone()));
        if current.jwks_fetched > seen.jwks_fetched {
            // Another login refreshed the keys meanwhile.
            return Ok(Some(current));
        }
        let min = if self.settings.allow_http { Duration::ZERO } else { JWKS_REFETCH_MIN };
        if current.jwks_fetched.elapsed() < min {
            return Ok(None);
        }
        let keys = self.fetch_jwks(&current.jwks_uri).await?;
        let updated = Arc::new(Provider { keys, jwks_fetched: Instant::now(), ..(*current).clone() });
        *cached = Some(updated.clone());
        Ok(Some(updated))
    }

    // ------------------------------------------------------------ flow

    /// Starts a flow: stores state, nonce, the provider PKCE verifier and the client's challenge and returns
    /// the provider's authorization URL.
    pub async fn start(
        &self,
        purpose: Purpose,
        user_id: Option<String>,
        client_challenge: &str,
        client_state: &str,
        device_name: String,
    ) -> Result<String, ApiError> {
        let provider = self.provider().await.map_err(|e| e.to_api())?;
        let state = util::random_token(32);
        let nonce = util::random_token(32);
        let verifier = Zeroizing::new(util::random_token(48));
        let mut url = provider.authorization_endpoint.clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.settings.client_id)
                .append_pair("redirect_uri", &self.settings.redirect_uri)
                .append_pair("scope", &self.settings.scopes.join(" "))
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge", &crate::routes::connect::s256(&verifier))
                .append_pair("code_challenge_method", "S256");
            if purpose == Purpose::Reauth {
                // A fresh authentication at the provider, not a silent session reuse (§8.4).
                q.append_pair("prompt", "login").append_pair("max_age", "0");
            }
        }
        let pending = PendingLogin {
            purpose,
            user_id,
            nonce,
            verifier,
            client_challenge: client_challenge.to_string(),
            client_state: client_state.to_string(),
            device_name,
            started_unix: crate::jwt::now_unix(),
            expires: Instant::now() + STATE_TTL,
        };
        if let Some(cluster) = &self.cluster {
            let name = format!("oidc-state:{}", util::sha256_b64(&state));
            cluster.put_sealed(&name, &pending, STATE_TTL).await.map_err(crate::cache::unavailable)?;
            return Ok(url.to_string());
        }
        let mut map = lock(&self.pending);
        let now = Instant::now();
        map.retain(|_, p| p.expires > now);
        if map.len() >= MAX_PENDING {
            return Err(busy());
        }
        map.insert(state, pending);
        Ok(url.to_string())
    }

    /// Handles the provider's redirect. `Ok((client_state, one-time code))`, or the error with the client
    /// state when the provider `state` was known.
    pub async fn callback(
        &self,
        state: &str,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<(String, String), (Option<String>, SsoError)> {
        let pending = match &self.cluster {
            Some(cluster) if state.len() <= 128 => {
                let name = format!("oidc-state:{}", util::sha256_b64(state));
                cluster.take_sealed::<PendingLogin>(&name).await.map_err(|_| (None, SsoError::Unreachable))?
            }
            Some(_) => None,
            None => {
                let mut map = lock(&self.pending);
                map.remove(state).filter(|p| p.expires > Instant::now())
            }
        };
        let Some(pending) = pending else { return Err((None, SsoError::StateInvalid)) };
        let fail = |e: SsoError| (Some(pending.client_state.clone()), e);
        if let Some(error) = error {
            return Err(fail(SsoError::IdpError(sanitize_error(error))));
        }
        let Some(code) = code.filter(|c| !c.is_empty() && c.len() <= 4096) else {
            return Err(fail(SsoError::IdpError("missing_code".into())));
        };
        let identity = self.redeem(&pending, code).await.map_err(fail)?;
        let one_time = util::random_token(32);
        let entry = PendingCode {
            purpose: pending.purpose,
            user_id: pending.user_id.clone(),
            client_challenge: pending.client_challenge.clone(),
            device_name: pending.device_name.clone(),
            identity,
            expires: Instant::now() + CODE_TTL,
        };
        if let Some(cluster) = &self.cluster {
            let name = format!("oidc-code:{}", util::sha256_b64(&one_time));
            cluster.put_sealed(&name, &entry, CODE_TTL).await.map_err(|_| fail(SsoError::Unreachable))?;
            return Ok((pending.client_state.clone(), one_time));
        }
        let mut codes = lock(&self.codes);
        let now = Instant::now();
        codes.retain(|_, c| c.expires > now);
        if codes.len() >= MAX_PENDING {
            return Err(fail(SsoError::Unreachable));
        }
        codes.insert(util::sha256_b64(&one_time), entry);
        Ok((pending.client_state.clone(), one_time))
    }

    /// Token request, ID token checks and (if needed) UserInfo.
    async fn redeem(&self, pending: &PendingLogin, code: &str) -> Result<VerifiedIdentity, SsoError> {
        let provider = self.provider().await?;
        let tokens = self.token_request(&provider, code, &pending.verifier).await?;
        let id_token = tokens.get("id_token").and_then(Value::as_str).ok_or(SsoError::TokenInvalid("no id_token"))?;
        let mut claims = self.verify_id_token(&provider, id_token, &pending.nonce).await?;
        if pending.purpose == Purpose::Reauth {
            // max_age=0 makes `auth_time` mandatory; it must lie after the start of this flow.
            let fresh = claims.get("auth_time").and_then(Value::as_i64).is_some_and(|t| t >= pending.started_unix - 60);
            if !fresh {
                return Err(SsoError::TokenInvalid("auth_time"));
            }
        }
        let subject = claims.get("sub").and_then(Value::as_str).unwrap_or_default().to_string();
        let s = &self.settings;
        let missing = |c: &Map<String, Value>| !c.contains_key(&s.username_claim) || !c.contains_key(&s.groups_claim);
        if missing(&claims)
            && let (Some(endpoint), Some(access)) =
                (provider.userinfo_endpoint.as_ref(), tokens.get("access_token").and_then(Value::as_str))
        {
            let info = self.userinfo(endpoint, access).await?;
            if info.get("sub").and_then(Value::as_str) != Some(subject.as_str()) {
                return Err(SsoError::TokenInvalid("userinfo sub"));
            }
            for (k, v) in info {
                claims.entry(k).or_insert(v);
            }
        }
        let groups = groups::groups_from_claim(claims.get(&s.groups_claim));
        Ok(VerifiedIdentity { subject, claims, groups })
    }

    async fn token_request(
        &self,
        provider: &Provider,
        code: &str,
        verifier: &str,
    ) -> Result<Map<String, Value>, SsoError> {
        let s = &self.settings;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &s.redirect_uri),
            ("code_verifier", verifier),
        ];
        let mut request = self.http.post(provider.token_endpoint.clone()).header(header::ACCEPT, "application/json");
        match s.client_secret.as_ref() {
            Some(secret) if provider.auth_basic => {
                // RFC 6749 §2.3.1: both parts form-encoded before the Basic encoding.
                request = request.basic_auth(form_encode(&s.client_id), Some(form_encode(secret)));
            }
            Some(secret) => {
                form.push(("client_id", &s.client_id));
                form.push(("client_secret", secret.as_str()));
            }
            None => form.push(("client_id", &s.client_id)),
        }
        let response = request.form(&form).send().await.map_err(|e| {
            tracing::warn!(error = %e, "SSO: token request failed");
            SsoError::Unreachable
        })?;
        let status = response.status();
        let body = Self::read_json(response).await;
        if !status.is_success() {
            return Err(match body.ok().as_ref().and_then(|b| b.get("error")).and_then(Value::as_str) {
                Some(error) => SsoError::IdpError(sanitize_error(error)),
                None => SsoError::Unreachable,
            });
        }
        match body? {
            Value::Object(map) => Ok(map),
            _ => Err(SsoError::Unreachable),
        }
    }

    async fn verify_id_token(
        &self,
        provider: &Arc<Provider>,
        token: &str,
        nonce: &str,
    ) -> Result<Map<String, Value>, SsoError> {
        let check = |p: &Provider| {
            let expected = idtoken::Expected {
                issuer: &self.settings.issuer,
                client_id: &self.settings.client_id,
                nonce,
                algorithms: &p.algorithms,
                now: crate::jwt::now_unix(),
            };
            idtoken::verify(token, &p.keys, &expected)
        };
        match check(provider) {
            Ok(claims) => Ok(claims),
            Err(idtoken::TokenError::UnknownKid) => match self.refresh_keys(provider).await? {
                Some(fresh) => check(&fresh).map_err(|e| {
                    tracing::warn!(error = %e, "SSO: ID token refused");
                    SsoError::TokenInvalid("id_token")
                }),
                None => Err(SsoError::TokenInvalid("unknown kid")),
            },
            Err(e) => {
                tracing::warn!(error = %e, "SSO: ID token refused");
                Err(SsoError::TokenInvalid("id_token"))
            }
        }
    }

    async fn userinfo(&self, endpoint: &Url, access_token: &str) -> Result<Map<String, Value>, SsoError> {
        let response = self
            .http
            .get(endpoint.clone())
            .bearer_auth(access_token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| SsoError::Unreachable)?;
        if !response.status().is_success() {
            return Err(SsoError::Unreachable);
        }
        match Self::read_json(response).await? {
            Value::Object(map) => Ok(map),
            _ => Err(SsoError::TokenInvalid("userinfo")),
        }
    }

    /// Takes a one-time code (single use, also when the verifier is wrong) and checks the client's PKCE
    /// verifier against the challenge of the start request.
    pub async fn take_code(&self, code: &str, verifier: &str) -> Result<PendingCode, ApiError> {
        let invalid = || ApiError::BadRequest {
            code: "sso.code_invalid",
            detail: "Code invalid, expired or already used".into(),
        };
        if !crate::routes::connect::valid_verifier(verifier) || code.len() > 128 {
            return Err(invalid());
        }
        let entry = match &self.cluster {
            Some(cluster) => cluster
                .take_sealed::<PendingCode>(&format!("oidc-code:{}", util::sha256_b64(code)))
                .await
                .map_err(crate::cache::unavailable)?,
            None => lock(&self.codes).remove(&util::sha256_b64(code)).filter(|c| c.expires > Instant::now()),
        };
        let entry = entry.ok_or_else(invalid)?;
        let computed = crate::routes::connect::s256(verifier);
        if !bool::from(computed.as_bytes().ct_eq(entry.client_challenge.as_bytes())) {
            return Err(invalid());
        }
        Ok(entry)
    }

    /// A reauth token for an identity reset of `user_id` (§8.4): 5 minutes, single use.
    pub fn issue_reauth(&self, user_id: &str) -> Result<String, ApiError> {
        let token = util::random_token(32);
        let mut map = lock(&self.reauth);
        let now = Instant::now();
        map.retain(|_, (_, exp)| *exp > now);
        if map.len() >= MAX_PENDING {
            return Err(busy());
        }
        map.insert(util::sha256_b64(&token), (user_id.to_string(), now + REAUTH_TTL));
        Ok(token)
    }

    /// Spends a reauth token; `true` if it was valid for `user_id`.
    pub fn take_reauth(&self, token: &str, user_id: &str) -> bool {
        let entry = lock(&self.reauth).remove(&util::sha256_b64(token));
        entry.is_some_and(|(uid, exp)| exp > Instant::now() && uid == user_id)
    }

    /// Where the callback sends the browser: always the node's own web origin.
    pub fn web_redirect(&self, query: &[(&str, &str)]) -> String {
        let mut url = Url::parse(&format!("{}/sso/callback", self.settings.web_origin.trim_end_matches('/')))
            .unwrap_or_else(|_| unreachable_url());
        url.query_pairs_mut().extend_pairs(query);
        url.to_string()
    }

    /// The provider's logout URL (§8.6) from the cached discovery document (`None` if it has none).
    pub async fn end_session_url(&self) -> Option<String> {
        let provider = self.provider().await.ok()?;
        let mut url = provider.end_session_endpoint.clone()?;
        url.query_pairs_mut().append_pair("client_id", &self.settings.client_id).append_pair(
            "post_logout_redirect_uri",
            &format!("{}/login", self.settings.web_origin.trim_end_matches('/')),
        );
        Some(url.to_string())
    }

    /// For tests: forget the cached provider document.
    pub async fn clear_cache(&self) {
        *self.provider.lock().await = None;
    }
}

fn unreachable_url() -> Url {
    // The web origin is validated at start; this is never reached.
    Url::parse("http://localhost/sso/callback").unwrap_or_else(|_| unreachable!("static URL"))
}

fn busy() -> ApiError {
    ApiError::Unavailable { code: "sso.busy", detail: "Too many pending sign-ins, please try again shortly".into() }
}

/// The provider's `error` value as it may appear in our redirect: `[A-Za-z0-9_.-]`, at most 64 characters.
pub fn sanitize_error(e: &str) -> String {
    let clean: String =
        e.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')).take(64).collect();
    if clean.is_empty() { "unknown".into() } else { clean }
}

/// `application/x-www-form-urlencoded` encoding of one value (for HTTP Basic client credentials).
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'*') {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `check-config`: reads the client secret, fetches discovery and JWKS and prints what the node will use.
/// Without an issuer it does nothing.
pub async fn check_provider(config: &Config) -> anyhow::Result<()> {
    let Some(oidc) = Oidc::from_config(config)? else { return Ok(()) };
    let provider = oidc.provider().await.map_err(|e| {
        anyhow::anyhow!(
            "TAVRN_OIDC_ISSUER: discovery or JWKS of '{}' failed ({}): unreachable, another issuer in the document, no allowed signing algorithm or not https",
            oidc.settings.issuer,
            e.code()
        )
    })?;
    eprintln!(
        "SSO: issuer {} ok, {} signing key(s), algorithms {:?}, redirect URI to register: {}",
        oidc.settings.issuer,
        provider.keys.len(),
        provider.algorithms,
        oidc.settings.redirect_uri
    );
    Ok(())
}

/// Refuses password, registration and passkey-only logins under `TAVRN_OIDC_ONLY` except for the accounts
/// of `TAVRN_ADMIN_USERS` (break-glass, §8.3).
pub fn check_password_login(config: &Config, username: &str) -> Result<(), ApiError> {
    if config.oidc_issuer().is_some() && config.oidc_only && !config.admin_users().iter().any(|a| a == username) {
        return Err(ApiError::Forbidden {
            code: "auth.password_login_disabled",
            detail: "This node only allows single sign-on".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn redirects_use_the_public_url() {
        // Delegation: identity domain tavrn.org, node served at app.tavrn.org.
        let c = Config {
            domain: "tavrn.org".into(),
            public_url: Some("https://app.tavrn.org".into()),
            oidc_issuer: Some("https://idp.example".into()),
            oidc_client_id: Some("tavrn".into()),
            oidc_client_secret: Some("s3cret".into()),
            ..Config::default()
        };
        let oidc = Oidc::from_config(&c).unwrap().unwrap();
        assert_eq!(oidc.settings.redirect_uri, "https://app.tavrn.org/api/v1/auth/oidc/callback");
        assert_eq!(oidc.settings.web_origin, "https://app.tavrn.org");
    }

    #[test]
    fn errors_are_sanitized() {
        assert_eq!(sanitize_error("access_denied"), "access_denied");
        assert_eq!(sanitize_error("<script>x"), "scriptx");
        assert_eq!(sanitize_error("&&&"), "unknown");
        assert_eq!(sanitize_error(&"a".repeat(100)).len(), 64);
    }

    #[test]
    fn form_encoding_of_credentials() {
        assert_eq!(form_encode("abc-DEF_1.2*"), "abc-DEF_1.2*");
        assert_eq!(form_encode("a b:c%"), "a+b%3Ac%25");
    }

    #[test]
    fn password_login_gate() {
        let mut c = Config { domain: "x.example".into(), ..Config::default() };
        assert!(check_password_login(&c, "alice").is_ok(), "no SSO: always allowed");
        c.oidc_issuer = Some("https://idp.example".into());
        c.oidc_only = true;
        c.admin_users = "root".into();
        assert!(check_password_login(&c, "alice").is_err());
        assert!(check_password_login(&c, "root").is_ok(), "break-glass");
        c.oidc_only = false;
        assert!(check_password_login(&c, "alice").is_ok());
    }
}
