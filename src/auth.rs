// SPDX-License-Identifier: AGPL-3.0-only
//! Passwords, session tokens, the authentication extractor and the rate limiter.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use argon2::{
    Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};
use serde::{Deserialize, Serialize};

use crate::{
    app::AppState,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    models::UserRow,
    store,
    util::{self, now},
};

/// Lifetime of an access token (`TAVRN_SESSION_ACCESS_MINUTES`).
pub fn access_ttl_secs(config: &crate::config::Config) -> i64 {
    i64::from(config.session_access_minutes) * 60
}

/// Sliding lifetime of a refresh token (`TAVRN_SESSION_REFRESH_DAYS`): every rotation extends the session by it.
pub fn refresh_ttl_secs(config: &crate::config::Config) -> i64 {
    i64::from(config.session_refresh_days) * 24 * 3600
}

/// Presenting the immediately previous refresh token within this many seconds of a rotation answers with the
/// current token pair instead of revoking the session (PROTOCOL.md §5b).
pub const REFRESH_REUSE_GRACE_SECS: i64 = 30;

// ---------------------------------------------------------------- Passwords

fn argon() -> Argon2<'static> {
    // 64 MiB, 3 iterations, 1 thread.
    let params = Params::new(64 * 1024, 3, 1, None).unwrap_or_default();
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    argon()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("password hash: {e}")))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| argon().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Argon2id (64 MiB, about 0.1–0.3 s of CPU) never runs on the async runtime: on the blocking pool, at most
/// `TAVRN_PASSWORD_HASH_CONCURRENCY` at a time, so a burst of logins cannot stall WebSockets and federation or
/// exhaust memory.
async fn blocking_hash<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    let permit = state
        .password_hashing
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("password hashing closed: {e}")))?;
    // The blocking task holds the slot: a cancelled request (client gone) cannot free it while Argon2 still runs.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("password hashing: {e}")))
}

/// [`hash_password`] off the async runtime (see [`blocking_hash`]).
pub async fn hash(state: &AppState, password: &str) -> Result<String, ApiError> {
    let password = zeroize::Zeroizing::new(password.to_string());
    blocking_hash(state, move || hash_password(&password)).await?
}

/// [`verify_password`] off the async runtime (see [`blocking_hash`]). Without a hash (unknown user, bot, SSO-only
/// account) a dummy hash is verified, so the answer takes as long.
pub async fn verify(state: &AppState, password: &str, hash: Option<&str>) -> Result<bool, ApiError> {
    let password = zeroize::Zeroizing::new(password.to_string());
    let (hash, real) = match hash {
        Some(h) => (h.to_string(), true),
        None => (DUMMY_HASH.to_string(), false),
    };
    Ok(blocking_hash(state, move || verify_password(&password, &hash)).await? && real)
}

/// Argon2id hash of a random value, only to spend the same time on unknown users.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHRzb21lc2FsdA$Vh1J9m0K0qYQ9XQy3pQ7F1D2v3kQ1nUO7a0Q7b2Zc4Y";

/// Default of `TAVRN_PASSWORD_HASH_CONCURRENCY`: twice the CPU cores, at least 2.
pub fn default_hash_concurrency() -> usize {
    (std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1) * 2).max(2)
}

/// At least 10 characters, at most 256; no composition rules (NIST 800-63B).
pub fn valid_password(p: &str) -> bool {
    (10..=256).contains(&p.chars().count())
}

// ---------------------------------------------------------------- Tokens

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    pub dev: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionExtra {
    pub dev: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub device_id: String,
}

pub fn issue_access_token(state: &AppState, user_id: &str, device_id: &str) -> Result<String, ApiError> {
    let key = state.signing_key();
    let now = jwt::now_unix();
    let claims = SessionClaims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: user_id.to_string(),
            aud: state.config.domain.clone(),
            exp: now + access_ttl_secs(&state.config),
            iat: now,
            jti: util::ulid(),
            typ: "session".into(),
        },
        dev: device_id.to_string(),
    };
    jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))
}

/// New session for a device: access token + fresh refresh token (stored only as a hash).
pub async fn issue_session(state: &AppState, user_id: &str, device_id: &str) -> Result<TokenPair, ApiError> {
    let refresh = util::random_token(32);
    store::users::create_session(
        &state.db,
        user_id,
        device_id,
        &util::sha256_b64(&refresh),
        refresh_ttl_secs(&state.config),
    )
    .await?;
    Ok(TokenPair {
        access_token: issue_access_token(state, user_id, device_id)?,
        refresh_token: refresh,
        expires_in: access_ttl_secs(&state.config),
        device_id: device_id.to_string(),
    })
}

/// The refresh token that replaces `refresh_token` at its rotation. Derived, not random, so that parallel refreshes
/// with the same token (two tabs, two requests after the access token expired) all end with the same token pair
/// although only hashes are stored: `HKDF-SHA256(IKM = node secret, info = "tavrn refresh rotation v1\0" || token)`.
/// Without the node secret (`keys/secrets.key`) the next token cannot be computed from a stolen one.
fn next_refresh_token(state: &AppState, refresh_token: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, state.secret_key.as_slice());
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    let info = [b"tavrn refresh rotation v1\0".as_slice(), refresh_token.as_bytes()];
    if hk.expand_multi_info(&info, out.as_mut()).is_err() {
        // 32 bytes are always within the HKDF output limit; fall back to a random (non-shared) token.
        return util::random_token(32);
    }
    URL_SAFE_NO_PAD.encode(out.as_ref())
}

/// Seconds since an RFC 3339 time (large if unreadable).
fn seconds_since(time: Option<&str>) -> i64 {
    time.and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds())
        .unwrap_or(i64::MAX)
}

/// Rotates a refresh token (PROTOCOL.md §5b). The rotation is atomic (only while the presented token is still the
/// current one); parallel refreshes with the same token get the same new pair. The immediately previous token
/// presented again within [`REFRESH_REUSE_GRACE_SECS`] of the rotation answers with the current pair as well;
/// later, it revokes the whole session (theft suspected).
pub async fn refresh_session(state: &AppState, refresh_token: &str) -> Result<TokenPair, ApiError> {
    let hash = util::sha256_b64(refresh_token);
    let unauthorized = || ApiError::Unauthorized { code: "auth.refresh_invalid" };
    let next = next_refresh_token(state, refresh_token);
    let next_hash = util::sha256_b64(&next);
    let live = |s: &crate::models::SessionRow| s.revoked_at.is_none() && s.expires_at > now();

    if let Some(session) = store::users::session_by_hash(&state.db, &hash).await? {
        if !live(&session) {
            return Err(unauthorized());
        }
        // A federated or SSO session ends at its hard limit whatever the refreshes (FEDERATION.md §2.5).
        let mut expires_at = util::in_seconds(refresh_ttl_secs(&state.config));
        if let Some(max) = session.max_expires_at.as_ref().filter(|max| **max < expires_at) {
            expires_at = max.clone();
        }
        if !store::users::rotate_session(&state.db, &session.id, &hash, &next_hash, &expires_at).await? {
            // A parallel refresh with the same token won the rotation: it stored the same derived token.
            let current = store::users::session_by_id(&state.db, &session.id).await?;
            if !current.is_some_and(|c| c.refresh_token_hash == next_hash && live(&c)) {
                return Err(unauthorized());
            }
        }
        return token_pair(state, &session, next).await;
    }
    if let Some(session) = store::users::session_by_prev_hash(&state.db, &hash).await? {
        let in_grace = seconds_since(session.rotated_at.as_deref()) <= REFRESH_REUSE_GRACE_SECS;
        if in_grace && session.refresh_token_hash == next_hash && live(&session) {
            return token_pair(state, &session, next).await;
        }
        tracing::warn!(session = session.id, "refresh token reused, session revoked");
        store::users::revoke_session(&state.db, &session.id).await?;
    }
    Err(unauthorized())
}

async fn token_pair(
    state: &AppState,
    session: &crate::models::SessionRow,
    refresh: String,
) -> Result<TokenPair, ApiError> {
    store::users::touch_device(&state.db, &session.device_id).await?;
    // Remote devices are known to their clients by the home device id.
    let device_id = match store::federation::home_device_id(&state.db, &session.device_id).await? {
        Some(home) => home,
        None => session.device_id.clone(),
    };
    Ok(TokenPair {
        access_token: issue_access_token(state, &session.user_id, &session.device_id)?,
        refresh_token: refresh,
        expires_in: access_ttl_secs(&state.config),
        device_id,
    })
}

// ---------------------------------------------------------------- Extractor

/// Authenticated user with device. Only full sessions: a pre-auth token (password done, second factor
/// missing) is refused with `auth.second_factor_required`.
///
/// Remote users (FEDERATION.md §2.6) authenticate with the session of a federated login. For them
/// `device_id` is the **local** row id of their device (all database references use it) and
/// `home_device_id` the device id on their home node (the identity in MLS credentials and the
/// `device_id` their clients know). Routes that belong to the home node refuse them
/// (`federation.local_only`, see `federation::guard`).
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: UserRow,
    pub device_id: String,
    /// Remote users only: the device id on the user's home node.
    pub home_device_id: Option<String>,
    /// Bots only (app token or federated session of a remote bot): application and effective scopes
    /// (APPLICATIONS.md §2.3). Every request of a bot passes the route table of `applications.rs`.
    pub app: Option<crate::applications::AppPrincipal>,
}

impl AuthUser {
    /// `true` for a user of another node with a federated session.
    pub fn is_remote(&self) -> bool {
        self.home_device_id.is_some()
    }

    /// The device id other users and clients know: the home device id of a remote device (MLS
    /// identities, message envelopes), the device id itself for local users.
    pub fn public_device_id(&self) -> &str {
        self.home_device_id.as_deref().unwrap_or(&self.device_id)
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

/// The unverified `typ` claim, only to pick the verification path (each path verifies `typ` itself).
fn peek_typ(token: &str) -> Option<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    #[derive(Deserialize)]
    struct Typ {
        typ: String,
    }
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Typ>(&bytes).ok().map(|t| t.typ)
}

pub async fn authenticate(state: &AppState, token: &str) -> Result<AuthUser, ApiError> {
    // Admin API tokens are valid for `/api/v1/admin/*` only (through `NodeAdmin`), never here: not for
    // other routes, the WebSocket or anything else that authenticates a user.
    if crate::admin_tokens::is_admin_token(token) {
        return Err(ApiError::Unauthorized { code: "auth.admin_token_not_allowed" });
    }
    if peek_typ(token).as_deref() == Some("app") {
        return crate::applications::authenticate(state, token).await;
    }
    let invalid = |code| ApiError::Unauthorized { code };
    let kid = jwt::peek_kid(token).map_err(|_| invalid("auth.token_invalid"))?;
    let key = state.keys.iter().find(|k| k.kid == kid).ok_or_else(|| invalid("auth.token_invalid"))?;
    let expected = Expected { iss: state.config.domain.clone(), aud: state.config.domain.clone(), typ: "session" };
    let (claims, extra): (StandardClaims, SessionExtra) = match jwt::verify(token, &key.verifying(), &expected) {
        Ok(v) => v,
        Err(jwt::JwtError::Expired) => return Err(invalid("auth.token_expired")),
        // A genuine pre-auth token: password done, second factor still missing.
        Err(jwt::JwtError::Claims(_)) => {
            let preauth = Expected { typ: "preauth", ..expected };
            return Err(match jwt::verify::<serde::de::IgnoredAny>(token, &key.verifying(), &preauth) {
                Ok(_) => invalid("auth.second_factor_required"),
                Err(_) => invalid("auth.token_invalid"),
            });
        }
        Err(_) => return Err(invalid("auth.token_invalid")),
    };
    // Development nodes only: `POST /dev/expire-access-tokens` ends every access token issued before it (e2e tests).
    if claims.iat < state.access_not_before.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(invalid("auth.token_expired"));
    }
    let mut user = store::users::by_id(&state.db, &claims.sub).await?.ok_or_else(|| invalid("auth.token_invalid"))?;
    if user.disabled_at.is_some() {
        return Err(invalid("auth.account_disabled"));
    }
    // Local bots authenticate with app tokens only; a session token naming one was not issued by this node's
    // rules (APPLICATIONS.md §1.4).
    if user.is_bot() && user.domain == state.config.domain {
        return Err(invalid("auth.token_invalid"));
    }
    // A local device whose sessions ended (logout, password change or reset, removal, disabled, …) loses its access
    // tokens at once, not when they expire (PROTOCOL.md §5b).
    if user.domain == state.config.domain && !crate::sessions::device_live(state, &extra.dev).await? {
        return Err(invalid("auth.session_revoked"));
    }
    if user.domain != state.config.domain {
        // Remote user: federation must (still) be allowed for the home domain and the federated session
        // must be live, so revocations (`session.revoke`) and the 7-day cap take effect immediately.
        if !state.config.federation_enabled {
            return Err(crate::federation::disabled());
        }
        state.federation.check_policy(&user.domain).map_err(|e| e.to_api())?;
        let home = store::federation::live_remote_session(&state.db, &user.id, &extra.dev)
            .await?
            .ok_or_else(|| invalid("auth.token_invalid"))?;
        // Node bans of the address or its domain end the API access at once (FEDERATION.md §3.2).
        if store::rooms::is_banned(&state.db, None, &user.address(), &user.domain).await? {
            return Err(invalid("auth.token_invalid"));
        }
        // A peer blocked after a key conflict or by an operator (FEDERATION.md §1.4, §9.4) loses its sessions at once.
        if store::federation::peer_status(&state.db, &user.domain)
            .await?
            .is_some_and(|s| s != crate::federation::discovery::STATUS_OK)
        {
            return Err(invalid("auth.token_invalid"));
        }
        // A bot whose owner is banned from the node goes too, as at the login (FEDERATION.md §3.2, APPLICATIONS.md §1.7).
        if let Some(owner) = user.owner_address.as_deref().filter(|_| user.is_bot())
            && let Some((_, domain)) = crate::util::parse_address(owner)
            && store::rooms::is_banned(&state.db, None, owner, domain).await?
        {
            return Err(invalid("auth.token_invalid"));
        }
        state.federation_api_limiter.check_all(&[format!("domain:{}", user.domain)])?;
        let app = if user.is_bot() {
            Some(crate::applications::remote_principal(state, &mut user, &extra.dev).await?)
        } else {
            None
        };
        return Ok(AuthUser { user, device_id: extra.dev, home_device_id: Some(home), app });
    }
    Ok(AuthUser { user, device_id: extra.dev, home_device_id: None, app: None })
}

/// Route checks for an authenticated request: `federation.local_only` for remote users (FEDERATION.md
/// §2.8) and, for bots, the fail-closed route table with the token's scopes (APPLICATIONS.md §2.5).
pub fn check_route(state: &AppState, auth: &AuthUser, parts: &Parts) -> Result<(), ApiError> {
    crate::federation::guard::check(state, auth, parts)?;
    if auth.user.is_bot() {
        let path = parts.extensions.get::<axum::extract::MatchedPath>().map(axum::extract::MatchedPath::as_str);
        let scopes = auth.app.as_ref().map(|a| a.scopes.as_slice()).unwrap_or_default();
        crate::applications::check_route(scopes, &parts.method, path)?;
    }
    Ok(())
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = bearer(&parts.headers).ok_or(ApiError::Unauthorized { code: "auth.required" })?;
        let auth = authenticate(state, token).await?;
        // The general per-user limit (`TAVRN_RATE_USER_PER_MINUTE`); route limits come on top.
        if let Some(limiter) = &state.user_api_limiter {
            limiter.check_all(&[format!("user:{}", auth.user.id)])?;
        }
        check_route(state, &auth, parts)?;
        // `TAVRN_LEGAL_TERMS_MODE=require`: nothing but the legal flow until the current terms are accepted.
        let path = parts.extensions.get::<axum::extract::MatchedPath>().map(axum::extract::MatchedPath::as_str);
        // `age.v1`: accounts without a date of birth complete it first (PROTOCOL.md §5e). Checked before the terms, so
        // the terms dialog stays reachable while the date of birth is missing (and the other way round).
        crate::age::check_required(state, &auth.user, path)?;
        crate::legal::documents::check_required(state, &auth.user, path).await?;
        Ok(auth)
    }
}

/// Node admins only: a node admin's session, or an admin API token (`tavrn_adm_…`) whose
/// scopes cover the route; the token then acts as its creator. Both share one rate limit class.
#[derive(Debug, Clone)]
pub struct NodeAdmin(pub AuthUser);

impl FromRequestParts<AppState> for NodeAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(token) = bearer(&parts.headers).filter(|t| crate::admin_tokens::is_admin_token(t)) {
            return crate::admin_tokens::authenticate(state, token, parts).await.map(NodeAdmin);
        }
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if !auth.user.is_node_admin() {
            return Err(ApiError::Forbidden { code: "auth.node_admin_required", detail: "Node admins only".into() });
        }
        state.admin_limiter.check_all(&[format!("admin:{}", auth.user.id)])?;
        Ok(NodeAdmin(auth))
    }
}

impl NodeAdmin {
    /// The admin token this request uses (`None` for a session).
    pub fn token_id(&self) -> Option<&str> {
        self.0.device_id.strip_prefix("admin-token:")
    }
}

/// Client address. If the connection comes from a trusted proxy (`TAVRN_TRUSTED_PROXIES`), the
/// **rightmost untrusted** address in `X-Forwarded-For` counts, so a client cannot forge the chain with
/// entries of its own. Otherwise the connection address itself counts.
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

pub fn resolve_client_ip(
    config: &crate::config::Config,
    peer: Option<std::net::IpAddr>,
    forwarded_for: Option<&str>,
) -> String {
    resolve_client_ip_with(&config.trusted_proxies(), peer, forwarded_for)
}

/// [`resolve_client_ip`] with the trusted proxies parsed already (`AppState::trusted_proxies`, once at start: the
/// list is consulted for the peer and every forwarded hop of every request).
pub fn resolve_client_ip_with(
    trusted: &[ipnet::IpNet],
    peer: Option<std::net::IpAddr>,
    forwarded_for: Option<&str>,
) -> String {
    let is_trusted = |ip: std::net::IpAddr| trusted.iter().any(|n| n.contains(&ip));
    let Some(peer) = peer else { return "unknown".into() };
    if !is_trusted(peer) {
        return peer.to_string();
    }
    let chain: Vec<std::net::IpAddr> =
        forwarded_for.unwrap_or("").split(',').filter_map(|s| s.trim().parse().ok()).collect();
    for ip in chain.iter().rev() {
        if !is_trusted(*ip) {
            return ip.to_string();
        }
    }
    // Only trusted addresses in the chain: the first one is then the origin (e.g. an internal network).
    chain.first().map(ToString::to_string).unwrap_or_else(|| peer.to_string())
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip());
        let forwarded = parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        Ok(ClientIp(resolve_client_ip_with(&state.trusted_proxies, peer, forwarded)))
    }
}

// ---------------------------------------------------------------- Rate limiter

/// Prefix length IPv6 client addresses are grouped by in rate limit keys (`TAVRN_RATE_LIMIT_IPV6_PREFIX`): one
/// host usually holds a whole /64, so per-address limits would be no limit at all. Set from the configuration when
/// the node starts.
static IPV6_RATE_PREFIX: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(64);

/// Sets the prefix of [`rate_key`] (`TAVRN_RATE_LIMIT_IPV6_PREFIX`, 32–128).
pub fn set_ipv6_rate_prefix(prefix: u8) {
    IPV6_RATE_PREFIX.store(prefix.clamp(32, 128), std::sync::atomic::Ordering::Relaxed);
}

/// The rate limit identity of a client address: IPv4 addresses as they are, IPv6 addresses (except IPv4-mapped
/// ones) by their network (`2001:db8:1:2::/64`), anything else unchanged.
pub fn rate_key(ip: &str) -> String {
    let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() else { return ip.to_string() };
    if let Some(v4) = addr.to_ipv4_mapped() {
        return v4.to_string();
    }
    let prefix = u32::from(IPV6_RATE_PREFIX.load(std::sync::atomic::Ordering::Relaxed));
    let mask = if prefix >= 128 { u128::MAX } else { !(u128::MAX >> prefix) };
    format!("{}/{prefix}", std::net::Ipv6Addr::from(u128::from(addr) & mask))
}

/// A limiter key with its client address normalised by [`rate_key`]: `ip:2001:db8::1` and `ip:2001:db8::2` are the
/// same key. Every limiter applies it, so no call site can forget it (keys are `<name>:<address>`, also
/// `domain:<d>|ip:<address>`).
pub fn normalize_key(key: &str) -> std::borrow::Cow<'_, str> {
    // An IPv6 address is the rest of the key after one of its colons (it contains colons itself, usernames,
    // domains and ids never do).
    for (i, _) in key.match_indices(':') {
        let rest = &key[i + 1..];
        if rest.contains(':') && rest.parse::<std::net::Ipv6Addr>().is_ok() {
            return std::borrow::Cow::Owned(format!("{}{}", &key[..=i], rate_key(rest)));
        }
    }
    std::borrow::Cow::Borrowed(key)
}

/// Keys above this count make the limiter sweep expired windows (at most once per [`SWEEP_INTERVAL`]).
const SWEEP_ABOVE: usize = 10_000;
/// Hard bound of a limiter's map: when even live windows fill it, keys that are not over their limit are dropped.
const MAX_KEYS: usize = 100_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Simple counter per key in a fixed window. Sufficient for a single instance;
/// multiple instances will use Valkey (phase 5).
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<Hits>,
}

struct Hits {
    map: HashMap<String, (u32, Instant)>,
    swept: Instant,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, hits: Mutex::new(Hits { map: HashMap::new(), swept: Instant::now() }) }
    }

    /// Lazy eviction: expired windows go at most once per second, never on every call; a map full of live windows
    /// keeps only the keys that are over their limit.
    fn sweep(&self, hits: &mut Hits, now: Instant) {
        if hits.map.len() <= SWEEP_ABOVE || now.duration_since(hits.swept) < SWEEP_INTERVAL {
            return;
        }
        hits.swept = now;
        hits.map.retain(|_, (_, start)| now.duration_since(*start) < self.window);
        if hits.map.len() >= MAX_KEYS {
            hits.map.retain(|_, (n, _)| *n > self.max);
        }
    }

    /// `Ok(())` or `Err(seconds until the next attempt)`.
    pub fn check(&self, key: &str) -> Result<(), u32> {
        let key = normalize_key(key);
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        self.sweep(&mut hits, now);
        let entry = hits.map.entry(key.into_owned()).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
        if entry.0 > self.max {
            let retry = self.window.saturating_sub(now.duration_since(entry.1)).as_secs() as u32 + 1;
            Err(retry)
        } else {
            Ok(())
        }
    }

    /// Like [`RateLimiter::check`] without counting: `Err(seconds)` while `key` is over its limit.
    pub fn peek(&self, key: &str) -> Result<(), u32> {
        let key = normalize_key(key);
        let hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match hits.map.get(key.as_ref()) {
            Some((n, start)) if *n >= self.max && now.duration_since(*start) < self.window => {
                Err(self.window.saturating_sub(now.duration_since(*start)).as_secs() as u32 + 1)
            }
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.hits.lock().unwrap_or_else(|e| e.into_inner()).map.len()
    }

    pub fn check_all(&self, keys: &[String]) -> Result<(), ApiError> {
        for k in keys {
            if let Err(retry_after_secs) = self.check(k) {
                return Err(ApiError::RateLimited { retry_after_secs });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "not-a-hash"));
    }

    #[test]
    fn password_policy() {
        assert!(valid_password("tencharsok"));
        assert!(!valid_password("short"));
        assert!(!valid_password(&"a".repeat(257)));
    }

    #[test]
    fn client_ip_resolution_resists_spoofing() {
        let config = crate::config::Config {
            domain: "x".into(),
            database_url: "postgres://x".into(),
            ..crate::config::Config::default()
        };
        let ip = |s: &str| s.parse::<std::net::IpAddr>().ok();
        // Directly connected, no proxy: the header is ignored.
        assert_eq!(resolve_client_ip(&config, ip("203.0.113.9"), Some("1.2.3.4")), "203.0.113.9");
        // Through the Docker proxy: client IP from the header.
        assert_eq!(resolve_client_ip(&config, ip("172.18.0.2"), Some("198.51.100.7")), "198.51.100.7");
        // The client prepends a forged address: the rightmost untrusted address counts.
        assert_eq!(resolve_client_ip(&config, ip("172.18.0.2"), Some("1.2.3.4, 198.51.100.7")), "198.51.100.7");
        // Two trusted proxies in a row.
        assert_eq!(resolve_client_ip(&config, ip("172.18.0.2"), Some("198.51.100.7, 10.0.0.5")), "198.51.100.7");
        // Only internal addresses: the origin is the first one.
        assert_eq!(resolve_client_ip(&config, ip("172.18.0.2"), Some("10.0.0.9")), "10.0.0.9");
        assert_eq!(resolve_client_ip(&config, ip("172.18.0.2"), None), "172.18.0.2");
        assert_eq!(resolve_client_ip(&config, None, Some("1.2.3.4")), "unknown");
    }

    #[test]
    fn ipv6_addresses_share_a_key_per_prefix() {
        assert_eq!(rate_key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(rate_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64");
        assert_ne!(rate_key("2001:db8:1:3::1"), rate_key("2001:db8:1:2::1"));
        assert_eq!(rate_key("203.0.113.9"), "203.0.113.9");
        assert_eq!(rate_key("::ffff:203.0.113.9"), "203.0.113.9", "IPv4-mapped counts as IPv4");
        assert_eq!(rate_key("unknown"), "unknown");
        assert_eq!(normalize_key("ip:2001:db8::1"), "ip:2001:db8::/64");
        assert_eq!(normalize_key("forgot:2001:db8::2"), "ip:2001:db8::/64".replace("ip:", "forgot:"));
        assert_eq!(normalize_key("domain:a.example|ip:2001:db8::7"), "domain:a.example|ip:2001:db8::/64");
        assert_eq!(normalize_key("ip:203.0.113.9"), "ip:203.0.113.9");
        assert_eq!(normalize_key("user:alice"), "user:alice");
        assert_eq!(normalize_key("2fa:01J9ZZZZZZZZZZZZZZZZZZZZZZ"), "2fa:01J9ZZZZZZZZZZZZZZZZZZZZZZ");
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        assert!(rl.check("ip:2001:db8::1").is_ok());
        assert!(rl.check("ip:2001:db8::2").is_ok());
        assert!(rl.check("ip:2001:db8::3").is_err(), "rotating addresses within a /64 share the limit");
        assert!(rl.check("ip:2001:db8:0:1::1").is_ok(), "another /64 has its own");
    }

    #[test]
    fn the_limiter_sweeps_lazily_and_stays_bounded() {
        let rl = RateLimiter::new(1, Duration::from_millis(20));
        for i in 0..(SWEEP_ABOVE + 100) {
            let _ = rl.check(&format!("k{i}"));
        }
        assert!(rl.len() > SWEEP_ABOVE, "no sweep within the first second");
        std::thread::sleep(Duration::from_millis(1100));
        let _ = rl.check("fresh");
        assert_eq!(rl.len(), 1, "expired windows go in one sweep");
        // A map full of live windows keeps only the keys over their limit.
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let _ = rl.check("blocked");
        let _ = rl.check("blocked");
        for i in 0..MAX_KEYS {
            let _ = rl.check(&format!("k{i}"));
        }
        rl.hits.lock().unwrap().swept = Instant::now() - SWEEP_INTERVAL;
        let _ = rl.check("next");
        assert!(rl.len() <= 2, "{}", rl.len());
        assert!(rl.peek("blocked").is_err(), "a blocked key stays blocked");
    }

    #[test]
    fn peek_does_not_count() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        assert!(rl.peek("a").is_ok());
        assert!(rl.check("a").is_ok());
        assert!(rl.peek("a").is_ok());
        assert!(rl.check("a").is_ok());
        assert!(rl.peek("a").is_err(), "at the limit: the next attempt would be refused");
        assert!(rl.peek("a").is_err());
        assert!(rl.check("b").is_ok());
    }

    #[test]
    fn rate_limiter_blocks_after_max_and_resets() {
        let rl = RateLimiter::new(2, Duration::from_millis(50));
        assert!(rl.check("a").is_ok());
        assert!(rl.check("a").is_ok());
        let retry = rl.check("a").unwrap_err();
        assert!(retry >= 1);
        assert!(rl.check("b").is_ok(), "other keys are independent");
        std::thread::sleep(Duration::from_millis(60));
        assert!(rl.check("a").is_ok(), "free again after the window");
    }
}
