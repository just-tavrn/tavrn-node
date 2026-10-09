// SPDX-License-Identifier: AGPL-3.0-only
//! Applications (bots): app tokens (`typ = "app"`), scopes, the fail-closed route table for bots, the
//! event filter of their WebSockets and the owner cascades (protocol/APPLICATIONS.md §1–§3).
//!
//! A bot is a user row with `kind = "bot"` and an owner. Its only credential is an app token: an EdDSA JWT
//! of this node, shown once and stored as a SHA-256 hash, bound to one bot device. Every request of a bot
//! (local app token or federated session of a remote bot) passes [`check_route`]: a route template that is
//! not in [`APP_ROUTES`] is refused, so new routes stay closed to bots until they are classified here.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    models::{Room, UserRow},
    permissions, store,
    store::applications::ApplicationRow,
    util,
};

/// Tokens (= bot devices) per application.
pub const MAX_TOKENS: i64 = 5;
/// The previous secret stays valid this long after a rotation by the bot (§2.2).
pub const ROTATION_OVERLAP_SECS: i64 = 24 * 3600;
/// Concurrent WebSockets per token; one more closes the oldest with [`CLOSE_REPLACED`] (§2.6).
pub const MAX_CONNECTIONS_PER_TOKEN: usize = 2;
/// WebSocket close code: replaced by a newer connection of the same token, do not reconnect.
pub const CLOSE_REPLACED: u16 = 4004;
/// Pending transfers expire after 7 days (§1.6).
pub const TRANSFER_TTL_SECS: i64 = 7 * 24 * 3600;

// ---------------------------------------------------------------- errors

pub fn bot_forbidden() -> ApiError {
    ApiError::Forbidden { code: "app.bot_forbidden", detail: "Bots cannot use this route".into() }
}

pub fn scope_missing(scope: &str) -> ApiError {
    ApiError::ForbiddenMeta {
        code: "app.scope_missing",
        detail: format!("The token lacks the scope {scope}"),
        meta: json!({ "scope": scope }),
    }
}

pub fn disabled(reason: &str) -> ApiError {
    ApiError::ForbiddenMeta {
        code: "app.disabled",
        detail: "This application is disabled".into(),
        meta: json!({ "reason": reason }),
    }
}

pub fn not_found() -> ApiError {
    ApiError::NotFound { code: "app.not_found", what: "Application".into() }
}

// ---------------------------------------------------------------- route table (§2.5)

/// What a route needs from an app token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Allowed for every app token (the handler may refuse bots for other reasons).
    Always,
    /// Needs this scope.
    Scope(&'static str),
    /// Needs one of these scopes.
    AnyScope(&'static [&'static str]),
}

use Access::{Always, AnyScope, Scope};

const MOD_OR_MANAGE: Access = AnyScope(&["moderation", "rooms:manage"]);

/// `(method, route template, access)` for app tokens. A template that is not here is refused with
/// `403 app.bot_forbidden` (fail closed). Deliberately absent (§2.5): password, second factor, WebAuthn,
/// secret storage, identity reset, `PATCH /users/me`, profile images, the scene library, friends and blocks,
/// the invite list, account invites, `POST /rooms`, `POST /rooms/{id}/join`, `/auth/connect/*`, reports,
/// the owner routes of `/applications`, `/admin/*` and group DM management.
pub const APP_ROUTES: &[(&str, &str, Access)] = &[
    // Always allowed (§2.4)
    ("GET", "/api/v1/node", Always),
    ("GET", "/api/v1/ws", Always),
    ("GET", "/api/v1/users/me", Always),
    ("GET", "/api/v1/users/{address}/profile", Always),
    ("GET", "/api/v1/rooms", Always),
    ("GET", "/api/v1/rooms/{room_id}", Always),
    ("POST", "/api/v1/rooms/{room_id}/leave", Always),
    ("POST", "/api/v1/federation/token", Always),
    ("GET", "/api/v1/applications/me", Always),
    ("GET", "/api/v1/applications/me/installations", Always),
    ("POST", "/api/v1/applications/me/tokens/rotate", Always),
    // E2EE (§3): identity, the token's device, KeyPackages, claims, the MLS delivery service, backups
    ("PUT", "/api/v1/users/me/identity", Always),
    ("PUT", "/api/v1/users/me/devices/{device_id}/key", Always),
    ("GET", "/api/v1/users/me/devices/{device_id}/key-packages", Always),
    ("POST", "/api/v1/users/me/devices/{device_id}/key-packages", Always),
    ("POST", "/api/v1/users/{username}/key-packages/claim", Always),
    ("POST", "/api/v1/conversations/{conversation_id}/mls/group", Always),
    ("GET", "/api/v1/conversations/{conversation_id}/mls/group-info", Always),
    ("POST", "/api/v1/conversations/{conversation_id}/mls/commits", Always),
    ("GET", "/api/v1/conversations/{conversation_id}/mls/messages", Always),
    ("GET", "/api/v1/mls/welcomes", Always),
    ("DELETE", "/api/v1/mls/welcomes/{welcome_id}", Always),
    ("GET", "/api/v1/conversations/{conversation_id}/mls/pending-removals", Always),
    ("GET", "/api/v1/mls/pending-removals", Always),
    // Inbox keys of write-only webhooks follow the MLS epochs (ENCRYPTION.md §5b).
    ("PUT", "/api/v1/conversations/{conversation_id}/inbox-key", Always),
    ("GET", "/api/v1/users/me/backups", Always),
    ("GET", "/api/v1/users/me/backups/{domain}/{conversation_id}", Always),
    ("PUT", "/api/v1/users/me/backups/{domain}/{conversation_id}", Always),
    // messages:read
    ("GET", "/api/v1/rooms/{room_id}/channels/{channel_id}/messages", Scope("messages:read")),
    ("GET", "/api/v1/conversations/{conversation_id}/messages", Scope("messages:read")),
    ("GET", "/api/v1/rooms/{room_id}/search", Scope("messages:read")),
    ("GET", "/api/v1/rooms/{room_id}/channels/{channel_id}/pins", Scope("messages:read")),
    ("GET", "/api/v1/conversations/{conversation_id}/pins", Scope("messages:read")),
    ("GET", "/api/v1/conversations/{conversation_id}/history-keys", Scope("messages:read")),
    ("DELETE", "/api/v1/conversations/{conversation_id}/history-keys/{share_id}", Scope("messages:read")),
    ("GET", "/api/v1/conversations/{conversation_id}/history-pending", Scope("messages:read")),
    ("GET", "/api/v1/blobs/{blob_id}", Scope("messages:read")),
    ("GET", "/api/v1/conversations", Scope("messages:read")),
    ("GET", "/api/v1/conversations/requests", Scope("messages:read")),
    ("GET", "/api/v1/conversations/{conversation_id}", Scope("messages:read")),
    ("GET", "/api/v1/rooms/{room_id}/emojis", Scope("messages:read")),
    ("GET", "/api/v1/rooms/{room_id}/emojis/{emoji_id}/image", Scope("messages:read")),
    // threads (PROTOCOL.md §7e): reading under messages:read, writing under messages:write
    ("GET", "/api/v1/rooms/{room_id}/channels/{channel_id}/threads", Scope("messages:read")),
    ("GET", "/api/v1/threads/{thread_id}", Scope("messages:read")),
    ("GET", "/api/v1/rooms/{room_id}/followed-threads", Scope("messages:read")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/threads", Scope("messages:write")),
    ("PATCH", "/api/v1/threads/{thread_id}", Scope("messages:write")),
    ("DELETE", "/api/v1/threads/{thread_id}", Scope("messages:write")),
    ("PUT", "/api/v1/threads/{thread_id}/read", Scope("messages:write")),
    ("POST", "/api/v1/threads/{thread_id}/follow", Scope("messages:write")),
    ("DELETE", "/api/v1/threads/{thread_id}/follow", Scope("messages:write")),
    // messages:write
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/messages", Scope("messages:write")),
    ("PATCH", "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}", Scope("messages:write")),
    ("DELETE", "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}", Scope("messages:write")),
    ("POST", "/api/v1/conversations/{conversation_id}/messages", Scope("messages:write")),
    ("PATCH", "/api/v1/conversations/{conversation_id}/messages/{message_id}", Scope("messages:write")),
    ("DELETE", "/api/v1/conversations/{conversation_id}/messages/{message_id}", Scope("messages:write")),
    (
        "PUT",
        "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
        Scope("messages:write"),
    ),
    (
        "DELETE",
        "/api/v1/rooms/{room_id}/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
        Scope("messages:write"),
    ),
    ("PUT", "/api/v1/conversations/{conversation_id}/messages/{message_id}/reactions/{emoji}", Scope("messages:write")),
    (
        "DELETE",
        "/api/v1/conversations/{conversation_id}/messages/{message_id}/reactions/{emoji}",
        Scope("messages:write"),
    ),
    ("PUT", "/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{message_id}", Scope("messages:write")),
    ("DELETE", "/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{message_id}", Scope("messages:write")),
    ("PUT", "/api/v1/conversations/{conversation_id}/pins/{message_id}", Scope("messages:write")),
    ("DELETE", "/api/v1/conversations/{conversation_id}/pins/{message_id}", Scope("messages:write")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/uploads", Scope("messages:write")),
    ("POST", "/api/v1/conversations/{conversation_id}/uploads", Scope("messages:write")),
    ("GET", "/api/v1/conversations/{conversation_id}/upload-policy", Scope("messages:write")),
    ("PUT", "/api/v1/conversations/{conversation_id}/read", Scope("messages:write")),
    // `cursor` needs messages:write, `whiteboard.*` additionally whiteboard (checked by the handler)
    ("POST", "/api/v1/conversations/{conversation_id}/ephemeral", Scope("messages:write")),
    // members:read
    ("GET", "/api/v1/rooms/{room_id}/members", Scope("members:read")),
    ("GET", "/api/v1/presence", Scope("members:read")),
    // moderation
    ("PATCH", "/api/v1/rooms/{room_id}/members/{user_id}", MOD_OR_MANAGE),
    ("DELETE", "/api/v1/rooms/{room_id}/members/{user_id}", Scope("moderation")),
    ("PUT", "/api/v1/rooms/{room_id}/members/{user_id}/timeout", Scope("moderation")),
    ("PATCH", "/api/v1/rooms/{room_id}/members/{user_id}/profile", Scope("moderation")),
    ("GET", "/api/v1/rooms/{room_id}/bans", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/bans", Scope("moderation")),
    ("DELETE", "/api/v1/rooms/{room_id}/bans/{subject}", Scope("moderation")),
    ("GET", "/api/v1/rooms/{room_id}/audit-log", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/moderation/purge", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/mute", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/disconnect", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/move", Scope("moderation")),
    ("POST", "/api/v1/rooms/{room_id}/voice/move-all", Scope("moderation")),
    // rooms:manage
    ("PATCH", "/api/v1/rooms/{room_id}", Scope("rooms:manage")),
    ("PUT", "/api/v1/rooms/{room_id}/icon", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/icon", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/categories", Scope("rooms:manage")),
    ("PATCH", "/api/v1/rooms/{room_id}/categories/{category_id}", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/categories/{category_id}", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/channels", Scope("rooms:manage")),
    ("PATCH", "/api/v1/rooms/{room_id}/channels/{channel_id}", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/channels/{channel_id}", Scope("rooms:manage")),
    ("PUT", "/api/v1/rooms/{room_id}/overrides", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/roles", Scope("rooms:manage")),
    ("PATCH", "/api/v1/rooms/{room_id}/roles/{role_id}", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/roles/{role_id}", Scope("rooms:manage")),
    ("GET", "/api/v1/rooms/{room_id}/invites", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/invites", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/invites/{code}", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/invites/direct", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/emojis", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/emojis/{emoji_id}", Scope("rooms:manage")),
    ("POST", "/api/v1/rooms/{room_id}/soundboard", Scope("rooms:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/soundboard/{sound_id}", Scope("rooms:manage")),
    ("PATCH", "/api/v1/rooms/{room_id}/soundboard/{sound_id}", Scope("rooms:manage")),
    // voice
    ("GET", "/api/v1/rooms/{room_id}/voice", Scope("voice")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/join", Scope("voice")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/leave", Scope("voice")),
    ("PATCH", "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/state", Scope("voice")),
    ("GET", "/api/v1/rooms/{room_id}/soundboard", Scope("voice")),
    ("GET", "/api/v1/rooms/{room_id}/soundboard/{sound_id}/audio", Scope("voice")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/soundboard/play", Scope("voice")),
    ("GET", "/api/v1/conversations/{conversation_id}/call", Scope("voice")),
    ("POST", "/api/v1/conversations/{conversation_id}/call/start", Scope("voice")),
    ("POST", "/api/v1/conversations/{conversation_id}/call/join", Scope("voice")),
    ("POST", "/api/v1/conversations/{conversation_id}/call/leave", Scope("voice")),
    ("POST", "/api/v1/conversations/{conversation_id}/call/decline", Scope("voice")),
    ("PATCH", "/api/v1/conversations/{conversation_id}/call/state", Scope("voice")),
    // whiteboard
    ("GET", "/api/v1/conversations/{conversation_id}/whiteboard", Scope("whiteboard")),
    // presence
    ("GET", "/api/v1/users/me/presence", Scope("presence")),
    ("PUT", "/api/v1/users/me/presence", Scope("presence")),
    ("PUT", "/api/v1/users/me/activity", Scope("presence")),
    ("DELETE", "/api/v1/users/me/activity", Scope("presence")),
    // webhooks:manage (APPLICATIONS.md §6.1)
    ("GET", "/api/v1/rooms/{room_id}/channels/{channel_id}/webhooks", Scope("webhooks:manage")),
    ("POST", "/api/v1/rooms/{room_id}/channels/{channel_id}/webhooks", Scope("webhooks:manage")),
    ("GET", "/api/v1/rooms/{room_id}/webhooks", Scope("webhooks:manage")),
    ("PATCH", "/api/v1/rooms/{room_id}/webhooks/{webhook_id}", Scope("webhooks:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/webhooks/{webhook_id}", Scope("webhooks:manage")),
    ("PUT", "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/avatar", Scope("webhooks:manage")),
    ("DELETE", "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/avatar", Scope("webhooks:manage")),
    ("POST", "/api/v1/rooms/{room_id}/webhooks/{webhook_id}/reset", Scope("webhooks:manage")),
    // commands (APPLICATIONS.md §5): the bot's own definitions, callbacks and follow-ups
    ("GET", "/api/v1/applications/me/commands", Scope("commands")),
    ("PUT", "/api/v1/applications/me/commands", Scope("commands")),
    ("POST", "/api/v1/interactions/{interaction_id}/callback", Scope("commands")),
    ("POST", "/api/v1/interactions/{interaction_id}/messages", Scope("commands")),
    // dms: 1:1 DMs only (`kind = group` and group membership are refused by the handlers)
    ("POST", "/api/v1/conversations", Scope("dms")),
    ("POST", "/api/v1/conversations/{conversation_id}/accept", Scope("dms")),
    ("POST", "/api/v1/conversations/{conversation_id}/decline", Scope("dms")),
];

/// The access rule of a route template for app tokens, `None` if bots may not use it.
pub fn route_access(method: &Method, path: &str) -> Option<Access> {
    APP_ROUTES.iter().find(|(m, p, _)| *m == method.as_str() && *p == path).map(|(_, _, a)| *a)
}

/// Checks a bot's request against [`APP_ROUTES`] and its effective scopes (§2.3 step 4).
pub fn check_route(scopes: &[String], method: &Method, path: Option<&str>) -> Result<(), ApiError> {
    let has = |s: &str| scopes.iter().any(|x| x == s);
    match path.and_then(|p| route_access(method, p)) {
        None => Err(bot_forbidden()),
        Some(Always) => Ok(()),
        Some(Scope(s)) if has(s) => Ok(()),
        Some(Scope(s)) => Err(scope_missing(s)),
        Some(AnyScope(list)) if list.iter().any(|s| has(s)) => Ok(()),
        Some(AnyScope(list)) => Err(scope_missing(list[0])),
    }
}

/// `403 app.scope_missing` unless the bot's token has `scope` (handlers that check content, e.g. the
/// ephemeral type). Users always pass.
pub fn require_scope(auth: &AuthUser, scope: &str) -> Result<(), ApiError> {
    match &auth.app {
        Some(app) if !app.scopes.iter().any(|s| s == scope) => Err(scope_missing(scope)),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------- events (§2.6)

/// Is an event of type `kind` delivered to a bot with these scopes? Unknown types are dropped (fail
/// closed); an event a scope does not cover is dropped, never truncated.
pub fn event_allowed(kind: &str, data: &Value, scopes: &[String]) -> bool {
    let has = |s: &str| scopes.iter().any(|x| x == s);
    let prefix = kind.split('.').next().unwrap_or(kind);
    match (prefix, kind) {
        ("room" | "channel" | "category" | "role" | "mls" | "application", _)
        | (_, "override.update" | "identity.changed" | "identity.rotated" | "devices.changed")
        | (_, crate::federation::inbox::SESSION_REVOKED_EVENT) => !matches!(kind, "room.invite"),
        ("message" | "reaction" | "pin" | "emoji" | "conversation" | "thread", _) | (_, "typing" | "read.update") => {
            kind != "conversation.invite" && has("messages:read")
        }
        ("member" | "presence", _) | (_, "user.update") => has("members:read"),
        ("voice" | "call" | "soundboard", _) => has("voice"),
        ("whiteboard", _) => has("whiteboard"),
        ("command" | "commands", _) => has("commands"),
        (_, "ephemeral") => {
            let typ = data.get("type").and_then(Value::as_str).unwrap_or("");
            if typ.starts_with("whiteboard.") { has("whiteboard") } else { has("messages:read") }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------- tokens (§2.1)

/// Claims of an app token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    /// The bot device bound to the token.
    pub dev: String,
    /// Application ULID.
    pub app: String,
    /// The owner's address.
    pub owner: String,
    /// The token's scopes.
    pub scp: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AppExtra {
    dev: String,
    app: String,
    #[allow(dead_code)]
    owner: String,
    scp: Vec<String>,
}

/// A freshly signed app token.
pub struct IssuedToken {
    pub secret: String,
    pub jti: String,
    pub hash: String,
    pub expires_at: String,
}

/// Signs an app token for `device_id` valid for `days` days.
pub fn issue_token(
    state: &AppState,
    app: &ApplicationRow,
    owner_address: &str,
    device_id: &str,
    scopes: &[String],
    days: i64,
) -> Result<IssuedToken, ApiError> {
    let key = state.signing_key();
    let now = jwt::now_unix();
    let exp = now + days * 86_400;
    let jti = util::ulid();
    let claims = AppClaims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: app.bot_user_id.clone(),
            aud: state.config.domain.clone(),
            exp,
            iat: now,
            jti: jti.clone(),
            typ: "app".into(),
        },
        dev: device_id.to_string(),
        app: app.id.clone(),
        owner: owner_address.to_string(),
        scp: scopes.to_vec(),
    };
    let secret = jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))?;
    let expires_at = chrono::DateTime::from_timestamp(exp, 0)
        .map(util::format_time)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("token expiry out of range")))?;
    Ok(IssuedToken { hash: util::sha256_b64(&secret), secret, jti, expires_at })
}

/// The application context of a bot's request.
#[derive(Debug, Clone)]
pub struct AppPrincipal {
    /// Local application ULID, or the reference `<domain>/<ULID>` of a remote bot.
    pub application_id: String,
    /// Local tokens only.
    pub token_id: Option<String>,
    /// Effective scopes: token ∩ application (local) or the federation token's scopes (remote).
    pub scopes: Vec<String>,
    /// `exp` of the app token (local tokens only), for the WebSocket.
    pub expires_at: Option<i64>,
    /// `exp − iat` of the app token (local tokens only): rotation keeps the lifetime.
    pub lifetime_secs: Option<i64>,
}

/// Effective scopes in canonical order: `token ∩ application`.
pub fn intersect(token: &[String], app: &[String]) -> Vec<String> {
    permissions::SCOPES
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| token.iter().any(|t| t == s) && app.iter().any(|a| a == s))
        .map(String::from)
        .collect()
}

/// Validates a scope list (`400 app.scope_invalid`) and returns it in canonical order without duplicates.
pub fn parse_scopes(scopes: &[String]) -> Result<Vec<String>, ApiError> {
    if let Some(bad) = scopes.iter().find(|s| !permissions::is_scope(s)) {
        return Err(ApiError::BadRequest { code: "app.scope_invalid", detail: format!("Unknown scope: {bad:.64}") });
    }
    Ok(intersect(scopes, &permissions::all_scopes()))
}

/// Why a bot may not act now (§2.3 step 3): `disabled` (application or bot), `owner_disabled`, `blocked`.
pub async fn disabled_reason(
    state: &AppState,
    app: &ApplicationRow,
    bot: &UserRow,
) -> Result<Option<&'static str>, ApiError> {
    if app.disabled_at.is_some() || bot.disabled_at.is_some() {
        return Ok(Some("disabled"));
    }
    match store::users::by_id(&state.db, &app.owner_id).await? {
        Some(owner) if owner.disabled_at.is_none() => {}
        _ => return Ok(Some("owner_disabled")),
    }
    if store::applications::is_blocked(&state.db, &bot.address()).await? {
        return Ok(Some("blocked"));
    }
    Ok(None)
}

/// Authenticates an app token (§2.3 steps 1–3 and 5; step 4, the route, is checked by the extractor).
pub async fn authenticate(state: &AppState, token: &str) -> Result<AuthUser, ApiError> {
    use subtle::ConstantTimeEq;
    let invalid = || ApiError::Unauthorized { code: "auth.token_invalid" };
    let kid = jwt::peek_kid(token).map_err(|_| invalid())?;
    let key = state.keys.iter().find(|k| k.kid == kid).ok_or_else(invalid)?;
    let expected = Expected { iss: state.config.domain.clone(), aud: state.config.domain.clone(), typ: "app" };
    let (std, extra): (StandardClaims, AppExtra) = match jwt::verify(token, &key.verifying(), &expected) {
        Ok(v) => v,
        Err(jwt::JwtError::Expired) => return Err(ApiError::Unauthorized { code: "auth.token_expired" }),
        Err(_) => return Err(invalid()),
    };
    // The node never issues longer tokens; a longer one was not made by this node's rules.
    if std.exp - std.iat > i64::from(state.config.app_token_max_days) * 86_400 + 60 {
        return Err(invalid());
    }
    let row = store::applications::token_by_jti(&state.db, &std.jti).await?.ok_or_else(invalid)?;
    let hash = util::sha256_b64(token);
    let stored = if row.jti == std.jti { Some(row.token_hash.as_str()) } else { row.prev_token_hash.as_deref() };
    let matches = stored.is_some_and(|h| bool::from(h.as_bytes().ct_eq(hash.as_bytes())));
    if !matches || row.application_id != extra.app || row.device_id != extra.dev {
        return Err(invalid());
    }
    let app = store::applications::by_id(&state.db, &row.application_id).await?.ok_or_else(invalid)?;
    let mut user = store::users::by_id(&state.db, &std.sub).await?.ok_or_else(invalid)?;
    if app.bot_user_id != user.id || user.kind != "bot" || user.domain != state.config.domain {
        return Err(invalid());
    }
    if let Some(reason) = disabled_reason(state, &app, &user).await? {
        return Err(disabled(reason));
    }
    state.app_request_limiter.check_all(&[format!("app:{}", app.id)]).await?;
    store::applications::touch_token(&state.db, &row.id).await?;
    let scopes = intersect(&extra.scp, &intersect(&row.scopes(), &app.scopes()));
    user.app_scopes = Some(scopes.clone());
    Ok(AuthUser {
        user,
        device_id: row.device_id,
        home_device_id: None,
        app: Some(AppPrincipal {
            application_id: app.id,
            token_id: Some(row.id),
            scopes,
            expires_at: Some(std.exp),
            lifetime_secs: Some(std.exp - std.iat),
        }),
    })
}

/// The application context of a remote bot's federated session (§2.8): the scopes stored with the
/// session (none stored = a token of an older home node = all scopes). Refused when this node does not
/// accept remote bots or has blocked this one.
pub async fn remote_principal(state: &AppState, user: &mut UserRow, device_id: &str) -> Result<AppPrincipal, ApiError> {
    if !state.config.federation_remote_bots {
        return Err(crate::federation::remote::bots_refused());
    }
    if store::applications::is_blocked(&state.db, &user.address()).await? {
        return Err(ApiError::Forbidden { code: "app.blocked", detail: "This application is blocked here".into() });
    }
    let (app_ref, scopes) = store::applications::remote_session_app(&state.db, &user.id, device_id)
        .await?
        .ok_or(ApiError::Unauthorized { code: "auth.token_invalid" })?;
    let scopes = match scopes {
        Some(json) => parse_scopes(&serde_json::from_str::<Vec<String>>(&json).unwrap_or_default()).unwrap_or_default(),
        None => permissions::all_scopes(),
    };
    state.app_request_limiter.check_all(&[format!("app:{}", user.id)]).await?;
    user.app_scopes = Some(scopes.clone());
    Ok(AppPrincipal {
        application_id: app_ref.unwrap_or_default(),
        token_id: None,
        scopes,
        expires_at: None,
        lifetime_secs: None,
    })
}

// ---------------------------------------------------------------- WebSockets per token (§2.6)

/// The open connections of one token, oldest first: (connection id, "replaced" signal).
type TokenConnections = VecDeque<(u64, Arc<tokio::sync::Notify>)>;

/// Open WebSockets per app token; the third one closes the oldest. With several instances the registrations are
/// also kept in the shared cache (`appconn:<token>`, field `<instance>/<id>`, value the registration time), so
/// the limit holds for the node as a whole: the oldest connection is closed wherever it is.
#[derive(Default)]
pub struct Connections {
    open: Mutex<HashMap<String, TokenConnections>>,
    next: AtomicU64,
    cluster: Option<Arc<crate::cache::Cluster>>,
}

/// Registrations in the shared cache outlive their connections at most this long (a crashed instance).
const SHARED_REGISTRATION_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Keeps a connection registered while it lives.
pub struct ConnectionGuard {
    connections: Arc<Connections>,
    token_id: String,
    id: u64,
    /// Notified when a newer connection of the same token replaced this one.
    pub replaced: Arc<tokio::sync::Notify>,
}

impl Connections {
    pub fn new(cluster: &Arc<crate::cache::Cluster>) -> Self {
        Self { cluster: cluster.is_shared().then(|| cluster.clone()), ..Self::default() }
    }

    /// Closes connection `id` of `token_id` on this instance (replaced on another instance).
    pub fn replace_local(&self, token_id: &str, id: u64) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(queue) = open.get_mut(token_id)
            && let Some(pos) = queue.iter().position(|(i, _)| *i == id)
            && let Some((_, signal)) = queue.remove(pos)
        {
            signal.notify_one();
        }
    }

    /// Registers the connection in the shared cache and closes the oldest ones of the node beyond the limit.
    async fn register_shared(cluster: Arc<crate::cache::Cluster>, this: Arc<Self>, token_id: String, id: u64) {
        let key = cluster.key(&format!("appconn:{token_id}"));
        let me = format!("{}/{id}", cluster.instance_id);
        let cache = cluster.cache();
        if let Err(e) = cache.hash_put(&key, &me, crate::cache::now_ms().to_string(), SHARED_REGISTRATION_TTL).await {
            tracing::warn!(error = %e, "app token connection not registered in the cache (limit per instance only)");
            return;
        }
        let Ok(all) = cache.hash_all(&key).await else { return };
        let live: std::collections::HashSet<String> =
            cluster.peers().into_iter().chain([cluster.instance_id.clone()]).collect();
        let mut entries: Vec<(u64, String)> = Vec::new();
        for (field, at) in all {
            let instance = field.split_once('/').map(|(i, _)| i).unwrap_or("");
            if live.contains(instance) {
                entries.push((at.parse().unwrap_or(0), field));
            } else {
                // A connection of an instance that is gone.
                let _ = cache.hash_remove(&key, &field).await;
            }
        }
        entries.sort();
        let excess = entries.len().saturating_sub(MAX_CONNECTIONS_PER_TOKEN);
        for (_, field) in entries.into_iter().take(excess) {
            let _ = cache.hash_remove(&key, &field).await;
            let Some((instance, conn)) = field.split_once('/') else { continue };
            let Ok(conn) = conn.parse::<u64>() else { continue };
            if instance == cluster.instance_id {
                this.replace_local(&token_id, conn);
            } else {
                cluster.send(crate::cache::Message::AppConnReplaced {
                    instance: instance.to_string(),
                    token: token_id.clone(),
                    id: conn,
                });
            }
        }
    }

    /// Registers a connection of `token_id`; beyond [`MAX_CONNECTIONS_PER_TOKEN`] the oldest is told to
    /// close with [`CLOSE_REPLACED`].
    pub fn register(self: &Arc<Self>, token_id: &str) -> ConnectionGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if let Some(cluster) = &self.cluster
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(Self::register_shared(cluster.clone(), self.clone(), token_id.to_string(), id));
        }
        let replaced = Arc::new(tokio::sync::Notify::new());
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let queue = open.entry(token_id.to_string()).or_default();
        queue.push_back((id, replaced.clone()));
        while queue.len() > MAX_CONNECTIONS_PER_TOKEN {
            if let Some((_, oldest)) = queue.pop_front() {
                // A stored permit reaches the connection even if it is not waiting right now.
                oldest.notify_one();
            }
        }
        ConnectionGuard { connections: self.clone(), token_id: token_id.to_string(), id, replaced }
    }

    /// Open connections of a token (tests, diagnostics).
    pub fn count(&self, token_id: &str) -> usize {
        self.open.lock().unwrap_or_else(|e| e.into_inner()).get(token_id).map_or(0, VecDeque::len)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(cluster) = &self.connections.cluster
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let (cluster, key) = (cluster.clone(), format!("appconn:{}", self.token_id));
            let field = format!("{}/{}", cluster.instance_id, self.id);
            runtime.spawn(async move {
                let _ = cluster.cache().hash_remove(&cluster.key(&key), &field).await;
            });
        }
        let mut open = self.connections.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(queue) = open.get_mut(&self.token_id) {
            queue.retain(|(id, _)| *id != self.id);
            if queue.is_empty() {
                open.remove(&self.token_id);
            }
        }
    }
}

// ---------------------------------------------------------------- cascades (§1.7)

/// Closes every WebSocket of the given bot devices (code 4001).
pub fn close_devices(state: &AppState, devices: Vec<String>) {
    if !devices.is_empty() {
        state.hub.devices(devices, crate::federation::inbox::SESSION_REVOKED_EVENT, json!({}));
    }
}

/// Closes every WebSocket of a bot.
pub async fn close_bot(state: &AppState, bot_user_id: &str) -> Result<(), ApiError> {
    let devices = store::users::devices_of(&state.db, bot_user_id).await?.into_iter().map(|d| d.id).collect();
    close_devices(state, devices);
    Ok(())
}

/// Removes a bot from a room like a kicked or banned member (`member.leave`, `mls.remove_needed`, voice) and
/// uninstalls it (`crate::installations::uninstalled`). `reason` goes into the event and the audit entry
/// (`no_bots`, `owner_banned`, `deleted`, …).
pub async fn remove_from_room(state: &AppState, room: &Room, bot: &UserRow, reason: &str) -> Result<bool, ApiError> {
    crate::installations::remove_member(state, room, bot, reason, None).await
}

/// A room or node ban of `subject` (an address or a domain): every bot whose owner it names leaves the
/// room (`room = Some`) or every room of this node (`None`) (§1.7). Returns the number of bots removed.
pub async fn ban_cascade(state: &AppState, room_id: Option<&str>, subject: &str) -> Result<usize, ApiError> {
    let mut removed = 0;
    for bot_id in store::applications::bots_of_owner_subject(&state.db, subject).await? {
        let Some(bot) = store::users::by_id(&state.db, &bot_id).await? else { continue };
        let rooms = match room_id {
            Some(r) => vec![r.to_string()],
            None => store::rooms::room_ids_of_user(&state.db, &bot.id).await?,
        };
        for rid in rooms {
            if let Some(room) = store::rooms::room_by_id(&state.db, &rid).await?
                && remove_from_room(state, &room, &bot, "owner_banned").await?
            {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// The owner was disabled by a node admin: every bot's WebSockets close and its federated sessions end
/// (tokens then fail with `403 app.disabled`, reason `owner_disabled`).
pub async fn owner_disabled(state: &AppState, owner_id: &str) -> Result<(), ApiError> {
    for app in store::applications::of_owner(&state.db, owner_id).await? {
        close_bot(state, &app.bot_user_id).await?;
        if let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? {
            crate::federation::remote::revoke_sessions(state, &bot, None).await?;
        }
    }
    Ok(())
}

/// Deletes an application (§1.7): tokens and devices, memberships, federated sessions; the bot stays as a
/// disabled tombstone. `actor` is the owner or a node admin.
pub async fn delete_application(state: &AppState, app: &ApplicationRow, actor: &UserRow) -> Result<(), ApiError> {
    let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { return Ok(()) };
    // Other nodes uninstall the bot and refuse it (APPLICATIONS.md §4.5); the index goes with the row.
    crate::installations::changed(state, app, true).await;
    crate::installations::remove_everywhere(state, &bot, "deleted", Some(&actor.id)).await?;
    let devices: Vec<String> = store::users::devices_of(&state.db, &bot.id).await?.into_iter().map(|d| d.id).collect();
    for device in &devices {
        crate::e2ee::device_removed(state, &bot, device).await?;
    }
    close_devices(state, devices);
    crate::federation::remote::revoke_sessions(state, &bot, None).await?;
    crate::federation::remote::devices_changed(state, &bot).await?;
    store::applications::delete(&state.db, app).await?;
    store::commands::replace_set(&state.db, &app_ref(state, &app.id), &[]).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&actor.id),
        "app.delete",
        &bot.address(),
        "",
        json!({ "application": app_ref(state, &app.id), "name": app.name }),
    )
    .await?;
    tracing::info!(application = app.id, bot = bot.address(), "application deleted");
    Ok(())
}

/// `application.token_expiring` goes out this many days before a token expires (smallest first, so a
/// token found late gets only the nearest notice).
pub const TOKEN_EXPIRY_NOTICE_DAYS: [i64; 2] = [1, 7];

/// Housekeeping (§2.2): `application.token_expiring { application_id, token_id, expires_at, days }` to the
/// owner's and the bot's connections, once per threshold and secret (a reset or rotation starts over).
/// Returns the number of notices.
pub async fn notify_expiring_tokens(state: &AppState, now: chrono::DateTime<chrono::Utc>) -> Result<usize, ApiError> {
    let mut sent = 0;
    for days in TOKEN_EXPIRY_NOTICE_DAYS {
        let before = util::format_time(now + chrono::Duration::days(days));
        for t in store::installations::expiring_tokens(&state.db, &before, days).await? {
            let Some(app) = store::applications::by_id(&state.db, &t.application_id).await? else { continue };
            state.hub.users(
                vec![app.owner_id.clone(), app.bot_user_id.clone()],
                "application.token_expiring",
                json!({ "application_id": app.id, "token_id": t.id, "expires_at": t.expires_at, "days": days }),
            );
            store::installations::mark_notified(&state.db, &t.id, days).await?;
            mail_token_expiry(state, &app, &t.expires_at, days).await?;
            sent += 1;
        }
    }
    Ok(sent)
}

/// The e-mail of a token expiry notice (§2.2) to the application's owner, in the owner's language: only to a local
/// owner with a confirmed address (an unconfirmed one may belong to someone else).
async fn mail_token_expiry(
    state: &AppState,
    app: &store::applications::ApplicationRow,
    expires_at: &str,
    days: i64,
) -> Result<(), ApiError> {
    let Some(owner) = store::users::by_id(&state.db, &app.owner_id).await? else { return Ok(()) };
    let Some(email) = owner.email.as_deref().filter(|_| owner.email_verified_at.is_some()) else { return Ok(()) };
    if owner.domain != state.config.domain || owner.disabled_at.is_some() {
        return Ok(());
    }
    let locale = store::users::locale(&state.db, &owner.id).await?;
    let expires = util::parse_time(expires_at)
        .map_or_else(|| expires_at.to_string(), |t| t.format("%Y-%m-%d %H:%M UTC").to_string());
    let link = format!("{}/settings/applications", state.mailer.public_url());
    let template = if days <= 1 { "app_token_expiring_day" } else { "app_token_expiring_week" };
    let vars = [
        ("name", owner.display_name.as_str()),
        ("application", app.name.as_str()),
        ("expires_at", &expires),
        ("link", &link),
    ];
    state.mailer.send_template(email, locale.as_deref(), template, &vars).await;
    Ok(())
}

/// The application reference `<domain>/<ULID>` (§0).
pub fn app_ref(state: &AppState, id: &str) -> String {
    format!("{}/{id}", state.config.domain)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn s(list: &[&str]) -> Vec<String> {
        list.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn route_table_fails_closed_and_checks_scopes() {
        let read = s(&["messages:read"]);
        let get = Method::GET;
        assert!(check_route(&read, &get, Some("/api/v1/rooms/{room_id}/channels/{channel_id}/messages")).is_ok());
        let err = check_route(&read, &Method::POST, Some("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"))
            .unwrap_err();
        assert_eq!(err.code(), "app.scope_missing");
        for (m, p) in [
            (Method::POST, "/api/v1/rooms"),
            (Method::POST, "/api/v1/rooms/{room_id}/join"),
            (Method::PATCH, "/api/v1/users/me"),
            (Method::POST, "/api/v1/users/me/password"),
            (Method::POST, "/api/v1/users/me/identity/reset"),
            (Method::GET, "/api/v1/users/me/secret-storage"),
            (Method::GET, "/api/v1/users/me/friends"),
            (Method::GET, "/api/v1/users/me/invites"),
            (Method::GET, "/api/v1/admin/users"),
            (Method::POST, "/api/v1/applications"),
            (Method::POST, "/api/v1/conversations/{conversation_id}/members"),
            (Method::DELETE, "/api/v1/rooms/{room_id}"),
            (Method::GET, "/api/v1/some/future/route"),
        ] {
            assert_eq!(
                check_route(&permissions::all_scopes(), &m, Some(p)).unwrap_err().code(),
                "app.bot_forbidden",
                "{m} {p}"
            );
        }
        assert_eq!(check_route(&read, &get, None).unwrap_err().code(), "app.bot_forbidden", "no matched route");
        assert!(check_route(&[], &get, Some("/api/v1/users/me")).is_ok());
        assert!(
            check_route(&s(&["rooms:manage"]), &Method::PATCH, Some("/api/v1/rooms/{room_id}/members/{user_id}"))
                .is_ok()
        );
    }

    #[test]
    fn every_scope_in_the_table_exists() {
        for (m, p, a) in APP_ROUTES {
            match a {
                Scope(s) => assert!(permissions::is_scope(s), "{m} {p}"),
                AnyScope(list) => assert!(list.iter().all(|s| permissions::is_scope(s)), "{m} {p}"),
                Always => {}
            }
            assert!(p.starts_with("/api/v1/"), "{p}");
        }
    }

    #[test]
    fn events_follow_scopes() {
        let none: Vec<String> = Vec::new();
        let d = json!({});
        assert!(event_allowed("room.update", &d, &none));
        assert!(event_allowed("mls.remove_needed", &d, &none));
        assert!(event_allowed("session.revoked", &d, &none));
        assert!(!event_allowed("message.create", &d, &none));
        assert!(event_allowed("message.create", &d, &s(&["messages:read"])));
        assert!(!event_allowed("thread.update", &d, &none));
        assert!(event_allowed("thread.update", &d, &s(&["messages:read"])));
        assert!(!event_allowed("thread.read", &d, &s(&["messages:write"])));
        assert!(!event_allowed("member.join", &d, &s(&["messages:read"])));
        assert!(event_allowed("member.join", &d, &s(&["members:read"])));
        assert!(!event_allowed("friend.request", &d, &permissions::all_scopes()), "unknown to bots: dropped");
        assert!(!event_allowed("room.invite", &d, &permissions::all_scopes()));
        assert!(!event_allowed("notifications.update", &d, &permissions::all_scopes()));
        let wb = json!({ "type": "whiteboard.update" });
        assert!(!event_allowed("ephemeral", &wb, &s(&["messages:read"])));
        assert!(event_allowed("ephemeral", &wb, &s(&["whiteboard"])));
        assert!(event_allowed("ephemeral", &json!({ "type": "cursor" }), &s(&["messages:read"])));
        assert!(event_allowed("command.invoke", &d, &s(&["commands"])));
        assert!(event_allowed("commands.update", &d, &s(&["commands"])));
        assert!(!event_allowed("command.invoke", &d, &s(&["messages:read", "messages:write"])));
        assert!(!event_allowed("interaction.reply", &d, &permissions::all_scopes()), "only for invokers");
    }

    #[test]
    fn scope_lists_are_validated_and_canonical() {
        assert_eq!(parse_scopes(&s(&["dms", "messages:read", "dms"])).unwrap(), s(&["messages:read", "dms"]));
        assert_eq!(parse_scopes(&s(&["admin"])).unwrap_err().code(), "app.scope_invalid");
        assert_eq!(intersect(&s(&["voice", "dms"]), &s(&["dms"])), s(&["dms"]));
    }

    #[tokio::test]
    async fn a_third_connection_replaces_the_oldest() {
        let conns = Arc::new(Connections::default());
        let first = conns.register("t1");
        let second = conns.register("t1");
        let other = conns.register("t2");
        assert_eq!(conns.count("t1"), 2);
        let third = conns.register("t1");
        assert_eq!(conns.count("t1"), 2);
        // The oldest got a permit, the others did not.
        tokio::time::timeout(std::time::Duration::from_millis(100), first.replaced.notified()).await.unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), second.replaced.notified()).await.is_err());
        drop((first, second, third));
        assert_eq!(conns.count("t1"), 0);
        assert_eq!(conns.count("t2"), 1);
        drop(other);
    }
}
