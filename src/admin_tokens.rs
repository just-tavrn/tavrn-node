// SPDX-License-Identifier: AGPL-3.0-only
//! Admin API tokens (`protocol/ENTITLEMENTS.md` §5): named bearer tokens of node admins
//! for the `/api/v1/admin/*` routes only, so that an operator's billing or subscription system can manage
//! entitlements without a user session.
//!
//! Format `tavrn_adm_<id>.<secret>` (id = ULID, secret = 32 random bytes base64url). Only the SHA-256 of the
//! whole token is stored and compared in constant time. A token acts with the rights of its creator, who
//! must still be an enabled node admin; it is valid only on the routes its scopes cover (fail closed: a
//! route not in [`required_scope`] is refused), never outside `/api/v1/admin/`, never on the WebSocket.
//! Every call is audit-logged with the token's name.

use axum::http::{Method, request::Parts};
use subtle::ConstantTimeEq;

use crate::{app::AppState, auth::AuthUser, error::ApiError, store, util};

pub const PREFIX: &str = "tavrn_adm_";

pub const SCOPE_ENTITLEMENTS: &str = "entitlements";
pub const SCOPE_USERS_READ: &str = "users:read";
pub const SCOPE_USERS_WRITE: &str = "users:write";
pub const SCOPE_INVITES: &str = "invites";
pub const SCOPES: &[&str] = &[SCOPE_ENTITLEMENTS, SCOPE_USERS_READ, SCOPE_USERS_WRITE, SCOPE_INVITES];

pub fn is_admin_token(token: &str) -> bool {
    token.starts_with(PREFIX)
}

/// A new token for the row `id`: the secret shown once and the hash to store.
pub fn generate(id: &str) -> (String, String) {
    let secret = format!("{PREFIX}{id}.{}", util::random_token(32));
    let hash = util::sha256_b64(&secret);
    (secret, hash)
}

/// The row id named by a token (`None` for anything not shaped like one).
pub fn parse_id(token: &str) -> Option<&str> {
    let (id, secret) = token.strip_prefix(PREFIX)?.split_once('.')?;
    (util::is_ulid(id) && !secret.is_empty() && secret.len() <= 64).then_some(id)
}

/// The scope a route needs (`method`, matched path with the `/api/v1` prefix); `None` = not open to tokens.
pub fn required_scope(method: &Method, path: &str) -> Option<&'static str> {
    let read = *method == Method::GET;
    match path {
        p if p.starts_with("/api/v1/admin/entitlements/") => Some(SCOPE_ENTITLEMENTS),
        "/api/v1/admin/users" if read => Some(SCOPE_USERS_READ),
        "/api/v1/admin/users/{user_id}" if *method == Method::PATCH => Some(SCOPE_USERS_WRITE),
        "/api/v1/admin/invites" if read || *method == Method::POST => Some(SCOPE_INVITES),
        "/api/v1/admin/invites/{code}" if *method == Method::DELETE => Some(SCOPE_INVITES),
        _ => None,
    }
}

fn invalid(code: &'static str) -> ApiError {
    ApiError::Unauthorized { code }
}

/// Authenticates an admin token for the current request (called by the `NodeAdmin` extractor). Returns the
/// creator as the acting admin (`device_id` = `admin-token:<id>`).
pub async fn authenticate(state: &AppState, token: &str, parts: &Parts) -> Result<AuthUser, ApiError> {
    let path = parts.extensions.get::<axum::extract::MatchedPath>().map(axum::extract::MatchedPath::as_str);
    let Some(path) = path.filter(|p| p.starts_with("/api/v1/admin/")) else {
        return Err(invalid("auth.admin_token_not_allowed"));
    };
    let id = parse_id(token).ok_or_else(|| invalid("auth.token_invalid"))?;
    let row = store::entitlements::admin_token(&state.db, id).await?;
    let hash = util::sha256_b64(token);
    // Compared in constant time; a missing row compares against a dummy so both paths cost the same.
    let stored = row.as_ref().map_or("", |r| r.token_hash.as_str());
    let matches = bool::from(stored.as_bytes().ct_eq(hash.as_bytes()));
    let Some(row) = row.filter(|_| matches) else { return Err(invalid("auth.token_invalid")) };
    if row.expires_at.as_deref().is_some_and(|e| e <= util::now().as_str()) {
        return Err(invalid("auth.token_expired"));
    }
    let user = store::users::by_id(&state.db, &row.created_by)
        .await?
        .filter(|u| u.domain == state.config.domain && u.disabled_at.is_none() && u.is_node_admin())
        .ok_or_else(|| ApiError::Forbidden {
            code: "auth.node_admin_required",
            detail: "The creator of this token is no longer a node admin".into(),
        })?;
    state.admin_limiter.check_all(&[format!("admin-token:{}", row.id)])?;
    let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
    let needed = required_scope(&parts.method, path).ok_or_else(|| ApiError::Forbidden {
        code: "admin_token.route_forbidden",
        detail: "Admin tokens cannot call this route".into(),
    })?;
    if !scopes.iter().any(|s| s == needed) {
        return Err(ApiError::ForbiddenMeta {
            code: "admin_token.scope_missing",
            detail: format!("The token lacks the scope {needed}"),
            meta: serde_json::json!({ "scope": needed }),
        });
    }
    store::entitlements::touch_admin_token(&state.db, &row.id).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&user.id),
        "admin.token_call",
        parts.uri.path(),
        &row.name,
        serde_json::json!({ "token_id": row.id, "token_name": row.name, "method": parts.method.as_str(), "route": path }),
    )
    .await?;
    Ok(AuthUser { user, device_id: format!("admin-token:{}", row.id), home_device_id: None, app: None })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn tokens_have_the_prefix_and_parse() {
        let id = util::ulid();
        let (secret, hash) = generate(&id);
        assert!(is_admin_token(&secret));
        assert_eq!(parse_id(&secret), Some(id.as_str()));
        assert_eq!(hash, util::sha256_b64(&secret));
        assert!(!hash.contains(&secret[PREFIX.len()..]), "the hash does not contain the secret");
        assert_eq!(parse_id("tavrn_adm_nope.x"), None);
        assert_eq!(parse_id(&format!("{PREFIX}{id}")), None);
        assert_eq!(parse_id(&format!("{PREFIX}{id}.")), None);
        assert_eq!(parse_id("eyJhbGciOi.x.y"), None);
    }

    #[test]
    fn scopes_cover_only_listed_routes() {
        assert_eq!(required_scope(&Method::GET, "/api/v1/admin/entitlements/plans"), Some(SCOPE_ENTITLEMENTS));
        assert_eq!(
            required_scope(&Method::DELETE, "/api/v1/admin/entitlements/grants/{grant_id}"),
            Some(SCOPE_ENTITLEMENTS)
        );
        assert_eq!(required_scope(&Method::GET, "/api/v1/admin/users"), Some(SCOPE_USERS_READ));
        assert_eq!(required_scope(&Method::PATCH, "/api/v1/admin/users/{user_id}"), Some(SCOPE_USERS_WRITE));
        assert_eq!(required_scope(&Method::POST, "/api/v1/admin/invites"), Some(SCOPE_INVITES));
        assert_eq!(required_scope(&Method::DELETE, "/api/v1/admin/invites/{code}"), Some(SCOPE_INVITES));
        // Closed: token management, purges, second-factor resets, bans, federation, SSO, overview, audit log.
        for (m, p) in [
            (Method::POST, "/api/v1/admin/tokens"),
            (Method::GET, "/api/v1/admin/tokens"),
            (Method::POST, "/api/v1/admin/users/{user_id}/purge"),
            (Method::POST, "/api/v1/admin/users/{user_id}/second-factor/reset"),
            (Method::POST, "/api/v1/admin/bans"),
            (Method::GET, "/api/v1/admin/overview"),
            (Method::GET, "/api/v1/admin/audit-log"),
            (Method::PUT, "/api/v1/admin/sso/group-map"),
            (Method::GET, "/api/v1/rooms"),
        ] {
            assert_eq!(required_scope(&m, p), None, "{m} {p}");
        }
    }
}
