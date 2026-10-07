// SPDX-License-Identifier: AGPL-3.0-only
//! Accounts behind SSO logins (APPLICATIONS.md §8.3–§8.6): resolving a verified identity to an account,
//! provisioning on the first login, linking, the session with its hard end, and the profile update.
//!
//! The node never links by email or username: an unknown identity always gets a new account (or
//! `sso.not_provisioned`), whatever claims it carries, because whoever controls a provider account with a
//! matching claim would otherwise take over a local account.

use serde_json::Value;

use crate::{
    app::AppState,
    auth,
    config::EmailMode,
    error::ApiError,
    models::UserRow,
    oidc::{Oidc, VerifiedIdentity},
    routes::auth::{AuthResponse, SessionStatus},
    store, util,
};

/// Attempts to find a free username before giving up (`-2` … `-999`, then random suffixes).
const SUFFIX_ATTEMPTS: u32 = 1000;

/// A username for a new account from the username claim: the grammar of PROTOCOL.md §1 (2–32 characters
/// of `[a-z0-9_.-]`, starting with a letter or digit). The local part of an email-like value is used;
/// other characters become `-`; too short values fall back to `user`.
pub fn sanitize_username(claim: &str) -> String {
    let local = claim.split('@').next().unwrap_or("");
    let mapped: String = local
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') { c } else { '-' })
        .collect();
    let trimmed = mapped.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    let mut name: String = trimmed.chars().take(32).collect();
    while name.ends_with('-') {
        name.pop();
    }
    if name.len() < 2 { "user".into() } else { name }
}

/// `base`, then `base-2`, `base-3`, …, each at most 32 characters.
pub fn candidate(base: &str, attempt: u32) -> String {
    if attempt <= 1 {
        return base.to_string();
    }
    let suffix = format!("-{attempt}");
    let keep = 32usize.saturating_sub(suffix.len());
    let head: String = base.chars().take(keep).collect();
    format!("{}{suffix}", head.trim_end_matches(['-', '.', '_']))
}

/// A display name from the claim: one line, no control characters, at most 64 characters.
pub fn sanitize_display_name(claim: Option<&str>) -> Option<String> {
    let name: String = claim?.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    let name = name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

fn claim_str<'a>(identity: &'a VerifiedIdentity, name: &str) -> Option<&'a str> {
    identity.claims.get(name).and_then(Value::as_str)
}

fn email_of(identity: &VerifiedIdentity) -> (Option<String>, bool) {
    let email = claim_str(identity, "email").map(|e| e.trim().to_lowercase()).filter(|e| {
        let Some((local, domain)) = e.split_once('@') else { return false };
        !local.is_empty() && e.len() <= 254 && domain.contains('.') && !e.chars().any(char::is_whitespace)
    });
    let verified = match identity.claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    (email, verified)
}

/// The account of a verified identity for a login: the linked account, or a new one (`AUTO_PROVISION`).
pub async fn login_account(state: &AppState, oidc: &Oidc, identity: &VerifiedIdentity) -> Result<UserRow, ApiError> {
    let s = &oidc.settings;
    if let Some(link) = store::oidc::identity_by_subject(&state.db, &s.issuer, &identity.subject).await? {
        let user = store::users::by_id(&state.db, &link.user_id)
            .await?
            .ok_or(ApiError::Unauthorized { code: "auth.account_disabled" })?;
        if user.disabled_at.is_some() {
            return Err(ApiError::Unauthorized { code: "auth.account_disabled" });
        }
        store::oidc::touch_login(&state.db, &s.issuer, &identity.subject).await?;
        if let Some(name) = sanitize_display_name(claim_str(identity, &s.display_name_claim))
            && name != user.display_name
        {
            store::users::update_profile(&state.db, &user.id, &name).await?;
        }
        return Ok(user);
    }
    if !s.auto_provision {
        return Err(ApiError::Forbidden {
            code: "sso.not_provisioned",
            detail: "No account is linked to this identity and accounts are not created automatically".into(),
        });
    }
    provision(state, oidc, identity).await
}

async fn provision(state: &AppState, oidc: &Oidc, identity: &VerifiedIdentity) -> Result<UserRow, ApiError> {
    let s = &oidc.settings;
    let cfg = &state.config;
    let (email, verified) = email_of(identity);
    let email = match cfg.email {
        EmailMode::None => None,
        EmailMode::Required if email.is_none() || !verified => {
            return Err(ApiError::Forbidden {
                code: "sso.email_unverified",
                detail: "This node requires a verified email address from the identity provider".into(),
            });
        }
        _ => email,
    };
    let base = sanitize_username(claim_str(identity, &s.username_claim).unwrap_or(""));
    let is_first = store::users::count_local(&state.db, &cfg.domain).await? == 0;
    let mut created = None;
    for attempt in 1..=SUFFIX_ATTEMPTS + 5 {
        let username = if attempt <= SUFFIX_ATTEMPTS {
            candidate(&base, attempt)
        } else {
            candidate(&base, 1000 + rand::random::<u32>() % 9_000_000)
        };
        // The names of TAVRN_ADMIN_USERS stay reserved for the operators' break-glass accounts: a provider
        // account must never obtain one (or its admin flag) by choosing a matching claim.
        if !util::valid_username(&username)
            || util::reserved_username(&username)
            || username == crate::federation::conformance::PROBE_USERNAME
            || cfg.admin_users().contains(&username)
        {
            continue;
        }
        let display =
            sanitize_display_name(claim_str(identity, &s.display_name_claim)).unwrap_or_else(|| username.clone());
        let new = store::oidc::NewSsoUser {
            username: &username,
            domain: &cfg.domain,
            display_name: &display,
            email: email.as_deref(),
            email_verified: email.is_some() && verified,
            // The first account of a fresh node administers it, as at registration; otherwise only the
            // group map grants the flag.
            is_node_admin: is_first,
            issuer: &s.issuer,
            subject: &identity.subject,
        };
        if let Some(user) = store::oidc::create_sso_user(&state.db, new).await? {
            created = Some(user);
            break;
        }
    }
    let user = created.ok_or_else(|| ApiError::conflict("auth.username_taken", "No free username found"))?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&user.id),
        "sso.provision",
        &user.address(),
        "",
        serde_json::json!({ "issuer": s.issuer }),
    )
    .await?;
    tracing::info!(issuer = s.issuer, user = user.address(), "SSO: account provisioned");
    Ok(user)
}

/// Links the identity to `user` (§8.3).
pub async fn link(state: &AppState, oidc: &Oidc, user: &UserRow, identity: &VerifiedIdentity) -> Result<(), ApiError> {
    let issuer = &oidc.settings.issuer;
    if let Some(existing) = store::oidc::identity_by_subject(&state.db, issuer, &identity.subject).await? {
        if existing.user_id == user.id {
            return Ok(());
        }
        return Err(identity_linked());
    }
    if store::oidc::identity_of_user(&state.db, &user.id, issuer).await?.is_some() {
        return Err(already_linked());
    }
    if !store::oidc::link(&state.db, &user.id, issuer, &identity.subject).await? {
        return Err(identity_linked());
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(&user.id),
        "sso.link",
        &user.address(),
        "",
        serde_json::json!({ "issuer": issuer }),
    )
    .await?;
    Ok(())
}

pub fn identity_linked() -> ApiError {
    ApiError::conflict("sso.identity_linked", "This identity is already linked to another account")
}

pub fn already_linked() -> ApiError {
    ApiError::conflict("sso.already_linked", "This account is already linked to an identity of the provider")
}

/// New device and SSO session (hard end after `TAVRN_OIDC_SESSION_DAYS`, §8.6). No second factor (§8.4).
pub async fn start_session(
    state: &AppState,
    oidc: &Oidc,
    user: &UserRow,
    device_name: &str,
    client: &str,
    reuse: Option<&str>,
) -> Result<AuthResponse, ApiError> {
    let device_id = crate::second_factor::session_device(state, user, device_name, client, reuse).await?;
    let refresh = util::random_token(32);
    store::oidc::create_sso_session(
        &state.db,
        &user.id,
        &device_id,
        &util::sha256_b64(&refresh),
        auth::refresh_ttl_secs(&state.config),
        oidc.settings.session_secs(),
    )
    .await?;
    let tokens = auth::TokenPair {
        access_token: auth::issue_access_token(state, &user.id, &device_id)?,
        refresh_token: refresh,
        expires_in: auth::access_ttl_secs(&state.config),
        device_id,
    };
    let reauth_token = Some(crate::reauth::for_new_session(state, &user.id, &tokens).await?);
    Ok(AuthResponse {
        status: SessionStatus::Ok,
        user: user.to_private(),
        tokens,
        recovery_code_used: false,
        reauth_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_follow_the_grammar() {
        assert_eq!(sanitize_username("Alice"), "alice");
        assert_eq!(sanitize_username("alice.smith@corp.example"), "alice.smith");
        assert_eq!(sanitize_username("Jürgen Müller"), "j-rgen-m-ller");
        assert_eq!(sanitize_username("__bob"), "bob");
        assert_eq!(sanitize_username("x"), "user");
        assert_eq!(sanitize_username(""), "user");
        assert_eq!(sanitize_username("ä"), "user");
        assert_eq!(sanitize_username(&"a".repeat(50)).len(), 32);
        for s in ["Alice", "a.b@c", "Jürgen Müller", "__bob", "x", "-.-", "日本語"] {
            assert!(util::valid_username(&sanitize_username(s)), "{s}");
        }
    }

    #[test]
    fn collision_candidates_stay_valid() {
        assert_eq!(candidate("alice", 1), "alice");
        assert_eq!(candidate("alice", 2), "alice-2");
        let long = "a".repeat(32);
        assert_eq!(candidate(&long, 12), format!("{}-12", "a".repeat(29)));
        assert!(util::valid_username(&candidate(&long, 999)));
        assert_eq!(candidate("ab.", 3), "ab-3");
    }

    #[test]
    fn display_names_are_cleaned() {
        assert_eq!(sanitize_display_name(Some("  Alice\u{7}  Smith ")).as_deref(), Some("Alice  Smith"));
        assert_eq!(sanitize_display_name(Some("  ")), None);
        assert_eq!(sanitize_display_name(None), None);
        assert_eq!(sanitize_display_name(Some(&"x".repeat(100))).map(|s| s.len()), Some(64));
    }
}
