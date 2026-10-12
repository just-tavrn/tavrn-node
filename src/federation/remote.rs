// SPDX-License-Identifier: AGPL-3.0-only
//! Remote users on this node (FEDERATION.md §2.5–§2.7) and the home-node side of revocations (§2.9).

use std::time::Instant;

use serde_json::{Value, json};

use super::tokens;
use crate::{
    app::AppState,
    auth::{self, TokenPair},
    error::ApiError,
    models::UserRow,
    store, util,
};

/// A federated session ends this long after the federated login (§2.5).
pub const SESSION_MAX_SECS: i64 = 7 * 24 * 3600;
/// Mirrors older than this are refreshed when the user logs in (§2.7).
pub use super::profiles::PROFILE_MAX_AGE_SECS;

fn remote_limit() -> ApiError {
    ApiError::Forbidden {
        code: "federation.remote_limit",
        detail: "This node accepts no further users of other nodes".into(),
    }
}

fn user_banned() -> ApiError {
    ApiError::Forbidden { code: "federation.user_banned", detail: "This account is banned on this node".into() }
}

pub fn bots_refused() -> ApiError {
    ApiError::Forbidden {
        code: "federation.bots_refused",
        detail: "This node does not accept bots of other nodes".into(),
    }
}

/// The result of a federated login: the remote user and a session of this node.
pub struct FederatedLogin {
    pub user: UserRow,
    /// `device_id` is the home device id.
    pub tokens: TokenPair,
    pub session_expires_at: String,
}

/// `POST /auth/federated` (§2.5): verifies the federation token, creates or updates the remote user and
/// its device, and issues the single session of that device.
pub async fn federated_login(
    state: &AppState,
    ip: &str,
    token: &str,
    device_name: &str,
    client: &str,
) -> Result<FederatedLogin, ApiError> {
    let started = Instant::now();
    if !state.config.federation_enabled {
        return Err(super::disabled());
    }
    let iss = tokens::peek_issuer(state, token)?;
    let result = login_inner(state, ip, token, &iss, device_name, client).await;
    let ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(login) => tracing::info!(
            issuer = iss,
            address = login.user.address(),
            device = login.tokens.device_id,
            result = "ok",
            ms,
            "federated login"
        ),
        Err(e) => tracing::info!(issuer = iss, result = e.code(), ms, "federated login refused"),
    }
    result
}

async fn login_inner(
    state: &AppState,
    ip: &str,
    token: &str,
    iss: &str,
    device_name: &str,
    client: &str,
) -> Result<FederatedLogin, ApiError> {
    super::check_policy(state, iss).await?;
    // Before the signature check the domain's budget counts per address: a peer's own attempts (the conformance
    // check's burst of invalid logins, §9) reach `429`, forged ones from elsewhere cannot use up its budget.
    if !state.config.misbehaves("no_rate_limit") {
        state.federation_login_limiter.check_all(&[format!("domain:{iss}|ip:{ip}")]).await?;
    }
    let t = match tokens::verify_federation_token(state, token, iss).await {
        Ok(t) => t,
        Err(e) => {
            if e.code() == "federation.issuer_mismatch" {
                // Validly signed by `iss` for a user of another domain: spoofing (§9.4).
                super::conformance::observe_issuer_mismatch(state, iss, token).await;
            }
            return Err(e);
        }
    };
    // Per domain only after the signature check (the route limits per address before): forged tokens in a
    // peer's name must not use up its budget.
    if !state.config.misbehaves("no_rate_limit") {
        state.federation_login_limiter.check_all(&[format!("domain:{iss}")]).await?;
    }
    // After the signature check, so only real peers can start a conformance run; before the `jti` is
    // spent, so the token can be retried after `federation.conformance_pending`.
    super::conformance::require(state, iss).await?;
    tokens::spend_jti(state, &t.std).await?;

    if store::rooms::is_banned(&state.db, None, &t.std.sub, &t.domain).await? {
        return Err(user_banned());
    }
    if let Some((owner, domain)) = &t.owner
        && store::rooms::is_banned(&state.db, None, &format!("{owner}@{domain}"), domain).await?
    {
        return Err(user_banned());
    }
    if t.kind == "bot" && !state.config.federation_remote_bots {
        return Err(bots_refused());
    }
    if t.kind == "bot" && store::applications::is_blocked(&state.db, &t.std.sub).await? {
        return Err(ApiError::Forbidden { code: "app.blocked", detail: "This application is blocked here".into() });
    }

    let owner_id = match &t.owner {
        Some((owner, domain)) => Some(ensure_remote_user(state, owner, domain, "user", None).await?.id),
        None => None,
    };
    let user = ensure_remote_user(state, &t.username, &t.domain, &t.kind, owner_id.as_deref()).await?;
    let user = reconcile_kind(state, user, &t.kind, owner_id.as_deref()).await?;
    if user.disabled_at.is_some() {
        return Err(ApiError::Unauthorized { code: "auth.account_disabled" });
    }
    refresh_profile(state, &user, Some(t.pv)).await?;

    let device_id =
        store::federation::ensure_remote_device(&state.db, &user.id, &t.device, &t.domain, device_name, client).await?;
    let refresh = util::random_token(32);
    let session_expires_at = util::in_seconds(SESSION_MAX_SECS);
    store::federation::replace_federated_session(
        &state.db,
        &user.id,
        &device_id,
        &util::sha256_b64(&refresh),
        &session_expires_at,
    )
    .await?;
    store::federation::touch_login(&state.db, &user.id).await?;
    // The home node's age claim of this login (FEDERATION.md §2.2): the latest one counts; never exposed.
    store::users::set_age_claim(&state.db, &user.id, t.age_over_18).await?;
    if t.kind == "bot" {
        // T keeps the application and the scopes with the session and applies them (APPLICATIONS.md §2.8).
        let app_ref = t.app.as_deref().map(|a| format!("{}/{a}", t.domain));
        store::applications::set_remote_session_app(
            &state.db,
            &user.id,
            &device_id,
            app_ref.as_deref(),
            t.scopes.as_deref(),
        )
        .await?;
        if let Some((owner, domain)) = &t.owner {
            store::applications::set_owner_address(&state.db, &user.id, &format!("{owner}@{domain}")).await?;
        }
    }
    let tokens = TokenPair {
        access_token: auth::issue_access_token(state, &user.id, &device_id)?,
        refresh_token: refresh,
        expires_in: auth::access_ttl_secs(&state.config),
        device_id: t.device.clone(),
    };
    let user = store::users::by_id(&state.db, &user.id).await?.unwrap_or(user);
    Ok(FederatedLogin { user, tokens, session_expires_at })
}

/// The verified token of the home node decides what the account is (FEDERATION.md §2.6). A row created earlier
/// as a stub (by a friend request, a block or an invitation) is a `user` without owner: a bot signing in with it
/// becomes a bot here, with its owner, so bot scopes, the bot route table, "no bots" and owner bans apply. The
/// reverse (a bot row presented as a user) would lift those limits and is refused (`federation.kind_mismatch`).
async fn reconcile_kind(
    state: &AppState,
    user: UserRow,
    kind: &str,
    owner_id: Option<&str>,
) -> Result<UserRow, ApiError> {
    if user.kind == kind && user.owner_id.as_deref() == owner_id {
        return Ok(user);
    }
    if user.kind == "bot" && kind != "bot" {
        tracing::warn!(user = user.address(), kind, "federated login refused: a bot account presented as another kind");
        return Err(ApiError::Forbidden {
            code: "federation.kind_mismatch",
            detail: "The account kind does not match the account known here".into(),
        });
    }
    tracing::info!(
        user = user.address(),
        from = user.kind,
        to = kind,
        "remote account kind or owner updated from the home node's token"
    );
    store::federation::set_remote_kind(&state.db, &user.id, kind, owner_id).await?;
    Ok(store::users::by_id(&state.db, &user.id).await?.unwrap_or(user))
}

/// The users row of `username@domain`, created (within the quotas) if it does not exist yet.
pub async fn ensure_remote_user(
    state: &AppState,
    username: &str,
    domain: &str,
    kind: &str,
    owner_id: Option<&str>,
) -> Result<UserRow, ApiError> {
    if let Some(user) = store::federation::user_by_address(&state.db, username, domain).await? {
        return Ok(user);
    }
    let c = &state.config;
    if store::federation::count_remote_users(&state.db, &c.domain).await? >= i64::from(c.federation_max_remote_users)
        || store::federation::count_users_of_domain(&state.db, domain).await?
            >= i64::from(c.federation_max_remote_users_per_domain)
    {
        tracing::warn!(domain, "remote user quota reached");
        return Err(remote_limit());
    }
    store::federation::create_remote_user(&state.db, username, domain, username, kind, owner_id).await
}

fn user_not_found() -> ApiError {
    ApiError::NotFound { code: "user.not_found", what: "User".into() }
}

/// `(username, domain)` of a reference `name` (this node) or `name@domain`; `None` if malformed.
pub fn parse_reference(state: &AppState, reference: &str) -> Option<(String, String)> {
    let r = reference.trim().to_lowercase();
    let (username, domain) = match r.rsplit_once('@') {
        Some((u, d)) => (u.to_string(), d.to_string()),
        None => (r.clone(), state.config.domain.clone()),
    };
    (util::valid_username(&username) && util::valid_domain(&domain)).then_some((username, domain))
}

/// The user a local action names (friend request, block, DM, direct invite): an active local user, or
/// a remote user that is created as a stub after its home node confirmed the profile (§2.6; `404
/// user.not_found` if the home node does not know the user).
pub async fn resolve_or_stub(state: &AppState, reference: &str) -> Result<UserRow, ApiError> {
    let (username, domain) = parse_reference(state, reference).ok_or_else(user_not_found)?;
    if domain == state.config.domain {
        // Webhook pseudo users are never the target of friend requests, blocks, DMs or invites (APPLICATIONS.md §6.1).
        return store::users::by_username(&state.db, &username, &domain)
            .await?
            .filter(|u| u.disabled_at.is_none() && u.kind != "webhook")
            .ok_or_else(user_not_found);
    }
    if !state.config.federation_enabled {
        return Err(super::disabled());
    }
    super::check_policy(state, &domain).await?;
    if let Some(user) = store::federation::user_by_address(&state.db, &username, &domain).await? {
        return if user.disabled_at.is_none() { Ok(user) } else { Err(user_not_found()) };
    }
    let profile = super::profiles::fetch(state, &username, &domain).await?;
    let user = ensure_remote_user(state, &username, &domain, "user", None).await?;
    super::profiles::apply(state, &user, &profile).await?;
    Ok(store::users::by_id(&state.db, &user.id).await?.unwrap_or(user))
}

/// A user this node already knows by reference (no network): an active local user or a remote user row.
pub async fn known_user(state: &AppState, reference: &str) -> Result<Option<UserRow>, ApiError> {
    let Some((username, domain)) = parse_reference(state, reference) else { return Ok(None) };
    let user = store::federation::user_by_address(&state.db, &username, &domain).await?;
    Ok(user.filter(|u| u.disabled_at.is_none() || u.domain != state.config.domain))
}

/// A node ban of a remote address or a domain (§3.3): ends the federated sessions of the affected
/// remote users (their WebSockets close) and removes them from every room of this node.
pub async fn apply_node_ban(state: &AppState, subject: &str) -> Result<(), ApiError> {
    let own = &state.config.domain;
    let users = match util::parse_address(subject) {
        Some((name, domain)) if domain != own => {
            store::federation::user_by_address(&state.db, name, domain).await?.into_iter().collect()
        }
        Some(_) => return Ok(()),
        None if subject != own => store::federation::users_within_domain(&state.db, subject).await?,
        None => return Ok(()),
    };
    for user in users.into_iter().filter(|u| u.domain != *own) {
        let devices = store::federation::revoke_remote_sessions(&state.db, &user.id, None).await?;
        if !devices.is_empty() {
            state.hub.devices(devices, super::inbox::SESSION_REVOKED_EVENT, json!({}));
        }
        for room_id in store::rooms::room_ids_of_user(&state.db, &user.id).await? {
            let member = store::rooms::member(&state.db, &room_id, &user.id).await?;
            if store::rooms::remove_member(&state.db, &room_id, &user.id).await? {
                crate::subscriptions::room_event(
                    state,
                    &room_id,
                    "member.leave",
                    json!({ "room_id": room_id, "user_id": user.id, "banned": true }),
                )
                .await;
                crate::e2ee::user_left_room(state, &room_id, &user).await?;
                if let Some(room) = store::rooms::room_by_id(&state.db, &room_id).await? {
                    crate::welcome::membership_ended(
                        state,
                        &room,
                        &user,
                        member.as_ref(),
                        crate::welcome::LeaveKind::Ban,
                    )
                    .await;
                    crate::installations::uninstalled(state, &room, &user, "banned", None).await?;
                    notify_ban(state, &user, &room_id, &room.name, "node").await;
                }
            }
        }
    }
    Ok(())
}

/// `ban.notify` (§5.2, information only, no reason) to the home node of a remote user that a room ban
/// (`scope = "room"`) or a node ban (`"node"`, one message per room the user was removed from) removed
/// from a room of this node. Only with `TAVRN_FEDERATION_NOTIFY_BANS=true`; never to a domain this node
/// does not federate with (a node ban of a whole domain blocks it). Failures are logged and never fail
/// the ban.
pub async fn notify_ban(state: &AppState, user: &UserRow, room_id: &str, room_name: &str, scope: &str) {
    let c = &state.config;
    if !c.federation_notify_bans || !c.federation_enabled || user.domain == c.domain {
        return;
    }
    if super::check_policy(state, &user.domain).await.is_err() {
        return;
    }
    let name: String = room_name.chars().take(100).collect();
    let payload = json!({ "room": { "node": c.domain, "id": room_id, "name": name }, "scope": scope });
    if let Err(e) = super::outbox::enqueue(state, &user.domain, "ban.notify", &c.domain, &user.address(), payload).await
    {
        tracing::warn!(error = %e, "ban.notify could not be queued");
    }
}

// ---------------------------------------------------------------- profiles

/// Refreshes the profile mirror of a remote user (`federation/profiles.rs`).
pub async fn refresh_profile(state: &AppState, user: &UserRow, hint: Option<i64>) -> Result<(), ApiError> {
    super::profiles::refresh(state, user, hint).await
}

// ---------------------------------------------------------------- home node: notifications

/// Domains that hear about key changes, revocations and profile changes of a local user (§5.2): the `federation_targets`
/// of the user (§2.4) plus the home domains of the user's friends and of the co-members of DMs and
/// group DMs hosted here.
pub async fn notification_domains(state: &AppState, user: &UserRow) -> Result<Vec<String>, ApiError> {
    let mut domains = store::federation::target_domains(&state.db, &user.id).await?;
    let mut contacts = store::social::contact_ids(&state.db, &user.id).await?;
    contacts.extend(store::social::friends_of(&state.db, &user.id).await?.into_iter().map(|(id, _)| id));
    for contact in store::users::by_ids(&state.db, &contacts).await? {
        if contact.domain != state.config.domain && !domains.contains(&contact.domain) {
            domains.push(contact.domain);
        }
    }
    domains.sort();
    Ok(domains)
}

/// Sends a notification about `user` to every domain of [`notification_domains`].
async fn notify_targets(state: &AppState, user: &UserRow, kind: &str, payload: Value) -> Result<(), ApiError> {
    if user.domain != state.config.domain {
        return Ok(());
    }
    for target in notification_domains(state, user).await? {
        super::outbox::enqueue(state, &target, kind, &user.address(), &target, payload.clone()).await?;
    }
    Ok(())
}

/// `session.revoke` (§2.9): `device` = one deleted device, `None` = every session of the user.
pub async fn revoke_sessions(state: &AppState, user: &UserRow, device: Option<&str>) -> Result<(), ApiError> {
    notify_targets(state, user, "session.revoke", json!({ "device": device })).await
}

/// `devices.changed` (§5.2): a device was removed or attested.
pub async fn devices_changed(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    notify_targets(state, user, "devices.changed", json!({})).await
}

/// The notification type of a changed public profile (§2.7 (d), §5.2).
pub const PROFILE_CHANGED: &str = "profile.changed";
/// A `profile.changed` waits this long before its first attempt, so a burst of edits leaves as one message.
pub const PROFILE_CHANGED_DELAY_SECS: i64 = 5;

/// `profile.changed { profile_version }` (§5.2) after a change of a local user's public profile, with the version
/// current now; a queued older one of the same user and target is replaced (at most one per user and target).
/// Bots are announced with `app.changed` (APPLICATIONS.md §4.5), webhooks never federate.
pub async fn profile_changed(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    if user.domain != state.config.domain || user.kind != "user" {
        return Ok(());
    }
    let targets = notification_domains(state, user).await?;
    if targets.is_empty() {
        return Ok(());
    }
    let (version, ..) = store::federation::profile_info(&state.db, &user.id).await?;
    for target in targets {
        super::outbox::enqueue_coalesced(
            state,
            &target,
            PROFILE_CHANGED,
            &user.address(),
            &target,
            json!({ "profile_version": version }),
            PROFILE_CHANGED_DELAY_SECS,
        )
        .await?;
    }
    Ok(())
}

/// `identity.changed` (§5.2) after an identity reset.
pub async fn identity_changed(state: &AppState, user: &UserRow, key: &str, reset_at: &str) -> Result<(), ApiError> {
    notify_targets(
        state,
        user,
        "identity.changed",
        json!({ "identity_public_key": key, "identity_reset_at": reset_at }),
    )
    .await
}
