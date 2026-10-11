// SPDX-License-Identifier: AGPL-3.0-only
//! Node administration: overview, users, account invites, node bans, audit log.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::{AppState, SOFTWARE_VERSION, capabilities},
    auth::NodeAdmin,
    error::{ApiError, ProblemDetails},
    jwt,
    models::{AccountInvite, AuditEntry, Ban, User},
    store,
    util::{self, now},
    validate::{self, bad},
};

#[derive(Serialize, ToSchema)]
pub struct AdminOverview {
    pub domain: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub users: i64,
    pub rooms: i64,
    pub messages: i64,
    pub blob_bytes: i64,
    pub registration: String,
    pub email: String,
    pub captcha_provider: String,
    pub gif_provider: String,
    pub room_creation: String,
    pub upload_max_bytes: u64,
    pub smtp_enabled: bool,
    /// Server-to-server notifications given up after their retries (FEDERATION.md §5.3).
    pub federation_undeliverable: i64,
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// Overview for node admins: counts and effective configuration.
#[utoipa::path(get, path = "/api/v1/admin/overview", security(("bearer" = [])), responses((status = 200, body = AdminOverview), (status = 403, body = ProblemDetails)))]
pub async fn overview(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<AdminOverview>, ApiError> {
    let c = &state.config;
    let s = store::admin::stats(&state.db, &c.domain).await?;
    Ok(Json(AdminOverview {
        domain: c.domain.clone(),
        version: SOFTWARE_VERSION.into(),
        capabilities: capabilities(c).into_iter().map(String::from).collect(),
        users: s.users,
        rooms: s.rooms,
        messages: s.messages,
        blob_bytes: s.blob_bytes,
        registration: enum_str(&c.registration),
        email: enum_str(&c.email),
        captcha_provider: enum_str(&c.captcha_provider),
        gif_provider: enum_str(&c.gif_provider),
        room_creation: enum_str(&c.room_creation),
        upload_max_bytes: c.upload_max_bytes,
        smtp_enabled: state.mailer.smtp_enabled(),
        federation_undeliverable: store::federation::undeliverable_count(&state.db).await?,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct UserQuery {
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub after: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AdminUser {
    #[serde(flatten)]
    pub user: User,
    pub email: Option<String>,
    pub email_verified: bool,
    pub disabled: bool,
    pub room_creation_grant: Option<i64>,
    /// Applications the user may still create with `TAVRN_APP_CREATION=invite`.
    pub app_creation_grant: i64,
}

async fn admin_user(state: &AppState, u: &crate::models::UserRow) -> Result<AdminUser, ApiError> {
    Ok(AdminUser {
        user: u.to_public(),
        email: u.email.clone(),
        email_verified: u.email_verified_at.is_some(),
        disabled: u.disabled_at.is_some(),
        room_creation_grant: store::users::room_creation_grant(&state.db, &u.id).await?,
        app_creation_grant: store::applications::creation_grant(&state.db, &u.id).await?,
    })
}

/// Search and list local users.
#[utoipa::path(get, path = "/api/v1/admin/users", security(("bearer" = [])), params(UserQuery), responses((status = 200, body = Vec<AdminUser>)))]
pub async fn list_users(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<UserQuery>,
) -> Result<Json<Vec<AdminUser>>, ApiError> {
    let rows = store::admin::list_users(
        &state.db,
        &state.config.domain,
        q.q.as_deref().unwrap_or("").trim(),
        validate::limit(q.limit, 50, 200),
        q.after.as_deref().unwrap_or(""),
    )
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for u in &rows {
        out.push(admin_user(&state, u).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub disabled: Option<bool>,
    pub node_admin: Option<bool>,
    /// Remaining room creations (mode `invite`); null does not remove the grant, 0 sets it to 0.
    pub room_creation_grant: Option<i64>,
    /// Applications the user may create with `TAVRN_APP_CREATION=invite` (0–100).
    pub app_creation_grant: Option<i64>,
}

/// Disable/enable a user, set the admin permission, grant room creation.
#[utoipa::path(patch, path = "/api/v1/admin/users/{user_id}", security(("bearer" = [])), params(("user_id" = String, Path)), request_body = UpdateUserRequest, responses((status = 200, body = AdminUser), (status = 404, body = ProblemDetails)))]
pub async fn update_user(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<AdminUser>, ApiError> {
    let target = store::users::by_id(&state.db, &user_id)
        .await?
        .filter(|u| u.domain == state.config.domain)
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
    if target.id == admin.user.id && (req.disabled == Some(true) || req.node_admin == Some(false)) {
        return Err(bad("admin.self", "You cannot disable yourself or revoke your own admin permission"));
    }
    // Bots are never node admins and own nothing (APPLICATIONS.md §1.4).
    if target.is_bot() && (req.node_admin == Some(true) || req.app_creation_grant.is_some()) {
        return Err(bad("app.bot_forbidden", "Bots cannot be node admins or create applications"));
    }
    if let Some(d) = req.disabled {
        store::admin::set_disabled(&state.db, &user_id, d).await?;
        if d {
            crate::sessions::revoke_all(&state, &target, None, crate::sessions::Reason::AccountDisabled).await?;
            crate::federation::remote::revoke_sessions(&state, &target, None).await?;
            // The owner's bots stop at once (APPLICATIONS.md §1.7); re-enabling the owner re-enables them.
            crate::applications::owner_disabled(&state, &target.id).await?;
        }
        store::rooms::audit(
            &state.db,
            None,
            Some(&admin.user.id),
            if d { "admin.user_disable" } else { "admin.user_enable" },
            &target.address(),
            "",
            serde_json::json!({}),
        )
        .await?;
    }
    if let Some(a) = req.node_admin {
        store::admin::set_node_admin(&state.db, &user_id, a).await?;
        store::rooms::audit(
            &state.db,
            None,
            Some(&admin.user.id),
            "admin.set_node_admin",
            &target.address(),
            "",
            serde_json::json!({ "admin": a }),
        )
        .await?;
    }
    if let Some(n) = req.room_creation_grant {
        let n = validate::range("room_creation_grant", n, 0, 1000)?;
        store::users::upsert_room_creation_grant(&state.db, &user_id, &admin.user.id, n).await?;
        store::rooms::audit(
            &state.db,
            None,
            Some(&admin.user.id),
            "admin.room_creation_grant",
            &target.address(),
            "",
            serde_json::json!({ "remaining": n }),
        )
        .await?;
    }
    if let Some(n) = req.app_creation_grant {
        let n = validate::range("app_creation_grant", n, 0, 100)?;
        store::applications::set_creation_grant(&state.db, &user_id, n).await?;
        store::rooms::audit(
            &state.db,
            None,
            Some(&admin.user.id),
            "admin.app_creation_grant",
            &target.address(),
            "",
            serde_json::json!({ "remaining": n }),
        )
        .await?;
    }
    let updated = store::users::by_id(&state.db, &user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
    Ok(Json(admin_user(&state, &updated).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct PurgeUserRequest {
    pub confirm_token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PurgeUserResponse {
    pub dry_run: bool,
    pub messages: i64,
    pub confirm_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ConfirmClaims {
    #[serde(flatten)]
    std: jwt::StandardClaims,
    target: String,
}

#[derive(Deserialize)]
struct ConfirmExtra {
    target: String,
}

/// Rescue for a locked-out user: removes TOTP, all WebAuthn credentials (with their passkey secret
/// storage entries) and the recovery codes, and signs the user out everywhere. The next login lands
/// in `enrollment_required`; the `recovery` secret storage entry stays, so history is unaffected.
/// Admins cannot reset their own factors here.
#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/second-factor/reset", security(("bearer" = [])), params(("user_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn reset_second_factor(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let target = store::users::by_id(&state.db, &user_id)
        .await?
        .filter(|u| u.domain == state.config.domain && u.kind == "user")
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
    if target.id == admin.user.id {
        return Err(ApiError::conflict(
            "admin.second_factor_self",
            "Your own second factor must be reset by another node admin",
        ));
    }
    let credentials = store::factors::reset_second_factor(&state.db, &target.id).await?;
    crate::sessions::revoke_all(&state, &target, None, crate::sessions::Reason::SecondFactorReset).await?;
    crate::federation::remote::revoke_sessions(&state, &target, None).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.second_factor_reset",
        &target.address(),
        "",
        serde_json::json!({ "admin_id": admin.user.id, "user_id": target.id, "webauthn_credentials": credentials }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Permanently delete all messages and files of a user on this node (preview, then confirmation).
#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/purge", security(("bearer" = [])), params(("user_id" = String, Path)), request_body = PurgeUserRequest, responses((status = 200, body = PurgeUserResponse)))]
pub async fn purge_user(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
    Json(req): Json<PurgeUserRequest>,
) -> Result<Json<PurgeUserResponse>, ApiError> {
    let target = store::users::by_id(&state.db, &user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
    let filter = store::messages::PurgeFilter {
        conversation_ids: Vec::new(),
        author_id: Some(user_id.clone()),
        from: None,
        to: None,
    };
    let key = state.signing_key();
    let expected = jwt::Expected {
        iss: state.config.domain.clone(),
        aud: format!("purge-user:{}", admin.user.id),
        typ: "confirm",
    };
    match req.confirm_token.as_deref() {
        None => {
            let count = store::messages::purge_count(&state.db, &filter).await?;
            let n = jwt::now_unix();
            let claims = ConfirmClaims {
                std: jwt::StandardClaims {
                    iss: expected.iss,
                    sub: user_id.clone(),
                    aud: expected.aud,
                    exp: n + 120,
                    iat: n,
                    jti: util::ulid(),
                    typ: "confirm".into(),
                },
                target: user_id,
            };
            let token = jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))?;
            Ok(Json(PurgeUserResponse { dry_run: true, messages: count, confirm_token: Some(token) }))
        }
        Some(token) => {
            let (_, extra): (jwt::StandardClaims, ConfirmExtra) = jwt::verify(token, &key.verifying(), &expected)
                .map_err(|_| {
                    bad(
                        "moderation.confirm_invalid",
                        "Confirmation token invalid or expired, please repeat the preview",
                    )
                })?;
            if extra.target != user_id {
                return Err(bad("moderation.confirm_mismatch", "The target changed after the preview"));
            }
            let deleted = crate::routes::messages::purge_with_blobs(&state, &filter).await?;
            store::rooms::audit(
                &state.db,
                None,
                Some(&admin.user.id),
                "admin.user_purge",
                &target.address(),
                "",
                serde_json::json!({ "deleted": deleted }),
            )
            .await?;
            Ok(Json(PurgeUserResponse { dry_run: false, messages: deleted, confirm_token: None }))
        }
    }
}

// ---------------------------------------------------------------- Account invites

#[derive(Deserialize, ToSchema, Default)]
pub struct CreateAccountInviteRequest {
    #[serde(default)]
    pub note: String,
    /// 0 = unlimited
    #[serde(default = "one")]
    pub max_uses: i64,
    /// Hours, 0 = unlimited
    #[serde(default)]
    pub expires_hours: i64,
}

fn one() -> i64 {
    1
}

/// Create an account invite (for `TAVRN_REGISTRATION=invite`).
#[utoipa::path(post, path = "/api/v1/admin/invites", security(("bearer" = [])), request_body = CreateAccountInviteRequest, responses((status = 201, body = AccountInvite)))]
pub async fn create_invite(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    body: Option<Json<CreateAccountInviteRequest>>,
) -> Result<(StatusCode, Json<AccountInvite>), ApiError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let note = validate::text("note", &req.note, 0, 200)?;
    let max_uses = validate::range("max_uses", req.max_uses, 0, 10_000)?;
    let hours = validate::range("expires_hours", req.expires_hours, 0, 24 * 365)?;
    let expires_at = (hours > 0).then(|| util::in_seconds(hours * 3600));
    let invite = store::admin::create_invite(&state.db, &admin.user.id, &note, max_uses, expires_at.as_deref()).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.invite_create",
        &invite.code,
        "",
        serde_json::json!({ "max_uses": max_uses }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(invite)))
}

/// List account invites.
#[utoipa::path(get, path = "/api/v1/admin/invites", security(("bearer" = [])), responses((status = 200, body = Vec<AccountInvite>)))]
pub async fn list_invites(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<AccountInvite>>, ApiError> {
    Ok(Json(store::admin::list_invites(&state.db).await?))
}

/// Delete an account invite.
#[utoipa::path(delete, path = "/api/v1/admin/invites/{code}", security(("bearer" = [])), params(("code" = String, Path)), responses((status = 204)))]
pub async fn delete_invite(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Path(code): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !store::admin::delete_invite(&state.db, &code).await? {
        return Err(ApiError::NotFound { code: "invite.not_found", what: "Invite".into() });
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Preview of an account invite (public): valid or not.
#[utoipa::path(get, path = "/api/v1/account-invites/{code}", params(("code" = String, Path)), responses((status = 200, description = "valid"), (status = 404, body = ProblemDetails)))]
pub async fn check_account_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let invalid = || ApiError::NotFound { code: "invite.invalid", what: "Invite".into() };
    let inv = store::admin::invite_by_code(&state.db, &code).await?.ok_or_else(invalid)?;
    let valid =
        (inv.max_uses == 0 || inv.uses < inv.max_uses) && inv.expires_at.as_deref().is_none_or(|e| e > now().as_str());
    if !valid {
        return Err(invalid());
    }
    Ok(Json(serde_json::json!({ "valid": true, "note": inv.note })))
}

// ---------------------------------------------------------------- Node bans and audit log

#[derive(Deserialize, ToSchema)]
pub struct NodeBanRequest {
    pub subject: String,
    #[serde(default)]
    pub reason: String,
}

/// Node-wide ban for `user@domain` or an entire domain.
#[utoipa::path(post, path = "/api/v1/admin/bans", security(("bearer" = [])), request_body = NodeBanRequest, responses((status = 201, body = Ban)))]
pub async fn ban(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Json(req): Json<NodeBanRequest>,
) -> Result<(StatusCode, Json<Ban>), ApiError> {
    let subject = req.subject.trim().to_lowercase();
    let reason = validate::text("reason", &req.reason, 0, 500)?;
    if util::parse_address(&subject).is_none() && !util::valid_domain(&subject) {
        return Err(bad("ban.subject_invalid", "Specify: alice@domain or domain"));
    }
    if subject == state.config.domain || subject == admin.user.address() {
        return Err(bad("ban.own", "Your own domain or your own account cannot be banned"));
    }
    if let Some((username, domain)) = util::parse_address(&subject)
        && domain == state.config.domain
        && let Some(target) = store::users::by_username(&state.db, username, domain).await?
    {
        store::admin::set_disabled(&state.db, &target.id, true).await?;
        crate::sessions::revoke_all(&state, &target, None, crate::sessions::Reason::NodeBan).await?;
        crate::federation::remote::revoke_sessions(&state, &target, None).await?;
        crate::applications::owner_disabled(&state, &target.id).await?;
    }
    let ban = store::rooms::add_ban(&state.db, None, &subject, &reason, &admin.user.id).await?;
    crate::federation::remote::apply_node_ban(&state, &subject).await?;
    // The bots of a banned owner leave every room of this node (APPLICATIONS.md §1.7).
    crate::applications::ban_cascade(&state, None, &subject).await?;
    store::rooms::audit(&state.db, None, Some(&admin.user.id), "admin.ban", &subject, &reason, serde_json::json!({}))
        .await?;
    Ok((StatusCode::CREATED, Json(ban)))
}

/// Lift a node-wide ban (a local account is not automatically re-enabled).
#[utoipa::path(delete, path = "/api/v1/admin/bans/{subject}", security(("bearer" = [])), params(("subject" = String, Path)), responses((status = 204)))]
pub async fn unban(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(subject): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !store::rooms::remove_ban(&state.db, None, &subject.to_lowercase()).await? {
        return Err(ApiError::NotFound { code: "ban.not_found", what: "Ban".into() });
    }
    store::rooms::audit(&state.db, None, Some(&admin.user.id), "admin.unban", &subject, "", serde_json::json!({}))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Node-wide bans.
#[utoipa::path(get, path = "/api/v1/admin/bans", security(("bearer" = [])), responses((status = 200, body = Vec<Ban>)))]
pub async fn list_bans(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<Vec<Ban>>, ApiError> {
    Ok(Json(store::rooms::bans(&state.db, None).await?))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub before: Option<String>,
}

/// Node-wide audit log (registrations, admin actions).
#[utoipa::path(get, path = "/api/v1/admin/audit-log", security(("bearer" = [])), params(AuditQuery), responses((status = 200, body = Vec<AuditEntry>)))]
pub async fn audit_log(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let rows =
        store::rooms::audit_entries(&state.db, None, validate::limit(q.limit, 50, 200), q.before.as_deref()).await?;
    Ok(Json(rows.iter().map(|r| r.to_api()).collect()))
}
