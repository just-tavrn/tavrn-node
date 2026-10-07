// SPDX-License-Identifier: AGPL-3.0-only
//! Applications (bots) of the signed-in user and their tokens (protocol/APPLICATIONS.md §1.2–§1.6, §2.2,
//! §3.4). Every owner route needs a full session of a local user (`/applications*` is local-only for remote
//! users, and not in the bot route table); `/applications/me*` serves the bot itself with its app token.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    applications::{self as apps, AppPrincipal},
    auth::AuthUser,
    config::{AppCreation, DmPolicy},
    error::{ApiError, ApiJson, ProblemDetails},
    media::MediaKind,
    models::{User, UserRow},
    permissions as p, profile, store,
    store::applications::{ApplicationRow, TokenRow},
    util,
    validate::{self, bad},
};

/// Maximum length of an application description (Markdown subset like the profile bio).
pub const DESCRIPTION_MAX_CHARS: usize = 400;
/// At most this many `rpc_origins` (§7.3).
pub const MAX_RPC_ORIGINS: usize = 10;

// ---------------------------------------------------------------- objects

/// A pending transfer of an application to another local user.
#[derive(Serialize, ToSchema)]
pub struct PendingTransfer {
    /// Address of the user the application goes to.
    pub to: String,
    pub created_at: String,
    pub expires_at: String,
}

/// An application as its owner (and the bot itself) sees it.
#[derive(Serialize, ToSchema)]
pub struct Application {
    pub id: String,
    /// `<domain>/<id>`
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    pub description: String,
    pub public: bool,
    /// The bot account (`kind = "bot"`, `owner`, `application_id`).
    pub bot: User,
    /// The owner's address.
    pub owner: String,
    /// Decimal permission mask the add flow proposes (never `administrator`).
    pub requested_permissions: String,
    /// Upper bound of every token's scopes.
    pub scopes: Vec<String>,
    /// Absent for the bot itself (`GET /applications/me`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interactions_url: Option<Option<String>>,
    pub rpc_origins: Vec<String>,
    pub commands_version: i64,
    /// Number of tokens (= bot devices).
    pub tokens: i64,
    pub disabled: bool,
    /// `admin`, `owner_disabled` or `blocked`; null when enabled.
    pub disabled_reason: Option<String>,
    /// The bot's "who can message me" (`friends`, `everyone_shared`, `everyone`).
    pub dm_policy: String,
    /// Pending transfer started by the owner, if any.
    pub transfer: Option<PendingTransfer>,
    pub created_at: String,
    pub add_link: String,
}

/// An app token without its secret.
#[derive(Serialize, ToSchema)]
pub struct AppToken {
    pub id: String,
    pub name: String,
    /// The bot device bound to the token.
    pub device_id: String,
    /// The token's scopes (effective: these ∩ the application's scopes).
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    /// Always null: revoked tokens are deleted with their device.
    pub revoked_at: Option<String>,
}

impl AppToken {
    fn of(row: &TokenRow) -> Self {
        Self {
            id: row.id.clone(),
            name: row.name.clone(),
            device_id: row.device_id.clone(),
            scopes: row.scopes(),
            created_at: row.created_at.clone(),
            expires_at: row.expires_at.clone(),
            last_used_at: row.last_used_at.clone(),
            revoked_at: row.revoked_at.clone(),
        }
    }
}

/// A new or reset token: the secret is shown only in this response.
#[derive(Serialize, ToSchema)]
pub struct TokenSecret {
    pub token: AppToken,
    /// The app token (JWT, `typ = "app"`). Stored by the node only as a hash; shown once.
    pub secret: String,
}

/// A rotated secret (`POST /applications/me/tokens/rotate`).
#[derive(Serialize, ToSchema)]
pub struct RotatedToken {
    pub secret: String,
    pub expires_at: String,
}

/// A transfer offered to the signed-in user.
#[derive(Serialize, ToSchema)]
pub struct IncomingTransfer {
    pub application_id: String,
    pub name: String,
    pub bot: User,
    /// Address of the current owner.
    pub from: String,
    pub created_at: String,
    pub expires_at: String,
}

async fn view(state: &AppState, app: &ApplicationRow, owner_view: bool) -> Result<Application, ApiError> {
    let bot = store::users::by_id(&state.db, &app.bot_user_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("application without bot")))?;
    let owner = store::users::by_id(&state.db, &app.owner_id).await?.map(|o| o.address()).unwrap_or_default();
    let reason = match apps::disabled_reason(state, app, &bot).await? {
        Some("disabled") => Some(app.disabled_reason.clone().unwrap_or_else(|| "admin".into())),
        other => other.map(String::from),
    };
    let transfer = match store::applications::transfer(&state.db, &app.id).await? {
        Some(t) if owner_view => store::users::by_id(&state.db, &t.to_user_id).await?.map(|to| PendingTransfer {
            to: to.address(),
            created_at: t.created_at,
            expires_at: t.expires_at,
        }),
        _ => None,
    };
    Ok(Application {
        id: app.id.clone(),
        reference: apps::app_ref(state, &app.id),
        name: app.name.clone(),
        description: app.description.clone(),
        public: app.public != 0,
        bot: bot.to_public(),
        owner,
        requested_permissions: (app.requested_permissions as u64).to_string(),
        scopes: app.scopes(),
        interactions_url: owner_view.then(|| app.interactions_url.clone()),
        rpc_origins: app.rpc_origins(),
        commands_version: app.commands_version,
        tokens: store::applications::count_tokens(&state.db, &app.id).await?,
        disabled: reason.is_some(),
        disabled_reason: reason,
        dm_policy: bot.dm_policy.clone(),
        transfer,
        created_at: app.created_at.clone(),
        add_link: format!("{}/add/{}", state.config.public_url(), app.id),
    })
}

/// The caller's own application `{id}` (`404 app.not_found` for everybody else: no oracle).
pub(crate) async fn owned(state: &AppState, auth: &AuthUser, id: &str) -> Result<ApplicationRow, ApiError> {
    if !util::is_ulid(id) {
        return Err(apps::not_found());
    }
    store::applications::by_id(&state.db, id).await?.filter(|a| a.owner_id == auth.user.id).ok_or_else(apps::not_found)
}

/// Owner routes are for local users with a full session, never for bots (also refused by the route table).
pub(crate) fn require_person(auth: &AuthUser) -> Result<(), ApiError> {
    if auth.user.is_bot() || auth.app.is_some() {
        return Err(apps::bot_forbidden());
    }
    if auth.is_remote() {
        return Err(crate::federation::guard::local_only());
    }
    Ok(())
}

/// `403 app.creation_forbidden` unless `user` may create (or receive) applications under
/// `TAVRN_APP_CREATION`; `409 app.limit_reached` at the per-owner limit.
async fn may_own_another(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    let forbidden = |detail: &str| ApiError::Forbidden { code: "app.creation_forbidden", detail: detail.into() };
    match state.config.app_creation {
        AppCreation::All => {}
        AppCreation::Admins if user.is_node_admin() => {}
        AppCreation::Admins => return Err(forbidden("Only node admins can create applications on this node")),
        AppCreation::Invite => {
            if !user.is_node_admin() && store::applications::creation_grant(&state.db, &user.id).await? <= 0 {
                return Err(forbidden("Creating applications needs a grant of a node admin"));
            }
        }
    }
    let max = state.config.apps_per_user;
    if store::applications::count_of_owner(&state.db, &user.id).await? >= i64::from(max) {
        return Err(ApiError::Conflict {
            code: "app.limit_reached",
            detail: format!("At most {max} applications per user"),
            meta: json!({ "max": max }),
        });
    }
    Ok(())
}

fn requested_permissions(value: &str) -> Result<u64, ApiError> {
    let invalid = || bad("app.permissions_invalid", "A decimal permission mask without administrator");
    let perms = p::parse(value.trim()).ok_or_else(invalid)?;
    if p::has(perms, p::ADMINISTRATOR) {
        return Err(invalid());
    }
    Ok(perms)
}

fn app_name(value: &str) -> Result<String, ApiError> {
    let name = validate::text("name", value, 2, 32)?;
    if name.contains('\n') {
        return Err(bad("validation.multiline", "name: one line only"));
    }
    Ok(name)
}

fn description(value: &str) -> Result<String, ApiError> {
    let d = validate::text("description", value, 0, DESCRIPTION_MAX_CHARS)?;
    Ok(d)
}

/// `https://host[:port]` without path, query, fragment or credentials.
fn rpc_origins(list: &[String]) -> Result<Vec<String>, ApiError> {
    if list.len() > MAX_RPC_ORIGINS {
        return Err(bad("app.url_invalid", format!("At most {MAX_RPC_ORIGINS} origins")));
    }
    let mut out: Vec<String> = Vec::new();
    for origin in list {
        let o = origin.trim().to_lowercase();
        let host = o.strip_prefix("https://").unwrap_or("");
        let (name, port) = match host.rsplit_once(':') {
            Some((n, port)) => (n, Some(port)),
            None => (host, None),
        };
        let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0));
        if !util::valid_domain(name) || !name.contains('.') && name != "localhost" || !port_ok {
            return Err(bad("app.url_invalid", format!("Not an https origin: {origin:.100}")));
        }
        if !out.contains(&o) {
            out.push(o);
        }
    }
    Ok(out)
}

/// The bot username derived from the name: lowercase, invalid characters → `-`, trimmed to 32.
fn derive_username(name: &str) -> String {
    let mut s: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') { c } else { '-' })
        .collect();
    s = s.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_string();
    s.truncate(28);
    if s.len() < 2 { format!("bot-{s}").trim_end_matches('-').to_string() } else { s }
}

fn audit_meta(state: &AppState, app: &ApplicationRow, extra: serde_json::Value) -> serde_json::Value {
    let mut meta = json!({ "application": apps::app_ref(state, &app.id) });
    if let (Some(m), Some(e)) = (meta.as_object_mut(), extra.as_object()) {
        m.extend(e.clone());
    }
    meta
}

pub(crate) async fn audit(
    state: &AppState,
    actor: &UserRow,
    action: &str,
    app: &ApplicationRow,
    meta: serde_json::Value,
) -> Result<(), ApiError> {
    let bot = store::users::by_id(&state.db, &app.bot_user_id).await?.map(|b| b.address()).unwrap_or_default();
    store::rooms::audit(&state.db, None, Some(&actor.id), action, &bot, "", audit_meta(state, app, meta)).await
}

// ---------------------------------------------------------------- create, list, read

#[derive(Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    /// 2–32 characters, the bot's display name.
    pub name: String,
    /// Optional immutable username of the bot (`PROTOCOL.md` §1); derived from `name` when absent.
    pub username: Option<String>,
    /// At most 400 characters.
    pub description: Option<String>,
    /// Every room manager may install it (default false: only the owner).
    pub public: Option<bool>,
    /// Decimal permission mask for the add flow, without `administrator` (default "0").
    pub requested_permissions: Option<String>,
    /// Upper bound of the tokens' scopes (default: all scopes).
    pub scopes: Option<Vec<String>>,
}

/// Create an application with its bot account (APPLICATIONS.md §1.3).
#[utoipa::path(post, path = "/api/v1/applications", security(("bearer" = [])), request_body = CreateApplicationRequest,
    responses((status = 201, body = Application), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<CreateApplicationRequest>,
) -> Result<(StatusCode, Json<Application>), ApiError> {
    require_person(&auth)?;
    let name = app_name(&req.name)?;
    let description = description(req.description.as_deref().unwrap_or(""))?;
    let perms = requested_permissions(req.requested_permissions.as_deref().unwrap_or("0"))?;
    let scopes = match &req.scopes {
        Some(s) => apps::parse_scopes(s)?,
        None => p::all_scopes(),
    };
    let username = match req.username.as_deref().map(|u| u.trim().to_lowercase()) {
        Some(u) if !util::valid_username(&u) => {
            return Err(bad("validation.username", "username: 2–32 characters of a-z 0-9 _ . -"));
        }
        other => other,
    };
    may_own_another(&state, &auth.user).await?;
    state.app_create_limiter.check_all(&[format!("app-create:{}", auth.user.id)]).await?;

    let domain = state.config.domain.clone();
    let candidates: Vec<String> = match &username {
        Some(u) => vec![u.clone()],
        None => {
            let base = derive_username(&name);
            std::iter::once(base.clone()).chain((2..=50).map(|n| format!("{base}-{n}"))).collect()
        }
    };
    let mut created = None;
    for candidate in candidates {
        if util::reserved_username(&candidate) {
            if username.is_some() {
                return Err(ApiError::conflict("app.username_taken", "This username is reserved"));
            }
            continue;
        }
        if store::applications::username_taken(&state.db, &candidate, &domain).await? {
            continue;
        }
        let new = store::applications::NewApplication {
            username: &candidate,
            domain: &domain,
            name: &name,
            description: &description,
            public: req.public.unwrap_or(false),
            requested_permissions: perms,
            scopes: &scopes,
            owner: &auth.user,
        };
        if let Some(app) = store::applications::create(&state.db, new).await? {
            created = Some(app);
            break;
        }
    }
    let Some(app) = created else {
        return Err(ApiError::conflict("app.username_taken", "This username is taken"));
    };
    if !description.is_empty() {
        let update = store::users::ProfileUpdate { bio: Some(&description), ..Default::default() };
        store::users::update_profile_fields(&state.db, &app.bot_user_id, update).await?;
    }
    if state.config.app_creation == AppCreation::Invite && !auth.user.is_node_admin() {
        store::applications::consume_creation_grant(&state.db, &auth.user.id).await?;
    }
    audit(&state, &auth.user, "app.create", &app, json!({ "name": app.name })).await?;
    tracing::info!(application = app.id, owner = auth.user.address(), "application created");
    Ok((StatusCode::CREATED, Json(view(&state, &app, true).await?)))
}

/// The caller's applications.
#[utoipa::path(get, path = "/api/v1/applications", security(("bearer" = [])), responses((status = 200, body = Vec<Application>), (status = 403, body = ProblemDetails)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<Application>>, ApiError> {
    require_person(&auth)?;
    let mut out = Vec::new();
    for app in store::applications::of_owner(&state.db, &auth.user.id).await? {
        out.push(view(&state, &app, true).await?);
    }
    Ok(Json(out))
}

/// Transfers of applications offered to the caller (accept or decline them).
#[utoipa::path(get, path = "/api/v1/applications/transfers", security(("bearer" = [])), responses((status = 200, body = Vec<IncomingTransfer>)))]
pub async fn incoming_transfers(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<IncomingTransfer>>, ApiError> {
    require_person(&auth)?;
    let mut out = Vec::new();
    for t in store::applications::transfers_to(&state.db, &auth.user.id).await? {
        let Some(app) = store::applications::by_id(&state.db, &t.application_id).await? else { continue };
        let (Some(bot), Some(from)) = (
            store::users::by_id(&state.db, &app.bot_user_id).await?,
            store::users::by_id(&state.db, &t.from_user_id).await?,
        ) else {
            continue;
        };
        out.push(IncomingTransfer {
            application_id: app.id.clone(),
            name: app.name.clone(),
            bot: bot.to_public(),
            from: from.address(),
            created_at: t.created_at,
            expires_at: t.expires_at,
        });
    }
    Ok(Json(out))
}

/// One of the caller's applications.
#[utoipa::path(get, path = "/api/v1/applications/{application_id}", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 200, body = Application), (status = 404, body = ProblemDetails)))]
pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Application>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    Ok(Json(view(&state, &app, true).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateApplicationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub public: Option<bool>,
    pub requested_permissions: Option<String>,
    /// Narrowing the scopes narrows every token at once (effective scopes = token ∩ application).
    pub scopes: Option<Vec<String>>,
    /// At most 10 `https://` origins for the local activity bridge (§7.3).
    pub rpc_origins: Option<Vec<String>>,
    /// The bot's "who can message me": friends | everyone_shared | everyone.
    pub dm_policy: Option<String>,
    /// `https://` URL that receives command invocations instead of the WebSocket (APPLICATIONS.md §5.6); verified
    /// with a ping first (§6.3, `app.url_verification_failed`); null removes it.
    #[serde(default, with = "crate::serde_with_double_option")]
    #[schema(value_type = Option<String>)]
    pub interactions_url: Option<Option<String>>,
}

/// Change an application (owner).
#[utoipa::path(patch, path = "/api/v1/applications/{application_id}", security(("bearer" = [])), params(("application_id" = String, Path)), request_body = UpdateApplicationRequest,
    responses((status = 200, body = Application), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UpdateApplicationRequest>,
) -> Result<Json<Application>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let name = req.name.as_deref().map(app_name).transpose()?;
    let description = req.description.as_deref().map(description).transpose()?;
    let perms = req.requested_permissions.as_deref().map(requested_permissions).transpose()?;
    let scopes = req.scopes.as_deref().map(apps::parse_scopes).transpose()?;
    let origins = req.rpc_origins.as_deref().map(rpc_origins).transpose()?;
    let dm_policy = req.dm_policy.as_deref().map(|d| validate::one_of("dm_policy", d, &DmPolicy::ALL)).transpose()?;
    // The interactions URL must answer the verification ping (§6.3) before it is stored.
    if let Some(Some(raw)) = &req.interactions_url {
        let url = state.hooks.check_url(raw.trim())?;
        state.app_commands_limiter.check_all(&[format!("app-url:{}", app.id)])?;
        crate::hooks::verify_url(&state, &app.id, &url).await?;
        store::commands::set_interactions_url(&state.db, &app.id, Some(url.as_str())).await?;
    } else if let Some(None) = &req.interactions_url {
        store::commands::set_interactions_url(&state.db, &app.id, None).await?;
    }
    store::applications::update(
        &state.db,
        &app,
        store::applications::ApplicationUpdate {
            name: name.as_deref(),
            description: description.as_deref(),
            public: req.public,
            requested_permissions: perms,
            scopes: scopes.as_deref(),
            rpc_origins: origins.as_deref(),
        },
    )
    .await?;
    if description.is_some() || dm_policy.is_some() {
        let update = store::users::ProfileUpdate {
            bio: description.as_deref(),
            dm_policy: dm_policy.as_deref(),
            ..Default::default()
        };
        store::users::update_profile_fields(&state.db, &app.bot_user_id, update).await?;
    }
    if name.is_some() || description.is_some() {
        profile::announce_user(&state, &app.bot_user_id).await?;
    }
    // Narrowed scopes apply at once: open WebSockets reconnect with the new effective scopes.
    if let Some(new) = &scopes
        && app.scopes().iter().any(|s| !new.contains(s))
    {
        apps::close_bot(&state, &app.bot_user_id).await?;
    }
    let changed: Vec<&str> = [
        ("name", req.name.is_some()),
        ("description", req.description.is_some()),
        ("public", req.public.is_some()),
        ("requested_permissions", req.requested_permissions.is_some()),
        ("scopes", req.scopes.is_some()),
        ("rpc_origins", req.rpc_origins.is_some()),
        ("dm_policy", req.dm_policy.is_some()),
        ("interactions_url", req.interactions_url.is_some()),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect();
    audit(&state, &auth.user, "app.update", &app, json!({ "changed": changed })).await?;
    let app = owned(&state, &auth, &id).await?;
    // Room nodes refetch the public document (APPLICATIONS.md §4.5).
    if name.is_some() || perms.is_some() || scopes.is_some() {
        crate::installations::changed(&state, &app, false).await;
    }
    Ok(Json(view(&state, &app, true).await?))
}

/// Set the bot's avatar (raw body, media pipeline of PROTOCOL.md §6b, 256 × 256 avatar rules).
#[utoipa::path(put, path = "/api/v1/applications/{application_id}/avatar", security(("bearer" = [])), params(("application_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 200, body = Application), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Application>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let bytes = crate::routes::profile::read_upload(&state, &auth, &headers, body).await?;
    let stored = profile::convert_and_store(&state, MediaKind::Avatar, &app.bot_user_id, bytes).await?;
    profile::set_user_media(&state, &app.bot_user_id, MediaKind::Avatar, Some(&stored)).await?;
    profile::announce_user(&state, &app.bot_user_id).await?;
    audit(&state, &auth.user, "app.update", &app, json!({ "changed": ["avatar"] })).await?;
    crate::installations::changed(&state, &app, false).await;
    Ok(Json(view(&state, &app, true).await?))
}

/// Remove the bot's avatar.
#[utoipa::path(delete, path = "/api/v1/applications/{application_id}/avatar", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 200, body = Application), (status = 404, body = ProblemDetails)))]
pub async fn delete_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Application>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    profile::set_user_media(&state, &app.bot_user_id, MediaKind::Avatar, None).await?;
    profile::announce_user(&state, &app.bot_user_id).await?;
    crate::installations::changed(&state, &app, false).await;
    Ok(Json(view(&state, &app, true).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteApplicationRequest {
    /// Must equal the application's current name.
    pub name: String,
}

/// Delete an application (§1.7): tokens, devices and memberships go; the bot stays as a tombstone.
#[utoipa::path(delete, path = "/api/v1/applications/{application_id}", security(("bearer" = [])), params(("application_id" = String, Path)), request_body = DeleteApplicationRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<DeleteApplicationRequest>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    if req.name.trim() != app.name {
        return Err(bad("app.name_confirm", "Type the application's name to confirm"));
    }
    apps::delete_application(&state, &app, &auth.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- transfer

#[derive(Deserialize, ToSchema)]
pub struct TransferRequest {
    /// Local username of the new owner.
    pub to: String,
}

fn transfer_target_invalid(detail: &str) -> ApiError {
    bad("app.transfer_target_invalid", detail.to_string())
}

/// Offer the application to another local user (pending for 7 days, one at a time).
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/transfer", security(("bearer" = [])), params(("application_id" = String, Path)), request_body = TransferRequest,
    responses((status = 202), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn start_transfer(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<TransferRequest>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    if store::applications::transfer(&state.db, &app.id).await?.is_some() {
        return Err(ApiError::conflict("app.transfer_pending", "A transfer of this application is pending"));
    }
    let username = req.to.trim().to_lowercase();
    let username = username.strip_suffix(&format!("@{}", state.config.domain)).unwrap_or(&username).to_string();
    let target = store::users::by_username(&state.db, &username, &state.config.domain)
        .await?
        .filter(|u| u.disabled_at.is_none() && !u.is_bot() && u.id != auth.user.id)
        .ok_or_else(|| transfer_target_invalid("No other active local user with this name"))?;
    may_own_another(&state, &target)
        .await
        .map_err(|_| transfer_target_invalid("This user cannot own another application"))?;
    store::applications::create_transfer(&state.db, &app, &target.id, apps::TRANSFER_TTL_SECS).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Cancel the pending transfer (owner).
#[utoipa::path(delete, path = "/api/v1/applications/{application_id}/transfer", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn cancel_transfer(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    if !store::applications::delete_transfer(&state.db, &app.id).await? {
        return Err(ApiError::NotFound { code: "app.transfer_not_found", what: "Transfer".into() });
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The pending transfer of `{id}` to the caller (`404 app.transfer_not_found` otherwise).
async fn offered(state: &AppState, auth: &AuthUser, id: &str) -> Result<ApplicationRow, ApiError> {
    let not_found = || ApiError::NotFound { code: "app.transfer_not_found", what: "Transfer".into() };
    if !util::is_ulid(id) {
        return Err(not_found());
    }
    let transfer = store::applications::transfer(&state.db, id).await?.ok_or_else(not_found)?;
    if transfer.to_user_id != auth.user.id {
        return Err(not_found());
    }
    store::applications::by_id(&state.db, id)
        .await?
        .filter(|a| a.owner_id == transfer.from_user_id)
        .ok_or_else(not_found)
}

/// Accept a transfer: the application becomes the caller's; every token and device of the bot is revoked
/// and its identity reset, so the new owner starts with fresh credentials.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/transfer/accept", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 200, body = Application), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn accept_transfer(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Application>, ApiError> {
    require_person(&auth)?;
    let app = offered(&state, &auth, &id).await?;
    may_own_another(&state, &auth.user)
        .await
        .map_err(|_| transfer_target_invalid("You cannot own another application"))?;
    let previous = store::users::by_id(&state.db, &app.owner_id).await?.map(|u| u.address()).unwrap_or_default();
    revoke_all(&state, &app).await?;
    reset_identity(&state, &app).await?;
    // The previous owner chose where events go: the new owner configures the subscription anew (§6.2).
    store::subscriptions::delete(&state.db, &app.id).await?;
    store::applications::complete_transfer(&state.db, &app, &auth.user).await?;
    if state.config.app_creation == AppCreation::Invite && !auth.user.is_node_admin() {
        store::applications::consume_creation_grant(&state.db, &auth.user.id).await?;
    }
    audit(&state, &auth.user, "app.transfer", &app, json!({ "from": previous, "to": auth.user.address() })).await?;
    let app = store::applications::by_id(&state.db, &id).await?.ok_or_else(apps::not_found)?;
    Ok(Json(view(&state, &app, true).await?))
}

/// Decline a transfer offered to the caller.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/transfer/decline", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn decline_transfer(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = offered(&state, &auth, &id).await?;
    store::applications::delete_transfer(&state.db, &app.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every token and device of the bot goes (transfer).
async fn revoke_all(state: &AppState, app: &ApplicationRow) -> Result<(), ApiError> {
    let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { return Ok(()) };
    let devices = store::applications::revoke_all_tokens(&state.db, app).await?;
    for device in &devices {
        crate::e2ee::device_removed(state, &bot, device).await?;
    }
    apps::close_devices(state, devices);
    crate::federation::remote::revoke_sessions(state, &bot, None).await?;
    crate::federation::remote::devices_changed(state, &bot).await?;
    Ok(())
}

// ---------------------------------------------------------------- identity reset (§3.4)

async fn reset_identity(state: &AppState, app: &ApplicationRow) -> Result<(), ApiError> {
    let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { return Ok(()) };
    let reset_at = store::applications::clear_identity(&state.db, &bot.id).await?;
    let mut recipients = store::social::contact_ids(&state.db, &bot.id).await?;
    recipients.push(bot.id.clone());
    recipients.push(app.owner_id.clone());
    state.hub.users(
        recipients,
        "identity.changed",
        json!({ "user": bot.address(), "user_id": bot.id, "identity_reset_at": reset_at, "at": util::now() }),
    );
    crate::e2ee::identity_reset(state, &bot).await?;
    // Other nodes refetch the keys and see no attested device; the new key follows with `identity.changed`
    // when the bot sets it (`PUT /users/me/identity`, APPLICATIONS.md §12).
    crate::federation::remote::devices_changed(state, &bot).await?;
    Ok(())
}

/// Reset the bot's identity (lost or leaked key file): its identity key, device attestations, KeyPackages
/// and backups are deleted; the bot process sets a new key on its next start.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/identity/reset", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn identity_reset(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    reset_identity(&state, &app).await?;
    audit(&state, &auth.user, "app.identity_reset", &app, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- tokens (§2.2)

#[derive(Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    /// 1–64 characters, also the name of the bot device.
    pub name: String,
    /// ⊆ the application's scopes (default: all of them).
    pub scopes: Option<Vec<String>>,
    /// 1 to `TAVRN_APP_TOKEN_MAX_DAYS` (default the maximum).
    pub expires_in_days: Option<i64>,
}

fn lifetime_days(state: &AppState, days: Option<i64>) -> Result<i64, ApiError> {
    let max = i64::from(state.config.app_token_max_days);
    validate::range("expires_in_days", days.unwrap_or(max), 1, max)
}

async fn owner_address(state: &AppState, app: &ApplicationRow) -> Result<String, ApiError> {
    Ok(store::users::by_id(&state.db, &app.owner_id).await?.map(|o| o.address()).unwrap_or_default())
}

/// Create a token, i.e. a bot device (`409 app.token_limit` beyond 5). The secret is shown once.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/tokens", security(("bearer" = [])), params(("application_id" = String, Path)), request_body = CreateTokenRequest,
    responses((status = 201, body = TokenSecret), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create_token(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CreateTokenRequest>,
) -> Result<(StatusCode, Json<TokenSecret>), ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let name = validate::name("name", &req.name, 64)?;
    let app_scopes = app.scopes();
    let scopes = match &req.scopes {
        Some(s) => {
            let s = apps::parse_scopes(s)?;
            if let Some(extra) = s.iter().find(|x| !app_scopes.contains(x)) {
                return Err(bad("app.scope_invalid", format!("The application does not allow the scope {extra}")));
            }
            s
        }
        None => app_scopes,
    };
    let days = lifetime_days(&state, req.expires_in_days)?;
    if store::applications::count_tokens(&state.db, &app.id).await? >= apps::MAX_TOKENS {
        return Err(ApiError::Conflict {
            code: "app.token_limit",
            detail: format!("At most {} tokens per application", apps::MAX_TOKENS),
            meta: json!({ "max": apps::MAX_TOKENS }),
        });
    }
    state.app_token_limiter.check_all(&[format!("app-token:{}", app.id)]).await?;
    let (token_id, device_id) = (util::ulid(), util::ulid());
    let issued = apps::issue_token(&state, &app, &owner_address(&state, &app).await?, &device_id, &scopes, days)?;
    store::applications::create_token(
        &state.db,
        store::applications::NewToken {
            id: &token_id,
            application_id: &app.id,
            bot_user_id: &app.bot_user_id,
            name: &name,
            scopes: &scopes,
            jti: &issued.jti,
            token_hash: &issued.hash,
            expires_at: &issued.expires_at,
        },
        &device_id,
    )
    .await?;
    audit(
        &state,
        &auth.user,
        "app.token_create",
        &app,
        json!({ "token": token_id, "name": name, "device": device_id }),
    )
    .await?;
    let row = store::applications::token(&state.db, &app.id, &token_id).await?.ok_or_else(apps::not_found)?;
    Ok((StatusCode::CREATED, Json(TokenSecret { token: AppToken::of(&row), secret: issued.secret })))
}

/// The application's tokens (never their secrets).
#[utoipa::path(get, path = "/api/v1/applications/{application_id}/tokens", security(("bearer" = [])), params(("application_id" = String, Path)),
    responses((status = 200, body = Vec<AppToken>), (status = 404, body = ProblemDetails)))]
pub async fn list_tokens(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Vec<AppToken>>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    Ok(Json(store::applications::tokens(&state.db, &app.id).await?.iter().map(AppToken::of).collect()))
}

#[derive(Deserialize, ToSchema, Default)]
pub struct ResetTokenRequest {
    pub expires_in_days: Option<i64>,
}

fn token_not_found() -> ApiError {
    ApiError::NotFound { code: "app.token_not_found", what: "Token".into() }
}

/// Reset a token: same device, new secret; the old secret is invalid at once and open WebSockets close.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/tokens/{token_id}/reset", security(("bearer" = [])),
    params(("application_id" = String, Path), ("token_id" = String, Path)), request_body = ResetTokenRequest,
    responses((status = 200, body = TokenSecret), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn reset_token(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, token_id)): Path<(String, String)>,
    body: Option<Json<ResetTokenRequest>>,
) -> Result<Json<TokenSecret>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let req = body.map(|b| b.0).unwrap_or_default();
    let row = store::applications::token(&state.db, &app.id, &token_id).await?.ok_or_else(token_not_found)?;
    let days = lifetime_days(&state, req.expires_in_days)?;
    state.app_token_limiter.check_all(&[format!("app-token:{}", app.id)]).await?;
    let issued =
        apps::issue_token(&state, &app, &owner_address(&state, &app).await?, &row.device_id, &row.scopes(), days)?;
    store::applications::reset_token(&state.db, &row.id, &issued.jti, &issued.hash, &issued.expires_at).await?;
    apps::close_devices(&state, vec![row.device_id.clone()]);
    audit(
        &state,
        &auth.user,
        "app.token_reset",
        &app,
        json!({ "token": row.id, "name": row.name, "device": row.device_id }),
    )
    .await?;
    let row = store::applications::token(&state.db, &app.id, &token_id).await?.ok_or_else(token_not_found)?;
    Ok(Json(TokenSecret { token: AppToken::of(&row), secret: issued.secret }))
}

/// Revoke a token: the token and its device are deleted (`devices.changed`, `mls.remove_needed`).
#[utoipa::path(delete, path = "/api/v1/applications/{application_id}/tokens/{token_id}", security(("bearer" = [])),
    params(("application_id" = String, Path), ("token_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn revoke_token(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, token_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let row = store::applications::token(&state.db, &app.id, &token_id).await?.ok_or_else(token_not_found)?;
    let Some(device) = store::applications::revoke_token(&state.db, &app.id, &row.id).await? else {
        return Err(token_not_found());
    };
    if let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? {
        crate::e2ee::device_removed(&state, &bot, &device).await?;
        crate::federation::remote::revoke_sessions(&state, &bot, Some(&device)).await?;
        crate::federation::remote::devices_changed(&state, &bot).await?;
    }
    apps::close_devices(&state, vec![device.clone()]);
    audit(&state, &auth.user, "app.token_revoke", &app, json!({ "token": row.id, "name": row.name, "device": device }))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- the bot itself

/// The caller's application context (app tokens of this node only).
pub(crate) fn bot_context(auth: &AuthUser) -> Result<&AppPrincipal, ApiError> {
    match &auth.app {
        Some(app) if app.token_id.is_some() && !auth.is_remote() => Ok(app),
        _ => Err(apps::not_found()),
    }
}

/// The bot's own application (with an app token).
#[utoipa::path(get, path = "/api/v1/applications/me", security(("bearer" = [])), responses((status = 200, body = Application), (status = 404, body = ProblemDetails)))]
pub async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Application>, ApiError> {
    let ctx = bot_context(&auth)?;
    let app = store::applications::by_id(&state.db, &ctx.application_id).await?.ok_or_else(apps::not_found)?;
    Ok(Json(view(&state, &app, false).await?))
}

/// Rotate the calling token (once per 24 hours): same token row and device, new secret with the same
/// lifetime; the previous secret stays valid for 24 hours so a bot can restart with the new one.
#[utoipa::path(post, path = "/api/v1/applications/me/tokens/rotate", security(("bearer" = [])),
    responses((status = 200, body = RotatedToken), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn rotate(State(state): State<AppState>, auth: AuthUser) -> Result<Json<RotatedToken>, ApiError> {
    let ctx = bot_context(&auth)?;
    let token_id = ctx.token_id.clone().unwrap_or_default();
    let app = store::applications::by_id(&state.db, &ctx.application_id).await?.ok_or_else(apps::not_found)?;
    let row = store::applications::token(&state.db, &app.id, &token_id).await?.ok_or_else(token_not_found)?;
    state.app_rotate_limiter.check_all(&[format!("rotate:{}", row.id)]).await?;
    let lifetime_days = ctx.lifetime_secs.map_or(i64::from(state.config.app_token_max_days), |s| (s / 86_400).max(1));
    let days = lifetime_days.min(i64::from(state.config.app_token_max_days));
    let issued =
        apps::issue_token(&state, &app, &owner_address(&state, &app).await?, &row.device_id, &row.scopes(), days)?;
    store::applications::rotate_token(
        &state.db,
        &row,
        &issued.jti,
        &issued.hash,
        &issued.expires_at,
        apps::ROTATION_OVERLAP_SECS,
    )
    .await?;
    tracing::info!(application = app.id, token = row.id, "app token rotated");
    Ok(Json(RotatedToken { secret: issued.secret, expires_at: issued.expires_at }))
}

#[derive(Deserialize, Default)]
pub struct DevNotifyExpiring {
    /// The time the housekeeping pretends it is (RFC 3339); default now.
    pub now: Option<String>,
}

/// Development nodes only (not in the API description): runs the hourly `application.token_expiring` housekeeping
/// (APPLICATIONS.md §2.2) at once, so SDK and e2e tests can watch the event. Answers the number of notices.
pub async fn dev_notify_expiring_tokens(
    State(state): State<AppState>,
    body: Option<Json<DevNotifyExpiring>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.config.dev {
        return Err(ApiError::NotFound { code: "route.not_found", what: "Route".into() });
    }
    let now = match body.and_then(|Json(b)| b.now) {
        Some(t) => chrono::DateTime::parse_from_rfc3339(&t)
            .map_err(|_| bad("validation.time", "now must be an RFC 3339 time"))?
            .with_timezone(&chrono::Utc),
        None => chrono::Utc::now(),
    };
    let sent = apps::notify_expiring_tokens(&state, now).await?;
    Ok(Json(json!({ "sent": sent })))
}
