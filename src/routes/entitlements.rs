// SPDX-License-Identifier: AGPL-3.0-only
//! Entitlements API (`protocol/ENTITLEMENTS.md`): plans, grants and effective values
//! for node admins (`/admin/entitlements/*`), admin API tokens (`/admin/tokens`), and the requester's own
//! effective values (`/users/me/entitlements`). Every change is written to the node's audit log.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, patch},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access,
    admin_tokens::{self, SCOPES},
    app::AppState,
    auth::{AuthUser, NodeAdmin},
    entitlements::{self, Entitlements, Limits, SubjectKind},
    error::{ApiError, ApiJson, ProblemDetails},
    models::UserRow,
    store::{self, entitlements as db},
    util,
    validate::{self, bad},
};

pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route("/admin/entitlements/keys", get(keys))
        .route("/admin/entitlements/plans", get(list_plans).post(create_plan).layer(small()))
        .route("/admin/entitlements/plans/{plan_id}", patch(update_plan).delete(delete_plan).layer(small()))
        .route("/admin/entitlements/grants", get(list_grants).post(create_grant).layer(small()))
        .route("/admin/entitlements/grants/{grant_id}", patch(update_grant).delete(delete_grant).layer(small()))
        .route("/admin/entitlements/effective", get(effective))
        .route("/admin/tokens", get(list_tokens).post(create_token).layer(small()))
        .route("/admin/tokens/{token_id}", axum::routing::delete(revoke_token))
        .route("/users/me/entitlements", get(my_entitlements))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        keys,
        list_plans,
        create_plan,
        update_plan,
        delete_plan,
        list_grants,
        create_grant,
        update_grant,
        delete_grant,
        effective,
        list_tokens,
        create_token,
        revoke_token,
        my_entitlements
    ),
    components(schemas(
        KeyInfo,
        Plan,
        CreatePlanRequest,
        UpdatePlanRequest,
        Grant,
        CreateGrantRequest,
        UpdateGrantRequest,
        EffectiveEntitlements,
        AdminToken,
        CreateAdminTokenRequest,
        CreatedAdminToken,
        MyEntitlements
    ))
)]
pub struct EntitlementsApi;

fn not_found(what: &str, code: &'static str) -> ApiError {
    ApiError::NotFound { code, what: what.into() }
}

async fn audit(
    state: &AppState,
    admin: &NodeAdmin,
    action: &str,
    target: &str,
    meta: serde_json::Value,
) -> Result<(), ApiError> {
    let mut meta = meta;
    if let (Some(token), Some(obj)) = (admin.token_id(), meta.as_object_mut()) {
        obj.insert("admin_token_id".into(), token.into());
    }
    store::rooms::audit(&state.db, None, Some(&admin.0.user.id), action, target, "", meta).await
}

/// Normalizes an expiry: RFC 3339 in the future (at most 100 years ahead), stored in the node's format.
fn expiry(field: &str, value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    let t = util::parse_time(v).ok_or_else(|| bad("validation.time", format!("{field}: an RFC 3339 timestamp")))?;
    let now = chrono::Utc::now();
    if t <= now {
        return Err(bad("entitlements.expiry_past", format!("{field}: must be in the future")));
    }
    if t > now + chrono::Duration::days(36_500) {
        return Err(bad("validation.range", format!("{field}: at most 100 years ahead")));
    }
    Ok(Some(util::format_time(t)))
}

// ---------------------------------------------------------------- Keys

#[derive(Serialize, ToSchema)]
pub struct KeyInfo {
    pub key: String,
    /// `max` (highest wins, 0 = unlimited), `flag` (0/1) or `shortest_non_zero` (retention).
    pub rule: String,
    /// `user` (the acting user's grants count) or `room` (the room owner's grants count).
    pub scope: String,
    /// Largest value a plan or grant may set.
    pub max: i64,
    /// The node's default (`TAVRN_*`).
    pub node_default: i64,
}

/// The known entitlement keys with their rules and node defaults.
#[utoipa::path(get, path = "/api/v1/admin/entitlements/keys", security(("bearer" = [])),
    responses((status = 200, body = Vec<KeyInfo>), (status = 403, body = ProblemDetails)))]
pub async fn keys(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<Vec<KeyInfo>>, ApiError> {
    Ok(Json(
        entitlements::KEYS
            .iter()
            .map(|d| KeyInfo {
                key: d.key.into(),
                rule: match d.rule {
                    entitlements::Rule::Max => "max",
                    entitlements::Rule::Flag => "flag",
                    entitlements::Rule::ShortestNonZero => "shortest_non_zero",
                }
                .into(),
                scope: match d.scope {
                    entitlements::Scope::User => "user",
                    entitlements::Scope::Room => "room",
                }
                .into(),
                max: d.max,
                node_default: entitlements::node_default(&state.config, d.key),
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------- Plans

#[derive(Serialize, ToSchema)]
pub struct Plan {
    pub id: String,
    pub name: String,
    /// Key → integer (0 = unlimited unless the key says otherwise).
    pub limits: Limits,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Grants that use the plan (expired ones included until housekeeping removes them).
    pub grants: i64,
}

async fn plan_api(state: &AppState, row: db::PlanRow) -> Result<Plan, ApiError> {
    Ok(Plan {
        grants: db::plan_in_use(&state.db, &row.id).await?,
        limits: entitlements::limits_from_text(&row.limits),
        id: row.id,
        name: row.name,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// All plans, by name.
#[utoipa::path(get, path = "/api/v1/admin/entitlements/plans", security(("bearer" = [])),
    responses((status = 200, body = Vec<Plan>), (status = 403, body = ProblemDetails)))]
pub async fn list_plans(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<Vec<Plan>>, ApiError> {
    let mut out = Vec::new();
    for row in db::plans(&state.db).await? {
        out.push(plan_api(&state, row).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePlanRequest {
    /// Unique, 1–100 characters.
    pub name: String,
    /// Key → integer; known keys only.
    #[schema(value_type = Object)]
    pub limits: serde_json::Value,
}

/// Create a plan.
#[utoipa::path(post, path = "/api/v1/admin/entitlements/plans", security(("bearer" = [])), request_body = CreatePlanRequest,
    responses((status = 201, body = Plan), (status = 400, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create_plan(
    State(state): State<AppState>,
    admin: NodeAdmin,
    ApiJson(req): ApiJson<CreatePlanRequest>,
) -> Result<(StatusCode, Json<Plan>), ApiError> {
    let name = validate::name("name", &req.name, 100)?;
    let limits = entitlements::parse_limits("limits", &req.limits)?;
    if db::plan_count(&state.db).await? >= db::MAX_PLANS {
        return Err(ApiError::conflict("entitlements.too_many_plans", format!("At most {} plans", db::MAX_PLANS)));
    }
    let row = db::create_plan(&state.db, &name, &limits, &admin.0.user.id)
        .await?
        .ok_or_else(|| ApiError::conflict("entitlements.plan_name_taken", "A plan with this name exists"))?;
    audit(&state, &admin, "entitlements.plan_create", &row.id, serde_json::json!({ "name": name, "limits": limits }))
        .await?;
    Ok((StatusCode::CREATED, Json(plan_api(&state, row).await?)))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdatePlanRequest {
    pub name: Option<String>,
    /// Replaces all limits of the plan.
    #[schema(value_type = Option<Object>)]
    pub limits: Option<serde_json::Value>,
}

/// Rename a plan or replace its limits (every grant using it changes with it).
#[utoipa::path(patch, path = "/api/v1/admin/entitlements/plans/{plan_id}", security(("bearer" = [])),
    params(("plan_id" = String, Path)), request_body = UpdatePlanRequest,
    responses((status = 200, body = Plan), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update_plan(
    State(state): State<AppState>,
    admin: NodeAdmin,
    Path(plan_id): Path<String>,
    ApiJson(req): ApiJson<UpdatePlanRequest>,
) -> Result<Json<Plan>, ApiError> {
    validate::ulid("plan_id", &plan_id)?;
    db::plan(&state.db, &plan_id).await?.ok_or_else(|| not_found("Plan", "entitlements.plan_not_found"))?;
    let name = req.name.as_deref().map(|n| validate::name("name", n, 100)).transpose()?;
    let limits = req.limits.as_ref().map(|l| entitlements::parse_limits("limits", l)).transpose()?;
    if !db::update_plan(&state.db, &plan_id, name.as_deref(), limits.as_ref()).await? {
        return Err(ApiError::conflict("entitlements.plan_name_taken", "A plan with this name exists"));
    }
    audit(&state, &admin, "entitlements.plan_update", &plan_id, serde_json::json!({ "name": name, "limits": limits }))
        .await?;
    let row = db::plan(&state.db, &plan_id).await?.ok_or_else(|| not_found("Plan", "entitlements.plan_not_found"))?;
    Ok(Json(plan_api(&state, row).await?))
}

/// Delete a plan that no grant uses (`409 entitlements.plan_in_use` otherwise).
#[utoipa::path(delete, path = "/api/v1/admin/entitlements/plans/{plan_id}", security(("bearer" = [])),
    params(("plan_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn delete_plan(
    State(state): State<AppState>,
    admin: NodeAdmin,
    Path(plan_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate::ulid("plan_id", &plan_id)?;
    let plan = db::plan(&state.db, &plan_id).await?.ok_or_else(|| not_found("Plan", "entitlements.plan_not_found"))?;
    let used = db::plan_in_use(&state.db, &plan_id).await?;
    if used > 0 {
        return Err(ApiError::Conflict {
            code: "entitlements.plan_in_use",
            detail: format!("{used} grants use this plan"),
            meta: serde_json::json!({ "grants": used }),
        });
    }
    db::delete_plan(&state.db, &plan_id).await?;
    audit(&state, &admin, "entitlements.plan_delete", &plan_id, serde_json::json!({ "name": plan.name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Grants

#[derive(Serialize, ToSchema)]
pub struct Grant {
    pub id: String,
    /// `user:<id>` or `room:<id>`.
    pub subject: String,
    pub subject_kind: String,
    pub subject_id: String,
    /// The user's address or the room's name (empty when the subject no longer exists).
    pub subject_label: String,
    pub plan_id: Option<String>,
    pub plan_name: Option<String>,
    /// Per-key values on top of the plan.
    pub overrides: Limits,
    /// Resolved values (plan + overrides).
    pub values: Limits,
    pub expires_at: Option<String>,
    pub expired: bool,
    pub note: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

async fn grants_api(state: &AppState, rows: Vec<db::GrantRow>) -> Result<Vec<Grant>, ApiError> {
    let user_ids: Vec<String> =
        rows.iter().filter(|g| g.subject_kind == "user").map(|g| g.subject_id.clone()).collect();
    let users = store::users::by_ids(&state.db, &user_ids).await?;
    let mut rooms = std::collections::HashMap::new();
    for g in rows.iter().filter(|g| g.subject_kind == "room") {
        if !rooms.contains_key(&g.subject_id)
            && let Some(r) = store::rooms::room_by_id(&state.db, &g.subject_id).await?
        {
            rooms.insert(g.subject_id.clone(), r.name);
        }
    }
    let plans: std::collections::HashMap<String, Limits> =
        db::plans(&state.db).await?.into_iter().map(|p| (p.id, entitlements::limits_from_text(&p.limits))).collect();
    let now = util::now();
    Ok(rows
        .into_iter()
        .map(|g| {
            let label = if g.subject_kind == "user" {
                users.iter().find(|u| u.id == g.subject_id).map(UserRow::address).unwrap_or_default()
            } else {
                rooms.get(&g.subject_id).cloned().unwrap_or_default()
            };
            let overrides = entitlements::limits_from_text(&g.overrides);
            let plan = g.plan_id.as_ref().and_then(|p| plans.get(p)).cloned().unwrap_or_default();
            Grant {
                subject: format!("{}:{}", g.subject_kind, g.subject_id),
                values: entitlements::merge(&plan, &overrides),
                expired: !entitlements::is_active(g.expires_at.as_deref(), &now),
                subject_label: label,
                overrides,
                id: g.id,
                subject_kind: g.subject_kind,
                subject_id: g.subject_id,
                plan_id: g.plan_id,
                plan_name: g.plan_name,
                expires_at: g.expires_at,
                note: g.note,
                created_by: g.created_by,
                created_at: g.created_at,
                updated_at: g.updated_at,
            }
        })
        .collect())
}

async fn grant_api(state: &AppState, id: &str) -> Result<Grant, ApiError> {
    let row = db::grant(&state.db, id).await?.ok_or_else(|| not_found("Grant", "entitlements.grant_not_found"))?;
    grants_api(state, vec![row]).await?.pop().ok_or_else(|| not_found("Grant", "entitlements.grant_not_found"))
}

/// Resolves `user:<id or address>` or `room:<id>` to a subject of this node. Grants exist for local users and
/// rooms only: a grant can never extend what a user of another node may do on that node.
async fn resolve_subject(state: &AppState, subject: &str) -> Result<(SubjectKind, String), ApiError> {
    let invalid = || bad("entitlements.subject_invalid", "subject: user:<id or address> or room:<id>");
    let (kind, value) = subject.trim().split_once(':').ok_or_else(invalid)?;
    match SubjectKind::parse(kind).ok_or_else(invalid)? {
        SubjectKind::User => Ok((SubjectKind::User, local_user(state, value).await?.id)),
        SubjectKind::Room => {
            validate::ulid("room", value)?;
            let room =
                store::rooms::room_by_id(&state.db, value).await?.ok_or_else(|| not_found("Room", "room.not_found"))?;
            Ok((SubjectKind::Room, room.id))
        }
    }
}

/// A local user by id or address (`alice` or `alice@<this domain>`).
async fn local_user(state: &AppState, value: &str) -> Result<UserRow, ApiError> {
    let value = value.trim();
    let user = if util::is_ulid(value) {
        store::users::by_id(&state.db, value).await?
    } else {
        let (name, domain) = util::parse_address(value).unwrap_or((value, state.config.domain.as_str()));
        if domain != state.config.domain {
            return Err(bad("entitlements.subject_not_local", "Grants are for users of this node only"));
        }
        store::users::by_username(&state.db, &name.to_lowercase(), domain).await?
    };
    let user = user.ok_or_else(|| not_found("User", "user.not_found"))?;
    if user.domain != state.config.domain {
        return Err(bad("entitlements.subject_not_local", "Grants are for users of this node only"));
    }
    Ok(user)
}

#[derive(Deserialize, IntoParams)]
pub struct GrantQuery {
    /// `user:<id or address>` or `room:<id>`.
    pub subject: Option<String>,
    /// Include expired grants (kept for a week).
    pub include_expired: Option<bool>,
    /// Page size (default 100, at most 500).
    pub limit: Option<i64>,
    /// Grant id to continue after.
    pub after: Option<String>,
}

/// Grants, optionally of one subject, ordered by id and paged with `after`.
#[utoipa::path(get, path = "/api/v1/admin/entitlements/grants", security(("bearer" = [])), params(GrantQuery),
    responses((status = 200, body = Vec<Grant>), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn list_grants(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<GrantQuery>,
) -> Result<Json<Vec<Grant>>, ApiError> {
    let subject = match q.subject.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(resolve_subject(&state, s).await?),
        None => None,
    };
    let now = util::now();
    let filter = db::GrantFilter {
        subject: subject.as_ref().map(|(k, id)| (*k, id.as_str())),
        include_expired: q.include_expired.unwrap_or(false),
        now: &now,
        after: q.after.as_deref(),
        limit: validate::limit(q.limit, 100, 500),
    };
    let rows = db::grants(&state.db, &filter).await?;
    Ok(Json(grants_api(&state, rows).await?))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantRequest {
    /// `user:<id or address>` (a local user) or `room:<id>`.
    pub subject: String,
    pub plan_id: Option<String>,
    /// Key → integer on top of the plan.
    #[schema(value_type = Option<Object>)]
    pub overrides: Option<serde_json::Value>,
    /// RFC 3339, in the future; null = no expiry.
    pub expires_at: Option<String>,
    pub note: Option<String>,
}

async fn check_plan(state: &AppState, plan_id: Option<&str>) -> Result<(), ApiError> {
    if let Some(p) = plan_id {
        validate::ulid("plan_id", p)?;
        db::plan(&state.db, p).await?.ok_or_else(|| not_found("Plan", "entitlements.plan_not_found"))?;
    }
    Ok(())
}

/// Grant a plan and/or overrides to a local user or a room.
#[utoipa::path(post, path = "/api/v1/admin/entitlements/grants", security(("bearer" = [])), request_body = CreateGrantRequest,
    responses((status = 201, body = Grant), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create_grant(
    State(state): State<AppState>,
    admin: NodeAdmin,
    ApiJson(req): ApiJson<CreateGrantRequest>,
) -> Result<(StatusCode, Json<Grant>), ApiError> {
    let (kind, subject_id) = resolve_subject(&state, &req.subject).await?;
    let plan_id = req.plan_id.as_deref().map(str::trim).filter(|p| !p.is_empty());
    check_plan(&state, plan_id).await?;
    let overrides = match &req.overrides {
        Some(v) => entitlements::parse_limits("overrides", v)?,
        None => Limits::new(),
    };
    if plan_id.is_none() && overrides.is_empty() {
        return Err(bad("entitlements.grant_empty", "A grant needs a plan or at least one override"));
    }
    let expires_at = expiry("expires_at", req.expires_at.as_deref())?;
    let note = validate::text("note", req.note.as_deref().unwrap_or(""), 0, 500)?;
    let now = util::now();
    if db::active_grant_count(&state.db, kind, &subject_id, &now).await? >= db::MAX_ACTIVE_GRANTS_PER_SUBJECT {
        return Err(ApiError::conflict(
            "entitlements.too_many_grants",
            format!("At most {} active grants per subject", db::MAX_ACTIVE_GRANTS_PER_SUBJECT),
        ));
    }
    let row = db::create_grant(
        &state.db,
        db::NewGrant {
            kind,
            subject_id: &subject_id,
            plan_id,
            overrides: &overrides,
            expires_at: expires_at.as_deref(),
            note: &note,
            created_by: &admin.0.user.id,
        },
    )
    .await?;
    audit(
        &state,
        &admin,
        "entitlements.grant_create",
        &format!("{}:{subject_id}", kind.as_str()),
        serde_json::json!({ "grant_id": row.id, "plan_id": plan_id, "overrides": overrides, "expires_at": expires_at }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(grant_api(&state, &row.id).await?)))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateGrantRequest {
    /// null removes the plan (the grant then needs overrides).
    #[serde(default, with = "crate::serde_with_double_option")]
    #[schema(value_type = Option<String>)]
    pub plan_id: Option<Option<String>>,
    /// Replaces all overrides.
    #[schema(value_type = Option<Object>)]
    pub overrides: Option<serde_json::Value>,
    /// null removes the expiry; a value must be in the future.
    #[serde(default, with = "crate::serde_with_double_option")]
    #[schema(value_type = Option<String>)]
    pub expires_at: Option<Option<String>>,
    pub note: Option<String>,
}

/// Change a grant's plan, overrides, expiry or note (the subject stays).
#[utoipa::path(patch, path = "/api/v1/admin/entitlements/grants/{grant_id}", security(("bearer" = [])),
    params(("grant_id" = String, Path)), request_body = UpdateGrantRequest,
    responses((status = 200, body = Grant), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn update_grant(
    State(state): State<AppState>,
    admin: NodeAdmin,
    Path(grant_id): Path<String>,
    ApiJson(req): ApiJson<UpdateGrantRequest>,
) -> Result<Json<Grant>, ApiError> {
    validate::ulid("grant_id", &grant_id)?;
    let row =
        db::grant(&state.db, &grant_id).await?.ok_or_else(|| not_found("Grant", "entitlements.grant_not_found"))?;
    let plan_id = match req.plan_id {
        Some(p) => p.map(|p| p.trim().to_string()).filter(|p| !p.is_empty()),
        None => row.plan_id.clone(),
    };
    check_plan(&state, plan_id.as_deref()).await?;
    let overrides = match &req.overrides {
        Some(v) => entitlements::parse_limits("overrides", v)?,
        None => entitlements::limits_from_text(&row.overrides),
    };
    if plan_id.is_none() && overrides.is_empty() {
        return Err(bad("entitlements.grant_empty", "A grant needs a plan or at least one override"));
    }
    let expires_at = match &req.expires_at {
        Some(e) => expiry("expires_at", e.as_deref())?,
        None => row.expires_at.clone(),
    };
    let note = match &req.note {
        Some(n) => validate::text("note", n, 0, 500)?,
        None => row.note.clone(),
    };
    db::update_grant(&state.db, &grant_id, plan_id.as_deref(), &overrides, expires_at.as_deref(), &note).await?;
    audit(
        &state,
        &admin,
        "entitlements.grant_update",
        &format!("{}:{}", row.subject_kind, row.subject_id),
        serde_json::json!({ "grant_id": grant_id, "plan_id": plan_id, "overrides": overrides, "expires_at": expires_at }),
    )
    .await?;
    Ok(Json(grant_api(&state, &grant_id).await?))
}

/// Delete a grant.
#[utoipa::path(delete, path = "/api/v1/admin/entitlements/grants/{grant_id}", security(("bearer" = [])),
    params(("grant_id" = String, Path)), responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_grant(
    State(state): State<AppState>,
    admin: NodeAdmin,
    Path(grant_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate::ulid("grant_id", &grant_id)?;
    let row =
        db::grant(&state.db, &grant_id).await?.ok_or_else(|| not_found("Grant", "entitlements.grant_not_found"))?;
    db::delete_grant(&state.db, &grant_id).await?;
    audit(
        &state,
        &admin,
        "entitlements.grant_delete",
        &format!("{}:{}", row.subject_kind, row.subject_id),
        serde_json::json!({ "grant_id": grant_id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Effective values

#[derive(Serialize, ToSchema)]
pub struct EffectiveEntitlements {
    pub user_id: Option<String>,
    pub room_id: Option<String>,
    /// Every key with its effective value.
    pub values: Limits,
    /// The node defaults for comparison.
    pub node_defaults: Limits,
    /// Retention bound of the room without its own setting (node value and room grants); null without a room.
    pub retention_bound_days: Option<i64>,
}

#[derive(Deserialize, IntoParams)]
pub struct EffectiveQuery {
    /// User id or address (local users only).
    pub user: Option<String>,
    /// Room id.
    pub room: Option<String>,
}

/// Effective values for a user and/or a room (room keys are evaluated for the room's owner).
#[utoipa::path(get, path = "/api/v1/admin/entitlements/effective", security(("bearer" = [])), params(EffectiveQuery),
    responses((status = 200, body = EffectiveEntitlements), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn effective(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<EffectiveQuery>,
) -> Result<Json<EffectiveEntitlements>, ApiError> {
    let user = match q.user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => Some(local_user(&state, u).await?),
        None => None,
    };
    let room = match q.room.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => {
            validate::ulid("room", r)?;
            Some(store::rooms::room_by_id(&state.db, r).await?.ok_or_else(|| not_found("Room", "room.not_found"))?)
        }
        None => None,
    };
    if user.is_none() && room.is_none() {
        return Err(bad("entitlements.subject_missing", "Give user and/or room"));
    }
    let e = Entitlements::load(&state, user.as_ref(), room.as_ref()).await?;
    Ok(Json(EffectiveEntitlements {
        user_id: user.map(|u| u.id),
        room_id: room.as_ref().map(|r| r.id.clone()),
        values: e.all(),
        node_defaults: entitlements::node_defaults(&state.config),
        retention_bound_days: room.as_ref().map(|_| e.retention_bound()),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct MyEntitlements {
    /// Every key with its effective value for the requester (and the room, if given).
    pub values: Limits,
    /// Largest upload in bytes here (the ceiling applied; encrypted uploads: minus the 16-byte GCM tag).
    pub upload_max_bytes: u64,
    /// With a room: the shortest retention the room may choose (0 = none); the room setting can only be shorter.
    pub retention_bound_days: Option<i64>,
}

#[derive(Deserialize, IntoParams)]
pub struct MyQuery {
    /// Room id (the requester must be a member).
    pub room: Option<String>,
}

/// The requester's effective entitlements, optionally in a room (clients show limits from it).
#[utoipa::path(get, path = "/api/v1/users/me/entitlements", security(("bearer" = [])), params(MyQuery),
    responses((status = 200, body = MyEntitlements), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn my_entitlements(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<MyQuery>,
) -> Result<Json<MyEntitlements>, ApiError> {
    let room = match q.room.as_deref().filter(|r| !r.is_empty()) {
        Some(r) => {
            validate::ulid("room", r)?;
            Some(access::room_access(&state, r, &auth.user).await?.room)
        }
        None => None,
    };
    let e = Entitlements::load(&state, Some(&auth.user), room.as_ref()).await?;
    Ok(Json(MyEntitlements {
        values: e.all(),
        upload_max_bytes: e.upload_max_bytes(&state.config),
        retention_bound_days: room.as_ref().map(|_| e.retention_bound()),
    }))
}

// ---------------------------------------------------------------- Admin API tokens

#[derive(Serialize, ToSchema)]
pub struct AdminToken {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub expired: bool,
}

impl From<db::AdminTokenRow> for AdminToken {
    fn from(r: db::AdminTokenRow) -> Self {
        Self {
            expired: !entitlements::is_active(r.expires_at.as_deref(), &util::now()),
            scopes: serde_json::from_str(&r.scopes).unwrap_or_default(),
            id: r.id,
            name: r.name,
            created_by: r.created_by,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct CreatedAdminToken {
    #[serde(flatten)]
    pub token: AdminToken,
    /// `tavrn_adm_…`: shown exactly once, only its hash is stored.
    pub secret: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAdminTokenRequest {
    /// 1–100 characters; shown in the audit log with every call.
    pub name: String,
    /// Any of `entitlements`, `users:read`, `users:write`, `invites` (at least one).
    pub scopes: Vec<String>,
    /// RFC 3339 in the future; null = no expiry.
    pub expires_at: Option<String>,
}

/// Admin API tokens (never their secrets).
#[utoipa::path(get, path = "/api/v1/admin/tokens", security(("bearer" = [])),
    responses((status = 200, body = Vec<AdminToken>), (status = 403, body = ProblemDetails)))]
pub async fn list_tokens(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<Vec<AdminToken>>, ApiError> {
    Ok(Json(db::admin_tokens(&state.db).await?.into_iter().map(AdminToken::from).collect()))
}

/// Create an admin API token (session only: tokens cannot create tokens). The secret is returned once.
#[utoipa::path(post, path = "/api/v1/admin/tokens", security(("bearer" = [])), request_body = CreateAdminTokenRequest,
    responses((status = 201, body = CreatedAdminToken), (status = 400, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create_token(
    State(state): State<AppState>,
    admin: NodeAdmin,
    ApiJson(req): ApiJson<CreateAdminTokenRequest>,
) -> Result<(StatusCode, Json<CreatedAdminToken>), ApiError> {
    let name = validate::name("name", &req.name, 100)?;
    let mut scopes: Vec<String> = Vec::new();
    for s in &req.scopes {
        let s = validate::one_of("scopes", s.trim(), SCOPES)?;
        if !scopes.contains(&s) {
            scopes.push(s);
        }
    }
    if scopes.is_empty() {
        return Err(bad("admin_token.scopes_missing", "At least one scope"));
    }
    let expires_at = expiry("expires_at", req.expires_at.as_deref())?;
    if db::admin_token_count(&state.db).await? >= db::MAX_ADMIN_TOKENS {
        return Err(ApiError::conflict(
            "admin_token.too_many",
            format!("At most {} admin tokens", db::MAX_ADMIN_TOKENS),
        ));
    }
    let id = util::ulid();
    let (secret, hash) = admin_tokens::generate(&id);
    let row =
        db::create_admin_token(&state.db, &id, &name, &hash, &scopes, &admin.0.user.id, expires_at.as_deref()).await?;
    audit(
        &state,
        &admin,
        "admin.token_create",
        &id,
        serde_json::json!({ "name": name, "scopes": scopes, "expires_at": expires_at }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(CreatedAdminToken { token: row.into(), secret })))
}

/// Revoke (delete) an admin API token.
#[utoipa::path(delete, path = "/api/v1/admin/tokens/{token_id}", security(("bearer" = [])),
    params(("token_id" = String, Path)), responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn revoke_token(
    State(state): State<AppState>,
    admin: NodeAdmin,
    Path(token_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate::ulid("token_id", &token_id)?;
    let row =
        db::admin_token(&state.db, &token_id).await?.ok_or_else(|| not_found("Token", "admin_token.not_found"))?;
    db::delete_admin_token(&state.db, &token_id).await?;
    audit(&state, &admin, "admin.token_revoke", &token_id, serde_json::json!({ "name": row.name })).await?;
    Ok(StatusCode::NO_CONTENT)
}
