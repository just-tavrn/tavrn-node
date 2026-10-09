// SPDX-License-Identifier: AGPL-3.0-only
//! The date of birth of accounts that have none yet and the operator's correction (PROTOCOL.md §5e, `age.v1`).

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::put,
};
use serde::Deserialize;
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    auth::{AuthUser, NodeAdmin},
    error::{ApiError, ProblemDetails},
    models::UserPrivate,
    routes::auth::own_account,
    store,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users/me/date-of-birth", put(set_date_of_birth))
        .route("/admin/users/{user_id}/date-of-birth", put(admin_set_date_of_birth))
}

#[derive(OpenApi)]
#[openapi(
    paths(set_date_of_birth, admin_set_date_of_birth),
    components(schemas(DateOfBirthRequest, AdminDateOfBirthRequest, crate::age::AgeStatus))
)]
pub struct AgeApi;

#[derive(Deserialize, ToSchema)]
pub struct DateOfBirthRequest {
    /// `YYYY-MM-DD`, between 1900-01-01 and today, at least the node's minimum age.
    pub date_of_birth: String,
}

/// Add the date of birth to an account that has none yet (accounts from before `age.v1`, accounts provisioned by
/// single sign-on; PROTOCOL.md §5e). Until then the node answers `age.status_required` everywhere else. It is set
/// once: the node operator corrects it on request.
#[utoipa::path(put, path = "/api/v1/users/me/date-of-birth", security(("bearer" = [])), request_body = DateOfBirthRequest,
    responses((status = 200, body = UserPrivate), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn set_date_of_birth(
    State(state): State<AppState>,
    mut auth: AuthUser,
    Json(req): Json<DateOfBirthRequest>,
) -> Result<Json<UserPrivate>, ApiError> {
    if auth.user.kind != "user" {
        return Err(crate::applications::bot_forbidden());
    }
    if auth.user.date_of_birth.is_some() {
        return Err(ApiError::conflict(
            "age.date_of_birth_set",
            "The date of birth is already set; ask the operator of this node to correct it",
        ));
    }
    let today = crate::age::today();
    let date = crate::age::parse(req.date_of_birth.trim(), today)?;
    crate::age::check_minimum(date, today, state.config.minimum_age)?;
    let value = date.format("%Y-%m-%d").to_string();
    store::users::set_date_of_birth(&state.db, &auth.user.id, Some(&value)).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.date_of_birth",
        &auth.user.address(),
        "",
        serde_json::json!({}),
    )
    .await?;
    auth.user.date_of_birth = Some(value);
    Ok(Json(own_account(&state, &auth).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct AdminDateOfBirthRequest {
    /// `YYYY-MM-DD` between 1900-01-01 and today; null removes it (the user is asked again at the next request).
    pub date_of_birth: Option<String>,
}

/// Correct a local user's date of birth on request (PROTOCOL.md §5e: users set it once). Audited as
/// `admin.date_of_birth` without the date itself. The minimum age is not applied here: an account the operator
/// finds too young is disabled or deleted instead.
#[utoipa::path(put, path = "/api/v1/admin/users/{user_id}/date-of-birth", security(("bearer" = [])), params(("user_id" = String, Path)),
    request_body = AdminDateOfBirthRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_set_date_of_birth(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
    Json(req): Json<AdminDateOfBirthRequest>,
) -> Result<StatusCode, ApiError> {
    let target = store::users::by_id(&state.db, &user_id)
        .await?
        .filter(|u| u.domain == state.config.domain && u.kind == "user" && u.deleted_at.is_none())
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
    let value = match req.date_of_birth.as_deref() {
        Some(raw) => Some(crate::age::parse(raw.trim(), crate::age::today())?.format("%Y-%m-%d").to_string()),
        None => None,
    };
    store::users::set_date_of_birth(&state.db, &target.id, value.as_deref()).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.date_of_birth",
        &target.address(),
        "",
        serde_json::json!({ "admin_id": admin.user.id, "user_id": target.id, "removed": value.is_none() }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
