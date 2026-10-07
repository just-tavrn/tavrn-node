// SPDX-License-Identifier: AGPL-3.0-only
//! The event subscription of an application (protocol/APPLICATIONS.md §6.2): owner routes only. Configuring
//! where events go needs the owner's full session, so a leaked bot token can never redirect the event stream
//! (the routes are local-only and not in `applications::APP_ROUTES`).

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    hooks, store,
    subscriptions::{self, Subscription},
};

pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route(
            "/applications/{application_id}/subscriptions",
            get(get_subscription).put(put_subscription).delete(delete_subscription).layer(small()),
        )
        .route("/applications/{application_id}/subscriptions/enable", post(enable))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_subscription, put_subscription, delete_subscription, enable),
    components(schemas(Subscription, PutSubscriptionRequest))
)]
pub struct SubscriptionsApi;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PutSubscriptionRequest {
    /// `https://` URL that receives the events (verified with a ping, §6.3).
    pub url: String,
    /// Event types (§6.2): `application.install`, `application.uninstall`, `member.join`, `member.leave`,
    /// `member.update`, `message.create`, `message.update`, `message.delete`, `commands.update`.
    pub events: Vec<String>,
}

fn not_found() -> ApiError {
    ApiError::NotFound { code: "subscription.not_found", what: "Subscription".into() }
}

/// Verifications per application (they send requests to a URL of the owner's choice): 10 per hour.
async fn verification_budget(state: &AppState, application_id: &str) -> Result<(), ApiError> {
    state.app_token_limiter.check_all(&[format!("app-sub:{application_id}")]).await
}

/// The application's event subscription (owner).
#[utoipa::path(get, path = "/api/v1/applications/{application_id}/subscriptions", security(("bearer" = [])),
    params(("application_id" = String, Path)),
    responses((status = 200, body = Subscription), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Subscription>, ApiError> {
    super::applications::require_person(&auth)?;
    let app = super::applications::owned(&state, &auth, &id).await?;
    let row = store::subscriptions::get(&state.db, &app.id).await?.ok_or_else(not_found)?;
    Ok(Json(subscriptions::view(&state, &row).await?))
}

/// Set (or replace) the subscription after verifying the URL with a ping (§6.3).
#[utoipa::path(put, path = "/api/v1/applications/{application_id}/subscriptions", security(("bearer" = [])),
    params(("application_id" = String, Path)), request_body = PutSubscriptionRequest,
    responses((status = 200, body = Subscription), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<PutSubscriptionRequest>,
) -> Result<Json<Subscription>, ApiError> {
    super::applications::require_person(&auth)?;
    let app = super::applications::owned(&state, &auth, &id).await?;
    let url = state.hooks.check_url(req.url.trim())?;
    let events = subscriptions::parse_events(&req.events)?;
    verification_budget(&state, &app.id).await?;
    hooks::verify_url(&state, &app.id, &url).await?;
    store::subscriptions::upsert(&state.db, &app.id, url.as_str(), &events).await?;
    super::applications::audit(
        &state,
        &auth.user,
        "app.subscription",
        &app,
        json!({ "url": url.as_str(), "events": events }),
    )
    .await?;
    let row = store::subscriptions::get(&state.db, &app.id).await?.ok_or_else(not_found)?;
    Ok(Json(subscriptions::view(&state, &row).await?))
}

/// Remove the subscription and every queued event.
#[utoipa::path(delete, path = "/api/v1/applications/{application_id}/subscriptions", security(("bearer" = [])),
    params(("application_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    super::applications::require_person(&auth)?;
    let app = super::applications::owned(&state, &auth, &id).await?;
    if !store::subscriptions::delete(&state.db, &app.id).await? {
        return Err(not_found());
    }
    super::applications::audit(&state, &auth.user, "app.subscription", &app, json!({ "deleted": true })).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Re-enable a disabled (or failing) subscription; the URL is verified again.
#[utoipa::path(post, path = "/api/v1/applications/{application_id}/subscriptions/enable", security(("bearer" = [])),
    params(("application_id" = String, Path)),
    responses((status = 200, body = Subscription), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn enable(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Subscription>, ApiError> {
    super::applications::require_person(&auth)?;
    let app = super::applications::owned(&state, &auth, &id).await?;
    let row = store::subscriptions::get(&state.db, &app.id).await?.ok_or_else(not_found)?;
    let url = state.hooks.check_url(&row.url)?;
    verification_budget(&state, &app.id).await?;
    hooks::verify_url(&state, &app.id, &url).await?;
    store::subscriptions::enable(&state.db, &app.id).await?;
    super::applications::audit(&state, &auth.user, "app.subscription", &app, json!({ "enabled": true })).await?;
    let row = store::subscriptions::get(&state.db, &app.id).await?.ok_or_else(not_found)?;
    Ok(Json(subscriptions::view(&state, &row).await?))
}
