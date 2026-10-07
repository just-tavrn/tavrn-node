// SPDX-License-Identifier: AGPL-3.0-only
//! Notification settings of the own account (`notifications.rs`): stored on the home node,
//! returned with `GET /users/me` as well, applied by the node to unread/mention counts and to received
//! `notify` hints. Remote users with a federated session are refused (`federation.local_only`).

use axum::{Json, extract::State};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    notifications::{self, NotificationSettings},
};

/// The own notification settings (defaults when never saved).
#[utoipa::path(get, path = "/api/v1/users/me/notification-settings", security(("bearer" = [])),
    responses((status = 200, body = NotificationSettings), (status = 403, body = ProblemDetails)))]
pub async fn get(State(state): State<AppState>, auth: AuthUser) -> Result<Json<NotificationSettings>, ApiError> {
    Ok(Json(notifications::load(&state.db, &auth.user.id).await?))
}

/// Replace the own notification settings: `global` `{ mode: all|mentions|nothing, sound, browser }`,
/// `rooms` by room id `{ mode?, muted_until?, suppress_everyone? }`, `channels` by conversation id
/// `{ mode?, muted_until? }` (`muted_until`: RFC 3339 or `"forever"`). At most 500 rooms, 2000 channels and
/// 64 KiB. The user's other devices get `notifications.update`.
#[utoipa::path(put, path = "/api/v1/users/me/notification-settings", security(("bearer" = [])),
    request_body = NotificationSettings,
    responses((status = 200, body = NotificationSettings), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 413, body = ProblemDetails)))]
pub async fn put(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<NotificationSettings>,
) -> Result<Json<NotificationSettings>, ApiError> {
    let settings = req.validated()?;
    notifications::save(&state.db, &auth.user.id, &settings).await?;
    state.hub.users(vec![auth.user.id.clone()], "notifications.update", serde_json::json!({ "settings": settings }));
    Ok(Json(settings))
}
