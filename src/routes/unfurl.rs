// SPDX-License-Identifier: AGPL-3.0-only
//! `GET /api/v1/unfurl`: a link preview for the sender's client (`crate::unfurl`).

use axum::{Json, extract::State};
use serde::Deserialize;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiQuery as Query, ProblemDetails},
    unfurl::UnfurlResponse,
};

#[derive(Deserialize, utoipa::IntoParams)]
pub struct UnfurlQuery {
    /// The http(s) URL to preview (at most 2048 characters).
    pub url: String,
}

/// Link preview of a public web page (OpenGraph, Twitter card, `<title>`), for the sender's client to put
/// into the message content. Home node only, rate-limited per user (30 per minute), SSRF-safe (public
/// addresses only, at most 3 redirects, 5 seconds, 1 MiB of HTML), cached for an hour.
#[utoipa::path(get, path = "/api/v1/unfurl", security(("bearer" = [])), params(UnfurlQuery),
    responses((status = 200, body = UnfurlResponse), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 415, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn unfurl(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<UnfurlQuery>,
) -> Result<Json<UnfurlResponse>, ApiError> {
    let unfurler = state
        .unfurl
        .as_ref()
        .ok_or_else(|| ApiError::NotFound { code: "unfurl.disabled", what: "Link previews".into() })?;
    Ok(Json(unfurler.unfurl(&auth.user.id, &q.url, &state.media).await?))
}
