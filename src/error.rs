// SPDX-License-Identifier: AGPL-3.0-only
//! Unified API error type. Every variant maps to an HTTP status and a stable `code`
//! and is served as RFC 9457 Problem Details (`application/problem+json`).

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

pub const ERROR_TYPE_BASE: &str = "https://tavrn.dev/errors/";

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{detail}")]
    BadRequest { code: &'static str, detail: String },
    /// 400 with extra data in `meta` (e.g. `command.invalid` names the `path`).
    #[error("{detail}")]
    BadRequestMeta { code: &'static str, detail: String, meta: Value },
    #[error("Authentication required")]
    Unauthorized { code: &'static str },
    #[error("{detail}")]
    Forbidden { code: &'static str, detail: String },
    /// 403 with extra data in `meta` (e.g. `upload.type_forbidden` names the category).
    #[error("{detail}")]
    ForbiddenMeta { code: &'static str, detail: String, meta: Value },
    #[error("{what} not found")]
    NotFound { code: &'static str, what: String },
    #[error("{detail}")]
    Conflict { code: &'static str, detail: String, meta: Value },
    #[error("{detail}")]
    PreconditionFailed { code: &'static str, detail: String, meta: Value },
    #[error("{detail}")]
    PayloadTooLarge { code: &'static str, detail: String, meta: Value },
    #[error("{detail}")]
    UnsupportedMedia { code: &'static str, detail: String },
    /// 410: the resource existed and is gone for good (e.g. `attachment.expired`).
    #[error("{detail}")]
    Gone { code: &'static str, detail: String },
    #[error("Too many requests")]
    RateLimited { retry_after_secs: u32 },
    #[error("Service temporarily unavailable: {detail}")]
    Unavailable { code: &'static str, detail: String },
    /// 503 with `Retry-After`: the request can succeed later (e.g. `federation.conformance_pending`).
    #[error("{detail}")]
    Pending { code: &'static str, detail: String, retry_after_secs: u32 },
    /// A peer node failed (unreachable, invalid answer): 502.
    #[error("{detail}")]
    BadGateway { code: &'static str, detail: String },
    /// 504: something this node waited for did not answer in time (e.g. `interaction.no_ack`).
    #[error("{detail}")]
    GatewayTimeout { code: &'static str, detail: String },
    /// Unexpected error. The cause is logged, never exposed.
    #[error("Internal error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_url: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null")]
    #[schema(value_type = Object)]
    pub meta: Value,
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } | Self::BadRequestMeta { .. } => StatusCode::BAD_REQUEST,
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } | Self::ForbiddenMeta { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::PreconditionFailed { .. } => StatusCode::PRECONDITION_FAILED,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMedia { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Gone { .. } => StatusCode::GONE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable { .. } | Self::Pending { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::BadGateway { .. } => StatusCode::BAD_GATEWAY,
            Self::GatewayTimeout { .. } => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::BadRequest { code, .. }
            | Self::BadRequestMeta { code, .. }
            | Self::GatewayTimeout { code, .. }
            | Self::Unauthorized { code }
            | Self::Forbidden { code, .. }
            | Self::ForbiddenMeta { code, .. }
            | Self::NotFound { code, .. }
            | Self::Conflict { code, .. }
            | Self::PreconditionFailed { code, .. }
            | Self::PayloadTooLarge { code, .. }
            | Self::UnsupportedMedia { code, .. }
            | Self::Gone { code, .. }
            | Self::Unavailable { code, .. }
            | Self::Pending { code, .. }
            | Self::BadGateway { code, .. } => code,
            Self::RateLimited { .. } => "rate_limited",
            Self::Internal(_) => "internal",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::BadRequest { .. } | Self::BadRequestMeta { .. } => "Bad request",
            Self::Unauthorized { .. } => "Not authenticated",
            Self::Forbidden { .. } | Self::ForbiddenMeta { .. } => "Forbidden",
            Self::NotFound { .. } => "Not found",
            Self::Conflict { .. } => "Conflict",
            Self::PreconditionFailed { .. } => "Precondition failed",
            Self::PayloadTooLarge { .. } => "Too large",
            Self::UnsupportedMedia { .. } => "File type not allowed",
            Self::Gone { .. } => "Gone",
            Self::RateLimited { .. } => "Too many requests",
            Self::Unavailable { .. } | Self::Pending { .. } => "Temporarily unavailable",
            Self::BadGateway { .. } => "Error from another node",
            Self::GatewayTimeout { .. } => "Timeout",
            Self::Internal(_) => "Internal error",
        }
    }

    pub fn to_problem(&self, request_id: Option<String>) -> ProblemDetails {
        let meta = match self {
            Self::PayloadTooLarge { meta, .. }
            | Self::Conflict { meta, .. }
            | Self::ForbiddenMeta { meta, .. }
            | Self::BadRequestMeta { meta, .. }
            | Self::PreconditionFailed { meta, .. } => meta.clone(),
            Self::RateLimited { retry_after_secs } | Self::Pending { retry_after_secs, .. } => {
                serde_json::json!({ "retry_after_secs": retry_after_secs })
            }
            _ => Value::Null,
        };
        let detail = match self {
            // Internal details stay in the log.
            Self::Internal(_) => "An unexpected error occurred. Please report it with the request_id.".to_string(),
            other => other.to_string(),
        };
        ProblemDetails {
            type_url: format!("{ERROR_TYPE_BASE}{}", self.code()),
            title: self.title().to_string(),
            status: self.status().as_u16(),
            detail,
            code: self.code().to_string(),
            request_id,
            meta,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(e) = &self {
            tracing::error!(error = ?e, "internal error");
        }
        let status = self.status();
        let problem = self.to_problem(None);
        let body = serde_json::to_vec(&problem).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = (status, body).into_response();
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
        if let Self::RateLimited { retry_after_secs } | Self::Pending { retry_after_secs, .. } = self
            && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        response
    }
}

impl ApiError {
    /// 409 without extra data.
    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Conflict { code, detail: detail.into(), meta: Value::Null }
    }
}

/// JSON body extractor whose rejections are Problem Details with stable codes
/// (`request.too_large`, `request.invalid_json`) instead of axum's plain-text answers.
/// Combine it with a per-route `DefaultBodyLimit` to cap the body size.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Self(v)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::PayloadTooLarge {
                code: "request.too_large",
                detail: "Request too large".into(),
                meta: Value::Null,
            }),
            Err(rejection) => Err(ApiError::BadRequest { code: "request.invalid_json", detail: rejection.body_text() }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn problem_details_carry_code_and_type() {
        let e = ApiError::NotFound { code: "room.not_found", what: "Room".into() };
        let p = e.to_problem(Some("01J".into()));
        assert_eq!(p.status, 404);
        assert_eq!(p.code, "room.not_found");
        assert_eq!(p.type_url, "https://tavrn.dev/errors/room.not_found");
        assert_eq!(p.detail, "Room not found");
        assert_eq!(p.request_id.as_deref(), Some("01J"));
    }

    #[test]
    fn internal_errors_hide_their_cause() {
        let e = ApiError::Internal(anyhow::anyhow!("db password=secret"));
        let json = serde_json::to_string(&e.to_problem(None)).unwrap();
        assert!(!json.contains("secret"));
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn payload_too_large_includes_meta() {
        let e = ApiError::PayloadTooLarge {
            code: "upload.too_large",
            detail: "max 25 MB".into(),
            meta: serde_json::json!({ "max_bytes": 100 }),
        };
        let p = e.to_problem(None);
        assert_eq!(p.meta["max_bytes"], 100);
    }

    #[test]
    fn bad_gateway_is_502_with_its_code() {
        let e = ApiError::BadGateway { code: "federation.peer_unreachable", detail: "x.example unreachable".into() };
        let p = e.to_problem(None);
        assert_eq!(p.status, 502);
        assert_eq!(p.code, "federation.peer_unreachable");
        assert_eq!(p.detail, "x.example unreachable");
    }

    #[tokio::test]
    async fn rate_limited_sets_retry_after_header() {
        let resp = ApiError::RateLimited { retry_after_secs: 7 }.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "7");
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/problem+json");
    }
}
