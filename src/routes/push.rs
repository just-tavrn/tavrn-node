// SPDX-License-Identifier: AGPL-3.0-only
//! Web push (PROTOCOL.md §6d, `push.rs`): the node's VAPID key and the push subscriptions of the own devices.
//! Subscriptions are registered with the home node only (remote users get `403 federation.local_only`, bots
//! `403 app.bot_forbidden`): it holds the notification settings and forwards the `notify` hints of other nodes.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    push::crypto::{KeyError, check_keys},
    store::{self, push::SubscriptionRow},
    util,
    validate::bad,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/push/vapid", get(vapid))
        .route("/users/me/push-subscriptions", get(list).put(register))
        .route("/users/me/push-subscriptions/test", post(test))
        .route("/users/me/push-subscriptions/{subscription_id}", delete(remove))
}

#[derive(OpenApi)]
#[openapi(
    paths(vapid, list, register, remove, test),
    components(schemas(VapidInfo, PushSubscriptionRequest, PushSubscriptionKeys, PushRegistration))
)]
pub struct PushApi;

/// Whether the node sends web pushes and the key browsers subscribe with.
#[derive(Debug, Serialize, ToSchema)]
pub struct VapidInfo {
    /// `TAVRN_PUSH`: the node sends web pushes (capability `push.webpush`).
    pub enabled: bool,
    /// The VAPID public key (RFC 8292): base64url of the uncompressed P-256 point, the `applicationServerKey` of
    /// `PushManager.subscribe()`. Null while push is off.
    pub public_key: Option<String>,
}

/// The browser's keys of a subscription (`PushSubscription.toJSON().keys`).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSubscriptionKeys {
    /// Base64url of the browser's P-256 public key (65 bytes, uncompressed).
    pub p256dh: String,
    /// Base64url of the 16-byte authentication secret.
    pub auth: String,
}

/// A browser push subscription (`PushSubscription.toJSON()`) of the requesting device.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PushSubscriptionRequest {
    /// The push service URL (`https://`, at most 2048 characters, a public host).
    pub endpoint: String,
    pub keys: PushSubscriptionKeys,
    /// The requesting device (optional; another device is refused with `400 push.device_invalid`).
    #[serde(default)]
    pub device_id: Option<String>,
    /// `expirationTime` of the browser: Unix milliseconds or null.
    #[serde(default, alias = "expirationTime")]
    pub expiration_time: Option<f64>,
}

/// A registered push subscription (the keys and the endpoint are never returned). Named apart from the browser's
/// `PushSubscription`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PushRegistration {
    pub id: String,
    pub device_id: String,
    /// Origin of the push service (`https://host`), to tell the subscriptions apart.
    pub push_service: String,
    /// The subscription belongs to the requesting device.
    pub current_device: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    /// Failed deliveries in a row (the node backs off and deletes the subscription after 30).
    pub failures: i64,
}

impl PushRegistration {
    fn of(row: SubscriptionRow, device_id: &str) -> Self {
        let push_service =
            reqwest::Url::parse(&row.endpoint).map(|u| u.origin().ascii_serialization()).unwrap_or_default();
        Self {
            current_device: row.device_id == device_id,
            id: row.id,
            device_id: row.device_id,
            push_service,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            expires_at: row.expires_at,
            failures: row.failures,
        }
    }
}

fn disabled() -> ApiError {
    ApiError::NotFound { code: "push.disabled", what: "Web push".into() }
}

/// VAPID key for web push.
///
/// Whether this node sends web pushes (`TAVRN_PUSH`) and the VAPID public key (RFC 8292) browsers subscribe with
/// (`applicationServerKey`). Public; `public_key` is null while push is off.
#[utoipa::path(get, path = "/api/v1/push/vapid",
    responses((status = 200, body = VapidInfo)))]
pub async fn vapid(State(state): State<AppState>) -> Json<VapidInfo> {
    Json(VapidInfo { enabled: state.push.enabled(), public_key: state.push.public_key().map(String::from) })
}

/// List the own push subscriptions.
///
/// Every registered push subscription of the account's devices, oldest first; `current_device` marks those of the
/// requesting device. Keys and endpoints are not returned, only the push service's origin.
#[utoipa::path(get, path = "/api/v1/users/me/push-subscriptions", security(("bearer" = [])),
    responses((status = 200, body = [PushRegistration]), (status = 403, body = ProblemDetails)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<PushRegistration>>, ApiError> {
    let rows = store::push::list(&state.db, &auth.user.id).await?;
    Ok(Json(rows.into_iter().map(|r| PushRegistration::of(r, &auth.device_id)).collect()))
}

/// Register a push subscription.
///
/// Registers the browser's push subscription (`PushSubscription.toJSON()`) for the requesting device, or updates
/// the account's one with the same endpoint (also from another of its devices). `201` when new, `200` when
/// updated. An endpoint of another account's live subscription is refused (`409 push.endpoint_taken`: the client
/// unsubscribes the browser and subscribes again); a stale one (expired, or its device has no live session) is
/// taken over. The endpoint must be an `https://` URL of a public host (`400
/// push.endpoint_invalid`), `keys.p256dh` an uncompressed P-256 point and `keys.auth` 16 bytes, both base64url
/// (`400 push.keys_invalid`). At most 20 subscriptions per account (`409 push.too_many`), 30 registrations per
/// hour (`429`). `404 push.disabled` while push is off. The subscription is deleted with the device and when its
/// sessions are revoked (sign-out).
#[utoipa::path(put, path = "/api/v1/users/me/push-subscriptions", security(("bearer" = [])),
    request_body = PushSubscriptionRequest,
    responses((status = 200, body = PushRegistration), (status = 201, body = PushRegistration),
        (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn register(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<PushSubscriptionRequest>,
) -> Result<(StatusCode, Json<PushRegistration>), ApiError> {
    if !state.push.enabled() {
        return Err(disabled());
    }
    if let Some(device) = req.device_id.as_deref()
        && device != auth.device_id
    {
        return Err(bad("push.device_invalid", "device_id must be the requesting device"));
    }
    state.push.register_limiter.check_all(std::slice::from_ref(&auth.user.id)).await?;
    let endpoint = state.push.check_endpoint(req.endpoint.trim())?;
    check_keys(&req.keys.p256dh, &req.keys.auth).map_err(|e| {
        bad(
            "push.keys_invalid",
            match e {
                KeyError::P256dh => "keys.p256dh must be a base64url uncompressed P-256 public key",
                KeyError::Auth => "keys.auth must be 16 bytes, base64url",
            },
        )
    })?;
    let expires_at = match req.expiration_time {
        Some(ms) if ms.is_finite() && ms > 0.0 => {
            let t = chrono::DateTime::from_timestamp_millis(ms as i64)
                .ok_or_else(|| bad("push.expiration_invalid", "expiration_time: Unix milliseconds"))?;
            if t <= chrono::Utc::now() {
                return Err(bad("push.expiration_invalid", "The subscription has already expired"));
            }
            Some(util::format_time(t))
        }
        Some(_) => return Err(bad("push.expiration_invalid", "expiration_time: Unix milliseconds")),
        None => None,
    };
    let p256dh = req.keys.p256dh.trim_end_matches('=');
    let secret = req.keys.auth.trim_end_matches('=');
    let saved = store::push::upsert(
        &state.db,
        store::push::NewSubscription {
            user_id: &auth.user.id,
            device_id: &auth.device_id,
            endpoint: endpoint.as_str(),
            p256dh,
            auth: secret,
            expires_at: expires_at.as_deref(),
        },
    )
    .await?;
    let (row, created) = match saved {
        store::push::Upsert::Saved(row, created) => (row, created),
        store::push::Upsert::TooMany => {
            return Err(ApiError::Conflict {
                code: "push.too_many",
                detail: format!("At most {} push subscriptions per account", store::push::MAX_PER_USER),
                meta: serde_json::json!({ "max": store::push::MAX_PER_USER }),
            });
        }
        store::push::Upsert::Taken => {
            return Err(ApiError::conflict(
                "push.endpoint_taken",
                "The endpoint belongs to another account's subscription; subscribe the browser again",
            ));
        }
    };
    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(PushRegistration::of(row, &auth.device_id))))
}

/// Delete a push subscription.
///
/// Deletes one push subscription of the account (any of its devices). Clients call it when the user turns push off
/// on a device and before signing out. `404 push.subscription_not_found` otherwise.
#[utoipa::path(delete, path = "/api/v1/users/me/push-subscriptions/{subscription_id}", security(("bearer" = [])),
    params(("subscription_id" = String, Path, description = "Subscription id")),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn remove(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(subscription_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if store::push::delete(&state.db, &auth.user.id, &subscription_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound { code: "push.subscription_not_found", what: "Push subscription".into() })
    }
}

/// Send a test push.
///
/// Queues a push of type `test` to every deliverable subscription of the account, even while a device is connected
/// (the settings' test button). `202`; at most 5 per 10 minutes (`429`), `404 push.disabled` while push is off.
#[utoipa::path(post, path = "/api/v1/users/me/push-subscriptions/test", security(("bearer" = [])),
    responses((status = 202), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn test(State(state): State<AppState>, auth: AuthUser) -> Result<StatusCode, ApiError> {
    if !state.push.enabled() {
        return Err(disabled());
    }
    state.push.test_limiter.check_all(std::slice::from_ref(&auth.user.id)).await?;
    crate::push::test(&state, &auth.user.id);
    Ok(StatusCode::ACCEPTED)
}
