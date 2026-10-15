// SPDX-License-Identifier: AGPL-3.0-only
pub mod admin;
pub mod age;
pub mod applications;
pub mod attachments;
pub mod auth;
pub mod backups;
pub mod calls;
pub mod channels;
pub mod commands;
pub mod conformance;
pub mod connect;
pub mod conversations;
pub mod conversations_index;
pub mod directory;
pub mod emojis;
pub mod entitlements;
pub mod federation;
pub mod files;
pub mod friends;
pub mod health;
pub mod history;
pub mod history_requests;
pub mod identity;
pub mod installations;
pub mod invites;
pub mod keys;
pub mod legal;
pub mod messages;
pub mod mls;
pub mod moderation;
pub mod node;
pub mod notifications;
pub mod oidc;
pub mod peer_resolve;
pub mod polls;
pub mod presence;
pub mod profile;
pub mod push;
pub mod read;
pub mod roles;
pub mod room_profiles;
pub mod rooms;
pub mod rtc;
pub mod search;
pub mod second_factor;
pub mod secret_storage;
pub mod subscriptions;
pub mod threads;
pub mod unfurl;
pub mod voice;
pub mod webhooks;
pub mod wellknown;
pub mod whiteboard;

use crate::error::ApiError;

/// Spends a confirmation token (`typ` `confirm`, e.g. of a purge): the first call passes, a replay within the token's
/// lifetime (on any instance) is `400 moderation.confirm_invalid` like an expired token, so one preview executes once.
pub(crate) async fn spend_confirmation(
    state: &crate::app::AppState,
    claims: &crate::jwt::StandardClaims,
) -> Result<(), ApiError> {
    let left = u64::try_from(claims.exp - crate::jwt::now_unix()).unwrap_or(0).max(1);
    let name = format!("confirm:{}", claims.jti);
    if state.cluster.claim_once(&name, std::time::Duration::from_secs(left)).await.map_err(crate::cache::unavailable)? {
        Ok(())
    } else {
        Err(crate::validate::bad(
            "moderation.confirm_invalid",
            "Confirmation token invalid or expired, please repeat the preview",
        ))
    }
}

/// Fallback for unknown paths: Problem Details here too instead of an empty 404.
pub async fn not_found() -> ApiError {
    ApiError::NotFound { code: "route.not_found", what: "Path".into() }
}
