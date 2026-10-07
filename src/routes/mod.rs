// SPDX-License-Identifier: AGPL-3.0-only
pub mod admin;
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
pub mod presence;
pub mod profile;
pub mod read;
pub mod roles;
pub mod room_profiles;
pub mod rooms;
pub mod rtc;
pub mod search;
pub mod second_factor;
pub mod secret_storage;
pub mod subscriptions;
pub mod unfurl;
pub mod voice;
pub mod webhooks;
pub mod wellknown;
pub mod whiteboard;

use crate::error::ApiError;

/// Fallback for unknown paths: Problem Details here too instead of an empty 404.
pub async fn not_found() -> ApiError {
    ApiError::NotFound { code: "route.not_found", what: "Path".into() }
}
