// SPDX-License-Identifier: AGPL-3.0-only
//! `federation.local_only`: routes that belong to a user's home node and are refused for remote users
//! with a federated session (FEDERATION.md §2.8). The check runs in the authentication extractors
//! (`AuthUser`, `second_factor::Principal`) against the matched route template, so a new route only
//! needs an entry here.

use axum::{
    extract::MatchedPath,
    http::{Method, request::Parts},
};

use crate::{app::AppState, auth::AuthUser, config::RoomCreation, error::ApiError};

/// `(method, route template)`; `*` = every method. A template ending in `/*` covers everything below.
pub const LOCAL_ONLY: &[(&str, &str)] = &[
    // Account, password and second factor
    ("PATCH", "/api/v1/users/me"),
    // Data rights, terms and notices of the account
    ("DELETE", "/api/v1/users/me"),
    ("*", "/api/v1/users/me/export"),
    ("*", "/api/v1/users/me/data"),
    ("*", "/api/v1/users/me/terms"),
    ("*", "/api/v1/users/me/terms/accept"),
    ("*", "/api/v1/users/me/legal-notices"),
    ("*", "/api/v1/users/me/legal-notices/*"),
    ("*", "/api/v1/users/me/password"),
    ("DELETE", "/api/v1/users/me/devices/{device_id}"),
    ("*", "/api/v1/auth/factors"),
    ("*", "/api/v1/auth/totp"),
    ("*", "/api/v1/auth/totp/enroll"),
    ("*", "/api/v1/auth/totp/confirm"),
    ("*", "/api/v1/auth/recovery-codes/regenerate"),
    ("*", "/api/v1/auth/webauthn/register/start"),
    ("*", "/api/v1/auth/webauthn/register/finish"),
    ("*", "/api/v1/auth/webauthn/credentials"),
    ("*", "/api/v1/auth/webauthn/credentials/{credential_id}"),
    // Single sign-on identity (APPLICATIONS.md §8.3)
    ("*", "/api/v1/auth/oidc/identity"),
    // Secret storage, identity, device keys and KeyPackages, backups
    ("*", "/api/v1/users/me/secret-storage"),
    ("*", "/api/v1/users/me/secret-storage/recovery"),
    ("*", "/api/v1/users/me/secret-storage/passkey/{credential_id}"),
    ("*", "/api/v1/users/me/identity"),
    ("*", "/api/v1/users/me/identity/reset"),
    ("*", "/api/v1/users/me/identity/rotate"),
    ("*", "/api/v1/users/me/identity/blob"),
    ("*", "/api/v1/users/me/devices/{device_id}/key"),
    ("*", "/api/v1/users/me/devices/{device_id}/key-packages"),
    ("*", "/api/v1/users/me/backups"),
    ("*", "/api/v1/users/me/backups/{domain}/{conversation_id}"),
    // Profile images; the profile fields go through PATCH /users/me above
    ("*", "/api/v1/users/me/avatar"),
    ("*", "/api/v1/users/me/header"),
    ("*", "/api/v1/users/me/background"),
    ("*", "/api/v1/users/me/background/{variant}"),
    // The whiteboard scene library and background conversion
    ("*", "/api/v1/users/me/whiteboards"),
    ("*", "/api/v1/users/me/whiteboards/background"),
    ("*", "/api/v1/users/me/whiteboards/{scene_id}"),
    ("*", "/api/v1/users/me/whiteboards/{scene_id}/thumbnail"),
    // Notification settings
    ("*", "/api/v1/users/me/notification-settings"),
    // Personal emojis and soundboard clips
    ("*", "/api/v1/users/me/emojis"),
    ("*", "/api/v1/users/me/emojis/{emoji_id}"),
    ("*", "/api/v1/users/me/sounds"),
    ("*", "/api/v1/users/me/sounds/{sound_id}"),
    // Friends and blocks
    ("*", "/api/v1/users/me/friends"),
    ("*", "/api/v1/users/me/friends/requests"),
    ("*", "/api/v1/users/me/friends/requests/{request_id}"),
    ("*", "/api/v1/users/me/friends/requests/{request_id}/accept"),
    ("*", "/api/v1/users/me/friends/{username}"),
    ("*", "/api/v1/users/me/blocks"),
    ("*", "/api/v1/users/me/blocks/{username}"),
    // The invite list (FEDERATION.md §4)
    ("*", "/api/v1/users/me/invites"),
    ("*", "/api/v1/users/me/invites/{invite_id}"),
    // DMs and group DMs live on the initiator's home node (§6)
    ("POST", "/api/v1/conversations"),
    // Reports go to the reporter's home node (FEDERATION.md §9.2)
    ("POST", "/api/v1/directory/reports"),
    // Applications live on their owner's home node (APPLICATIONS.md §1.6, §2.2); a remote bot uses the
    // `/applications/me*` routes of its own home node.
    ("*", "/api/v1/applications"),
    ("*", "/api/v1/applications/*"),
    // Link previews are created by the sender's home node
    ("*", "/api/v1/unfurl"),
    // Federation tokens and node administration
    ("*", "/api/v1/federation/token"),
    ("*", "/api/v1/admin/*"),
];

fn matches(rule: &(&str, &str), method: &Method, path: &str) -> bool {
    let (m, template) = rule;
    let method_ok = *m == "*" || *m == method.as_str();
    let path_ok = match template.strip_suffix("/*") {
        Some(prefix) => path.starts_with(&format!("{prefix}/")),
        None => path == *template,
    };
    method_ok && path_ok
}

/// `true` if the route (matched template) is refused for remote users. Creating rooms is allowed for
/// them only with `TAVRN_ROOM_CREATION=federated`.
pub fn is_local_only(room_creation: RoomCreation, method: &Method, path: &str) -> bool {
    if method == Method::POST && path == "/api/v1/rooms" {
        return room_creation != RoomCreation::Federated;
    }
    LOCAL_ONLY.iter().any(|rule| matches(rule, method, path))
}

pub fn local_only() -> ApiError {
    ApiError::Forbidden {
        code: "federation.local_only",
        detail: "This is only possible on the home node of this account".into(),
    }
}

/// Refuses remote users on local-only routes. Fails closed if the route template is unknown.
pub fn check(state: &AppState, auth: &AuthUser, parts: &Parts) -> Result<(), ApiError> {
    if !auth.is_remote() {
        return Ok(());
    }
    let Some(path) = parts.extensions.get::<MatchedPath>().map(MatchedPath::as_str) else {
        return Err(local_only());
    };
    if is_local_only(state.config.room_creation, &parts.method, path) {
        return Err(local_only());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_match_methods_templates_and_prefixes() {
        let local = |m: Method, p: &str| is_local_only(RoomCreation::Local, &m, p);
        assert!(local(Method::POST, "/api/v1/users/me/password"));
        assert!(local(Method::PATCH, "/api/v1/users/me"));
        assert!(!local(Method::GET, "/api/v1/users/me"), "reading the own profile is fine");
        assert!(local(Method::DELETE, "/api/v1/users/me/devices/{device_id}"));
        assert!(!local(Method::GET, "/api/v1/users/me/devices"));
        assert!(local(Method::POST, "/api/v1/conversations"));
        assert!(!local(Method::GET, "/api/v1/conversations"), "listing conversations on this node is fine");
        assert!(local(Method::GET, "/api/v1/admin/users"));
        assert!(local(Method::POST, "/api/v1/admin/users/{user_id}/second-factor/reset"));
        assert!(!local(Method::GET, "/api/v1/administrator"), "prefix rules end at a path segment");
        assert!(!local(Method::POST, "/api/v1/rooms/{room_id}/join"));
        assert!(!local(Method::POST, "/api/v1/rooms/{room_id}/channels/{channel_id}/messages"));
        assert!(local(Method::PUT, "/api/v1/users/me/avatar"));
        assert!(!local(Method::PUT, "/api/v1/users/me/presence"), "presence is pushed to every node");
        assert!(!local(Method::POST, "/api/v1/conversations/{conversation_id}/accept"));
        assert!(local(Method::POST, "/api/v1/applications"));
        assert!(local(Method::POST, "/api/v1/applications/{application_id}/tokens"));
        assert!(local(Method::GET, "/api/v1/applications/me"));
        assert!(local(Method::DELETE, "/api/v1/users/me"));
        assert!(local(Method::GET, "/api/v1/users/me/export"));
        assert!(local(Method::POST, "/api/v1/users/me/legal-notices/{case_id}/counter-notice"));
    }

    #[test]
    fn room_creation_follows_the_node_setting() {
        for mode in [RoomCreation::None, RoomCreation::Invite, RoomCreation::Local] {
            assert!(is_local_only(mode, &Method::POST, "/api/v1/rooms"), "{mode:?}");
        }
        assert!(!is_local_only(RoomCreation::Federated, &Method::POST, "/api/v1/rooms"));
        assert!(!is_local_only(RoomCreation::Local, &Method::GET, "/api/v1/rooms"));
    }
}
