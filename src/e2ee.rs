// SPDX-License-Identifier: AGPL-3.0-only
//! Node side of end-to-end encryption (ENCRYPTION.md): shared checks and `mls.remove_needed`.

use serde_json::json;
use tavrn_crypto::ds::DsGroup;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiError,
    models::UserRow,
    store::{self, e2ee::DeviceKeyRow},
    validate::bad,
};

/// Qualified conversation id `<domain>/<ULID>` (MLS group id, AAD).
pub fn qualified(state: &AppState, conversation_id: &str) -> String {
    format!("{}/{conversation_id}", state.config.domain)
}

/// Device identity `<user address>/<device id>`.
pub fn device_identity(user: &UserRow, device_id: &str) -> String {
    format!("{}/{device_id}", user.address())
}

/// Decodes a base64url field with an upper bound on the decoded size.
pub fn decode(field: &str, value: &str, max: usize, too_large: &'static str) -> Result<Vec<u8>, ApiError> {
    if value.len() > max / 3 * 4 + 4 {
        return Err(ApiError::PayloadTooLarge {
            code: too_large,
            detail: format!("{field}: at most {max} bytes"),
            meta: json!({ "max_bytes": max }),
        });
    }
    let bytes = tavrn_crypto::util::b64url_decode(value)
        .map_err(|_| bad("validation.base64url", format!("{field}: not valid base64url")))?;
    if bytes.len() > max {
        return Err(ApiError::PayloadTooLarge {
            code: too_large,
            detail: format!("{field}: at most {max} bytes"),
            meta: json!({ "max_bytes": max }),
        });
    }
    Ok(bytes)
}

/// Decodes a 32-byte Ed25519 public key (rejects malformed and weak keys).
pub fn decode_public_key(value: &str) -> Result<[u8; 32], ApiError> {
    let invalid = || bad("e2ee.key_invalid", "Invalid public key (32-byte Ed25519, base64url)");
    let bytes: [u8; 32] =
        tavrn_crypto::util::b64url_decode(value).ok().and_then(|b| b.try_into().ok()).ok_or_else(invalid)?;
    match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
        Ok(k) if !k.is_weak() => Ok(bytes),
        _ => Err(invalid()),
    }
}

pub fn not_attested() -> ApiError {
    ApiError::Forbidden {
        code: "e2ee.device_not_attested",
        detail: "This device is not attested with the current security key".into(),
    }
}

/// The session's device key if the device is attested under the current identity key (§9).
/// For a remote user the key comes from the key cache, i.e. as attested on the home node (FEDERATION.md §3.6).
pub async fn attested_session_key(state: &AppState, auth: &AuthUser) -> Result<[u8; 32], ApiError> {
    if let Some(home) = &auth.home_device_id {
        crate::federation::keys::ensure(state, &auth.user, Some(home)).await?;
    }
    let row = store::e2ee::device_key(&state.db, &auth.device_id).await?;
    attested_key_of(row.as_ref(), &auth.user.id).ok_or_else(not_attested)
}

/// Attested device key of a device row that belongs to `user_id`.
pub fn attested_key_of(row: Option<&DeviceKeyRow>, user_id: &str) -> Option<[u8; 32]> {
    let row = row.filter(|r| r.user_id == user_id)?;
    tavrn_crypto::util::b64url_decode(row.attested_key()?).ok()?.try_into().ok()
}

/// The claim budget of a target user (ENCRYPTION.md §4.5): KeyPackage claims for another user, local or from other
/// nodes, count against `TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR` whoever claims, so that claims in many invented or
/// sybil names cannot drain the user's KeyPackages. A user's claims for their own devices do not count.
pub async fn claim_budget(state: &AppState, target: &UserRow) -> Result<(), ApiError> {
    state.claim_target_limiter.check_all(std::slice::from_ref(&target.id)).await
}

// ---------------------------------------------------------------- mls.remove_needed

/// Emits `mls.remove_needed { conversation_id, identities }` for every group whose roster
/// contains identities matching `matches`, to the conversation's current audience, and records the leaves as
/// pending removals (`reason`: `deleted`, `unattested` or `not_member`, ENCRYPTION.md §4.7) so that clients that
/// were offline find them later.
async fn remove_needed(state: &AppState, groups: Vec<(String, Vec<u8>)>, reason: &str, matches: impl Fn(&str) -> bool) {
    for (conversation_id, ds_state) in groups {
        let Ok(group) = DsGroup::import_state(&ds_state) else { continue };
        let Ok(roster) = group.roster() else { continue };
        let identities: Vec<String> = roster.into_iter().map(|e| e.identity).filter(|i| matches(i)).collect();
        if identities.is_empty() {
            continue;
        }
        if let Err(e) = store::pending_removals::insert(&state.db, &conversation_id, &identities, reason).await {
            tracing::warn!(error = %e, conversation_id, "pending MLS removals not recorded");
        }
        let data = json!({ "conversation_id": conversation_id, "identities": identities });
        let row = match store::social::conversation(&state.db, &conversation_id).await {
            Ok(Some(row)) => row,
            _ => continue,
        };
        match row.room_id {
            Some(room_id) => {
                state.hub.room(&room_id, "mls.remove_needed", data);
            }
            None => {
                if let Ok(members) = store::social::member_ids(&state.db, &conversation_id).await {
                    state.hub.users(members, "mls.remove_needed", data);
                }
            }
        }
    }
}

fn of_user(address: String) -> impl Fn(&str) -> bool {
    move |identity: &str| identity.split_once('/').is_some_and(|(a, _)| a == address)
}

/// A user left a room or was kicked/banned: their leaves in the room's channel groups.
pub async fn user_left_room(state: &AppState, room_id: &str, user: &UserRow) -> Result<(), ApiError> {
    // Every path that ends a membership (leave, kick, ban, remote leave) passes here: leave voice as well.
    let (room, user_id) = (room_id.to_string(), user.id.clone());
    crate::voice::spawn_effect(state, move |s| async move { crate::voice::disconnect_user(&s, &room, &user_id).await });
    let groups = store::e2ee::groups_in_room(&state.db, room_id).await?;
    remove_needed(state, groups, store::pending_removals::NOT_MEMBER, of_user(user.address())).await;
    Ok(())
}

/// A "no bots" flag was set (APPLICATIONS.md §3.5): the leaves of the room's bot members in these channels.
pub async fn bots_excluded(state: &AppState, room_id: &str, channel_ids: &[String]) -> Result<(), ApiError> {
    let bot_ids = store::applications::bot_member_ids(&state.db, room_id).await?;
    if bot_ids.is_empty() {
        return Ok(());
    }
    let addresses: Vec<String> =
        store::users::by_ids(&state.db, &bot_ids).await?.iter().map(UserRow::address).collect();
    let groups: Vec<(String, Vec<u8>)> = store::e2ee::groups_in_room(&state.db, room_id)
        .await?
        .into_iter()
        .filter(|(id, _)| channel_ids.contains(id))
        .collect();
    remove_needed(state, groups, store::pending_removals::NOT_MEMBER, move |identity: &str| {
        identity.split_once('/').is_some_and(|(a, _)| addresses.iter().any(|b| b == a))
    })
    .await;
    Ok(())
}

/// An age gate was switched on (PROTOCOL.md §5e): the leaves of the room's members below it in these channels'
/// groups, and those members leave the room's voice channels.
pub async fn below_age_gate(state: &AppState, room_id: &str, channel_ids: &[String]) -> Result<(), ApiError> {
    let mut below = Vec::new();
    for user in store::users::by_ids(&state.db, &store::rooms::member_ids(&state.db, room_id).await?).await? {
        if !crate::age::is_adult(state, &user).await? {
            let (room, user_id) = (room_id.to_string(), user.id.clone());
            crate::voice::spawn_effect(state, move |s| async move {
                crate::voice::disconnect_user(&s, &room, &user_id).await;
            });
            below.push(user.address());
        }
    }
    if below.is_empty() {
        return Ok(());
    }
    let groups: Vec<(String, Vec<u8>)> = store::e2ee::groups_in_room(&state.db, room_id)
        .await?
        .into_iter()
        .filter(|(id, _)| channel_ids.contains(id))
        .collect();
    remove_needed(state, groups, store::pending_removals::NOT_MEMBER, move |identity: &str| {
        identity.split_once('/').is_some_and(|(a, _)| below.iter().any(|b| b == a))
    })
    .await;
    Ok(())
}

/// A member's moved participation in a voice channel ended (`VOICE.md` §7) and they may not view the channel by
/// their permissions: their leaves in the channel's group.
pub async fn left_channel_group(state: &AppState, channel_id: &str, user: &UserRow) -> Result<(), ApiError> {
    if let Some(ds) = store::e2ee::group_state(&state.db, channel_id).await? {
        remove_needed(
            state,
            vec![(channel_id.to_string(), ds)],
            store::pending_removals::NOT_MEMBER,
            of_user(user.address()),
        )
        .await;
    }
    Ok(())
}

/// A user left (or was removed from) a group DM.
pub async fn user_left_conversation(state: &AppState, conversation_id: &str, user: &UserRow) -> Result<(), ApiError> {
    if let Some(ds) = store::e2ee::group_state(&state.db, conversation_id).await? {
        remove_needed(
            state,
            vec![(conversation_id.to_string(), ds)],
            store::pending_removals::NOT_MEMBER,
            of_user(user.address()),
        )
        .await;
    }
    Ok(())
}

/// A device was deleted: its leaf in every group of the user.
pub async fn device_removed(state: &AppState, user: &UserRow, device_id: &str) -> Result<(), ApiError> {
    let groups = store::e2ee::groups_of_user(&state.db, &user.id).await?;
    let identity = device_identity(user, device_id);
    remove_needed(state, groups, store::pending_removals::DELETED, move |i| i == identity).await;
    Ok(())
}

/// Identity reset: every leaf of the user is unattested until the device re-attests and rejoins.
pub async fn identity_reset(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    let groups = store::e2ee::groups_of_user(&state.db, &user.id).await?;
    remove_needed(state, groups, store::pending_removals::UNATTESTED, of_user(user.address())).await;
    Ok(())
}
