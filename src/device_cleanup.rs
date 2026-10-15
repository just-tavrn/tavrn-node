// SPDX-License-Identifier: AGPL-3.0-only
//! Housekeeping of devices and MLS leaves (ENCRYPTION.md §4.7): stale devices
//! (`TAVRN_DEVICE_STALE_DAYS`), leaves of devices that no longer exist, old pending removals and device tombstones.

use std::{collections::HashMap, sync::Mutex};

use chrono::{DateTime, Utc};

use crate::{app::AppState, error::ApiError, store, util};

/// Stale devices deleted per round.
pub const STALE_BATCH: i64 = 200;
/// Groups whose roster is compared with the devices per round (a rotating window over all groups).
pub const GHOST_SCAN_BATCH: i64 = 200;
/// Pending removals are dropped after this many days (the leaf stays a ghost the clients still detect).
pub const PENDING_MAX_AGE_DAYS: i64 = 90;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Stale devices deleted.
    pub devices: u64,
    /// Leaves of missing or unattested devices newly recorded as pending removals.
    pub ghosts: u64,
    /// Pending removals dropped after 90 days.
    pub expired: u64,
    /// Device tombstones dropped after `TAVRN_DEVICE_STALE_DAYS` (ENCRYPTION.md §2.3).
    pub tombstones: u64,
}

/// Deletes devices of local users not seen for `TAVRN_DEVICE_STALE_DAYS` (never the only device of a user, never one
/// with a live session) like a deletion in the settings: sessions, federated sessions, `mls.remove_needed` and
/// pending removals for their leaves, `devices.changed` to the user's contacts.
pub async fn prune_stale_devices(state: &AppState, now: DateTime<Utc>) -> Result<u64, ApiError> {
    let days = i64::from(state.config.device_stale_days);
    if days == 0 {
        return Ok(0);
    }
    let cutoff = util::format_time(now - chrono::Duration::days(days));
    let stale = store::users::stale_devices(&state.db, &state.config.domain, &cutoff, STALE_BATCH).await?;
    let mut deleted = 0;
    for device in stale {
        let Some(user) = store::users::by_id(&state.db, &device.user_id).await? else { continue };
        if !store::users::delete_device(&state.db, &user.id, &device.id).await? {
            continue;
        }
        deleted += 1;
        tracing::info!(
            user = user.address(),
            device = device.id,
            last_seen = device.last_seen_at,
            "stale device deleted"
        );
        crate::e2ee::device_removed(state, &user, &device.id).await?;
        crate::federation::remote::revoke_sessions(state, &user, Some(&device.id)).await?;
        crate::federation::remote::devices_changed(state, &user).await?;
    }
    Ok(deleted)
}

/// Where the rotating ghost scan continues (in memory: a restart starts over, which is harmless).
static SCAN_CURSOR: Mutex<String> = Mutex::new(String::new());

/// Compares the rosters of up to [`GHOST_SCAN_BATCH`] groups with the devices of this node's users and records
/// leaves of devices that no longer exist (`deleted`) or are not attested under the current identity key
/// (`unattested`) as pending removals. Leaves of remote users are left to their clients (their home node knows).
pub async fn detect_ghost_leaves(state: &AppState) -> Result<u64, ApiError> {
    let after = SCAN_CURSOR.lock().map(|c| c.clone()).unwrap_or_default();
    let groups = store::pending_removals::groups_after(&state.db, &after, GHOST_SCAN_BATCH).await?;
    let next = if (groups.len() as i64) < GHOST_SCAN_BATCH {
        String::new()
    } else {
        groups.last().map(|g| g.0.clone()).unwrap_or_default()
    };
    if let Ok(mut c) = SCAN_CURSOR.lock() {
        *c = next;
    }
    let own = format!("@{}", state.config.domain);
    let mut found = 0;
    // A user is looked up once per round, however many groups and leaves name them.
    let mut users: HashMap<String, Option<crate::models::UserRow>> = HashMap::new();
    for (conversation_id, roster) in crate::e2ee::rosters(groups).await {
        let mut deleted = Vec::new();
        let mut unattested = Vec::new();
        // The local leaves' device keys of the group in one statement per 500.
        let local: Vec<String> = roster
            .iter()
            .filter_map(|e| tavrn_crypto::util::parse_device_identity(&e.identity))
            .filter(|(address, _)| address.ends_with(&own))
            .map(|(_, device)| device.to_string())
            .collect();
        let keys = store::e2ee::device_keys(&state.db, &local).await?;
        for entry in roster {
            let Some((address, device_id)) = tavrn_crypto::util::parse_device_identity(&entry.identity) else {
                continue;
            };
            let Some(username) = address.strip_suffix(&own) else { continue };
            if !users.contains_key(username) {
                let user = store::users::by_username(&state.db, username, &state.config.domain).await?;
                users.insert(username.to_string(), user);
            }
            let Some(Some(user)) = users.get(username) else {
                deleted.push(entry.identity.clone());
                continue;
            };
            let row = keys.get(device_id);
            if row.is_none_or(|r| r.user_id != user.id) {
                deleted.push(entry.identity.clone());
            } else if crate::e2ee::attested_key_of(row, &user.id).is_none_or(|k| k != entry.signature_key) {
                unattested.push(entry.identity.clone());
            }
        }
        let known = store::pending_removals::of_conversation(&state.db, &conversation_id).await?;
        let fresh = |ids: Vec<String>| -> Vec<String> {
            ids.into_iter().filter(|i| !known.iter().any(|k| &k.identity == i)).collect()
        };
        let (deleted, unattested) = (fresh(deleted), fresh(unattested));
        found += (deleted.len() + unattested.len()) as u64;
        store::pending_removals::insert(&state.db, &conversation_id, &deleted, store::pending_removals::DELETED)
            .await?;
        store::pending_removals::insert(&state.db, &conversation_id, &unattested, store::pending_removals::UNATTESTED)
            .await?;
    }
    Ok(found)
}

/// One housekeeping round: stale devices first (their leaves become pending removals), then the expiry of old
/// pending removals and the ghost scan (which records leaves that are still there afresh).
pub async fn run(state: &AppState, now: DateTime<Utc>) -> Result<CleanupReport, ApiError> {
    let devices = prune_stale_devices(state, now).await?;
    let cutoff = util::format_time(now - chrono::Duration::days(PENDING_MAX_AGE_DAYS));
    let expired = store::pending_removals::prune(&state.db, &cutoff).await?;
    let ghosts = detect_ghost_leaves(state).await?;
    let tombstones = prune_tombstones(state, now).await?;
    Ok(CleanupReport { devices, ghosts, expired, tombstones })
}

/// Drops device tombstones older than `TAVRN_DEVICE_STALE_DAYS` (kept forever when the setting is 0): after that,
/// a deleted device can no longer be attested again as retired.
pub async fn prune_tombstones(state: &AppState, now: DateTime<Utc>) -> Result<u64, ApiError> {
    let days = i64::from(state.config.device_stale_days);
    if days == 0 {
        return Ok(0);
    }
    store::users::prune_tombstones(&state.db, &util::format_time(now - chrono::Duration::days(days))).await
}
