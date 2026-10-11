// SPDX-License-Identifier: AGPL-3.0-only
//! Ending the sessions of local devices (PROTOCOL.md §5b) and the liveness check of local access tokens.
//!
//! Access tokens are short-lived JWTs, but a revocation (logout, password change or reset, device removal, an admin
//! disabling the account or resetting its second factor, a node ban, account deletion) must take effect at once:
//! [`revoke_devices`] marks the sessions revoked, closes the devices' WebSockets (`session.revoked`, close code
//! 4001) and removes them from voice channels and calls. [`device_live`] lets `auth::authenticate` refuse an access
//! token whose device has no live session any more (`401 auth.session_revoked`); positive answers are cached for
//! [`LIVE_TTL`], so the check costs one indexed lookup per device and five seconds, not one per request. A
//! revocation clears the cache of this instance at once; other instances of a cluster follow within [`LIVE_TTL`]
//! (their WebSockets close at once through the event bus).

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::json;

use crate::{app::AppState, error::ApiError, models::UserRow, store};

/// How long a positive liveness answer is reused.
pub const LIVE_TTL: Duration = Duration::from_secs(5);
/// At most this many devices are remembered (a full cache drops its stale entries, then everything).
const LIVE_MAX: usize = 50_000;

/// Why sessions end (logged; the WebSocket close is the same for every reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Logout,
    PasswordChange,
    PasswordReset,
    DeviceRemoved,
    AccountDisabled,
    SecondFactorReset,
    NodeBan,
    AccountDeleted,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logout => "logout",
            Self::PasswordChange => "password_change",
            Self::PasswordReset => "password_reset",
            Self::DeviceRemoved => "device_removed",
            Self::AccountDisabled => "account_disabled",
            Self::SecondFactorReset => "second_factor_reset",
            Self::NodeBan => "node_ban",
            Self::AccountDeleted => "account_deleted",
        }
    }

    /// Reasons that end every device of the account, so voice and calls end for all of them.
    fn whole_account(self) -> bool {
        matches!(self, Self::AccountDisabled | Self::SecondFactorReset | Self::NodeBan | Self::AccountDeleted)
    }
}

/// Devices whose session was found live recently (device id → when).
#[derive(Default)]
pub struct LiveCache {
    checked: Mutex<HashMap<String, Instant>>,
}

impl LiveCache {
    fn fresh(&self, device_id: &str) -> bool {
        let checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
        checked.get(device_id).is_some_and(|at| at.elapsed() < LIVE_TTL)
    }

    fn remember(&self, device_id: &str) {
        let mut checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
        if checked.len() >= LIVE_MAX {
            checked.retain(|_, at| at.elapsed() < LIVE_TTL);
            if checked.len() >= LIVE_MAX {
                checked.clear();
            }
        }
        checked.insert(device_id.to_string(), Instant::now());
    }

    /// Forgets devices whose sessions just ended (the next request checks the database).
    pub fn forget(&self, device_ids: &[String]) {
        let mut checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
        for d in device_ids {
            checked.remove(d);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.checked.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// `true` if the local device `device_id` still has a live session (cached for [`LIVE_TTL`]).
pub async fn device_live(state: &AppState, device_id: &str) -> Result<bool, ApiError> {
    if state.live_sessions.fresh(device_id) {
        return Ok(true);
    }
    let live = store::home::device_has_live_session(&state.db, device_id).await?;
    if live {
        state.live_sessions.remember(device_id);
    }
    Ok(live)
}

/// Ends the sessions of `device_ids` (local devices of `user`): marks them revoked, closes their WebSockets (4001)
/// and removes them from voice channels and calls (every device of the account for the reasons that end the whole
/// account: disabled, second factor reset, node ban, deletion).
pub async fn revoke_devices(
    state: &AppState,
    user: &UserRow,
    device_ids: &[String],
    reason: Reason,
) -> Result<(), ApiError> {
    for device_id in device_ids {
        store::users::revoke_device_sessions(&state.db, &user.id, device_id).await?;
    }
    state.live_sessions.forget(device_ids);
    if !device_ids.is_empty() {
        state.hub.devices(device_ids.to_vec(), crate::federation::inbox::SESSION_REVOKED_EVENT, json!({}));
    }
    if user.domain == state.config.domain {
        let devices = (!reason.whole_account()).then(|| device_ids.to_vec());
        if reason.whole_account() || !device_ids.is_empty() {
            crate::voice::disconnect_everywhere(state, &user.id, devices).await;
        }
    }
    tracing::info!(user = user.address(), devices = device_ids.len(), reason = reason.as_str(), "sessions revoked");
    Ok(())
}

/// Ends the sessions of every device of `user` except `keep` (the device of the request, after a password change).
pub async fn revoke_all(state: &AppState, user: &UserRow, keep: Option<&str>, reason: Reason) -> Result<(), ApiError> {
    let devices: Vec<String> = store::users::devices_of(&state.db, &user.id)
        .await?
        .into_iter()
        .map(|d| d.id)
        .filter(|id| Some(id.as_str()) != keep)
        .collect();
    revoke_devices(state, user, &devices, reason).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_remembers_forgets_and_stays_bounded() {
        let c = LiveCache::default();
        assert!(!c.fresh("d1"));
        c.remember("d1");
        c.remember("d2");
        assert!(c.fresh("d1"));
        c.forget(&["d1".into()]);
        assert!(!c.fresh("d1"), "a revocation clears the entry");
        assert!(c.fresh("d2"));
        for i in 0..LIVE_MAX + 10 {
            c.remember(&format!("x{i}"));
        }
        assert!(c.len() <= LIVE_MAX, "bounded: {}", c.len());
    }

    #[test]
    fn whole_account_reasons() {
        assert!(Reason::NodeBan.whole_account());
        assert!(Reason::AccountDisabled.whole_account());
        assert!(!Reason::Logout.whole_account());
        assert!(!Reason::DeviceRemoved.whole_account());
        assert_eq!(Reason::PasswordReset.as_str(), "password_reset");
    }
}
