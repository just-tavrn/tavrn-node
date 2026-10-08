// SPDX-License-Identifier: AGPL-3.0-only
//! App sessions of the connect flow (FEDERATION.md §8 step 3, capability `connect.app`).
//!
//! A native app (the desktop app) has no `https://<domain>` origin the connect flow could redirect to. It creates an
//! app session with its PKCE challenge (`POST /auth/connect/session`), opens this node's `/connect?session=…` page,
//! and polls the session (`GET /auth/connect/session/{id}`) until the user confirmed there; the page's
//! `POST /auth/connect/code { session_id }` stores the one-time code with the session instead of redirecting. The
//! app gets the code exactly once and exchanges it with its verifier (`POST /auth/connect/token`).
//!
//! The confirmation may carry **sealed unlock material** (`sealed_unlock`): the PRF output of the page's passkey
//! ceremony, sealed to a key only the app holds. The node keeps it opaque and hands it out with the code, once. An
//! **unlock** session (`Purpose::Unlock`) belongs to the signed-in user who created it and yields only that
//! material, no code.
//!
//! Sessions live in the node's cache (in memory, or the shared cache of several instances), sealed with a key
//! derived from `secrets.key`, under the SHA-256 of their id: the data record (`connect-session:`, read and
//! overwritten, never removed before its lifetime ends, so a poll never misses it), a marker taken by the one
//! confirmation (`connect-open:`) and the code and sealed material taken by the one poll that hands them out
//! (`connect-ready:`). A session
//! is pending for at most 10 minutes; once confirmed it lives as long as its code (2 minutes); an expired or spent
//! session answers `410` for another 10 minutes, then it is unknown (`404`).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{
    cache::{self, Cluster, now_ms},
    error::ApiError,
    util,
};

/// Announced in `/.well-known/tavrn` (PROTOCOL.md §3).
pub const CAPABILITY: &str = "connect.app";
/// How long a session waits for the confirmation.
pub const SESSION_TTL_SECS: u64 = 600;
/// How long a confirmed session keeps its code (the lifetime of a connect code).
pub const CODE_TTL_SECS: u64 = crate::routes::connect::CODE_TTL_SECS;
/// How long an expired or spent session still answers `410 connect.session_expired`.
const GRACE: Duration = Duration::from_secs(600);
/// Polls per session and minute (the app polls every 2 seconds).
pub const POLLS_PER_SESSION: u32 = 60;
/// Default device name of the session (FEDERATION.md §8).
pub const DEFAULT_DEVICE_NAME: &str = "Desktop app";

/// New sessions per client IP and minute.
pub fn create_limit(dev: bool) -> u32 {
    if dev { 100 } else { 10 }
}

/// New sessions of the whole node per minute (bounds the cache entries an attacker with many addresses can create).
pub fn create_limit_node(dev: bool) -> u32 {
    if dev { 10_000 } else { 1000 }
}

/// Polls per client IP and minute (many apps behind one address).
pub fn poll_limit_ip(dev: bool) -> u32 {
    if dev { 6000 } else { 600 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Pending,
    Ready,
    Spent,
}

/// What an app session is for (FEDERATION.md §8 step 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    /// Sign the app in: the confirmation issues a code (and may carry sealed unlock material).
    #[default]
    Login,
    /// Unlock a signed-in app: the session's own user sends sealed unlock material, no code is issued.
    Unlock,
}

impl Purpose {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "unlock" => Some(Self::Unlock),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Unlock => "unlock",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    challenge: String,
    device_name: String,
    stage: Stage,
    /// Unix milliseconds: pending until then, or (confirmed) the code's end.
    expires_at_ms: u64,
    #[serde(default)]
    purpose: Purpose,
    /// Unlock sessions: the user who created it (only that user may confirm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
}

/// A pending session as the confirmation needs it.
#[derive(Debug, Clone)]
pub struct Open {
    pub challenge: String,
    pub device_name: String,
    pub purpose: Purpose,
    pub user_id: Option<String>,
}

/// What the confirmation leaves for the app's one poll.
#[derive(Debug, Serialize, Deserialize)]
struct Handout {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    sealed_unlock: Option<String>,
}

/// Smallest and largest sealed unlock material (decoded bytes): a sealed box adds 48 bytes to its plaintext, and the
/// protocol caps it at 1 KiB.
pub const SEALED_UNLOCK_MIN: usize = 49;
pub const SEALED_UNLOCK_MAX: usize = 1024;

/// Sealed unlock material as the protocol allows it: base64url without padding of 49 to 1024 bytes. The node never
/// looks inside.
pub fn valid_sealed_unlock(s: &str) -> bool {
    s.len() <= SEALED_UNLOCK_MAX.div_ceil(3) * 4
        && URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| (SEALED_UNLOCK_MIN..=SEALED_UNLOCK_MAX).contains(&b.len()))
}

pub fn sealed_unlock_invalid() -> ApiError {
    ApiError::BadRequest {
        code: "connect.sealed_unlock_invalid",
        detail: "sealed_unlock: expected base64url of 49 to 1024 bytes, only with session_id".into(),
    }
}

/// What a poll finds.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Pending {
        device_name: String,
        purpose: Purpose,
        expires_in: u64,
    },
    /// The code (login sessions) and the sealed unlock material (if the page sent any), handed out exactly once.
    Ready {
        code: Option<String>,
        sealed_unlock: Option<String>,
        expires_in: u64,
    },
    Expired,
    Unknown,
}

pub fn session_invalid_404() -> ApiError {
    ApiError::NotFound { code: "connect.session_invalid", what: "Sign-in session".into() }
}

pub fn session_invalid() -> ApiError {
    ApiError::BadRequest { code: "connect.session_invalid", detail: "Unknown sign-in session".into() }
}

pub fn session_expired() -> ApiError {
    ApiError::Gone {
        code: "connect.session_expired",
        detail: "The sign-in session expired or was already completed; start the sign-in again in the app".into(),
    }
}

/// A session id as this node issues it: 32 random bytes in base64url without padding (43 characters).
pub fn valid_id(id: &str) -> bool {
    id.len() == 43 && URL_SAFE_NO_PAD.decode(id).is_ok_and(|b| b.len() == 32)
}

pub struct ConnectSessions {
    cluster: Arc<Cluster>,
    /// Milliseconds; shortened only by tests.
    session_ttl: AtomicU64,
    code_ttl: AtomicU64,
}

fn secs_left(expires_at_ms: u64, now: u64) -> u64 {
    expires_at_ms.saturating_sub(now).div_ceil(1000)
}

impl ConnectSessions {
    pub fn new(cluster: &Arc<Cluster>) -> Self {
        Self {
            cluster: cluster.clone(),
            session_ttl: AtomicU64::new(SESSION_TTL_SECS * 1000),
            code_ttl: AtomicU64::new(CODE_TTL_SECS * 1000),
        }
    }

    /// Tests: both lifetimes (pending and confirmed) become `ttl`.
    pub fn set_lifetimes_for_tests(&self, ttl: Duration) {
        let ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        self.session_ttl.store(ms, Ordering::Relaxed);
        self.code_ttl.store(ms, Ordering::Relaxed);
    }

    fn names(id: &str) -> (String, String, String) {
        let h = util::sha256_b64(id);
        (format!("connect-session:{h}"), format!("connect-open:{h}"), format!("connect-ready:{h}"))
    }

    async fn put(&self, name: &str, record: &Record) -> Result<(), ApiError> {
        let left = Duration::from_millis(record.expires_at_ms.saturating_sub(now_ms()));
        self.cluster.put_sealed(name, record, left + GRACE).await.map_err(cache::unavailable)
    }

    /// A new pending session (`user_id`: the creator of an unlock session); returns its id and lifetime in seconds.
    pub async fn create(
        &self,
        challenge: &str,
        device_name: &str,
        purpose: Purpose,
        user_id: Option<&str>,
    ) -> Result<(String, u64), ApiError> {
        let id = util::random_token(32);
        let ttl = self.session_ttl.load(Ordering::Relaxed);
        let (data, open, _) = Self::names(&id);
        let record = Record {
            challenge: challenge.to_string(),
            device_name: device_name.to_string(),
            stage: Stage::Pending,
            expires_at_ms: now_ms() + ttl,
            purpose,
            user_id: user_id.map(str::to_string),
        };
        self.put(&data, &record).await?;
        self.cluster.put_sealed(&open, &true, Duration::from_millis(ttl)).await.map_err(cache::unavailable)?;
        Ok((id, ttl.div_ceil(1000)))
    }

    /// The pending session for a confirmation: `connect.session_invalid` (400) if unknown, `410` if it expired or
    /// was already confirmed.
    pub async fn open(&self, id: &str) -> Result<Open, ApiError> {
        if !valid_id(id) {
            return Err(session_invalid());
        }
        let (data, _, _) = Self::names(id);
        let record: Record =
            self.cluster.get_sealed(&data).await.map_err(cache::unavailable)?.ok_or_else(session_invalid)?;
        if record.stage != Stage::Pending || now_ms() >= record.expires_at_ms {
            return Err(session_expired());
        }
        Ok(Open {
            challenge: record.challenge,
            device_name: record.device_name,
            purpose: record.purpose,
            user_id: record.user_id,
        })
    }

    /// Confirms the session once (the marker is taken atomically, so of two confirmations only one succeeds) and
    /// stores `code` and `sealed_unlock` for the app's next poll.
    pub async fn confirm(
        &self,
        id: &str,
        session: &Open,
        code: Option<&str>,
        sealed_unlock: Option<&str>,
    ) -> Result<(), ApiError> {
        let (data, open, ready) = Self::names(id);
        if self.cluster.take_sealed::<bool>(&open).await.map_err(cache::unavailable)?.is_none() {
            return Err(session_expired());
        }
        let ttl = self.code_ttl.load(Ordering::Relaxed);
        let handout = Handout { code: code.map(str::to_string), sealed_unlock: sealed_unlock.map(str::to_string) };
        self.cluster.put_sealed(&ready, &handout, Duration::from_millis(ttl)).await.map_err(cache::unavailable)?;
        let record = Record {
            challenge: session.challenge.clone(),
            device_name: session.device_name.clone(),
            stage: Stage::Ready,
            expires_at_ms: now_ms() + ttl,
            purpose: session.purpose,
            user_id: session.user_id.clone(),
        };
        self.put(&data, &record).await
    }

    /// The app's poll: pending, the code and sealed unlock material (once), expired or unknown.
    pub async fn poll(&self, id: &str) -> Result<Poll, ApiError> {
        if !valid_id(id) {
            return Ok(Poll::Unknown);
        }
        let (data, _, ready) = Self::names(id);
        let Some(mut record) = self.cluster.get_sealed::<Record>(&data).await.map_err(cache::unavailable)? else {
            return Ok(Poll::Unknown);
        };
        let now = now_ms();
        if now >= record.expires_at_ms {
            return Ok(Poll::Expired);
        }
        match record.stage {
            Stage::Pending => Ok(Poll::Pending {
                device_name: record.device_name,
                purpose: record.purpose,
                expires_in: secs_left(record.expires_at_ms, now),
            }),
            Stage::Spent => Ok(Poll::Expired),
            Stage::Ready => {
                let Some(handout) = self.cluster.take_sealed::<Handout>(&ready).await.map_err(cache::unavailable)?
                else {
                    return Ok(Poll::Expired);
                };
                let expires_in = secs_left(record.expires_at_ms, now);
                record.stage = Stage::Spent;
                self.put(&data, &record).await?;
                Ok(Poll::Ready { code: handout.code, sealed_unlock: handout.sealed_unlock, expires_in })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn standalone() -> ConnectSessions {
        ConnectSessions::new(&Arc::new(Cluster::standalone("n.test", &[1; 32])))
    }

    #[test]
    fn ids() {
        assert!(valid_id(&util::random_token(32)));
        assert!(!valid_id(""));
        assert!(!valid_id(&util::random_token(31)));
        assert!(!valid_id(&"+".repeat(43)));
        assert!(!valid_id(&format!("{}=", util::random_token(32))));
    }

    #[tokio::test]
    async fn a_session_is_confirmed_once_and_hands_out_its_code_once() {
        let s = standalone();
        let (id, ttl) = s.create("challenge", "Laptop", Purpose::Login, None).await.unwrap();
        assert_eq!(ttl, SESSION_TTL_SECS);
        assert!(
            matches!(s.poll(&id).await.unwrap(), Poll::Pending { ref device_name, purpose: Purpose::Login, .. } if device_name == "Laptop")
        );
        let open = s.open(&id).await.unwrap();
        assert_eq!((open.challenge.as_str(), open.device_name.as_str()), ("challenge", "Laptop"));
        s.confirm(&id, &open, Some("the-code"), None).await.unwrap();
        assert!(
            matches!(s.confirm(&id, &open, Some("other"), None).await, Err(ApiError::Gone { .. })),
            "confirmed once"
        );
        assert!(matches!(s.open(&id).await, Err(ApiError::Gone { .. })));
        assert!(
            matches!(s.poll(&id).await.unwrap(), Poll::Ready { ref code, sealed_unlock: None, expires_in } if code.as_deref() == Some("the-code") && expires_in <= CODE_TTL_SECS)
        );
        assert_eq!(s.poll(&id).await.unwrap(), Poll::Expired, "the code is handed out once");
    }

    #[test]
    fn sealed_unlock_limits() {
        let b64 = |n: usize| URL_SAFE_NO_PAD.encode(vec![7u8; n]);
        assert!(valid_sealed_unlock(&b64(SEALED_UNLOCK_MIN)));
        assert!(valid_sealed_unlock(&b64(SEALED_UNLOCK_MAX)));
        assert!(!valid_sealed_unlock(&b64(SEALED_UNLOCK_MIN - 1)));
        assert!(!valid_sealed_unlock(&b64(SEALED_UNLOCK_MAX + 1)));
        assert!(!valid_sealed_unlock(""));
        assert!(!valid_sealed_unlock(&format!("{}=", b64(50))));
        assert!(!valid_sealed_unlock(&format!("{}+", b64(60))));
        assert!(!valid_sealed_unlock(&"A".repeat(100_000)));
        assert_eq!(Purpose::parse("unlock"), Some(Purpose::Unlock));
        assert_eq!(Purpose::parse("login").map(Purpose::as_str), Some("login"));
        assert_eq!(Purpose::parse("Login"), None);
    }

    #[tokio::test]
    async fn an_unlock_session_keeps_its_user_and_hands_out_only_the_material() {
        let s = standalone();
        let (id, _) = s.create("challenge", "Laptop", Purpose::Unlock, Some("user-1")).await.unwrap();
        assert!(matches!(s.poll(&id).await.unwrap(), Poll::Pending { purpose: Purpose::Unlock, .. }));
        let open = s.open(&id).await.unwrap();
        assert_eq!((open.purpose, open.user_id.as_deref()), (Purpose::Unlock, Some("user-1")));
        s.confirm(&id, &open, None, Some("box")).await.unwrap();
        assert_eq!(
            s.poll(&id).await.unwrap(),
            Poll::Ready { code: None, sealed_unlock: Some("box".into()), expires_in: CODE_TTL_SECS }
        );
        assert_eq!(s.poll(&id).await.unwrap(), Poll::Expired, "once");
    }

    #[tokio::test]
    async fn unknown_and_expired_sessions() {
        let s = standalone();
        assert_eq!(s.poll(&util::random_token(32)).await.unwrap(), Poll::Unknown);
        assert_eq!(s.poll("not-an-id").await.unwrap(), Poll::Unknown);
        assert!(matches!(s.open("not-an-id").await, Err(ApiError::BadRequest { .. })));
        assert!(matches!(s.open(&util::random_token(32)).await, Err(ApiError::BadRequest { .. })));

        s.set_lifetimes_for_tests(Duration::from_millis(50));
        let (id, _) = s.create("c", "d", Purpose::Login, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(s.poll(&id).await.unwrap(), Poll::Expired, "410 within the grace period, not 404");
        assert!(matches!(s.open(&id).await, Err(ApiError::Gone { .. })));

        let (id, _) = s.create("c", "d", Purpose::Login, None).await.unwrap();
        let open = s.open(&id).await.unwrap();
        s.confirm(&id, &open, Some("code"), None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(s.poll(&id).await.unwrap(), Poll::Expired, "a confirmed session lives as long as its code");
    }

    #[tokio::test]
    async fn sessions_created_on_one_instance_are_confirmed_and_polled_on_others() {
        let shared: Arc<dyn cache::Cache> = Arc::new(cache::memory::InProcess::default());
        let instance = |id: &str| {
            ConnectSessions::new(&Arc::new(Cluster::shared_with("n.test", id, shared.clone(), &[2; 32], "")))
        };
        let (a, b, c) = (instance("a"), instance("b"), instance("c"));
        let (id, _) = a.create("challenge", "Laptop", Purpose::Login, None).await.unwrap();
        let open = b.open(&id).await.unwrap();
        b.confirm(&id, &open, Some("code"), Some("sealed-box")).await.unwrap();
        assert!(matches!(a.confirm(&id, &open, Some("again"), None).await, Err(ApiError::Gone { .. })));
        assert!(
            matches!(c.poll(&id).await.unwrap(), Poll::Ready { ref code, ref sealed_unlock, .. } if code.as_deref() == Some("code") && sealed_unlock.as_deref() == Some("sealed-box"))
        );
        assert_eq!(a.poll(&id).await.unwrap(), Poll::Expired);
    }

    #[tokio::test]
    async fn the_cache_never_sees_the_code_or_the_challenge_in_the_clear() {
        let shared = Arc::new(cache::memory::InProcess::default());
        let cluster = Arc::new(Cluster::shared_with("n.test", "a", shared.clone(), &[2; 32], ""));
        let s = ConnectSessions::new(&cluster);
        let (id, _) = s.create("secret-challenge", "Laptop", Purpose::Login, None).await.unwrap();
        let open = s.open(&id).await.unwrap();
        s.confirm(&id, &open, Some("secret-code"), Some("secret-sealed-unlock")).await.unwrap();
        let (data, _, ready) = ConnectSessions::names(&id);
        for name in [data, ready] {
            let raw = cache::Cache::get(shared.as_ref(), &cluster.key(&name)).await.unwrap().unwrap();
            assert!(!raw.contains("secret") && !raw.contains("Laptop") && !raw.contains("sealed"), "{raw}");
        }
        assert!(!ConnectSessions::names(&id).0.contains(&id), "keys carry the hash of the id only");
    }
}
