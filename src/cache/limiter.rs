// SPDX-License-Identifier: AGPL-3.0-only
//! Rate limits that protect accounts and the node (logins, registrations, second factors, the federation inbox,
//! webhook executions, app tokens): with several instances an attacker must not get the limit once per instance,
//! so the counters live in the cache (`INCR` + `PEXPIRE NX` in one transaction, a fixed window like
//! [`RateLimiter`]). Standalone they are exactly the in-memory [`RateLimiter`]. If the cache fails the instance
//! falls back to its own counter (logged), so a cache outage never disables the limit.
//!
//! Limits that only shed load (typing, presence, reads, uploads, …) stay per instance (`docs/SCALING.md`).

use std::{sync::Arc, time::Duration};

use crate::{auth::RateLimiter, error::ApiError};

use super::Cluster;

/// Keys longer than this are hashed (they may carry user input such as a username).
const MAX_KEY: usize = 128;

pub struct SharedLimiter {
    name: &'static str,
    max: u32,
    window: Duration,
    local: RateLimiter,
    cluster: Option<Arc<Cluster>>,
}

impl SharedLimiter {
    /// `name` separates the limiters in the cache (`tavrn:<domain>:rl:<name>:<key>`).
    pub fn new(name: &'static str, max: u32, window: Duration, cluster: &Arc<Cluster>) -> Self {
        Self {
            name,
            max,
            window,
            local: RateLimiter::new(max, window),
            cluster: cluster.is_shared().then(|| cluster.clone()),
        }
    }

    /// `Ok(())` or `Err(seconds until the next attempt)`.
    pub async fn check(&self, key: &str) -> Result<(), u32> {
        let Some(cluster) = &self.cluster else { return self.local.check(key) };
        let key = self.cache_key(key);
        match cluster.cache().hit(&cluster.key(&format!("rl:{}:{key}", self.name)), self.window).await {
            Ok((n, left)) if n > u64::from(self.max) => {
                Err(u32::try_from(left.as_secs()).unwrap_or(u32::MAX).saturating_add(1))
            }
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(limiter = self.name, error = %e, "shared rate limit unavailable, counting on this instance");
                self.local.check(&key)
            }
        }
    }

    /// The key in the cache: client addresses normalised (`auth::normalize_key`), long keys hashed.
    fn cache_key(&self, key: &str) -> String {
        let key = crate::auth::normalize_key(key);
        if key.len() > MAX_KEY { crate::util::sha256_b64(&key) } else { key.into_owned() }
    }

    /// Like [`SharedLimiter::check`] without counting: `Err(seconds)` while `key` is at or over its limit.
    pub async fn peek(&self, key: &str) -> Result<(), u32> {
        let Some(cluster) = &self.cluster else { return self.local.peek(key) };
        let key = self.cache_key(key);
        match cluster.cache().get(&cluster.key(&format!("rl:{}:{key}", self.name))).await {
            Ok(Some(n)) if n.trim().parse::<u64>().is_ok_and(|n| n >= u64::from(self.max)) => {
                Err(u32::try_from(self.window.as_secs()).unwrap_or(u32::MAX).saturating_add(1))
            }
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(limiter = self.name, error = %e, "shared rate limit unavailable, counting on this instance");
                self.local.peek(&key)
            }
        }
    }

    /// [`SharedLimiter::check`] for many keys at once (one fan-out over many users): the cache round trips run
    /// concurrently on its multiplexed connection. `true` for each key under its limit, in the order of `keys`.
    pub async fn check_many(&self, keys: &[String]) -> Vec<bool> {
        futures::future::join_all(keys.iter().map(|k| async move { self.check(k).await.is_ok() })).await
    }

    /// [`SharedLimiter::peek`] for many keys at once, like [`SharedLimiter::check_many`].
    pub async fn peek_many(&self, keys: &[String]) -> Vec<bool> {
        futures::future::join_all(keys.iter().map(|k| async move { self.peek(k).await.is_ok() })).await
    }

    /// Counts every key in order and stops at the first one over its limit (like [`RateLimiter::check_all`]).
    pub async fn check_all(&self, keys: &[String]) -> Result<(), ApiError> {
        for k in keys {
            if let Err(retry_after_secs) = self.check(k).await {
                return Err(ApiError::RateLimited { retry_after_secs });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cache::{Cache, memory::InProcess};

    #[tokio::test]
    async fn standalone_counts_like_the_in_memory_limiter() {
        let c = Arc::new(Cluster::standalone("n.test", &[0; 32]));
        let l = SharedLimiter::new("login", 2, Duration::from_millis(80), &c);
        assert!(l.check("a").await.is_ok());
        assert!(l.check("a").await.is_ok());
        assert!(l.check("a").await.unwrap_err() >= 1);
        assert!(l.check("b").await.is_ok());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(l.check("a").await.is_ok(), "next window");
        let err = l.check_all(&["a".into(), "a".into(), "a".into()]).await.unwrap_err();
        let keys: Vec<String> = ["c", "d", "c", "c"].map(String::from).to_vec();
        assert_eq!(l.peek_many(&keys).await, [true; 4]);
        assert_eq!(l.check_many(&keys).await.iter().filter(|ok| **ok).count(), 3, "c twice, d once");
        assert_eq!(l.peek_many(&keys).await, [false, true, false, false]);
        assert!(matches!(err, ApiError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn instances_share_one_counter() {
        let cache: Arc<dyn Cache> = Arc::new(InProcess::default());
        let a = Arc::new(Cluster::shared_with("n.test", "a", cache.clone(), &[0; 32], ""));
        let b = Arc::new(Cluster::shared_with("n.test", "b", cache.clone(), &[0; 32], ""));
        let la = SharedLimiter::new("login", 3, Duration::from_secs(60), &a);
        let lb = SharedLimiter::new("login", 3, Duration::from_secs(60), &b);
        let other = SharedLimiter::new("register", 3, Duration::from_secs(60), &b);
        for _ in 0..3 {
            la.check("ip:1").await.unwrap();
        }
        let retry = lb.check("ip:1").await.unwrap_err();
        assert!((1..=61).contains(&retry), "{retry}");
        assert!(other.check("ip:1").await.is_ok(), "limiters are separate");
        // Long keys are hashed, still counted.
        let long = "u".repeat(500);
        for _ in 0..3 {
            la.check(&long).await.unwrap();
        }
        assert!(lb.check(&long).await.is_err());
        // Peeking counts nothing, on both instances.
        let pa = SharedLimiter::new("peek", 2, Duration::from_secs(60), &a);
        let pb = SharedLimiter::new("peek", 2, Duration::from_secs(60), &b);
        assert!(pa.peek("user:x").await.is_ok());
        pa.check("user:x").await.unwrap();
        pb.check("user:x").await.unwrap();
        assert!(pa.peek("user:x").await.is_err(), "at the limit on the other instance as well");
        assert!(pb.peek("user:y").await.is_ok());
        // Addresses of one IPv6 /64 share a counter.
        let v6 = SharedLimiter::new("v6", 1, Duration::from_secs(60), &a);
        v6.check("ip:2001:db8::1").await.unwrap();
        assert!(v6.check("ip:2001:db8::2").await.is_err());
    }
}
