// SPDX-License-Identifier: AGPL-3.0-only
//! Leader election among the instances of one node: one lease `tavrn:<domain>:leader` (`SET NX PX`, renewed by
//! its holder every third of its lifetime). The leader runs the singleton jobs (housekeeping, the federation
//! outbox, event subscription delivery, directory and conformance workers, voice reconciliation and the grace
//! sweep, the whiteboard sweep) and holds the voice, call and whiteboard state; the others relay those requests
//! to it. A standalone instance is always the leader.
//!
//! Leadership is time-bound: [`super::Cluster::is_leader`] turns false when the lease would have expired, even
//! if the renewing task died, so two instances never both believe they lead longer than a renewal interval.
//! A renewal that fails (cache unreachable) ends the leadership at once; while the cache is down there is no
//! leader and the singleton jobs pause.

use std::{sync::Arc, sync::atomic::Ordering, time::Duration};

use super::{Cluster, lock, now_ms};
use crate::app::AppState;

/// Lifetime of the lease in production; a crashed leader is replaced after at most this.
pub const LEASE: Duration = Duration::from_secs(15);

const KEY: &str = "leader";

/// One attempt to acquire or renew the lease. Returns whether this instance leads now.
pub async fn round(cluster: &Cluster, lease: Duration) -> bool {
    let key = cluster.key(KEY);
    let started = now_ms();
    match cluster.cache.lease(&key, &cluster.instance_id, lease).await {
        Ok(true) => {
            let was = cluster.is_leader();
            // Counted from before the request: the lease in the cache lives at least this long.
            // A tenth of the lease as margin for clock steps and the request's own latency.
            let ms = u64::try_from(lease.as_millis()).unwrap_or(u64::MAX);
            let until = started.saturating_add(ms - ms / 10);
            cluster.leader_until.store(until, Ordering::Relaxed);
            *lock(&cluster.leader_id) = Some(cluster.instance_id.clone());
            if !was {
                tracing::info!(instance = %cluster.instance_id, "this instance is the leader now");
            }
            true
        }
        Ok(false) => {
            if cluster.is_leader() {
                tracing::warn!(instance = %cluster.instance_id, "leader lease lost");
            }
            cluster.leader_until.store(0, Ordering::Relaxed);
            let current = cluster.cache.get(&key).await.ok().flatten();
            *lock(&cluster.leader_id) = current;
            false
        }
        Err(e) => {
            if cluster.is_leader() {
                tracing::error!(error = %e, "leader lease cannot be renewed (cache unreachable): stepping down");
            }
            cluster.leader_until.store(0, Ordering::Relaxed);
            false
        }
    }
}

/// Keeps acquiring/renewing the lease every third of `lease`. Nothing to do standalone (always the leader).
pub fn spawn(state: &AppState, lease: Duration) -> Option<tokio::task::JoinHandle<()>> {
    let cluster: Arc<Cluster> = state.cluster.clone();
    if !cluster.is_shared() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(lease / 3);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            round(&cluster, lease).await;
        }
    }))
}

/// Instances starting at the same time run the migrations, the startup fixups and the storage key setup one
/// after another: this lease is held from before the migrations until the state is assembled.
const STARTUP_KEY: &str = "startup";
/// Longest time one instance may hold the startup lease (long migrations), and the longest wait for it.
pub const STARTUP_LEASE: Duration = Duration::from_secs(300);

/// Waits until this instance holds the startup lease (nothing standalone).
pub async fn startup_lock(cluster: &Cluster) -> anyhow::Result<()> {
    if !cluster.is_shared() {
        return Ok(());
    }
    let key = cluster.key(STARTUP_KEY);
    let deadline = tokio::time::Instant::now() + STARTUP_LEASE;
    let mut logged = false;
    loop {
        match cluster.cache.lease(&key, &cluster.instance_id, STARTUP_LEASE).await {
            Ok(true) => return Ok(()),
            Ok(false) if !logged => {
                tracing::info!("another instance is starting (migrations), waiting for it");
                logged = true;
            }
            Ok(false) => {}
            Err(e) => anyhow::bail!("TAVRN_CACHE_URL: the cache failed during the start: {e}"),
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("another instance held the startup lease for over {STARTUP_LEASE:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Releases the startup lease.
pub async fn startup_unlock(cluster: &Cluster) {
    if cluster.is_shared() {
        let _ = cluster.cache.release(&cluster.key(STARTUP_KEY), &cluster.instance_id).await;
    }
}

/// Gives the lease up (graceful shutdown), so another instance takes over at its next renewal.
pub async fn step_down(cluster: &Cluster) {
    if !cluster.is_shared() {
        return;
    }
    let was = cluster.is_leader();
    cluster.leader_until.store(0, Ordering::Relaxed);
    if was && let Err(e) = cluster.cache.release(&cluster.key(KEY), &cluster.instance_id).await {
        tracing::warn!(error = %e, "leader lease not released (it expires by itself)");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cache::{Cache, memory::InProcess};

    #[tokio::test]
    async fn exactly_one_instance_leads_and_another_takes_over() {
        let cache: Arc<dyn Cache> = Arc::new(InProcess::default());
        let a = Cluster::shared_with("n.test", "a", cache.clone(), &[0; 32], "");
        let b = Cluster::shared_with("n.test", "b", cache.clone(), &[0; 32], "");
        let lease = Duration::from_millis(600);
        assert!(round(&a, lease).await);
        assert!(!round(&b, lease).await);
        assert!(a.is_leader() && !b.is_leader());
        assert_eq!(b.leader_id().as_deref(), Some("a"));
        // a stops renewing (crashed): its leadership lapses by itself, b takes over after the lease.
        tokio::time::sleep(lease).await;
        assert!(!a.is_leader(), "time-bound");
        assert!(round(&b, lease).await);
        assert!(!round(&a, lease).await);
        // A graceful stop hands over at once.
        step_down(&b).await;
        assert!(!b.is_leader());
        assert!(round(&a, lease).await);
    }
}
