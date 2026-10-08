// SPDX-License-Identifier: AGPL-3.0-only
//! Several instances of one node (`TAVRN_CACHE_URL`, docs/SCALING.md): test nodes that share one database, one
//! data directory (node keys, `secrets.key`) and one cache, each serving HTTP on its own port.
//!
//! The cache is either an in-process one shared by the instances (always) or the Valkey/Redis of
//! `TAVRN_TEST_CACHE_URL` (e.g. `redis://127.0.0.1:56379`; tests using it are skipped with a message when unset).

use std::{sync::Arc, time::Duration};

use tavrn_node::{
    app::{AppState, router},
    cache::{Cache, Cluster, memory::InProcess, valkey::Valkey},
};

use super::{TestNode, dev_config};

pub struct Instance {
    pub node: TestNode,
    /// `http://127.0.0.1:<port>`
    pub base: String,
}

impl Instance {
    pub fn ws_url(&self) -> String {
        format!("{}/api/v1/ws", self.base.replace("http://", "ws://"))
    }
}

/// All integration tests share one process and one test Valkey: scenarios hold this lock shared, a test that
/// disturbs the whole Valkey (dropping every connection) holds it exclusively and so never runs alongside them.
static VALKEY_USE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Held while a test uses the shared Valkey (see [`valkey`], [`valkey_exclusive`]).
pub enum ValkeyGuard {
    Shared(tokio::sync::RwLockReadGuard<'static, ()>),
    Exclusive(tokio::sync::RwLockWriteGuard<'static, ()>),
}

/// The Valkey of `TAVRN_TEST_CACHE_URL`, or `None` (with a message) when the variable is unset. Keep the guard
/// until the test ends.
pub async fn valkey(test: &str) -> Option<(Arc<dyn Cache>, ValkeyGuard)> {
    let url = valkey_url(test)?;
    let guard = ValkeyGuard::Shared(VALKEY_USE.read().await);
    Some((connect_valkey(&url).await, guard))
}

/// [`valkey`] for a test that disturbs the whole Valkey: no other Valkey test runs meanwhile.
pub async fn valkey_exclusive(test: &str) -> Option<(Arc<dyn Cache>, ValkeyGuard)> {
    let url = valkey_url(test)?;
    let guard = ValkeyGuard::Exclusive(VALKEY_USE.write().await);
    Some((connect_valkey(&url).await, guard))
}

fn valkey_url(test: &str) -> Option<String> {
    let Ok(url) = std::env::var("TAVRN_TEST_CACHE_URL") else {
        eprintln!("{test}: skipped, set TAVRN_TEST_CACHE_URL=redis://127.0.0.1:56379 (a test Valkey) to run it");
        return None;
    };
    Some(url)
}

async fn connect_valkey(url: &str) -> Arc<dyn Cache> {
    Arc::new(Valkey::connect(url).await.expect("the Valkey of TAVRN_TEST_CACHE_URL answers"))
}

pub fn in_process() -> Arc<dyn Cache> {
    Arc::new(InProcess::default())
}

/// A fresh database for the instances: PostgreSQL with `TAVRN_TEST_DATABASE_URL`, else an SQLite file.
async fn shared_database(dir: &std::path::Path) -> (String, Option<super::databases::TestDatabase>) {
    match std::env::var("TAVRN_TEST_DATABASE_URL") {
        Ok(_) => super::test_database_url().await,
        Err(_) => (format!("sqlite://{}/tavrn.db?mode=rwc", dir.display()), None),
    }
}

/// A unique identity domain per test: instances of one test share a cache namespace, tests do not.
pub fn domain() -> String {
    format!("c{}.test", &tavrn_node::util::ulid().to_lowercase()[16..])
}

/// `n` instances of the node `domain` sharing `cache`. Instance ids are `i0`, `i1`, …; nobody leads yet.
pub async fn instances(domain: &str, cache: Arc<dyn Cache>, n: usize) -> Vec<Instance> {
    instances_with(domain, cache, n, |_| {}).await
}

/// [`instances`] with each state changed by `tweak` before its router is built.
pub async fn instances_with(
    domain: &str,
    cache: Arc<dyn Cache>,
    n: usize,
    tweak: impl Fn(&mut AppState),
) -> Vec<Instance> {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let (url, db) = shared_database(tmp.path()).await;
    let mut out = Vec::new();
    let (mut tmp, mut db) = (Some(tmp), db);
    for i in 0..n {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut config = dev_config(domain, &data_dir, &url);
        config.listen = listener.local_addr().unwrap().to_string();
        config.validate().unwrap();
        let key_dir = std::path::Path::new(&data_dir).join("keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let secret = tavrn_node::keys::load_or_create_secret(&key_dir).unwrap();
        let cluster = Cluster::shared_with(domain, &format!("i{i}"), cache.clone(), &secret, &base);
        let mut state = AppState::init_with(config, Default::default(), Some(cluster)).await.unwrap();
        tweak(&mut state);
        let app = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap()
        });
        out.push(Instance {
            node: TestNode {
                router: router(state.clone()),
                state,
                factors: Default::default(),
                reauth: Default::default(),
                // The first instance owns the shared directory; the others get an unused one.
                _tmp: tmp.take().unwrap_or_else(|| tempfile::tempdir().unwrap()),
                // ... and the shared database.
                _db: db.take(),
            },
            base,
        });
    }
    // Every instance has heard of every other one (relay addresses, presence).
    wait_for(Duration::from_secs(5), || out.iter().all(|i| i.node.state.cluster.peers().len() == n - 1)).await;
    out
}

/// Makes instance `leader` the leader (one lease round each, the leader first).
pub async fn elect(instances: &[Instance], leader: usize, lease: Duration) {
    assert!(tavrn_node::cache::leader::round(&instances[leader].node.state.cluster, lease).await);
    for (i, inst) in instances.iter().enumerate() {
        if i != leader {
            assert!(!tavrn_node::cache::leader::round(&inst.node.state.cluster, lease).await);
        }
    }
}

/// Polls `cond` every 20 ms until it holds; fails the test after `max`.
pub async fn wait_for(max: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + max;
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "condition not reached within {max:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The same factors (TOTP secret, recovery codes) on another instance's test node.
pub fn share_factors(from: &TestNode, to: &TestNode) {
    let factors = from.factors.lock().unwrap().clone();
    to.factors.lock().unwrap().extend(factors);
}
