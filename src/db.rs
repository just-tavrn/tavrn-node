// SPDX-License-Identifier: AGPL-3.0-only
//! Database access via `sqlx::AnyPool`, so that PostgreSQL (production) and SQLite (development)
//! share the same code. Migrations live in `migrations/` and run at startup.

use anyhow::Context;
use log::LevelFilter;
use sqlx::{
    AnyPool, ConnectOptions, Connection,
    any::{AnyConnectOptions, AnyPoolOptions},
};
use std::{str::FromStr, time::Duration};

pub type Pool = AnyPool;

/// Connections of a PostgreSQL pool (per instance; docs/HANDBOOK.md "Database" sizes `max_connections` by it).
const MAX_CONNECTIONS: u32 = 16;
/// Connections a PostgreSQL pool keeps open even when the node is idle. Without them an idle node dropped all its
/// connections after the idle timeout, and the first clicks after a quiet period paid a new connection (TCP, TLS,
/// SCRAM authentication) plus the re-preparation of every statement on it.
const MIN_CONNECTIONS: u32 = 2;
/// An idle connection is closed after this long (above the minimum). sqlx's default (10 minutes) is short for a
/// chat node with quiet hours; the minimum connections stay regardless.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Every connection is replaced after this long, so server-side memory (prepared statements, caches) and a
/// failover behind a DNS name are picked up eventually.
const MAX_LIFETIME: Duration = Duration::from_secs(2 * 3600);
/// A connection idle for longer than this is pinged before it is handed out (a firewall or the server may have
/// dropped it); a connection in recent use is handed out directly. sqlx's default pings on every acquire, a
/// round trip per request (and per transaction) that a busy node does not need.
const PING_AFTER_IDLE: Duration = Duration::from_secs(30);

/// The pool settings of a database URL: SQLite (development and tests) is one connection, kept open.
fn pool_options(database_url: &str) -> AnyPoolOptions {
    let sqlite = database_url.starts_with("sqlite:");
    AnyPoolOptions::new()
        .max_connections(if sqlite { 1 } else { MAX_CONNECTIONS })
        .min_connections(if sqlite { 1 } else { MIN_CONNECTIONS })
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(IDLE_TIMEOUT)
        .max_lifetime(MAX_LIFETIME)
        .test_before_acquire(false)
        .before_acquire(|conn, meta| {
            Box::pin(async move {
                if needs_ping(meta.idle_for) {
                    conn.ping().await?;
                }
                Ok(true)
            })
        })
}

/// Whether a connection that was idle for `idle_for` is pinged before use ([`PING_AFTER_IDLE`]).
fn needs_ping(idle_for: Duration) -> bool {
    idle_for > PING_AFTER_IDLE
}

/// The default of `TAVRN_DB_SLOW_STATEMENT_MS` (sqlx's own).
pub const SLOW_STATEMENT: Duration = Duration::from_secs(1);

/// Connects with the default slow statement threshold (tests and tools).
pub async fn connect(database_url: &str) -> anyhow::Result<Pool> {
    connect_with(database_url, Some(SLOW_STATEMENT)).await
}

/// Connects, migrates and prepares the search schema. A statement that takes `slow_statement` or longer is logged as
/// a warning (`sqlx::query`: `slow statement`); `None` turns that off.
pub async fn connect_with(database_url: &str, slow_statement: Option<Duration>) -> anyhow::Result<Pool> {
    sqlx::any::install_default_drivers();
    if let Some(dir) = sqlite_parent_dir(database_url) {
        std::fs::create_dir_all(&dir).with_context(|| format!("cannot create SQLite directory {dir}"))?;
    }
    let failed = || format!("database connection failed ({})", redact(database_url));
    let options = AnyConnectOptions::from_str(database_url).with_context(failed)?;
    // Off: never "slow", so every statement keeps its normal (debug) level, which the per-request statement count of
    // `TAVRN_LOG_SLOW_REQUEST_MS` relies on.
    let options = match slow_statement {
        Some(threshold) => options.log_slow_statements(LevelFilter::Warn, threshold),
        None => options.log_slow_statements(LevelFilter::Off, Duration::MAX),
    };
    let pool = pool_options(database_url).connect_with(options).await.with_context(failed)?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("database migration failed (schema newer than the binary? Then a downgrade is not possible)")?;
    // Full-text structures that differ between PostgreSQL and SQLite (migration 0210, search.rs).
    crate::search::ensure_schema(&pool, crate::search::Dialect::of(database_url))
        .await
        .context("search index schema could not be created")?;
    Ok(pool)
}

/// Simple connection check for `/readyz`.
pub async fn ping(pool: &Pool) -> bool {
    sqlx::query("SELECT 1").execute(pool).await.is_ok()
}

fn sqlite_parent_dir(url: &str) -> Option<String> {
    let path = url.strip_prefix("sqlite://")?.split('?').next()?;
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    let parent = std::path::Path::new(path).parent()?;
    (!parent.as_os_str().is_empty()).then(|| parent.to_string_lossy().into_owned())
}

/// Removes the password from a connection URL for logs and error messages.
pub fn redact(url: &str) -> String {
    match (url.find("://"), url.find('@')) {
        (Some(s), Some(a)) if a > s => {
            let creds = &url[s + 3..a];
            match creds.split_once(':') {
                Some((user, _)) => format!("{}://{}:***@{}", &url[..s], user, &url[a + 1..]),
                None => url.to_string(),
            }
        }
        _ => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn redact_hides_password() {
        assert_eq!(redact("postgres://tavrn:secret@db/tavrn"), "postgres://tavrn:***@db/tavrn");
        assert_eq!(redact("sqlite://x.db"), "sqlite://x.db");
        assert_eq!(redact("postgres://user@db/x"), "postgres://user@db/x");
    }

    #[test]
    fn sqlite_parent_dir_is_detected() {
        assert_eq!(sqlite_parent_dir("sqlite://data-dev/tavrn.db?mode=rwc"), Some("data-dev".into()));
        assert_eq!(sqlite_parent_dir("sqlite://tavrn.db"), None);
        assert_eq!(sqlite_parent_dir("sqlite::memory:"), None);
        assert_eq!(sqlite_parent_dir("postgres://x"), None);
    }

    #[test]
    fn pool_keeps_connections_and_pings_only_after_idle() {
        let pg = pool_options("postgres://u@db/x");
        assert_eq!((pg.get_min_connections(), pg.get_max_connections()), (MIN_CONNECTIONS, MAX_CONNECTIONS));
        assert!(!pg.get_test_before_acquire(), "no ping round trip on every acquire");
        assert_eq!(pg.get_idle_timeout(), Some(IDLE_TIMEOUT));
        assert_eq!(pg.get_max_lifetime(), Some(MAX_LIFETIME));
        assert!(IDLE_TIMEOUT < MAX_LIFETIME);
        let sqlite = pool_options("sqlite://data-dev/tavrn.db?mode=rwc");
        assert_eq!((sqlite.get_min_connections(), sqlite.get_max_connections()), (1, 1));
        assert!(!needs_ping(Duration::ZERO));
        assert!(!needs_ping(PING_AFTER_IDLE));
        assert!(needs_ping(PING_AFTER_IDLE + Duration::from_millis(1)));
    }

    /// The pool hands out its connection again and again (`before_acquire` keeps it).
    #[tokio::test]
    async fn the_pool_reuses_its_connection() {
        let pool = connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE t (x INTEGER)").execute(&pool).await.unwrap();
        for i in 0..5_i64 {
            sqlx::query("INSERT INTO t (x) VALUES ($1)").bind(i).execute(&pool).await.unwrap();
        }
        // An in-memory database lives in its one connection: the rows prove it was never replaced.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM t").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(pool.size(), 1);
    }

    #[tokio::test]
    async fn in_memory_sqlite_connects_and_migrates() {
        let pool = connect("sqlite::memory:").await.unwrap();
        assert!(ping(&pool).await);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_settings").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    /// Migration 0410: a room's categories and permission overrides are read through an index, not a table scan.
    #[tokio::test]
    async fn room_snapshot_reads_use_the_room_indexes() {
        let pool = connect("sqlite::memory:").await.unwrap();
        for (sql, index) in [
            ("SELECT id FROM categories WHERE room_id = 'r' ORDER BY position, id", "categories_room"),
            ("SELECT id FROM permission_overrides WHERE room_id = 'r' ORDER BY id", "permission_overrides_room"),
        ] {
            let plan: Vec<(i64, i64, i64, String)> =
                sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}")).fetch_all(&pool).await.unwrap();
            assert!(plan.iter().any(|(.., detail)| detail.contains(index)), "{sql}: {plan:?}");
        }
    }

    /// Binary columns (BYTEA) round-trip through the `Any` driver on SQLite (and PostgreSQL in test-pg).
    #[tokio::test]
    async fn binary_columns_roundtrip() {
        // On PostgreSQL a database `t_<ulid>` like the integration tests' (tests/common/databases.rs), dropped at
        // the end; if the test fails, their sweep drops it later.
        let postgres = match std::env::var("TAVRN_TEST_DATABASE_URL") {
            Ok(base) => {
                sqlx::any::install_default_drivers();
                let name = format!("t_{}", crate::util::ulid().to_lowercase());
                let admin = sqlx::AnyPool::connect(&base).await.unwrap();
                sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
                Some((admin, format!("{}/{name}", base.rsplit_once('/').unwrap().0), name))
            }
            Err(_) => None,
        };
        let url = postgres.as_ref().map_or("sqlite::memory:", |(_, url, _)| url.as_str());
        let pool = connect(url).await.unwrap();
        let ts = crate::util::now();
        sqlx::query(
            "INSERT INTO users (id, username, domain, display_name, created_at) VALUES ('u', 'u', 'd', 'u', $1)",
        )
        .bind(&ts)
        .execute(&pool)
        .await
        .unwrap();
        let blob: Vec<u8> = (0..=255u8).chain([0, 0, 255]).collect();
        sqlx::query(
            "INSERT INTO key_backups (user_id, conversation, blob, etag, updated_at) VALUES ('u', 'c', $1, 'e', $2)",
        )
        .bind(blob.clone())
        .bind(&ts)
        .execute(&pool)
        .await
        .unwrap();
        let back: Vec<u8> =
            sqlx::query_scalar("SELECT blob FROM key_backups WHERE user_id = 'u'").fetch_one(&pool).await.unwrap();
        assert_eq!(back, blob);
        pool.close().await;
        if let Some((admin, _, name)) = postgres {
            sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&admin).await.unwrap();
        }
    }

    #[tokio::test]
    async fn unreachable_database_is_a_clear_error() {
        let err = connect("postgres://u:pw@127.0.0.1:1/x").await.unwrap_err().to_string();
        assert!(err.contains("database connection failed"), "{err}");
        assert!(!err.contains("pw@"), "the password must not appear in the message: {err}");
    }
}
