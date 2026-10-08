// SPDX-License-Identifier: AGPL-3.0-only
//! Database access via `sqlx::AnyPool`, so that PostgreSQL (production) and SQLite (development)
//! share the same code. Migrations live in `migrations/` and run at startup.

use anyhow::Context;
use sqlx::{AnyPool, any::AnyPoolOptions};
use std::time::Duration;

pub type Pool = AnyPool;

pub async fn connect(database_url: &str) -> anyhow::Result<Pool> {
    sqlx::any::install_default_drivers();
    if let Some(dir) = sqlite_parent_dir(database_url) {
        std::fs::create_dir_all(&dir).with_context(|| format!("cannot create SQLite directory {dir}"))?;
    }
    let pool = AnyPoolOptions::new()
        .max_connections(if database_url.starts_with("sqlite:") { 1 } else { 16 })
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
        .with_context(|| format!("database connection failed ({})", redact(database_url)))?;
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

    #[tokio::test]
    async fn in_memory_sqlite_connects_and_migrates() {
        let pool = connect("sqlite::memory:").await.unwrap();
        assert!(ping(&pool).await);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_settings").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
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
