// SPDX-License-Identifier: AGPL-3.0-only
//! The throwaway PostgreSQL databases of the tests (`TAVRN_TEST_DATABASE_URL`).
//!
//! Every test node gets its own database `t_<ulid>` on the server of `TAVRN_TEST_DATABASE_URL`. The name carries
//! its creation time (the first ten characters of a ULID are the milliseconds since the epoch), so leftovers can
//! be recognized without bookkeeping:
//! - a test node drops its database when it is dropped ([`TestDatabase`]);
//! - before a database is created, the databases `t_*` older than `TAVRN_TEST_DB_MAX_AGE_SECS` (default 20
//!   minutes) are dropped: what a killed or crashed run left behind ([`sweep`], at most once a minute per
//!   test binary).

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use sqlx::{AnyConnection, Connection};

/// Prefix of the test databases; nothing else is ever dropped.
pub const PREFIX: &str = "t_";

/// Age after which a leftover test database is dropped, unless `TAVRN_TEST_DB_MAX_AGE_SECS` says otherwise.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(20 * 60);

/// Milliseconds since the epoch.
pub fn now_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    u64::try_from(since.as_millis()).unwrap()
}

/// A test database name created at `ms` (milliseconds since the epoch).
pub fn name_at(ms: u64) -> String {
    let ulid = ulid::Ulid::from_parts(ms, ulid::Ulid::new().random());
    format!("{PREFIX}{}", ulid.to_string().to_lowercase())
}

/// Creation time (milliseconds since the epoch) of the test database `name`, `None` for any other name.
pub fn created_ms(name: &str) -> Option<u64> {
    let text = name.strip_prefix(PREFIX).filter(|u| u.len() == ulid::ULID_LEN)?;
    let ulid = ulid::Ulid::from_string(text).ok()?;
    // The decoder wraps values beyond 128 bits (a first character above 7) instead of rejecting them.
    ulid.to_string().eq_ignore_ascii_case(text).then_some(ulid.timestamp_ms())
}

/// The test databases among `names` older than `max_age` at `now_ms`, never `base` (the database of
/// `TAVRN_TEST_DATABASE_URL`).
pub fn stale<'a>(names: &'a [String], base: &str, now_ms: u64, max_age: Duration) -> Vec<&'a str> {
    let max_age = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
    names
        .iter()
        .map(String::as_str)
        .filter(|name| *name != base)
        .filter(|name| created_ms(name).is_some_and(|created| now_ms.saturating_sub(created) > max_age))
        .collect()
}

/// Drops the stale test databases (see [`stale`]) on the server of `admin`, the one of `base_url`; returns how
/// many it dropped. Errors are ignored per database: another test binary may be sweeping the same name.
pub async fn sweep(admin: &mut AnyConnection, base_url: &str, max_age: Duration) -> usize {
    let names: Vec<String> = sqlx::query_scalar(r"SELECT datname::text FROM pg_database WHERE datname LIKE 't\_%'")
        .fetch_all(&mut *admin)
        .await
        .expect("list the test databases");
    let mut dropped = 0;
    for name in stale(&names, database_name(base_url), now_ms(), max_age) {
        if drop_database(admin, name).await {
            dropped += 1;
        }
    }
    dropped
}

/// The database name in a PostgreSQL URL.
fn database_name(url: &str) -> &str {
    let path = url.rsplit_once('/').map_or("", |(_, path)| path);
    path.split_once('?').map_or(path, |(name, _)| name)
}

/// Drops the test database `name` (ending its connections); `false` when it was not dropped.
async fn drop_database(admin: &mut AnyConnection, name: &str) -> bool {
    // Only names `t_<ulid>` get here: letters and digits, nothing to escape.
    debug_assert!(created_ms(name).is_some(), "{name}");
    sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)")).execute(&mut *admin).await.is_ok()
}

/// `TAVRN_TEST_DB_MAX_AGE_SECS`, else [`DEFAULT_MAX_AGE`].
pub fn max_age() -> Duration {
    match std::env::var("TAVRN_TEST_DB_MAX_AGE_SECS") {
        Ok(secs) => {
            Duration::from_secs(secs.trim().parse().expect("TAVRN_TEST_DB_MAX_AGE_SECS is a number of seconds"))
        }
        Err(_) => DEFAULT_MAX_AGE,
    }
}

/// Whether this test binary should sweep now: at most once a minute, so hundreds of tests starting at once
/// list the databases only once.
fn sweep_due() -> bool {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = now_ms();
    let last = LAST.load(Ordering::Relaxed);
    now.saturating_sub(last) >= 60_000 && LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// Creates a fresh test database on the server of `base_url` (the URL of `TAVRN_TEST_DATABASE_URL`), after
/// sweeping the stale ones. Returns its URL and the guard that drops it.
pub async fn create(base_url: &str) -> (String, TestDatabase) {
    let mut admin = admin(base_url).await;
    if sweep_due() {
        sweep(&mut admin, base_url, max_age()).await;
    }
    let name = format!("{PREFIX}{}", tavrn_node::util::ulid().to_lowercase());
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();
    let _ = admin.close().await;
    let (prefix, _) = base_url.rsplit_once('/').unwrap();
    (format!("{prefix}/{name}"), TestDatabase { base_url: base_url.into(), name })
}

/// A test database; dropping the guard drops the database (and ends the connections still open to it).
pub struct TestDatabase {
    base_url: String,
    name: String,
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let (base_url, name) = (self.base_url.clone(), std::mem::take(&mut self.name));
        // A destructor cannot await, and the test's runtime cannot block on async work from inside: a thread
        // with its own runtime drops the database. Failures are left to the sweep.
        let dropping = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            runtime.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(10), async {
                    sqlx::any::install_default_drivers();
                    if let Ok(mut admin) = AnyConnection::connect(&base_url).await {
                        drop_database(&mut admin, &name).await;
                        let _ = admin.close().await;
                    }
                })
                .await;
            });
        });
        let _ = dropping.join();
    }
}

/// Connects to the database of `url` (the server's administrative connection).
pub async fn admin(url: &str) -> AnyConnection {
    sqlx::any::install_default_drivers();
    AnyConnection::connect(url).await.expect("the PostgreSQL of TAVRN_TEST_DATABASE_URL answers")
}

/// Whether the database `name` exists on the server of `admin`.
pub async fn exists(admin: &mut AnyConnection, name: &str) -> bool {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
    n == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600_000;

    #[test]
    fn the_name_carries_the_creation_time() {
        // The example ULID of the specification: its first ten characters 01ARZ3NDEK, read as Crockford base32,
        // are 1469922850259 ms (2016-07-30 23:54:10.259 UTC).
        assert_eq!(created_ms("t_01arz3ndektsv4rrffq69g5fav"), Some(1_469_922_850_259));
        assert_eq!(created_ms("t_01ARZ3NDEKTSV4RRFFQ69G5FAV"), Some(1_469_922_850_259));
        let ms = 1_790_000_000_123;
        let name = name_at(ms);
        assert!(name.starts_with(PREFIX) && name.len() == 28, "{name}");
        assert_eq!(name, name.to_lowercase(), "PostgreSQL folds unquoted names to lower case");
        assert_eq!(created_ms(&name), Some(ms));
        assert_ne!(name_at(ms), name, "the random part differs");
    }

    #[test]
    fn other_names_are_not_test_databases() {
        for name in [
            "tavrn_test",
            "postgres",
            "template1",
            "perf_01arz3ndektsv4rrffq69g5fav",
            "t_",
            "t_foo",
            "t_01arz3ndektsv4rrffq69g5fa",   // 25 characters
            "t_01arz3ndektsv4rrffq69g5favx", // 27 characters
            "t_01arz3ndektsv4rrffq69g5fa!",
            "t_81arz3ndektsv4rrffq69g5fav", // beyond the largest ULID
            "x_01arz3ndektsv4rrffq69g5fav",
        ] {
            assert_eq!(created_ms(name), None, "{name}");
        }
    }

    #[test]
    fn only_old_test_databases_are_stale() {
        let now = 1_790_000_000_000;
        let old = name_at(now - HOUR);
        let fresh = name_at(now - 60_000);
        let future = name_at(now + HOUR);
        let names: Vec<String> =
            [old.as_str(), fresh.as_str(), future.as_str(), "tavrn_test", "t_foo", "postgres"].map(String::from).into();
        assert_eq!(stale(&names, "tavrn_test", now, DEFAULT_MAX_AGE), vec![old.as_str()]);
        assert_eq!(stale(&names, "tavrn_test", now, Duration::from_secs(30)), vec![old.as_str(), fresh.as_str()]);
        // Never the database of TAVRN_TEST_DATABASE_URL, even when it looks like a test database.
        assert!(stale(&names, &old, now, DEFAULT_MAX_AGE).is_empty());
    }
}
