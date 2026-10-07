// SPDX-License-Identifier: AGPL-3.0-only
//! The tests' own PostgreSQL databases (tests/common/databases.rs): leftovers are swept, a test node drops its
//! database when it goes away. PostgreSQL only: skipped without `TAVRN_TEST_DATABASE_URL`.

use std::time::Duration;

use crate::common::{databases, test_node};

fn postgres(test: &str) -> Option<String> {
    let url = std::env::var("TAVRN_TEST_DATABASE_URL").ok();
    if url.is_none() {
        eprintln!("{test}: skipped, set TAVRN_TEST_DATABASE_URL (a test PostgreSQL) to run it");
    }
    url
}

#[tokio::test]
async fn stale_test_databases_are_swept_and_fresh_ones_stay() {
    let Some(base) = postgres("stale_test_databases_are_swept_and_fresh_ones_stay") else { return };
    let mut admin = databases::admin(&base).await;
    let now = databases::now_ms();
    let old = databases::name_at(now - 3_600_000);
    let fresh = databases::name_at(now);
    for name in [&old, &fresh] {
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();
    }

    databases::sweep(&mut admin, &base, Duration::from_secs(30 * 60)).await;
    assert!(!databases::exists(&mut admin, &old).await, "the database of an hour ago is swept");
    assert!(databases::exists(&mut admin, &fresh).await, "a fresh database stays");

    sqlx::query(&format!("DROP DATABASE {fresh}")).execute(&mut admin).await.unwrap();
}

#[tokio::test]
async fn a_test_node_drops_its_database_when_it_goes_away() {
    let Some(base) = postgres("a_test_node_drops_its_database_when_it_goes_away") else { return };
    let node = test_node("a.test").await;
    node.register("alice").await;
    let name = node.state.config.database_url.rsplit_once('/').unwrap().1.to_string();
    assert!(databases::created_ms(&name).is_some(), "{name}");
    let mut admin = databases::admin(&base).await;
    assert!(databases::exists(&mut admin, &name).await);

    drop(node);
    assert!(!databases::exists(&mut admin, &name).await, "{name} is dropped with its node");
}
