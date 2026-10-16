// SPDX-License-Identifier: AGPL-3.0-only
//! Write latency of the PostgreSQL server under the node (perf/README.md "Noisy runners").
//!
//! Every message the node accepts is a PostgreSQL commit, and the server commits with fsync, so the send latency
//! budgets measure the machine's disk as well as the node. GitHub's runners of one label differ there: on the
//! AMD EPYC 9V74 runners even the MLS join commits of the setup, one after the other with nothing else running,
//! took 98-110 ms at p95 (20-30 ms on the others), and the send p95 was 107-134 ms against 10-12 ms elsewhere
//! with the same node. This probe measures the disk without the node: one-row inserts, each its own commit, on a
//! table of its own in the run's throwaway database, while the node is idle.

use std::time::{Duration, Instant};

use anyhow::Result;
use sqlx::{Connection, Executor, PgConnection};

use crate::stats::Samples;

/// Commits one row every `every` for `window`; latencies in milliseconds.
pub async fn commit_latency(database_url: &str, window: Duration, every: Duration) -> Result<Samples> {
    let mut conn = PgConnection::connect(database_url).await?;
    conn.execute("CREATE TABLE loadgen_disk_probe (id BIGSERIAL PRIMARY KEY, pad TEXT NOT NULL)").await?;
    // About the size of a message row.
    let pad = "x".repeat(200);
    let mut samples = Samples::default();
    let start = tokio::time::Instant::now();
    let mut next = start;
    while next < start + window {
        tokio::time::sleep_until(next).await;
        let t0 = Instant::now();
        match sqlx::query("INSERT INTO loadgen_disk_probe (pad) VALUES ($1)").bind(&pad).execute(&mut conn).await {
            Ok(_) => samples.push(t0.elapsed().as_secs_f64() * 1000.0),
            Err(_) => samples.errors += 1,
        }
        next += every;
    }
    conn.close().await?;
    Ok(samples)
}
