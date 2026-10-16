// SPDX-License-Identifier: AGPL-3.0-only
//! Write latency of the PostgreSQL server under the node (perf/README.md "Noisy runners").
//!
//! Every message the node accepts is a PostgreSQL commit, and the server commits with fsync, so the send latency
//! budgets measure the machine's disk as well as the node. GitHub's runners of one label differ there: on the
//! AMD EPYC 9V74 runners the send p95 was 75-140 ms against 10-18 ms on the others with the same node, while the
//! reads and the node's CPU were as always. This probe commits one small row at a time on a table of its own in
//! the run's throwaway database, beside the node: its tail is the disk's, measured in the same window as the
//! node's sends.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use sqlx::{Connection, Executor, PgConnection};
use tokio::{sync::watch, task::JoinHandle};

use crate::stats::Samples;

/// A running probe: one commit every `every` until [`Probe::finish`].
pub struct Probe {
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<Samples>>,
}

impl Probe {
    pub async fn start(database_url: &str, every: Duration) -> Result<Self> {
        let mut conn = PgConnection::connect(database_url).await?;
        conn.execute("CREATE TABLE IF NOT EXISTS loadgen_disk_probe (id BIGSERIAL PRIMARY KEY, pad TEXT NOT NULL)")
            .await?;
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            // About the size of a message row.
            let pad = "x".repeat(200);
            let mut samples = Samples::default();
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    _ = tick.tick() => {}
                }
                let t0 = Instant::now();
                match sqlx::query("INSERT INTO loadgen_disk_probe (pad) VALUES ($1)")
                    .bind(&pad)
                    .execute(&mut conn)
                    .await
                {
                    Ok(_) => samples.push(t0.elapsed().as_secs_f64() * 1000.0),
                    Err(_) => samples.errors += 1,
                }
            }
            conn.close().await?;
            Ok(samples)
        });
        Ok(Self { stop, task })
    }

    pub async fn finish(self) -> Result<Samples> {
        let _ = self.stop.send(true);
        self.task.await.map_err(|e| anyhow!("disk probe: {e}"))?
    }
}
