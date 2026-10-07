// SPDX-License-Identifier: AGPL-3.0-only
//! CPU time and resident memory of the node process from `/proc/<pid>/stat` and `/proc/<pid>/status`
//! (Linux only), sampled every second in the background.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

use crate::stats::{lock, round1, round2};

/// One reading of the process.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Snapshot {
    /// Seconds since the sampler started.
    pub t: f64,
    /// User + system CPU time in seconds.
    pub cpu_secs: f64,
    /// Resident set size in MiB.
    pub rss_mb: f64,
}

/// Clock ticks per second for the `utime`/`stime` fields.
fn clock_ticks() -> f64 {
    // SAFETY: sysconf has no preconditions and only reads a constant of the C library.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

/// utime + stime in ticks. The command name (field 2) may contain spaces and parentheses, so the
/// fields are counted after the last `)`: state is field 3, utime field 14, stime field 15.
pub fn parse_stat_ticks(stat: &str) -> Result<u64> {
    let rest = stat.rsplit_once(')').map(|(_, r)| r).ok_or_else(|| anyhow!("unexpected /proc stat format"))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] is field 3 (state), so field n is fields[n - 3].
    let utime: u64 = fields.get(11).ok_or_else(|| anyhow!("stat: utime missing"))?.parse()?;
    let stime: u64 = fields.get(12).ok_or_else(|| anyhow!("stat: stime missing"))?.parse()?;
    Ok(utime + stime)
}

/// `VmRSS` in kB from `/proc/<pid>/status`.
pub fn parse_rss_kb(status: &str) -> Result<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).ok_or_else(|| anyhow!("status: VmRSS missing"))?;
    let kb = line.split_whitespace().nth(1).ok_or_else(|| anyhow!("status: VmRSS value missing"))?;
    Ok(kb.parse()?)
}

/// Reads the process once (`t` is filled in by the caller).
pub fn read(pid: u32) -> Result<Snapshot> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).with_context(|| format!("/proc/{pid}/stat"))?;
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).with_context(|| format!("/proc/{pid}/status"))?;
    Ok(Snapshot {
        t: 0.0,
        cpu_secs: parse_stat_ticks(&stat)? as f64 / clock_ticks(),
        rss_mb: parse_rss_kb(&status)? as f64 / 1024.0,
    })
}

/// Background sampler of one process.
#[derive(Clone)]
pub struct Sampler {
    pid: u32,
    start: Instant,
    samples: Arc<Mutex<Vec<Snapshot>>>,
}

impl Sampler {
    /// Starts sampling `pid` every second until the process disappears.
    pub fn start(pid: u32) -> Result<Self> {
        read(pid)?;
        let sampler = Self { pid, start: Instant::now(), samples: Arc::default() };
        let bg = sampler.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                match bg.now() {
                    Ok(s) => lock(&bg.samples).push(s),
                    Err(_) => break,
                }
            }
        });
        Ok(sampler)
    }

    /// Reads the process now (also stored in the timeline).
    pub fn now(&self) -> Result<Snapshot> {
        let mut s = read(self.pid)?;
        s.t = self.start.elapsed().as_secs_f64();
        Ok(s)
    }

    /// Starts a measurement window.
    pub fn window(&self) -> Result<Window> {
        Ok(Window { from: self.now()? })
    }

    /// Highest RSS seen between two points in time (including both readings).
    fn max_rss(&self, from: &Snapshot, to: &Snapshot) -> f64 {
        lock(&self.samples)
            .iter()
            .filter(|s| s.t >= from.t && s.t <= to.t)
            .map(|s| s.rss_mb)
            .fold(from.rss_mb.max(to.rss_mb), f64::max)
    }

    /// The whole timeline (one sample per second).
    pub fn timeline(&self) -> Vec<Snapshot> {
        lock(&self.samples).clone()
    }
}

/// CPU and memory of the node over one scenario.
pub struct Window {
    from: Snapshot,
}

/// Result of a [`Window`].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Usage {
    /// CPU in percent of one core over the window.
    pub cpu_pct: f64,
    pub rss_max_mb: f64,
    pub rss_end_mb: f64,
    pub secs: f64,
}

impl Window {
    pub fn finish(self, sampler: &Sampler) -> Result<Usage> {
        let to = sampler.now()?;
        let secs = (to.t - self.from.t).max(1e-3);
        Ok(Usage {
            cpu_pct: round2((to.cpu_secs - self.from.cpu_secs) / secs * 100.0),
            rss_max_mb: round1(sampler.max_rss(&self.from, &to)),
            rss_end_mb: round1(to.rss_mb),
            secs: round1(secs),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_after_the_command_name() -> Result<()> {
        // Field 2 contains a space and a parenthesis; utime = 1234, stime = 66.
        let stat = "4242 (tavrn (node) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1234 66 0 0 20 0 9 0 1 2 3";
        assert_eq!(parse_stat_ticks(stat)?, 1300);
        assert!(parse_stat_ticks("garbage").is_err());
        assert!(parse_stat_ticks("1 (x) S 1 2").is_err());
        Ok(())
    }

    #[test]
    fn rss_from_status() -> Result<()> {
        let status = "Name:\ttavrn-node\nVmPeak:\t  100 kB\nVmRSS:\t   51200 kB\nThreads:\t9\n";
        assert_eq!(parse_rss_kb(status)?, 51200);
        assert!(parse_rss_kb("Name: x\n").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reads_the_own_process() -> Result<()> {
        let s = read(std::process::id())?;
        assert!(s.rss_mb > 0.0);
        assert!(s.cpu_secs >= 0.0);
        Ok(())
    }
}
