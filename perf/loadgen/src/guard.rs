// SPDX-License-Identifier: AGPL-3.0-only
//! Refuses to start the benchmarks on a busy machine (perf/README.md "Running alone"): the full tier
//! starts a node, 200 MLS clients and up to 1000 sockets, and next to other heavy work it both skews
//! the numbers and can exhaust the memory of the machine. Linux only (reads `/proc`); elsewhere
//! the check is skipped. `PERF_GUARD=off` disables it.

use std::time::Duration;

use anyhow::{Result, bail};

/// Memory that must be available (`MemAvailable`) before a run starts.
pub const MIN_AVAILABLE_GB: f64 = 6.0;
/// How long to wait for the machine to calm down (e.g. right after a release build) before refusing.
const WAIT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_secs(10);

/// Why the machine is too busy, or `None` when a run may start.
pub fn busy(available_gb: f64, load1: f64, cores: usize) -> Option<String> {
    let max_load = cores as f64 / 2.0;
    let mut reasons = Vec::new();
    if available_gb < MIN_AVAILABLE_GB {
        reasons.push(format!("only {available_gb:.1} GB memory available (needs {MIN_AVAILABLE_GB} GB)"));
    }
    if load1 > max_load {
        reasons.push(format!("1-minute load average {load1:.1} exceeds half the cores ({max_load:.1} of {cores})"));
    }
    if reasons.is_empty() { None } else { Some(reasons.join(", ")) }
}

fn available_gb() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / (1024.0 * 1024.0))
}

fn load1() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg").ok()?.split_whitespace().next()?.parse().ok()
}

/// Waits up to two minutes for enough free memory and a low load, then fails with a clear message.
pub async fn ensure_quiet_machine() -> Result<()> {
    if std::env::var("PERF_GUARD").is_ok_and(|v| v == "off") {
        return Ok(());
    }
    let cores = std::thread::available_parallelism().map(usize::from).unwrap_or(1);
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let (Some(mem), Some(load)) = (available_gb(), load1()) else { return Ok(()) };
        let Some(reason) = busy(mem, load, cores) else { return Ok(()) };
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "refusing to start: the machine is busy ({reason}). The benchmarks must run alone on the machine and \
                 need about 8 GB free; stop other heavy work and retry (PERF_GUARD=off skips this check)."
            );
        }
        eprintln!("waiting for a quiet machine: {reason}");
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_low_memory_and_high_load() {
        assert_eq!(busy(10.0, 3.0, 20), None);
        assert!(busy(5.9, 3.0, 20).is_some_and(|r| r.contains("5.9 GB")));
        assert!(busy(10.0, 10.5, 20).is_some_and(|r| r.contains("load average 10.5")));
        assert_eq!(busy(10.0, 10.0, 20), None, "exactly half the cores is allowed");
        let both = busy(1.0, 50.0, 4).unwrap_or_default();
        assert!(both.contains("memory") && both.contains("load"));
    }
}
