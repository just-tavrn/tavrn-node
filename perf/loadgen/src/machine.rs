// SPDX-License-Identifier: AGPL-3.0-only
//! Machine speed of the run, so that the node's CPU under load can be budgeted on any machine
//! (perf/README.md "Machine speed").
//!
//! The node's CPU share depends on the machine as much as on the node: GitHub's 4-core runners of the
//! same label are AMD EPYC 7763, 9V45 or 9V74 or Intel Xeon machines, and the same node measured from
//! 10.2 % to 13.9 % (and before the read buffer fix from 12.5 % to 25.3 %) of one core on them. The MLS
//! catch-up of the setup (every member processes the commits after its own join) is the same computation
//! in every run of the default scale, and its CPU time follows the runner the way the node's does: scaled
//! by it, the runners agree within about 10 %. Its CPU time is the machine's speed; the node's CPU is
//! scaled by it to the reference machine.
//!
//! The computation is fixed only as long as the code doing it is: OpenMLS through tavrn-crypto. The
//! tavrn-crypto release of 0.4.0-rc.10 caches loaded groups and made the catch-up twice as cheap on the
//! same machine, which hid the node's own gain of the same night in the scaled values. The reference
//! therefore names the crate versions it was taken with ([`CALIBRATED_WITH`]), and a test fails when
//! `Cargo.lock` moves away from them, so that the reference is measured again (perf/README.md).

use crate::stats::round2;

/// Members of the default run. The catch-up's work grows with the group, so the calibration holds for this scale only.
pub const CALIBRATED_CLIENTS: usize = 200;

/// CPU seconds of the default run's catch-up on the reference machine: GitHub's 4-core `ubuntu-latest` runner with an
/// AMD EPYC 7763, with the crates of [`CALIBRATED_WITH`]. Two runs of 0.4.0-rc.10 on that runner measured 32.3 and 32.2
/// CPU seconds (2026-10-16, runs 38961332219 and 38961335441). The reference machine is the same as before the
/// tavrn-crypto update (60 CPU seconds with the uncached groups), so the scaled values of older runs stay comparable.
/// openmls 0.9.2 (security fixes) kept the cost: against the same node on one machine (pinned to four CPUs, four runs
/// each, alternating) the catch-up took 60.1-62.4 CPU seconds with 0.9.1 and 58.4-62.8 with 0.9.2 (2026-10-27), a
/// ratio of 0.98 within the spread of the runs, so the reference stays.
pub const REFERENCE_CATCH_UP_CPU_SECS: f64 = 32.25;

/// The crates that do the catch-up's work, with the `Cargo.lock` checksums the reference was measured with. A new
/// version (or a git source instead of the registry) can change the work; then measure the reference again.
pub const CALIBRATED_WITH: [(&str, &str); 3] = [
    ("tavrn-crypto", "ff97c66ebb266d2f06a72251e470a384ae132a737e0030e57bf85df210d9c86f"),
    ("openmls", "ce4173f914cbc2dd28d9499f19e92f3e1bfebd9eea1607889924a77ca63d3ffc"),
    ("openmls_rust_crypto", "36bf3fe824ead6e81d22f49a9cd7feffca3494979fac14c1248e19516e3625f1"),
];

/// CPU time of the calling thread in seconds.
pub fn thread_cpu_secs() -> Option<f64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime only writes the timespec it is given, which lives for the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    (rc == 0).then(|| ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9)
}

/// Speed of this machine relative to the reference (0.5: half as fast, the same work takes twice the CPU time), from
/// the catch-up's CPU seconds; `None` at another scale than the calibrated one or without a measurement.
pub fn speed_factor(catch_up_cpu_secs: Option<f64>, clients: usize) -> Option<f64> {
    let secs = catch_up_cpu_secs.filter(|s| s.is_finite() && *s > 0.0)?;
    (clients == CALIBRATED_CLIENTS).then(|| REFERENCE_CATCH_UP_CPU_SECS / secs)
}

/// CPU model and topology from `/proc/cpuinfo`: whether the logical CPUs are cores of their own or hyperthreads that
/// share one (`threads_per_core` 2). Runners of the same label differ in both.
pub fn cpu_topology(cpuinfo: &str) -> serde_json::Value {
    let field = |name: &str| {
        cpuinfo.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    };
    let num = |name: &str| field(name).and_then(|v| v.parse::<u32>().ok());
    let logical = cpuinfo.lines().filter(|l| l.split_once(':').is_some_and(|(k, _)| k.trim() == "processor")).count();
    let threads_per_core = num("siblings").zip(num("cpu cores")).filter(|(_, c)| *c > 0).map(|(s, c)| s / c);
    serde_json::json!({ "model": field("model name"), "logical": logical, "threads_per_core": threads_per_core })
}

/// Rounds to three decimal places (the speed factor in the results).
pub fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// A CPU share of this machine in percent of one core of the reference machine.
pub fn on_reference(cpu_pct: f64, factor: f64) -> f64 {
    round2(cpu_pct * factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_cpu_time_grows_with_work() {
        let before = thread_cpu_secs().unwrap_or_default();
        let mut x = 0u64;
        for i in 0..5_000_000u64 {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
        }
        std::hint::black_box(x);
        let after = thread_cpu_secs().unwrap_or_default();
        assert!(after > before, "{after} > {before}");
    }

    #[test]
    fn a_machine_twice_as_slow_halves_the_share() {
        // Twice the reference's catch-up CPU: the machine is half as fast, 24 % there are 12 % on the reference.
        let factor = speed_factor(Some(REFERENCE_CATCH_UP_CPU_SECS * 2.0), CALIBRATED_CLIENTS);
        assert_eq!(factor, Some(0.5));
        assert_eq!(on_reference(24.0, 0.5), 12.0);
        assert_eq!(on_reference(12.0, 2.0), 24.0);
        assert_eq!(speed_factor(Some(REFERENCE_CATCH_UP_CPU_SECS), CALIBRATED_CLIENTS), Some(1.0));
    }

    /// The `checksum` of a package in `Cargo.lock` (`None` for a git or path source, or a missing package).
    fn locked_checksum<'a>(lock: &'a str, name: &str) -> Option<&'a str> {
        let entry = lock.split("[[package]]").find(|p| p.lines().any(|l| l.trim() == format!("name = \"{name}\"")))?;
        entry.lines().find_map(|l| l.trim().strip_prefix("checksum = \"")?.strip_suffix('"'))
    }

    #[test]
    fn the_reference_matches_the_locked_crates() {
        let lock = include_str!("../../../Cargo.lock");
        for (name, checksum) in CALIBRATED_WITH {
            assert_eq!(
                locked_checksum(lock, name),
                Some(checksum),
                "{name} changed in Cargo.lock: the MLS catch-up that calibrates the machine speed may cost differently \
                 now. Measure REFERENCE_CATCH_UP_CPU_SECS again (perf/README.md \"Machine speed\"), then update \
                 CALIBRATED_WITH."
            );
        }
        let sample = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://example.org/a\"\n\n\
                      [[package]]\nname = \"b\"\nversion = \"2.0.0\"\nchecksum = \"abc\"\n";
        assert_eq!(locked_checksum(sample, "a"), None);
        assert_eq!(locked_checksum(sample, "b"), Some("abc"));
        assert_eq!(locked_checksum(sample, "c"), None);
    }

    #[test]
    fn topology_from_cpuinfo() {
        let smt = "processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\nsiblings\t: 4\ncpu cores\t: 2\n\n\
                   processor\t: 1\nmodel name\t: AMD EPYC 7763 64-Core Processor\nsiblings\t: 4\ncpu cores\t: 2\n";
        let t = cpu_topology(smt);
        assert_eq!(t["model"], "AMD EPYC 7763 64-Core Processor");
        assert_eq!(t["logical"], 2);
        assert_eq!(t["threads_per_core"], 2);
        assert_eq!(cpu_topology("processor : 0\n")["threads_per_core"], serde_json::Value::Null);
    }

    #[test]
    fn no_factor_at_another_scale_or_without_a_measurement() {
        assert_eq!(speed_factor(Some(30.0), 50), None);
        assert_eq!(speed_factor(None, CALIBRATED_CLIENTS), None);
        assert_eq!(speed_factor(Some(0.0), CALIBRATED_CLIENTS), None);
        assert_eq!(speed_factor(Some(f64::NAN), CALIBRATED_CLIENTS), None);
    }
}
