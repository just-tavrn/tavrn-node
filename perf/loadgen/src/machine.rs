// SPDX-License-Identifier: AGPL-3.0-only
//! Machine speed of the run, so that the node's CPU under load can be budgeted on any machine
//! (perf/README.md "Machine speed").
//!
//! The node's CPU share depends on the machine as much as on the node: GitHub's 4-core runners of the
//! same label are AMD EPYC 9V45 or EPYC 7763 machines, and nodes without a relevant change measured
//! 12.5 % and 23.7 % plaintext load on them, while the load generator's own unchanged catch-up took
//! 12.5 s and 22.7 s: the same factor. That work is fixed: the MLS catch-up of the setup (every member
//! processes the commits after its own join, OpenMLS from the pinned tavrn-crypto) is the same
//! computation in every run of the default scale. Its CPU time is the machine's speed; the node's CPU
//! is scaled by it to the reference machine.

use crate::stats::round2;

/// Members of the default run. The catch-up's work grows with the group, so the calibration holds for this scale only.
pub const CALIBRATED_CLIENTS: usize = 200;

/// CPU seconds of the default run's catch-up on the reference machine. The reference is about GitHub's 4-core
/// `ubuntu-latest` runner with an AMD EPYC 7763, the nightly's usual machine: its catch-up took 22.7 s and 24.8 s of
/// wall time on four threads (2026-10-13 and 2026-10-14), and four catch-up threads are busy 65 % of that wall time
/// together (the members who joined first have the most commits to process; 30.7 CPU seconds in 11.8 s pinned to
/// four CPUs), so 59 to 64 CPU seconds.
pub const REFERENCE_CATCH_UP_CPU_SECS: f64 = 60.0;

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

    #[test]
    fn no_factor_at_another_scale_or_without_a_measurement() {
        assert_eq!(speed_factor(Some(30.0), 50), None);
        assert_eq!(speed_factor(None, CALIBRATED_CLIENTS), None);
        assert_eq!(speed_factor(Some(0.0), CALIBRATED_CLIENTS), None);
        assert_eq!(speed_factor(Some(f64::NAN), CALIBRATED_CLIENTS), None);
    }
}
