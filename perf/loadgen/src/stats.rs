// SPDX-License-Identifier: AGPL-3.0-only
//! Latency samples and percentiles.

use std::sync::{Mutex, MutexGuard};

use serde_json::{Value, json};

/// Locks a mutex, ignoring poisoning (a panicked task must not hide the measurements of the others).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Latencies of one operation in milliseconds plus the number of failed attempts.
#[derive(Debug, Default, Clone)]
pub struct Samples {
    values: Vec<f64>,
    pub errors: u64,
}

impl Samples {
    pub fn push(&mut self, ms: f64) {
        self.values.push(ms);
    }

    pub fn count(&self) -> usize {
        self.values.len()
    }

    /// Nearest-rank percentile (`p` in 0..=100); `None` without samples.
    pub fn percentile(&self, p: f64) -> Option<f64> {
        if self.values.is_empty() {
            return None;
        }
        let mut sorted = self.values.clone();
        sorted.sort_by(f64::total_cmp);
        let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        Some(sorted[rank.clamp(1, sorted.len()) - 1])
    }

    /// `{ count, errors, p50, p95, p99, max }` in milliseconds (rounded to 0.1 ms).
    pub fn summary(&self) -> Value {
        let r = |v: Option<f64>| v.map(round1);
        json!({
            "count": self.count(),
            "errors": self.errors,
            "p50": r(self.percentile(50.0)),
            "p95": r(self.percentile(95.0)),
            "p99": r(self.percentile(99.0)),
            "max": r(self.percentile(100.0)),
        })
    }
}

/// Rounds to one decimal place.
pub fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Rounds to two decimal places.
pub fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_nearest_rank() {
        let mut s = Samples::default();
        assert_eq!(s.percentile(50.0), None);
        for v in 1..=100 {
            s.push(v as f64);
        }
        assert_eq!(s.percentile(50.0), Some(50.0));
        assert_eq!(s.percentile(95.0), Some(95.0));
        assert_eq!(s.percentile(99.0), Some(99.0));
        assert_eq!(s.percentile(100.0), Some(100.0));
        assert_eq!(s.percentile(0.0), Some(1.0));
    }

    #[test]
    fn percentiles_of_few_samples_and_summary() {
        let mut s = Samples::default();
        s.push(30.0);
        s.push(10.0);
        s.push(20.0);
        s.errors = 2;
        assert_eq!(s.percentile(50.0), Some(20.0));
        assert_eq!(s.percentile(95.0), Some(30.0));
        let sum = s.summary();
        assert_eq!(sum["count"], 3);
        assert_eq!(sum["errors"], 2);
        assert_eq!(sum["max"], 30.0);
    }

    #[test]
    fn rounding() {
        assert_eq!(round1(1.26), 1.3);
        assert_eq!(round1(0.04), 0.0);
        assert_eq!(round2(0.044), 0.04);
    }
}
