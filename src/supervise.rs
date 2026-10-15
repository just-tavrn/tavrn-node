// SPDX-License-Identifier: AGPL-3.0-only
//! Background workers that survive a panic: [`supervised`] starts a worker again when it ends with one, so a single
//! bad round (an index out of bounds, a slice at a wrong boundary) cannot stop the federation outbox, the
//! housekeeping or the voice sweeps until the next restart. [`log_panics`] sends panic messages through the log
//! (JSON with `TAVRN_LOG_FORMAT=json`) instead of plain stderr.

use std::time::Duration;

use tokio::task::JoinHandle;

/// How long a worker that panicked waits before it starts again.
pub const RESTART_DELAY: Duration = Duration::from_secs(1);

/// Aborts the task when dropped (the supervisor's own abort reaches the worker).
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the worker `start` spawns and spawns it again after [`RESTART_DELAY`] whenever it ends with a panic (logged
/// at error level with the worker's `name`). A worker that returns ends the supervisor; aborting the supervisor's
/// handle aborts the running worker.
pub fn supervised<F>(name: &'static str, start: F) -> JoinHandle<()>
where
    F: Fn() -> JoinHandle<()> + Send + 'static,
{
    supervised_with(name, RESTART_DELAY, start)
}

fn supervised_with<F>(name: &'static str, delay: Duration, start: F) -> JoinHandle<()>
where
    F: Fn() -> JoinHandle<()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let mut worker = AbortOnDrop(start());
            match (&mut worker.0).await {
                Ok(()) => return,
                Err(e) if e.is_panic() => {
                    tracing::error!(worker = name, "background worker panicked, starting it again");
                    tokio::time::sleep(delay).await;
                }
                Err(_) => return,
            }
        }
    })
}

/// Logs panics through `tracing` (error level, with the location), so they appear in the node's log format.
pub fn log_panics() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        tracing::error!(%location, %message, "panic");
    }));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[tokio::test]
    async fn a_worker_that_panics_starts_again_and_one_that_returns_ends() {
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = runs.clone();
        let supervisor = supervised_with("test", Duration::from_millis(10), move || {
            let counter = counter.clone();
            tokio::spawn(async move {
                if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                    panic!("a bad round");
                }
            })
        });
        tokio::time::timeout(Duration::from_secs(5), supervisor).await.unwrap().unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 3, "two panics, then a normal end");
    }

    #[tokio::test]
    async fn aborting_the_supervisor_stops_the_worker() {
        let alive = Arc::new(AtomicUsize::new(0));
        let flag = alive.clone();
        let supervisor = supervised("test", move || {
            let flag = flag.clone();
            tokio::spawn(async move {
                let _guard = Counted(flag.clone());
                flag.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            })
        });
        while alive.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        supervisor.abort();
        for _ in 0..100 {
            if alive.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the worker still runs");
    }

    /// Decrements the counter when the worker's future is dropped.
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
