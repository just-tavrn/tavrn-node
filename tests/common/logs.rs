// SPDX-License-Identifier: AGPL-3.0-only
//! Log captures for tests that prove a secret never reaches a log line, and statement counts of a piece of work.
//!
//! Every integration test shares one process. A thread-local subscriber (`set_default`) is not enough there: while it
//! is the only live dispatcher, tracing-core computes the interest of a callsite another test's thread registers with
//! that thread's empty default and caches `never` for every thread, so captures lost events at random. Instead one
//! process-wide subscriber is installed once; its dynamic filter answers per event (no callsite is ever cached as
//! disabled) and lets everything through while a capture runs. Captures run one at a time ([`CAPTURE`]); events of other tests
//! in that window land in the capture too, which is harmless for checks of the test's own random secrets.

use std::{
    io::Write,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use tracing_subscriber::{Layer, filter::dynamic_filter_fn, layer::SubscriberExt};

/// One log capture at a time.
pub static CAPTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A capture is running (read for every event, so lock-free).
static CAPTURING: AtomicBool = AtomicBool::new(false);
/// The running capture's buffer.
static ACTIVE: Mutex<Option<Capture>> = Mutex::new(None);
static INSTALLED: OnceLock<()> = OnceLock::new();

/// Collects everything the subscriber writes.
#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Everything written so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// Writes into the running capture (nothing when none runs).
struct ToActive;

impl Write for ToActive {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(capture) = ACTIVE.lock().unwrap().as_ref() {
            capture.0.lock().unwrap().extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stops the capture when dropped.
pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::SeqCst);
        *ACTIVE.lock().unwrap() = None;
    }
}

/// Installs the process-wide subscriber once: the capture layer and the node's statement counter
/// ([`statements`]).
fn install() {
    INSTALLED.get_or_init(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(|| ToActive)
            .with_ansi(false)
            // Dynamic: asked for every event (a `filter_fn` caches its first answer per callsite).
            .with_filter(dynamic_filter_fn(|_, _| CAPTURING.load(Ordering::SeqCst)));
        let registry = tracing_subscriber::registry().with(tavrn_node::telemetry::statement_counter()).with(layer);
        tracing::subscriber::set_global_default(registry).expect("no other global subscriber in the test process");
    });
}

/// Runs `fut` and counts the database statements it runs (in its own task; work it spawns does not count), the
/// counter of the slow request log (`telemetry.rs`). Concurrent tests do not disturb the count.
pub async fn statements<F: std::future::Future>(fut: F) -> (F::Output, u64) {
    use tracing::Instrument;
    install();
    let span = tracing::trace_span!(target: tavrn_node::telemetry::REQUEST_SPAN, "request");
    let out = fut.instrument(span.clone()).await;
    let n = tavrn_node::telemetry::statements(&span).expect("the statement counter is installed");
    (out, n)
}

/// Starts capturing every event at every level (hold [`CAPTURE`] first); dropping the guard stops.
pub fn start() -> (Capture, Guard) {
    install();
    let capture = Capture::default();
    *ACTIVE.lock().unwrap() = Some(capture.clone());
    CAPTURING.store(true, Ordering::SeqCst);
    (capture, Guard)
}
