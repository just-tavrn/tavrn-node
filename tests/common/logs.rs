// SPDX-License-Identifier: AGPL-3.0-only
//! Log captures for tests that prove a secret never reaches a log line. A thread-local subscriber captures the
//! events of the requests a test sends; tracing's callsite interest cache and max level are process-wide and every
//! integration test shares this process, so captures run one at a time ([`CAPTURE`]) and rebuild that cache first.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

/// One log capture at a time (see the module comment).
pub static CAPTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Collects everything the subscriber writes.
#[derive(Clone, Default)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Everything written so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Starts capturing every event of this thread at every level (hold [`CAPTURE`] first); dropping the guard stops.
pub fn start() -> (Capture, tracing::subscriber::DefaultGuard) {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // Interest computed on other threads (without this subscriber) must not hide this thread's events.
    tracing::callsite::rebuild_interest_cache();
    (capture, guard)
}
