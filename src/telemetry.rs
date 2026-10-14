// SPDX-License-Identifier: AGPL-3.0-only
//! Logging initialization (`tracing`). Format and level come from the configuration.
//!
//! With `TAVRN_LOG_SLOW_REQUEST_MS` a second layer counts the database statements of each request: sqlx reports
//! every statement as an event of the target `sqlx::query` (at debug level, in the span of the request that runs it,
//! also on SQLite's worker thread), and [`StatementCounter`] adds them up in the request's span ([`REQUEST_SPAN`]).
//! The output keeps its own filter (`TAVRN_LOG_LEVEL`), so the statements are counted but not printed.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{Event, Subscriber, span};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::Targets, fmt, layer::Context, prelude::*, registry::LookupSpan,
};

use crate::config::{Config, LogFormat};

/// Target of the span [`crate::metrics::track`] runs a request in while the slow request log is on.
pub const REQUEST_SPAN: &str = "tavrn_node::request";
/// Target of sqlx's statement events.
const SQLX_STATEMENTS: &str = "sqlx::query";

pub fn init(config: &Config) {
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(config.slow_request_threshold().map(|_| statement_counter()));
    let result = match config.log_format {
        LogFormat::Json => registry.with(fmt::layer().json().with_filter(filter)).try_init(),
        LogFormat::Text => registry.with(fmt::layer().with_filter(filter)).try_init(),
    };
    // Tests may call init several times; a second call is not an error.
    let _ = result;
}

/// The statement counting layer with its own filter: request spans and sqlx's statement events only.
pub fn statement_counter<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    StatementCounter.with_filter(
        Targets::new()
            .with_target(REQUEST_SPAN, tracing::Level::TRACE)
            .with_target(SQLX_STATEMENTS, tracing::Level::TRACE),
    )
}

/// Counts sqlx's statement events in the nearest enclosing request span.
pub struct StatementCounter;

/// The statement count of one request span.
struct Statements(AtomicU64);

impl<S> Layer<S> for StatementCounter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() == REQUEST_SPAN
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut().insert(Statements(AtomicU64::new(0)));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != SQLX_STATEMENTS {
            return;
        }
        let Some(scope) = ctx.event_scope(event) else { return };
        for span in scope {
            if let Some(count) = span.extensions().get::<Statements>() {
                count.0.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}

/// The statements counted in a request span so far; `None` when the span is disabled or nothing counts.
pub fn statements(span: &tracing::Span) -> Option<u64> {
    span.with_subscriber(|(id, dispatch)| {
        let registry = dispatch.downcast_ref::<Registry>()?;
        let data = registry.span(id)?;
        let count = data.extensions().get::<Statements>()?.0.load(Ordering::Relaxed);
        Some(count)
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tracing::Instrument;

    /// Statement events inside a request span count towards it, other events and events outside do not; nested
    /// spans count towards the request.
    #[test]
    fn statements_are_counted_per_request_span() {
        let subscriber = tracing_subscriber::registry().with(statement_counter());
        tracing::subscriber::with_default(subscriber, || {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            runtime.block_on(async {
                let span = tracing::trace_span!(target: REQUEST_SPAN, "request");
                async {
                    tracing::debug!(target: "sqlx::query", "SELECT 1");
                    tracing::info!(target: "tavrn_node::other", "not a statement");
                    tracing::warn!(target: "sqlx::query", "slow statement");
                    async { tracing::debug!(target: "sqlx::query", "SELECT 2") }
                        .instrument(tracing::info_span!("inner"))
                        .await;
                }
                .instrument(span.clone())
                .await;
                tracing::debug!(target: "sqlx::query", "outside");
                assert_eq!(statements(&span), Some(3));
                let other = tracing::trace_span!(target: REQUEST_SPAN, "request");
                assert_eq!(statements(&other), Some(0));
            });
        });
        // Without the counting layer the span is disabled: no count.
        let span = tracing::trace_span!(target: REQUEST_SPAN, "request");
        assert_eq!(statements(&span), None);
    }
}
