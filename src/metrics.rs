// SPDX-License-Identifier: AGPL-3.0-only
//! Basic operational metrics: `GET /metrics` in the Prometheus text exposition format (docs/HANDBOOK.md, "Metrics
//! and health").
//!
//! Off by default (`TAVRN_METRICS=on`). With `TAVRN_METRICS_TOKEN` scrapers send `Authorization: Bearer <token>`;
//! without a token only requests whose TCP peer and forwarded addresses (`X-Forwarded-For`) are all on loopback or in
//! `TAVRN_TRUSTED_PROXIES` are answered, so a public request through a reverse proxy on the same host is refused.
//! Everything else gets the same `404` as an unknown path.
//!
//! Every instance keeps its own registry (counters since its start); gauges are read at scrape time. Labels are
//! bounded: HTTP routes are route templates (`/api/v1/rooms/{room_id}`), never ids; unmatched paths count as
//! `unmatched`.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use subtle::ConstantTimeEq;
use tracing::Instrument;

use crate::app::AppState;

/// Latency buckets in seconds (API calls, uploads and long polls alike).
const BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

pub struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    /// Messages created on this instance, by `encrypted` = `true` | `false`.
    pub messages: IntCounterVec,
    /// Bytes of uploaded attachments and files.
    pub upload_bytes: IntCounter,
    /// Deliveries of the federation outbox, by `result` = `success` | `failure`.
    pub federation_deliveries: IntCounterVec,
    pub push_sent: IntCounter,
    pub push_failed: IntCounter,
    /// Unix time of the last finished housekeeping round on this instance.
    pub housekeeping_last_run: IntGauge,
    websocket_connections: IntGauge,
    connected_devices: IntGauge,
    voice_participants: IntGauge,
    calls_active: IntGauge,
    db_pool_connections: IntGauge,
    db_pool_idle: IntGauge,
    cache_up: IntGauge,
}

fn counter_vec(registry: &Registry, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).unwrap_or_else(|_| unreachable!("valid metric {name}"));
    let _ = registry.register(Box::new(c.clone()));
    c
}

fn counter(registry: &Registry, name: &str, help: &str) -> IntCounter {
    let c = IntCounter::new(name, help).unwrap_or_else(|_| unreachable!("valid metric {name}"));
    let _ = registry.register(Box::new(c.clone()));
    c
}

fn gauge(registry: &Registry, name: &str, help: &str) -> IntGauge {
    let g = IntGauge::new(name, help).unwrap_or_else(|_| unreachable!("valid metric {name}"));
    let _ = registry.register(Box::new(g.clone()));
    g
}

impl Metrics {
    /// A registry with every metric. `cache` registers `tavrn_cache_up` (only with `TAVRN_CACHE_URL`).
    pub fn new(version: &str, cache: bool) -> Self {
        let r = Registry::new();
        let http_duration = HistogramVec::new(
            HistogramOpts::new("tavrn_http_request_duration_seconds", "HTTP request latency by route template")
                .buckets(BUCKETS.to_vec()),
            &["method", "route"],
        )
        .unwrap_or_else(|_| unreachable!("valid histogram"));
        let _ = r.register(Box::new(http_duration.clone()));
        let build = IntGaugeVec::new(Opts::new("tavrn_build_info", "Version of the running node"), &["version"])
            .unwrap_or_else(|_| unreachable!("valid gauge"));
        build.with_label_values(&[version]).set(1);
        let _ = r.register(Box::new(build));
        let cache_up = IntGauge::new("tavrn_cache_up", "1 while the shared cache (Valkey) answers")
            .unwrap_or_else(|_| unreachable!("valid gauge"));
        if cache {
            let _ = r.register(Box::new(cache_up.clone()));
        }
        Self {
            http_requests: counter_vec(
                &r,
                "tavrn_http_requests_total",
                "HTTP requests by method, route template and status",
                &["method", "route", "status"],
            ),
            http_duration,
            messages: counter_vec(&r, "tavrn_messages_total", "Messages created", &["encrypted"]),
            upload_bytes: counter(&r, "tavrn_upload_bytes_total", "Bytes of uploaded attachments and files"),
            federation_deliveries: counter_vec(
                &r,
                "tavrn_federation_deliveries_total",
                "Delivery attempts of the federation outbox",
                &["result"],
            ),
            push_sent: counter(&r, "tavrn_push_sent_total", "Web pushes accepted by a push service"),
            push_failed: counter(&r, "tavrn_push_failed_total", "Web pushes that failed"),
            housekeeping_last_run: gauge(
                &r,
                "tavrn_housekeeping_last_run_timestamp_seconds",
                "Unix time of the last housekeeping round (0 before the first)",
            ),
            websocket_connections: gauge(&r, "tavrn_websocket_connections", "Open WebSocket connections of users"),
            connected_devices: gauge(&r, "tavrn_connected_devices", "Devices with at least one open connection"),
            voice_participants: gauge(&r, "tavrn_voice_participants", "Participants in voice channels"),
            calls_active: gauge(&r, "tavrn_calls_active", "Active calls in DMs and group DMs"),
            db_pool_connections: gauge(&r, "tavrn_db_pool_connections", "Open database connections"),
            db_pool_idle: gauge(&r, "tavrn_db_pool_idle", "Idle database connections"),
            cache_up,
            registry: r,
        }
    }

    /// Counts one HTTP request.
    pub fn observe_request(&self, method: &str, route: &str, status: u16, seconds: f64) {
        self.http_requests.with_label_values(&[method, route, &status.to_string()]).inc();
        self.http_duration.with_label_values(&[method, route]).observe(seconds);
    }

    /// Counts a new message.
    pub fn message(&self, encrypted: bool) {
        self.messages.with_label_values(&[if encrypted { "true" } else { "false" }]).inc();
    }

    /// Counts a federation delivery attempt.
    pub fn federation_delivery(&self, success: bool) {
        self.federation_deliveries.with_label_values(&[if success { "success" } else { "failure" }]).inc();
    }

    /// The text exposition with the gauges read now.
    pub async fn render(&self, state: &AppState) -> String {
        self.websocket_connections.set(state.hub.connections() as i64);
        self.connected_devices.set(state.presence.connected_devices() as i64);
        let voice = {
            let participants = state.voice.participants();
            participants.keys().iter().map(|k| participants.identities_in(k).len()).sum::<usize>()
        };
        self.voice_participants.set(voice as i64);
        self.calls_active.set(state.calls.active().len() as i64);
        self.db_pool_connections.set(i64::from(state.db.size()));
        self.db_pool_idle.set(state.db.num_idle() as i64);
        if let Some(up) = state.cluster.ready().await {
            self.cache_up.set(i64::from(up));
        }
        let mut out = Vec::new();
        if TextEncoder::new().encode(&self.registry.gather(), &mut out).is_err() {
            return String::new();
        }
        String::from_utf8(out).unwrap_or_default()
    }
}

/// Middleware: counts every request by method, route template and status, and logs the slow ones
/// (`TAVRN_LOG_SLOW_REQUEST_MS`).
pub async fn track(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let slow = state.config.slow_request_threshold();
    if !state.config.metrics.on() && slow.is_none() {
        return next.run(request).await;
    }
    let started = Instant::now();
    let method = request.method().as_str().to_string();
    let route = request.extensions().get::<MatchedPath>().map_or("unmatched", |p| p.as_str()).to_string();
    let (response, statements) = if slow.is_some() {
        // The request runs in a span that counts its database statements (`telemetry.rs`).
        let span = tracing::trace_span!(target: crate::telemetry::REQUEST_SPAN, "request");
        let response = next.run(request).instrument(span.clone()).await;
        (response, crate::telemetry::statements(&span))
    } else {
        (next.run(request).await, None)
    };
    let elapsed = started.elapsed();
    let status = response.status().as_u16();
    if state.config.metrics.on() {
        state.metrics.observe_request(&method, &route, status, elapsed.as_secs_f64());
    }
    if slow.is_some_and(|threshold| elapsed >= threshold) {
        log_slow_request(&method, &route, status, elapsed, statements);
    }
    response
}

/// The `slow request` line: method, route template (never ids), status, duration in milliseconds (microsecond
/// precision) and, when counted, the database statements the request ran.
pub fn log_slow_request(method: &str, route: &str, status: u16, elapsed: Duration, statements: Option<u64>) {
    let duration_ms = elapsed.as_micros() as f64 / 1000.0;
    match statements {
        Some(queries) => {
            tracing::info!(target: SLOW_REQUEST, %method, %route, status, duration_ms, queries, "slow request");
        }
        None => tracing::info!(target: SLOW_REQUEST, %method, %route, status, duration_ms, "slow request"),
    }
}

/// Log target of the `slow request` lines (`TAVRN_LOG_LEVEL` can address it, e.g. `warn,tavrn_node::slow_request=info`).
pub const SLOW_REQUEST: &str = "tavrn_node::slow_request";

/// `GET /metrics` (not part of the API specification: an operator endpoint).
pub async fn endpoint(State(state): State<AppState>, request: Request) -> Response {
    let not_found =
        || crate::error::ApiError::NotFound { code: "route.not_found", what: "Path".into() }.into_response();
    let headers: &HeaderMap = request.headers();
    let connect = request.extensions().get::<ConnectInfo<SocketAddr>>();
    if !state.config.metrics.on() {
        return not_found();
    }
    let allowed = match state.config.metrics_token() {
        Some(token) => headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| bool::from(t.trim().as_bytes().ct_eq(token.as_bytes()))),
        // Without a token: the TCP peer and every address a proxy forwarded (`X-Forwarded-For`) must be loopback or
        // trusted proxies, so a public request through a reverse proxy on the same host is refused (a forged header
        // can only lead to a refusal). Requests without a peer address (an in-process router) are refused.
        None => connect.is_some_and(|ConnectInfo(addr)| {
            let internal = |ip: std::net::IpAddr| {
                let ip = ip.to_canonical();
                ip.is_loopback() || state.config.is_trusted_proxy(ip)
            };
            let forwarded = headers.get_all("x-forwarded-for").iter().all(|v| {
                v.to_str().is_ok_and(|v| v.split(',').all(|a| a.trim().parse::<std::net::IpAddr>().is_ok_and(internal)))
            });
            internal(addr.ip()) && forwarded
        }),
    };
    if !allowed {
        return not_found();
    }
    let body = state.metrics.render(&state).await;
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], Body::from(body))
        .into_response()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Collects what a test subscriber writes.
    #[derive(Clone, Default)]
    struct Written(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Written {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn slow_requests_are_logged_with_route_status_duration_and_statements() {
        let written = Written::default();
        let writer = written.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_slow_request("GET", "/api/v1/rooms/{room_id}", 200, Duration::from_micros(12_345), Some(7));
            log_slow_request("POST", "unmatched", 404, Duration::from_millis(3), None);
        });
        let text = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for part in [
            "INFO",
            "tavrn_node::slow_request",
            "slow request",
            "method=GET",
            "route=/api/v1/rooms/{room_id}",
            "status=200",
            "duration_ms=12.345",
            "queries=7",
        ] {
            assert!(lines[0].contains(part), "{part} in {}", lines[0]);
        }
        assert!(lines[1].contains("status=404") && lines[1].contains("duration_ms=3"), "{}", lines[1]);
        assert!(!lines[1].contains("queries="), "no count without the counting layer: {}", lines[1]);
    }

    #[test]
    fn registry_renders_counters_and_build_info() {
        let m = Metrics::new("1.2.3", false);
        m.observe_request("GET", "/api/v1/rooms/{room_id}", 200, 0.02);
        m.message(true);
        m.message(false);
        m.message(false);
        m.federation_delivery(false);
        m.push_sent.inc();
        let mut out = Vec::new();
        TextEncoder::new().encode(&m.registry.gather(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#"tavrn_build_info{version="1.2.3"} 1"#), "{text}");
        assert!(
            text.contains(r#"tavrn_http_requests_total{method="GET",route="/api/v1/rooms/{room_id}",status="200"} 1"#)
        );
        assert!(text.contains(r#"tavrn_messages_total{encrypted="false"} 2"#));
        assert!(text.contains(r#"tavrn_federation_deliveries_total{result="failure"} 1"#));
        assert!(text.contains("tavrn_push_sent_total 1"));
        assert!(text.contains("tavrn_http_request_duration_seconds_bucket"));
        assert!(!text.contains("tavrn_cache_up"), "only with a cache");
        let mut out = Vec::new();
        TextEncoder::new().encode(&Metrics::new("1", true).registry.gather(), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("tavrn_cache_up 0"));
    }
}
