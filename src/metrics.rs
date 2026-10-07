// SPDX-License-Identifier: AGPL-3.0-only
//! Basic operational metrics: `GET /metrics` in the Prometheus text exposition format (docs/HANDBOOK.md, "Metrics
//! and health").
//!
//! Off by default (`TAVRN_METRICS=on`). With `TAVRN_METRICS_TOKEN` scrapers send `Authorization: Bearer <token>`;
//! without a token only peers on loopback or in `TAVRN_TRUSTED_PROXIES` are answered (the TCP peer address, never
//! `X-Forwarded-For`). Everything else gets the same `404` as an unknown path, so the route does not reveal itself.
//!
//! Every instance keeps its own registry (counters since its start); gauges are read at scrape time. Labels are
//! bounded: HTTP routes are route templates (`/api/v1/rooms/{room_id}`), never ids; unmatched paths count as
//! `unmatched`.

use std::{net::SocketAddr, time::Instant};

use axum::{
    body::Body,
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use subtle::ConstantTimeEq;

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

/// Middleware: counts every request by method, route template and status.
pub async fn track(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !state.config.metrics.on() {
        return next.run(request).await;
    }
    let started = Instant::now();
    let method = request.method().as_str().to_string();
    let route = request.extensions().get::<MatchedPath>().map_or("unmatched", |p| p.as_str()).to_string();
    let response = next.run(request).await;
    state.metrics.observe_request(&method, &route, response.status().as_u16(), started.elapsed().as_secs_f64());
    response
}

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
        // Without a token: the TCP peer must be loopback or a trusted proxy. Requests without a peer address (an
        // in-process router) are refused.
        None => connect.is_some_and(|ConnectInfo(addr)| {
            let ip = addr.ip().to_canonical();
            ip.is_loopback() || state.config.is_trusted_proxy(ip)
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
        assert!(text.contains(r#"tavrn_http_requests_total{method="GET",route="/api/v1/rooms/{room_id}",status="200"} 1"#));
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
