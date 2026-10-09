// SPDX-License-Identifier: AGPL-3.0-only
//! The tavrn node as a library, so integration tests can build the router without a network.

pub mod access;
pub mod admin_tokens;
pub mod app;
pub mod applications;
pub mod auth;
pub mod automod;
pub mod bot_channels;
pub mod cache;
pub mod calls;
pub mod captcha;
pub mod commands;
pub mod config;
pub mod connect_sessions;
pub mod db;
pub mod device_cleanup;
pub mod device_proof;
pub mod e2ee;
pub mod embeds;
pub mod emoji;
pub mod emoji_cache;
pub mod entitlements;
pub mod error;
pub mod federation;
pub mod files;
pub mod fixups;
pub mod gifs;
pub mod history;
pub mod hooks;
pub mod housekeeping;
pub mod hub;
pub mod installations;
pub mod interactions;
pub mod jwt;
pub mod keys;
pub mod legal;
pub mod mail;
pub mod mail_templates;
pub mod media;
pub mod metrics;
pub mod models;
pub mod notifications;
pub mod oidc;
pub mod openapi;
pub mod permissions;
pub mod presence;
pub mod profile;
pub mod push;
pub mod reauth;
pub mod reports;
pub mod routes;
pub mod search;
pub mod second_factor;
pub mod storage;
pub mod store;
pub mod subscriptions;
pub mod telemetry;
pub mod threads;
pub mod unfurl;
pub mod uploads;
pub mod util;
pub mod validate;
pub mod visibility;
pub mod voice;
pub mod webapp;
pub mod webhooks;
pub mod welcome;
pub mod whiteboard;
pub mod ws;

/// Serde helper for `Option<Option<T>>`: missing field = unchanged, `null` = clear, value = set.
pub mod serde_with_double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(d).map(Some)
    }
}

use std::net::SocketAddr;

use anyhow::Context;
use tokio::signal;

use crate::config::Config;

/// Starts the node with the given configuration and runs until SIGTERM/SIGINT.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    // Fail before anything starts if voice is on but livekit-server is missing (clear install hint).
    voice::livekit::check_binary(&config)?;
    media::check_binary(&config)?;
    let state = app::AppState::init(config.clone()).await?;
    // Several instances: compete for the leader lease (singleton jobs, voice state) before anything else starts.
    let leader = cache::leader::spawn(&state, cache::leader::LEASE);
    // Hostnames among the announced media addresses are resolved before LiveKit starts (and kept current).
    let advertiser = voice::advertise::start(&state).await;
    let livekit = if config.voice_enabled { Some(voice::livekit::Supervisor::start(&state)?) } else { None };
    let reconciler = config.voice_enabled.then(|| voice::spawn_reconciler(state.clone()));
    let grace_sweeper = config.voice_enabled.then(|| voice::spawn_grace_sweeper(state.clone()));
    let housekeeping = housekeeping::spawn(state.clone());
    let search_backfill = search::spawn_backfill(state.clone());
    let outbox = federation::outbox::spawn(state.clone());
    let subscriptions = subscriptions::spawn(state.clone());
    let directory = federation::announce::spawn(state.clone());
    let conformance = federation::conformance::spawn(state.clone());
    let whiteboards = whiteboard::spawn_sweeper(state.clone());
    let reloads = spawn_reload_on_hangup(state.clone());
    if config.federation_allow_private {
        tracing::warn!(
            "TAVRN_FEDERATION_ALLOW_PRIVATE=true: peers on private and loopback addresses are allowed (SSRF protection off)"
        );
    }
    if config.app_allow_private_urls && !config.dev {
        tracing::warn!(
            "TAVRN_APP_ALLOW_PRIVATE_URLS=true: application URLs on private and loopback addresses are allowed (SSRF protection off)"
        );
    }
    if config.files_external.on() && config.files_external_private.on() {
        tracing::warn!(
            "TAVRN_FILES_EXTERNAL_PRIVATE=on: files channel stores on private and loopback addresses and plain http are allowed (SSRF protection off)"
        );
    }
    let router = app::router(state.clone());

    let addr: SocketAddr =
        config.listen.parse().with_context(|| format!("TAVRN_LISTEN is not a valid address: {}", config.listen))?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot open port {addr} (in use or no permission?)"))?;

    tracing::info!(domain = %config.domain, %addr, dev = config.dev, "tavrn node started");

    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server stopped")?;

    // Tell the other instances this one's connections are gone and hand the leadership over.
    if let Some(l) = leader {
        l.abort();
    }
    cache::shutdown(&state).await;
    housekeeping.abort();
    search_backfill.abort();
    outbox.abort();
    subscriptions.abort();
    directory.abort();
    conformance.abort();
    whiteboards.abort();
    reloads.abort();
    if let Some(r) = reconciler {
        r.abort();
    }
    if let Some(g) = grace_sweeper {
        g.abort();
    }
    if let Some(a) = advertiser {
        a.abort();
    }
    if let Some(lk) = livekit {
        lk.stop().await;
    }
    tracing::info!("shut down cleanly");
    Ok(())
}

/// SIGHUP reads the operator's auto-moderation lists again (MODERATION.md §2.3); the hourly housekeeping does it too.
fn spawn_reload_on_hangup(state: app::AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        match signal::unix::signal(signal::unix::SignalKind::hangup()) {
            Ok(mut hangup) => {
                while hangup.recv().await.is_some() {
                    tracing::info!("SIGHUP received, reading the auto-moderation node lists again");
                    let _ = automod::reload_node_lists(&state).await;
                }
            }
            Err(e) => tracing::error!(error = %e, "could not install the SIGHUP handler"),
        }
        #[cfg(not(unix))]
        let _ = state;
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "could not install the Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "could not install the SIGTERM handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, finishing in-flight requests");
}
