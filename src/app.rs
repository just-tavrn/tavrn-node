// SPDX-License-Identifier: AGPL-3.0-only
//! Router and shared state.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    http::{HeaderName, StatusCode, header},
    routing::{get, post, put},
};
use tower_http::{
    cors::{AllowHeaders, Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    auth::RateLimiter, cache::limiter::SharedLimiter, captcha::CaptchaVerifier, config::Config, db, gifs::GifClient,
    hub::Hub, keys::NodeKey, mail::Mailer, routes, storage::BlobStorage, ws,
};

pub const SOFTWARE_NAME: &str = "tavrn-node";
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: u32 = 1;

/// Capabilities this node actually offers right now. Grows with the phases.
pub fn capabilities(config: &Config) -> Vec<&'static str> {
    let mut caps = vec!["content.v1", tavrn_crypto::CAPABILITY, "reactions", "attachments", "pins", "emojis"];
    if config.gif_provider != crate::config::GifProvider::None {
        caps.push("gifs");
    }
    if config.unfurl == crate::unfurl::UnfurlSetting::On {
        caps.push("unfurl");
    }
    if config.federation_enabled {
        caps.push("federation");
        caps.push(crate::federation::CAPABILITY);
    }
    // Applications and installations, commands (APPLICATIONS.md §10.1).
    caps.push(crate::installations::CAPABILITY);
    caps.push(crate::commands::CAPABILITY);
    // App sessions of the connect flow for native apps (FEDERATION.md §8 step 3).
    caps.push(crate::connect_sessions::CAPABILITY);
    if config.oidc_issuer().is_some() {
        caps.push(crate::oidc::CAPABILITY);
    }
    // Incoming webhooks, subscriptions, hook tokens and embeds (APPLICATIONS.md §10.1).
    if config.webhooks_enabled {
        caps.push("webhooks.v1");
    }
    // Node-side message search over unencrypted channels (PROTOCOL.md §7d).
    if config.search_enabled {
        caps.push("search.v1");
    }
    if config.push.on() {
        caps.push(crate::push::CAPABILITY);
    }
    // Reports and content auto-moderation (MODERATION.md).
    caps.push("reports.v1");
    caps.push("automod.v1");
    // Forwarding reports about remote users to their home node (MODERATION.md §1.6): a federation feature.
    if config.federation_enabled {
        caps.push(crate::reports::forward::CAPABILITY);
    }
    // History restore after a key reset by request and approval (ENCRYPTION.md §7b).
    caps.push("history.restore");
    // History shares sealed per recipient device (ENCRYPTION.md §7b "Format v2").
    caps.push("history.shares2");
    // End-to-end encrypted files channels (FILES.md §8).
    caps.push("files.e2ee");
    // Polls with vote records and the plaintext close time (PROTOCOL.md §7g).
    caps.push("polls.v1");
    // Buttons, select menus and modals of applications (APPLICATIONS.md §5.10).
    caps.push(crate::components::CAPABILITY);
    // Threads, forum posts and announcement channels (PROTOCOL.md §7e).
    caps.extend(["threads", "forum", "announcement", "threads.client_ids"]);
    if config.voice_enabled {
        caps.push("voice");
        caps.push("soundboard");
        if config.screenshare_enabled {
            caps.push("screenshare");
        }
    }
    // Date of birth, private age status and age gates (PROTOCOL.md §5e).
    caps.push(crate::age::CAPABILITY);
    caps
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<Vec<NodeKey>>,
    /// Secret for data at rest (`<data_dir>/keys/secrets.key`), e.g. TOTP secrets.
    pub secret_key: Arc<zeroize::Zeroizing<[u8; 32]>>,
    pub db: db::Pool,
    /// This instance among the node's instances (`TAVRN_CACHE_URL`, `cache.rs`); standalone without a cache.
    pub cluster: Arc<crate::cache::Cluster>,
    pub hub: Hub,
    pub mailer: Mailer,
    pub captcha: CaptchaVerifier,
    pub storage: BlobStorage,
    pub gifs: Option<GifClient>,
    /// Link previews (`TAVRN_UNFURL`); `None` when switched off.
    pub unfurl: Option<Arc<crate::unfurl::Unfurler>>,
    pub login_limiter: Arc<SharedLimiter>,
    /// Password reset mails per account (`forgot-user:<id>`, 3 per hour).
    pub forgot_limiter: Arc<SharedLimiter>,
    /// Confirmation mails sent again per account (`verify-mail-user:<id>`, 3 per hour).
    pub verify_mail_limiter: Arc<SharedLimiter>,
    pub register_limiter: Arc<SharedLimiter>,
    /// KeyPackage claims per claiming user (`claim:<user id>`).
    pub claim_limiter: Arc<RateLimiter>,
    /// KeyPackage uploads per device (`kp:<device id>`).
    pub key_package_limiter: Arc<RateLimiter>,
    /// MLS commits per device (`commit:<device id>`).
    pub commit_limiter: Arc<RateLimiter>,
    /// Backup uploads per user (`backup:<user id>`).
    pub backup_limiter: Arc<RateLimiter>,
    /// Friend requests per user (`friend:<user id>`).
    pub friend_limiter: Arc<RateLimiter>,
    /// New DMs and group DMs per user (`conv:<user id>`).
    pub conversation_limiter: Arc<RateLimiter>,
    /// Second-factor attempts per account (`2fa:<user id>`, 5 per 5 minutes).
    pub second_factor_user_limiter: Arc<SharedLimiter>,
    /// Second-factor attempts per client IP (`2fa-ip:<ip>`, 20 per 5 minutes).
    pub second_factor_ip_limiter: Arc<SharedLimiter>,
    /// Secret storage writes per user (`secret-storage:<user id>`).
    pub secret_storage_limiter: Arc<RateLimiter>,
    /// Read marker updates per user (`read:<user id>`).
    pub read_limiter: Arc<RateLimiter>,
    /// New threads per user (`thread:<user id>`, 10 per minute; PROTOCOL.md §7e).
    pub thread_limiter: Arc<RateLimiter>,
    /// WebAuthn relying party.
    pub webauthn: Arc<webauthn_rs::prelude::Webauthn>,
    /// Outbound HTTP client for every request to other nodes (FEDERATION.md §1.3).
    pub federation: Arc<crate::federation::client::FederationClient>,
    /// Federated logins per remote domain (`domain:<domain>`, `TAVRN_FEDERATION_RATE_LOGINS` per minute).
    pub federation_login_limiter: Arc<SharedLimiter>,
    /// The share of one account (`user:<address>`) and of one client address (`domain:<domain>|ip:<address>`) of a
    /// domain's federated logins: a quarter of `TAVRN_FEDERATION_RATE_LOGINS`, at least 1.
    pub federation_login_share_limiter: Arc<SharedLimiter>,
    /// Inbox messages per remote domain (`domain:<domain>`, `TAVRN_FEDERATION_RATE_INBOX` per minute).
    pub federation_inbox_limiter: Arc<SharedLimiter>,
    /// Node-token requests (inbox, KeyPackage claims) per client address, before the signature check
    /// (`ip:<address>`).
    pub federation_ip_limiter: Arc<SharedLimiter>,
    /// Federation tokens per device (`token:<device id>`, 30 per minute).
    pub federation_token_limiter: Arc<SharedLimiter>,
    /// API requests of remote users per home domain (`domain:<domain>`, `TAVRN_FEDERATION_RATE_API` per minute).
    pub federation_api_limiter: Arc<RateLimiter>,
    /// API requests of one remote user (`user:<id>`, `TAVRN_FEDERATION_RATE_API_PER_USER` per minute, at most the
    /// domain's budget), counted before [`AppState::federation_api_limiter`].
    pub federation_user_api_limiter: Arc<RateLimiter>,
    /// S2S KeyPackage claims per requesting node (`domain:<domain>`, `TAVRN_FEDERATION_RATE_CLAIMS` per minute).
    pub federation_claim_limiter: Arc<RateLimiter>,
    /// S2S KeyPackage claims per requester and user (`<requester>|<user>`, 10 per hour, FEDERATION.md §3.5).
    pub claim_pair_limiter: Arc<SharedLimiter>,
    /// KeyPackage claims of unrelated requesters per source and target user (`<local | node domain>|<user id>`,
    /// `TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR` per hour, ENCRYPTION.md §3.2).
    pub claim_target_limiter: Arc<SharedLimiter>,
    /// The same claims per target user over all sources (`<user id>`, ten times the per-source budget per hour).
    pub claim_target_total_limiter: Arc<SharedLimiter>,
    /// Direct room invites per inviter (`invite:<user id>`, 20 per hour, §3.4).
    pub direct_invite_limiter: Arc<RateLimiter>,
    /// Received `room.invite` notifications per sender and recipient (10 per hour, §5.2).
    pub room_invite_inbox_limiter: Arc<RateLimiter>,
    /// `notify` hints per remote member and conversation (1 per 60 seconds, §5.2), counted for the whole node.
    pub notify_limiter: Arc<SharedLimiter>,
    /// Key cache refetches through `federation::keys::ensure` per remote user (1 per minute, §3.5).
    pub keys_fetch_limiter: Arc<RateLimiter>,
    /// Background refreshes of a remote user's profile mirror started by profile reads (`<user id>`, 1 per minute,
    /// FEDERATION.md §2.7): anonymous reads of a user whose home node fails cannot pile up refresh tasks.
    pub profile_refresh_limiter: Arc<RateLimiter>,
    /// Mirror refreshes started by received `profile.changed` per sender and user (`<iss>|<user id>`, 10 per 10
    /// minutes, FEDERATION.md §5.2); beyond it the inbox answers `429` and the sender retries later.
    pub profile_changed_limiter: Arc<SharedLimiter>,
    /// Received `node.announce` per sending domain (`domain:<domain>`, 1 per 10 minutes, FEDERATION.md §7.2).
    pub directory_announce_limiter: Arc<RateLimiter>,
    /// Public directory reads per client IP (`dir-ip:<ip>`; anonymous room discovery `discover-ip:<ip>`; 120 per
    /// minute each).
    pub directory_limiter: Arc<RateLimiter>,
    /// Wakes the outbox worker when a notification was queued.
    pub outbox_wakeup: Arc<tokio::sync::Notify>,
    /// Pending one-time codes of the connect flow (FEDERATION.md §8).
    pub connect_codes: Arc<routes::connect::ConnectCodes>,
    /// App sessions of the connect flow (FEDERATION.md §8 step 3) and their limits: creations per IP and for the
    /// whole node, polls per session and per IP.
    pub connect_sessions: Arc<crate::connect_sessions::ConnectSessions>,
    pub connect_session_limiter: Arc<SharedLimiter>,
    pub connect_session_node_limiter: Arc<SharedLimiter>,
    pub connect_poll_limiter: Arc<SharedLimiter>,
    pub connect_poll_ip_limiter: Arc<SharedLimiter>,
    /// Conformance check runs in progress (FEDERATION.md §9).
    pub conformance: Arc<crate::federation::conformance::Runner>,
    /// Voice: LiveKit credentials and client, process status, participants (`protocol/VOICE.md`).
    pub voice: crate::voice::SharedVoice,
    /// Voice joins and state changes per user (`voice:<user id>`).
    pub voice_limiter: Arc<RateLimiter>,
    /// Calls in DMs and group DMs (`calls.rs`).
    pub calls: Arc<crate::calls::Calls>,
    /// Media pipeline for avatars, headers, room icons and backgrounds (`media.rs`).
    pub media: Arc<crate::media::Pipeline>,
    /// Image uploads per user (`media:<user id>`).
    pub media_limiter: Arc<RateLimiter>,
    /// Presence of the users with a session on this node (`presence.rs`).
    pub presence: Arc<crate::presence::Registry>,
    /// Presence and activity updates per device (`presence:<device id>`) and room presence toggles per user
    /// (`presence-room:<user id>`).
    pub presence_limiter: Arc<RateLimiter>,
    /// API requests per user and minute (`TAVRN_RATE_USER_PER_MINUTE`, `None` when off).
    pub user_api_limiter: Option<Arc<RateLimiter>>,
    /// Files channels: listings and searches (`files:<user id>`), uploads (`files-upload:<user id>`).
    pub files_limiter: Arc<RateLimiter>,
    /// Purge previews per moderator (`purge:<user id>`).
    pub purge_limiter: Arc<RateLimiter>,
    /// The unauthenticated emoji and sound proxy (`?host=`, remote fetches) per address (`ip:<address>`).
    pub media_proxy_limiter: Arc<RateLimiter>,
    /// Fetches of the emoji and sound proxy from other nodes (cache misses) per client address (`miss:<ip>`).
    pub media_miss_limiter: Arc<RateLimiter>,
    /// When this instance last enforced `TAVRN_MEDIA_CACHE_MAX_BYTES` (`emoji_cache`).
    pub media_cache_checked: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Whiteboard sessions and ephemeral audiences (`whiteboard.rs`).
    pub whiteboards: Arc<crate::whiteboard::Whiteboards>,
    /// Ephemeral events per sender (`eph:<user id>`, 30 per second, also in development).
    pub ephemeral_limiter: Arc<RateLimiter>,
    /// Writes to the whiteboard scene library per user (`scenes:<user id>`).
    pub scene_limiter: Arc<RateLimiter>,
    /// Single sign-on via OpenID Connect (APPLICATIONS.md §8); `None` without `TAVRN_OIDC_ISSUER`.
    pub oidc: Option<Arc<crate::oidc::Oidc>>,
    /// API requests per application (`app:<application id>`, remote bots `app:<user id>`;
    /// `TAVRN_APP_RATE_REQUESTS` per minute, APPLICATIONS.md §2.7).
    pub app_request_limiter: Arc<SharedLimiter>,
    /// Token creations and resets per application (`app-token:<application id>`, 10 per hour).
    pub app_token_limiter: Arc<SharedLimiter>,
    /// Token rotations by the bot per token (`rotate:<token id>`, once per 24 hours).
    pub app_rotate_limiter: Arc<SharedLimiter>,
    /// Application creations per user (`app-create:<user id>`, 5 per day).
    pub app_create_limiter: Arc<SharedLimiter>,
    /// Messages per bot and conversation (`bot-msg:<bot id>:<conversation id>`, 5 per 5 seconds).
    pub bot_message_limiter: Arc<RateLimiter>,
    /// Vote changes per user and minute (PROTOCOL.md §7g; part of the protocol, also in development).
    pub poll_vote_limiter: Arc<SharedLimiter>,
    /// New DMs per bot (`bot-dm:<bot id>`, 10 per 10 minutes).
    pub bot_dm_limiter: Arc<RateLimiter>,
    /// Open WebSockets per app token (at most 2, APPLICATIONS.md §2.6).
    pub app_connections: Arc<crate::applications::Connections>,
    /// Live interactions and the bots' receiving connections (APPLICATIONS.md §5.5–§5.7).
    pub interactions: Arc<crate::interactions::Interactions>,
    /// Interactions per invoking user (`interaction:<user id>`, 5 per 5 seconds, APPLICATIONS.md §2.7).
    pub interaction_limiter: Arc<RateLimiter>,
    /// Command announcements per application (`app-cmd:<application id>`, 10 per hour) and interactions URL
    /// verifications (`app-url:<application id>`, 10 per hour).
    pub app_commands_limiter: Arc<RateLimiter>,
    /// Outbound client for application URLs (hook requests, APPLICATIONS.md §6.3).
    pub hooks: Arc<crate::hooks::HookClient>,
    /// Webhook executions per webhook (`wh:<id>`): 5 per 2 seconds and 30 per minute (APPLICATIONS.md §2.7).
    pub webhook_burst_limiter: Arc<SharedLimiter>,
    pub webhook_minute_limiter: Arc<SharedLimiter>,
    /// Wakes the delivery worker of event subscriptions when an event was queued (APPLICATIONS.md §6.2).
    pub subscription_wakeup: Arc<tokio::sync::Notify>,
    /// Search requests per user (`search:<user id>`, `TAVRN_SEARCH_RATE_PER_MINUTE` per minute).
    pub search_limiter: Arc<RateLimiter>,
    /// The operator's auto-moderation lists (`TAVRN_AUTOMOD_WORDS_FILE`, `TAVRN_AUTOMOD_LINKS`, MODERATION.md §2.3).
    pub node_automod: Arc<crate::automod::NodeFilter>,
    /// Admin API calls per node admin session (`admin:<user id>`) and per admin token (`admin-token:<id>`).
    pub admin_limiter: Arc<RateLimiter>,
    /// Takedown notices per client IP (`notice-ip:<ip>`, `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR` per hour).
    pub legal_notice_limiter: Arc<SharedLimiter>,
    /// Notices forwarded by other nodes per sending domain (`<domain>`, `TAVRN_LEGAL_NOTICE_INBOUND_PER_HOUR` per
    /// hour) and from all domains together (five times as many).
    pub legal_inbound_limiter: Arc<SharedLimiter>,
    pub legal_inbound_total_limiter: Arc<SharedLimiter>,
    /// Reports forwarded by other nodes (MODERATION.md §1.6): per sending registrable domain and in total.
    pub reports_inbound_limiter: Arc<SharedLimiter>,
    pub reports_inbound_total_limiter: Arc<SharedLimiter>,
    /// Status-link lookups (notices, account deletions) per client IP (`lookup-ip:<ip>`, 60 per hour).
    pub legal_lookup_limiter: Arc<SharedLimiter>,
    /// Per account (user id): access tokens issued before this Unix time are expired. Only development nodes fill it
    /// (`POST /dev/expire-access-tokens`, e2e tests of the refresh paths); empty otherwise. Per account, so a test
    /// never ends the sessions of the tests running in parallel on the same node.
    pub access_not_before: Arc<std::sync::Mutex<std::collections::HashMap<String, i64>>>,
    /// Web push (`push.rs`): VAPID key, subscriptions' sender, limits.
    pub push: Arc<crate::push::Push>,
    /// Counters and gauges of `GET /metrics` (`metrics.rs`).
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Local devices whose session was found live recently (`sessions::device_live`).
    pub live_sessions: Arc<crate::sessions::LiveCache>,
    /// Heartbeat of WebSockets (`ws::PING_INTERVAL`; tests shorten it to watch the session re-check).
    pub ws_ping: Duration,
    /// `TAVRN_TRUSTED_PROXIES`, parsed once (`auth::ClientIp` consults it for every request).
    pub trusted_proxies: Arc<[ipnet::IpNet]>,
    /// How long a WebSocket send may take before the connection ends (`ws::SEND_TIMEOUT`; tests shorten it).
    pub ws_send_timeout: Duration,
    /// Argon2 runs at once (`TAVRN_PASSWORD_HASH_CONCURRENCY`, `auth::hash`/`auth::verify`).
    pub password_hashing: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    /// Builds the state: load/create keys, connect to and migrate the database.
    pub async fn init(config: Config) -> anyhow::Result<Self> {
        Self::init_with_federation(config, crate::federation::client::ClientOptions::default()).await
    }

    /// Like [`AppState::init`] with a federation client built by the caller (tests inject DNS lookups
    /// and short timeouts).
    pub async fn init_with_federation(
        config: Config,
        options: crate::federation::client::ClientOptions,
    ) -> anyhow::Result<Self> {
        Self::init_with(config, options, None).await
    }

    /// Like [`AppState::init_with_federation`], optionally joining a cluster built by the caller (tests share one
    /// in-process cache between two states); otherwise the cluster comes from `TAVRN_CACHE_URL`.
    pub async fn init_with(
        config: Config,
        options: crate::federation::client::ClientOptions,
        cluster: Option<crate::cache::Cluster>,
    ) -> anyhow::Result<Self> {
        let key_dir = std::path::Path::new(&config.data_dir).join("keys");
        let keys = NodeKey::load_or_create(&key_dir)?;
        let secret_key = Arc::new(crate::keys::load_or_create_secret(&key_dir)?);
        // Fail fast (before migrations) when the configured cache does not answer.
        let cluster = Arc::new(match cluster {
            Some(c) => c,
            None => crate::cache::Cluster::from_config(&config, &secret_key).await?,
        });
        // Several instances starting together: one at a time through migrations, fixups and key setup.
        crate::cache::leader::startup_lock(&cluster).await?;
        let prepared = async {
            let db = db::connect_with(&config.database_url, config.slow_statement_threshold()).await?;
            crate::fixups::run(&db).await?;
            let storage = BlobStorage::open(&config, db.clone()).await?;
            anyhow::Ok((db, storage))
        }
        .await;
        crate::cache::leader::startup_unlock(&cluster).await;
        let (db, storage) = prepared?;
        let webauthn = Arc::new(crate::second_factor::build_webauthn(&config)?);
        // Application URLs share the injected DNS lookup with the federation client (tests).
        let hooks = Arc::new(crate::hooks::HookClient::new(&config, options.lookup.clone())?);
        let options_lookup = options.lookup.clone();
        let federation = Arc::new(crate::federation::client::FederationClient::with_options(&config, options)?);
        let push = Arc::new(crate::push::Push::new(&config, &cluster, options_lookup)?);
        let mut state = Self::assemble(config, keys, secret_key, db, storage, federation, webauthn, cluster, push)?;
        state.hooks = hooks;
        crate::cache::start(&state);
        crate::push::start(&state);
        crate::voice::spawn_access_watcher(&state);
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        config: Config,
        keys: Vec<NodeKey>,
        secret_key: Arc<zeroize::Zeroizing<[u8; 32]>>,
        db: db::Pool,
        storage: BlobStorage,
        federation: Arc<crate::federation::client::FederationClient>,
        webauthn: Arc<webauthn_rs::prelude::Webauthn>,
        cluster: Arc<crate::cache::Cluster>,
        push: Arc<crate::push::Push>,
    ) -> anyhow::Result<Self> {
        crate::auth::set_ipv6_rate_prefix(config.rate_limit_ipv6_prefix);
        let mailer = Mailer::from_config(&config);
        let captcha = CaptchaVerifier::from_config(&config);
        let gifs = GifClient::from_config(&config);
        let unfurl = crate::unfurl::Unfurler::from_config(&config).map(Arc::new);
        // In development mode (including tests) the limits are generous, in production strict.
        let (login_max, register_max) = if config.dev { (1000, 1000) } else { (10, 5) };
        // (claim, key packages, commit, backup, friend, conversation) per window below.
        let e2ee = if config.dev { (1000, 1000, 1000, 1000, 1000, 1000) } else { (120, 30, 60, 60, 20, 30) };
        // (second factor per account, per IP, secret storage writes)
        let factors = if config.dev { (1000, 1000, 1000) } else { (5, 20, 30) };
        let read_max = if config.dev { 1000 } else { 120 };
        let thread_max = if config.dev { 1000 } else { 10 };
        let token_max = if config.dev { 1000 } else { 30 };
        // (claim pair, direct invites, received room invites) per hour
        let invites = if config.dev { (1000, 1000, 1000) } else { (10, 20, 10) };
        // (announces per domain and 10 minutes, directory reads per IP and minute)
        let directory = if config.dev { (1000, 1000) } else { (1, 120) };
        let limiter = |max: u32, secs: u64| Arc::new(RateLimiter::new(max, Duration::from_secs(secs)));
        // Limits that protect accounts and the node are shared by all instances (`cache::limiter`).
        let shared = |name: &'static str, max: u32, secs: u64| {
            Arc::new(SharedLimiter::new(name, max, Duration::from_secs(secs), &cluster))
        };
        Ok(Self {
            federation,
            federation_login_limiter: shared("fed-login", config.federation_rate_logins, 60),
            federation_login_share_limiter: shared("fed-login-share", (config.federation_rate_logins / 4).max(1), 60),
            federation_inbox_limiter: shared("fed-inbox", config.federation_rate_inbox, 60),
            federation_ip_limiter: shared("fed-ip", if config.dev { 10_000 } else { 600 }, 60),
            federation_token_limiter: shared("fed-token", token_max, 60),
            federation_api_limiter: limiter(config.federation_rate_api, 60),
            federation_user_api_limiter: limiter(
                config.federation_rate_api_per_user.min(config.federation_rate_api).max(1),
                60,
            ),
            federation_claim_limiter: limiter(config.federation_rate_claims, 60),
            claim_pair_limiter: shared("claim-pair", invites.0, 3600),
            claim_target_limiter: shared("claim-target", config.e2ee_claims_per_target_per_hour, 3600),
            claim_target_total_limiter: shared(
                "claim-target-total",
                config.e2ee_claims_per_target_per_hour.saturating_mul(10),
                3600,
            ),
            direct_invite_limiter: limiter(invites.1, 3600),
            room_invite_inbox_limiter: limiter(invites.2, 3600),
            notify_limiter: shared("fed-notify", 1, 60),
            keys_fetch_limiter: limiter(1, 60),
            profile_refresh_limiter: limiter(1, 60),
            profile_changed_limiter: shared(
                "fed-profile-changed",
                crate::federation::profiles::CHANGED_PER_WINDOW,
                crate::federation::profiles::CHANGED_WINDOW_SECS,
            ),
            directory_announce_limiter: limiter(directory.0, 600),
            directory_limiter: limiter(directory.1, 60),
            outbox_wakeup: Arc::new(tokio::sync::Notify::new()),
            conformance: Arc::new(crate::federation::conformance::Runner::default()),
            voice: Arc::new(crate::voice::VoiceRuntime::new(&config)?),
            voice_limiter: limiter(if config.dev { 1000 } else { 60 }, 60),
            calls: Arc::new(crate::calls::Calls::new(
                std::time::Duration::from_secs(config.voice_reconnect_grace_secs),
                config.dev,
            )),
            media: Arc::new(crate::media::Pipeline::new(&config)),
            media_limiter: limiter(if config.dev { 1000 } else { 30 }, 3600),
            presence: Arc::new(crate::presence::Registry::new(&cluster)),
            presence_limiter: limiter(if config.dev { 1000 } else { 60 }, 60),
            user_api_limiter: (config.rate_user_per_minute > 0).then(|| limiter(config.rate_user_per_minute, 60)),
            files_limiter: limiter(if config.dev { 1000 } else { 120 }, 60),
            purge_limiter: limiter(if config.dev { 1000 } else { 10 }, 60),
            media_proxy_limiter: limiter(if config.dev { 10_000 } else { 600 }, 60),
            media_miss_limiter: limiter(crate::emoji_cache::miss_limit(config.dev), 60),
            media_cache_checked: Arc::default(),
            whiteboards: Arc::new(crate::whiteboard::Whiteboards::default()),
            ephemeral_limiter: limiter(crate::whiteboard::EVENTS_PER_SECOND, 1),
            // Autosave every 30 s plus manual saves, thumbnails and renames.
            scene_limiter: limiter(if config.dev { 1000 } else { 360 }, 3600),
            oidc: crate::oidc::Oidc::from_config(&config)?.map(|o| Arc::new(o.with_cluster(&cluster))),
            // Bot limits are the same in development: they are part of the protocol (APPLICATIONS.md §2.7).
            app_request_limiter: shared("app-request", config.app_rate_requests, 60),
            app_token_limiter: shared("app-token", 10, 3600),
            app_rotate_limiter: shared("app-rotate", 1, 24 * 3600),
            app_create_limiter: shared("app-create", 5, 24 * 3600),
            bot_message_limiter: limiter(5, 5),
            poll_vote_limiter: shared("poll-vote", crate::polls::VOTES_PER_MINUTE, 60),
            bot_dm_limiter: limiter(10, 600),
            interactions: Arc::new(crate::interactions::Interactions::new(&cluster)),
            interaction_limiter: limiter(5, 5),
            app_commands_limiter: limiter(10, 3600),
            hooks: Arc::new(crate::hooks::HookClient::from_config(&config)?),
            webhook_burst_limiter: shared("webhook-burst", 5, 2),
            webhook_minute_limiter: shared("webhook-minute", 30, 60),
            subscription_wakeup: Arc::new(tokio::sync::Notify::new()),
            admin_limiter: limiter(if config.dev { 100_000 } else { 600 }, 60),
            legal_notice_limiter: shared("legal-notice", config.legal_notice_rate_per_hour, 3600),
            legal_inbound_limiter: shared("legal-inbound", config.legal_notice_inbound_per_hour, 3600),
            legal_inbound_total_limiter: shared("legal-inbound-all", config.legal_notice_inbound_per_hour * 5, 3600),
            reports_inbound_limiter: shared("reports-inbound", config.reports_inbound_per_hour, 3600),
            reports_inbound_total_limiter: shared("reports-inbound-all", config.reports_inbound_per_hour * 5, 3600),
            legal_lookup_limiter: shared("legal-lookup", if config.dev { 1000 } else { 60 }, 3600),
            search_limiter: limiter(config.search_rate_per_minute, 60),
            node_automod: Arc::new(crate::automod::NodeFilter::from_config(&config)?),
            access_not_before: Arc::default(),
            live_sessions: Arc::default(),
            ws_ping: crate::ws::PING_INTERVAL,
            trusted_proxies: config.trusted_proxies().into(),
            ws_send_timeout: crate::ws::SEND_TIMEOUT,
            password_hashing: Arc::new(tokio::sync::Semaphore::new(match config.password_hash_concurrency {
                0 => crate::auth::default_hash_concurrency(),
                n => n as usize,
            })),
            push,
            metrics: Arc::new(crate::metrics::Metrics::new(SOFTWARE_VERSION, cluster.is_shared())),
            app_connections: Arc::new(crate::applications::Connections::new(&cluster)),
            connect_codes: Arc::new(routes::connect::ConnectCodes::new(&cluster)),
            connect_sessions: Arc::new(crate::connect_sessions::ConnectSessions::new(&cluster)),
            connect_session_limiter: shared("connect-session", crate::connect_sessions::create_limit(config.dev), 60),
            connect_session_node_limiter: shared(
                "connect-session-node",
                crate::connect_sessions::create_limit_node(config.dev),
                60,
            ),
            connect_poll_limiter: shared("connect-poll", crate::connect_sessions::POLLS_PER_SESSION, 60),
            connect_poll_ip_limiter: shared("connect-poll-ip", crate::connect_sessions::poll_limit_ip(config.dev), 60),
            cluster: cluster.clone(),
            config: Arc::new(config),
            keys: Arc::new(keys),
            secret_key,
            db,
            hub: Hub::with_bus(cluster.event_sender()),
            captcha,
            storage,
            gifs,
            unfurl,
            mailer,
            login_limiter: shared("login", login_max, 60),
            forgot_limiter: shared("forgot-user", 3, 3600),
            verify_mail_limiter: shared("verify-mail-user", 3, 3600),
            register_limiter: shared("register", register_max, 600),
            claim_limiter: limiter(e2ee.0, 60),
            key_package_limiter: limiter(e2ee.1, 60),
            commit_limiter: limiter(e2ee.2, 60),
            backup_limiter: limiter(e2ee.3, 60),
            friend_limiter: limiter(e2ee.4, 3600),
            conversation_limiter: limiter(e2ee.5, 3600),
            second_factor_user_limiter: shared("2fa-user", factors.0, 300),
            second_factor_ip_limiter: shared("2fa-ip", factors.1, 300),
            secret_storage_limiter: limiter(factors.2, 3600),
            // Clients debounce markers; 120 per minute leave room for many open tabs.
            read_limiter: limiter(read_max, 60),
            thread_limiter: limiter(thread_max, 60),
            webauthn,
        })
    }

    /// Newest key, used for signing.
    pub fn signing_key(&self) -> &NodeKey {
        // `load_or_create` guarantees at least one key.
        self.keys.last().unwrap_or_else(|| unreachable!("keys is never empty"))
    }
}

/// CORS for every route (FEDERATION.md §8): web clients of other nodes call this node's API with
/// bearer tokens. Any origin, never credentials (there are no cookies), the request headers clients
/// send, the response headers they read, preflight cached for 10 minutes.
pub fn cors() -> CorsLayer {
    // Bearer tokens only, never cookies, so any origin may call the API without credentials, and the preflight
    // mirrors whatever request headers a client names: the native apps (origin `tauri.localhost`) send the
    // `Tavrn-*` headers of the upload routes, and a fixed list silently broke every new one ("network error").
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(AllowHeaders::mirror_request())
        .expose_headers([
            header::ETAG,
            header::RETRY_AFTER,
            header::LOCATION,
            header::CONTENT_RANGE,
            header::CONTENT_DISPOSITION,
        ])
        .max_age(Duration::from_secs(600))
}

/// `Permissions-Policy` of every response.
pub const PERMISSIONS_POLICY: &str = "camera=(self), microphone=(self), display-capture=(self), geolocation=(), \
     payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), accelerometer=(), gyroscope=(), magnetometer=()";

pub fn router(state: AppState) -> Router {
    let request_id = HeaderName::from_static("x-request-id");
    // Uploads may be as large as the node limit. JSON routes are bounded by axum's default body limit (2 MiB) or a
    // smaller `DefaultBodyLimit` of their own; byte routes check their sizes themselves.
    let body_limit =
        (state.config.upload_ceiling() as usize).max(routes::mls::MLS_BODY_LIMIT).max(crate::media::MAX_INPUT_BYTES)
            + 64 * 1024;
    let mls_limit = axum::extract::DefaultBodyLimit::max(routes::mls::MLS_BODY_LIMIT);
    // Small JSON bodies, among them the anonymous sign-in routes: nothing an anonymous client sends is kept large.
    let small = || axum::extract::DefaultBodyLimit::max(16 * 1024);
    let webauthn_limit = || axum::extract::DefaultBodyLimit::max(routes::second_factor::WEBAUTHN_BODY_LIMIT);

    let api = Router::new()
        .route("/node", get(routes::node::get_node))
        .route("/ws", get(ws::ws_handler))
        .route("/auth/register", post(routes::auth::register).layer(small()))
        .route("/auth/login", post(routes::auth::login).layer(small()))
        .route("/auth/refresh", post(routes::auth::refresh).layer(small()))
        .route("/auth/device-nonce", post(routes::auth::device_nonce).layer(small()))
        .route("/auth/reauth", post(routes::second_factor::reauth).layer(webauthn_limit()))
        .route("/auth/reauth/webauthn/start", post(routes::second_factor::reauth_webauthn_start))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/verify-email", post(routes::auth::verify_email).layer(small()))
        .route("/auth/verify-email/resend", post(routes::auth::resend_verification).layer(small()))
        .route("/auth/forgot-password", post(routes::auth::forgot_password).layer(small()))
        .route("/auth/reset-password", post(routes::auth::reset_password).layer(small()))
        .route("/auth/second-factor/verify", post(routes::second_factor::verify).layer(small()))
        .route("/auth/factors", get(routes::second_factor::factors))
        .route("/auth/totp/enroll", post(routes::second_factor::totp_enroll))
        .route("/auth/totp/confirm", post(routes::second_factor::totp_confirm).layer(small()))
        .route("/auth/totp", axum::routing::delete(routes::second_factor::totp_remove).layer(small()))
        .route("/auth/recovery-codes/regenerate", post(routes::second_factor::regenerate_recovery_codes).layer(small()))
        .route("/auth/webauthn/register/start", post(routes::second_factor::webauthn_register_start))
        .route(
            "/auth/webauthn/register/finish",
            post(routes::second_factor::webauthn_register_finish).layer(webauthn_limit()),
        )
        .route("/auth/webauthn/credentials", get(routes::second_factor::webauthn_credentials))
        .route(
            "/auth/webauthn/credentials/{credential_id}",
            axum::routing::delete(routes::second_factor::webauthn_delete_credential),
        )
        .route("/auth/webauthn/login/start", post(routes::second_factor::webauthn_login_start).layer(small()))
        .route(
            "/auth/webauthn/login/finish",
            post(routes::second_factor::webauthn_login_finish).layer(webauthn_limit()),
        )
        .route("/account-invites/{code}", get(routes::admin::check_account_invite))
        .route("/admin/overview", get(routes::admin::overview))
        .route("/admin/users", get(routes::admin::list_users))
        .route("/admin/users/{user_id}", axum::routing::patch(routes::admin::update_user))
        .route("/admin/users/{user_id}/purge", post(routes::admin::purge_user))
        .route("/admin/users/{user_id}/second-factor/reset", post(routes::admin::reset_second_factor))
        .route("/admin/invites", get(routes::admin::list_invites).post(routes::admin::create_invite))
        .route("/admin/invites/{code}", axum::routing::delete(routes::admin::delete_invite))
        .route("/admin/bans", get(routes::admin::list_bans).post(routes::admin::ban))
        .route("/admin/bans/{subject}", axum::routing::delete(routes::admin::unban))
        .route("/admin/audit-log", get(routes::admin::audit_log))
        .route("/admin/directory/delisted", get(routes::directory::delisted))
        .route("/admin/directory/relist", post(routes::directory::relist).layer(small()))
        .route("/admin/directory/nodes/{domain}", axum::routing::delete(routes::directory::delist_node))
        .route("/admin/directory/rooms/{node}/{room_id}", axum::routing::delete(routes::directory::delist_room))
        .route("/directory/nodes", get(routes::directory::nodes))
        .route("/directory/nodes/{domain}", get(routes::directory::node))
        .route("/directory/rooms", get(routes::directory::rooms))
        .route("/directory/reports", post(routes::directory::report).layer(small()))
        .route("/admin/directory/reports", get(routes::directory::report_summary))
        .route(
            "/admin/directory/reports/{domain}",
            get(routes::directory::reports_of).delete(routes::directory::dismiss_reports),
        )
        // Applications (bots), APPLICATIONS.md §1–§3.
        .route("/applications", get(routes::applications::list).post(routes::applications::create).layer(small()))
        .route("/applications/transfers", get(routes::applications::incoming_transfers))
        .route("/applications/me", get(routes::applications::me))
        .route("/applications/me/tokens/rotate", post(routes::applications::rotate))
        .route(
            "/applications/{application_id}",
            get(routes::applications::get)
                .patch(routes::applications::update)
                .delete(routes::applications::delete)
                .layer(small()),
        )
        .route(
            "/applications/{application_id}/avatar",
            put(routes::applications::put_avatar)
                .delete(routes::applications::delete_avatar)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/applications/{application_id}/transfer",
            post(routes::applications::start_transfer).delete(routes::applications::cancel_transfer).layer(small()),
        )
        .route("/applications/{application_id}/transfer/accept", post(routes::applications::accept_transfer))
        .route("/applications/{application_id}/transfer/decline", post(routes::applications::decline_transfer))
        .route("/applications/{application_id}/identity/reset", post(routes::applications::identity_reset))
        .route(
            "/applications/{application_id}/tokens",
            get(routes::applications::list_tokens).post(routes::applications::create_token).layer(small()),
        )
        .route(
            "/applications/{application_id}/tokens/{token_id}",
            axum::routing::delete(routes::applications::revoke_token),
        )
        .route(
            "/applications/{application_id}/tokens/{token_id}/reset",
            post(routes::applications::reset_token).layer(small()),
        )
        .route("/users/me", get(routes::auth::me).patch(routes::profile::update_me).delete(routes::legal::delete_me))
        .route("/users/me/devices", get(routes::auth::devices))
        .route("/users/me/devices/retired", post(routes::keys::put_retired_device))
        .route("/users/me/devices/{device_id}", axum::routing::delete(routes::auth::delete_device))
        .route("/users/me/password", post(routes::auth::change_password))
        .route(
            "/users/me/notification-settings",
            get(routes::notifications::get)
                .put(routes::notifications::put)
                .layer(axum::extract::DefaultBodyLimit::max(2 * crate::notifications::MAX_BYTES)),
        )
        .route("/users/{address}/profile", get(routes::profile::get_profile))
        // Profiles, presence and media. Image uploads read their body themselves (media.rs cap).
        .route(
            "/users/me/avatar",
            put(routes::profile::put_avatar)
                .delete(routes::profile::delete_avatar)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/users/me/header",
            put(routes::profile::put_header)
                .delete(routes::profile::delete_header)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/users/me/background",
            get(routes::profile::get_background)
                .put(routes::profile::put_background)
                .delete(routes::profile::delete_background)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/users/me/background/{variant}", get(routes::profile::background_image))
        .route("/users/me/voice", get(routes::voice::my_states))
        .route("/users/me/presence", get(routes::presence::get_mine).put(routes::presence::put_mine).layer(small()))
        .route(
            "/users/me/activity",
            put(routes::presence::put_activity).delete(routes::presence::delete_activity).layer(small()),
        )
        .route("/presence", get(routes::presence::list))
        .route(
            "/rooms/{room_id}/presence",
            get(routes::presence::get_room_setting).put(routes::presence::put_room_setting).layer(small()),
        )
        .route("/media/{media_id}", get(routes::profile::get_media))
        .route("/media/{media_id}/animated", get(routes::profile::get_media_animated))
        .route(
            "/rooms/{room_id}/icon",
            put(routes::profile::put_room_icon)
                .delete(routes::profile::delete_room_icon)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/users/{username}/keys", get(routes::keys::get_keys))
        .route("/users/{username}/key-packages/claim", post(routes::keys::claim_key_packages))
        .route("/users/me/identity", put(routes::keys::put_identity).layer(small()))
        .route("/users/me/identity/reset", post(routes::keys::reset_identity).layer(small()))
        .route(
            "/users/me/identity/rotate",
            post(routes::identity::rotate)
                .layer(axum::extract::DefaultBodyLimit::max(routes::identity::ROTATE_BODY_LIMIT)),
        )
        .route("/users/me/identity/blob", get(routes::identity::blob))
        .route("/users/me/devices/{device_id}/key", put(routes::keys::put_device_key).layer(small()))
        .route("/users/me/devices/{device_id}/share-key", put(routes::keys::put_share_key).layer(small()))
        .route(
            "/users/me/devices/{device_id}/key-packages",
            get(routes::keys::count_key_packages)
                .post(routes::keys::upload_key_packages)
                .layer(axum::extract::DefaultBodyLimit::max(routes::keys::KEY_PACKAGE_BODY_LIMIT)),
        )
        .route("/users/me/secret-storage", get(routes::secret_storage::list))
        .route("/users/me/secret-storage/recovery", put(routes::secret_storage::put_recovery).layer(small()))
        .route(
            "/users/me/secret-storage/passkey/{credential_id}",
            put(routes::secret_storage::put_passkey).delete(routes::secret_storage::delete_passkey).layer(small()),
        )
        .route("/users/me/backups", get(routes::backups::list_backups))
        .route(
            "/users/me/backups/{domain}/{conversation_id}",
            get(routes::backups::get_backup).put(routes::backups::put_backup),
        )
        // Whiteboard scene library: bodies are read with their own limits.
        .route("/users/me/whiteboards", get(routes::whiteboard::list_scenes))
        .route(
            "/users/me/whiteboards/background",
            post(routes::whiteboard::convert_background).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/users/me/whiteboards/{scene_id}",
            get(routes::whiteboard::get_scene)
                .put(routes::whiteboard::put_scene)
                .patch(routes::whiteboard::rename_scene)
                .delete(routes::whiteboard::delete_scene)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/users/me/whiteboards/{scene_id}/thumbnail",
            get(routes::whiteboard::get_thumbnail)
                .put(routes::whiteboard::put_thumbnail)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/users/me/friends", get(routes::friends::list))
        .route("/users/me/friends/requests", post(routes::friends::send_request).layer(small()))
        .route("/users/me/friends/requests/{request_id}", axum::routing::delete(routes::friends::delete_request))
        .route("/users/me/friends/requests/{request_id}/accept", post(routes::friends::accept))
        .route("/users/me/friends/{username}", axum::routing::delete(routes::friends::remove))
        .route("/users/me/blocks", get(routes::friends::blocks).post(routes::friends::block).layer(small()))
        .route("/users/me/blocks/{username}", axum::routing::delete(routes::friends::unblock))
        .route("/conversations", get(routes::conversations::list).post(routes::conversations::create).layer(small()))
        .route(
            "/conversations/{conversation_id}",
            get(routes::conversations::get).patch(routes::conversations::update).layer(small()),
        )
        .route("/conversations/{conversation_id}/members", post(routes::conversations::add_member).layer(small()))
        .route("/conversations/requests", get(routes::conversations::requests))
        .route("/conversations/{conversation_id}/accept", post(routes::conversations::accept))
        .route("/conversations/{conversation_id}/decline", post(routes::conversations::decline).layer(small()))
        .route(
            "/conversations/{conversation_id}/members/{username}",
            axum::routing::delete(routes::conversations::remove_member),
        )
        .route(
            "/conversations/{conversation_id}/messages",
            get(routes::messages::list_conversation_messages).post(routes::messages::create_conversation_message),
        )
        .route("/conversations/{conversation_id}/read", put(routes::read::mark_read).layer(small()))
        // Ephemeral events (whiteboard, cursors): fanned out, never stored.
        .route(
            "/conversations/{conversation_id}/ephemeral",
            post(routes::whiteboard::post_ephemeral)
                .layer(axum::extract::DefaultBodyLimit::max(crate::whiteboard::MAX_CONTENT_BYTES + 16 * 1024)),
        )
        .route("/conversations/{conversation_id}/whiteboard", get(routes::whiteboard::get_session))
        .route("/conversations/{conversation_id}/upload-policy", get(routes::attachments::upload_policy))
        .route(
            "/conversations/{conversation_id}/messages/{message_id}",
            axum::routing::patch(routes::messages::edit_conversation_message)
                .delete(routes::messages::delete_conversation_message),
        )
        .route(
            "/conversations/{conversation_id}/messages/{message_id}/reactions/{emoji}",
            put(routes::attachments::add_conversation_reaction)
                .delete(routes::attachments::remove_conversation_reaction)
                .get(routes::attachments::list_reactors),
        )
        // Poll vote records (PROTOCOL.md §7g): one per member and poll.
        .route(
            "/conversations/{conversation_id}/messages/{message_id}/poll/vote",
            put(routes::polls::put_poll_vote).delete(routes::polls::delete_poll_vote).layer(small()),
        )
        .route("/conversations/{conversation_id}/messages/{message_id}/poll/votes", get(routes::polls::list_poll_votes))
        .route("/conversations/{conversation_id}/pins", get(routes::attachments::list_conversation_pins))
        .route(
            "/conversations/{conversation_id}/pins/{message_id}",
            put(routes::attachments::pin_in_conversation).delete(routes::attachments::unpin_in_conversation),
        )
        .route(
            "/conversations/{conversation_id}/uploads",
            post(routes::attachments::upload_to_conversation).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/conversations/{conversation_id}/mls/group", post(routes::mls::create_group).layer(mls_limit))
        .route("/conversations/{conversation_id}/mls/group-info", get(routes::mls::group_info))
        .route("/conversations/{conversation_id}/mls/commits", post(routes::mls::post_commit).layer(mls_limit))
        .route("/conversations/{conversation_id}/mls/messages", get(routes::mls::log))
        .route(
            "/conversations/{conversation_id}/history-keys",
            get(routes::history::list_shares).post(routes::history::create_share),
        )
        .route(
            "/conversations/{conversation_id}/history-keys/{share_id}",
            axum::routing::delete(routes::history::ack_share),
        )
        .route("/conversations/{conversation_id}/history-pending", get(routes::history::list_pending))
        .route(
            "/rooms/{room_id}/history-requests",
            get(routes::history_requests::list).post(routes::history_requests::create),
        )
        .route("/rooms/{room_id}/history-requests/mine", get(routes::history_requests::mine))
        .route(
            "/rooms/{room_id}/history-requests/{request_id}",
            axum::routing::delete(routes::history_requests::cancel),
        )
        .route("/rooms/{room_id}/history-requests/{request_id}/approve", post(routes::history_requests::approve))
        .route("/rooms/{room_id}/history-requests/{request_id}/deny", post(routes::history_requests::deny))
        .route("/conversations/{conversation_id}/mls/pending-removals", get(routes::mls::pending_removals))
        .route("/mls/pending-removals", get(routes::mls::own_pending_removals))
        .route("/mls/welcomes", get(routes::mls::welcomes))
        .route("/mls/welcomes/{welcome_id}", axum::routing::delete(routes::mls::delete_welcome))
        .route("/rooms", get(routes::rooms::list_my_rooms).post(routes::rooms::create_room))
        .route("/rooms/discover", get(routes::rooms::discover_rooms))
        .route(
            "/rooms/{room_id}",
            get(routes::rooms::get_room).patch(routes::rooms::update_room).delete(routes::rooms::delete_room),
        )
        .route("/rooms/{room_id}/join", post(routes::rooms::join_room))
        .route("/rooms/{room_id}/leave", post(routes::rooms::leave_room))
        .route("/rooms/{room_id}/members", get(routes::rooms::list_members))
        .route(
            "/rooms/{room_id}/members/{user_id}",
            axum::routing::patch(routes::rooms::update_member).delete(routes::rooms::kick_member),
        )
        .route("/rooms/{room_id}/members/{user_id}/timeout", put(routes::rooms::timeout_member))
        // Per-room profiles; the avatar upload reads its body itself (media.rs cap).
        .route(
            "/rooms/{room_id}/members/me/profile",
            put(routes::room_profiles::put_own).delete(routes::room_profiles::delete_own).layer(small()),
        )
        .route(
            "/rooms/{room_id}/members/me/avatar",
            put(routes::room_profiles::put_avatar)
                .delete(routes::room_profiles::delete_avatar)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/rooms/{room_id}/members/{user_id}/profile",
            axum::routing::patch(routes::room_profiles::moderate).layer(small()),
        )
        .route("/rooms/{room_id}/bans", get(routes::rooms::list_bans).post(routes::rooms::ban))
        .route("/rooms/{room_id}/bans/{subject}", axum::routing::delete(routes::rooms::unban))
        .route("/rooms/{room_id}/invites", get(routes::rooms::list_invites).post(routes::rooms::create_invite))
        .route("/rooms/{room_id}/invites/{code}", axum::routing::delete(routes::rooms::delete_invite))
        .route("/rooms/{room_id}/audit-log", get(routes::rooms::audit_log))
        .route("/rooms/{room_id}/moderation/purge", post(routes::rooms::purge))
        .route("/rooms/{room_id}/categories", post(routes::channels::create_category))
        .route(
            "/rooms/{room_id}/categories/{category_id}",
            axum::routing::patch(routes::channels::update_category).delete(routes::channels::delete_category),
        )
        .route("/rooms/{room_id}/channels", post(routes::channels::create_channel))
        .route(
            "/rooms/{room_id}/channels/{channel_id}",
            axum::routing::patch(routes::channels::update_channel).delete(routes::channels::delete_channel),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/messages",
            get(routes::messages::list_messages).post(routes::messages::create_message),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/messages/{message_id}",
            axum::routing::patch(routes::messages::edit_message).delete(routes::messages::delete_message),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
            put(routes::attachments::add_reaction).delete(routes::attachments::remove_reaction),
        )
        .route("/rooms/{room_id}/channels/{channel_id}/pins", get(routes::attachments::list_pins))
        .route(
            "/rooms/{room_id}/channels/{channel_id}/pins/{message_id}",
            put(routes::attachments::pin).delete(routes::attachments::unpin),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/uploads",
            post(routes::attachments::upload).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/blobs/{blob_id}", get(routes::attachments::download))
        .route(
            "/rooms/{room_id}/emojis",
            get(routes::emojis::list).post(routes::emojis::create).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/rooms/{room_id}/emojis/{emoji_id}", axum::routing::delete(routes::emojis::delete))
        .route("/rooms/{room_id}/emojis/{emoji_id}/image", get(routes::emojis::image))
        // Personal emojis and clips, public emoji and clip bytes.
        .route("/emojis/{emoji_id}/image", get(routes::emojis::public_image))
        .route("/sounds/{sound_id}/audio", get(routes::voice::public_sound_audio))
        .route("/admin/media-cache/{host}/{origin_id}", axum::routing::delete(routes::emojis::purge_cache))
        .route(
            "/users/me/emojis",
            get(routes::emojis::list_personal)
                .post(routes::emojis::create_personal)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route(
            "/users/me/emojis/{emoji_id}",
            axum::routing::patch(routes::emojis::rename_personal)
                .delete(routes::emojis::delete_personal)
                .layer(small()),
        )
        .route(
            "/users/me/sounds",
            get(routes::voice::list_personal_sounds)
                .post(routes::voice::create_personal_sound)
                .layer(axum::extract::DefaultBodyLimit::max(routes::voice::SOUNDBOARD_MAX_BYTES + 1024)),
        )
        .route(
            "/users/me/sounds/{sound_id}",
            axum::routing::patch(routes::voice::update_personal_sound)
                .delete(routes::voice::delete_personal_sound)
                .layer(small()),
        )
        .route("/rooms/{room_id}/channels/{channel_id}/soundboard/play", post(routes::voice::play_sound).layer(small()))
        .route("/gifs", get(routes::emojis::gifs))
        .route("/unfurl", get(routes::unfurl::unfurl))
        .route("/rooms/{room_id}/overrides", put(routes::channels::set_override))
        .route("/rooms/{room_id}/roles", post(routes::roles::create_role))
        .route(
            "/rooms/{room_id}/roles/{role_id}",
            axum::routing::patch(routes::roles::update_role).delete(routes::roles::delete_role),
        )
        .route("/invites/{code}", get(routes::rooms::get_invite))
        .route("/invites/{code}/join", post(routes::rooms::join_by_invite))
        .route("/users/{username}/avatar", get(routes::federation::avatar))
        .route("/auth/federated", post(routes::federation::federated_login).layer(small()))
        .route("/federation/token", post(routes::federation::issue_token).layer(small()))
        .route("/federation/peer/{domain}", get(routes::connect::peer_document))
        .route("/federation/resolve/{domain}", get(routes::peer_resolve::resolve_peer))
        .route("/auth/connect/code", post(routes::connect::connect_code).layer(small()))
        .route("/auth/connect/token", post(routes::connect::connect_token).layer(small()))
        .route("/auth/connect/session", post(routes::connect::create_session).layer(small()))
        .route("/auth/connect/session/{session_id}", get(routes::connect::poll_session))
        // The handler reads the body itself with the 512 KiB cap of §4 (`index.too_large`).
        .route(
            "/users/me/conversations-index",
            get(routes::conversations_index::get_index).put(routes::conversations_index::put_index),
        )
        // The inbox reads its body itself with a hard 64 KiB cap (`federation.payload_too_large`).
        .route("/federation/inbox", post(routes::federation::inbox))
        // Reads its body itself with a hard cap (`federation.payload_too_large`).
        .route("/federation/key-packages/claim", post(routes::federation::claim))
        .route("/users/me/invites", get(routes::invites::list))
        .route("/users/me/invites/{invite_id}", axum::routing::delete(routes::invites::dismiss))
        .route("/rooms/{room_id}/invites/direct", post(routes::rooms::direct_invite).layer(small()))
        // Conformance (FEDERATION.md §9): the probe's throwaway rooms, peer state, admin view and actions.
        .route("/federation/conformance/room", post(routes::conformance::create_room))
        .route("/federation/conformance/room/{room_id}", axum::routing::delete(routes::conformance::delete_room))
        .route("/federation/peers/{domain}/state", get(routes::conformance::peer_state))
        .route("/admin/federation/peers", get(routes::conformance::list_peers))
        .route("/admin/federation/peers/{domain}/check", post(routes::conformance::check_peer))
        .route("/admin/federation/peers/{domain}/block", post(routes::conformance::block_peer).layer(small()))
        .route("/admin/federation/peers/{domain}/unblock", post(routes::conformance::unblock_peer))
        // Voice (protocol/VOICE.md).
        .route("/rooms/{room_id}/voice", get(routes::voice::room_states))
        .route("/rooms/{room_id}/channels/{channel_id}/voice/join", post(routes::voice::join))
        .route("/rooms/{room_id}/channels/{channel_id}/voice/leave", post(routes::voice::leave))
        .route(
            "/rooms/{room_id}/channels/{channel_id}/voice/state",
            axum::routing::patch(routes::voice::update_state).layer(small()),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/mute",
            post(routes::voice::mute_member).layer(small()),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/disconnect",
            post(routes::voice::disconnect_member),
        )
        .route(
            "/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/move",
            post(routes::voice::move_member).layer(small()),
        )
        .route("/rooms/{room_id}/voice/move-all", post(routes::voice::move_all).layer(small()))
        .route("/voice/test", post(routes::voice::connection_test))
        // Calls in DMs and group DMs (VOICE.md §11).
        .route("/conversations/{conversation_id}/call", get(routes::calls::get_call))
        .route("/conversations/{conversation_id}/call/start", post(routes::calls::start))
        .route("/conversations/{conversation_id}/call/join", post(routes::calls::join))
        .route("/conversations/{conversation_id}/call/leave", post(routes::calls::leave))
        .route("/conversations/{conversation_id}/call/decline", post(routes::calls::decline))
        .route(
            "/conversations/{conversation_id}/call/state",
            axum::routing::patch(routes::calls::update_state).layer(small()),
        )
        .route(
            "/voice/webhook",
            post(routes::voice::webhook).layer(axum::extract::DefaultBodyLimit::max(routes::voice::WEBHOOK_BODY_LIMIT)),
        )
        .route(
            "/rooms/{room_id}/soundboard",
            get(routes::voice::list_sounds)
                .post(routes::voice::create_sound)
                .layer(axum::extract::DefaultBodyLimit::max(routes::voice::SOUNDBOARD_MAX_BYTES + 1024)),
        )
        .route(
            "/rooms/{room_id}/soundboard/{sound_id}",
            axum::routing::delete(routes::voice::delete_sound).patch(routes::voice::update_sound).layer(small()),
        )
        .route("/rooms/{room_id}/soundboard/{sound_id}/audio", get(routes::voice::sound_audio));
    // Test hooks of development nodes (never on a production node).
    let api = if state.config.dev {
        api.route("/dev/expire-access-tokens", post(routes::auth::dev_expire_access_tokens))
            .route("/dev/forget-retired-device", post(routes::auth::dev_forget_retired_device))
            .route("/dev/notify-expiring-tokens", post(routes::applications::dev_notify_expiring_tokens))
    } else {
        api
    };

    Router::new()
        .route("/healthz", get(routes::health::healthz))
        .route("/readyz", get(routes::health::readyz))
        .route("/metrics", get(crate::metrics::endpoint))
        .route("/.well-known/tavrn", get(routes::wellknown::get_well_known))
        // LiveKit signaling (token-checked proxy to 127.0.0.1, routes/rtc.rs).
        .route("/rtc", get(routes::rtc::proxy))
        .route("/rtc/{*rest}", get(routes::rtc::proxy))
        .nest(
            "/api/v1",
            api.merge(routes::oidc::routes())
                .merge(routes::entitlements::routes())
                .merge(routes::files::routes())
                .merge(routes::webhooks::routes())
                .merge(routes::subscriptions::routes())
                .merge(routes::installations::routes())
                .merge(routes::search::routes())
                .merge(routes::threads::routes())
                .merge(routes::commands::routes())
                .merge(routes::legal::routes())
                .merge(routes::push::routes())
                .merge(routes::moderation::routes())
                .merge(routes::age::routes()),
        )
        // Legal pages as standalone HTML; other `/legal/…` paths are the web client's.
        .merge(routes::legal::page_routes())
        .fallback(crate::webapp::handler)
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        // Problem Details name the request id (`request_id`), from the header set below.
        .layer(axum::middleware::from_fn(crate::error::request_scope))
        // Request spans carry the route, the request id and the path with webhook secrets redacted (APPLICATIONS.md
        // §9.4), never the query: every log line of a request (an internal error too) can be matched to its report.
        .layer(TraceLayer::new_for_http().make_span_with(crate::webhooks::RedactedSpan))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)))
        // Files channel uploads stream large files: outside the 30-second limit.
        .route(
            routes::files::UPLOAD_PATH,
            routes::files::upload_route()
                .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, routes::files::UPLOAD_TIMEOUT)),
        )
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        // Camera, microphone and screen capture only for the node's own pages (voice, video, screen sharing);
        // every other powerful feature off.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            axum::http::HeaderValue::from_static(PERMISSIONS_POLICY),
        ))
        .layer(cors())
        // Several instances: voice, call and whiteboard requests go to the leader (`cache::relay`).
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::cache::relay::middleware))
        // Request counts and latency by route template (`metrics.rs`); a no-op while `TAVRN_METRICS` is off.
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::metrics::track))
        .with_state(state)
}
