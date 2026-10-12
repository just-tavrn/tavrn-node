// SPDX-License-Identifier: AGPL-3.0-only
//! Configuration of the node.
//!
//! Order of sources (later ones override earlier ones):
//! 1. built-in defaults, 2. `TAVRN_CONFIG` (TOML file, optional), 3. environment variables `TAVRN_*`.
//!
//! After loading, **everything** is validated. Every error is collected and printed together,
//! so operators do not have to restart ten times to find ten errors.

use std::fmt;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    Open,
    Invite,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailMode {
    None,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomCreation {
    None,
    Invite,
    Local,
    Federated,
}

/// Who may create applications (`TAVRN_APP_CREATION`, APPLICATIONS.md §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppCreation {
    /// Every local user with a full session.
    All,
    /// Users with an application grant (`PATCH /admin/users/{id} { app_creation_grant }`).
    Invite,
    /// Node admins only.
    Admins,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptchaProvider {
    None,
    Turnstile,
}

/// Encryption at rest of the blob storage (`TAVRN_STORAGE_ENCRYPTION`): `on` (default) or
/// `off` (new files are written unencrypted, encrypted files stay readable; for debugging only).
/// A plain on/off switch (`on`/`off`, also `true`/`false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Switch {
    #[serde(alias = "true")]
    On,
    #[serde(alias = "false")]
    Off,
}

impl Switch {
    pub fn on(self) -> bool {
        self == Self::On
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageEncryption {
    On,
    Off,
}

impl StorageEncryption {
    pub fn enabled(self) -> bool {
        self == Self::On
    }
}

/// What a new version of the terms of service means for existing users (`TAVRN_LEGAL_TERMS_MODE`):
/// `notice` shows the acceptance dialog once after sign-in, `require` refuses the API (`403 legal.terms_required`)
/// until the user accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TermsMode {
    Notice,
    Require,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GifProvider {
    None,
    Giphy,
    Tenor,
}

/// Who may start a direct message: the node's upper bound (`TAVRN_DM_POLICY`) and every user's own
/// setting ("Who can message me"). Ordered from strict to open; the effective policy of a
/// user is the stricter of the two. Non-friends land in the recipient's message requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmPolicy {
    /// Only friends; the owner of a bot may always message it.
    Friends,
    /// Friends and people who share a room with the recipient.
    EveryoneShared,
    /// Anyone of any federated node (blocks still apply). `open` is the former name.
    #[serde(alias = "open")]
    Everyone,
}

impl DmPolicy {
    pub const ALL: [&'static str; 3] = ["friends", "everyone_shared", "everyone"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Friends => "friends",
            Self::EveryoneShared => "everyone_shared",
            Self::Everyone => "everyone",
        }
    }

    /// The stored user setting (unknown values count as the default).
    pub fn parse(s: &str) -> Self {
        match s {
            "friends" => Self::Friends,
            "everyone" | "open" => Self::Everyone,
            _ => Self::EveryoneShared,
        }
    }
}

/// `TAVRN_OIDC_GROUP_SYNC` (protocol/APPLICATIONS.md §8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OidcGroupSync {
    /// Grant what the groups map to, never revoke.
    Add,
    /// Also revoke what an earlier sync granted once the group is gone (manual grants stay).
    Sync,
}

/// `TAVRN_MEDIA_FFMPEG`: where the media pipeline finds ffmpeg (src/media.rs).
pub const MEDIA_FFMPEG_AUTO: &str = "auto";
pub const MEDIA_FFMPEG_OFF: &str = "off";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Development mode (not from the file/env, but from the CLI flag).
    #[serde(default)]
    pub dev: bool,

    /// Public domain of the node; also its identity in the collective.
    pub domain: String,
    /// Display name of the node.
    pub name: String,
    pub description: String,
    /// Address the server speaks HTTP on. TLS is always handled by the reverse proxy in front of it.
    pub listen: String,
    /// Proxies (IPs or CIDR, comma-separated) whose `X-Forwarded-For` is trusted.
    /// Default: private networks and localhost, suitable for Docker networks.
    pub trusted_proxies: String,

    /// `TAVRN_PUBLIC_URL`: base URL of the host that serves this node, e.g.
    /// `https://app.tavrn.org` for the identity domain `tavrn.org`. Default `https://<domain>` (in dev mode
    /// `http://<domain>:<listen port>`). Everything that builds absolute URLs uses it; identity, addresses,
    /// token issuers and key ids keep `domain`.
    pub public_url: Option<String>,
    /// Origin of the web client for WebAuthn (default: the public URL). Override only when the web client
    /// runs elsewhere (development and tests, e.g. `http://localhost:5173`).
    pub webauthn_origin: Option<String>,
    /// `TAVRN_WEBAUTHN_RP_ID`: relying party id of passkeys (default: the identity domain). Must be the host
    /// of the WebAuthn origin or a parent domain of it, so passkeys survive a move of the app host.
    pub webauthn_rp_id: Option<String>,
    /// `TAVRN_WEBAUTHN_APP_ORIGINS`: WebAuthn origins of the node's own apps besides the web origin (comma-separated,
    /// each `android:apk-key-hash:<base64url SHA-256 of the signing certificate>`), PROTOCOL.md §5a.4. Accepted for
    /// registrations and assertions and published as `webauthn.origins`. Empty: only the web origin.
    pub webauthn_app_origins: String,

    /// `postgres://…`; in development mode also `sqlite://…`.
    pub database_url: String,
    /// `TAVRN_CACHE_URL`: optional Valkey/Redis (`redis://[user:pw@]host:port[/db]`, `rediss://` for TLS) shared by
    /// several instances of this node (docs/SCALING.md). Unset: one instance, everything in memory. The password
    /// is never printed by `check-config`.
    #[serde(serialize_with = "redact_url_password")]
    pub cache_url: Option<String>,
    /// `TAVRN_INSTANCE_ID`: name of this instance among several (`[A-Za-z0-9._-]`, ≤ 64); default random per start.
    pub instance_id: Option<String>,
    /// `TAVRN_INSTANCE_URL`: where the other instances reach this one (`http://10.0.0.5:8080`, relayed voice and
    /// whiteboard requests); default the address of the interface towards the cache with the listen port.
    pub instance_url: Option<String>,
    /// Directory for blobs, keys, certificates.
    pub data_dir: String,

    pub registration: Registration,
    pub email: EmailMode,
    /// `smtp://host:port` (unencrypted, e.g. an internal relay), `smtps://host:port` (TLS),
    /// `smtp+starttls://host:port`; optionally `user:pass@`.
    pub smtp_url: Option<String>,
    /// Sender address; default `noreply@<domain>`.
    pub smtp_from: Option<String>,
    /// Operator overrides of the mail templates, `<dir>/<language>/<name>.txt` (`mail_templates.rs`); default
    /// `<TAVRN_DATA_DIR>/templates/mail`.
    pub mail_templates_dir: Option<String>,
    /// Optional captcha: `none` or `turnstile` (Cloudflare).
    pub captcha_provider: CaptchaProvider,
    pub turnstile_site_key: Option<String>,
    pub turnstile_secret_key: Option<String>,
    /// Require the captcha at registration (only with a provider).
    pub captcha_register: bool,
    /// Require the captcha at login (only with a provider).
    pub captcha_login: bool,
    pub room_creation: RoomCreation,
    pub max_rooms_per_user: u32,
    /// Upper bound of the users' direct-message settings: `friends`, `everyone_shared` or
    /// `everyone` (default; `open` is accepted as an alias). Users choose within it (default `everyone_shared`).
    pub dm_policy: DmPolicy,
    /// Media pipeline (avatars, headers, room icons, voice backgrounds): `auto` (ffmpeg from `PATH`, off if
    /// missing), `off` (static PNG/JPEG only, animated and video input refused) or a path to ffmpeg.
    pub media_ffmpeg: String,
    /// Concurrent ffmpeg jobs (1–8); further uploads wait in a short queue.
    pub media_workers: u32,
    /// Scenes per user in the whiteboard library (`/users/me/whiteboards`), 1–1000.
    pub whiteboard_max_scenes: u32,

    pub uploads_enabled: bool,
    pub upload_max_bytes: u64,
    /// Comma-separated, wildcards like `image/*` allowed.
    pub upload_allowed_types: String,
    /// Executables, scripts, installers and disk images (protocol/PROTOCOL.md §7a) may be attached by
    /// members whose upload categories include `other`. Off by default: they are always refused.
    pub upload_allow_executables: bool,
    /// Upload categories in DMs and group DMs hosted here (comma list of `images`, `audio`, `video`,
    /// `documents`, `archives`, `other`; default all).
    pub upload_dm_categories: String,
    pub storage_quota_per_room_bytes: u64,
    /// Encryption at rest of stored files: `on` (default) or `off` (debugging only).
    pub storage_encryption: StorageEncryption,
    /// Images up to this size (bytes) load as previews automatically where the user's setting allows it;
    /// larger ones show a placeholder with a "load" button. 0 = never automatically.
    pub preview_auto_max_bytes: u64,
    /// Sender-generated link previews (`GET /api/v1/unfurl`): `on` (default) or `off`.
    pub unfurl: crate::unfurl::UnfurlSetting,
    /// Message retention (PROTOCOL.md §7f): messages are deleted this many days after they were sent by the hourly
    /// housekeeping (`0` = keep forever, at most 36500); rooms may only shorten it. Pinned messages and the welcome
    /// channel are exempt.
    pub retention_days: u32,
    /// Custom emojis per room: maximum count and maximum file size.
    pub emoji_max_per_room: u32,
    pub emoji_max_bytes: u64,

    // ---- Entitlement defaults (protocol/ENTITLEMENTS.md). `0` = unlimited unless noted.
    /// Largest upload size an entitlement grant can raise `upload.max_bytes` to (and the body limit of the
    /// upload routes). `0` = `TAVRN_UPLOAD_MAX_BYTES` (grants cannot raise the upload size).
    pub upload_max_bytes_ceiling: u64,
    /// `voice.max_participants`: participants per voice channel (`0` = only `TAVRN_VOICE_MAX_PARTICIPANTS`).
    pub voice_channel_max_participants: u32,
    /// `stream.max_height`: screen share height cap in pixels (`0` = `TAVRN_SCREENSHARE_MAX_RESOLUTION` only).
    pub stream_max_height: u32,
    /// `stream.max_fps`: screen share frame rate cap (`0` = `TAVRN_SCREENSHARE_MAX_FPS` only).
    pub stream_max_fps: u32,
    /// `camera.max_height`: camera height cap in pixels (`0` = `TAVRN_CAMERA_MAX_RESOLUTION` only).
    pub camera_max_height: u32,
    /// `emoji.max_personal`: personal emojis per user.
    pub emoji_max_personal: u32,
    /// `sounds.max_per_room`: soundboard clips per room.
    pub sounds_max_per_room: u32,
    /// `sounds.max_personal`: personal soundboard clips per user.
    pub sounds_max_personal: u32,
    /// `attachments.retention_days`: attachments of channels and DMs are deleted after this many days
    /// (`0` = keep forever); rooms may only shorten it.
    pub attachment_retention_days: u32,
    /// `files_channels.enabled`: files channels may be created (`on`/`off`).
    pub files_channels: Switch,
    /// `files_channels.max_bytes`: storage per files channel.
    pub files_channels_max_bytes: u64,
    /// Cached copies of other nodes' emojis and clips are evicted after this many days without use;
    /// 0 = never.
    pub media_cache_unused_days: u32,
    /// Total size of the cached copies of other nodes' emojis and clips; the least recently used go first.
    pub media_cache_max_bytes: u64,
    /// Size of the cached copies from one origin node; its least recently used copies go first.
    pub media_cache_max_bytes_per_host: u64,
    /// Files channels may use external WebDAV/S3 stores (`TAVRN_FILES_EXTERNAL`, default off, FILES.md §5).
    pub files_external: Switch,
    /// External stores may be on private, loopback or link-local addresses and use plain http
    /// (`TAVRN_FILES_EXTERNAL_PRIVATE`, default off: SSRF protection).
    pub files_external_private: Switch,
    /// GIF search: `none`, `giphy` or `tenor`; the key stays on the node.
    pub gif_provider: GifProvider,
    pub gif_api_key: Option<String>,

    pub voice_enabled: bool,
    /// Audio bitrate cap of every voice channel (8–512 kbps). The default 192 makes every client preset up to
    /// "Music" (stereo Opus, VOICE.md §4a) reachable; new channels still start at
    /// [`DEFAULT_CHANNEL_BITRATE_KBPS`].
    pub voice_max_bitrate_kbps: u32,
    pub screenshare_enabled: bool,
    pub screenshare_max_resolution: String,
    pub screenshare_max_fps: u32,
    /// Webcam sharing (the `use_camera` permission still applies).
    pub camera_enabled: bool,
    /// `360p`, `720p` or `1080p`.
    pub camera_max_resolution: String,
    pub camera_max_fps: u32,
    /// Participants per voice channel at most (LiveKit `room.max_participants`); channel user limits apply below it.
    pub voice_max_participants: u32,
    /// A participant whose connection drops stays in the channel as "reconnecting" this long (0–600 s; 0 removes
    /// it at once).
    pub voice_reconnect_grace_secs: u64,
    /// `from-to`, UDP ports for media.
    pub rtc_udp_port_range: String,
    /// Public IP address LiveKit announces to clients, or a hostname (dynamic DNS) resolved at start and
    /// every minute (all A and AAAA addresses). Empty (and no `rtc_advertise_ips`): detected via STUN, IPv4
    /// and IPv6 (production) or taken from the local interfaces (`--dev`).
    pub rtc_external_ip: Option<String>,
    /// More addresses the media server is reachable at, comma-separated (the host's global IPv6, the LAN
    /// address for clients in the same network when the router has no NAT loopback). Together with
    /// `rtc_external_ip`: the first IPv4 and the first IPv6 become LiveKit's `node_ip`, every further address
    /// is handed to the clients, which add it as an extra ICE candidate (VOICE.md §10.2). Entries may be
    /// hostnames (dynamic DNS): resolved at start and periodically, LiveKit restarts when the set changes.
    pub rtc_advertise_ips: String,
    /// Addresses of hostnames in `rtc_external_ip`/`rtc_advertise_ips` may be private (LAN, ULA). Off: only
    /// public addresses of a hostname are announced (IP literals are taken as configured; `--dev` allows all).
    pub rtc_advertise_private: bool,
    /// STUN servers (`host:port`, comma-separated) for the address detection; empty = LiveKit's defaults.
    pub rtc_stun_servers: String,
    /// ICE over TCP (fallback when UDP is blocked); must be published and forwarded like the UDP range.
    /// 0 = off. Default 7881 (`--dev`: 0, several development nodes share a machine).
    pub rtc_tcp_port: u16,
    /// LiveKit's embedded TURN server (relays media for clients behind strict NATs or firewalls).
    pub rtc_turn_enabled: bool,
    /// Domain of TURN over TLS (`turns:<domain>:443`, TLS terminated by the reverse proxy). Default
    /// `turn.<host of TAVRN_PUBLIC_URL>` (`turn.<TAVRN_DOMAIN>` when that host is an IP address).
    pub rtc_turn_domain: Option<String>,
    /// TURN over UDP (published like the media ports); 0 = off.
    pub rtc_turn_udp_port: u16,
    /// Plain TCP port behind the proxy's TLS termination for TURN/TLS; 0 = off.
    pub rtc_turn_tls_port: u16,
    /// Local relay ports of the TURN server (`from-to`; reached only from inside the container, not published).
    pub rtc_turn_relay_port_range: String,
    /// Path or name (looked up in `PATH`) of the `livekit-server` binary started as a child process.
    pub livekit_binary: String,
    /// Local TCP port of LiveKit's signaling and API (bound to 127.0.0.1 only, reached through `/rtc`).
    pub livekit_port: u16,

    pub federation_enabled: bool,
    /// Comma-separated domains of the reference nodes this node announces itself to and pulls peer lists
    /// from (FEDERATION.md §7.2). Empty in development mode.
    pub reference_nodes: String,
    /// Announce this node to the reference nodes and allow other nodes to list it (§7.2).
    pub directory_listing: bool,
    /// Cached rooms of other nodes for the Discover page, in total (§7.3).
    pub directory_max_rooms: u32,
    /// Comma-separated domains that are never federated with.
    pub federation_blocklist: String,
    /// Comma-separated domains; if set, federate only with these (the blocklist still wins).
    pub federation_allowlist: String,
    /// Allow peers on private/loopback addresses (development, tests, closed intranets).
    pub federation_allow_private: bool,
    /// `--dev` only: `domain=http://host:port` mapping for local multi-node setups and tests.
    pub federation_dev_peers: String,
    /// When a peer's identity domain serves no `/.well-known/tavrn` (404, or no HTTPS server at all), look up
    /// `_tavrn._tcp.<domain>` SRV and fetch the document from its target (FEDERATION.md §1.4); also used by
    /// `GET /federation/resolve/{domain}` for clients.
    pub federation_srv_fallback: bool,
    /// Accept bots of other nodes (APPLICATIONS.md §2.8; whether this node's own bots may federate is
    /// `apps_federate`).
    pub federation_remote_bots: bool,
    /// API requests per user and minute (every authenticated route; `0` = off, the default in development mode).
    pub rate_user_per_minute: u32,
    /// Argon2 password hashes and checks running at once (`0` = twice the CPU cores, at least 2).
    pub password_hash_concurrency: u32,
    /// IPv6 client addresses share their per-address rate limits by this prefix length (32–128; 64 = one /64).
    pub rate_limit_ipv6_prefix: u8,
    /// WebSocket connections one user may hold at once (`0` = unlimited).
    pub ws_max_sockets_per_user: u32,
    /// Federated logins per remote domain and minute.
    pub federation_rate_logins: u32,
    /// Inbox messages per remote domain and minute.
    pub federation_rate_inbox: u32,
    /// API requests of all users of one remote domain per minute (FEDERATION.md §3.2).
    pub federation_rate_api: u32,
    /// KeyPackage claims per requesting node and minute (served by this node as home node, §3.5).
    pub federation_rate_claims: u32,
    /// Remote users in total.
    pub federation_max_remote_users: u32,
    /// Remote users per home domain.
    pub federation_max_remote_users_per_domain: u32,
    /// Seconds a request to a peer waits for a free connection slot (per peer, then node-wide) before it fails
    /// (1–120, default 10; FEDERATION.md §1.3): one slow peer cannot hold up requests to every other.
    pub federation_permit_timeout_secs: u32,
    /// Peers this node learned of only through signed requests whose signature it could not check yet (no
    /// verified request from them so far): at most this many cached documents (10–1000000, default 1000); unused
    /// rows are pruned after 30 days.
    pub federation_max_unverified_peers: u32,
    /// Discovery fetches at the same time for issuers of requests whose signature cannot be checked yet and for
    /// which this node has no cached document (1–64, default 12): beyond it such requests are refused at once
    /// (`503 federation.busy`), so unsigned requests naming many slow domains keep most connection slots free.
    pub federation_discovery_slots: u32,
    /// Refuse federated logins and inbox messages of peers whose latest conformance result is neither
    /// `pass` nor `warn`, including peers not checked yet (FEDERATION.md §9.4).
    pub federation_require_conformance: bool,
    /// Remote users without a federated login for this many days, and with nothing that still ties them
    /// to this node (memberships, friendships, messages, …), are deleted by the housekeeping job
    /// (FEDERATION.md §2.6). `0` keeps them forever.
    pub federation_remote_user_retention_days: u32,
    /// Send `ban.notify` (FEDERATION.md §5.2, information only) to the home node of a remote user who is
    /// removed from a room by a room or node ban.
    pub federation_notify_bans: bool,
    /// `--dev` only: comma-separated misbehaviors for conformance tests of a deliberately broken node
    /// (`accept_bad_signatures`, `replay_ok`, `plaintext_ok`, `no_rate_limit`). Refused without `--dev`.
    pub dev_misbehave: String,

    /// Auto-moderation: more than this many messages of a user per channel within 5 seconds count as spam (0 = off).
    pub automod_burst_limit: u32,
    /// Timeout in minutes after a spam burst.
    pub automod_timeout_minutes: u32,
    /// The operator's word list for every unencrypted conversation (one term per line, protocol MODERATION.md §2.3).
    pub automod_words_file: Option<String>,
    /// `off` (default) or the path of a domain blocklist for every unencrypted conversation (one domain per line).
    pub automod_links: String,
    /// Reports a user may send per hour (1–1000, default 10, MODERATION.md §1.3).
    pub reports_rate_per_hour: u32,
    /// Days resolved and dismissed reports are kept (1–36500, default 90, MODERATION.md §1.5).
    pub reports_retention_days: u32,

    // ---- Single sign-on via OpenID Connect (protocol/APPLICATIONS.md §8)
    /// Issuer URL of the OpenID provider; SSO is enabled when set. Discovery at
    /// `<issuer>/.well-known/openid-configuration`; `https://` only (`http://` with `--dev`).
    pub oidc_issuer: Option<String>,
    /// Client id registered at the provider (required with an issuer).
    pub oidc_client_id: Option<String>,
    /// Client secret of a confidential client. Never printed by `check-config`.
    #[serde(skip_serializing)]
    pub oidc_client_secret: Option<String>,
    /// File holding the client secret (keeps it out of the environment).
    pub oidc_client_secret_file: Option<String>,
    /// Requested scopes (space or comma separated), must contain `openid`.
    pub oidc_scopes: String,
    /// Claim the username of a new account comes from.
    pub oidc_username_claim: String,
    /// Claim the display name comes from (updated on every login).
    pub oidc_display_name_claim: String,
    /// Claim holding the groups (array of strings), from the ID token or UserInfo.
    pub oidc_groups_claim: String,
    /// Text of the login button; empty = the client's translation of "Sign in with SSO".
    pub oidc_button_label: Option<String>,
    /// Disable password, registration and passkey-only logins (except for `TAVRN_ADMIN_USERS`).
    pub oidc_only: bool,
    /// Create accounts on the first SSO login.
    pub oidc_auto_provision: bool,
    /// Group → rights map (JSON, §8.5); when set, the admin API cannot change it.
    pub oidc_group_map: Option<String>,
    /// `add`: grant only; `sync`: also revoke what an earlier sync granted.
    pub oidc_group_sync: OidcGroupSync,
    /// Hard end of an SSO session in days (1–30).
    pub oidc_session_days: u32,
    /// Lifetime of an access token in minutes (5–1440, default 60).
    pub session_access_minutes: u32,
    /// Sliding lifetime of a refresh token in days (1–3650, default 90): every refresh extends it; SSO sessions keep
    /// `TAVRN_OIDC_SESSION_DAYS` as their hard end, federated sessions their 7 days.
    pub session_refresh_days: u32,
    /// Devices not seen for this many days are deleted by housekeeping (never the only device of a user, never one
    /// with a live session); `0` = never (default 180).
    pub device_stale_days: u32,
    /// KeyPackage claims per target user and hour from one source (this node, or one other node) by requesters who
    /// share no room, DM or friendship with the target (1–10000, default 60; ten times that per target over all
    /// sources; ENCRYPTION.md §3.2): nobody drains a user's KeyPackages or locks out their contacts.
    pub e2ee_claims_per_target_per_hour: u32,
    /// Who may create applications (bots), APPLICATIONS.md §1.2.
    pub app_creation: AppCreation,
    /// Applications per owner (0–100); node admins are not exempt.
    pub apps_per_user: u32,
    /// Installed applications per room (0–1000), APPLICATIONS.md §4.2.
    pub apps_per_room: u32,
    /// Maximum lifetime of an app token in days (1–3650).
    pub app_token_max_days: u32,
    /// API requests (REST and WebSocket operations) per application and minute.
    pub app_rate_requests: u32,
    /// This node's bots may obtain federation tokens for other nodes (APPLICATIONS.md §2.8).
    pub apps_federate: bool,
    /// Application URLs (interactions URL, event subscriptions) may point at private and loopback addresses
    /// (APPLICATIONS.md §6.3). Default `false`, `true` in development mode; development nodes also accept
    /// `http://` application URLs.
    pub app_allow_private_urls: bool,
    /// Node admins approve every command definition before it is offered in this node's rooms
    /// (APPLICATIONS.md §5.2); a changed definition is pending again.
    pub app_commands_require_approval: bool,
    /// Incoming webhooks (APPLICATIONS.md §6.1); `false` refuses creation and execution (`webhook.disabled`).
    pub webhooks_enabled: bool,
    /// Webhooks per channel (1–50; a room has at most 50).
    pub webhooks_per_channel: u32,
    /// Node-side message search over unencrypted channels; `false` removes the
    /// route (`404 search.disabled`) and stops indexing.
    pub search_enabled: bool,
    /// Search requests per user and minute (1–10000); search is expensive.
    pub search_rate_per_minute: u32,
    /// The public takedown form `POST /legal/notices` (protocol/LEGAL.md); off by default.
    /// Cases forwarded by other nodes (S2S `legal.notice`) are opened either way.
    pub legal_notices: Switch,
    /// Notices accepted per client IP and hour (1–1000, default 5).
    pub legal_notice_rate_per_hour: u32,
    /// Days a closed case is kept after its last activity (30–36500, default 1095 = 3 years).
    pub legal_notice_retention_days: u32,
    /// Notices forwarded by other nodes (S2S `legal.notice`) accepted per sending domain and hour (1–1000, default
    /// 10); all domains together get five times as many.
    pub legal_notice_inbound_per_hour: u32,
    /// Actioned notices against one user after which the admin page suggests disabling the account (1–100, default
    /// 3); a suggestion only, never automatic.
    pub legal_repeat_threshold: u32,
    /// Days the uploader may answer an actioned notice with a counter-notice (1–365, default 14).
    pub legal_counter_notice_days: u32,
    /// `notice` (default) or `require`, see [`TermsMode`].
    pub legal_terms_mode: TermsMode,
    /// Days a deleted account stays a tombstone with its username reserved, so a node admin can undo the deletion
    /// (1–365, default 30). After that the account row is erased and the username is free again.
    pub account_delete_grace_days: u32,

    /// `TAVRN_PUSH`: web push notifications to browsers and installed web apps (PROTOCOL.md §6d, capability
    /// `push.webpush`); on by default. The VAPID key is `<data_dir>/keys/vapid.key`.
    pub push: Switch,
    /// `TAVRN_PUSH_CONTACT`: the VAPID `sub` push services may use to reach the operator (`mailto:` or `https:`);
    /// default: the public URL.
    pub push_contact: Option<String>,
    /// `TAVRN_PUSH_MAX_PER_MINUTE`: pushes per user and minute (1–1000, default 10); in addition at most one per
    /// conversation and user every 30 seconds.
    pub push_max_per_minute: u32,
    /// `TAVRN_METRICS`: `GET /metrics` in the Prometheus text format; off by default.
    pub metrics: Switch,
    /// `TAVRN_METRICS_TOKEN`: bearer token scrapers must send (at least 16 characters). Empty: `/metrics` answers
    /// only to loopback and `TAVRN_TRUSTED_PROXIES` clients. Never printed by `check-config`.
    #[serde(skip_serializing)]
    pub metrics_token: Option<String>,

    /// Comma-separated usernames with node admin permissions.
    pub admin_users: String,
    pub log_level: String,
    pub log_format: LogFormat,
    /// Minimum age for registration (13–99, default 16; PROTOCOL.md §5e): every registration path refuses younger
    /// people with `age.below_minimum`.
    pub minimum_age: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dev: false,
            domain: String::new(),
            name: "tavrn".into(),
            description: String::new(),
            listen: "0.0.0.0:8080".into(),
            trusted_proxies: "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7".into(),
            public_url: None,
            webauthn_origin: None,
            webauthn_rp_id: None,
            webauthn_app_origins: String::new(),
            database_url: String::new(),
            cache_url: None,
            instance_id: None,
            instance_url: None,
            data_dir: "/data".into(),
            registration: Registration::Invite,
            email: EmailMode::Optional,
            smtp_url: None,
            smtp_from: None,
            mail_templates_dir: None,
            captcha_provider: CaptchaProvider::None,
            turnstile_site_key: None,
            turnstile_secret_key: None,
            captcha_register: true,
            captcha_login: false,
            room_creation: RoomCreation::Invite,
            max_rooms_per_user: 5,
            dm_policy: DmPolicy::Everyone,
            media_ffmpeg: MEDIA_FFMPEG_AUTO.into(),
            media_workers: 1,
            whiteboard_max_scenes: 50,
            uploads_enabled: true,
            upload_max_bytes: 25 * 1024 * 1024,
            upload_allowed_types: "image/*,video/*,audio/*,application/pdf,text/plain,application/zip".into(),
            upload_allow_executables: false,
            upload_dm_categories: "images,audio,video,documents,archives,other".into(),
            storage_quota_per_room_bytes: 10 * 1024 * 1024 * 1024,
            storage_encryption: StorageEncryption::On,
            preview_auto_max_bytes: 5 * 1024 * 1024,
            unfurl: crate::unfurl::UnfurlSetting::On,
            retention_days: 0,
            emoji_max_per_room: 100,
            emoji_max_bytes: 256 * 1024,
            upload_max_bytes_ceiling: 0,
            voice_channel_max_participants: 0,
            stream_max_height: 0,
            stream_max_fps: 0,
            camera_max_height: 0,
            emoji_max_personal: 20,
            sounds_max_per_room: 50,
            sounds_max_personal: 10,
            attachment_retention_days: 0,
            files_channels: Switch::On,
            files_channels_max_bytes: 0,
            media_cache_unused_days: 365,
            media_cache_max_bytes: 2 * 1024 * 1024 * 1024,
            media_cache_max_bytes_per_host: 64 * 1024 * 1024,
            files_external: Switch::Off,
            files_external_private: Switch::Off,
            gif_provider: GifProvider::None,
            gif_api_key: None,
            voice_enabled: true,
            voice_max_bitrate_kbps: 192,
            screenshare_enabled: true,
            screenshare_max_resolution: "1080p".into(),
            screenshare_max_fps: 30,
            camera_enabled: true,
            camera_max_resolution: "720p".into(),
            camera_max_fps: 30,
            voice_max_participants: 50,
            voice_reconnect_grace_secs: 45,
            rtc_udp_port_range: "61000-61100".into(),
            rtc_external_ip: None,
            rtc_advertise_ips: String::new(),
            rtc_advertise_private: false,
            rtc_stun_servers: String::new(),
            rtc_tcp_port: 7881,
            rtc_turn_enabled: false,
            rtc_turn_domain: None,
            rtc_turn_udp_port: 3478,
            rtc_turn_tls_port: 5349,
            rtc_turn_relay_port_range: "30000-30999".into(),
            livekit_binary: "livekit-server".into(),
            livekit_port: 7880,
            federation_enabled: true,
            // No built-in reference node: operators choose theirs (deploy/.env.example has an example).
            reference_nodes: String::new(),
            directory_listing: true,
            directory_max_rooms: 5000,
            federation_blocklist: String::new(),
            federation_allowlist: String::new(),
            federation_allow_private: false,
            federation_srv_fallback: true,
            federation_dev_peers: String::new(),
            federation_remote_bots: true,
            rate_user_per_minute: 1200,
            password_hash_concurrency: 0,
            rate_limit_ipv6_prefix: 64,
            ws_max_sockets_per_user: 20,
            federation_rate_logins: 60,
            federation_rate_inbox: 300,
            federation_rate_api: 3000,
            federation_rate_claims: 120,
            federation_max_remote_users: 10_000,
            federation_max_remote_users_per_domain: 1000,
            federation_permit_timeout_secs: 10,
            federation_max_unverified_peers: 1000,
            federation_discovery_slots: 12,
            federation_require_conformance: false,
            federation_remote_user_retention_days: 90,
            federation_notify_bans: false,
            dev_misbehave: String::new(),
            automod_burst_limit: 10,
            automod_timeout_minutes: 10,
            automod_words_file: None,
            automod_links: "off".into(),
            reports_rate_per_hour: 10,
            reports_retention_days: 90,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_client_secret_file: None,
            oidc_scopes: "openid profile email groups".into(),
            oidc_username_claim: "preferred_username".into(),
            oidc_display_name_claim: "name".into(),
            oidc_groups_claim: "groups".into(),
            oidc_button_label: None,
            oidc_only: false,
            oidc_auto_provision: true,
            oidc_group_map: None,
            oidc_group_sync: OidcGroupSync::Add,
            oidc_session_days: 7,
            session_access_minutes: 60,
            session_refresh_days: 90,
            device_stale_days: 180,
            e2ee_claims_per_target_per_hour: 60,
            app_creation: AppCreation::All,
            apps_per_user: 5,
            apps_per_room: 25,
            app_token_max_days: 365,
            app_rate_requests: 1200,
            apps_federate: true,
            app_allow_private_urls: false,
            app_commands_require_approval: false,
            webhooks_enabled: true,
            webhooks_per_channel: 10,
            search_enabled: true,
            search_rate_per_minute: 30,
            legal_notices: Switch::Off,
            legal_notice_rate_per_hour: 5,
            legal_notice_retention_days: 1095,
            legal_notice_inbound_per_hour: 10,
            legal_repeat_threshold: 3,
            legal_counter_notice_days: 14,
            legal_terms_mode: TermsMode::Notice,
            account_delete_grace_days: 30,
            push: Switch::On,
            push_contact: None,
            push_max_per_minute: 10,
            metrics: Switch::Off,
            metrics_token: None,
            admin_users: String::new(),
            log_level: "info".into(),
            log_format: LogFormat::Text,
            minimum_age: 16,
        }
    }
}

/// `check-config` prints the cache URL without its password.
fn redact_url_password<S: serde::Serializer>(url: &Option<String>, s: S) -> Result<S::Ok, S::Error> {
    match url.as_deref() {
        None => s.serialize_none(),
        Some(u) => match u
            .split_once("://")
            .and_then(|(scheme, rest)| rest.rsplit_once('@').map(|(cred, host)| (scheme, cred, host)))
        {
            Some((scheme, cred, host)) => {
                let user = cred.split_once(':').map(|(u, _)| u).unwrap_or(cred);
                s.serialize_some(&format!("{scheme}://{user}:***@{host}"))
            }
            None => s.serialize_some(u),
        },
    }
}

/// Collected validation errors, one per line, with the name of the affected variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub problems: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for p in &self.problems {
            writeln!(f, "  - {p}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Flags of `TAVRN_DEV_MISBEHAVE` (development nodes that break the protocol on purpose, FEDERATION.md §13.1).
pub const MISBEHAVIORS: &[&str] = &["accept_bad_signatures", "replay_ok", "plaintext_ok", "no_rate_limit"];

/// Bitrate of a new voice channel without an explicit `bitrate_kbps` (kbps, lowered to the node's cap): the
/// "High" preset of the clients (VOICE.md §4a).
pub const DEFAULT_CHANNEL_BITRATE_KBPS: u32 = 64;
pub const SCREENSHARE_RESOLUTIONS: &[&str] = &["720p", "1080p", "1440p", "4k"];
pub const CAMERA_RESOLUTIONS: &[&str] = &["360p", "720p", "1080p"];

impl Config {
    /// Loads the defaults, the optional TOML file (`TAVRN_CONFIG`) and `TAVRN_*` environment variables, and validates.
    pub fn load(dev: bool) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(Self::defaults_for(dev)));
        if let Ok(path) = std::env::var("TAVRN_CONFIG") {
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed("TAVRN_").ignore(&["CONFIG", "DEV"]));
        let mut config: Self = figment
            .extract()
            .map_err(|e| ConfigError { problems: e.into_iter().map(|err| err.to_string()).collect() })?;
        config.dev = dev;
        config.validate()?;
        Ok(config)
    }

    /// Defaults that differ in development mode.
    pub fn defaults_for(dev: bool) -> Self {
        let mut c = Self::default();
        if dev {
            c.rate_user_per_minute = 0;
            c.domain = "localhost".into();
            c.listen = "127.0.0.1:8080".into();
            c.database_url = "sqlite://data-dev/tavrn.db?mode=rwc".into();
            c.data_dir = "data-dev".into();
            c.registration = Registration::Open;
            c.room_creation = RoomCreation::Local;
            c.log_level = "debug,sqlx=info".into();
            // A development node never announces itself to the public reference node.
            c.reference_nodes = String::new();
            // Several development nodes share one machine: no fixed TCP media port unless configured.
            c.rtc_tcp_port = 0;
            // Test receivers of application URLs run on the developer's machine (APPLICATIONS.md §6.3).
            c.app_allow_private_urls = true;
            // End-to-end tests submit many notices from one address.
            c.legal_notice_rate_per_hour = 1000;
        }
        c
    }

    /// Reports and the auto-moderation node lists (MODERATION.md §1.3, §1.5, §2.3).
    fn validate_moderation(&self, problems: &mut Vec<String>) {
        if !(1..=1000).contains(&self.reports_rate_per_hour) {
            problems.push("TAVRN_REPORTS_RATE_PER_HOUR must be between 1 and 1000".into());
        }
        if !(1..=36_500).contains(&self.reports_retention_days) {
            problems.push("TAVRN_REPORTS_RETENTION_DAYS must be between 1 and 36500".into());
        }
        if let Some(path) = self.automod_words_file.as_deref().filter(|p| !p.trim().is_empty())
            && let Err(e) = crate::automod::read_terms(path)
        {
            problems.push(format!("TAVRN_AUTOMOD_WORDS_FILE: {e}"));
        }
        match self.automod_links.trim() {
            "" | "off" => {}
            path => {
                if let Err(e) = crate::automod::read_list(path) {
                    problems.push(format!("TAVRN_AUTOMOD_LINKS: {e} (off or the path of a domain list)"));
                }
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if self.domain.trim().is_empty() {
            problems.push("TAVRN_DOMAIN is missing (public domain of the node, e.g. chat.example.org)".into());
        } else if self.domain != self.domain.to_lowercase() || self.domain.contains('/') || self.domain.contains(':') {
            problems.push(format!(
                "TAVRN_DOMAIN='{}' is invalid: lowercase only, without scheme, path or port",
                self.domain
            ));
        }

        self.validate_public_url(&mut problems);
        self.validate_cache(&mut problems);
        if !(32..=128).contains(&self.rate_limit_ipv6_prefix) {
            problems.push("TAVRN_RATE_LIMIT_IPV6_PREFIX must be between 32 and 128".into());
        }
        if self.media_cache_max_bytes_per_host > self.media_cache_max_bytes {
            problems.push("TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST cannot exceed TAVRN_MEDIA_CACHE_MAX_BYTES".into());
        }

        if self.listen.parse::<std::net::SocketAddr>().is_err() {
            problems.push(format!("TAVRN_LISTEN='{}' is not a valid address (e.g. 0.0.0.0:8080)", self.listen));
        }

        for entry in split_list(&self.trusted_proxies) {
            if parse_net(&entry).is_none() {
                problems
                    .push(format!("TAVRN_TRUSTED_PROXIES contains the invalid entry '{entry}' (IP or CIDR expected)"));
            }
        }

        if self.database_url.trim().is_empty() {
            problems.push("TAVRN_DATABASE_URL is missing (e.g. postgres://tavrn:pw@db/tavrn)".into());
        } else if self.database_url.starts_with("sqlite:") && !self.dev {
            problems.push(
                "TAVRN_DATABASE_URL: SQLite is only allowed in development mode (--dev), production needs PostgreSQL"
                    .into(),
            );
        } else if !self.database_url.starts_with("postgres://")
            && !self.database_url.starts_with("postgresql://")
            && !self.database_url.starts_with("sqlite:")
        {
            problems.push("TAVRN_DATABASE_URL must start with postgres:// (or sqlite: in dev mode)".into());
        }

        if self.captcha_provider == CaptchaProvider::Turnstile
            && (self.turnstile_site_key.as_deref().unwrap_or("").trim().is_empty()
                || self.turnstile_secret_key.as_deref().unwrap_or("").trim().is_empty())
        {
            problems.push("TAVRN_TURNSTILE_SITE_KEY and TAVRN_TURNSTILE_SECRET_KEY are required with TAVRN_CAPTCHA_PROVIDER=turnstile".into());
        }

        if let Some(url) = self.smtp_url.as_deref().map(str::trim).filter(|u| !u.is_empty())
            && crate::mail::SmtpSettings::parse(url).is_none()
        {
            problems.push(format!("TAVRN_SMTP_URL='{url}' is invalid (smtp://, smtps:// or smtp+starttls://host:port, optionally user:pass@)"));
        }
        if let Some(from) = self.smtp_from.as_deref().map(str::trim).filter(|f| !f.is_empty())
            && from.parse::<lettre::message::Mailbox>().is_err()
        {
            problems.push(format!("TAVRN_SMTP_FROM='{from}' is not a valid sender address"));
        }
        let templates = crate::mail_templates::dir_of(self);
        let explicit = self.mail_templates_dir.as_deref().is_some_and(|d| !d.trim().is_empty());
        if explicit && !templates.is_dir() {
            problems.push(format!("TAVRN_MAIL_TEMPLATES_DIR='{}' is not a directory", templates.display()));
        } else if templates.is_dir() {
            for p in crate::mail_templates::check_dir(&templates) {
                problems.push(format!("TAVRN_MAIL_TEMPLATES_DIR: {p}"));
            }
        }

        if self.gif_provider != GifProvider::None && self.gif_api_key.as_deref().unwrap_or("").trim().is_empty() {
            problems.push("TAVRN_GIF_API_KEY is missing (needed with TAVRN_GIF_PROVIDER=giphy|tenor)".into());
        }

        if self.email == EmailMode::Required && self.smtp_url.as_deref().unwrap_or("").trim().is_empty() {
            problems
                .push("TAVRN_SMTP_URL is missing but required with TAVRN_EMAIL=required (email verification)".into());
        }

        if self.media_workers == 0 || self.media_workers > 8 {
            problems.push("TAVRN_MEDIA_WORKERS must be between 1 and 8".into());
        }
        if crate::uploads::parse_names(&split_list(&self.upload_dm_categories)).is_none() {
            problems.push(
                "TAVRN_UPLOAD_DM_CATEGORIES: comma list of images, audio, video, documents, archives, other".into(),
            );
        }
        if self.whiteboard_max_scenes == 0 || self.whiteboard_max_scenes > 1000 {
            problems.push("TAVRN_WHITEBOARD_MAX_SCENES must be between 1 and 1000".into());
        }
        let ffmpeg = self.media_ffmpeg.trim();
        if ffmpeg.is_empty() {
            problems.push("TAVRN_MEDIA_FFMPEG must not be empty (auto, off or a path to ffmpeg)".into());
        } else if ffmpeg != MEDIA_FFMPEG_AUTO
            && ffmpeg != MEDIA_FFMPEG_OFF
            && !std::path::Path::new(ffmpeg).is_absolute()
        {
            problems.push(format!("TAVRN_MEDIA_FFMPEG='{ffmpeg}' is invalid: auto, off or an absolute path to ffmpeg"));
        }

        if self.upload_max_bytes == 0 && self.uploads_enabled {
            problems.push("TAVRN_UPLOAD_MAX_BYTES must be greater than 0, or set TAVRN_UPLOADS_ENABLED=false".into());
        }

        if !SCREENSHARE_RESOLUTIONS.contains(&self.screenshare_max_resolution.as_str()) {
            problems.push(format!(
                "TAVRN_SCREENSHARE_MAX_RESOLUTION='{}' is invalid, allowed: {}",
                self.screenshare_max_resolution,
                SCREENSHARE_RESOLUTIONS.join(", ")
            ));
        }
        if self.screenshare_max_fps == 0 || self.screenshare_max_fps > 60 {
            problems.push("TAVRN_SCREENSHARE_MAX_FPS must be between 1 and 60".into());
        }
        if self.voice_max_bitrate_kbps < 8 || self.voice_max_bitrate_kbps > 512 {
            problems.push("TAVRN_VOICE_MAX_BITRATE_KBPS must be between 8 and 512".into());
        }

        if self.rtc_udp_port_range().is_none() {
            problems.push(format!(
                "TAVRN_RTC_UDP_PORT_RANGE='{}' is invalid, expected e.g. 61000-61100 (from < to, both > 1024)",
                self.rtc_udp_port_range
            ));
        }
        self.validate_voice(&mut problems);

        for d in self.reference_nodes() {
            if !crate::federation::valid_node_domain(&d) {
                problems.push(format!(
                    "TAVRN_REFERENCE_NODES contains the invalid domain '{d}' (lowercase, at least one dot, without port)"
                ));
            }
        }
        if self.directory_max_rooms == 0 {
            problems.push("TAVRN_DIRECTORY_MAX_ROOMS must be greater than 0".into());
        }

        self.validate_federation(&mut problems);
        self.validate_oidc(&mut problems);
        self.validate_entitlements(&mut problems);
        if self.apps_per_user > 100 {
            problems.push("TAVRN_APPS_PER_USER must be between 0 and 100".into());
        }
        if self.apps_per_room > 1000 {
            problems.push("TAVRN_APPS_PER_ROOM must be between 0 and 1000".into());
        }
        if !(1..=3650).contains(&self.app_token_max_days) {
            problems.push("TAVRN_APP_TOKEN_MAX_DAYS must be between 1 and 3650".into());
        }
        if self.app_rate_requests == 0 {
            problems.push("TAVRN_APP_RATE_REQUESTS must be greater than 0".into());
        }
        if !(1..=10_000).contains(&self.search_rate_per_minute) {
            problems.push("TAVRN_SEARCH_RATE_PER_MINUTE must be between 1 and 10000".into());
        }
        self.validate_legal(&mut problems);
        self.validate_push_metrics(&mut problems);
        if !(1..=crate::webhooks::MAX_PER_ROOM as u32).contains(&self.webhooks_per_channel) {
            problems.push("TAVRN_WEBHOOKS_PER_CHANNEL must be between 1 and 50".into());
        }
        if !(5..=1440).contains(&self.session_access_minutes) {
            problems.push("TAVRN_SESSION_ACCESS_MINUTES must be between 5 and 1440".into());
        }
        if !(1..=3650).contains(&self.session_refresh_days) {
            problems.push("TAVRN_SESSION_REFRESH_DAYS must be between 1 and 3650".into());
        }
        if self.device_stale_days > 36_500 {
            problems.push("TAVRN_DEVICE_STALE_DAYS must be between 0 and 36500 (0 = never)".into());
        }
        if !(1..=10_000).contains(&self.e2ee_claims_per_target_per_hour) {
            problems.push("TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR must be between 1 and 10000".into());
        }
        if !(13..=99).contains(&self.minimum_age) {
            problems.push("TAVRN_MINIMUM_AGE must be between 13 and 99".into());
        }

        if problems.is_empty() { Ok(()) } else { Err(ConfigError { problems }) }
    }

    /// Node defaults of the entitlement keys.
    /// `TAVRN_PUBLIC_URL`, `TAVRN_WEBAUTHN_ORIGIN` and `TAVRN_WEBAUTHN_RP_ID`.
    fn validate_public_url(&self, problems: &mut Vec<String>) {
        if self.domain.trim().is_empty() {
            return;
        }
        if let Some(url) = self.public_url.as_deref().map(str::trim).filter(|u| !u.is_empty())
            && !valid_public_url(url, self.dev)
        {
            problems.push(format!(
                "TAVRN_PUBLIC_URL='{url}' is invalid: https://<host>[:port] without path, query or fragment expected (http:// and IP addresses only with --dev)"
            ));
            return;
        }
        let configured_origin = self.webauthn_origin.as_deref().map(str::trim).filter(|o| !o.is_empty());
        if let Some(origin) = configured_origin
            && !valid_webauthn_origin(origin)
        {
            problems.push(format!(
                "TAVRN_WEBAUTHN_ORIGIN='{origin}' is invalid: http(s)://<host>[:port] without path expected"
            ));
            return;
        }
        for origin in split_list(&self.webauthn_app_origins) {
            if !valid_app_origin(&origin) {
                problems.push(format!(
                    "TAVRN_WEBAUTHN_APP_ORIGINS contains the invalid entry '{origin}': android:apk-key-hash:<base64url of the SHA-256 of the signing certificate, 43 characters> expected"
                ));
            }
        }
        let rp_id = self.webauthn_rp_id();
        if !crate::util::valid_domain(&rp_id) || !(rp_id.contains('.') || self.dev) {
            problems.push(format!(
                "TAVRN_WEBAUTHN_RP_ID='{rp_id}' is invalid: a lowercase domain with at least one dot expected"
            ));
            return;
        }
        let origin = self.webauthn_origin();
        let host = reqwest::Url::parse(&origin).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
        if !rp_id_covers(&rp_id, &host) {
            let source = if configured_origin.is_some() { "TAVRN_WEBAUTHN_ORIGIN" } else { "TAVRN_PUBLIC_URL" };
            problems.push(format!(
                "TAVRN_WEBAUTHN_RP_ID='{rp_id}' (default: TAVRN_DOMAIN) is not a registrable suffix of the host '{host}' of {source}: set TAVRN_WEBAUTHN_RP_ID to '{host}' or a parent domain of it, or serve the web client under the relying party domain"
            ));
        }
    }

    /// `TAVRN_PUSH_*` and `TAVRN_METRICS_*`.
    fn validate_push_metrics(&self, problems: &mut Vec<String>) {
        if !(1..=1000).contains(&self.push_max_per_minute) {
            problems.push("TAVRN_PUSH_MAX_PER_MINUTE must be between 1 and 1000".into());
        }
        if let Some(contact) = self.push_contact.as_deref().map(str::trim).filter(|c| !c.is_empty())
            && !valid_push_contact(contact)
        {
            problems.push(format!(
                "TAVRN_PUSH_CONTACT='{contact}' is invalid: a mailto: address or an https:// URL (at most 256 characters)"
            ));
        }
        if let Some(token) = self.metrics_token.as_deref().filter(|t| !t.is_empty())
            && (token.chars().count() < 16 || token.len() > 256 || !token.chars().all(|c| c.is_ascii_graphic()))
        {
            problems.push(
                "TAVRN_METRICS_TOKEN must be 16 to 256 printable ASCII characters without spaces (or empty)".into(),
            );
        }
    }

    /// The VAPID contact (`TAVRN_PUSH_CONTACT`, else the public URL).
    pub fn push_contact(&self) -> String {
        self.push_contact
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(String::from)
            .unwrap_or_else(|| self.public_url())
    }

    /// The bearer token of `/metrics`, `None` when empty.
    pub fn metrics_token(&self) -> Option<&str> {
        self.metrics_token.as_deref().map(str::trim).filter(|t| !t.is_empty())
    }

    fn validate_legal(&self, problems: &mut Vec<String>) {
        self.validate_moderation(problems);
        if !(1..=1000).contains(&self.legal_notice_rate_per_hour) {
            problems.push("TAVRN_LEGAL_NOTICE_RATE_PER_HOUR must be between 1 and 1000".into());
        }
        if !(30..=36_500).contains(&self.legal_notice_retention_days) {
            problems.push("TAVRN_LEGAL_NOTICE_RETENTION_DAYS must be between 30 and 36500".into());
        }
        if !(1..=1000).contains(&self.legal_notice_inbound_per_hour) {
            problems.push("TAVRN_LEGAL_NOTICE_INBOUND_PER_HOUR must be between 1 and 1000".into());
        }
        if !(1..=100).contains(&self.legal_repeat_threshold) {
            problems.push("TAVRN_LEGAL_REPEAT_THRESHOLD must be between 1 and 100".into());
        }
        if !(1..=365).contains(&self.legal_counter_notice_days) {
            problems.push("TAVRN_LEGAL_COUNTER_NOTICE_DAYS must be between 1 and 365".into());
        }
        if !(1..=365).contains(&self.account_delete_grace_days) {
            problems.push("TAVRN_ACCOUNT_DELETE_GRACE_DAYS must be between 1 and 365".into());
        }
    }

    fn validate_entitlements(&self, problems: &mut Vec<String>) {
        if self.upload_max_bytes_ceiling != 0 && self.upload_max_bytes_ceiling < self.upload_max_bytes {
            problems.push("TAVRN_UPLOAD_MAX_BYTES_CEILING must be 0 or at least TAVRN_UPLOAD_MAX_BYTES".into());
        }
        let ranges: [(&str, u64, u64); 10] = [
            ("TAVRN_VOICE_CHANNEL_MAX_PARTICIPANTS", self.voice_channel_max_participants.into(), 1000),
            ("TAVRN_STREAM_MAX_HEIGHT", self.stream_max_height.into(), 4320),
            ("TAVRN_STREAM_MAX_FPS", self.stream_max_fps.into(), 240),
            ("TAVRN_CAMERA_MAX_HEIGHT", self.camera_max_height.into(), 4320),
            ("TAVRN_EMOJI_MAX_PERSONAL", self.emoji_max_personal.into(), 100_000),
            ("TAVRN_SOUNDS_MAX_PER_ROOM", self.sounds_max_per_room.into(), 100_000),
            ("TAVRN_SOUNDS_MAX_PERSONAL", self.sounds_max_personal.into(), 100_000),
            ("TAVRN_ATTACHMENT_RETENTION_DAYS", self.attachment_retention_days.into(), 36_500),
            ("TAVRN_RETENTION_DAYS", self.retention_days.into(), 36_500),
            ("TAVRN_MAX_ROOMS_PER_USER", self.max_rooms_per_user.into(), 1_000_000),
        ];
        for (name, value, max) in ranges {
            if value > max {
                problems.push(format!("{name} must be between 0 and {max} (0 = unlimited)"));
            }
        }
    }

    /// The largest upload any user can get (`TAVRN_UPLOAD_MAX_BYTES_CEILING`, at least the node default).
    pub fn upload_ceiling(&self) -> u64 {
        self.upload_max_bytes_ceiling.max(self.upload_max_bytes)
    }

    fn validate_voice(&self, problems: &mut Vec<String>) {
        if !CAMERA_RESOLUTIONS.contains(&self.camera_max_resolution.as_str()) {
            problems.push(format!(
                "TAVRN_CAMERA_MAX_RESOLUTION='{}' is invalid, allowed: {}",
                self.camera_max_resolution,
                CAMERA_RESOLUTIONS.join(", ")
            ));
        }
        if self.camera_max_fps == 0 || self.camera_max_fps > 60 {
            problems.push("TAVRN_CAMERA_MAX_FPS must be between 1 and 60".into());
        }
        if self.voice_max_participants == 0 || self.voice_max_participants > 1000 {
            problems.push("TAVRN_VOICE_MAX_PARTICIPANTS must be between 1 and 1000".into());
        }
        if self.voice_reconnect_grace_secs > 600 {
            problems.push("TAVRN_VOICE_RECONNECT_GRACE_SECS must be between 0 and 600".into());
        }
        if self.livekit_port <= 1024 {
            problems.push(format!("TAVRN_LIVEKIT_PORT={} is invalid (1025–65535)", self.livekit_port));
        } else if self.listen.parse::<std::net::SocketAddr>().is_ok_and(|a| a.port() == self.livekit_port) {
            problems.push(format!("TAVRN_LIVEKIT_PORT={} is already the port of TAVRN_LISTEN", self.livekit_port));
        }
        if let Some(ip) = self.rtc_external_ip()
            && !advertisable_ip(ip)
            && advertise_hostname(ip).is_none()
        {
            problems.push(format!(
                "TAVRN_RTC_EXTERNAL_IP='{ip}' is neither a usable IP address (no link-local, multicast or 0.0.0.0 address) nor a hostname"
            ));
        }
        for ip in split_list(&self.rtc_advertise_ips) {
            if !advertisable_ip(&ip) && advertise_hostname(&ip).is_none() {
                problems.push(format!(
                    "TAVRN_RTC_ADVERTISE_IPS contains '{ip}': neither a usable IP address (no link-local, multicast or 0.0.0.0 address) nor a hostname"
                ));
            }
        }
        for server in split_list(&self.rtc_stun_servers) {
            if !valid_host_port(&server) {
                problems.push(format!("TAVRN_RTC_STUN_SERVERS contains '{server}': host:port expected"));
            }
        }
        self.validate_rtc_ports(problems);
        if self.livekit_binary.trim().is_empty() {
            problems.push("TAVRN_LIVEKIT_BINARY must not be empty (default: livekit-server)".into());
        }
    }

    /// TCP ports LiveKit listens on (ICE/TCP, TURN/TLS) must not clash with each other or the node's ports.
    fn validate_rtc_ports(&self, problems: &mut Vec<String>) {
        let listen = self.listen_port();
        let mut tcp: Vec<(&str, u16)> = vec![("TAVRN_LISTEN", listen), ("TAVRN_LIVEKIT_PORT", self.livekit_port)];
        let mut check = |name: &'static str, port: u16, tcp_port: bool, problems: &mut Vec<String>| {
            if port != 0 && port <= 1024 {
                problems.push(format!("{name}={port} is invalid (0 = off, otherwise 1025–65535)"));
            } else if port != 0 && tcp_port {
                if let Some((other, _)) = tcp.iter().find(|(_, p)| *p == port) {
                    problems.push(format!("{name}={port} is already the port of {other}"));
                }
                tcp.push((name, port));
            }
        };
        check("TAVRN_RTC_TCP_PORT", self.rtc_tcp_port, true, problems);
        if !self.rtc_turn_enabled {
            return;
        }
        check("TAVRN_RTC_TURN_TLS_PORT", self.rtc_turn_tls_port, true, problems);
        check("TAVRN_RTC_TURN_UDP_PORT", self.rtc_turn_udp_port, false, problems);
        if self.rtc_turn_udp_port == 0 && self.rtc_turn_tls_port == 0 {
            problems.push(
                "TAVRN_RTC_TURN_ENABLED=true needs TAVRN_RTC_TURN_UDP_PORT or TAVRN_RTC_TURN_TLS_PORT (both 0)".into(),
            );
        }
        if let Some((from, to)) = self.rtc_udp_port_range()
            && (from..=to).contains(&self.rtc_turn_udp_port)
        {
            problems.push(format!(
                "TAVRN_RTC_TURN_UDP_PORT={} lies in the media range TAVRN_RTC_UDP_PORT_RANGE",
                self.rtc_turn_udp_port
            ));
        }
        match self.rtc_turn_relay_port_range() {
            None => problems.push(format!(
                "TAVRN_RTC_TURN_RELAY_PORT_RANGE='{}' is invalid, expected e.g. 30000-30999 (from < to, both > 1024)",
                self.rtc_turn_relay_port_range
            )),
            Some((from, to)) => {
                if let Some((a, b)) = self.rtc_udp_port_range()
                    && from <= b
                    && a <= to
                {
                    problems.push("TAVRN_RTC_TURN_RELAY_PORT_RANGE overlaps with TAVRN_RTC_UDP_PORT_RANGE".into());
                }
            }
        }
        if self.rtc_turn_tls_port != 0 && !crate::util::valid_domain(&self.rtc_turn_domain()) {
            problems.push(format!(
                "TAVRN_RTC_TURN_DOMAIN='{}' is not a valid domain (TURN over TLS needs one, default turn.<TAVRN_DOMAIN>)",
                self.rtc_turn_domain()
            ));
        }
    }

    /// `TAVRN_RTC_TURN_DOMAIN`, default `turn.<host of the public URL>` (`turn.<TAVRN_DOMAIN>` when that host is
    /// an IP address).
    pub fn rtc_turn_domain(&self) -> String {
        self.rtc_turn_domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| {
                let host = self.public_host();
                let host = if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
                    &self.domain
                } else {
                    &host
                };
                format!("turn.{host}")
            })
    }

    pub fn rtc_turn_relay_port_range(&self) -> Option<(u16, u16)> {
        parse_port_range(&self.rtc_turn_relay_port_range)
    }

    /// The IP literals of `TAVRN_RTC_ADVERTISE_IPS` (hostnames and invalid entries are left out).
    pub fn rtc_advertise_ips(&self) -> Vec<std::net::IpAddr> {
        split_list(&self.rtc_advertise_ips).iter().filter_map(|s| s.parse().ok()).collect()
    }

    /// Every announced address entry in order: `TAVRN_RTC_EXTERNAL_IP` first, then `TAVRN_RTC_ADVERTISE_IPS`;
    /// each an IP literal or a hostname (normalized). Invalid entries are left out (the validation names them).
    pub fn rtc_advertise_entries(&self) -> Vec<AdvertiseEntry> {
        let mut out = Vec::new();
        for raw in self.rtc_external_ip().map(String::from).into_iter().chain(split_list(&self.rtc_advertise_ips)) {
            let entry = if advertisable_ip(&raw) {
                raw.trim().parse().ok().map(AdvertiseEntry::Ip)
            } else {
                advertise_hostname(&raw).map(AdvertiseEntry::Host)
            };
            if let Some(entry) = entry
                && !out.contains(&entry)
            {
                out.push(entry);
            }
        }
        out
    }

    /// `TAVRN_RTC_STUN_SERVERS`.
    pub fn rtc_stun_servers(&self) -> Vec<String> {
        split_list(&self.rtc_stun_servers)
    }

    /// Audio bitrate of calls in DMs (VOICE.md §11): speech, so the bitrate of a new voice channel, lowered to
    /// the node's cap.
    pub fn call_audio_bitrate_kbps(&self) -> u32 {
        DEFAULT_CHANNEL_BITRATE_KBPS.min(self.voice_max_bitrate_kbps)
    }

    /// `TAVRN_RTC_EXTERNAL_IP`, if set.
    pub fn rtc_external_ip(&self) -> Option<&str> {
        self.rtc_external_ip.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }

    /// Port of `TAVRN_LISTEN` (8080 if unparsable; validation reports that case).
    fn validate_cache(&self, problems: &mut Vec<String>) {
        if let Some(url) = self.cache_url.as_deref().map(str::trim).filter(|u| !u.is_empty())
            && !crate::cache::valid_url(url)
        {
            problems.push(format!(
                "TAVRN_CACHE_URL='{}' is invalid: redis://[user:password@]host[:port][/db] or rediss://… (TLS)",
                crate::cache::target_of(url)
            ));
        }
        if let Some(id) = self.instance_id.as_deref().map(str::trim).filter(|i| !i.is_empty())
            && !crate::cache::valid_instance_id(id)
        {
            problems
                .push(format!("TAVRN_INSTANCE_ID='{id}' is invalid: 1–64 characters of A–Z, a–z, 0–9, '.', '_', '-'"));
        }
        if let Some(url) = self.instance_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            let ok = reqwest::Url::parse(url).is_ok_and(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
                    && matches!(u.path(), "" | "/")
                    && u.query().is_none()
            });
            if !ok {
                problems.push(format!(
                    "TAVRN_INSTANCE_URL='{url}' is invalid: http(s)://<host>[:port] where the other instances reach this one"
                ));
            }
        }
    }

    pub fn listen_port(&self) -> u16 {
        self.listen.parse::<std::net::SocketAddr>().map(|a| a.port()).unwrap_or(8080)
    }

    fn validate_federation(&self, problems: &mut Vec<String>) {
        for (var, list) in [
            ("TAVRN_FEDERATION_BLOCKLIST", &self.federation_blocklist),
            ("TAVRN_FEDERATION_ALLOWLIST", &self.federation_allowlist),
        ] {
            for d in split_list(list) {
                if !crate::federation::valid_node_domain(&d) {
                    problems.push(format!(
                        "{var} contains the invalid domain '{d}' (lowercase, at least one dot, without port)"
                    ));
                }
            }
        }
        if !self.federation_dev_peers.trim().is_empty() {
            if !self.dev {
                problems.push("TAVRN_FEDERATION_DEV_PEERS is only allowed in development mode (--dev)".into());
            } else if let Err(e) = self.federation_dev_peers() {
                problems.push(format!("TAVRN_FEDERATION_DEV_PEERS is invalid: {e}"));
            }
        }
        if self.federation_rate_logins == 0 {
            problems.push("TAVRN_FEDERATION_RATE_LOGINS must be greater than 0".into());
        }
        if self.federation_rate_inbox == 0 {
            problems.push("TAVRN_FEDERATION_RATE_INBOX must be greater than 0".into());
        }
        if self.federation_rate_api == 0 {
            problems.push("TAVRN_FEDERATION_RATE_API must be greater than 0".into());
        }
        if self.federation_rate_claims == 0 {
            problems.push("TAVRN_FEDERATION_RATE_CLAIMS must be greater than 0".into());
        }
        if !(1..=120).contains(&self.federation_permit_timeout_secs) {
            problems.push("TAVRN_FEDERATION_PERMIT_TIMEOUT_SECS must be between 1 and 120".into());
        }
        if !(10..=1_000_000).contains(&self.federation_max_unverified_peers) {
            problems.push("TAVRN_FEDERATION_MAX_UNVERIFIED_PEERS must be between 10 and 1000000".into());
        }
        if !(1..=64).contains(&self.federation_discovery_slots) {
            problems.push("TAVRN_FEDERATION_DISCOVERY_SLOTS must be between 1 and 64".into());
        }
        if !self.dev_misbehave.trim().is_empty() {
            if !self.dev {
                problems.push("TAVRN_DEV_MISBEHAVE is only allowed in development mode (--dev)".into());
            }
            for flag in split_list(&self.dev_misbehave) {
                if !MISBEHAVIORS.contains(&flag.as_str()) {
                    problems.push(format!(
                        "TAVRN_DEV_MISBEHAVE: unknown flag '{flag}' (allowed: {})",
                        MISBEHAVIORS.join(", ")
                    ));
                }
            }
        }
    }

    /// Single sign-on (protocol/APPLICATIONS.md §8.1): the combination is checked here; the provider itself
    /// is contacted lazily (an unreachable provider never stops the node).
    fn validate_oidc(&self, problems: &mut Vec<String>) {
        let Some(issuer) = self.oidc_issuer() else {
            let stray = [
                ("TAVRN_OIDC_CLIENT_ID", self.oidc_client_id.as_deref().is_some_and(|s| !s.trim().is_empty())),
                ("TAVRN_OIDC_ONLY", self.oidc_only),
                ("TAVRN_OIDC_GROUP_MAP", self.oidc_group_map.as_deref().is_some_and(|s| !s.trim().is_empty())),
            ];
            for (var, set) in stray {
                if set {
                    problems
                        .push(format!("{var} is set but TAVRN_OIDC_ISSUER is empty (SSO is off without an issuer)"));
                }
            }
            return;
        };
        match reqwest::Url::parse(issuer) {
            Ok(url)
                if (url.scheme() == "https" || (self.dev && url.scheme() == "http"))
                    && url.host_str().is_some()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty() => {}
            _ => problems.push(format!(
                "TAVRN_OIDC_ISSUER='{issuer}' is invalid: an https:// URL without query or fragment expected (http:// only with --dev)"
            )),
        }
        if self.oidc_client_id.as_deref().is_none_or(|s| s.trim().is_empty()) {
            problems.push("TAVRN_OIDC_CLIENT_ID is required with TAVRN_OIDC_ISSUER".into());
        }
        let secret = self.oidc_client_secret.as_deref().is_some_and(|s| !s.trim().is_empty());
        match self.oidc_client_secret_file.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            Some(_) if secret => {
                problems.push("TAVRN_OIDC_CLIENT_SECRET and TAVRN_OIDC_CLIENT_SECRET_FILE are both set; use one".into())
            }
            Some(file) if !std::path::Path::new(file).is_file() => {
                problems.push(format!("TAVRN_OIDC_CLIENT_SECRET_FILE='{file}' is not a readable file"));
            }
            _ => {}
        }
        let scopes = self.oidc_scopes();
        if !scopes.iter().any(|s| s == "openid") {
            problems.push("TAVRN_OIDC_SCOPES must contain openid".into());
        }
        if let Some(bad) = scopes.iter().find(|s| !s.chars().all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')) {
            problems.push(format!("TAVRN_OIDC_SCOPES contains the invalid scope '{bad}'"));
        }
        for (var, claim) in [
            ("TAVRN_OIDC_USERNAME_CLAIM", &self.oidc_username_claim),
            ("TAVRN_OIDC_DISPLAY_NAME_CLAIM", &self.oidc_display_name_claim),
            ("TAVRN_OIDC_GROUPS_CLAIM", &self.oidc_groups_claim),
        ] {
            if claim.trim().is_empty() || claim.len() > 100 {
                problems.push(format!("{var} must name a claim (1–100 characters)"));
            }
        }
        if self.oidc_button_label.as_deref().is_some_and(|l| l.trim().chars().count() > 64) {
            problems.push("TAVRN_OIDC_BUTTON_LABEL: at most 64 characters".into());
        }
        if !(1..=30).contains(&self.oidc_session_days) {
            problems.push("TAVRN_OIDC_SESSION_DAYS must be between 1 and 30".into());
        }
        if let Some(map) = self.oidc_group_map.as_deref().map(str::trim).filter(|m| !m.is_empty())
            && let Err(e) = crate::oidc::groups::parse(map)
        {
            problems.push(format!("TAVRN_OIDC_GROUP_MAP: {e}"));
        }
    }

    /// `TAVRN_OIDC_ISSUER`, if SSO is configured.
    pub fn oidc_issuer(&self) -> Option<&str> {
        self.oidc_issuer.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }

    /// `TAVRN_OIDC_SCOPES` as a list (space or comma separated).
    pub fn oidc_scopes(&self) -> Vec<String> {
        self.oidc_scopes.split([' ', ',']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
    }

    /// `true` if this (development) node deliberately misbehaves in `flag` (`TAVRN_DEV_MISBEHAVE`, only
    /// for conformance tests). Always `false` outside `--dev`.
    pub fn misbehaves(&self, flag: &str) -> bool {
        self.dev && split_list(&self.dev_misbehave).iter().any(|f| f == flag)
    }

    /// Parsed `TAVRN_FEDERATION_DEV_PEERS`: domain → base URL (`http(s)://host[:port]`, no path).
    pub fn federation_dev_peers(&self) -> Result<std::collections::HashMap<String, reqwest::Url>, String> {
        let mut peers = std::collections::HashMap::new();
        for entry in split_list(&self.federation_dev_peers) {
            let (domain, url) = entry.split_once('=').ok_or_else(|| format!("'{entry}': domain=url expected"))?;
            let domain = domain.trim();
            if !crate::federation::valid_node_domain(domain) {
                return Err(format!("'{domain}' is not a valid domain"));
            }
            let url = reqwest::Url::parse(url.trim()).map_err(|_| format!("'{}' is not a valid URL", url.trim()))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || url.path() != "/"
                || url.query().is_some()
                || !url.username().is_empty()
            {
                return Err(format!("'{url}': http(s)://host:port without path expected"));
            }
            peers.insert(domain.to_string(), url);
        }
        Ok(peers)
    }

    pub fn federation_allowlist(&self) -> Vec<String> {
        split_list(&self.federation_allowlist)
    }

    pub fn rtc_udp_port_range(&self) -> Option<(u16, u16)> {
        parse_port_range(&self.rtc_udp_port_range)
    }

    pub fn reference_nodes(&self) -> Vec<String> {
        split_list(&self.reference_nodes)
    }

    pub fn smtp_from(&self) -> String {
        self.smtp_from
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("noreply@{}", self.domain))
    }

    /// Is the captcha active for registration or login, respectively?
    pub fn captcha_required(&self, action: CaptchaAction) -> bool {
        self.captcha_provider != CaptchaProvider::None
            && match action {
                CaptchaAction::Register => self.captcha_register,
                CaptchaAction::Login => self.captcha_login,
            }
    }

    /// WebAuthn origin: `TAVRN_WEBAUTHN_ORIGIN` or the public URL.
    pub fn webauthn_origin(&self) -> String {
        self.webauthn_origin
            .as_deref()
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .map(|o| o.trim_end_matches('/').to_string())
            .unwrap_or_else(|| self.public_url())
    }

    /// The app origins of `TAVRN_WEBAUTHN_APP_ORIGINS` (validated at start), without duplicates, in their order.
    pub fn webauthn_app_origins(&self) -> Vec<String> {
        let mut origins: Vec<String> = Vec::new();
        for origin in split_list(&self.webauthn_app_origins) {
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        origins
    }

    /// Every origin the node accepts for WebAuthn: the web origin first, then the app origins (`webauthn.origins`,
    /// PROTOCOL.md §5a.4).
    pub fn webauthn_origins(&self) -> Vec<String> {
        let web = self.webauthn_origin();
        std::iter::once(web.clone()).chain(self.webauthn_app_origins().into_iter().filter(|o| *o != web)).collect()
    }

    /// WebAuthn relying party id: `TAVRN_WEBAUTHN_RP_ID` or the identity domain.
    pub fn webauthn_rp_id(&self) -> String {
        self.webauthn_rp_id
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| self.domain.clone())
    }

    pub fn trusted_proxies(&self) -> Vec<ipnet::IpNet> {
        split_list(&self.trusted_proxies).iter().filter_map(|e| parse_net(e)).collect()
    }

    pub fn is_trusted_proxy(&self, ip: std::net::IpAddr) -> bool {
        self.trusted_proxies().iter().any(|n| n.contains(&ip))
    }

    pub fn federation_blocklist(&self) -> Vec<String> {
        split_list(&self.federation_blocklist)
    }

    pub fn admin_users(&self) -> Vec<String> {
        split_list(&self.admin_users)
    }

    pub fn upload_allowed_types(&self) -> Vec<String> {
        split_list(&self.upload_allowed_types)
    }

    /// `TAVRN_UPLOAD_DM_CATEGORIES` as a mask (validated at start).
    pub fn upload_dm_categories(&self) -> crate::uploads::Categories {
        crate::uploads::parse_names(&split_list(&self.upload_dm_categories)).unwrap_or(crate::uploads::DEFAULT_EVERYONE)
    }

    /// Public base URL of the host serving this node: `TAVRN_PUBLIC_URL` as an origin without
    /// trailing slash, otherwise `https://<domain>` (in dev mode `http://<domain>:<listen port>`).
    pub fn public_url(&self) -> String {
        if let Some(url) = self.public_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            return match reqwest::Url::parse(url) {
                Ok(u) => u.origin().ascii_serialization(),
                Err(_) => url.trim_end_matches('/').to_string(),
            };
        }
        if self.dev {
            let port = self.listen.rsplit(':').next().unwrap_or("8080");
            format!("http://{}:{}", self.domain, port)
        } else {
            format!("https://{}", self.domain)
        }
    }

    /// Host (with brackets for IPv6, without port) of [`Self::public_url`].
    pub fn public_host(&self) -> String {
        reqwest::Url::parse(&self.public_url())
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| self.domain.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaAction {
    Register,
    Login,
}

/// `http(s)://host[:port]` without path, query, fragment or user info.
fn valid_webauthn_origin(origin: &str) -> bool {
    let Ok(url) = webauthn_rs::prelude::Url::parse(origin) else { return false };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && !origin.contains('#')
}

/// Prefix of an Android app's WebAuthn origin (PROTOCOL.md §5a.4).
pub const ANDROID_ORIGIN_PREFIX: &str = "android:apk-key-hash:";

/// An app origin of `TAVRN_WEBAUTHN_APP_ORIGINS`: `android:apk-key-hash:` and the base64url (no padding) of a
/// SHA-256 (32 bytes, 43 characters). iOS origins are not specified yet.
fn valid_app_origin(origin: &str) -> bool {
    use base64::Engine as _;
    origin.strip_prefix(ANDROID_ORIGIN_PREFIX).is_some_and(|hash| {
        hash.len() == 43
            && base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(hash).is_ok_and(|bytes| bytes.len() == 32)
    })
}

/// WebAuthn rule: the relying party id must be the origin's host or a registrable parent domain of it.
fn rp_id_covers(rp_id: &str, host: &str) -> bool {
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

/// `TAVRN_PUBLIC_URL`: `https://<host>[:port]` without path, query, fragment or user info. The host may be
/// any domain (delegation: the identity domain `tavrn.org` served at `app.tavrn.org` or `chat.example.net`);
/// `http://` and IP addresses only in development mode.
/// A VAPID contact (RFC 8292 §2.1): `mailto:<address>` or an `https://` URL.
pub fn valid_push_contact(contact: &str) -> bool {
    if contact.len() > 256 || contact.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if let Some(address) = contact.strip_prefix("mailto:") {
        return address.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'));
    }
    reqwest::Url::parse(contact).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some())
}

pub fn valid_public_url(url: &str, dev: bool) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else { return false };
    let Some(host) = u.host_str() else { return false };
    let ip = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok();
    let host_ok = if ip { dev } else { crate::util::valid_domain(host) && (dev || host.contains('.')) };
    (u.scheme() == "https" || (dev && u.scheme() == "http"))
        && host_ok
        && u.path() == "/"
        && u.query().is_none()
        && u.username().is_empty()
        && u.password().is_none()
        && !url.contains('#')
}

/// IP or CIDR; a bare IP becomes a /32 or /128, respectively.
fn parse_net(s: &str) -> Option<ipnet::IpNet> {
    s.parse::<ipnet::IpNet>().ok().or_else(|| s.parse::<std::net::IpAddr>().ok().map(ipnet::IpNet::from))
}

/// `from-to` with `1024 < from < to`.
fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('-')?;
    let from: u16 = a.trim().parse().ok()?;
    let to: u16 = b.trim().parse().ok()?;
    (from > 1024 && from < to).then_some((from, to))
}

/// An address clients can be told to send media to: not unspecified, multicast or link-local.
/// One entry of `TAVRN_RTC_EXTERNAL_IP`/`TAVRN_RTC_ADVERTISE_IPS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertiseEntry {
    Ip(std::net::IpAddr),
    /// A hostname (dynamic DNS), lowercase, without trailing dot.
    Host(String),
}

/// A hostname in the address settings: a domain with at least one dot and a non-numeric top-level label
/// (so a mistyped IP address is not taken for a name), case-insensitive, an optional trailing dot.
pub fn advertise_hostname(s: &str) -> Option<String> {
    let host = s.trim().trim_end_matches('.').to_ascii_lowercase();
    (crate::util::valid_domain(&host)
        && host.contains('.')
        && host.rsplit('.').next().is_some_and(|tld| !tld.chars().all(|c| c.is_ascii_digit())))
    .then_some(host)
}

fn advertisable_ip(s: &str) -> bool {
    match s.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            !(ip.is_unspecified() || ip.is_multicast() || ip.is_link_local() || ip.is_broadcast())
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !(ip.is_unspecified() || ip.is_multicast() || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
        Err(_) => false,
    }
}

/// `host:port` of a STUN server (a domain or an IPv4 address; IPv6 in brackets).
fn valid_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else { return false };
    if !port.parse::<u16>().is_ok_and(|p| p > 0) {
        return false;
    }
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    host.parse::<std::net::IpAddr>().is_ok() || crate::util::valid_domain(host)
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::result_large_err)]
    use super::*;

    fn prod() -> Config {
        Config {
            domain: "chat.example.org".into(),
            database_url: "postgres://tavrn:pw@db/tavrn".into(),
            ..Config::default()
        }
    }

    #[test]
    fn valid_production_config_passes() {
        prod().validate().unwrap();
    }

    #[test]
    fn push_and_metrics_settings_are_validated() {
        let c = prod();
        assert!(c.push.on() && !c.metrics.on(), "push on, metrics off by default");
        assert_eq!(c.push_max_per_minute, 10);
        assert_eq!(c.push_contact(), "https://chat.example.org", "default contact: the public URL");
        assert_eq!(c.metrics_token(), None);
        let ok = |c: Config| c.validate().is_ok();
        assert!(ok(Config { push_contact: Some("mailto:ops@example.org".into()), ..prod() }));
        assert!(ok(Config { push_contact: Some("https://example.org/contact".into()), ..prod() }));
        assert!(ok(Config { metrics_token: Some(String::new()), ..prod() }), "empty token: loopback rule");
        assert!(ok(Config { metrics_token: Some("0123456789abcdef".into()), ..prod() }));
        for bad in [
            Config { push_max_per_minute: 0, ..prod() },
            Config { push_max_per_minute: 1001, ..prod() },
            Config { push_contact: Some("ops@example.org".into()), ..prod() },
            Config { push_contact: Some("http://example.org".into()), ..prod() },
            Config { push_contact: Some("mailto:nobody".into()), ..prod() },
            Config { metrics_token: Some("short".into()), ..prod() },
            Config { metrics_token: Some("with space 0123456789".into()), ..prod() },
        ] {
            assert!(
                bad.validate().is_err(),
                "{:?} {:?} {:?}",
                bad.push_max_per_minute,
                bad.push_contact,
                bad.metrics_token
            );
        }
        let c = Config { push_contact: Some(" mailto:ops@example.org ".into()), ..prod() };
        assert_eq!(c.push_contact(), "mailto:ops@example.org");
        let json = serde_json::to_string(&Config { metrics_token: Some("0123456789abcdef".into()), ..prod() }).unwrap();
        assert!(!json.contains("0123456789abcdef"), "check-config never prints the token");
    }

    #[test]
    fn dev_defaults_are_valid() {
        let c = Config { dev: true, ..Config::defaults_for(true) };
        c.validate().unwrap();
        assert_eq!(c.domain, "localhost");
        assert_eq!(c.public_url(), "http://localhost:8080");
    }

    #[test]
    fn missing_domain_and_db_are_both_reported() {
        let c = Config::default();
        let err = c.validate().unwrap_err();
        assert_eq!(err.problems.len(), 2, "{err}");
        assert!(err.problems[0].contains("TAVRN_DOMAIN"));
        assert!(err.problems[1].contains("TAVRN_DATABASE_URL"));
    }

    #[test]
    fn domain_must_be_lowercase_without_port() {
        let c = Config { domain: "Chat.Example.org".into(), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("invalid"));
        let c = Config { domain: "chat.example.org:443".into(), ..prod() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn smtp_settings_are_validated() {
        let c = Config {
            smtp_url: Some("smtp://192.0.2.10:8025".into()),
            smtp_from: Some("noreply@example.test".into()),
            ..prod()
        };
        c.validate().unwrap();
        assert_eq!(c.smtp_from(), "noreply@example.test");
        assert_eq!(prod().smtp_from(), "noreply@chat.example.org");
        let c = Config { smtp_url: Some("ftp://x".into()), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_SMTP_URL"));
        let c = Config { smtp_from: Some("not a mailbox".into()), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_SMTP_FROM"));
    }

    #[test]
    fn gif_provider_requires_key() {
        let c = Config { gif_provider: GifProvider::Tenor, ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_GIF_API_KEY"));
        let c = Config { gif_provider: GifProvider::Tenor, gif_api_key: Some("k".into()), ..prod() };
        c.validate().unwrap();
    }

    #[test]
    fn captcha_requires_keys_and_flags() {
        let c = Config { captcha_provider: CaptchaProvider::Turnstile, ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_TURNSTILE_SITE_KEY"));
        let c = Config {
            captcha_provider: CaptchaProvider::Turnstile,
            turnstile_site_key: Some("s".into()),
            turnstile_secret_key: Some("k".into()),
            ..prod()
        };
        c.validate().unwrap();
        assert!(c.captcha_required(CaptchaAction::Register));
        assert!(!c.captcha_required(CaptchaAction::Login));
        assert!(!prod().captcha_required(CaptchaAction::Register), "never without a provider");
    }

    #[test]
    fn trusted_proxies_are_parsed_and_validated() {
        let c = prod();
        assert!(c.is_trusted_proxy("172.18.0.2".parse().unwrap()), "the Docker network is trusted by default");
        assert!(!c.is_trusted_proxy("203.0.113.5".parse().unwrap()));
        let c = Config { trusted_proxies: "203.0.113.5, 2001:db8::/32".into(), ..prod() };
        c.validate().unwrap();
        assert!(c.is_trusted_proxy("203.0.113.5".parse().unwrap()));
        assert!(c.is_trusted_proxy("2001:db8::1".parse().unwrap()));
        assert!(!c.is_trusted_proxy("127.0.0.1".parse().unwrap()));
        let c = Config { trusted_proxies: "not-a-net".into(), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_TRUSTED_PROXIES"));
    }

    #[test]
    fn sqlite_only_in_dev() {
        let c = Config { database_url: "sqlite://x.db".into(), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("SQLite"));
        let c = Config { dev: true, database_url: "sqlite://x.db".into(), ..prod() };
        c.validate().unwrap();
    }

    #[test]
    fn required_email_needs_smtp() {
        let c = Config { email: EmailMode::Required, ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_SMTP_URL"));
        let c = Config { email: EmailMode::Required, smtp_url: Some("smtp://x".into()), ..prod() };
        c.validate().unwrap();
    }

    #[test]
    fn port_range_is_parsed_and_validated() {
        assert_eq!(prod().rtc_udp_port_range(), Some((61000, 61100)));
        for bad in ["50100-50000", "abc", "80-90", "50000"] {
            let c = Config { rtc_udp_port_range: bad.into(), ..prod() };
            assert!(c.validate().is_err(), "{bad} should be invalid");
        }
    }

    #[test]
    fn screenshare_limits_are_validated() {
        let c = Config { screenshare_max_resolution: "8k".into(), ..prod() };
        assert!(c.validate().is_err());
        let c = Config { screenshare_max_fps: 0, ..prod() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn voice_settings_have_defaults_and_are_validated() {
        let c = prod();
        assert!(c.voice_enabled && c.camera_enabled && c.screenshare_enabled);
        assert_eq!((c.livekit_port, c.livekit_binary.as_str()), (7880, "livekit-server"));
        assert_eq!((c.camera_max_resolution.as_str(), c.camera_max_fps), ("720p", 30));
        assert_eq!(c.voice_max_participants, 50);
        assert_eq!(c.voice_reconnect_grace_secs, 45);
        // The cap leaves room for every client preset up to "Music" (stereo, 192 kbps); calls are speech and
        // get the default channel bitrate below it.
        assert_eq!((c.voice_max_bitrate_kbps, c.call_audio_bitrate_kbps()), (192, 64));
        assert_eq!(Config { voice_max_bitrate_kbps: 32, ..prod() }.call_audio_bitrate_kbps(), 32);
        assert_eq!(c.rtc_external_ip(), None);
        let bad = Config {
            camera_max_resolution: "4k".into(),
            camera_max_fps: 0,
            voice_max_participants: 0,
            voice_reconnect_grace_secs: 601,
            livekit_port: 80,
            rtc_external_ip: Some("not-an-ip".into()),
            livekit_binary: " ".into(),
            ..prod()
        };
        let err = bad.validate().unwrap_err();
        for var in [
            "TAVRN_CAMERA_MAX_RESOLUTION",
            "TAVRN_CAMERA_MAX_FPS",
            "TAVRN_VOICE_MAX_PARTICIPANTS",
            "TAVRN_VOICE_RECONNECT_GRACE_SECS",
            "TAVRN_LIVEKIT_PORT",
            "TAVRN_RTC_EXTERNAL_IP",
            "TAVRN_LIVEKIT_BINARY",
        ] {
            assert!(err.problems.iter().any(|p| p.contains(var)), "{var}: {err}");
        }
        let clash = Config { livekit_port: 8080, ..prod() };
        assert!(clash.validate().unwrap_err().problems[0].contains("TAVRN_LISTEN"));
        let ok = Config { rtc_external_ip: Some(" 203.0.113.7 ".into()), ..prod() };
        ok.validate().unwrap();
        assert_eq!(ok.rtc_external_ip(), Some("203.0.113.7"));
        assert_eq!(ok.listen_port(), 8080);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_VOICE_ENABLED", "false");
            jail.set_env("TAVRN_LIVEKIT_PORT", "7999");
            jail.set_env("TAVRN_CAMERA_ENABLED", "false");
            jail.set_env("TAVRN_RTC_EXTERNAL_IP", "2001:db8::1");
            let c = Config::load(false).unwrap();
            assert!(!c.voice_enabled && !c.camera_enabled);
            assert_eq!(c.livekit_port, 7999);
            assert_eq!(c.rtc_external_ip(), Some("2001:db8::1"));
            Ok(())
        });
    }

    #[test]
    fn rtc_connectivity_settings_have_defaults_and_are_validated() {
        let c = prod();
        assert_eq!((c.rtc_tcp_port, c.rtc_turn_enabled), (7881, false));
        assert_eq!(Config::defaults_for(true).rtc_tcp_port, 0, "development nodes share a machine");
        assert_eq!(c.rtc_turn_domain(), "turn.chat.example.org");
        assert_eq!(c.rtc_turn_relay_port_range(), Some((30000, 30999)));
        assert!(c.rtc_advertise_ips().is_empty() && c.rtc_stun_servers().is_empty());
        let ok = Config {
            rtc_advertise_ips: "2001:db8::5, 192.168.0.23".into(),
            rtc_stun_servers: "stun.example.org:3478,[2001:db8::1]:3478,192.0.2.1:19302".into(),
            rtc_turn_enabled: true,
            rtc_turn_domain: Some(" TURN.Example.org ".into()),
            ..prod()
        };
        ok.validate().unwrap();
        assert_eq!(ok.rtc_advertise_ips().len(), 2);
        assert_eq!(ok.rtc_turn_domain(), "turn.example.org");
        let bad = Config {
            rtc_external_ip: Some("0.0.0.0".into()),
            rtc_advertise_ips: "fe80::1,192.168.0.23,nope".into(),
            rtc_stun_servers: "stun.example.org".into(),
            rtc_tcp_port: 8080,
            rtc_turn_enabled: true,
            rtc_turn_udp_port: 61050,
            rtc_turn_tls_port: 7880,
            rtc_turn_relay_port_range: "61090-61200".into(),
            ..prod()
        };
        let err = bad.validate().unwrap_err();
        for needle in [
            "TAVRN_RTC_EXTERNAL_IP='0.0.0.0'",
            "TAVRN_RTC_ADVERTISE_IPS contains 'fe80::1'",
            "TAVRN_RTC_ADVERTISE_IPS contains 'nope'",
            "TAVRN_RTC_STUN_SERVERS",
            "TAVRN_RTC_TCP_PORT=8080 is already the port of TAVRN_LISTEN",
            "TAVRN_RTC_TURN_TLS_PORT=7880 is already the port of TAVRN_LIVEKIT_PORT",
            "TAVRN_RTC_TURN_UDP_PORT=61050 lies in the media range",
            "TAVRN_RTC_TURN_RELAY_PORT_RANGE overlaps",
        ] {
            assert!(err.problems.iter().any(|p| p.contains(needle)), "{needle}: {err}");
        }
        assert!(!err.problems.iter().any(|p| p.contains("'192.168.0.23'")), "LAN addresses are fine: {err}");
        // Hostnames (dynamic DNS) are accepted next to IP literals; mistyped addresses and bare names are not.
        let names = Config {
            rtc_external_ip: Some("Home.DynDNS.example.".into()),
            rtc_advertise_ips: "2001:db8::5, v6.home.example, 192.168.0.23,home.dyndns.example".into(),
            ..prod()
        };
        names.validate().unwrap();
        assert_eq!(
            names.rtc_advertise_entries(),
            vec![
                AdvertiseEntry::Host("home.dyndns.example".into()),
                AdvertiseEntry::Ip("2001:db8::5".parse().unwrap()),
                AdvertiseEntry::Host("v6.home.example".into()),
                AdvertiseEntry::Ip("192.168.0.23".parse().unwrap()),
            ],
            "external first, duplicates dropped"
        );
        assert_eq!(names.rtc_advertise_ips().len(), 2, "only the literals");
        for bad in ["300.1.1.1", "1.2.3", "localhost", "home_x.example", "-a.example", "a..example", "http://a.example"]
        {
            let c = Config { rtc_advertise_ips: bad.into(), ..prod() };
            assert!(c.validate().is_err(), "{bad}");
            assert!(c.rtc_advertise_entries().is_empty(), "{bad}");
            let c = Config { rtc_external_ip: Some(bad.into()), ..prod() };
            assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_RTC_EXTERNAL_IP"), "{bad}");
        }
        assert!(!prod().rtc_advertise_private);
        let none = Config { rtc_turn_enabled: true, rtc_turn_udp_port: 0, rtc_turn_tls_port: 0, ..prod() };
        assert!(none.validate().unwrap_err().problems[0].contains("needs TAVRN_RTC_TURN_UDP_PORT"));
        let low = Config { rtc_tcp_port: 443, ..prod() };
        assert!(low.validate().unwrap_err().problems[0].contains("TAVRN_RTC_TCP_PORT=443"));
        let same = Config { rtc_turn_enabled: true, rtc_turn_tls_port: 7881, ..prod() };
        assert!(same.validate().unwrap_err().problems[0].contains("port of TAVRN_RTC_TCP_PORT"));
        let domain = Config { rtc_turn_enabled: true, rtc_turn_domain: Some("bad domain".into()), ..prod() };
        assert!(domain.validate().unwrap_err().problems[0].contains("TAVRN_RTC_TURN_DOMAIN"));
        // TURN settings are not checked while TURN is off.
        Config { rtc_turn_relay_port_range: "x".into(), ..prod() }.validate().unwrap();
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_RTC_ADVERTISE_IPS", "2001:db8::5");
            jail.set_env("TAVRN_RTC_TCP_PORT", "0");
            jail.set_env("TAVRN_RTC_TURN_ENABLED", "true");
            jail.set_env("TAVRN_RTC_TURN_UDP_PORT", "3479");
            jail.set_env("TAVRN_RTC_ADVERTISE_PRIVATE", "true");
            let c = Config::load(false).unwrap();
            assert!(c.rtc_advertise_private);
            assert_eq!(c.rtc_advertise_ips(), vec!["2001:db8::5".parse::<std::net::IpAddr>().unwrap()]);
            assert_eq!((c.rtc_tcp_port, c.rtc_turn_enabled, c.rtc_turn_udp_port), (0, true, 3479));
            Ok(())
        });
    }

    #[test]
    fn webauthn_origin_defaults_to_the_public_url_and_is_validated() {
        assert_eq!(prod().webauthn_origin(), "https://chat.example.org");
        let dev = Config { dev: true, ..Config::defaults_for(true) };
        assert_eq!(dev.webauthn_origin(), "http://localhost:8080");
        for ok in ["http://localhost:5173", "https://chat.example.org", "https://app.chat.example.org/"] {
            let c = Config { webauthn_origin: Some(ok.into()), ..prod() };
            if ok.contains("localhost") {
                let c = Config { webauthn_origin: Some(ok.into()), ..dev.clone() };
                c.validate().unwrap();
                assert_eq!(c.webauthn_origin(), ok);
            } else {
                c.validate().unwrap();
            }
        }
        for bad in [
            "ftp://chat.example.org",
            "https://evil.example",
            "https://notchat.example.org",
            "https://chat.example.org/x",
            "not a url",
        ] {
            let c = Config { webauthn_origin: Some(bad.into()), ..prod() };
            assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_WEBAUTHN_ORIGIN"), "{bad}");
        }
    }

    #[test]
    fn webauthn_app_origins_are_validated_and_listed_after_the_web_origin() {
        // Fake hashes: 32 bytes of zeros and of 0x04 (`android:apk-key-hash:` + 43 base64url characters).
        let hash = "A".repeat(43);
        let debug = format!("{}A", "B".repeat(42));
        assert_eq!(
            prod().webauthn_origins(),
            vec!["https://chat.example.org".to_string()],
            "default: the web origin only"
        );
        assert!(prod().webauthn_app_origins().is_empty());
        let c = Config {
            webauthn_app_origins: format!(
                " android:apk-key-hash:{hash} , android:apk-key-hash:{debug},android:apk-key-hash:{hash}"
            ),
            ..prod()
        };
        c.validate().unwrap();
        assert_eq!(
            c.webauthn_origins(),
            vec![
                "https://chat.example.org".to_string(),
                format!("android:apk-key-hash:{hash}"),
                format!("android:apk-key-hash:{debug}"),
            ],
            "web origin first, app origins in their order, without duplicates"
        );
        for bad in [
            "https://chat.example.org".to_string(),
            "android:apk-key-hash:".to_string(),
            format!("android:apk-key-hash:{hash}="),
            format!("android:apk-key-hash:{}", &hash[1..]),
            format!("android:apk-key-hash:{}+", &hash[1..]),
            format!("android:apk-key-hash:{}/A", &hash[2..]),
            format!("android:apk-key-hash:{}B", &hash[1..]),
            "android:apk-key-hash:A4:5B:00:11".to_string(),
            "ios:bundle-id:org.tavrn.app".to_string(),
            format!("Android:apk-key-hash:{hash}"),
        ] {
            let c = Config { webauthn_app_origins: format!("android:apk-key-hash:{hash},{bad}"), ..prod() };
            let err = c.validate().unwrap_err();
            assert_eq!(err.problems.len(), 1, "{bad}: {err}");
            assert!(err.problems[0].contains("TAVRN_WEBAUTHN_APP_ORIGINS"), "{bad}: {err}");
        }
    }

    #[test]
    fn public_url_defaults_to_the_domain_and_accepts_any_host() {
        assert_eq!(prod().public_url(), "https://chat.example.org");
        assert_eq!(prod().public_host(), "chat.example.org");
        // Delegation: identity domain tavrn.org, app on another host.
        let tavrn = |url: &str| Config { domain: "tavrn.org".into(), public_url: Some(url.into()), ..prod() };
        for (url, normalized) in [
            ("https://app.tavrn.org", "https://app.tavrn.org"),
            ("https://app.tavrn.org/", "https://app.tavrn.org"),
            (" https://APP.tavrn.org ", "https://app.tavrn.org"),
            ("https://tavrn.org:8443", "https://tavrn.org:8443"),
            ("https://tavrn.org:443/", "https://tavrn.org"),
        ] {
            let c = tavrn(url);
            c.validate().unwrap();
            assert_eq!(c.public_url(), normalized, "{url}");
        }
        // Another host entirely: valid, but the default relying party id (the identity domain) does not
        // cover it, so passkeys need TAVRN_WEBAUTHN_RP_ID (see the WebAuthn test).
        let other = tavrn("https://chat.example.net");
        let err = other.validate().unwrap_err();
        assert_eq!(err.problems.len(), 1, "{err}");
        assert!(err.problems[0].contains("TAVRN_WEBAUTHN_RP_ID"), "{err}");
        let other = Config { webauthn_rp_id: Some("chat.example.net".into()), ..other };
        other.validate().unwrap();
        assert_eq!(other.public_url(), "https://chat.example.net");
        for bad in [
            "app.tavrn.org",
            "http://app.tavrn.org",
            "ftp://app.tavrn.org",
            "https://app.tavrn.org/chat",
            "https://app.tavrn.org/?x=1",
            "https://app.tavrn.org/#x",
            "https://user:pw@app.tavrn.org",
            "https://127.0.0.1",
            "https://[::1]:8443",
            "https://localhost",
            "https://app_x.tavrn.org",
            "not a url",
        ] {
            let err = tavrn(bad).validate().unwrap_err();
            assert!(err.problems[0].contains("TAVRN_PUBLIC_URL"), "{bad}: {err}");
        }
    }

    #[test]
    fn plain_http_and_ip_public_urls_only_in_dev_mode() {
        let dev = Config { dev: true, ..Config::defaults_for(true) };
        assert_eq!(dev.public_url(), "http://localhost:8080", "dev default: domain and listen port");
        for url in ["http://127.0.0.1:18081", "http://localhost:5173", "https://app.a.test", "http://[::1]:9000"] {
            let c = Config {
                public_url: Some(url.into()),
                webauthn_origin: Some("http://localhost:5173".into()),
                ..dev.clone()
            };
            c.validate().unwrap();
            assert_eq!(c.public_url(), url);
        }
        let c = Config { public_url: Some("http://127.0.0.1:18081".into()), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_PUBLIC_URL"));
        // An IP public URL in dev mode keeps the TURN default on the domain.
        let ip = Config { domain: "a.test".into(), public_url: Some("http://127.0.0.1:1".into()), ..dev };
        assert_eq!(ip.rtc_turn_domain(), "turn.a.test");
    }

    #[test]
    fn absolute_urls_use_the_public_url() {
        let c = Config { domain: "tavrn.org".into(), public_url: Some("https://app.tavrn.org".into()), ..prod() };
        c.validate().unwrap();
        assert_eq!(c.webauthn_origin(), "https://app.tavrn.org", "WebAuthn origin defaults to the public URL");
        assert_eq!(c.webauthn_rp_id(), "tavrn.org", "relying party id stays the identity domain");
        assert_eq!(c.rtc_turn_domain(), "turn.app.tavrn.org");
        assert_eq!(c.smtp_from(), "noreply@tavrn.org", "mail identity stays the domain");
    }

    #[test]
    fn webauthn_rp_id_must_be_a_registrable_suffix_of_the_origin_host() {
        let tavrn = |public: &str, origin: Option<&str>, rp: Option<&str>| Config {
            domain: "tavrn.org".into(),
            public_url: Some(public.into()),
            webauthn_origin: origin.map(String::from),
            webauthn_rp_id: rp.map(String::from),
            ..prod()
        };
        for (public, origin, rp) in [
            ("https://tavrn.org", None, None),
            ("https://app.tavrn.org", None, None),
            ("https://a.b.tavrn.org", None, Some("b.tavrn.org")),
            ("https://app.tavrn.org", Some("https://web.tavrn.org"), None),
            ("https://app.tavrn.org", None, Some("app.tavrn.org")),
            ("https://chat.example.net", None, Some("example.net")),
            ("https://app.tavrn.org", None, Some(" APP.tavrn.org ")),
        ] {
            let c = tavrn(public, origin, rp);
            let result = c.validate();
            assert!(result.is_ok(), "{public} {origin:?} {rp:?}: {:?}", result.err());
        }
        assert_eq!(tavrn("https://app.tavrn.org", None, Some(" APP.tavrn.org ")).webauthn_rp_id(), "app.tavrn.org");
        for (public, origin, rp) in [
            ("https://app.tavrn.org", None, Some("org")),
            ("https://app.tavrn.org", None, Some("other.org")),
            ("https://app.tavrn.org", None, Some("pp.tavrn.org")),
            ("https://tavrn.org", None, Some("app.tavrn.org")),
            ("https://app.tavrn.org", Some("https://evil.example"), None),
            ("https://notavrn.org", None, None),
            ("https://app.tavrn.org", None, Some("https://tavrn.org")),
        ] {
            let err = tavrn(public, origin, rp).validate().unwrap_err();
            assert!(err.problems[0].contains("TAVRN_WEBAUTHN_RP_ID"), "{public} {origin:?} {rp:?}: {err}");
        }
        // Development: localhost is a valid relying party id.
        let dev =
            Config { dev: true, webauthn_origin: Some("http://localhost:5173".into()), ..Config::defaults_for(true) };
        dev.validate().unwrap();
        assert_eq!(dev.webauthn_rp_id(), "localhost");
    }

    #[test]
    fn delegation_settings_load_from_the_environment() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "tavrn.org");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://x@db/x");
            jail.set_env("TAVRN_PUBLIC_URL", "https://app.tavrn.org");
            jail.set_env("TAVRN_WEBAUTHN_RP_ID", "tavrn.org");
            jail.set_env("TAVRN_FEDERATION_SRV_FALLBACK", "false");
            let c = Config::load(false).unwrap();
            assert_eq!((c.public_url(), c.webauthn_rp_id()), ("https://app.tavrn.org".into(), "tavrn.org".into()));
            assert!(!c.federation_srv_fallback);
            Ok(())
        });
        assert!(prod().federation_srv_fallback, "SRV fallback is on by default");
    }

    #[test]
    fn directory_settings() {
        let c = prod();
        assert!(c.reference_nodes().is_empty(), "no reference nodes unless TAVRN_REFERENCE_NODES is set");
        assert!(c.directory_listing);
        assert_eq!(c.directory_max_rooms, 5000);
        assert!(Config::defaults_for(true).reference_nodes().is_empty(), "development nodes never announce");
        for bad in ["localhost", "a.example:443", "https://a.example", "A.example", "10.0.0.1"] {
            let c = Config { reference_nodes: bad.into(), ..prod() };
            let err = c.validate().unwrap_err();
            assert!(err.problems[0].contains("TAVRN_REFERENCE_NODES"), "{bad}: {err}");
        }
        let c = Config { reference_nodes: String::new(), ..prod() };
        c.validate().unwrap();
        let c = Config { directory_max_rooms: 0, ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_DIRECTORY_MAX_ROOMS"));
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_REFERENCE_NODES", "ref.example,other.example");
            jail.set_env("TAVRN_DIRECTORY_LISTING", "false");
            jail.set_env("TAVRN_DIRECTORY_MAX_ROOMS", "12");
            let c = Config::load(false).unwrap();
            assert_eq!(c.reference_nodes(), vec!["ref.example", "other.example"]);
            assert!(!c.directory_listing);
            assert_eq!(c.directory_max_rooms, 12);
            Ok(())
        });
    }

    #[test]
    fn session_lifetimes_are_bounded() {
        let c = prod();
        assert_eq!((c.session_access_minutes, c.session_refresh_days, c.device_stale_days), (60, 90, 180));
        assert!(c.validate().is_ok());
        let msg = |c: Config| c.validate().unwrap_err().problems.join("\n");
        assert!(msg(Config { session_access_minutes: 4, ..prod() }).contains("TAVRN_SESSION_ACCESS_MINUTES"));
        assert!(msg(Config { session_access_minutes: 1441, ..prod() }).contains("TAVRN_SESSION_ACCESS_MINUTES"));
        assert!(msg(Config { session_refresh_days: 0, ..prod() }).contains("TAVRN_SESSION_REFRESH_DAYS"));
        assert!(msg(Config { device_stale_days: 36_501, ..prod() }).contains("TAVRN_DEVICE_STALE_DAYS"));
        assert!(Config { device_stale_days: 0, ..prod() }.validate().is_ok(), "0 switches the cleanup off");
        assert_eq!(c.e2ee_claims_per_target_per_hour, 60);
        for bad in [0, 10_001] {
            let c = Config { e2ee_claims_per_target_per_hour: bad, ..prod() };
            assert!(msg(c).contains("TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR"));
        }
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_SESSION_ACCESS_MINUTES", "15");
            jail.set_env("TAVRN_SESSION_REFRESH_DAYS", "30");
            jail.set_env("TAVRN_DEVICE_STALE_DAYS", "0");
            jail.set_env("TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR", "7");
            let c = Config::load(false).unwrap();
            assert_eq!((c.session_access_minutes, c.session_refresh_days, c.device_stale_days), (15, 30, 0));
            assert_eq!(c.e2ee_claims_per_target_per_hour, 7);
            Ok(())
        });
    }

    #[test]
    fn lists_are_split_and_trimmed() {
        let c = Config { reference_nodes: " a.example, b.example ,,".into(), ..prod() };
        assert_eq!(c.reference_nodes(), vec!["a.example", "b.example"]);
        assert!(c.admin_users().is_empty());
    }

    #[test]
    fn load_reads_env_overrides() {
        // Environment variables are process-wide; this test only sets its own and cleans up.
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_REGISTRATION", "open");
            jail.set_env("TAVRN_UPLOAD_MAX_BYTES", "1000");
            jail.set_env("TAVRN_DM_POLICY", "open");
            let c = Config::load(false).unwrap();
            assert_eq!(c.dm_policy, DmPolicy::Everyone, "open is the old name of everyone");
            assert_eq!(c.domain, "env.example");
            assert_eq!(c.registration, Registration::Open);
            assert_eq!(c.upload_max_bytes, 1000);
            Ok(())
        });
    }

    #[test]
    fn cache_settings_load_validate_and_hide_the_password() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_CACHE_URL", "redis://:s3cret@valkey:6379/1");
            jail.set_env("TAVRN_INSTANCE_ID", "tavrn-2");
            jail.set_env("TAVRN_INSTANCE_URL", "http://10.0.0.5:8080");
            let c = Config::load(false).unwrap();
            assert_eq!(c.cache_url.as_deref(), Some("redis://:s3cret@valkey:6379/1"));
            assert_eq!(c.instance_id.as_deref(), Some("tavrn-2"));
            let printed = serde_json::to_string(&c).unwrap();
            assert!(!printed.contains("s3cret"), "check-config never prints the password");
            assert!(printed.contains("redis://:***@valkey:6379/1"));
            Ok(())
        });
        let base = Config { domain: "x.example".into(), database_url: "postgres://x".into(), ..Config::default() };
        assert!(base.validate().is_ok(), "no cache is fine");
        for (field, bad) in [
            ("TAVRN_CACHE_URL", Config { cache_url: Some("valkey:6379".into()), ..base.clone() }),
            ("TAVRN_CACHE_URL", Config { cache_url: Some("http://valkey:6379".into()), ..base.clone() }),
            ("TAVRN_INSTANCE_ID", Config { instance_id: Some("a b".into()), ..base.clone() }),
            ("TAVRN_INSTANCE_URL", Config { instance_url: Some("ftp://x".into()), ..base.clone() }),
            ("TAVRN_INSTANCE_URL", Config { instance_url: Some("http://u:p@x:8080".into()), ..base.clone() }),
            ("TAVRN_INSTANCE_URL", Config { instance_url: Some("http://x:8080/api".into()), ..base.clone() }),
        ] {
            let err = bad.validate().unwrap_err();
            assert!(err.problems.iter().any(|p| p.starts_with(field)), "{field}: {err}");
            assert!(!err.to_string().contains("pw@"), "no credentials in messages");
        }
        let ok = Config {
            cache_url: Some("rediss://user:pw@cache.example:6380/0".into()),
            instance_id: Some("node-a.1".into()),
            instance_url: Some("http://tavrn-1:8080".into()),
            ..base.clone()
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn load_reads_entitlement_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_ATTACHMENT_RETENTION_DAYS", "30");
            jail.set_env("TAVRN_STREAM_MAX_HEIGHT", "720");
            jail.set_env("TAVRN_FILES_CHANNELS", "off");
            jail.set_env("TAVRN_UPLOAD_MAX_BYTES_CEILING", "104857600");
            let c = Config::load(false).unwrap();
            assert_eq!(c.attachment_retention_days, 30);
            assert_eq!(c.stream_max_height, 720);
            assert_eq!(c.files_channels, Switch::Off);
            assert_eq!(c.files_external, Switch::Off, "external stores are off by default");
            assert_eq!(c.upload_ceiling(), 104_857_600);
            assert_eq!(c.emoji_max_personal, 20);
            assert_eq!(c.sounds_max_personal, 10);
            assert_eq!(c.sounds_max_per_room, 50);
            jail.set_env("TAVRN_UPLOAD_MAX_BYTES_CEILING", "1000");
            jail.set_env("TAVRN_STREAM_MAX_FPS", "1000");
            let err = Config::load(false).unwrap_err().to_string();
            assert!(err.contains("TAVRN_UPLOAD_MAX_BYTES_CEILING"), "{err}");
            assert!(err.contains("TAVRN_STREAM_MAX_FPS"), "{err}");
            Ok(())
        });
        assert_eq!(Config::default().upload_ceiling(), Config::default().upload_max_bytes);
    }

    #[test]
    fn message_retention_is_validated() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            assert_eq!(Config::load(false).unwrap().retention_days, 0, "keep forever by default");
            jail.set_env("TAVRN_RETENTION_DAYS", "365");
            assert_eq!(Config::load(false).unwrap().retention_days, 365);
            jail.set_env("TAVRN_RETENTION_DAYS", "36501");
            let err = Config::load(false).unwrap_err().to_string();
            assert!(err.contains("TAVRN_RETENTION_DAYS must be between 0 and 36500"), "{err}");
            Ok(())
        });
    }

    #[test]
    fn load_reports_errors_from_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_SCREENSHARE_MAX_FPS", "999");
            jail.set_env("TAVRN_TRUSTED_PROXIES", "not-valid");
            let err = Config::load(false).unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_TRUSTED_PROXIES")));
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_SCREENSHARE_MAX_FPS")));
            Ok(())
        });
    }

    #[test]
    fn federation_defaults_match_the_spec() {
        let c = prod();
        assert!(c.federation_enabled);
        assert!(!c.federation_allow_private);
        assert!(c.federation_remote_bots);
        assert_eq!((c.federation_rate_logins, c.federation_rate_inbox), (60, 300));
        assert_eq!((c.federation_rate_api, c.federation_rate_claims), (3000, 120));
        assert_eq!((c.federation_max_remote_users, c.federation_max_remote_users_per_domain), (10_000, 1000));
        assert_eq!((c.federation_permit_timeout_secs, c.federation_max_unverified_peers), (10, 1000));
        assert_eq!(c.federation_discovery_slots, 12);
        assert_eq!(c.legal_notice_inbound_per_hour, 10);
        for (bad, var) in [
            (Config { federation_permit_timeout_secs: 0, ..prod() }, "TAVRN_FEDERATION_PERMIT_TIMEOUT_SECS"),
            (Config { federation_max_unverified_peers: 9, ..prod() }, "TAVRN_FEDERATION_MAX_UNVERIFIED_PEERS"),
            (Config { federation_discovery_slots: 65, ..prod() }, "TAVRN_FEDERATION_DISCOVERY_SLOTS"),
            (Config { legal_notice_inbound_per_hour: 0, ..prod() }, "TAVRN_LEGAL_NOTICE_INBOUND_PER_HOUR"),
        ] {
            assert!(bad.validate().unwrap_err().problems.iter().any(|p| p.contains(var)), "{var}");
        }
        assert!(c.federation_dev_peers().unwrap().is_empty());
        assert_eq!(c.federation_remote_user_retention_days, 90);
        assert!(!c.federation_notify_bans);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS", "30");
            jail.set_env("TAVRN_FEDERATION_NOTIFY_BANS", "true");
            let c = Config::load(false).unwrap();
            assert_eq!(c.federation_remote_user_retention_days, 30);
            assert!(c.federation_notify_bans);
            Ok(())
        });
    }

    #[test]
    fn federation_domain_lists_are_validated() {
        let c = Config { federation_blocklist: "evil.example, spam.example".into(), ..prod() };
        c.validate().unwrap();
        for bad in ["Evil.example", "evil.example:443", "127.0.0.1", "localhost", "https://evil.example"] {
            let c = Config { federation_blocklist: bad.into(), ..prod() };
            assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_FEDERATION_BLOCKLIST"), "{bad}");
            let c = Config { federation_allowlist: bad.into(), ..prod() };
            assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_FEDERATION_ALLOWLIST"), "{bad}");
        }
        let c = Config { federation_allowlist: " a.example ,b.example".into(), ..prod() };
        assert_eq!(c.federation_allowlist(), vec!["a.example", "b.example"]);
    }

    #[test]
    fn federation_dev_peers_only_in_dev_mode_and_well_formed() {
        let peers = "a.test=http://127.0.0.1:18081,b.test=http://127.0.0.1:18082";
        let c = Config { federation_dev_peers: peers.into(), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("--dev"), "refused without --dev");
        let c = Config { dev: true, federation_dev_peers: peers.into(), ..prod() };
        c.validate().unwrap();
        let map = c.federation_dev_peers().unwrap();
        assert_eq!(map["a.test"].as_str(), "http://127.0.0.1:18081/");
        assert_eq!(map["b.test"].port(), Some(18082));
        for bad in [
            "a.test",
            "a.test=ftp://127.0.0.1:1",
            "a.test=http://127.0.0.1:1/path",
            "a.test=http://user@127.0.0.1:1",
            "localhost=http://127.0.0.1:1",
            "a.test=not a url",
        ] {
            let c = Config { dev: true, federation_dev_peers: bad.into(), ..prod() };
            assert!(c.validate().unwrap_err().problems[0].contains("TAVRN_FEDERATION_DEV_PEERS"), "{bad}");
        }
    }

    #[test]
    fn federation_rates_must_be_positive() {
        let c = Config {
            federation_rate_logins: 0,
            federation_rate_inbox: 0,
            federation_rate_api: 0,
            federation_rate_claims: 0,
            ..prod()
        };
        let err = c.validate().unwrap_err();
        for var in ["LOGINS", "INBOX", "API", "CLAIMS"] {
            assert!(err.problems.iter().any(|p| p.contains(&format!("TAVRN_FEDERATION_RATE_{var}"))), "{err}");
        }
    }

    #[test]
    fn application_settings_load_and_validate() {
        let c = Config::default();
        assert_eq!(c.app_creation, AppCreation::All);
        assert_eq!((c.apps_per_user, c.app_token_max_days, c.app_rate_requests), (5, 365, 1200));
        assert_eq!(c.apps_per_room, 25);
        assert!(c.apps_federate && c.federation_remote_bots);
        assert!(!c.app_commands_require_approval);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_APP_CREATION", "admins");
            jail.set_env("TAVRN_APPS_PER_USER", "0");
            jail.set_env("TAVRN_APP_TOKEN_MAX_DAYS", "30");
            jail.set_env("TAVRN_APPS_FEDERATE", "false");
            jail.set_env("TAVRN_APP_COMMANDS_REQUIRE_APPROVAL", "true");
            let c = Config::load(false).unwrap();
            assert!(c.app_commands_require_approval);
            assert_eq!(c.app_creation, AppCreation::Admins);
            assert_eq!((c.apps_per_user, c.app_token_max_days), (0, 30));
            assert!(!c.apps_federate);
            assert!(c.federation_remote_bots, "the two switches are independent");
            jail.set_env("TAVRN_APPS_PER_USER", "101");
            jail.set_env("TAVRN_APPS_PER_ROOM", "1001");
            jail.set_env("TAVRN_APP_TOKEN_MAX_DAYS", "0");
            jail.set_env("TAVRN_APP_RATE_REQUESTS", "0");
            let err = Config::load(false).unwrap_err();
            for var in
                ["TAVRN_APPS_PER_USER", "TAVRN_APPS_PER_ROOM", "TAVRN_APP_TOKEN_MAX_DAYS", "TAVRN_APP_RATE_REQUESTS"]
            {
                assert!(err.problems.iter().any(|p| p.contains(var)), "{err}");
            }
            jail.set_env("TAVRN_APP_CREATION", "everyone");
            assert!(Config::load(false).is_err());
            Ok(())
        });
    }

    #[test]
    fn webhook_settings_load_and_validate() {
        let c = Config::default();
        assert!(c.webhooks_enabled && !c.app_allow_private_urls);
        assert_eq!(c.webhooks_per_channel, 10);
        assert!(Config::defaults_for(true).app_allow_private_urls, "development nodes allow local receivers");
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_WEBHOOKS_ENABLED", "false");
            jail.set_env("TAVRN_WEBHOOKS_PER_CHANNEL", "3");
            jail.set_env("TAVRN_APP_ALLOW_PRIVATE_URLS", "true");
            let c = Config::load(false).unwrap();
            assert!(!c.webhooks_enabled && c.app_allow_private_urls);
            assert_eq!(c.webhooks_per_channel, 3);
            for bad in ["0", "51"] {
                jail.set_env("TAVRN_WEBHOOKS_PER_CHANNEL", bad);
                let err = Config::load(false).unwrap_err();
                assert!(err.problems.iter().any(|p| p.contains("TAVRN_WEBHOOKS_PER_CHANNEL")), "{err}");
            }
            Ok(())
        });
    }

    #[test]
    fn legal_settings_load_and_validate() {
        let c = Config::default();
        assert!(!c.legal_notices.on());
        assert_eq!(
            (c.legal_notice_rate_per_hour, c.legal_notice_retention_days, c.legal_repeat_threshold),
            (5, 1095, 3)
        );
        assert_eq!((c.legal_counter_notice_days, c.account_delete_grace_days), (14, 30));
        assert_eq!(c.legal_terms_mode, TermsMode::Notice);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_LEGAL_NOTICES", "on");
            jail.set_env("TAVRN_LEGAL_TERMS_MODE", "require");
            jail.set_env("TAVRN_LEGAL_NOTICE_RETENTION_DAYS", "365");
            jail.set_env("TAVRN_LEGAL_REPEAT_THRESHOLD", "5");
            jail.set_env("TAVRN_ACCOUNT_DELETE_GRACE_DAYS", "7");
            let c = Config::load(false).unwrap();
            assert!(c.legal_notices.on());
            assert_eq!(c.legal_terms_mode, TermsMode::Require);
            assert_eq!((c.legal_notice_retention_days, c.legal_repeat_threshold), (365, 5));
            assert_eq!(c.account_delete_grace_days, 7);
            for (var, bad) in [
                ("TAVRN_LEGAL_NOTICE_RETENTION_DAYS", "10"),
                ("TAVRN_LEGAL_REPEAT_THRESHOLD", "0"),
                ("TAVRN_ACCOUNT_DELETE_GRACE_DAYS", "0"),
                ("TAVRN_LEGAL_COUNTER_NOTICE_DAYS", "400"),
                ("TAVRN_LEGAL_NOTICE_RATE_PER_HOUR", "0"),
            ] {
                jail.set_env(var, bad);
                let err = Config::load(false).unwrap_err();
                assert!(err.problems.iter().any(|p| p.contains(var)), "{err}");
                jail.set_env(var, "30");
            }
            jail.set_env("TAVRN_LEGAL_TERMS_MODE", "maybe");
            assert!(Config::load(false).is_err());
            Ok(())
        });
    }

    #[test]
    fn search_settings_load_and_validate() {
        let c = Config::default();
        assert!(c.search_enabled);
        assert_eq!(c.search_rate_per_minute, 30);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_SEARCH_ENABLED", "false");
            jail.set_env("TAVRN_SEARCH_RATE_PER_MINUTE", "5");
            let c = Config::load(false).unwrap();
            assert!(!c.search_enabled);
            assert_eq!(c.search_rate_per_minute, 5);
            for bad in ["0", "10001"] {
                jail.set_env("TAVRN_SEARCH_RATE_PER_MINUTE", bad);
                let err = Config::load(false).unwrap_err();
                assert!(err.problems.iter().any(|p| p.contains("TAVRN_SEARCH_RATE_PER_MINUTE")), "{err}");
            }
            Ok(())
        });
    }

    #[test]
    fn the_general_user_limit_is_on_in_production_and_off_in_development() {
        assert_eq!(Config::defaults_for(false).rate_user_per_minute, 1200);
        assert_eq!(Config::defaults_for(true).rate_user_per_minute, 0);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_RATE_USER_PER_MINUTE", "90");
            assert_eq!(Config::load(false).unwrap().rate_user_per_minute, 90);
            jail.set_env("TAVRN_RATE_LIMIT_IPV6_PREFIX", "56");
            jail.set_env("TAVRN_PASSWORD_HASH_CONCURRENCY", "3");
            jail.set_env("TAVRN_WS_MAX_SOCKETS_PER_USER", "5");
            jail.set_env("TAVRN_MEDIA_CACHE_MAX_BYTES", "1048576");
            jail.set_env("TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST", "65536");
            let c = Config::load(false).unwrap();
            assert_eq!((c.rate_limit_ipv6_prefix, c.password_hash_concurrency, c.ws_max_sockets_per_user), (56, 3, 5));
            assert_eq!((c.media_cache_max_bytes, c.media_cache_max_bytes_per_host), (1_048_576, 65_536));
            jail.set_env("TAVRN_RATE_LIMIT_IPV6_PREFIX", "16");
            assert!(Config::load(false).unwrap_err().to_string().contains("TAVRN_RATE_LIMIT_IPV6_PREFIX"));
            jail.set_env("TAVRN_RATE_LIMIT_IPV6_PREFIX", "64");
            jail.set_env("TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST", "2097152");
            assert!(Config::load(false).unwrap_err().to_string().contains("PER_HOST"));
            Ok(())
        });
    }

    #[test]
    fn load_reads_federation_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_FEDERATION_ALLOWLIST", "a.example");
            jail.set_env("TAVRN_FEDERATION_ALLOW_PRIVATE", "true");
            jail.set_env("TAVRN_FEDERATION_REMOTE_BOTS", "false");
            jail.set_env("TAVRN_FEDERATION_RATE_LOGINS", "5");
            jail.set_env("TAVRN_FEDERATION_RATE_API", "50");
            jail.set_env("TAVRN_FEDERATION_RATE_CLAIMS", "6");
            jail.set_env("TAVRN_FEDERATION_MAX_REMOTE_USERS_PER_DOMAIN", "7");
            let c = Config::load(false).unwrap();
            assert_eq!(c.federation_allowlist(), vec!["a.example"]);
            assert!(c.federation_allow_private);
            assert!(!c.federation_remote_bots);
            assert_eq!(c.federation_rate_logins, 5);
            assert_eq!((c.federation_rate_api, c.federation_rate_claims), (50, 6));
            assert_eq!(c.federation_max_remote_users_per_domain, 7);
            jail.set_env("TAVRN_FEDERATION_DEV_PEERS", "a.test=http://127.0.0.1:1");
            let err = Config::load(false).unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_FEDERATION_DEV_PEERS")), "{err}");
            Ok(())
        });
    }

    #[test]
    fn misbehave_flags_only_in_dev_mode_and_known() {
        let c = Config { dev_misbehave: "replay_ok".into(), ..prod() };
        let err = c.validate().unwrap_err();
        assert!(err.problems.iter().any(|p| p.contains("TAVRN_DEV_MISBEHAVE")), "{err}");
        assert!(!c.misbehaves("replay_ok"), "never outside --dev");
        let c = Config { dev: true, dev_misbehave: "replay_ok, no_rate_limit".into(), ..prod() };
        c.validate().unwrap();
        assert!(c.misbehaves("replay_ok") && c.misbehaves("no_rate_limit"));
        assert!(!c.misbehaves("plaintext_ok"));
        let c = Config { dev: true, dev_misbehave: "be_evil".into(), ..prod() };
        assert!(c.validate().unwrap_err().problems[0].contains("be_evil"));
        assert!(!Config::default().federation_require_conformance);
    }

    #[test]
    fn load_reads_conformance_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_FEDERATION_REQUIRE_CONFORMANCE", "true");
            assert!(Config::load(false).unwrap().federation_require_conformance);
            jail.set_env("TAVRN_DEV_MISBEHAVE", "plaintext_ok");
            let err = Config::load(false).unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_DEV_MISBEHAVE")), "{err}");
            Ok(())
        });
    }

    #[test]
    fn unknown_dm_policy_is_rejected() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_DM_POLICY", "anyone");
            let err = Config::load(false).unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("DM_POLICY")), "{err}");
            Ok(())
        });
        assert_eq!(Config::default().dm_policy, DmPolicy::Everyone, "users choose; their default is everyone_shared");
        assert!(DmPolicy::Friends < DmPolicy::EveryoneShared && DmPolicy::EveryoneShared < DmPolicy::Everyone);
        for s in DmPolicy::ALL {
            assert_eq!(DmPolicy::parse(s).as_str(), s);
        }
        assert_eq!(DmPolicy::parse("open"), DmPolicy::Everyone);
    }

    #[test]
    fn upload_settings_are_validated() {
        let c = prod();
        assert!(!c.upload_allow_executables);
        assert_eq!(c.upload_dm_categories(), crate::uploads::ALL);
        let err = Config { upload_dm_categories: "images,binaries".into(), ..prod() }.validate().unwrap_err();
        assert!(err.problems.iter().any(|p| p.contains("TAVRN_UPLOAD_DM_CATEGORIES")), "{err}");
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_UPLOAD_ALLOW_EXECUTABLES", "true");
            jail.set_env("TAVRN_UPLOAD_DM_CATEGORIES", "images, video");
            let c = Config::load(false).unwrap();
            assert!(c.upload_allow_executables);
            assert_eq!(c.upload_dm_categories(), crate::uploads::IMAGES | crate::uploads::VIDEO);
            Ok(())
        });
    }

    #[test]
    fn storage_encryption_and_preview_cap() {
        let c = prod();
        assert_eq!(c.storage_encryption, StorageEncryption::On, "encrypted at rest by default");
        assert_eq!(c.preview_auto_max_bytes, 5 * 1024 * 1024);
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_STORAGE_ENCRYPTION", "off");
            jail.set_env("TAVRN_PREVIEW_AUTO_MAX_BYTES", "1048576");
            let c = Config::load(false).unwrap();
            assert!(!c.storage_encryption.enabled());
            assert_eq!(c.preview_auto_max_bytes, 1024 * 1024);
            jail.set_env("TAVRN_STORAGE_ENCRYPTION", "maybe");
            assert!(Config::load(false).is_err(), "only on or off");
            Ok(())
        });
    }

    #[test]
    fn whiteboard_scene_limit_is_validated() {
        assert_eq!(prod().whiteboard_max_scenes, 50);
        assert!(Config { whiteboard_max_scenes: 1000, ..prod() }.validate().is_ok());
        for n in [0, 1001] {
            let err = Config { whiteboard_max_scenes: n, ..prod() }.validate().unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_WHITEBOARD_MAX_SCENES")), "{n}: {err}");
        }
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_WHITEBOARD_MAX_SCENES", "7");
            let c = Config::load(false).unwrap();
            assert_eq!(c.whiteboard_max_scenes, 7);
            Ok(())
        });
    }

    #[test]
    fn media_settings_are_validated() {
        let ok = Config { media_ffmpeg: "/usr/bin/ffmpeg".into(), media_workers: 2, ..prod() };
        assert!(ok.validate().is_ok());
        for (ffmpeg, workers) in [("relative/ffmpeg", 1), ("", 1), ("auto", 0), ("off", 9)] {
            let c = Config { media_ffmpeg: ffmpeg.into(), media_workers: workers, ..prod() };
            let err = c.validate().unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains("TAVRN_MEDIA")), "{ffmpeg} {workers}: {err}");
        }
    }

    fn sso() -> Config {
        Config {
            oidc_issuer: Some("https://idp.example/realms/tavrn".into()),
            oidc_client_id: Some("tavrn".into()),
            oidc_client_secret: Some("s3cret".into()),
            ..prod()
        }
    }

    #[test]
    fn oidc_settings_have_defaults_and_are_validated() {
        let c = prod();
        assert_eq!(c.oidc_issuer(), None);
        assert_eq!(c.oidc_scopes(), ["openid", "profile", "email", "groups"]);
        assert_eq!((c.oidc_session_days, c.oidc_group_sync, c.oidc_auto_provision), (7, OidcGroupSync::Add, true));
        sso().validate().unwrap();
        let problem = |c: Config, var: &str| {
            let err = c.validate().unwrap_err();
            assert!(err.problems.iter().any(|p| p.contains(var)), "{var}: {err}");
        };
        problem(Config { oidc_issuer: Some("http://idp.example".into()), ..sso() }, "TAVRN_OIDC_ISSUER");
        problem(Config { oidc_issuer: Some("https://idp.example/?x=1".into()), ..sso() }, "TAVRN_OIDC_ISSUER");
        problem(Config { oidc_issuer: Some("idp.example".into()), ..sso() }, "TAVRN_OIDC_ISSUER");
        problem(Config { oidc_client_id: None, ..sso() }, "TAVRN_OIDC_CLIENT_ID");
        problem(Config { oidc_scopes: "profile email".into(), ..sso() }, "TAVRN_OIDC_SCOPES");
        problem(Config { oidc_session_days: 0, ..sso() }, "TAVRN_OIDC_SESSION_DAYS");
        problem(Config { oidc_session_days: 31, ..sso() }, "TAVRN_OIDC_SESSION_DAYS");
        problem(
            Config { oidc_group_map: Some("{ \"g\": { \"room_creation\": -1 } }".into()), ..sso() },
            "TAVRN_OIDC_GROUP_MAP",
        );
        problem(
            Config { oidc_client_secret_file: Some("/nonexistent/secret".into()), oidc_client_secret: None, ..sso() },
            "TAVRN_OIDC_CLIENT_SECRET_FILE",
        );
        problem(Config { oidc_client_secret_file: Some("/etc/hostname".into()), ..sso() }, "both set");
        problem(Config { oidc_username_claim: " ".into(), ..sso() }, "TAVRN_OIDC_USERNAME_CLAIM");
        problem(Config { oidc_only: true, ..prod() }, "TAVRN_OIDC_ONLY");
        // http:// only in development mode.
        let dev = Config { dev: true, oidc_issuer: Some("http://127.0.0.1:9000".into()), ..sso() };
        dev.validate().unwrap();
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.set_env("TAVRN_OIDC_ISSUER", "https://auth.example/application/o/tavrn/");
            jail.set_env("TAVRN_OIDC_CLIENT_ID", "tavrn");
            jail.set_env("TAVRN_OIDC_CLIENT_SECRET", "very-secret");
            jail.set_env("TAVRN_OIDC_GROUP_SYNC", "sync");
            jail.set_env("TAVRN_OIDC_ONLY", "true");
            jail.set_env("TAVRN_OIDC_SCOPES", "openid,profile");
            let c = Config::load(false).unwrap();
            assert_eq!(c.oidc_issuer(), Some("https://auth.example/application/o/tavrn/"));
            assert_eq!(c.oidc_group_sync, OidcGroupSync::Sync);
            assert!(c.oidc_only);
            assert_eq!(c.oidc_scopes(), ["openid", "profile"]);
            // `check-config` prints the configuration: never the client secret.
            let printed = serde_json::to_string(&c).unwrap();
            assert!(!printed.contains("very-secret"), "{printed}");
            assert_eq!(c.oidc_client_secret.as_deref(), Some("very-secret"));
            Ok(())
        });
    }

    #[test]
    fn moderation_settings_load_and_validate() {
        let c = Config::default();
        assert_eq!((c.reports_rate_per_hour, c.reports_retention_days), (10, 90));
        assert_eq!((c.automod_words_file.as_deref(), c.automod_links.as_str()), (None, "off"));
        figment::Jail::expect_with(|jail| {
            jail.set_env("TAVRN_DOMAIN", "env.example");
            jail.set_env("TAVRN_DATABASE_URL", "postgres://u:p@h/db");
            jail.create_file("words.txt", "spam*\n# comment\n")?;
            jail.create_file("links.txt", "evil.test\n")?;
            jail.set_env("TAVRN_AUTOMOD_WORDS_FILE", "words.txt");
            jail.set_env("TAVRN_AUTOMOD_LINKS", "links.txt");
            jail.set_env("TAVRN_REPORTS_RATE_PER_HOUR", "20");
            jail.set_env("TAVRN_REPORTS_RETENTION_DAYS", "30");
            let c = Config::load(false).unwrap();
            assert_eq!((c.reports_rate_per_hour, c.reports_retention_days), (20, 30));
            assert_eq!((c.automod_words_file.as_deref(), c.automod_links.as_str()), (Some("words.txt"), "links.txt"));
            for (var, bad) in [
                ("TAVRN_REPORTS_RATE_PER_HOUR", "0"),
                ("TAVRN_REPORTS_RETENTION_DAYS", "0"),
                ("TAVRN_AUTOMOD_WORDS_FILE", "missing.txt"),
                ("TAVRN_AUTOMOD_LINKS", "missing.txt"),
            ] {
                let keep = std::env::var(var).unwrap_or_default();
                jail.set_env(var, bad);
                let err = Config::load(false).unwrap_err();
                assert!(err.problems.iter().any(|p| p.contains(var)), "{err}");
                jail.set_env(var, keep);
            }
            jail.set_env("TAVRN_AUTOMOD_LINKS", "off");
            assert!(Config::load(false).is_ok());
            Ok(())
        });
    }
}
