# tavrn-node operator handbook

Everything an operator needs to run a tavrn node, in the order you need it: from the requirements and the
installation through configuration, the reverse proxy, keys and backups, voice, federation, scaling and
monitoring to upgrades and a hardening checklist. Read it top to bottom once; later, jump to a section.

The commands below run in the directory that holds your `docker-compose.yml` and `.env`, with the container
named `tavrn` as in [`deploy/docker-compose.yml`](../deploy/docker-compose.yml). Protocol references
(`FEDERATION.md`, `VOICE.md`, …) point to the [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol)
repository, which is the `protocol/` submodule of this repository.

## Contents

1. [Requirements](#requirements)
2. [Install with Docker Compose](#install-with-docker-compose)
3. [Configuration](#configuration)
4. [Reverse proxy and TLS](#reverse-proxy-and-tls)
5. [Keys and backups](#keys-and-backups)
6. [Database](#database)
7. [Storage and media](#storage-and-media)
8. [Federation](#federation)
9. [Voice and video](#voice-and-video)
10. [Web push](#web-push)
11. [Metrics and health](#metrics-and-health)
12. [Scaling with Valkey](#scaling-with-valkey)
13. [Webhooks and applications](#webhooks-and-applications)
14. [Legal pages and GDPR](#legal-pages-and-gdpr)
15. [Moderation and auto-moderation](#moderation-and-auto-moderation)
16. [Threads and forum channels](#threads-and-forum-channels)
17. [The `doctor` and other CLI commands](#the-doctor-and-other-cli-commands)
18. [Logs and troubleshooting](#logs-and-troubleshooting)
19. [Upgrade and rollback](#upgrade-and-rollback)
20. [Security hardening checklist](#security-hardening-checklist)

## Requirements

| What | Details |
|---|---|
| **A Linux host with Docker** | Docker Engine with the Compose plugin. The node is one Rust process; the image adds `livekit-server` (voice and video) and a minimal static `ffmpeg` (media conversion). Hardware needs are modest; voice traffic is the part that grows with use. |
| **A domain** | `TAVRN_DOMAIN` is the identity of the node and part of every address (`alice@chat.example.org`). Addresses cannot be renamed later, so choose it with care. The node may run on another host than its identity domain ([delegation](#identity-domain-and-node-host-delegation)). |
| **A reverse proxy with TLS** | nginx, Caddy, Traefik or Nginx Proxy Manager. The node speaks plain HTTP only and never terminates TLS; nodes federate over HTTPS only. See [Reverse proxy and TLS](#reverse-proxy-and-tls). |
| **PostgreSQL** | The compose file runs `postgres:17-alpine` next to the node; any existing PostgreSQL server or managed service works too (`TAVRN_DATABASE_URL`). SQLite exists only for development (`--dev`). See [Database](#database). |
| **A data volume** | `./data`, mounted at `/data`: the node's keys and the uploaded files. Back it up together with the database ([Keys and backups](#keys-and-backups)). |
| **Ports for voice** | A UDP range (default `61000-61100`) and one TCP port (default `7881`) reachable from the internet, published 1:1 to the container and forwarded by the router. Optional: UDP `3478` for TURN, and TURN over TLS on 443 through the proxy. Voice can be switched off (`TAVRN_VOICE_ENABLED=false`). See [Voice and video](#voice-and-video). |
| **Outbound HTTPS** | Federation with other nodes, the reference nodes of the directory, link previews, web push to the browser vendors' push services, the SSO provider and the captcha or GIF provider when configured. |
| **Optional: SMTP** | E-mail confirmation, password resets and legal notices (`TAVRN_SMTP_URL`). Without it the node works without e-mail. |
| **Optional: Valkey or Redis ≥ 7** | Only to run one node as several instances behind a load balancer ([Scaling with Valkey](#scaling-with-valkey)). |

## Install with Docker Compose

1. Put [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) and [`deploy/.env.example`](../deploy/.env.example)
   into a directory on the host, and copy `.env.example` to `.env` there.
2. In `.env`, set at least `TAVRN_DOMAIN` and `POSTGRES_PASSWORD` (long and random), and decide on
   `TAVRN_REGISTRATION` (`invite` by default). If the node is served on another host than its identity domain,
   set `TAVRN_PUBLIC_URL` as well ([delegation](#identity-domain-and-node-host-delegation)).
3. Start it:

   ```sh
   docker compose up -d
   docker compose logs -f tavrn      # the node validates its configuration and names every problem
   ```

4. Point the reverse proxy at `127.0.0.1:8080` with WebSocket support ([Reverse proxy and TLS](#reverse-proxy-and-tls);
   examples in [`deploy/nginx.conf.example`](../deploy/nginx.conf.example) and
   [`deploy/Caddyfile.example`](../deploy/Caddyfile.example)).
5. Open the firewall for voice: the UDP range `TAVRN_RTC_UDP_PORT_RANGE` (default `61000-61100`) and
   `TAVRN_RTC_TCP_PORT` (default `7881`), published 1:1 and forwarded by the router.
6. Open `https://<your domain>` and register: **the first account becomes node admin** (as does every account
   named in `TAVRN_ADMIN_USERS`).
7. Check the configuration: `docker compose exec tavrn tavrn-node check-config` prints the effective
   configuration and checks the LiveKit binary and, with SSO, the provider. Then
   [verify the proxy](#verify-the-proxy) and run the connection test in the web client
   (*Settings → Voice & video → Test connection*).
8. Set up backups ([Keys and backups](#keys-and-backups)) before the node gets users.

What the compose file does:

- **`tavrn`**: the image `ghcr.io/just-tavrn/tavrn-node:${IMAGE_TAG:-latest}` (pin a release line with
  `IMAGE_TAG`, see [Upgrade and rollback](#upgrade-and-rollback)), HTTP published on
  `127.0.0.1:${TAVRN_HOST_PORT:-8080}` only (for a proxy on the same host; if the proxy runs as a container on the
  same Docker network, drop that line and use `tavrn:8080` as the target), the UDP media range and the ICE/TCP port
  published 1:1, the TURN lines commented out. It reads `.env`, builds `TAVRN_DATABASE_URL` from
  `POSTGRES_PASSWORD` unless you set it, mounts `./data` at `/data`, and runs with a read-only root file system and a
  `tmpfs` on `/tmp`. The image runs as the unprivileged user `tavrn` (uid 10001) under `tini`.
- **`db`**: `postgres:17-alpine` with its data in `./pgdata` and a health check; the node starts once it is
  healthy. For an external database remove this service and set `TAVRN_DATABASE_URL` in `.env`.
- **`valkey`** (commented out): only for several instances ([Scaling with Valkey](#scaling-with-valkey)).
- **`networks`** (commented out): an IPv6 subnet for the default network, for voice over IPv6
  ([Voice and video](#voice-and-video)).
- `TAVRN_REFERENCE_NODES` defaults to the project owner's public test node as an example; set it in `.env` to
  replace it, or to an empty value for none ([Getting listed in the directory](#getting-listed-in-the-directory)).

Many published UDP ports make Docker's userland proxy slow; with large ranges consider `network_mode: host`.

## Configuration

### How the configuration is loaded

Every setting is a `TAVRN_*` environment variable; in the compose setup they come from `.env`
([`deploy/.env.example`](../deploy/.env.example) is the annotated template). The node reads, later sources
overriding earlier ones:

1. the built-in defaults (the tables below),
2. an optional TOML file named by `TAVRN_CONFIG` (keys are the variable names without `TAVRN_` in lowercase,
   e.g. `registration = "open"`),
3. the `TAVRN_*` environment variables.

Every value is then validated, and **all** problems are printed together (`Configuration error:` with one line
per problem and the name of the variable); the process exits with code 2. Check a configuration without starting
the server: `docker compose exec tavrn tavrn-node check-config` (prints the effective configuration as JSON; the
Valkey password, the OIDC client secret and the metrics token are never printed).

On/off switches accept `true`/`false`; those documented as `on | off` accept `on`/`off` as well as
`true`/`false`. Lists are comma-separated. Sizes are in bytes.

`--dev` (or `TAVRN_DEV=true`) starts a development node with different defaults: domain `localhost`, listen
`127.0.0.1:8080`, SQLite in `data-dev/` (database `sqlite://data-dev/tavrn.db?mode=rwc`), data directory
`data-dev`, registration `open`, room creation `local`, log level `debug,sqlx=info`, no reference nodes,
`TAVRN_RTC_TCP_PORT=0`, private application URLs allowed and 1000 legal notices per hour; `http://` public URLs
and OIDC issuers, `TAVRN_FEDERATION_DEV_PEERS` and `TAVRN_DEV_MISBEHAVE` are only accepted there. Never run
`--dev` in production.

### Node identity, addresses and database

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_DOMAIN` | **required** | Identity domain of the node: addresses `alice@<domain>`, node keys, tokens. Lowercase, without scheme, path or port. Cannot be changed later without losing the node's identity. |
| `TAVRN_PUBLIC_URL` | `https://<TAVRN_DOMAIN>` | Where the node (web client, API, `/rtc`) is served: `https://<host>[:port]`, no path, query or fragment (`http://` and IP addresses only with `--dev`). Everything that builds absolute URLs uses it ([delegation](#identity-domain-and-node-host-delegation)). |
| `TAVRN_NAME` | `tavrn` | Display name of the node (directory, discovery document). |
| `TAVRN_DESCRIPTION` | empty | Short description of the node (directory). |
| `TAVRN_LISTEN` | `0.0.0.0:8080` | Address and port of the plain-HTTP server. |
| `TAVRN_TRUSTED_PROXIES` | `127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7` | IPs or CIDRs whose `X-Forwarded-For` is trusted. Connections from elsewhere are rate-limited and banned by their own address. Also decides who may read `/metrics` without a token. |
| `TAVRN_DATABASE_URL` | empty (compose: built from `POSTGRES_PASSWORD`) | `postgres://user:password@host:port/db` (or `postgresql://`). `sqlite:` only with `--dev`. |
| `TAVRN_DATA_DIR` | `/data` (image) | Directory for `keys/`, `blobs/` (stored files) and the generated LiveKit configuration. |
| `TAVRN_ADMIN_USERS` | empty | Comma-separated usernames with node admin rights (besides the first registered account). |
| `TAVRN_CONFIG` | unset | Path of an optional TOML configuration file (see above). |

### Registration, accounts and sessions

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_REGISTRATION` | `invite` | `open`, `invite` (account invites from the node administration) or `closed`. `closed` only blocks new accounts, never federation. |
| `TAVRN_EMAIL` | `optional` | `none`, `optional` or `required` (`required` needs `TAVRN_SMTP_URL`). |
| `TAVRN_SMTP_URL` | unset | `smtp://host:port` (plain, internal relay), `smtps://host:port` (TLS) or `smtp+starttls://host:port`, optionally `user:pass@`. Test it with `tavrn-node send-test-mail you@example.org`. |
| `TAVRN_SMTP_FROM` | `noreply@<TAVRN_DOMAIN>` | Sender address. |
| `TAVRN_CAPTCHA_PROVIDER` | `none` | `none` or `turnstile` (Cloudflare Turnstile). |
| `TAVRN_TURNSTILE_SITE_KEY`, `TAVRN_TURNSTILE_SECRET_KEY` | unset | Required with `TAVRN_CAPTCHA_PROVIDER=turnstile`. |
| `TAVRN_CAPTCHA_REGISTER` | `true` | Require the captcha at registration (only with a provider). |
| `TAVRN_CAPTCHA_LOGIN` | `false` | Require the captcha at login (only with a provider). |
| `TAVRN_WEBAUTHN_ORIGIN` | the public URL | Origin of the web client for passkeys. Override only for development and tests (e.g. `http://localhost:5173`). |
| `TAVRN_WEBAUTHN_RP_ID` | `TAVRN_DOMAIN` | Relying party id of passkeys; must be the host of the origin or a parent domain of it, otherwise the node refuses to start. Changing it later invalidates every registered passkey ([Passkeys](#passkeys)). |
| `TAVRN_SESSION_ACCESS_MINUTES` | `60` | Access token lifetime (5–1440). |
| `TAVRN_SESSION_REFRESH_DAYS` | `90` | Sliding refresh token lifetime (1–3650); every refresh extends it. SSO sessions keep `TAVRN_OIDC_SESSION_DAYS` as their hard end, federated sessions their 7 days. |
| `TAVRN_DEVICE_STALE_DAYS` | `180` | Devices unused this long are deleted by the hourly housekeeping (never a user's only device, never one with a live session); 0–36500, `0` = never. |
| `TAVRN_DM_POLICY` | `everyone` | Upper bound of every user's "Who can message me": `friends`, `everyone_shared` (friends and shared rooms) or `everyone` (`open` is the old name). Users choose within it (their default is `everyone_shared`); non-friends land in the recipient's message requests; blocks always apply. |

The second factor (TOTP or passkeys) is mandatory for every account and cannot be switched off.

### Single sign-on (OpenID Connect)

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_OIDC_ISSUER` | unset | Issuer URL of the OpenID provider; SSO is on when set. `https://` only (`http://` with `--dev`), must match the provider's `issuer` exactly. |
| `TAVRN_OIDC_CLIENT_ID` | unset | Client id at the provider (required with an issuer). |
| `TAVRN_OIDC_CLIENT_SECRET` | unset | Client secret of a confidential client (never printed). Use this **or** the file variant. |
| `TAVRN_OIDC_CLIENT_SECRET_FILE` | unset | File holding the client secret (keeps it out of the environment), e.g. `/data/keys/oidc-client-secret`. |
| `TAVRN_OIDC_SCOPES` | `openid profile email groups` | Requested scopes (space or comma separated); must contain `openid`. |
| `TAVRN_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim the username of new accounts comes from (sanitized, `-2` appended on a collision). |
| `TAVRN_OIDC_DISPLAY_NAME_CLAIM` | `name` | Claim the display name comes from (updated on every login). |
| `TAVRN_OIDC_GROUPS_CLAIM` | `groups` | Claim holding the groups (array of strings), from the ID token or UserInfo. |
| `TAVRN_OIDC_BUTTON_LABEL` | empty | Text of the login button (at most 64 characters); empty: the client's "Sign in with SSO". |
| `TAVRN_OIDC_ONLY` | `false` | `true`: password and passkey logins and registration only for `TAVRN_ADMIN_USERS` (break-glass accounts). |
| `TAVRN_OIDC_AUTO_PROVISION` | `true` | Create accounts on the first SSO login. |
| `TAVRN_OIDC_GROUP_MAP` | unset | JSON group → rights map, e.g. `{"it-admins":{"node_admin":true},"staff":{"room_creation":5}}`; when set, the admin API cannot change it. |
| `TAVRN_OIDC_GROUP_SYNC` | `add` | `add` grants only; `sync` also revokes what an earlier sync granted (never manual grants). |
| `TAVRN_OIDC_SESSION_DAYS` | `7` | Hard end of an SSO session in days (1–30). |

Setting it up with a provider (protocol: APPLICATIONS.md §8):

1. Create a confidential OAuth2/OpenID client at the provider with the **authorization code flow and PKCE
   (S256)** and register exactly this redirect URI: `<TAVRN_PUBLIC_URL>/api/v1/auth/oidc/callback` (by default
   `https://<TAVRN_DOMAIN>/api/v1/auth/oidc/callback`). As post-logout redirect URI register
   `<TAVRN_PUBLIC_URL>/login`. Sign ID tokens with RS256, PS256, ES256 or EdDSA (never HS256). Add a `groups`
   claim if you want the group mapping.
   - **Keycloak**: client type OpenID Connect, client authentication on, standard flow only, "PKCE method"
     S256. For groups add a "Group Membership" mapper (token claim name `groups`, "Full group path" off).
     Issuer: `https://keycloak.example/realms/<realm>`.
   - **Authentik**: provider type "OAuth2/OpenID Provider", client type confidential, signing key set (RS256).
     The default scope mappings include `groups`. Issuer: `https://authentik.example/application/o/<slug>/`
     (with the trailing slash, exactly as shown in the provider's overview).
2. Configure the node (secrets preferably through a file):

   ```bash
   TAVRN_OIDC_ISSUER=https://keycloak.example/realms/company
   TAVRN_OIDC_CLIENT_ID=tavrn
   TAVRN_OIDC_CLIENT_SECRET_FILE=/data/keys/oidc-client-secret
   # optional:
   TAVRN_OIDC_BUTTON_LABEL=Sign in with Company SSO
   TAVRN_OIDC_GROUP_MAP={"it-admins":{"node_admin":true},"staff":{"room_creation":5},"devs":{"rooms":[{"room":"01J…","roles":["01J…"]}]}}
   TAVRN_OIDC_GROUP_SYNC=add          # sync also revokes what an earlier sync granted (never manual grants)
   TAVRN_OIDC_ONLY=false              # true: password logins only for TAVRN_ADMIN_USERS (break-glass)
   ```

3. Check it: `docker compose exec tavrn tavrn-node check-config` fetches the provider's discovery document and
   keys and prints the redirect URI to register.

Notes: provider requests use verified TLS, follow no redirects and may target LAN addresses. An unreachable
provider never stops the node (it is contacted on demand). SSO logins need no tavrn second factor (the provider
is responsible), but end-to-end encryption still asks for the recovery key on the first login. Existing password
accounts link their provider identity themselves in *Settings → Security* (the node never links by e-mail or
username). Without `TAVRN_OIDC_GROUP_MAP` admins edit the mapping through `PUT /api/v1/admin/sso/group-map`;
group changes take effect at the next SSO login, at the latest after `TAVRN_OIDC_SESSION_DAYS`. With
`TAVRN_OIDC_ONLY=true` keep at least one account in `TAVRN_ADMIN_USERS`, so an outage of the provider cannot lock
you out; those names are never given to accounts created by SSO. `TAVRN_OIDC_CLIENT_ID`, `TAVRN_OIDC_ONLY` or
`TAVRN_OIDC_GROUP_MAP` without an issuer is a configuration error.

### Rooms, uploads and storage

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_ROOM_CREATION` | `invite` | Who may create rooms: `none` (node admins only), `invite` (node admins and users with a room-creation grant), `local` (every local user) or `federated` (also users of other nodes signed in through federation). |
| `TAVRN_MAX_ROOMS_PER_USER` | `5` | Rooms a user may own (entitlement `rooms.max_owned`; 0–1000000, `0` = unlimited). |
| `TAVRN_UPLOADS_ENABLED` | `true` | `false` switches file uploads off. |
| `TAVRN_UPLOAD_MAX_BYTES` | `26214400` (25 MiB) | Largest upload (entitlement `upload.max_bytes`); must be > 0 while uploads are on. The proxy must allow bodies at least this large. |
| `TAVRN_UPLOAD_ALLOWED_TYPES` | `image/*,video/*,audio/*,application/pdf,text/plain,application/zip` | Allowed MIME types, wildcards like `image/*` allowed. |
| `TAVRN_UPLOAD_ALLOW_EXECUTABLES` | `false` | Executables, scripts, installers and disk images (`exe`, `msi`, `bat`, `sh`, `jar`, `apk`, `dmg`, `iso`, …; PROTOCOL.md §7a) are refused unless this is `true` **and** the member's upload categories (role setting) include `other`. |
| `TAVRN_UPLOAD_DM_CATEGORIES` | `images,audio,video,documents,archives,other` | Upload categories in DMs and group DMs hosted here. |
| `TAVRN_STORAGE_QUOTA_PER_ROOM_BYTES` | `10737418240` (10 GiB) | Storage per room (entitlement `storage.max_bytes_per_room`). |
| `TAVRN_STORAGE_ENCRYPTION` | `on` | Encryption at rest of every stored file; `off` stores new files unencrypted (debugging only; encrypted files stay readable). See [Storage and media](#storage-and-media). |
| `TAVRN_RETENTION_DAYS` | `0` | Accepted for compatibility; this version does not use it. File retention is `TAVRN_ATTACHMENT_RETENTION_DAYS`. |
| `TAVRN_EMOJI_MAX_PER_ROOM` | `100` | Custom emojis per room (entitlement `emoji.max_per_room`). |
| `TAVRN_EMOJI_MAX_BYTES` | `262144` (256 KiB) | Largest custom emoji file. |
| `TAVRN_PREVIEW_AUTO_MAX_BYTES` | `5242880` (5 MiB) | Images up to this size load as previews by themselves where the user's setting allows it (always / friends and shared rooms / never); larger ones show a placeholder with a "Load" button. `0` = never automatically. |
| `TAVRN_MEDIA_CACHE_UNUSED_DAYS` | `365` | Cached copies of other nodes' custom emojis and soundboard clips are evicted after this many days without use; `0` = never. |

### Entitlement defaults

Entitlements (protocol: ENTITLEMENTS.md) are the per-user and per-room limits. The values here and the ones
marked "entitlement" above are the node defaults; node admins extend them per user or room with plans and grants
(admin page "Entitlements" or the admin API with a `tavrn_adm_` token). `0` = unlimited unless noted.

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_UPLOAD_MAX_BYTES_CEILING` | `0` | Largest upload a grant can allow; `0` = `TAVRN_UPLOAD_MAX_BYTES` (grants cannot raise it). Otherwise at least `TAVRN_UPLOAD_MAX_BYTES`; also the body limit of the upload routes. |
| `TAVRN_VOICE_CHANNEL_MAX_PARTICIPANTS` | `0` | `voice.max_participants` per voice channel (0–1000; `0` = only `TAVRN_VOICE_MAX_PARTICIPANTS`). |
| `TAVRN_STREAM_MAX_HEIGHT` | `0` | `stream.max_height`, screen share height in pixels (0–4320; `0` = only `TAVRN_SCREENSHARE_MAX_RESOLUTION`). Enforced by the clients. |
| `TAVRN_STREAM_MAX_FPS` | `0` | `stream.max_fps` (0–240; `0` = only `TAVRN_SCREENSHARE_MAX_FPS`). Enforced by the clients. |
| `TAVRN_CAMERA_MAX_HEIGHT` | `0` | `camera.max_height` in pixels (0–4320; `0` = only `TAVRN_CAMERA_MAX_RESOLUTION`). Enforced by the clients. |
| `TAVRN_EMOJI_MAX_PERSONAL` | `20` | `emoji.max_personal`, personal emojis per user (0–100000). |
| `TAVRN_SOUNDS_MAX_PER_ROOM` | `50` | `sounds.max_per_room`, soundboard clips per room (0–100000). |
| `TAVRN_SOUNDS_MAX_PERSONAL` | `10` | `sounds.max_personal`, personal soundboard clips (0–100000). |
| `TAVRN_ATTACHMENT_RETENTION_DAYS` | `0` | `attachments.retention_days`: attachments of channels and DMs are deleted this many days after the upload by the hourly housekeeping; messages keep listing them as "file expired". Pinned messages keep their files. Rooms may only shorten it. 0–36500, `0` = keep forever. |
| `TAVRN_FILES_CHANNELS` | `on` | `files_channels.enabled`: files channels may be created (`on`/`off`). |
| `TAVRN_FILES_CHANNELS_MAX_BYTES` | `0` | `files_channels.max_bytes`, storage per files channel. |
| `TAVRN_FILES_EXTERNAL` | `off` | Files channels on external WebDAV/S3 stores (protocol: FILES.md §5). |
| `TAVRN_FILES_EXTERNAL_PRIVATE` | `off` | `on` also allows external stores on private, loopback or link-local addresses and plain `http` (stores in the LAN); this disables the SSRF protection for them. |

### Media, previews and search

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_MEDIA_FFMPEG` | `auto` | Media pipeline for avatars, profile headers, room icons and video backgrounds: `auto` (ffmpeg from `PATH`; the image ships one), `off` (only static PNG/JPEG/WebP, no animations or video input) or an absolute path to ffmpeg. |
| `TAVRN_MEDIA_WORKERS` | `1` | Concurrent conversions (1–8); a few more uploads wait, the rest get `503 media.busy`. |
| `TAVRN_WHITEBOARD_MAX_SCENES` | `50` | Whiteboard scenes per user in the encrypted library (1–1000, at most 5 MB each). |
| `TAVRN_GIF_PROVIDER` | `none` | GIF search: `none`, `giphy` or `tenor`. The API key stays on the node; clients only ask the node. |
| `TAVRN_GIF_API_KEY` | unset | Required with a GIF provider. |
| `TAVRN_UNFURL` | `on` | Link previews: the sender's client asks this node to load a linked page (public addresses only, 5 s, 1 MiB of HTML, image downscaled to a 40 KiB WebP) and puts the preview into the message. The node sees the URLs its users preview; readers never fetch anything. `off`: no previews from this node (`404 unfurl.disabled`). |
| `TAVRN_SEARCH_ENABLED` | `true` | Node-side message search over **unencrypted** channels (protocol: SEARCH.md); `false` removes the route (`404 search.disabled`) and stops indexing. Encrypted conversations are only searched in the clients' local encrypted index. |
| `TAVRN_SEARCH_RATE_PER_MINUTE` | `30` | Search requests per user and minute (1–10000). |

### Voice and video settings

The node starts and supervises `livekit-server` with a configuration generated from these values
([Voice and video](#voice-and-video) explains ports and addresses).

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_VOICE_ENABLED` | `true` | `false`: no voice channels, no LiveKit process. |
| `TAVRN_VOICE_MAX_BITRATE_KBPS` | `96` | Audio bitrate cap for every voice channel (8–512). |
| `TAVRN_VOICE_MAX_PARTICIPANTS` | `50` | Participants per voice channel at most (1–1000); channel user limits apply below it. |
| `TAVRN_VOICE_RECONNECT_GRACE_SECS` | `45` | A dropped participant stays "reconnecting" this long (0–600; `0` = leave at once). |
| `TAVRN_SCREENSHARE_ENABLED` | `true` | Screen sharing. |
| `TAVRN_SCREENSHARE_MAX_RESOLUTION` | `1080p` | `720p`, `1080p`, `1440p` or `4k`. |
| `TAVRN_SCREENSHARE_MAX_FPS` | `30` | 1–60. |
| `TAVRN_CAMERA_ENABLED` | `true` | Webcam sharing (the `use_camera` permission still applies). |
| `TAVRN_CAMERA_MAX_RESOLUTION` | `720p` | `360p`, `720p` or `1080p`. |
| `TAVRN_CAMERA_MAX_FPS` | `30` | 1–60. |
| `TAVRN_RTC_UDP_PORT_RANGE` | `61000-61100` | UDP media ports (`from-to`, from < to, both > 1024), published 1:1. Keep it outside the Linux ephemeral range 32768–60999. |
| `TAVRN_RTC_EXTERNAL_IP` | unset | Public address LiveKit announces (IPv4, or a hostname resolved at start and every minute). Empty together with `TAVRN_RTC_ADVERTISE_IPS`: detected via STUN (IPv4 and IPv6). |
| `TAVRN_RTC_ADVERTISE_IPS` | empty | More addresses, comma-separated (IPs or hostnames): the first IPv4 and the first IPv6 (with `TAVRN_RTC_EXTERNAL_IP`) replace the container's private addresses, every further one is handed to clients as an extra candidate. No link-local, multicast or `0.0.0.0` addresses. |
| `TAVRN_RTC_ADVERTISE_PRIVATE` | `false` | `true`: private addresses (LAN, ULA) that hostnames resolve to are announced too (IP literals are always taken as configured). |
| `TAVRN_RTC_STUN_SERVERS` | empty (LiveKit's defaults) | `host:port` list for the address detection. |
| `TAVRN_RTC_TCP_PORT` | `7881` | ICE over TCP, the fallback when UDP is blocked; publish and forward it like the UDP range. `0` = off, otherwise 1025–65535 and different from the other TCP ports. |
| `TAVRN_RTC_TURN_ENABLED` | `false` | LiveKit's embedded TURN server for clients behind strict NATs or firewalls. Needs at least one of the two TURN ports. |
| `TAVRN_RTC_TURN_UDP_PORT` | `3478` | TURN over UDP, published and forwarded (`0` = off); must not lie in the media range. |
| `TAVRN_RTC_TURN_TLS_PORT` | `5349` | Plain TCP port behind the proxy's TLS termination for TURN over TLS on 443 (`0` = off). |
| `TAVRN_RTC_TURN_DOMAIN` | `turn.<host of TAVRN_PUBLIC_URL>` | Name clients use for `turns:<domain>:443` (`turn.<TAVRN_DOMAIN>` when the public URL's host is an IP address). |
| `TAVRN_RTC_TURN_RELAY_PORT_RANGE` | `30000-30999` | Relay sockets of the TURN server inside the container (not published); must not overlap the media range. |
| `TAVRN_LIVEKIT_PORT` | `7880` | LiveKit's signaling/API port on `127.0.0.1` inside the container (1025–65535, not the `TAVRN_LISTEN` port). Never published; clients use `/rtc`. |
| `TAVRN_LIVEKIT_BINARY` | `livekit-server` | Path or name in `PATH` of the LiveKit binary (outside Docker: `just livekit-install`). |

### Federation and directory settings

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_FEDERATION_ENABLED` | `true` | `false`: no federation tokens, federated logins, inbox or outbox. |
| `TAVRN_REFERENCE_NODES` | empty (compose and `.env.example`: an example node) | Comma-separated domains of the reference nodes this node announces itself to and pulls the node list from ([directory](#getting-listed-in-the-directory)). Lowercase, at least one dot, no port. |
| `TAVRN_DIRECTORY_LISTING` | `true` | `false`: never announce; other nodes refuse to list this node. |
| `TAVRN_DIRECTORY_MAX_ROOMS` | `5000` | Cached rooms of other nodes for Discover in total (at most 200 per node; > 0). |
| `TAVRN_FEDERATION_BLOCKLIST` | empty | Domains never federated with (also blocks their subdomains). |
| `TAVRN_FEDERATION_ALLOWLIST` | empty | If set, federate only with these domains (the blocklist still wins). |
| `TAVRN_FEDERATION_ALLOW_PRIVATE` | `false` | `true` allows peers on private or loopback addresses (development, tests, closed intranets). |
| `TAVRN_FEDERATION_SRV_FALLBACK` | `true` | When a peer's identity domain serves no `/.well-known/tavrn` (404, or no HTTPS server at all), look up `_tavrn._tcp.<domain>` SRV and fetch the document from its target ([SRV record](#srv-record-instead-of-the-well-known-file)). |
| `TAVRN_FEDERATION_REMOTE_BOTS` | `true` | Accept bots of other nodes. |
| `TAVRN_FEDERATION_RATE_LOGINS` | `60` | Federated logins per remote domain and minute (> 0). |
| `TAVRN_FEDERATION_RATE_INBOX` | `300` | Inbox messages per remote domain and minute (> 0). |
| `TAVRN_FEDERATION_RATE_API` | `3000` | API requests of all users of one remote domain per minute (> 0). |
| `TAVRN_FEDERATION_RATE_CLAIMS` | `120` | KeyPackage claims per requesting node and minute (> 0). |
| `TAVRN_FEDERATION_MAX_REMOTE_USERS` | `10000` | Remote users in total. |
| `TAVRN_FEDERATION_MAX_REMOTE_USERS_PER_DOMAIN` | `1000` | Remote users per home domain. |
| `TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS` | `90` | Remote users without a federated login for this many days and with nothing left on this node (no memberships, friendships, blocks, messages, …) are deleted by the hourly housekeeping; `0` keeps them forever. |
| `TAVRN_FEDERATION_NOTIFY_BANS` | `false` | `true`: tell the home node of a remote user that a room or node ban removed them from a room (`ban.notify`, information only, never the reason). |
| `TAVRN_FEDERATION_REQUIRE_CONFORMANCE` | `false` | `true`: also refuse federated logins and inbox messages of nodes that were not checked yet or failed ([conformance checks](#conformance-checks-of-other-nodes)). |
| `TAVRN_FEDERATION_DEV_PEERS` | empty | Development only (refused without `--dev`): `domain=http://host:port` pairs for local multi-node setups. |
| `TAVRN_DEV_MISBEHAVE` | empty | Development only (refused without `--dev`): a node that breaks the protocol on purpose for conformance tests (`accept_bad_signatures`, `replay_ok`, `plaintext_ok`, `no_rate_limit`). Never in production. |

### Applications, bots and webhooks settings

Bot tokens are a single factor: rooms, categories and channels can be declared "no bots" in their settings
(protocol: APPLICATIONS.md §1.2, §9.6). Details: [Webhooks and applications](#webhooks-and-applications).

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_APP_CREATION` | `all` | Who may create applications: `all` (every local user with a full session), `invite` (users with an application grant from an admin) or `admins`. |
| `TAVRN_APPS_PER_USER` | `5` | Applications per owner (0–100); node admins are not exempt. |
| `TAVRN_APPS_PER_ROOM` | `25` | Installed applications per room (0–1000). |
| `TAVRN_APP_TOKEN_MAX_DAYS` | `365` | Maximum app token lifetime (1–3650 days). |
| `TAVRN_APP_RATE_REQUESTS` | `1200` | API requests (REST and WebSocket operations) per application and minute (> 0). |
| `TAVRN_APPS_FEDERATE` | `true` | This node's bots may obtain federation tokens for other nodes. |
| `TAVRN_APP_ALLOW_PRIVATE_URLS` | `false` (`--dev`: `true`) | Application URLs (interactions URL, event subscriptions) on private or loopback addresses (intranets; turns the SSRF protection off for them). |
| `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL` | `false` | Node admins approve every application command definition before it is offered in this node's rooms (a changed definition is pending again). |
| `TAVRN_WEBHOOKS_ENABLED` | `true` | Incoming webhooks; `false` refuses creation and execution (`webhook.disabled`). |
| `TAVRN_WEBHOOKS_PER_CHANNEL` | `10` | Webhooks per channel (1–50; a room has at most 50). |

### Moderation settings

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_AUTOMOD_BURST_LIMIT` | `10` | More than this many messages of a user per channel within 5 seconds count as spam (`0` = off). |
| `TAVRN_AUTOMOD_TIMEOUT_MINUTES` | `10` | Timeout in minutes after a spam burst. |

<!-- TODO(merge): complete after the threads/moderation merge -->
Reports and content auto-moderation add `TAVRN_REPORTS_RETENTION_DAYS`, `TAVRN_REPORTS_RATE_PER_HOUR`,
`TAVRN_AUTOMOD_WORDS_FILE` and `TAVRN_AUTOMOD_LINKS`; see [Moderation and auto-moderation](#moderation-and-auto-moderation).

### Legal settings

Details: [Legal pages and GDPR](#legal-pages-and-gdpr).

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_LEGAL_NOTICES` | `off` | `on` opens the public takedown notice form `/legal/notice` (captcha when configured). Notices forwarded by other nodes are accepted either way. |
| `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR` | `5` (`--dev`: 1000) | Notices per client address and hour (1–1000). |
| `TAVRN_LEGAL_NOTICE_RETENTION_DAYS` | `1095` | Cases are kept this long after their last change (30–36500; 1095 = 3 years). |
| `TAVRN_LEGAL_REPEAT_THRESHOLD` | `3` | Actioned notices against one user after which the admin page suggests disabling the account (1–100; a suggestion only, never automatic). |
| `TAVRN_LEGAL_COUNTER_NOTICE_DAYS` | `14` | Days the uploader may answer an actioned notice with a counter-notice (1–365). |
| `TAVRN_LEGAL_TERMS_MODE` | `notice` | `notice`: ask once after a new version of the terms; `require`: refuse the API (`403 legal.terms_required`) until accepted (declining signs out). |
| `TAVRN_ACCOUNT_DELETE_GRACE_DAYS` | `30` | Deleted accounts can be restored by an admin this long, with the username reserved; then they are erased (1–365). |

### Web push and metrics settings

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_PUSH` | `on` | Web push notifications to browsers and installed web apps (PWAs). See [Web push](#web-push). |
| `TAVRN_PUSH_CONTACT` | the node's public URL (`TAVRN_PUBLIC_URL`) | VAPID contact, a `mailto:` address or an `https://` URL (at most 256 characters) that push services may use to reach the operator. |
| `TAVRN_PUSH_MAX_PER_MINUTE` | `10` | Pushes per user and minute (1–1000); in addition at most one push per conversation and user every 30 seconds. |
| `TAVRN_METRICS` | `off` | `on` exposes `GET /metrics` (Prometheus text format) on the node's HTTP port. See [Metrics and health](#metrics-and-health). |
| `TAVRN_METRICS_TOKEN` | empty | When set (16–256 printable ASCII characters without spaces), scrapers must send `Authorization: Bearer <token>`; never printed by `check-config`. When empty, `/metrics` answers only to loopback and the addresses in `TAVRN_TRUSTED_PROXIES`. |

### Several instances

Details: [Scaling with Valkey](#scaling-with-valkey).

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_CACHE_URL` | unset | `redis://[user:password@]host[:port][/db]` or `rediss://…` (TLS); enables several instances. The password never appears in logs or `check-config`; URL-encode special characters. |
| `TAVRN_INSTANCE_ID` | random per start (logged) | `[A-Za-z0-9._-]{1,64}`; names the instance in logs, the cache and `livekit-<id>.yaml`. |
| `TAVRN_INSTANCE_URL` | address towards the cache + listen port | `http(s)://host[:port]` where the other instances reach this one. |

### Logging

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_LOG_LEVEL` | `info` (`--dev`: `debug,sqlx=info`) | A log filter: a level (`error`, `warn`, `info`, `debug`, `trace`) or per-module directives such as `info,sqlx=warn`. An invalid filter falls back to `info`. |
| `TAVRN_LOG_FORMAT` | `text` | `text` or `json` (one JSON object per line, for log collectors). |

### Variables outside the node

These are read by `docker-compose.yml`, not by the node:

| Variable | Meaning |
|---|---|
| `POSTGRES_PASSWORD` | Password of the compose PostgreSQL (required by the compose file). |
| `IMAGE_TAG` | Image tag, e.g. `0.1` to pin a release line; default `latest`. |
| `TAVRN_HOST_PORT` | Host port on `127.0.0.1` the reverse proxy points at (default `8080`). |
| `VALKEY_PASSWORD` | Password of the optional `valkey` service (the same one goes into `TAVRN_CACHE_URL`). |

## Reverse proxy and TLS

tavrn speaks plain HTTP only (default port 8080). TLS, certificates and HTTP/2 are always handled by a reverse
proxy in front of it. This is mandatory, not optional: nodes only federate over HTTPS (the identity domain's
`/.well-known/tavrn` and the endpoints it names, see [delegation](#identity-domain-and-node-host-delegation)).

### What the proxy must do

1. **Pass WebSockets through** (`Upgrade`/`Connection` headers) for `/api/v1/ws` and for the voice signaling
   under `/rtc` (`/rtc`, `/rtc/v1`; the HTTP checks `/rtc/validate` and `/rtc/v1/validate` are plain GETs). Use a
   long read timeout (an hour): both are long-lived connections.
2. **Set `X-Forwarded-For`.** tavrn only trusts the header when the connection comes from an address in
   `TAVRN_TRUSTED_PROXIES` (default: private networks and localhost). If your proxy lives elsewhere, add its
   address, otherwise rate limits and bans apply to the proxy address instead of the client.
3. **Allow large bodies**, at least as large as `TAVRN_UPLOAD_MAX_BYTES` (or `TAVRN_UPLOAD_MAX_BYTES_CEILING` when
   grants raise it).

Also recommended: redirect HTTP to HTTPS, send HSTS, and block `/metrics` for the public
([Metrics and health](#metrics-and-health)). Route `/rtc` only to tavrn, never to LiveKit's port 7880 (which is
not published at all). `/api/v1/voice/webhook` receives LiveKit's events from inside the container; requests
from outside are rejected unless signed with the node's LiveKit secret, so the proxy does not need to block it
(it may).

### nginx and Caddy

Complete examples are in the repository:

- [`deploy/nginx.conf.example`](../deploy/nginx.conf.example): HTTPS server with HTTP/2 and HSTS,
  `client_max_body_size 100m`, `proxy_pass http://127.0.0.1:8080` with `Host`, `X-Forwarded-For`,
  `X-Forwarded-Proto`, the WebSocket headers (`Upgrade $http_upgrade`, `Connection "upgrade"`) and
  `proxy_read_timeout 3600s`, plus the HTTP → HTTPS redirect. Certificates e.g. via certbot.
- [`deploy/Caddyfile.example`](../deploy/Caddyfile.example): `reverse_proxy 127.0.0.1:8080` with automatic
  certificates and a 100 MB body limit; Caddy passes WebSockets and `X-Forwarded-For` by itself.

Several instances: list every instance as an upstream (nginx `upstream`, Caddy `reverse_proxy` with several
upstreams), see [Load balancer](#load-balancer).

### Nginx Proxy Manager (Portainer)

Create a proxy host:

| Field | Value |
|---|---|
| Domain Names | `chat.example.org` |
| Scheme | `http` |
| Forward Hostname | `tavrn` (container on the same Docker network) or the host IP |
| Forward Port | `8080` |
| Websockets Support | **on** (covers `/api/v1/ws` and `/rtc`) |
| Block Common Exploits | on |
| SSL | request a Let's Encrypt certificate, enable **Force SSL**, **HTTP/2** and HSTS |

Under "Advanced" add: `client_max_body_size 100m;` and `proxy_read_timeout 3600s;`

If NPM shares a Docker network with the tavrn container, `tavrn` does not need a published TCP port (remove the
`8080` entry in `docker-compose.yml` and attach the tavrn service to NPM's network). The media ports (UDP range,
TCP 7881, optionally TURN) stay published on the host.

### TURN over TLS through the proxy

With `TAVRN_RTC_TURN_ENABLED=true` and `TAVRN_RTC_TURN_TLS_PORT` (default 5349), clients connect to
`turns:<TAVRN_RTC_TURN_DOMAIN>:443` (default `turn.<host of TAVRN_PUBLIC_URL>`). tavrn never terminates TLS, so the
proxy does: give the TURN domain its own DNS record pointing at the proxy, a certificate for it, and a **TCP
stream** that terminates TLS and forwards plain TCP to the container's TLS port (publish it on `127.0.0.1` only,
see the commented line in `docker-compose.yml`). Port 443 of the TURN domain must not be an HTTP virtual host at
the same time. nginx:

```nginx
stream {
    server {
        listen 443 ssl;                       # a separate IP, or use ssl_preread to share 443 (below)
        ssl_certificate     /etc/letsencrypt/live/turn.chat.example.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/turn.chat.example.org/privkey.pem;
        proxy_pass 127.0.0.1:5349;
        proxy_timeout 1h;
    }
}
```

To share port 443 with the web server, route by name with `ssl_preread` in a `stream` block in front: the TURN name
goes to a TLS-terminating stream server on an internal port, everything else to the HTTPS server. Clients always use
port 443 (LiveKit announces `turns:<domain>:443`). Nginx Proxy Manager: a *Stream* (TCP) listening on 443 of an
address its proxy hosts do not use, with an SSL certificate for the TURN domain (stream SSL needs a recent NPM
release), forwarding to `tavrn:5349`. Without a TLS-terminating stream proxy, leave `TAVRN_RTC_TURN_TLS_PORT=0` and
use TURN over UDP. The rest of TURN is in [Voice and video](#turn-optional-for-strict-networks).

### Identity domain and node host (delegation)

The identity of a node is its domain (`TAVRN_DOMAIN`): addresses `alice@example.org`, node keys, tokens. The node
itself may run on another host (`TAVRN_PUBLIC_URL`, default `https://<TAVRN_DOMAIN>`), for example because the
domain already carries a website:

```bash
TAVRN_DOMAIN=example.org                    # addresses alice@example.org
TAVRN_PUBLIC_URL=https://chat.example.org   # where the web client and the API live
# TAVRN_WEBAUTHN_RP_ID=example.org          # the default; passkeys keep working if the app host moves later
```

The node serves its discovery document on its own host as usual; it names `domain: example.org` and the
endpoints on `chat.example.org`. Clients and other nodes always resolve the identity domain first:
`https://example.org/.well-known/tavrn`. So the website on `example.org` has to answer that one path (CORS-open,
`application/json`). There are two ways:

1. **Reverse-proxy rule (preferred)**: forward `/.well-known/tavrn` of the website to the node. The document
   always carries the current node keys, so key rotation needs no further step.

   nginx (in the `server` block of `example.org`):

   ```nginx
   location = /.well-known/tavrn {
       proxy_pass https://chat.example.org;   # or http://127.0.0.1:8080 when the node runs on the same machine
       proxy_set_header Host chat.example.org;
       proxy_ssl_server_name on;
   }
   ```

   Caddy:

   ```caddyfile
   example.org {
       handle /.well-known/tavrn {
           reverse_proxy https://chat.example.org {
               header_up Host chat.example.org
           }
       }
       # … the website
   }
   ```

   Do not redirect instead of proxying: nodes follow redirects only on the same host, browsers not at all.
2. **Static copy**: `docker compose exec tavrn tavrn-node well-known > well-known.json` prints the document; serve
   it as `/.well-known/tavrn` with `Content-Type: application/json`, `Access-Control-Allow-Origin: *` and
   `Cache-Control: max-age=300`. **Caveat**: the copy must be refreshed whenever the node keys change (rotation,
   compromise) and whenever settings in it change (name, registration, policies, capabilities). Peers cache it for
   at most an hour and refuse tokens signed with a key they do not find in it, so a stale copy breaks federation
   until it is updated. Prefer the proxy rule.

Check: `curl -s https://example.org/.well-known/tavrn | jq '.domain, .api'` must print `"example.org"` and
`"https://chat.example.org/api/v1"`.

Rules the node enforces (FEDERATION.md §1.3, §1.4): the document's `domain` must equal the queried domain; the
endpoints must be `https` (and are checked against private addresses like the domain itself); peers cache them as
long as the document (5 minutes to 1 hour), and a cached endpoint that stops answering is resolved again at once
(at most once a minute), so a move takes effect at the next failure.

#### SRV record instead of the well-known file

You need EITHER the well-known on the identity domain OR a DNS record, never both:

```dns
_tavrn._tcp.example.org. 3600 IN SRV 10 0 443 chat.example.org.
```

Resolution order (FEDERATION.md §1.3 has the decision table): `https://example.org/.well-known/tavrn` first; when
the website has no such file (404) or there is no HTTPS server on `example.org` at all, the SRV record
(`TAVRN_FEDERATION_SRV_FALLBACK`, default on): the document is fetched from
`https://chat.example.org:443/.well-known/tavrn` (the node serves it on its own host) and must name
`example.org`; only then, after a 404, the direct `https://example.org/api/v1`. Other HTTP errors (5xx, 403, …)
are errors. Browsers cannot query DNS records, so web clients ask the node they were loaded from
(`GET /api/v1/federation/resolve/example.org`), which runs the same order: the connect flow, invites and add links
work with an SRV-only setup too. It relies on DNS (use DNSSEC where you can); the conformance and
key-consistency checks still apply.

#### Passkeys

The relying party id is `TAVRN_WEBAUTHN_RP_ID` (default `TAVRN_DOMAIN`), the origin the public URL. The id must
be the origin's host or a parent domain of it: `example.org` covers `chat.example.org`, so with the default a
later move to `app.example.org` keeps every passkey. A public URL on an unrelated host (`chat.example.net` for
`example.org`) needs `TAVRN_WEBAUTHN_RP_ID=chat.example.net`; the node refuses to start otherwise. Changing the
relying party id later invalidates all registered passkeys (users sign in with TOTP or a recovery code and
register them again).

Everything else that builds absolute URLs (mail links, invite and application add links, the OIDC redirect URI
`<public URL>/api/v1/auth/oidc/callback`, the LiveKit signaling URL, `turn.<public host>`) uses the public URL.

### Hosted nodes under one domain

A hosting service that runs nodes as `<name>.example.org` gives every node its own identity domain
(`TAVRN_DOMAIN=<name>.example.org`, `TAVRN_PUBLIC_URL=https://<name>.example.org`, the default) and its own
well-known on its own host. They never collide with the delegation of `example.org` itself (another domain,
another document, other keys). The node needs nothing special; the hosting service must enforce, before it
creates a node name:

- **Reserved labels**: `www`, `app`, `api`, `turn` (and `turn.<label>` names for TURN over TLS), `mail`, `smtp`,
  `imap`, `mx`, `ns1`/`ns2`, `cdn`, `static`, `assets`, `status`, `docs`, `blog`, `git`, `matrix`, `identity`,
  `auth`, `login`, `sso`, `id`, `account`, `accounts`, `well-known`, `localhost` and every label starting with
  `xn--` unless it is valid IDNA.
- **Impersonation block list** (case-insensitive, also with digits for letters like `0`/`o`, `1`/`l` and with
  hyphens removed): `admin`, `administrator`, `root`, `support`, `help`, `helpdesk`, `security`, `abuse`,
  `postmaster`, `hostmaster`, `webmaster`, `noreply`, `official`, `staff`, `team`, `moderator`, `mod`, `system`,
  `tavrn`, `billing`, `payment`, `verify`, `verification`, plus the names of well-known brands and of other chat
  services. Users see the domain as part of every address, so `support.example.org` would read as the hosting
  service's own support.
- Labels follow the node domain rules (lowercase `a-z0-9-`, 1–63 characters, no leading or trailing hyphen) and
  are never reused after a node is deleted (addresses and keys of the old node stay in other nodes' caches).

### Verify the proxy

```bash
curl -s https://chat.example.org/.well-known/tavrn | jq .domain   # discovery reachable
curl -s https://chat.example.org/readyz                             # {"ready":true,"database":true,"livekit":true,"cache":null}
curl -s https://chat.example.org/healthz                            # {"status":"ok","voice":"running"}
curl -s -o /dev/null -w '%{http_code}\n' https://chat.example.org/rtc/validate   # 401
```

`/rtc/validate` must answer `401` with the code `voice.token_invalid` (the proxy reaches tavrn, tavrn refuses
without a token).

## Keys and backups

### The key files

The data volume (`./data`, mounted at `/data`, `TAVRN_DATA_DIR`) holds the uploaded files in `blobs/` and, in
`keys/`, the node's keys. All of them are created at the first start with mode 0600:

| File | What it is | If it is lost or replaced |
|---|---|---|
| `keys/node-<kid>.pem` | The node's Ed25519 signing keys (federation, tokens). All keys in the directory are published in `/.well-known/tavrn`; the newest one signs. | Other nodes no longer trust the node's identity. |
| `keys/secrets.key` | 32 random bytes that encrypt data at rest such as the users' TOTP secrets, and the single-use values in the cache with several instances. Never rotated. | Every TOTP enrollment becomes unusable (users then need a passkey, a recovery code or an admin reset of their second factor). |
| `keys/storage.key` | The storage key: wraps the per-file keys of every stored file (attachments, avatars, headers, room icons, emojis, soundboard clips). `keys/storage.key.next` exists only during a [rotation](#rotating-the-storage-key). | **Every stored file is unreadable**; the node refuses to start when the file is missing or does not match the stored keys. |
| `keys/livekit.key` | LiveKit's API key and secret (`<key>: <secret>`). | Regenerated at the next start, nothing lost. With several instances all must use the same file. |
| `keys/vapid.key` | The VAPID key for [web push](#web-push): a P-256 private key, PKCS#8 PEM. | Every browser push subscription becomes invalid: users must re-enable push on each device. No other data is lost. |

Optional files you place there yourself, such as `keys/oidc-client-secret` for `TAVRN_OIDC_CLIENT_SECRET_FILE`,
belong in the same backup. `livekit.yaml` (or `livekit-<instance id>.yaml`) in the data directory is regenerated
at every start.

**Never replace or delete the key files; restore them from the same backup as the database.** The node never
creates a new `storage.key` when one is expected: it refuses to start instead.

### What to back up

Back up the **database** and the **data volume together**, before every upgrade and regularly. They belong
together: the database holds the wrapped file keys (`blob_keys`) and references every file in `blobs/`, the key
files open both.

A consistent backup with a short downtime:

```bash
docker compose stop tavrn
docker compose exec -T db pg_dump -U tavrn -Fc tavrn > backup/tavrn-$(date +%F).dump
tar -C . -czf backup/tavrn-data-$(date +%F).tar.gz data
docker compose start tavrn
```

Without downtime, dump the database first and copy the volume afterwards: files uploaded in between are not
referenced by the dump and are removed later by the housekeeping as orphans. Keep the key files in a second,
separate place as well (they are small and change rarely: after the first start, a storage key rotation, a new
signing key). Encrypt the backups; anyone holding the database, the volume and `keys/` holds everything the node
holds.

### Restoring

1. Stop the node, restore the database dump (`docker compose exec -T db pg_restore -U tavrn -d tavrn --clean
   --if-exists < backup/tavrn-<date>.dump`) and the `data` directory (including `keys/`) **from the same backup**.
2. Start the image version the backup was taken with, or a newer one (migrations only go forward; an older binary
   refuses a newer schema).
3. Check `docker compose logs tavrn`, `/readyz` and a few attachments.

Because a storage key rotation does not re-encrypt the files, an old key together with an old database backup
still opens the files of that time.

## Database

- **PostgreSQL** is the production database: the compose service `db` (`postgres:17-alpine`, data in
  `./pgdata`) or an external server or managed service via `TAVRN_DATABASE_URL`
  (`postgres://user:password@host:port/db`; remove the `db` service then). SQLite is refused outside `--dev`.
- **Connections**: every instance opens a pool of up to 16 connections. With several instances set
  `max_connections` to at least `16 × instances + 10`, or put PgBouncer in session mode in between.
- **Migrations** are built into the binary and run automatically at every start (with several instances under a
  startup lease, one instance after the other). They only go forward: the node refuses to start against a
  database whose schema is newer than the binary (`database migration failed (schema newer than the binary? …)`),
  so a downgrade means restoring a backup ([Upgrade and rollback](#upgrade-and-rollback)).
- **Backups**: `pg_dump` together with the data volume, see [Keys and backups](#keys-and-backups).
- **Major PostgreSQL upgrades** (e.g. 17 → 18) are not done by the node: dump with `pg_dump`, start the new
  PostgreSQL version on an empty data directory, restore, then start the node. Do not just change the image tag of
  the `db` service on an existing `./pgdata`.
- The node cleans up after itself through the hourly **housekeeping** (handshake log, federation state, orphaned
  files, attachment retention, stale devices, remote users, legal retention, …); no database maintenance besides
  PostgreSQL's own autovacuum is needed.

## Storage and media

### Encryption at rest and the storage key

Stored files are encrypted at rest (`TAVRN_STORAGE_ENCRYPTION=on`, the default): attachments, avatars, headers,
room icons, custom emojis and soundboard clips lie in `data/blobs` as AES-256-GCM ciphertext, each file with its
own key, and those keys are wrapped with the node's **storage key** `keys/storage.key` (32 random bytes, mode
0600, created at the first start) and kept in the database (`blob_keys`). The node decrypts while streaming a
download, so the blob directory can be copied, synced or later moved to object storage without exposing content.
This protects the storage layer, it is not end-to-end encryption (the node holds the keys; attachments of
encrypted conversations are ciphertext anyway and are simply wrapped once more).

**Back up `keys/storage.key` together with the database and the volume: without it every stored file is
unreadable.** The node refuses to start when the file is missing or does not match the stored keys, instead of
creating a new one. Files written by older versions are encrypted in place in the background after the start
(resumable, about 32 MB/s, progress in the log). `TAVRN_STORAGE_ENCRYPTION=off` stores new files unencrypted (for
debugging only; encrypted files stay readable, a warning is logged at every start).

### Rotating the storage key

Stop the node, run the rotation, start it again and back up the new key file:

```bash
docker compose stop tavrn
docker compose run --rm tavrn tavrn-node rotate-storage-key
docker compose start tavrn
```

The rotation creates `keys/storage.key.next`, re-wraps every file key with it (the files themselves are not
re-encrypted, so it takes seconds) and then replaces `keys/storage.key`. An interrupted run is finished by running
it again; a node started in between reads files wrapped with either key. Because the files are not re-encrypted,
an old key together with an old database backup still opens the files of that time. The command prints the old and
new key ids and the number of re-wrapped file keys, and warns about files wrapped with a key the node does not have
(those are unreadable). With several instances stop all of them first.

### Media pipeline (ffmpeg)

Avatars, profile headers, room icons and video backgrounds are converted by `ffmpeg`. The image contains a
minimal static `ffmpeg` (about 7 MB, only image and short-video decoders and the WebP encoder, no network
protocols). Uploads are limited to 20 MB and 30 seconds and converted without network access with a 30-second
limit per job, `TAVRN_MEDIA_WORKERS` (default 1) at a time; animated input becomes animated WebP with a still first
frame. Results are at most 1 MB per variant for avatars and icons and 2 MB for headers. `TAVRN_MEDIA_FFMPEG=off`
turns the conversion off (static PNG/JPEG/WebP only); outside the image point `TAVRN_MEDIA_FFMPEG` at an ffmpeg
with libwebp (`just ffmpeg-install`).

### Uploads, quotas and retention

Upload size, types, the executable rule, per-room quotas and attachment retention are listed under
[Rooms, uploads and storage](#rooms-uploads-and-storage) and [Entitlement defaults](#entitlement-defaults). The
hourly housekeeping deletes expired attachments (messages keep listing them as "file expired"; pinned messages keep
theirs), orphaned files and cached copies of other nodes' emojis and clips (`TAVRN_MEDIA_CACHE_UNUSED_DAYS`).
Files channels can use external WebDAV/S3 stores only with `TAVRN_FILES_EXTERNAL=on`.

### Profiles, presence and message requests

What users see, so you can answer their questions: users edit their profile under *Settings → Profile*: display name,
avatar and profile header (PNG, JPEG, GIF, WebP or a short MP4/WebM; the node crops and converts them, animated ones
loop for up to ten seconds and only move while someone hovers them or while the user speaks in voice), a short
Markdown bio and up to ten linked accounts (Steam, Battle.net, Xbox, PlayStation, Nintendo, Twitch, YouTube, X,
Mastodon, a website; shown as "not verified"). A click on a name or avatar opens the profile card. The footer card
sets the status (online, idle, do not disturb, invisible), a custom status and an activity; the client reports idle
after ten minutes without input. *Settings → Privacy & safety* sets who can message you (friends, friends and shared
rooms, everyone), hides your activity and lists the people you blocked with your private notes. Messages from people
who are not your friends wait under *Message requests* until you accept them; friend requests can carry a short
message. The "+" in the room list also joins rooms from an invite link or code.

For operators: `TAVRN_DM_POLICY` is the upper bound of what users may allow (`friends`, `everyone_shared`,
`everyone`; default `everyone`). Presence is kept per node: clients push it to every node they use, nodes never
forward it to each other.

### Whiteboard

Every conversation has a whiteboard: the 🖍 button in the header of a channel, DM or group DM opens it full screen
(Excalidraw: text, shapes, freehand, images). The one who opens it presents it; the others see a live dot on the
button and join on demand ("Join whiteboard session"), watch live with named cursors and can leave again. Only the
presenter edits until they open the board for everyone, grant single participants ("Who can edit") or lock it again.
The presenter sets a background color or image, keeps a personal library of scenes (save, load, rename, delete; the
current scene is saved every 30 seconds), and closes the board for everyone. Anyone in the session can save the board
as PNG or SVG or share it as an image into a channel or DM. Phones pan and zoom the board with the usual gestures; the
board's actions sit in the "⋯" menu there. In a voice call the 🖍 control presents a board on your tile (instead of a
screen share; one at a time): the others see a badge and a live preview on your tile (and a badge in the channel
list), join from the tile (or by double-clicking it) and get it as a large tile they can focus, maximize or pop out
into its own window. Changes travel end-to-end encrypted like messages and are never stored on the node; scenes are
stored encrypted on the user's home node
([WHITEBOARD.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/WHITEBOARD.md)). Operators limit the library
with `TAVRN_WHITEBOARD_MAX_SCENES` (default 50 scenes of at most 5 MB per user).

## Federation

Nodes federate with each other over HTTPS with signed requests (protocol: FEDERATION.md). Users of one node join
rooms, send DMs and add friends on other nodes; their home node vouches for them. Federation is on by default
(`TAVRN_FEDERATION_ENABLED`).

### Discovery and delegation

Every node serves its discovery document at `https://<TAVRN_DOMAIN>/.well-known/tavrn`: domain, endpoints, node
keys, policies and capabilities. Other nodes resolve a domain in the order well-known → SRV record → direct
`https://<domain>/api/v1`. If the node runs on another host than its identity domain, the identity domain must
proxy the well-known path or publish an SRV record: [Identity domain and node host
(delegation)](#identity-domain-and-node-host-delegation). The node also serves the document on its own host.

Outbound federation requests go only to public addresses (private and loopback addresses are refused unless
`TAVRN_FEDERATION_ALLOW_PRIVATE=true`, meant for development and closed intranets).

### Blocklists, allowlists and limits

- `TAVRN_FEDERATION_BLOCKLIST`: domains never federated with, including their subdomains. Node admins can also
  block a node in the Federation tab of the node administration.
- `TAVRN_FEDERATION_ALLOWLIST`: if set, the node federates only with these domains (a closed federation); the
  blocklist still wins.
- Rate limits per remote domain and minute: `TAVRN_FEDERATION_RATE_LOGINS`, `…_INBOX`, `…_API`, `…_CLAIMS`;
  quotas of remote users: `TAVRN_FEDERATION_MAX_REMOTE_USERS`, `…_PER_DOMAIN`.
- Remote users with nothing left on this node are deleted after `TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`.
- Bots: `TAVRN_FEDERATION_REMOTE_BOTS` (accept other nodes' bots), `TAVRN_APPS_FEDERATE` (this node's bots on other
  nodes).
- `TAVRN_FEDERATION_NOTIFY_BANS=true` tells a banned remote user's home node about the removal (never the
  reason).

Notifications for conversations on other nodes reach a user through the federation `notify` hint at the user's
home node (only DMs, group DMs, mentions and calls for remote conversations); the home node then
sends [web push](#web-push) where needed.

### Getting listed in the directory

Nodes find each other through **reference nodes** (`TAVRN_REFERENCE_NODES`, several comma-separated are fine).
The setting is empty by default; `deploy/.env.example` and `deploy/docker-compose.yml` set the project owner's
public test node as an example, which you may replace or remove. Without a reference node a node neither announces
itself nor pulls a node list; its Discover page then shows only the nodes that announce themselves to it. With
`TAVRN_DIRECTORY_LISTING=true` (the default) a node announces itself to each of them at startup, every 6 hours and
whenever a room is listed or unlisted. The reference node verifies the announce against the node's own
`/.well-known/tavrn` (it must be reachable over HTTPS with a valid certificate, and federation must be on), then
lists the node and fetches its discoverable rooms from the node itself; every room comes with a listing the node
signs, so no other node can forge it. A node not heard from for 48 hours drops out of the list. Nodes also pull the
node lists of their reference nodes, so the Discover page of every node shows the whole directory.

- To be listed: keep `TAVRN_DIRECTORY_LISTING=true`, make sure the reference node can reach your
  `https://<domain>/.well-known/tavrn`, and let room owners mark public rooms as listed. Only rooms marked that way
  appear; the node's name and description come from `TAVRN_NAME` and `TAVRN_DESCRIPTION`.
- Not to be listed: `TAVRN_DIRECTORY_LISTING=false`. The node still federates and its users can still use
  Discover; other nodes refuse to list it.
- To run a reference node: there is nothing extra to switch on, every node accepts announces. Point other nodes'
  `TAVRN_REFERENCE_NODES` at your domain. `TAVRN_DIRECTORY_MAX_ROOMS` (default 5000) caps the cached rooms of other
  nodes (at most 200 per node). Announces are limited to one per domain every 10 minutes.
- Moderation: node admins remove a node or a single room from their directory with
  `DELETE /api/v1/admin/directory/nodes/{domain}` or `DELETE /api/v1/admin/directory/rooms/{node}/{room_id}` (undo
  with `POST /api/v1/admin/directory/relist`); delisted entries are neither shown nor passed on. Blocked domains
  (`TAVRN_FEDERATION_BLOCKLIST`, node bans of a domain) are never listed.
- A listing node lists itself: its own entry (built from `TAVRN_NAME`, `TAVRN_DESCRIPTION` and its discovery
  document) and its listed rooms appear in its own directory, so a reference node shows up in the lists other
  nodes pull from it.
- Reports: users report other nodes or their rooms from the Discover page ("Report"). Reports go to the admins of
  the user's own node, never to the reported node, and never block anything on their own: the Federation tab of
  the node administration shows the count per node and the reports, and removes a node from the directory from
  there. Three different users reporting the same node within 7 days leave a notice in the audit log. Each user can
  send 10 reports a day; reports are kept 180 days.

### Conformance checks of other nodes

A node checks the behavior of every node it federates with (not its code): shortly after the first contact, then
daily, and on demand ([FEDERATION.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/FEDERATION.md) §9). The
checks use the reserved system account `tavrn-conformance` (created at the first start, no password, hidden from
user lists; the username cannot be registered) and a throwaway room on the other node, and verify among other
things that forged, replayed, expired or misaddressed tokens are refused, that the inbox refuses unsigned and
tampered messages, that the MLS delivery service refuses stale, replayed and tampered commits, that plaintext is
refused in encrypted channels, and that logins are rate-limited.

- **Hard failures** (e.g. a forged signature is accepted) and spoofing seen in live traffic (a token for a user of
  another domain, a forged `from`, repeated tampered inbox messages) **block the node automatically**. A later check
  without hard failures lifts an automatic block. Warnings never block.
- `keys.consistent` also fetches the other node's discovery document from every address its domain resolves to
  (IPv4 and IPv6, several hosts): different keys on different addresses are a hard failure (a split view or an
  interception on one path). Roll out new signing keys to all hosts of a node at once.
- `TAVRN_FEDERATION_REQUIRE_CONFORMANCE=true` (default `false`) additionally refuses federated logins and inbox
  messages of nodes that were not checked yet (`503 federation.conformance_pending`, the check starts at once) or
  failed.
- The **Federation** tab of the node administration lists the known nodes with their result, failure and violation
  counts; it runs a check now, blocks and unblocks a node (all audited). The same over the API:
  `GET /api/v1/admin/federation/peers`, `POST …/peers/{domain}/check`, `…/block`, `…/unblock`.
- From the command line: `docker compose exec tavrn tavrn-node doctor --peer community.example`
  ([CLI commands](#the-doctor-and-other-cli-commands)).
- Users see a warning above the rooms of a node that failed the check of their home node; rooms of a node their
  home node blocks are not shown at all.

## Voice and video

The node runs `livekit-server` (bundled in the image) as a supervised child process: it generates LiveKit's API
key once (`/data/keys/livekit.key`, back it up with the volume; a lost file is simply regenerated) and its
configuration (`/data/livekit.yaml`) at every start, restarts it with a backoff when it crashes and stops it on
shutdown. `/healthz` reports `"voice": "running"`, `/readyz` includes `"livekit": true`. Voice is end-to-end
encrypted (frame keys from the channel's MLS group); the node and LiveKit only forward encrypted media (protocol:
[VOICE.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/VOICE.md)). `TAVRN_VOICE_ENABLED=false` switches
voice off completely (no LiveKit process). All settings: [Voice and video settings](#voice-and-video-settings).

### Signaling and media ports

- **Signaling** goes through the proxy like everything else: `wss://<public host>/rtc`. tavrn checks the LiveKit
  token of every connection (signature, expiry, and that its holder may still join the channel or call) before it
  forwards it to LiveKit, which listens on `127.0.0.1:7880` inside the container only. Do not publish or proxy port
  7880, and do not route `/rtc` anywhere but to tavrn.
- **Media** does **not** go through the proxy. Publish and forward (router port forwarding to the host running the
  container, firewall open) these ports 1:1, the same numbers outside and inside, because LiveKit announces them:

  | What | Port(s) | Setting |
  |---|---|---|
  | Media | UDP `61000-61100` | `TAVRN_RTC_UDP_PORT_RANGE` (keep it outside the Linux ephemeral range 32768-60999, or random outgoing UDP sockets on the host block the publication) |
  | ICE over TCP (fallback when UDP is blocked) | TCP `7881` | `TAVRN_RTC_TCP_PORT` (0 = off) |
  | TURN over UDP (optional) | UDP `3478` | `TAVRN_RTC_TURN_UDP_PORT` with `TAVRN_RTC_TURN_ENABLED=true` |
  | TURN over TLS (optional) | TCP `443` on the proxy → `127.0.0.1:5349` | `TAVRN_RTC_TURN_TLS_PORT`, [through the proxy](#turn-over-tls-through-the-proxy) |

  `docker-compose.yml` publishes the first two; the TURN lines are commented out. Firewall example:
  `ufw allow 61000:61100/udp`, `ufw allow 7881/tcp` (or your cloud's security group).
- **Capacity**: every connected participant uses one or two ports of the range (one per WebRTC peer connection), so
  101 ports carry about 50 participants node-wide. Widen the range for more.

### Announced addresses

LiveKit tells clients where to send media (VOICE.md §10.2). Inside Docker the container only knows its private
addresses, so the node announces either the public addresses detected via STUN at start (IPv4 and IPv6, default)
or the ones you configure: `TAVRN_RTC_EXTERNAL_IP` (public IPv4) and `TAVRN_RTC_ADVERTISE_IPS` (more,
comma-separated). Both also accept hostnames (dynamic DNS, see below). Docker's container addresses are never
announced. The startup log line `LiveKit starting media=…` lists what is announced and which ports are open;
compare it with the router.

- **Clients in the same network as the node** reach the public address only if the router supports NAT loopback
  ("hairpin NAT"). Many home routers do not; then put the host's LAN address into `TAVRN_RTC_ADVERTISE_IPS` (e.g.
  `TAVRN_RTC_ADVERTISE_IPS=192.168.0.23`): clients add it as an extra candidate, LAN clients connect directly,
  others ignore it. IPv6 avoids the problem entirely (no NAT), see the next point.
- **IPv6**: Docker's default bridge network has no IPv6, and an IPv6-enabled network gives the container only a
  private ULA (`fd…`); announcing that is useless. Give the network an IPv6 subnet (the commented `networks:` block
  in `docker-compose.yml`, Docker 27+; a ULA is fine, Docker forwards the host's global IPv6 to it for published
  ports), so Docker publishes the ports on the host's global IPv6 as well, open them in the host firewall (IPv6
  needs no port forwarding on the router, but the router's IPv6 firewall must allow inbound traffic to the host for
  these ports), and let STUN detect the global address or add it to `TAVRN_RTC_ADVERTISE_IPS`. The node never
  announces link-local addresses (`fe80::`).

**Connection test**: in the web client, *Settings → Voice & video → Test connection* tries every path from the
current device (UDP to each announced address, TCP, TURN) and says which failed and what to check. Run it once
from inside the LAN and once from a phone on mobile data.

### TURN (optional, for strict networks)

Some networks (corporate Wi-Fi, some mobile carriers, hotel networks) allow nothing but outgoing HTTPS. For those,
enable LiveKit's embedded TURN server: `TAVRN_RTC_TURN_ENABLED=true`. Clients get short-lived TURN credentials from
LiveKit and relay their media through it; the relay reaches LiveKit inside the container, so no router hairpin is
needed.

- **TURN over UDP** (`TAVRN_RTC_TURN_UDP_PORT`, default 3478): publish and forward that UDP port. Helps behind
  symmetric NATs.
- **TURN over TLS on port 443** (`TAVRN_RTC_TURN_TLS_PORT`, default 5349): clients connect to
  `turns:<TAVRN_RTC_TURN_DOMAIN>:443`; the proxy terminates TLS and forwards plain TCP, see
  [TURN over TLS through the proxy](#turn-over-tls-through-the-proxy).
- Relays only go to LiveKit itself (loopback); the TURN server refuses every other private address, so it cannot be
  used to reach other machines in your network. Each participant may hold at most 12 relay allocations. The relay
  sockets use `TAVRN_RTC_TURN_RELAY_PORT_RANGE` inside the container (not published).

### Dynamic addresses and proxies like Cloudflare

Media ports cannot be proxied: HTTP reverse proxies and CDNs like Cloudflare forward neither UDP nor arbitrary TCP
ports, so the media path must reach your host directly. Keep the web/API/`/rtc` hostname behind the proxy if you
like, but use direct (DNS-only, "grey cloud") records for media. With a home connection whose address changes:

- **Hostname entries with dynamic DNS**: `TAVRN_RTC_EXTERNAL_IP=home.dyndns.example` (and/or hostnames in
  `TAVRN_RTC_ADVERTISE_IPS`). The node resolves them (A and AAAA) at start and every minute, or after the record's
  TTL if longer, announces their public addresses (private ones only with `TAVRN_RTC_ADVERTISE_PRIVATE=true`) and
  restarts LiveKit when they change; calls reconnect within the grace period. Give the record a low TTL (60–300 s)
  and keep it unproxied. If a name does not resolve the node keeps its last known addresses; if none ever resolved,
  `/healthz` shows `voice_problem` and LiveKit falls back to the STUN detection.
- **TURN with a hostname**: `TAVRN_RTC_TURN_ENABLED=true` with TURN over TLS, clients use `turns:turn.<host>:443`
  and resolve that name themselves at every reconnect, so a new address takes effect at the next reconnect without
  the node noticing. Give `turn.<host>` a low TTL; it must reach your TLS-terminating stream proxy directly (not
  through an HTTP-only CDN). This is the most robust path for rotating addresses and strict networks at once.

### Limits and dropped connections

- **Limits:** `TAVRN_VOICE_MAX_BITRATE_KBPS`, `TAVRN_VOICE_MAX_PARTICIPANTS`, `TAVRN_SCREENSHARE_*`,
  `TAVRN_CAMERA_*`, and the entitlement defaults `TAVRN_VOICE_CHANNEL_MAX_PARTICIPANTS`, `TAVRN_STREAM_*`,
  `TAVRN_CAMERA_MAX_HEIGHT`.
- **Dropped connections:** a participant whose connection breaks stays in the channel as "reconnecting" for
  `TAVRN_VOICE_RECONNECT_GRACE_SECS` (default 45) while the client rejoins by itself; a join from another device of
  the same user replaces the first.
- Several instances: [Voice and video with several instances](#voice-and-video-with-several-instances).

## Web push

The node sends web push notifications (RFC 8030 push, RFC 8291 message encryption, RFC 8292 VAPID; protocol:
PROTOCOL.md §6d, capability `push.webpush` in the discovery document) to browsers and installed web apps (PWAs), so
users learn about new messages, mentions and calls while no tab of the web client is open.

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_PUSH` | `on` | `off` switches web push off. |
| `TAVRN_PUSH_CONTACT` | the node's public URL (`TAVRN_PUBLIC_URL`) | The VAPID contact (a `mailto:` address or an `https://` URL, at most 256 characters) that push services may use to reach the operator, e.g. `mailto:admin@example.org`. |
| `TAVRN_PUSH_MAX_PER_MINUTE` | `10` | Pushes per user and minute (1–1000). |

How it behaves:

- **When**: a push is only sent when the user has no open connection to the node. Besides
  `TAVRN_PUSH_MAX_PER_MINUTE` there is at most one push per conversation and user every 30 seconds.
- **Content**: push payloads are encrypted end-to-end to the browser (RFC 8291); the push services only see
  ciphertext. For **encrypted conversations** a push never contains message content, only the conversation, its
  name and the sender's display name. For **unencrypted conversations** it carries a text preview (at most 120
  characters) only when the user turned on "show message text in push notifications" (default off).
- **The VAPID key** `<data>/keys/vapid.key` (a P-256 private key, PKCS#8 PEM, mode 0600) is created at the first
  start. Back it up with the other [key files](#keys-and-backups). If it is lost or replaced, every browser
  subscription becomes invalid and users must re-enable push on each device; nothing else is lost.
- **Outbound traffic**: the node sends HTTPS `POST` requests to the push services of the browser vendors. The
  endpoints are chosen by the browsers (hosts of Google, Mozilla, Apple, Microsoft and others), so egress HTTPS to
  the internet must be allowed. Endpoints on private or loopback addresses are refused.
- **Remote conversations**: notifications for rooms on other nodes arrive through the federation `notify` hint at
  the user's home node, which sends the push (only DMs, group DMs, mentions and calls for remote conversations).
- **Several instances**: any instance sends; the rate counters live in Valkey.
- **iPhone and iPad**: users have to add the web app to the home screen (install it as a PWA) before Safari
  allows push.
- **Monitoring**: `tavrn_push_sent_total` and `tavrn_push_failed_total` ([Metrics and health](#metrics-and-health)).
  Many failures usually mean blocked egress or a replaced `vapid.key`.

## Metrics and health

### Health endpoints

| Endpoint | Answers | Use it for |
|---|---|---|
| `GET /healthz` | Always `200` while the process serves requests: `{"status":"ok","voice":"running"}`. `voice` is the state of the supervised LiveKit process (`disabled`, `stopped`, `starting`, `running`, `restarting`); `voice_problem` appears when the operator has to fix something in the voice setup (e.g. none of the announced hostnames resolves). | Liveness. |
| `GET /readyz` | `200` or `503` with `{"ready":…,"database":…,"livekit":…,"cache":…}`. `ready` requires the database and, with voice on, LiveKit answering on its local port (`livekit` is `null` with voice off). `cache` reports Valkey and the cache bus (`null` without `TAVRN_CACHE_URL`) but is **not** part of `ready`. | Readiness, load balancer health checks, external monitoring. |

The image's Docker `HEALTHCHECK` runs `tavrn-node check-config` every 30 seconds: the container turns unhealthy
when the configuration, the LiveKit binary or (with SSO) the provider check fails. It does not replace a
`/readyz` check.

### Prometheus metrics

`TAVRN_METRICS=on` exposes `GET /metrics` in the Prometheus text format on the node's HTTP port (`TAVRN_LISTEN`).
Access:

- `TAVRN_METRICS_TOKEN` set (16–256 printable ASCII characters without spaces): scrapers must send
  `Authorization: Bearer <token>`.
- `TAVRN_METRICS_TOKEN` empty: `/metrics` answers only to requests from loopback and from the addresses in
  `TAVRN_TRUSTED_PROXIES`, decided by the client address as for rate limits (a request forwarded by a trusted
  proxy counts as its original client, so public requests through a reverse proxy on the same host are refused);
  everything else gets the same `404` as an unknown path. The default `TAVRN_TRUSTED_PROXIES` contains all private
  networks, so set a token when untrusted hosts share a private network with the node.
- Block `/metrics` at the reverse proxy for the public anyway (nginx: `location = /metrics { return 404; }`) and
  scrape the instances directly, not through the public host name.

Metrics (all prefixed `tavrn_`):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `tavrn_http_requests_total` | counter | `method`, `route`, `status` | HTTP requests. `route` is the route template such as `/api/v1/rooms/{room_id}`, never an id. |
| `tavrn_http_request_duration_seconds` | histogram | `method`, `route` | Request duration. |
| `tavrn_websocket_connections` | gauge | | Open WebSocket connections of users. |
| `tavrn_connected_devices` | gauge | | Devices with at least one open connection. |
| `tavrn_messages_total` | counter | `encrypted="true"\|"false"` | Messages created on this instance. |
| `tavrn_upload_bytes_total` | counter | | Bytes of uploaded attachments and files. |
| `tavrn_voice_participants` | gauge | | Participants in voice channels. |
| `tavrn_calls_active` | gauge | | Active calls in DMs and group DMs. |
| `tavrn_federation_deliveries_total` | counter | `result="success"\|"failure"` | Delivery attempts of the federation outbox. |
| `tavrn_push_sent_total` | counter | | Web pushes accepted by a push service. |
| `tavrn_push_failed_total` | counter | | Web pushes that failed. |
| `tavrn_db_pool_connections` | gauge | | Open database connections. |
| `tavrn_db_pool_idle` | gauge | | Idle database connections. |
| `tavrn_cache_up` | gauge | | `1` Valkey reachable, `0` not; only with `TAVRN_CACHE_URL`. |
| `tavrn_housekeeping_last_run_timestamp_seconds` | gauge | | Unix time of the last finished housekeeping round on this instance; `0` before the first (hourly, the first one hour after the start; only the leader runs it with several instances). |
| `tavrn_build_info` | gauge | `version` | Always `1`; the label carries the node version. |

Each instance exposes its own metrics: scrape every instance. A Prometheus scrape configuration with the token in
a file:

```yaml
scrape_configs:
  - job_name: tavrn
    metrics_path: /metrics
    scheme: http
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/tavrn-metrics-token   # the value of TAVRN_METRICS_TOKEN
    static_configs:
      - targets: ["tavrn-1.internal:8080", "tavrn-2.internal:8080"]
```

### Dashboards and alerts

Graph request rate and latency per `route`, WebSocket connections, voice participants and the database pool in
Grafana or a similar tool. Alerts worth having (adapt thresholds to your node):

```yaml
groups:
  - name: tavrn
    rules:
      - alert: TavrnHighErrorRate          # more than 5 % server errors
        expr: sum(rate(tavrn_http_requests_total{status=~"5.."}[5m])) / sum(rate(tavrn_http_requests_total[5m])) > 0.05
        for: 10m
      - alert: TavrnPushFailing            # more failed than delivered pushes
        expr: sum(rate(tavrn_push_failed_total[15m])) > sum(rate(tavrn_push_sent_total[15m]))
        for: 30m
      - alert: TavrnFederationFailing      # more than 20 % failed deliveries to other nodes
        expr: sum(rate(tavrn_federation_deliveries_total{result="failure"}[15m])) / sum(rate(tavrn_federation_deliveries_total[15m])) > 0.2
        for: 30m
      - alert: TavrnHousekeepingStalled    # no housekeeping run for more than 2 hours
        expr: time() - max(tavrn_housekeeping_last_run_timestamp_seconds) > 7200 and max(tavrn_housekeeping_last_run_timestamp_seconds) > 0
        for: 15m
      - alert: TavrnCacheDown
        expr: tavrn_cache_up == 0
        for: 2m
```

Add a probe of `/readyz` per instance (e.g. with the Prometheus blackbox exporter) and alert when it fails. With
several instances only the leader runs the housekeeping, hence `max()` across the instances in the housekeeping
rule.

## Scaling with Valkey

A tavrn node normally runs as **one** `tavrn-node serve` process with PostgreSQL: everything short-lived (realtime
events, presence, rate limits, flow state) lives in that process's memory. For more capacity or availability an
operator can run **several instances of the same node** behind a load balancer. They share

- one PostgreSQL database (`TAVRN_DATABASE_URL`, unchanged),
- one `/data` volume (node keys, `secrets.key`, `storage.key`, `livekit.key`, `vapid.key`, uploaded files, media),
- one Valkey or Redis ≥ 7 (`TAVRN_CACHE_URL`).

With `TAVRN_CACHE_URL` unset nothing changes: no Valkey, no new dependency, every code path below takes its
in-memory branch.

This section first says how to run several instances, then how they act as one node and, as a reference,
where every piece of in-memory state went.

### Operating several instances

#### Requirements for several instances

- **The same configuration** on every instance (`TAVRN_DOMAIN`, `TAVRN_PUBLIC_URL`, policies, `TAVRN_CACHE_URL`),
  except `TAVRN_INSTANCE_ID`, `TAVRN_INSTANCE_URL` and the per-instance media ports below.
- **A shared `/data` volume** (one host with a bind mount, or NFS/CephFS/…): node keys, `secrets.key`,
  `storage.key` and the uploaded files must be the same for every instance. Start **one instance alone the very
  first time** (it creates the keys), or copy `keys/` to every instance before the first start.
- **PostgreSQL connections**: every instance opens up to 16. Set `max_connections` to at least
  `16 × instances + 10` (or put PgBouncer in session mode in between).
- **Valkey or Redis ≥ 7** (`PEXPIRE … NX`, `GETDEL`), reachable only from the instances, with a password
  (`requirepass`). Persistence is not needed: after a Valkey restart the instances resubscribe, resync their
  clients and re-announce their presence; counters and pending codes start over. One Valkey database per logical
  node: tavrn prefixes its keys with `tavrn:<domain>:`, but LiveKit's keys are not prefixed. `rediss://` for TLS.
- **`TAVRN_TRUSTED_PROXIES`** must contain the reverse proxy and the instances' own network (relayed requests
  carry the client address in `X-Forwarded-For`); the default (private networks) covers the usual setups.
- **`TAVRN_INSTANCE_URL`** (`http://tavrn-1:8080`): where the other instances reach this one; default: this host's
  address towards Valkey with the `TAVRN_LISTEN` port. The instances must reach each other on that port.

#### Load balancer

- **No sticky sessions needed for HTTP**: every request may go to any instance.
- **WebSockets** (`/api/v1/ws`, `/rtc`) stay on the instance they connected to until they reconnect; nothing else
  is required (no affinity). The proxy must pass `Upgrade` as for a single node.
- Health: `GET /readyz` per instance (`database`, `livekit`, `cache`). `cache: false` is reported but does not make
  the instance unready: a cache outage degrades every instance alike (local rate limits, no relaying, resync
  afterwards), taking them all out of the balancer would take the node offline. Alert on it instead
  (`tavrn_cache_up == 0`).
- Rolling updates: stop one instance at a time (SIGTERM: it leaves the bus, hands over the leadership and LiveKit
  stops), start the new version; migrations run under the startup lease.

#### Voice and video with several instances

With `TAVRN_CACHE_URL` every instance writes `livekit-<instance id>.yaml` with a `redis:` section (`address`,
`username`, `db`, `use_tls` for `rediss://`; the password goes to the child as `REDIS_PASSWORD`, never into the
file). The LiveKit processes then form **one distributed LiveKit**: a room lives on one LiveKit node, signaling
from any node is relayed through Redis, so the `/rtc` proxy of every instance reaches every room. Operator steps:

- **Media addresses**: clients send media to the LiveKit node that hosts the room, directly. Either every
  instance gets its **own public IP**, or instances sharing an IP need **different port ranges**
  (`TAVRN_RTC_UDP_PORT_RANGE`, `TAVRN_RTC_TCP_PORT`, `TAVRN_RTC_TURN_UDP_PORT`, `TAVRN_RTC_TURN_RELAY_PORT_RANGE`)
  forwarded to the right host. Set `TAVRN_RTC_ADVERTISE_IPS` per instance where STUN detection does not give
  the right address.
- **TURN over TLS** (`turns:<domain>:443` through the proxy): the proxy cannot know which instance's TURN server a
  client needs. Give each instance its own `TAVRN_RTC_TURN_DOMAIN` (`turn1.example.org`, `turn2…`) routed by SNI
  to that instance, or leave TURN/TLS off and rely on UDP plus ICE/TCP.
- LiveKit's own region-aware placement (`region`) is not configured: placement is by load across all nodes.
- The webhook of a room reaches the instance whose LiveKit hosts it and is relayed to the leader; only the leader
  reconciles.

#### Web push and metrics with several instances

- [Web push](#web-push): any instance sends; the per-user rate counters live in Valkey.
- [Metrics](#metrics-and-health): each instance exposes its own `/metrics`; scrape every instance (by its own
  address, not through the load balancer). `tavrn_cache_up` reports Valkey per instance; the housekeeping
  timestamp comes from the leader.

#### Example: two instances on one host

```yaml
# docker-compose.override.yml next to deploy/docker-compose.yml (uncomment the "valkey" service there)
services:
  tavrn:
    environment:
      TAVRN_INSTANCE_ID: tavrn-1
      TAVRN_INSTANCE_URL: http://tavrn:8080
    depends_on: { valkey: { condition: service_healthy } }
  tavrn-2:
    image: ghcr.io/just-tavrn/tavrn-node:${IMAGE_TAG:-latest}
    restart: unless-stopped
    env_file: .env
    environment:
      TAVRN_DATABASE_URL: postgres://tavrn:${POSTGRES_PASSWORD}@db:5432/tavrn
      TAVRN_INSTANCE_ID: tavrn-2
      TAVRN_INSTANCE_URL: http://tavrn-2:8080
      TAVRN_RTC_UDP_PORT_RANGE: 61200-61300      # differs from tavrn-1 (same public IP)
      TAVRN_RTC_TCP_PORT: "7882"
    ports:
      - "127.0.0.1:8081:8080"
      - "61200-61300:61200-61300/udp"
      - "7882:7882/tcp"
    volumes: ["./data:/data"]                     # the same directory as tavrn-1
    depends_on: { db: { condition: service_healthy }, valkey: { condition: service_healthy } }
    read_only: true
    tmpfs: ["/tmp"]
```

The reverse proxy balances `127.0.0.1:8080` and `127.0.0.1:8081` (nginx `upstream`, Caddy `reverse_proxy` with
two upstreams); `.env` sets `TAVRN_CACHE_URL=redis://:<password>@valkey:6379/0` and `VALKEY_PASSWORD`.

#### Example: an identity domain with a delegated application host

`example.org` is the identity domain, delegated to `chat.example.org`: `TAVRN_DOMAIN=example.org`,
`TAVRN_PUBLIC_URL=https://chat.example.org`, the well-known on `example.org`. `chat.example.org` resolves to the load
balancer (HAProxy, nginx or a cloud LB terminating TLS) in front of two or more instances on separate hosts; each
host has its own public IP for media, announced by STUN or `TAVRN_RTC_ADVERTISE_IPS`, and, with TURN/TLS,
its own `turnN.example.org`. PostgreSQL (managed or a primary with a replica for failover), Valkey and the shared
`/data` storage sit on the private network, reachable from the instances only. Instances can be added or removed
at any time; the leader moves by itself.

#### Failure behaviour

| Situation | Behaviour |
|---|---|
| `TAVRN_CACHE_URL` set but unreachable at start | `tavrn-node serve` exits with code **3** and `TAVRN_CACHE_URL: Valkey/Redis at host:port is not reachable (…)` (no password in the message). |
| Valkey down while running | Commands time out after 2 s and reconnect with backoff (connection manager); the bus resubscribes with backoff up to 10 s. Meanwhile: security limits count per instance, connect/SSO flows answer `503 node.cache_unavailable`, there is no leader (singleton jobs pause, relayed routes are served locally), events between instances are lost. Voice is down as well (distributed LiveKit itself needs Redis), so voice side effects that find no leader are not retried. Afterwards every affected client gets `resync`. |
| Bus silently stuck (no own heartbeat echo for 20 s) | The subscription is renewed, clients resync. |
| An instance crashes | Its WebSocket clients reconnect elsewhere; the others drop its connections after 20 s; if it was the leader another one takes over within 15 s. |
| The leader is unreachable for relayed requests | `503 node.leader_unavailable` with `Retry-After: 2`. |

#### Settings for several instances

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_CACHE_URL` | empty | `redis://[user:password@]host[:port][/db]` or `rediss://…`; enables several instances |
| `TAVRN_INSTANCE_ID` | random per start (logged) | `[A-Za-z0-9._-]{1,64}`; names the instance in logs, the cache and `livekit-<id>.yaml` |
| `TAVRN_INSTANCE_URL` | address towards the cache + listen port | `http(s)://host[:port]` where the other instances reach this one |

> **Command interactions (APPLICATIONS.md §5.6)** reach a bot connected to any instance. The instance that takes the >
invocation owns the pending interaction, in memory as on a single node; the 3-second wait happens there. Every >
instance registers its receiving bot connections in the cache (hash `cmdrecv:<bot user id>`, field >
`<instance>/<connection>`, removed when the connection closes; entries of instances that stopped sending heartbeats >
are ignored). Without a local receiver the owner picks one live instance holding a receiver (round robin) and >
publishes `Invoke { instance, bot, data }` on the bus; that instance hands the `command.invoke` event to one of its >
connections (round robin over the bot's devices as before). The owner also stores `interaction:<id>` = its instance id
> (TTL 16 minutes, the interaction's lifetime plus a minute). The bot answers over REST, which the load balancer may
send > anywhere: callbacks and follow-ups (`/interactions/{id}/callback|messages`) for an interaction that is not
pending on > the receiving instance are relayed over HTTP to the owner's `TAVRN_INSTANCE_URL` (like the requests
relayed to the > leader, `Tavrn-Relayed` stops a second hop; `503 interaction.owner_unavailable` when the owner does
not answer). > Chosen over moving pending interactions into the cache because the waiting invocation, the "first
response wins" > claim and the follow-up counter stay in one process, with no distributed locking. A restart or crash
of the owner > loses its pending interactions (invokers get `504 interaction.no_ack`), as on a single node. The
interactions URL > (§6.3) is called by the owner itself and needs nothing of this. Without `TAVRN_CACHE_URL` nothing
changes.


### How the instances act as one node

The cache layer is `src/cache/`: a small `Cache` trait (fixed-window counters, single-use values, leases,
hashes, a pub/sub bus) with two implementations, `InProcess` (the default, one per process) and `Valkey`
(redis-rs over its connection manager). It is chosen once at startup and held by `AppState::cluster`.

| Mechanism | How |
|---|---|
| **Event fan-out** | Every hub event is published once on the bus `tavrn:<domain>:bus` (the WebSocket frame serialized once by the sender); the other instances inject it into their local broadcast. A WebSocket on any instance gets every event. |
| **Presence** | Each instance announces the open connections per device of its users and every idle/activity change on the bus; every instance keeps that replica next to its own connections. "Online", the effective status, activities, `GET /presence` and the "notify remote members only when nobody is online" rule see all instances. An instance not heard from for 20 s (heartbeat every 5 s) or one that said goodbye no longer counts; the leader then announces its users as offline. |
| **Security rate limits** | One counter per key in the cache: `INCR` + `PEXPIRE … NX` + `PTTL` in one `MULTI`, a fixed window like the in-memory limiter. If the cache fails the instance counts locally (logged), so a cache outage never disables a limit. |
| **Single-use values** | Connect codes and the OIDC `state` and one-time codes are stored in the cache with their TTL, encrypted with AES-256-GCM under a key derived from `secrets.key` (the cache never sees PKCE verifiers, nonces or identity claims), the key name bound as associated data, and taken with `GETDEL` (exactly one instance gets them). |
| **Leader** | One lease `tavrn:<domain>:leader` (`SET NX PX`, renewed by its holder every third of its 15 s lifetime). The leader runs every singleton job and holds the voice, call and whiteboard state. Leadership is time-bound (it ends when the lease would have expired, even if the renewing task died); a failed renewal ends it at once; a graceful stop releases it. |
| **Relay to the leader** | Requests whose state the leader holds (voice channels, calls, soundboard play, whiteboard sessions and ephemeral events, the LiveKit webhook) are forwarded by the other instances to the leader's `TAVRN_INSTANCE_URL` with the original method, headers and body, `X-Forwarded-For` extended and `Tavrn-Relayed` set (no second hop). A leader that does not answer gives `503 node.leader_unavailable` with `Retry-After: 2`. |
| **Wakeups and side effects** | "New outbox item" and "new subscription event" wake the leader's workers over the bus; voice side effects of kicks, bans, timeouts and deletions (`disconnect_user`, `close_channel`, `close_room`) are handed to the leader. |
| **Startup** | Migrations, the startup fixups and the storage key setup run under a startup lease: instances starting together go one after another. |

#### Realtime resync

There is no ring buffer of past events: a `hello` with `last_event_id` is always answered with `{"op":"resync"}`
(PROTOCOL.md §6). That keeps a reconnect to *another* instance correct: it could not replay the first instance's
events. Should a ring buffer be added later, its entries must be keyed by instance id and sequence, and a
`last_event_id` from another instance must still produce a resync.

The node also sends `resync` on an open connection whenever events may have been lost:

- the connection lagged behind the local broadcast (as before),
- the instance's bus subscription broke and was renewed (all its connections resync),
- an instance could not publish for a while: once the cache answers again it publishes a `Resync` first and the
  other instances' connections reload.

Events are never dropped silently: every failed publish is logged and leads to that resync.

### Audit of the in-memory state

"Per instance" means each instance keeps its own copy and that is correct (or acceptable, with the reason);
"shared" means it moved to the cache or the database; "leader only" means one instance at a time.

#### Realtime, presence and connections

| State | Decision | Reason / implementation |
|---|---|---|
| Hub broadcast (`hub.rs`) | **shared** | Bus fan-out, see [How the instances act as one node](#how-the-instances-act-as-one-node). |
| Hub online map (WebSockets per user) | per instance + replica | The local count stays; `presence::is_online` adds the replicated connections of the other instances (calls ringing, presence audiences, `notify` hints to remote members in `federation/social.rs`). |
| `last_event_id` replay | — | No ring buffer exists; always `resync` ([Realtime resync](#realtime-resync)). |
| Presence registry (`presence.rs`): connections, idle flag, activity per device | **shared** (bus replica) | REST calls (`PUT /users/me/presence`, activity) and the WebSocket of the same device usually hit different instances. |
| Presence batching (`last_sent`, `pending`, `last_public`) | per instance | Only throttles the updates an instance sends; a duplicate update after a change on another instance is harmless (clients apply the latest). |
| Custom status expiry timers | per instance | Readers filter expired statuses anyway; the timer only pushes the update. |
| Typing throttle (per connection) | per instance | Bound to the WebSocket. |
| App token connections (≤ 2 per token, APPLICATIONS.md §2.6) | **shared** | Hash `appconn:<token>` in the cache (field `<instance>/<id>`); beyond two the oldest connection is closed wherever it is (bus message to its instance). |
| Command receivers and pending interactions (`interactions.rs`, APPLICATIONS.md §5.6) | **shared** registry + owner | Receivers in the hash `cmdrecv:<bot user id>`; a pending interaction lives on the instance that took the invocation, `interaction:<id>` names it, callbacks and follow-ups are relayed there (see the note at the end). |
| `access_not_before` | per instance | Development test hook (`POST /dev/expire-access-tokens`), never set in production. |

#### Rate limits

| Limiter | Decision | Reason |
|---|---|---|
| `login_limiter` (login, re-auth, connect exchange, federated login, device nonces, identity reset), `register_limiter` (registration, forgot password) | **shared** | Password guessing and account creation must not scale with the number of instances. |
| `second_factor_user_limiter`, `second_factor_ip_limiter` | **shared** | TOTP / recovery code guessing. |
| `federation_inbox_limiter`, `federation_login_limiter`, `federation_token_limiter` | **shared** | Per remote domain / device; a peer or token must not get N× its quota. |
| `claim_pair_limiter` | **shared** | Protects KeyPackages from being drained by one requester. |
| `webhook_burst_limiter`, `webhook_minute_limiter` | **shared** | Webhook execution is unauthenticated apart from the URL secret. |
| `app_request_limiter`, `app_token_limiter`, `app_rotate_limiter`, `app_create_limiter` | **shared** | Protocol limits of applications and token issuance (APPLICATIONS.md §2.7). |
| `voice_limiter`, ring limiter of calls, `ephemeral_limiter` | node-wide by relaying | Their routes are relayed to the leader, so the leader's counter is the node's. |
| `claim_limiter`, `key_package_limiter`, `commit_limiter`, `backup_limiter`, `friend_limiter`, `conversation_limiter`, `secret_storage_limiter`, `read_limiter`, `presence_limiter`, `media_limiter`, `scene_limiter`, `admin_limiter`, `direct_invite_limiter`, `room_invite_inbox_limiter`, `notify_limiter`, `keys_fetch_limiter`, `directory_announce_limiter`, `directory_limiter`, `federation_api_limiter`, `federation_claim_limiter`, `bot_message_limiter`, `bot_dm_limiter`, unfurl per user, OIDC start/token per IP, files backend changes | per instance | Load shedding and spam damping of authenticated or already-signed traffic: with N instances a client gets at most N× the budget, which bounds the load per instance exactly as before. The OIDC exchange guards 256-bit codes, not a guessable secret. |

#### Single-use tokens, nonces and challenges

| Item | Decision | Reason |
|---|---|---|
| Device-proof nonce (`POST /auth/device-nonce`) | database (already) | A JWT signed with the shared node key; its `jti` is spent in the pre-auth spend table, so a nonce issued by one instance is accepted once by any. |
| Pre-auth tokens (second factor) | database (already) | JWT + spend table. |
| WebAuthn challenges (registration, login, re-auth) | database (already) | Ceremony state rows (`store/factors.rs`). |
| Re-auth tokens (`Tavrn-Reauth`) | stateless (already) | JWT bound to the live session. |
| Connect codes (FEDERATION.md §8) | **shared** (cache, sealed) | Issued and exchanged by different requests; volume tiny, TTL 2 min. |
| OIDC provider `state` (10 min) and one-time codes (60 s) | **shared** (cache, sealed) | Start, callback and exchange are three requests. |
| OIDC re-auth map (`Oidc::issue_reauth`) | per instance | Unused: SSO re-authentication returns the stateless reauth JWT; nothing issues these. |
| Federation inbox `jti` replay protection, inbox dedupe | database (already) | |

#### Caches

| Cache | Decision | Reason |
|---|---|---|
| Unfurl results (1 h, LRU) | per instance | Public link previews; a miss refetches. |
| OIDC discovery document and JWKS | per instance | Refetched on demand. |
| Federation client: delegation cache, discovery endpoints, per-peer concurrency semaphores | per instance | Caches of signed or re-validated public data; the concurrency cap per peer becomes N× (each instance is its own client). |
| Federation key cache, discovery cache, remote emoji/sound copies | database / storage (already) | |
| Entitlements | database (no in-memory cache) | |
| Whiteboard audience cache (2 s) | leader only | Ephemeral events are relayed to the leader. |

#### Voice, calls, whiteboards

| State | Decision | Reason |
|---|---|---|
| Voice participants (`voice/state.rs`) | **leader only** | All voice routes and the LiveKit webhook are relayed to the leader; it reconciles every 30 s against LiveKit, whose room service answers for the whole LiveKit cluster. After a leader change the new leader rebuilds the participants from LiveKit at its first reconciliation (≤ 30 s, `voice.state` is published then). |
| Call state (`calls.rs`: ringing, participants) | **leader only** + flag | Call routes are relayed; the leader keeps `call:<conversation>` in the cache while a call runs so the `/rtc` proxy of every instance can admit its members. A leader change ends running DM calls (the ringing and answer state is gone; the reconciliation then removes their participants): like a restart of a single node, documented limitation. |
| Whiteboard sessions | **leader only** | Session routes and ephemeral events are relayed; the sweep runs on the leader. Fan-out of the events goes over the bus. After a leader change the owner's next keepalive (30 s) opens the session again, as after a restart. |
| Soundboard play | leader only | Relayed (it checks the voice participants); the data message itself travels through LiveKit. |
| LiveKit process status, `livekit.key` | per instance / shared file | Every instance supervises its own LiveKit; the key file on the shared volume makes them one cluster. |
| Voice side effects (kick/ban/timeout/deletion) | leader only | Handed to the leader over the bus. |
| Voice reconciliation, grace sweep | leader only | |

#### Background jobs

| Job | Decision |
|---|---|
| Housekeeping (handshake log, federation state, orphaned files, in-place storage encryption, **attachment retention**, entitlement grants, **remote emoji/sound cache eviction**, history shares, device cleanup incl. the ghost scan cursor, app token expiry notices, remote users, directory reports) | leader only |
| Federation outbox delivery | leader only (any instance queues and wakes it) |
| Event subscription delivery | leader only (any instance queues and wakes it) |
| Directory announce and pruning | leader only |
| Conformance worker and probe account | leader only (manual checks run where requested; the per-instance "running" set only de-duplicates them there) |
| Voice reconciliation, grace sweep, whiteboard sweep | leader only |
| Media pipeline workers (`TAVRN_MEDIA_WORKERS`) | per instance (each processes its own uploads) |
| Startup: migrations, fixups, storage key | one instance at a time (startup lease) |

LeafCleaner (the web client's MLS leaf removal, `src/lib/leafCleanup.ts` in tavrn-web) keeps its server state in the
database (`pending_removals`), so it is unaffected.

## Webhooks and applications

### Applications and bots

Applications (bots) act through app tokens, slash commands, interactions and event subscriptions (protocol:
[APPLICATIONS.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md)); the bot runtime and SDK
are in [tavrn-js](https://github.com/just-tavrn/tavrn-js). What the operator decides:

- **Who may create applications**: `TAVRN_APP_CREATION` = `all` (default), `invite` (an admin grants it per user,
  `PATCH /admin/users/{id} { app_creation_grant }`, or through the SSO group map) or `admins`.
- **How many**: `TAVRN_APPS_PER_USER` (default 5 per owner, node admins included), `TAVRN_APPS_PER_ROOM` (default 25
  installed per room).
- **Tokens and load**: `TAVRN_APP_TOKEN_MAX_DAYS` (default 365) caps the token lifetime; `TAVRN_APP_RATE_REQUESTS`
  (default 1200 per application and minute) caps REST and WebSocket operations.
- **Command review**: `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL=true` makes node admins approve every command definition
  (and every change of one) before it is offered in this node's rooms.
- **Federation**: `TAVRN_APPS_FEDERATE` (this node's bots may act on other nodes) and
  `TAVRN_FEDERATION_REMOTE_BOTS` (other nodes' bots may act here), both on by default.
- **Outbound requests**: the node calls applications' interactions URLs and event subscription endpoints. They must
  be public `https` addresses unless `TAVRN_APP_ALLOW_PRIVATE_URLS=true` (intranets; this turns the SSRF protection
  off for them).
- Bot tokens are a single factor: room owners can declare rooms, categories and channels "no bots".

With several instances, command interactions reach a bot connected to any instance
([Settings for several instances](#settings-for-several-instances) explains how).

### Incoming webhooks

`TAVRN_WEBHOOKS_ENABLED` (default `true`) and `TAVRN_WEBHOOKS_PER_CHANNEL` (default 10, 1–50, at most 50 per room)
control incoming webhooks. Webhook execution is unauthenticated apart from the URL secret; its rate limits are
shared across instances.

A tavrn webhook is a URL (`https://<node>/api/v1/webhooks/<id>/<secret>`) that a service such as CI or monitoring
uses to post messages into one channel. Anyone who knows the URL can post; nobody can read through it. The rules are
in `protocol/APPLICATIONS.md` §6.1 (payload, limits) and §6.1a (encrypted channels).

### Webhooks in unencrypted channels

Post the JSON payload:

```sh
curl -X POST "$WEBHOOK_URL" -H 'content-type: application/json' \
  -d '{ "content": { "type": "text", "body": "Deploy **v1.2** finished" }, "username": "CI" }'
```

### Webhooks in end-to-end encrypted channels

The person who creates the webhook chooses who seals the messages:

- **Sealed by the service** (default): the service encrypts every message itself, so the node never sees the text.
  It needs the code below.
- **Sealed by the node**: the service posts plaintext exactly as above, over HTTPS; the node encrypts it on arrival
  and stores only the encrypted message. The node sees the text at that moment, so its operator could read it.

For a webhook sealed by the service:

1. `GET $WEBHOOK_URL/inbox-key` returns `{ "epoch": 42, "public_key": "<base64url>", "algorithm":
   "x25519-xsalsa20poly1305-sealedbox" }`: the current public key of the channel's members. It changes whenever the
   channel's membership or keys change (an "epoch"); fetch it before every post or cache it for a short while.
2. Seal the payload `{ "content": { "type": "text", "body": "…", "embeds": [ … ] }, "username": "…" }` (UTF-8 JSON;
   `username` and `embeds` are optional) with libsodium's **sealed box** (`crypto_box_seal`) to that public key.
3. `POST $WEBHOOK_URL` with `{ "sealed": "<base64url of the box>", "epoch": 42 }`. Anything else is refused with
   `400 webhook.sealed_required`; `409 webhook.pending_key` means no member has published a key yet (a member has to
   open the channel once).

base64url is RFC 4648 §5 without padding. A key from a slightly older epoch still works: members of that epoch can
read the message, and the node accepts any epoch up to the newest one.

#### Node.js (`libsodium-wrappers`)

```js
import sodium from "libsodium-wrappers";

const B64 = sodium.base64_variants.URLSAFE_NO_PADDING;

export async function postSealed(webhookUrl, payload) {
  await sodium.ready;
  const key = await (await fetch(`${webhookUrl}/inbox-key`)).json();
  const box = sodium.crypto_box_seal(JSON.stringify(payload), sodium.from_base64(key.public_key, B64));
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sealed: sodium.to_base64(box, B64), epoch: key.epoch }),
  });
  if (!res.ok) throw new Error(`webhook: ${res.status} ${await res.text()}`);
}

await postSealed(process.env.WEBHOOK_URL, { content: { type: "text", body: "Deploy **v1.2** finished" }, username: "CI" });
```

#### Python (`pynacl`, `requests`)

```python
import base64, json, os
import requests
from nacl.public import PublicKey, SealedBox

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def post_sealed(webhook_url: str, payload: dict) -> None:
    key = requests.get(f"{webhook_url}/inbox-key", timeout=10).json()
    box = SealedBox(PublicKey(unb64url(key["public_key"]))).encrypt(json.dumps(payload).encode())
    r = requests.post(webhook_url, json={"sealed": b64url(box), "epoch": key["epoch"]}, timeout=10)
    r.raise_for_status()

post_sealed(os.environ["WEBHOOK_URL"], {"content": {"type": "text", "body": "Backup finished"}, "username": "Backup"})
```

#### Go (`golang.org/x/crypto/nacl/box`)

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/nacl/box"
)

func postSealed(webhookURL string, payload any) error {
	resp, err := http.Get(webhookURL + "/inbox-key")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var key struct {
		Epoch     int64  `json:"epoch"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("bad inbox key")
	}
	var pk [32]byte
	copy(pk[:], raw)
	msg, _ := json.Marshal(payload)
	sealed, err := box.SealAnonymous(nil, msg, &pk, rand.Reader)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"sealed": base64.RawURLEncoding.EncodeToString(sealed), "epoch": key.Epoch})
	post, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer post.Body.Close()
	if post.StatusCode >= 300 {
		return fmt.Errorf("webhook: %s", post.Status)
	}
	return nil
}

func main() {
	payload := map[string]any{"content": map[string]any{"type": "text", "body": "Nightly build green"}}
	if err := postSealed(os.Getenv("WEBHOOK_URL"), payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

#### What sealing protects, and what not

Only devices that are members of the channel in that epoch (and members who later receive the epoch's keys through
the channel's history setting) can open the box. The node stores it, cannot open it, and never logs payloads. Two
limits remain (`protocol/ENCRYPTION.md` §5b): a malicious node could hand the service its own public key instead of the
members' key (the service cannot tell), and in "sealed by the node" mode the node sees each text once when it arrives.
Keep the webhook URL secret like a password; it also guards the key route.

## Legal pages and GDPR

Imprint, privacy policy, terms, takedown notices and the users' data rights (protocol:
[LEGAL.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/LEGAL.md)). Nothing here is legal advice: you run
the node and remain responsible for it. Settings: [Legal settings](#legal-settings).

1. **Designated contact.** Admin → Legal → "Contact for notices": name, postal address and e-mail of the person who
   receives notices (the DMCA designated agent and the DSA point of contact). For the US safe harbour, also register
   the agent with the US Copyright Office.
2. **Pages.** Admin → Legal: pick the document, "Insert template" (privacy policy in English or German, a German
   imprint, a terms skeleton from `templates/legal/`), replace every `[[OPERATOR: …]]` note, review the text with a
   lawyer, remove the template notice, publish. Check at least: controller and data protection officer, hosting
   provider, the third parties you actually use (SMTP, Turnstile and its transfer basis, GIF provider, SSO provider,
   external file storage, Valkey, and the browser vendors' push services for web push), attachment, log, audit log
   and backup retention, the supervisory authority, the minimum age; in the imprint the full postal address (no
   P.O. box), representatives, register and VAT numbers and the person responsible under § 18 Abs. 2 MStV. The
   pages appear at `https://<domain>/legal/<kind>` and behind the "Legal" link of every sign-in screen.
3. **Terms.** Once terms are published, registration asks for them. Each new version is shown to every user once;
   `TAVRN_LEGAL_TERMS_MODE=require` blocks accounts until they accept (declining signs out).
4. **Notices.** `TAVRN_LEGAL_NOTICES=on` opens the public form `https://<domain>/legal/notice` (captcha when
   configured, `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR`). Cases appear in Admin → Notices: remove content (with a
   statement of reasons for the uploader), disable the account, reject, or forward to the node that hosts the
   content. After `TAVRN_LEGAL_REPEAT_THRESHOLD` actioned notices against one user the page suggests disabling the
   account; uploaders may send a counter-notice within `TAVRN_LEGAL_COUNTER_NOTICE_DAYS`. Configure SMTP
   (`TAVRN_SMTP_URL`) so reporters and uploaders get their mails.
5. **Retention.** Cases are kept `TAVRN_LEGAL_NOTICE_RETENTION_DAYS` (default 1095 = 3 years) after their last
   change; export them as JSON from the Notices tab for your records. Deleted accounts can be restored for
   `TAVRN_ACCOUNT_DELETE_GRACE_DAYS` (default 30) in Admin → Users, then they are erased.
6. **Data rights.** Users download their data under *Settings → Profile → "My data"* and delete their account under
   *Settings → Privacy & safety*. On request you can do both for them in Admin → Users (your confirmation is required
   and audited).

What the node can and cannot see, for the privacy policy: the content of encrypted conversations (messages, voice,
whiteboards) is end-to-end encrypted and never readable by the node; metadata (who is in which room, when messages
are sent, IP addresses in logs) and unencrypted channels are. Link previews show the node which URLs users preview.
Web push payloads carry no content of encrypted conversations. Retention you control: attachments
(`TAVRN_ATTACHMENT_RETENTION_DAYS`), stale devices (`TAVRN_DEVICE_STALE_DAYS`), remote users
(`TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`), legal cases, deleted accounts, and your own log and backup
rotation.

## Moderation and auto-moderation

### Node administration

The first account registered on a node becomes node admin (plus anyone listed in `TAVRN_ADMIN_USERS`). Node admins
get a "Node administration" page in the client: overview and effective configuration, users (disable, promote,
room-creation grants, delete all content, reset a locked-out user's second factor), account invites for
`TAVRN_REGISTRATION=invite`, node-wide bans, other nodes with their conformance results (block, unblock, check),
entitlements, legal pages and notices, and the node audit log. Room moderation (kicks, bans, timeouts, roles and
permissions) is done by each room's owners and moderators.

### Spam bursts

`TAVRN_AUTOMOD_BURST_LIMIT` (default 10): more than this many messages of one user in one room channel within 5
seconds count as a flood. The node deletes the burst (with its attachments), gives the user a room timeout of
`TAVRN_AUTOMOD_TIMEOUT_MINUTES` (default 10), alerts the room's moderators and writes `automod.spam` to the room's
audit log. Room owners, moderators (permission to moderate members) and node admins are exempt. `0` switches the
detection off. It works on message metadata only, so it applies to encrypted channels too.

### Reports

<!-- TODO(merge): complete after the threads/moderation merge -->
Users report messages and members to the moderators of a room. `TAVRN_REPORTS_RETENTION_DAYS` (default 90):
resolved and dismissed reports and their evidence are deleted after that. `TAVRN_REPORTS_RATE_PER_HOUR` (default
10): reports per user and hour. Reporters of encrypted messages may deliberately release the plaintext as evidence;
otherwise the node never sees it.

### Content auto-moderation

<!-- TODO(merge): complete after the threads/moderation merge -->
`TAVRN_AUTOMOD_WORDS_FILE`: a file with one blocked term per line. `TAVRN_AUTOMOD_LINKS`: `off` or the path of a
link blocklist file. Both apply to unencrypted conversations only, never to ciphertext. Room moderators configure
their own rules in the room settings.

## Threads and forum channels

<!-- TODO(merge): complete after the threads/moderation merge -->
Threads are archived automatically after a period of inactivity set per channel (default 7 days); the hourly
housekeeping does the archiving. There is no node setting besides that.

## The `doctor` and other CLI commands

The binary is `tavrn-node`; in the container run it with `docker compose exec tavrn tavrn-node <command>` (node
running) or `docker compose run --rm tavrn tavrn-node <command>` (node stopped). Every command loads and validates
the configuration first and exits with code **2** on a configuration error. The global flag `--dev` (or
`TAVRN_DEV=true`) selects development mode.

| Command | What it does | Exit codes |
|---|---|---|
| `serve` (default) | Starts the server. | `1` on an error, `3` when `TAVRN_CACHE_URL` is set but Valkey is unreachable at start. |
| `check-config` | Loads, validates and prints the effective configuration as JSON (no secrets), checks that the LiveKit binary is there (with voice on) and, with SSO, fetches the provider's discovery document and keys and prints the redirect URI to register. Also the image's health check. | `0` ok, `2` problem. |
| `send-test-mail <to>` | Sends a test mail through `TAVRN_SMTP_URL` (without SMTP the mail is only logged). | `0` sent, `1` failed. |
| `doctor --peer <domain>` | Runs the [conformance checks](#conformance-checks-of-other-nodes) against another node with this node's configuration, keys and database and prints one line per check (`pass`, `warn`, `fail`, `skip` with a reason). The result is stored like an admin's check (a hard failure blocks the peer). Run it while the node is running: the other node claims the probe's keys from it. | `0` ok, `1` hard failure, `2` the check could not run. |
| `rotate-storage-key` | [Rotates the storage key](#rotating-the-storage-key). Stop the node first; back up the new key file afterwards. Resumable. | `0` done, `1` failed. |
| `well-known` | Prints the discovery document (`/.well-known/tavrn`) for a [static copy](#identity-domain-and-node-host-delegation) on the identity domain. Needs the node keys (start the node once first). | `0` ok, `2` no keys. |
| `openapi` | Prints the OpenAPI specification of the node's API as JSON. | `0`. |

Examples:

```bash
docker compose exec tavrn tavrn-node check-config
docker compose exec tavrn tavrn-node send-test-mail you@example.org
docker compose exec tavrn tavrn-node doctor --peer community.example
docker compose exec tavrn tavrn-node well-known > well-known.json
docker compose run --rm tavrn tavrn-node rotate-storage-key      # node stopped
```

## Logs and troubleshooting

### Logs

`docker compose logs -f tavrn` shows the node's log on stdout/stderr. `TAVRN_LOG_LEVEL` (default `info`) takes a level
or per-module directives (`info,sqlx=warn`, `debug` for a short investigation); `TAVRN_LOG_FORMAT=json` writes one
JSON object per line for log collectors. Logs contain addresses, usernames and request metadata, so treat them as
personal data and rotate them (Docker's `json-file` driver with `max-size`/`max-file`, or your collector's retention).
The output of the supervised LiveKit process is forwarded into the node's log. Useful lines: `LiveKit starting
media=…` (announced addresses and ports), `new node signing key generated` (first start), the background storage
encryption progress, `Auto-moderation: message flood`.

### Common problems

| Symptom | Cause and fix |
|---|---|
| The container exits at once with `Configuration error:` | One line per problem with the variable name; fix them all, `docker compose up -d` again (exit code 2). |
| `TAVRN_CACHE_URL: Valkey/Redis at host:port is not reachable (…)`, exit code 3 | Valkey down, wrong host, password or TLS scheme. See [Failure behaviour](#failure-behaviour). |
| The node refuses to start because of `storage.key` | The file is missing or does not belong to this database. Restore `keys/` from the same backup as the database; never let the node create a new one ([Keys and backups](#keys-and-backups)). |
| `database migration failed (schema newer than the binary? …)` | An older image against a newer database: start the newer image again, or restore the backup taken before the upgrade ([Upgrade and rollback](#upgrade-and-rollback)). |
| The node refuses to start because of `TAVRN_WEBAUTHN_RP_ID` | The public URL's host is not covered by the relying party id; see [Passkeys](#passkeys). |
| Rate limits or bans hit everybody at once | The proxy's address is not in `TAVRN_TRUSTED_PROXIES`, so every request seems to come from the proxy. Add it. |
| Uploads fail with `413` | The proxy's body limit is below `TAVRN_UPLOAD_MAX_BYTES` (nginx `client_max_body_size`, Caddy `request_body max_size`). |
| The web client loads but never connects or keeps reconnecting | WebSockets are not passed through (`Upgrade`/`Connection` headers, "Websockets Support" in NPM) or the proxy's read timeout is short. |
| `/rtc/validate` does not answer `401` | `/rtc` is not routed to tavrn. |
| Voice connects but nobody hears anyone, or only some users | The UDP range or TCP 7881 is not published 1:1, not open in the firewall or not forwarded; or the wrong address is announced. Compare `LiveKit starting media=…` with the router and run the connection test. LAN clients without NAT loopback: add the LAN address to `TAVRN_RTC_ADVERTISE_IPS`. |
| Docker cannot publish the UDP range | The range lies in the ephemeral range 32768–60999 and a socket on the host occupies a port; move the range above 61000. |
| Users on corporate or hotel networks cannot join voice | Enable TURN, ideally over TLS on 443 ([TURN](#turn-optional-for-strict-networks)). |
| `/healthz` shows `voice_problem` | Usually none of the hostnames in `TAVRN_RTC_EXTERNAL_IP`/`TAVRN_RTC_ADVERTISE_IPS` resolves. |
| `/readyz` answers `503` with `"livekit": false` | LiveKit is not running: look for `livekit-server exited, restarting` in the log; outside the image check `TAVRN_LIVEKIT_BINARY`. |
| Other nodes cannot reach yours, or the directory does not list it | `https://<TAVRN_DOMAIN>/.well-known/tavrn` must be reachable with a valid certificate; with delegation check the proxy rule or SRV record; a static copy may be stale after a key change. `TAVRN_DIRECTORY_LISTING` must be on. |
| A peer answers `503 federation.conformance_pending` or your node is blocked by a peer | Conformance checks; run `tavrn-node doctor --peer <domain>` and see [Conformance checks](#conformance-checks-of-other-nodes). |
| No e-mails arrive | Run `tavrn-node send-test-mail you@example.org`; check `TAVRN_SMTP_URL` and `TAVRN_SMTP_FROM`. |
| SSO login fails | Run `tavrn-node check-config`: it checks the issuer and prints the redirect URI to register; the issuer must match exactly (Authentik with the trailing slash). |
| Avatars or animated images are refused, `503 media.busy` | ffmpeg missing (`TAVRN_MEDIA_FFMPEG`) or too many conversions at once (`TAVRN_MEDIA_WORKERS`). |
| Webhook posts fail with `409 webhook.pending_key` or `400 webhook.sealed_required` | See [Webhooks in end-to-end encrypted channels](#webhooks-in-end-to-end-encrypted-channels). |
| Push notifications stop for everybody | Egress HTTPS blocked, or `keys/vapid.key` was replaced (users must re-enable push). Watch `tavrn_push_failed_total`. |
| Push does not work on iPhone or iPad | The web app must be added to the home screen first. |
| `503 node.leader_unavailable` or `node.cache_unavailable` with several instances | See [Failure behaviour](#failure-behaviour). |

## Upgrade and rollback

```sh
docker compose pull && docker compose up -d
```

- **Back up first** (database and data volume together, [Keys and backups](#keys-and-backups)).
- **Migrations run automatically at start and only forward.** The node refuses to start against a database that is
  newer than the binary, so a **downgrade means restoring the backup** taken before the upgrade (database and data
  volume), then starting the older image.
- **Pin a release line** with `IMAGE_TAG` in `.env` (for example `0.1`) to get fixes without surprises; the default
  `latest` follows every release. Images are tagged `X.Y.Z`, `X.Y` and `latest`. Read the
  [release notes](https://github.com/just-tavrn/tavrn-node/releases) before moving to a new minor version; versions
  before 1.0 may still change configuration or behavior between minor versions, and the release notes say what an
  operator has to do.
- After the upgrade: check the log for configuration errors, `/readyz`, and `check-config`.
- **Several instances** behind a load balancer: update **one instance at a time** (SIGTERM: it leaves the bus, hands
  over the leadership and LiveKit stops), start the new version; migrations run under the startup lease. See
  [Scaling with Valkey](#scaling-with-valkey).
- Watch the releases of the repository for security fixes.

Rollback in short:

```sh
docker compose down
# restore the database dump and ./data (with keys/) from the backup taken before the upgrade
# set IMAGE_TAG in .env to the previous version
docker compose up -d
```

## Security hardening checklist

- [ ] TLS at the reverse proxy with HSTS; HTTP redirects to HTTPS; the node's port 8080 is published on
      `127.0.0.1` (or only on the proxy's Docker network), never on a public interface.
- [ ] `TAVRN_TRUSTED_PROXIES` lists only your proxies (and, with several instances, the instances' network).
- [ ] LiveKit's port 7880 is not published; `/rtc` goes only to tavrn; the TURN/TLS backend port is published on
      `127.0.0.1` only.
- [ ] Only the media ports (UDP range, TCP 7881, optional UDP 3478) are open besides 80/443.
- [ ] `/metrics` is off, or protected by `TAVRN_METRICS_TOKEN` and blocked at the proxy for the public.
- [ ] `POSTGRES_PASSWORD` and `VALKEY_PASSWORD` are long and random; PostgreSQL and Valkey are reachable only from
      the node's network (no host ports).
- [ ] Secrets in files where possible (`TAVRN_OIDC_CLIENT_SECRET_FILE`); `.env` readable only by the operator.
- [ ] `./data/keys` stays mode 0600, owned by the container user; it is backed up, encrypted, and the restore has
      been tested.
- [ ] `TAVRN_STORAGE_ENCRYPTION=on` (the default).
- [ ] Registration fits your community: `invite` or `closed` unless you want open sign-ups; with `open`, a captcha
      (`TAVRN_CAPTCHA_PROVIDER`) and `TAVRN_EMAIL=required` with SMTP.
- [ ] Node admins are few; with `TAVRN_OIDC_ONLY=true` at least one break-glass account in `TAVRN_ADMIN_USERS`.
- [ ] `TAVRN_UPLOAD_ALLOW_EXECUTABLES=false` (the default); `TAVRN_UPLOAD_ALLOWED_TYPES` as narrow as practical.
- [ ] SSRF switches stay off unless needed: `TAVRN_FEDERATION_ALLOW_PRIVATE`, `TAVRN_APP_ALLOW_PRIVATE_URLS`,
      `TAVRN_FILES_EXTERNAL_PRIVATE`.
- [ ] Never `--dev`, `TAVRN_FEDERATION_DEV_PEERS` or `TAVRN_DEV_MISBEHAVE` in production.
- [ ] Consider `TAVRN_FEDERATION_REQUIRE_CONFORMANCE=true` and a `TAVRN_FEDERATION_BLOCKLIST`; for a closed
      community `TAVRN_FEDERATION_ALLOWLIST` or `TAVRN_FEDERATION_ENABLED=false`.
- [ ] The container runs as shipped: unprivileged user, read-only root file system, `tmpfs` on `/tmp`.
- [ ] `IMAGE_TAG` pinned to a release line; releases watched for security fixes; backups before every upgrade.
- [ ] Logs rotated and treated as personal data; the privacy policy says what the node sees.
- [ ] Legal contact, imprint and privacy policy published where the law requires them
      ([Legal pages and GDPR](#legal-pages-and-gdpr)).

Report vulnerabilities privately as described in the [security
policy](https://github.com/just-tavrn/.github/blob/main/SECURITY.md).