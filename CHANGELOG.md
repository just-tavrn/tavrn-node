# Changelog

Changes of the tavrn node and its container image `ghcr.io/just-tavrn/tavrn-node`, newest first. Releases are the
tags `vX.Y.Z` of this repository; the image tags follow them (`X.Y.Z`, `X.Y`, `latest`). Upgrade notes are in the
[README](README.md) ("Upgrading"); protocol changes in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release of the node and its container image.

- **Performance and observability**: the database pool keeps 2 PostgreSQL connections open while idle, closes
  further idle ones after 30 minutes and pings a connection only after 30 seconds of idleness (the first requests
  after a quiet period no longer pay a new connection, and no request pays a ping); a role save is one statement
  with its audit row in the same transaction. `TAVRN_LOG_SLOW_REQUEST_MS` (default off) logs requests at or above a
  threshold with route template, status, duration and statement count; `TAVRN_DB_SLOW_STATEMENT_MS` (default 1000,
  0 = off) sets the threshold of the slow statement warning (docs/HANDBOOK.md "Performance").

- **Rooms and channels**: text, voice, announcement, forum and files channels, threads and forum posts, roles with
  layered permissions (room, channel and single-member overrides), visibility that withholds events, hints and pushes
  of channels a member cannot view.
- **End-to-end encryption delivery service** (MLS): key packages, commits checked against the public group state,
  stale epochs refused, history shares sealed per device, history restore after a key reset, encrypted files
  channels.
- **Federation** between nodes, direct messages and friends across nodes, a signed "over 18" claim instead of dates
  of birth. `deploy/.env.example` lists new nodes at the official reference node `tavrn.org` by default (clear `TAVRN_REFERENCE_NODES` to stay out of every directory).
- **Voice, video and screen sharing** through a supervised `livekit-server`, moves into voice channels, the voice
  state of all rooms (`/users/me/voice`).
- **Accounts**: mandatory second factor, passkeys, single sign-on, sessions and devices, age assurance (date of
  birth at registration, minimum age, adults-only rooms and channels).
- **Operators**: moderation with reports and evidence, auto-moderation, web push, localized mails with replaceable
  templates, message retention, metrics, legal tooling (takedown notices), clustering with Valkey, the operator
  handbook and deployment examples (Docker Compose, reverse proxies).
- **Container image for `linux/amd64` and `linux/arm64`**: one manifest list per tag (`edge` and the releases), so
  the node runs natively on ARM servers; the arm64 image is cross-compiled on the amd64 build host, and a plain
  `docker build` still builds for the host's own architecture.
- **Files channels on external stores only** (`TAVRN_FILES_INTERNAL=off`, protocol FILES.md §5): the node keeps no
  files of files channels; a new files channel takes uploads and folders once its managers set a WebDAV or S3 store
  (`403 files.internal_disabled` before, `backend: "none"` in its usage), and the node's own storage cannot be
  chosen. `GET /node` and the discovery document carry `files_internal`.
- **Voice session timer and channel status** (protocol VOICE.md §5, §2a; fixes #65, #66): every voice state carries
  `session_started_at` (set with the first connected participant of an empty channel, kept while anybody is
  connected or reconnecting, cleared with the last one; in memory with the participants), and voice channels carry
  a `status` line (at most 128 characters) that members with the new channel-scoped permission `voice_status`
  (bit 38) change through `PATCH …/channels/{id}` `{ status }` without `manage_channels` (`403
  channel.status_forbidden`, `400 channel.status_not_voice` on other kinds; audit `channel.voice_status`, event
  `channel.update`). Migration 0390 adds the column; a startup fixup grants the bit once to every role that holds
  `manage_channels` (`fixup.voice_status`).
- **Polls and date polls** (protocol PROTOCOL.md §7g, capability `polls.v1`; fixes just-tavrn/tavrn-protocol#35):
  messages carry the plaintext close time `poll_closes_at` (migration 0400; set on create 1 minute to 1 year ahead;
  through `PATCH …/messages/{id} { poll_closes_at }` the author or `manage_messages` closes a poll now, also one
  without a close time, or moves its close time earlier, never later; audit `message.poll_close`), plaintext polls are checked (`400 message.poll_invalid`) and cannot be edited
  (`400 message.poll_immutable`). Vote records, one per user and poll (the last device wins), live in the new table
  `poll_votes` and go with their message: `PUT`/`DELETE /conversations/{id}/messages/{message_id}/poll/vote`, `GET
  …/poll/votes`; encrypted votes pass the §5.3 checks, plaintext votes are checked against the poll; `409
  poll.closed`, `413 poll.vote_too_large` (4 KiB), 10 changes per user and minute. Events `poll.vote` and
  `poll.vote.delete` to the conversation audience; votes never count as unread or notify. Bots vote with
  `messages:write`, read votes and `poll.*` events with `messages:read`. New permission `create_polls` (bit 39,
  channel-scoped, default of `@everyone`, in DMs, denied in the welcome channel, covered by `messages:write`) for
  plaintext polls and every message with a close time; a startup fixup grants it once to every role and override
  that allows `send_messages` (`fixup.create_polls`).
- **Screen publishers for the Android app** (protocol VOICE.md §4b): `voice/join` and `call/join` take an optional
  `{ "role": "screen" }` and issue a device's second LiveKit participant `<user>/<device>#screen` that may only
  publish the screen share and its audio and never subscribes; it needs the device in the channel or call and the
  `stream` permission (`409 voice.not_connected`, `403 voice.stream_forbidden`), one per device
  (`409 voice.screen_active`), takes no seat, is listed right after its device with `screen_of` and leaves with it
  (leave, disconnect, end of the grace period, kick, another device). `voice/leave` and `call/leave` with the same
  body end it alone. Nothing to configure.
- **The files channel quota covers the node's own storage only** (protocol FILES.md §4, §5):
  `TAVRN_FILES_CHANNELS_MAX_BYTES` (`files_channels.max_bytes`) no longer limits channels on external WebDAV/S3
  stores. Their managers can set an optional limit per store in the channel's storage settings (`max_bytes` of
  `PUT …/files/backend`, `0` = unlimited), enforced with `413 files.quota_exceeded` and shown as the channel's limit.
- **Reports v2: forwarding to the home node** (protocol MODERATION.md §1.6, `reports.v2`): node admins forward a
  report about a user of another node with `POST /reports/{id}/forward` (once, through the federation outbox, the
  reporter as a pseudonym); the home node stores `report.forward` in its admins' inbox with the origin, once per
  original report and at most `TAVRN_REPORTS_INBOUND_PER_HOUR` (default 20) per sending domain and hour. Migration
  `0380_reports_v2.sql` adds the forwarding and origin columns to `reports`.

### Fixed

- A passkey whose registration did not announce the PRF extension can unlock messages after all (protocol
  ENCRYPTION.md §2.4, fixes #69): `PUT /users/me/secret-storage/passkey/{credential_id}` accepts the entry for any
  passkey of the user and marks the credential `prf_supported` in the same transaction, instead of refusing it with
  `409 secret_storage.prf_unsupported`. Some authenticators report the extension only when used or gain it with a
  system update (Windows Hello); the client's "Enable message unlock" stores the entry for them.
- A changed avatar, header, display name, bio, linked accounts or DM setting now reaches the other nodes within
  seconds: the home node sends `profile.changed` (FEDERATION.md §5.2) to the nodes the user signed in on and the home
  nodes of friends and DM contacts, coalesced to one message per user and node, and those nodes refresh their copy
  of the profile in the background (rate-limited per sender and user). Before, a DM hosted on another node kept
  showing the old picture until the user's next federated login there, which could take days. No configuration
  change is needed; nodes without this version keep refreshing as before.
- A registration that fails (missing e-mail, captcha, password, username, date of birth, terms) no longer uses up
  the invite: the invite is redeemed in the transaction that creates the account.
- Call rings are pushed also while the user has an open WebSocket (local calls and ring hints of other nodes): a
  phone keeps the connection of a frozen background tab open, so a connection did not mean the ring was heard. The
  web client's service worker shows a ring only while no page of the client is visible. Messages still push only
  without a connection.

### Security

- The connect flow no longer issues a re-authentication token, and a connect code needs one.
- Logout, password change or reset, device removal, disabling, second-factor reset and node bans end access tokens,
  WebSockets, voice and calls of the affected devices at once.
- Removing a device id that belongs to another account no longer ends that account's sessions.
- Linking or unlinking a single sign-on identity needs a re-authentication token.
- The cache of other nodes' emojis and clips is capped in total and per origin node, and its fetches are limited per
  client address; the federation client's per-peer map stays bounded.
- Password hashing runs off the request threads behind a concurrency limit; per-address limits group IPv6 clients by
  prefix; the in-memory rate limiter evicts lazily.
- Only failed logins count against an account, and the right password with a valid device proof passes a locked
  account; re-authentication and identity reset have their own limits.
- Password reset mails are limited per account and a pending reset link stays valid.
- `POST /auth/forgot-password` and `POST /auth/verify-email/resend` hand the mail to a background task after storing
  the token, so they answer as fast for an account that gets a mail as for an unknown one: with a slow SMTP relay the
  response time no longer tells which accounts or addresses exist.
- WebSocket connections count against the per-user limit, are capped per user, rate-limit read markers and refuse
  frames over 64 KiB.
- Media conversions use only the probed video stream and refuse inputs with several.
- Uploads are classified by their sanitized name; bidirectional control characters are stripped from file names.
- Without SMTP, production nodes log no mail bodies, keep no outbox and answer password reset requests with
  `503 mail.unavailable`.
- The web client's CSP no longer allows font hosts, names the captcha hosts only when a captcha is configured and
  forbids plugins; every response carries a Permissions-Policy; the Caddy example sends HSTS and hides `/metrics`.
- A discovery document found through an SRV record is requested for the identity domain: the target must present a
  certificate valid for that domain. A document from another source with none of the known keys is a key conflict.
- A key conflict or an operator block ends the peer's federated sessions at once.
- Requests to a slow peer no longer hold node-wide connection slots (`TAVRN_FEDERATION_PERMIT_TIMEOUT_SECS`); failed
  discovery is remembered for a minute; peers known only from unverified requests are capped
  (`TAVRN_FEDERATION_MAX_UNVERIFIED_PEERS`) and pruned after 30 days unused.
- The address filter refuses further IPv6 transition ranges (6to4, local-use NAT64, IPv4-compatible, Teredo) and
  192.88.99.0/24.
- Node and room domain bans cover subdomains.
- A remote stub takes kind and owner from the first federated login's verified token; a bot is never turned into a
  user.
- Inviters and callers of third nodes are treated as unverified: never a friend, always a request, shown with `via`.
- `ban.notify` is only delivered to users who signed in on the sending node.
- Forwarded legal notices need federation history and are limited per sending domain and in total
  (`TAVRN_LEGAL_NOTICE_INBOUND_PER_HOUR`); they send no confirmation mail to the address the sender named.
- Profile reads start at most one background refresh per remote user and minute.
- Discovery fetches for unknown issuers of unverified requests run in their own slots
  (`TAVRN_FEDERATION_DISCOVERY_SLOTS`), so floods naming many slow domains leave the shared slots to known peers.
- Ring pushes naming a caller of a third node carry `via`.
- A remote user's identity reset is recorded together with its history window or not at all (the home node retries).
- Assigning a role is limited to roles whose permissions the actor holds; override deny bits and upload categories are
  limited to what the actor holds.
- A limited invite admits exactly as many people as it allows, also under concurrent joins.
- DM typing and call joins respect blocks and message requests; blocking ends a running DM call.
- The room-wide webhook list and purge events leave out channels hidden from the member.
- Generated node signing keys get a `kid` of the date plus a random suffix, so a restored node never repeats one.
- An external join must remove every leaf that carries the joining device's key; a device is in an MLS group at most
  once.
- A member may remove a leaf whose key is not the attested key of the device it names.
- The delivery service refuses commits that change a leaf's identity or leave two leaves with the same key.
- An identity reset records the history window of the account's memberships in the reset's own transaction.
- KeyPackage claims for a user by requesters who share no room, DM or friendship with them count against a budget per
  source (this node or one other node) and target user (`TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR`, default 60).
- Release images are built GitHub-hosted without any build cache, from a tavrn-web release tag (a branch fails the
  release), by a reusable workflow pinned by commit, and carry a GitHub build provenance attestation.
- The `edge` image is built on GitHub-hosted runners only, never on the shared self-hosted runners.
- The Dockerfile pins every base image by digest; CI and the `just` install recipes check livekit-server and ffmpeg
  downloads against pinned checksums, and the CI Valkey is pinned by digest.
- The publication check prints only file and line of a private match, never the matching text.

