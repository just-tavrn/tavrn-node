# Changelog

Changes of the tavrn node and its container image `ghcr.io/just-tavrn/tavrn-node`, newest first. Releases are the
tags `vX.Y.Z` of this repository; the image tags follow them (`X.Y.Z`, `X.Y`, `latest`). Upgrade notes are in the
[README](README.md) ("Upgrading"); protocol changes in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release of the node and its container image.

- **Message components** (protocol APPLICATIONS.md §5.10, capability `components.v1`): buttons and select menus in
  bots' messages (refused in plaintext from people and webhooks, `400 message.components_invalid` with `meta.path`),
  `POST /conversations/{id}/messages/{message_id}/interactions` (permission `use_components`, bit 40, granted once
  to every role with *Send messages*, marker `fixup.use_components`), the callback types `update` and `modal`,
  `POST /interactions/{id}/submit`, events `component.invoke` and `modal.submit`, `message_id` on ephemeral replies,
  and `TAVRN_COMPONENT_MAX_AGE_DAYS` (default 30, 0 = no limit).
- **Performance and observability**: the database pool keeps 2 PostgreSQL connections open while idle, closes
  further idle ones after 30 minutes and pings a connection only after 30 seconds of idleness (the first requests
  after a quiet period no longer pay a new connection, and no request pays a ping); a role save is one statement
  with its audit row in the same transaction; a voice leave answers before LiveKit confirmed the removal (a rejoin
  of the same device waits for it); migration 0410 indexes a room's categories and permission overrides. A WebSocket
  connection reads through a 4 KiB buffer instead of 128 KiB: zeroing the large buffer before every read was about
  40 % of the node's user CPU while it fans messages out (the 20 msg/s benchmark to 200 connections needs a third
  to almost half less CPU), and an open connection holds 70 to 100 KiB less memory.
  `TAVRN_LOG_SLOW_REQUEST_MS` (default off) logs requests at or above a
  threshold with route template, status, duration and statement count; `TAVRN_DB_SLOW_STATEMENT_MS` (default 1000,
  0 = off) sets the threshold of the slow statement warning (docs/HANDBOOK.md "Performance").
- **Fan-out and services under load**: a message's web pushes load their recipients in batches (one statement per
  500 users instead of four per member; 108 statements for a channel with 20 offline subscribers became 13), skip
  coalesced members first, deliver to several users at once, and DMs, mentions, rings and notices have a queue of
  their own; attachments stream into storage (memory per upload is a chunk, not the file) and are cut off at the
  limit; the embedded web client is served without a copy per request, compressed and with an `ETag`; room
  auto-moderation rules are compiled once per room and matched in one pass over the message; the search index is
  written from the message after its delivery; `notify` hints to many remote members are queued in one statement,
  limited per node; the channel visibility snapshot evaluates each member once, keeps viewers as bit sets and
  survives cosmetic updates (nicknames, topics, descriptions); WebSocket sends time out after 15 seconds; the
  heartbeat checks all connected devices together; GIF searches are cached and limited per user, and provider
  errors (GIF, captcha) answer `503`/`502` instead of `500`; background workers start again after a panic.

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
  `docker build` still builds for the host's own architecture. The image's minimal ffmpeg is 8.1.3, the release the
  tests run against (README.md "Tool versions"); the Rust dependencies are a layer of their own (cargo-chef), so a
  build after a code change reuses them.
- **Files channels on external stores only** (`TAVRN_FILES_INTERNAL=off`, protocol FILES.md §5): the node keeps no
  files of files channels; a new files channel takes uploads and folders once its managers set a WebDAV or S3 store
  (`403 files.internal_disabled` before, `backend: "none"` in its usage), and the node's own storage cannot be
  chosen. `GET /node` and the discovery document carry `files_internal`.
- **Entitlement `files_channels.internal`** (protocol ENTITLEMENTS.md, FILES.md §5; fixes #64): a room key whose node
  default is `TAVRN_FILES_INTERNAL`; a value set by the room owner's plan or override, or by a room grant, wins in
  both directions (rule `setting`), so an operator can allow the node's own storage for some owners on a node with
  external stores only (the quota `files_channels.max_bytes` applies there), or take it away for some on a node
  that keeps files. The files usage carries the room's value as `internal_allowed`, `GET …/files/backend` too;
  `files_internal` in `GET /node` stays the node default.
- **Voice session timer and channel status** (protocol VOICE.md §5, §2a; fixes #65, #66): every voice state carries
  `session_started_at` (set with the first connected participant of an empty channel, kept while anybody is
  connected or reconnecting, cleared with the last one; in memory with the participants), and voice channels carry
  a `status` line (at most 128 characters) that members with the new channel-scoped permission `voice_status`
  (bit 38) change through `PATCH …/channels/{id}` `{ status }` without `manage_channels` (`403
  channel.status_forbidden`, `400 channel.status_not_voice` on other kinds; audit `channel.voice_status`, event
  `channel.update`). Migration 0390 adds the column; a startup fixup grants the bit once to every role that holds
  `manage_channels` (`fixup.voice_status`).
- **Reaction events name the change and the reactor** (protocol PROTOCOL.md §6, §7 "Reactions"; fixes #83,
  just-tavrn/tavrn-protocol#43): the `message.update` of a reaction change carries `reaction: { emoji, user,
  user_id, added }` and is sent only when the reactions changed. Message events (`message.create`, `message.update`
  of reactions, edits, pins and poll closes, also those of event subscriptions) carry `reactions[].me = false` for
  every recipient; responses keep the caller's flags. `GET /conversations/{id}/messages/{message_id}/reactions/{emoji}?after=&limit=`
  lists the reactors (oldest first, at most 100 per page, the message's read rules, bots `messages:read`).
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

- A database outage during the WebSocket hello closes with `1013` (try again later, reason `db.unavailable`) instead
  of `4001 auth.token_invalid`, which made clients refresh and then end the session.
- Malformed JSON bodies and query strings answer Problem Details (`400 request.invalid_json`,
  `400 request.invalid_query`) instead of plain text, and every Problem Details body carries the
  `request_id` of the `x-request-id` header; the request log span (route, request id) is at level info, so a
  reported error can be found in the log.
- A message is written together with its attachments, spoilers and poll close time (one transaction), and an admin
  user update is validated as a whole before anything changes.
- The refresh of a remote bot's profile after `app.changed` sends `user.update { user }` like every other sender
  (it sent the bare user object; fixes #90).

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

- One node may hold at most 500 entries of a bot's install index (of 10 000), so it can no longer fill the index and
  make the bot miss other nodes' installations.
- A bot's interaction replies and follow-ups pass the checks of an ordinary message: role mentions, the room's and the
  node's content rules, slowmode, blocks and the channel kind; they are indexed for search like the bot's own
  messages.
- Room auto-moderation rules are matched off the request threads within a fixed work budget per message, and the
  matcher skips the starts of a term that cannot match, so crafted rules and messages no longer cost seconds of CPU
  per message; a message that would need more work than the budget is refused with `403 automod.blocked`.
- Auto-moderation `delete` and `timeout` rules act only on members ranked below the member who last saved the rules
  (the rank is recorded with them), so a low-ranked room manager can no longer time out or silence higher moderators
  through a rule.
- Auto-moderation timeouts (keyword rules and the flood limit) publish `member.update` like a moderator's timeout, so
  clients learn them and ephemeral events and typing are refused at once.
- Several instances: when events may have been lost on the cache bus, an instance drops its channel visibility
  snapshots and every WebSocket reloads the rooms it receives, so a membership whose `member.leave` was lost no longer
  receives the room's events.
- A remote user counts against their own limit (`TAVRN_FEDERATION_RATE_API_PER_USER`, default 600 per minute) before
  the budget of their home domain, and federated logins against a share per account and per client address, so one
  account can no longer lock the other users of its domain out; a rate-limited WebSocket hello closes with `4002
  rate_limited` instead of `4001`.
- `TAVRN_TRUSTED_PROXIES` defaults to loopback only (it listed every private network, so on a node reached directly
  from a private network every client could choose its rate-limit address with `X-Forwarded-For` and read `/metrics`).
  `deploy/docker-compose.yml` sets Docker's private ranges, where the reverse proxy connects through Docker's gateway;
  other setups list their proxy (docs/HANDBOOK.md).
- Configuration printouts no longer show a password from a query parameter that contains `@`, and an invalid
  `TAVRN_SMTP_URL` is named in the error without its password.
- `POST /auth/login` refuses a username no account can have (`400 auth.username_invalid`) before it is looked up or
  counted; the anonymous sign-in routes take bodies of at most 16 KiB; rate limiters store long keys as hashes and
  keep a hard bound on their number of keys, also on single-instance nodes.
- The in-memory rate limiter keeps keys that reached their limit when its map is full, so a full map no longer unlocks
  locked accounts.
- A `Tavrn-Relayed` value with an extreme time is refused instead of overflowing the age check.
- `check-config` prints the passwords of `TAVRN_DATABASE_URL` and `TAVRN_SMTP_URL`, secret query parameters, the
  Turnstile secret and the GIF key as `***`. The image's health check is the new `tavrn-node health` (one request to
  `/healthz`, nothing printed), so the container state no longer holds the configuration and the identity provider
  is not contacted every 30 seconds.
- The history window of encrypted conversations (ENCRYPTION.md §7b) also applies to the records of files channels
  after a key reset and to pins and reactions: `GET …/pins` lists only pinned messages inside the requester's window,
  and reaction and pin routes answer `404 message.not_found` for messages outside it.
- `Tavrn-Relayed` (several instances) is honoured only with a valid HMAC of one of the node's instances; a header a
  client sets is ignored.
- Purge confirmation tokens (rooms and node admins) execute once.
- The HTTP clients of link previews and external file stores fail closed when they cannot be built; provider and
  LiveKit errors are logged without the request URL (no API key, search term or access token in the log).
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

