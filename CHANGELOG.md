# Changelog

Changes of the tavrn node and its container image `ghcr.io/just-tavrn/tavrn-node`, newest first. Releases are the
tags `vX.Y.Z` of this repository; the image tags follow them (`X.Y.Z`, `X.Y`, `latest`). Upgrade notes are in the
[README](README.md) ("Upgrading"); protocol changes in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release of the node and its container image.

- **Rooms and channels**: text, voice, announcement, forum and files channels, threads and forum posts, roles with
  layered permissions (room, channel and single-member overrides), visibility that withholds events, hints and pushes
  of channels a member cannot view.
- **End-to-end encryption delivery service** (MLS): key packages, commits checked against the public group state,
  stale epochs refused, history shares sealed per device, history restore after a key reset, encrypted files
  channels.
- **Federation** between nodes, direct messages and friends across nodes, a signed "over 18" claim instead of dates
  of birth.
- **Voice, video and screen sharing** through a supervised `livekit-server`, moves into voice channels, the voice
  state of all rooms (`/users/me/voice`).
- **Accounts**: mandatory second factor, passkeys, single sign-on, sessions and devices, age assurance (date of
  birth at registration, minimum age, adults-only rooms and channels).
- **Operators**: moderation with reports and evidence, auto-moderation, web push, localized mails with replaceable
  templates, message retention, metrics, legal tooling (takedown notices), clustering with Valkey, the operator
  handbook and deployment examples (Docker Compose, reverse proxies).

### Security

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

