# Several instances of one node

A tavrn node normally runs as **one** `tavrn-node serve` process with PostgreSQL: everything short-lived (realtime
events, presence, rate limits, flow state) lives in that process's memory. For more capacity or availability an
operator can run **several instances of the same node** behind a load balancer. They share

- one PostgreSQL database (`TAVRN_DATABASE_URL`, unchanged),
- one `/data` volume (node keys, `secrets.key`, `storage.key`, `livekit.key`, uploaded files, media),
- one Valkey or Redis ≥ 7 (`TAVRN_CACHE_URL`).

With `TAVRN_CACHE_URL` unset nothing changes: no Valkey, no new dependency, every code path below takes its
in-memory branch.

## 1. How the instances act as one node

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

### Realtime resync

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

## 2. Audit of the in-memory state

"Per instance" means each instance keeps its own copy and that is correct (or acceptable, with the reason);
"shared" means it moved to the cache or the database; "leader only" means one instance at a time.

### Realtime, presence and connections

| State | Decision | Reason / implementation |
|---|---|---|
| Hub broadcast (`hub.rs`) | **shared** | Bus fan-out, see §1. |
| Hub online map (WebSockets per user) | per instance + replica | The local count stays; `presence::is_online` adds the replicated connections of the other instances (calls ringing, presence audiences, `notify` hints to remote members in `federation/social.rs`). |
| `last_event_id` replay | — | No ring buffer exists; always `resync` (§1). |
| Presence registry (`presence.rs`): connections, idle flag, activity per device | **shared** (bus replica) | REST calls (`PUT /users/me/presence`, activity) and the WebSocket of the same device usually hit different instances. |
| Presence batching (`last_sent`, `pending`, `last_public`) | per instance | Only throttles the updates an instance sends; a duplicate update after a change on another instance is harmless (clients apply the latest). |
| Custom status expiry timers | per instance | Readers filter expired statuses anyway; the timer only pushes the update. |
| Typing throttle (per connection) | per instance | Bound to the WebSocket. |
| App token connections (≤ 2 per token, APPLICATIONS.md §2.6) | **shared** | Hash `appconn:<token>` in the cache (field `<instance>/<id>`); beyond two the oldest connection is closed wherever it is (bus message to its instance). |
| Command receivers and pending interactions (`interactions.rs`, APPLICATIONS.md §5.6) | **shared** registry + owner | Receivers in the hash `cmdrecv:<bot user id>`; a pending interaction lives on the instance that took the invocation, `interaction:<id>` names it, callbacks and follow-ups are relayed there (see the note at the end). |
| `access_not_before` | per instance | Development test hook (`POST /dev/expire-access-tokens`), never set in production. |

### Rate limits

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

### Single-use tokens, nonces and challenges

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

### Caches

| Cache | Decision | Reason |
|---|---|---|
| Unfurl results (1 h, LRU) | per instance | Public link previews; a miss refetches. |
| OIDC discovery document and JWKS | per instance | Refetched on demand. |
| Federation client: delegation cache, discovery endpoints, per-peer concurrency semaphores | per instance | Caches of signed or re-validated public data; the concurrency cap per peer becomes N× (each instance is its own client). |
| Federation key cache, discovery cache, remote emoji/sound copies | database / storage (already) | |
| Entitlements | database (no in-memory cache) | |
| Whiteboard audience cache (2 s) | leader only | Ephemeral events are relayed to the leader. |

### Voice, calls, whiteboards

| State | Decision | Reason |
|---|---|---|
| Voice participants (`voice/state.rs`) | **leader only** | All voice routes and the LiveKit webhook are relayed to the leader; it reconciles every 30 s against LiveKit, whose room service answers for the whole LiveKit cluster. After a leader change the new leader rebuilds the participants from LiveKit at its first reconciliation (≤ 30 s, `voice.state` is published then). |
| Call state (`calls.rs`: ringing, participants) | **leader only** + flag | Call routes are relayed; the leader keeps `call:<conversation>` in the cache while a call runs so the `/rtc` proxy of every instance can admit its members. A leader change ends running DM calls (the ringing and answer state is gone; the reconciliation then removes their participants): like a restart of a single node, documented limitation. |
| Whiteboard sessions | **leader only** | Session routes and ephemeral events are relayed; the sweep runs on the leader. Fan-out of the events goes over the bus. After a leader change the owner's next keepalive (30 s) opens the session again, as after a restart. |
| Soundboard play | leader only | Relayed (it checks the voice participants); the data message itself travels through LiveKit. |
| LiveKit process status, `livekit.key` | per instance / shared file | Every instance supervises its own LiveKit; the key file on the shared volume makes them one cluster. |
| Voice side effects (kick/ban/timeout/deletion) | leader only | Handed to the leader over the bus. |
| Voice reconciliation, grace sweep | leader only | |

### Background jobs

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

LeafCleaner (the web client's MLS leaf removal, `src/lib/leafCleanup.ts` in tavrn-web) keeps its server state in the database
(`pending_removals`), so it is unaffected.

## 3. Operating several instances

### Requirements

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

### Load balancer

- **No sticky sessions needed for HTTP**: every request may go to any instance.
- **WebSockets** (`/api/v1/ws`, `/rtc`) stay on the instance they connected to until they reconnect; nothing else
  is required (no affinity). The proxy must pass `Upgrade` as for a single node.
- Health: `GET /readyz` per instance (`database`, `livekit`, `cache`). `cache: false` is reported but does not make
  the instance unready: a cache outage degrades every instance alike (local rate limits, no relaying, resync
  afterwards), taking them all out of the balancer would take the node offline. Alert on it instead.
- Rolling updates: stop one instance at a time (SIGTERM: it leaves the bus, hands over the leadership and LiveKit
  stops), start the new version; migrations run under the startup lease.

### Voice and video (LiveKit)

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

### Example: two instances on one host

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

### Example: an identity domain with a delegated application host

`example.org` is the identity domain, delegated to `chat.example.org`: `TAVRN_DOMAIN=example.org`,
`TAVRN_PUBLIC_URL=https://chat.example.org`, the well-known on `example.org`. `chat.example.org` resolves to the load
balancer (HAProxy, nginx or a cloud LB terminating TLS) in front of two or more instances on separate hosts; each
host has its own public IP for media, announced by STUN or `TAVRN_RTC_ADVERTISE_IPS`, and, with TURN/TLS,
its own `turnN.example.org`. PostgreSQL (managed or a primary with a replica for failover), Valkey and the shared
`/data` storage sit on the private network, reachable from the instances only. Instances can be added or removed
at any time; the leader moves by itself.

### Failure behaviour

| Situation | Behaviour |
|---|---|
| `TAVRN_CACHE_URL` set but unreachable at start | `tavrn-node serve` exits with code **3** and `TAVRN_CACHE_URL: Valkey/Redis at host:port is not reachable (…)` (no password in the message). |
| Valkey down while running | Commands time out after 2 s and reconnect with backoff (connection manager); the bus resubscribes with backoff up to 10 s. Meanwhile: security limits count per instance, connect/SSO flows answer `503 node.cache_unavailable`, there is no leader (singleton jobs pause, relayed routes are served locally), events between instances are lost. Voice is down as well (distributed LiveKit itself needs Redis), so voice side effects that find no leader are not retried. Afterwards every affected client gets `resync`. |
| Bus silently stuck (no own heartbeat echo for 20 s) | The subscription is renewed, clients resync. |
| An instance crashes | Its WebSocket clients reconnect elsewhere; the others drop its connections after 20 s; if it was the leader another one takes over within 15 s. |
| The leader is unreachable for relayed requests | `503 node.leader_unavailable` with `Retry-After: 2`. |

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_CACHE_URL` | empty | `redis://[user:password@]host[:port][/db]` or `rediss://…`; enables several instances |
| `TAVRN_INSTANCE_ID` | random per start (logged) | `[A-Za-z0-9._-]{1,64}`; names the instance in logs, the cache and `livekit-<id>.yaml` |
| `TAVRN_INSTANCE_URL` | address towards the cache + listen port | `http(s)://host[:port]` where the other instances reach this one |

> **Command interactions (APPLICATIONS.md §5.6)** reach a bot connected to any instance. The instance that takes the
> invocation owns the pending interaction, in memory as on a single node; the 3-second wait happens there. Every
> instance registers its receiving bot connections in the cache (hash `cmdrecv:<bot user id>`, field
> `<instance>/<connection>`, removed when the connection closes; entries of instances that stopped sending heartbeats
> are ignored). Without a local receiver the owner picks one live instance holding a receiver (round robin) and
> publishes `Invoke { instance, bot, data }` on the bus; that instance hands the `command.invoke` event to one of its
> connections (round robin over the bot's devices as before). The owner also stores `interaction:<id>` = its instance id
> (TTL 16 minutes, the interaction's lifetime plus a minute). The bot answers over REST, which the load balancer may send
> anywhere: callbacks and follow-ups (`/interactions/{id}/callback|messages`) for an interaction that is not pending on
> the receiving instance are relayed over HTTP to the owner's `TAVRN_INSTANCE_URL` (like the requests relayed to the
> leader, `Tavrn-Relayed` stops a second hop; `503 interaction.owner_unavailable` when the owner does not answer).
> Chosen over moving pending interactions into the cache because the waiting invocation, the "first response wins"
> claim and the follow-up counter stay in one process, with no distributed locking. A restart or crash of the owner
> loses its pending interactions (invokers get `504 interaction.no_ack`), as on a single node. The interactions URL
> (§6.3) is called by the owner itself and needs nothing of this. Without `TAVRN_CACHE_URL` nothing changes.
