-- Phase 3, steps 1 and 2 (FEDERATION.md): discovery cache, tokens, remote users and federated sessions,
-- signed inbox and outbox. Portable SQL: TEXT ids and RFC 3339 timestamps, BIGINT booleans/counters.

-- Incremented on every change of display name or avatar (§2.7); remote nodes refresh their mirror by it.
ALTER TABLE users ADD COLUMN profile_version BIGINT NOT NULL DEFAULT 1;

-- Remote devices (§2.5): the local row id stays a fresh ULID, the home device id is stored beside it,
-- so a remote device can never collide with or take over a local device row.
ALTER TABLE devices ADD COLUMN home_device_id TEXT;
ALTER TABLE devices ADD COLUMN home_domain TEXT;
CREATE UNIQUE INDEX devices_home ON devices(user_id, home_device_id);

-- Hard end of a federated session (7 days after the federated login), whatever the refreshes.
ALTER TABLE sessions ADD COLUMN max_expires_at TEXT;

-- Mirror state of remote users (§2.6). The users row itself holds the mirrored profile.
CREATE TABLE remote_users (
    user_id            TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    profile_version    BIGINT NOT NULL DEFAULT 0,
    profile_fetched_at TEXT,
    avatar_sha256      TEXT,
    avatar_mime        TEXT,
    keys_fetched_at    TEXT,
    last_login_at      TEXT
);

-- Discovery documents of peers (§1.4, called `known_nodes` in the spec). `status`: ok | key_conflict.
-- `kid_refresh_at`: last refetch caused by an unknown `kid` (at most one per 5 minutes).
-- Reserved for conformance and reputation (§9.3): conformance, conformance_checked_at, reputation.
CREATE TABLE federation_peers (
    domain                 TEXT PRIMARY KEY,
    document               TEXT NOT NULL,
    fetched_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'ok',
    kid_refresh_at         TEXT,
    conformance            TEXT,
    conformance_checked_at TEXT,
    reputation             BIGINT NOT NULL DEFAULT 0
);

-- Every key ever seen per peer and kid: a kid that later names a different key is a hard failure.
CREATE TABLE federation_peer_keys (
    domain        TEXT NOT NULL,
    kid           TEXT NOT NULL,
    x             TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (domain, kid)
);

-- Spent `jti`s of tokens of other nodes, kept until exp + 5 minutes (§2.1).
CREATE TABLE federation_replay (
    iss        TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (iss, jti)
);
CREATE INDEX federation_replay_expires ON federation_replay(expires_at);

-- Recipients of revocations and key changes (§2.4), pruned after 30 days without a new token.
CREATE TABLE federation_targets (
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    target         TEXT NOT NULL,
    last_issued_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id, target)
);

-- Inbox dedupe by (sender, message id) for 7 days (§5.1).
CREATE TABLE federation_inbox_seen (
    iss     TEXT NOT NULL,
    id      TEXT NOT NULL,
    type    TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (iss, id)
);
CREATE INDEX federation_inbox_seen_at ON federation_inbox_seen(seen_at);

-- Outgoing notifications (§5.3). `body` is the exact JSON sent on every attempt.
CREATE TABLE federation_outbox (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    type        TEXT NOT NULL,
    body        TEXT NOT NULL,
    attempts    BIGINT NOT NULL DEFAULT 0,
    next_at     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    last_status BIGINT,
    last_error  TEXT
);
CREATE INDEX federation_outbox_due ON federation_outbox(next_at);
CREATE INDEX federation_outbox_target ON federation_outbox(target);
