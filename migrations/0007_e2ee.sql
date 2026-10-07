-- Phase 2 (end-to-end encryption, ENCRYPTION.md), direct messages and friends.
-- Keys and signatures are base64url TEXT (like users.identity_pubkey); MLS messages, DS state and
-- backups are binary. BYTEA is PostgreSQL's binary type; SQLite accepts the type name and stores
-- the bound byte strings as BLOB values unchanged.

-- Device keys and their attestation by the account identity key (ENCRYPTION.md §3.1).
-- A device counts as attested only while attested_identity_key equals users.identity_pubkey.
ALTER TABLE devices ADD COLUMN public_key TEXT;
ALTER TABLE devices ADD COLUMN identity_signature TEXT;
ALTER TABLE devices ADD COLUMN attested_identity_key TEXT;
ALTER TABLE devices ADD COLUMN attested_at TEXT;

-- Single-use MLS KeyPackages per device (§3.2).
CREATE TABLE key_packages (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_package BYTEA NOT NULL,
    hash        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX key_packages_hash ON key_packages(hash);
CREATE INDEX key_packages_device ON key_packages(device_id, id);

-- Delivery service state per conversation (§4.4).
CREATE TABLE mls_groups (
    conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL,
    group_info      BYTEA NOT NULL,
    ds_state        BYTEA NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Handshake log; the primary key enforces "first commit for an epoch wins".
CREATE TABLE mls_commits (
    conversation_id     TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch               BIGINT NOT NULL,
    message             BYTEA NOT NULL,
    committer_device_id TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    PRIMARY KEY (conversation_id, epoch)
);

-- Pending Welcomes, one row per added device.
CREATE TABLE mls_welcomes (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL,
    welcome         BYTEA NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX mls_welcomes_device ON mls_welcomes(device_id, id);

-- Encrypted history backups (§7). `conversation` is the qualified id `<domain>/<ULID>`.
CREATE TABLE key_backups (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation TEXT NOT NULL,
    blob         BYTEA NOT NULL,
    etag         TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (user_id, conversation)
);

-- Direct messages and group DMs. `dm_key` (both user ids, sorted) makes 1:1 DMs unique.
ALTER TABLE conversations ADD COLUMN name TEXT;
ALTER TABLE conversations ADD COLUMN creator_id TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE conversations ADD COLUMN dm_key TEXT;
CREATE UNIQUE INDEX conversations_dm_key ON conversations(dm_key);

CREATE TABLE conversation_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at       TEXT NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX conversation_members_user ON conversation_members(user_id);

-- Friends (local node; federation in phase 3). A friendship is stored in both directions.
CREATE TABLE friends (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_id)
);

CREATE TABLE friend_requests (
    id           TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    UNIQUE (from_user_id, to_user_id)
);
CREATE INDEX friend_requests_to ON friend_requests(to_user_id);

CREATE TABLE user_blocks (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, blocked_id)
);
