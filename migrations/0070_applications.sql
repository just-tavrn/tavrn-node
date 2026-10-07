-- Phase 5 step 1 (protocol/APPLICATIONS.md §1–§3): applications (bot accounts with an owner), app tokens,
-- transfers, the node's application blocklist and "no bots" zones. Portable SQL: TEXT ids, RFC 3339
-- timestamps, BIGINT booleans and masks, JSON arrays as TEXT.

-- Every user object of a bot carries its owner and application (APPLICATIONS.md §1.4). Kept on the user row
-- so that every `User` can be built without a join: `owner_address` is the owner's address (also for
-- remote bots, from the federation token), `application_id` the application ULID (local bots) or the
-- application reference `<domain>/<ULID>` (remote bots).
ALTER TABLE users ADD COLUMN owner_address TEXT;
ALTER TABLE users ADD COLUMN application_id TEXT;
-- `TAVRN_APP_CREATION=invite`: applications a user may still create (consumed per creation).
ALTER TABLE users ADD COLUMN app_creation_grant BIGINT NOT NULL DEFAULT 0;

CREATE TABLE applications (
    id                    TEXT PRIMARY KEY,
    bot_user_id           TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    owner_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    public                BIGINT NOT NULL DEFAULT 0,
    requested_permissions BIGINT NOT NULL DEFAULT 0,
    scopes                TEXT NOT NULL,              -- JSON array, the upper bound of every token
    interactions_url      TEXT,
    rpc_origins           TEXT NOT NULL DEFAULT '[]', -- JSON array of https origins
    commands_version      BIGINT NOT NULL DEFAULT 0,
    disabled_at           TEXT,
    disabled_reason       TEXT,                       -- admin (owner_disabled and blocked are computed)
    created_at            TEXT NOT NULL
);
CREATE INDEX applications_owner ON applications(owner_id);

-- One row per token = per bot device (§3.2). Only SHA-256 hashes of the secrets are stored. `prev_*` keeps
-- the previous secret valid for 24 hours after a rotation by the bot (§2.2).
CREATE TABLE application_tokens (
    id                  TEXT PRIMARY KEY,
    application_id      TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    device_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    scopes              TEXT NOT NULL,                -- JSON array, ⊆ the application's scopes
    jti                 TEXT NOT NULL UNIQUE,
    token_hash          TEXT NOT NULL,
    prev_jti            TEXT,
    prev_token_hash     TEXT,
    prev_valid_until    TEXT,
    rotated_at          TEXT,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    last_used_at        TEXT,
    revoked_at          TEXT
);
CREATE INDEX application_tokens_app ON application_tokens(application_id);
CREATE INDEX application_tokens_prev ON application_tokens(prev_jti);

-- A pending transfer of an application to another local user (§1.6), one at a time.
CREATE TABLE application_transfers (
    application_id TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    from_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL
);
CREATE INDEX application_transfers_to ON application_transfers(to_user_id);

-- The node's application blocklist (§4.4, admin routes in step 2); checked for app tokens and federated
-- logins of bots from step 1 on.
CREATE TABLE application_blocks (
    subject    TEXT PRIMARY KEY,                     -- bot address
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

-- Federated sessions of remote bots carry the application reference and the effective scopes of the
-- federation token (FEDERATION.md §2.2). NULL scopes on a bot session = token of an older home node (all).
ALTER TABLE sessions ADD COLUMN application_ref TEXT;
ALTER TABLE sessions ADD COLUMN scopes TEXT;

-- "No bots" zones (§3.5, PLAN.md 4.7 item 7).
ALTER TABLE rooms ADD COLUMN no_bots BIGINT NOT NULL DEFAULT 0;
ALTER TABLE categories ADD COLUMN no_bots BIGINT NOT NULL DEFAULT 0;
ALTER TABLE channels ADD COLUMN no_bots BIGINT NOT NULL DEFAULT 0;
