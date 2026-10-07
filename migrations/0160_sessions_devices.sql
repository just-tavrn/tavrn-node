-- Sessions and devices (PLAN.md §8, PROTOCOL.md §5b, ENCRYPTION.md §4.7).
-- Portable SQL: TEXT ids, RFC 3339 timestamps.

-- Refresh rotation with a short grace: the time of the last rotation. Presenting the immediately previous refresh
-- token (`prev_refresh_token_hash`) within 30 seconds of it answers with the same new token instead of revoking
-- the session (two tabs or two parallel requests that refreshed at once).
ALTER TABLE sessions ADD COLUMN rotated_at TEXT;
CREATE INDEX sessions_prev_hash ON sessions(prev_refresh_token_hash);
CREATE INDEX sessions_device ON sessions(device_id);

-- MLS leaves that must be removed from a group (ENCRYPTION.md §4.7): the device was deleted, is no longer attested
-- or its user is no longer entitled. Rows are deleted when a commit removes the leaf, when the leaf is gone from the
-- roster, or after 90 days.
CREATE TABLE mls_pending_removals (
    conversation_id TEXT NOT NULL,
    identity        TEXT NOT NULL,          -- <user address>/<device id>
    reason          TEXT NOT NULL,          -- deleted | unattested | not_member
    created_at      TEXT NOT NULL,
    PRIMARY KEY (conversation_id, identity)
);
CREATE INDEX mls_pending_removals_identity ON mls_pending_removals(identity);
CREATE INDEX mls_pending_removals_created ON mls_pending_removals(created_at);

-- Retired devices (ENCRYPTION.md §2.3, §5.2): a deleted device keeps its attested key here, so the history it wrote
-- stays verifiable and decryptable. A separate table rather than a flag on `devices`, so that nothing that works with
-- active devices (sessions, KeyPackages, claims, commits, device lists) can pick up a removed one. `source`: `deleted`
-- (copied when the device was deleted) or `reattested` (attested again by a device of the same user from the leaf key
-- in an MLS roster, for devices deleted before this table existed).
CREATE TABLE retired_devices (
    device_id             TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key            TEXT NOT NULL,
    identity_signature    TEXT NOT NULL,
    attested_identity_key TEXT,
    source                TEXT NOT NULL,
    deleted_at            TEXT NOT NULL
);
CREATE INDEX retired_devices_user ON retired_devices(user_id);
