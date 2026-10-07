-- Identity key rotation with continuity and device tombstones (ENCRYPTION.md §2.3, §9a; PLAN.md 4.13 items 12, 13).
-- Portable SQL: TEXT ids, RFC 3339 timestamps. `rooms.welcome_channel_enabled` stays as an unused column (the
-- welcome channel can no longer be switched off; a startup fixup sets it back to 1 everywhere).

-- The continuity chain of an account (oldest first): generation n is the key that statement n introduced
-- (generation 0, the key derived from the master secret, has no row). `identity_blob` is the new key wrapped under
-- the account's master secret (the node cannot unwrap it). An identity reset deletes the user's rows.
CREATE TABLE identity_continuity (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generation    BIGINT NOT NULL,
    old_key       TEXT NOT NULL,
    new_key       TEXT NOT NULL,
    at            TEXT NOT NULL,
    sig_old       TEXT NOT NULL,
    sig_new       TEXT NOT NULL,
    identity_blob TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (user_id, generation)
);

-- Ids of deleted local devices (ENCRYPTION.md §2.3): re-attesting a retired device is only possible for an id the
-- home node lists here. Pruned after `TAVRN_DEVICE_STALE_DAYS`.
CREATE TABLE device_tombstones (
    device_id  TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    deleted_at TEXT NOT NULL
);
CREATE INDEX device_tombstones_user ON device_tombstones(user_id);
CREATE INDEX device_tombstones_deleted ON device_tombstones(deleted_at);

INSERT INTO device_tombstones (device_id, user_id, deleted_at)
SELECT device_id, user_id, deleted_at FROM retired_devices;
