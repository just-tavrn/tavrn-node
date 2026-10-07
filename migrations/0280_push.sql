-- Web push (protocol PROTOCOL.md §6d, RFC 8030/8291/8292): the push subscriptions of local users' devices.
-- Portable SQL: TEXT ids (ULID), RFC 3339 timestamps, booleans as BIGINT 0/1.

-- One browser push subscription per row. `endpoint` is the push service URL the browser handed out (unique: one
-- browser profile registers it once; a new sign-in on the same browser takes it over). `p256dh` (65-byte uncompressed
-- P-256 point) and `auth` (16 bytes) are the browser's keys of RFC 8291, base64url. A subscription belongs to the
-- device that registered it and goes with the device and its sessions. `failures` counts consecutive failed
-- deliveries (429/5xx/network); `retry_at` holds back the next attempt after one; `expires_at` is the browser's
-- `expirationTime` if it gave one.
CREATE TABLE push_subscriptions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    endpoint     TEXT NOT NULL UNIQUE,
    p256dh       TEXT NOT NULL,
    auth         TEXT NOT NULL,
    expires_at   TEXT,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    failures     BIGINT NOT NULL DEFAULT 0,
    retry_at     TEXT
);
CREATE INDEX push_subscriptions_user ON push_subscriptions(user_id);
CREATE INDEX push_subscriptions_device ON push_subscriptions(device_id);
