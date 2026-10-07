-- Phase 5 step 4 (protocol/APPLICATIONS.md §6): incoming webhooks, the envelope field `webhook` of their messages,
-- and the outgoing event subscriptions of applications with their outbox. Portable SQL: TEXT ids, RFC 3339
-- timestamps, BIGINT booleans, JSON arrays as TEXT.

-- One row per webhook. The secret of the URL is stored only as base64url SHA-256 (`token_hash`). `user_id` is the
-- webhook's pseudo user (`users.kind = 'webhook'`, username `wh.<lowercase id>`), the author of its messages; it
-- stays as a disabled tombstone when the webhook is deleted, so its messages keep an author.
CREATE TABLE webhooks (
    id                      TEXT PRIMARY KEY,
    room_id                 TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    channel_id              TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id                 TEXT NOT NULL REFERENCES users(id),
    name                    TEXT NOT NULL,
    token_hash              TEXT NOT NULL,
    allow_mentions_everyone BIGINT NOT NULL DEFAULT 0,
    suspended               BIGINT NOT NULL DEFAULT 0,
    created_by              TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at              TEXT NOT NULL,
    last_used_at            TEXT
);
CREATE INDEX webhooks_channel ON webhooks(channel_id);
CREATE INDEX webhooks_room ON webhooks(room_id);

-- Envelope field `webhook: { id, name }` (name = the per-message `username` or the webhook's name at the time).
ALTER TABLE messages ADD COLUMN webhook_id TEXT;
ALTER TABLE messages ADD COLUMN webhook_name TEXT;

-- The event subscription of an application (§6.2), at most one per application.
CREATE TABLE application_subscriptions (
    application_id  TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    events          TEXT NOT NULL,                     -- JSON array of event types
    state           TEXT NOT NULL DEFAULT 'active',    -- active | failing | disabled
    last_success_at TEXT,
    last_error      TEXT,
    dropped         BIGINT NOT NULL DEFAULT 0,          -- events dropped because the queue was full
    enabled_at      TEXT NOT NULL,                     -- last (re-)verification
    created_at      TEXT NOT NULL
);

-- Queued hook deliveries: the exact JSON body per event and application, retried like FEDERATION.md §5.3.
CREATE TABLE application_outbox (
    id             TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    event_id       TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    body           TEXT NOT NULL,
    attempts       BIGINT NOT NULL DEFAULT 0,
    next_at        TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    last_error     TEXT
);
CREATE INDEX application_outbox_due ON application_outbox(next_at);
CREATE INDEX application_outbox_app ON application_outbox(application_id, id);
