-- Polls (protocol PROTOCOL.md §7g). Portable SQL: TEXT ids (ULID), RFC 3339 timestamps, BIGINT integers.
-- `poll_closes_at` is the plaintext close time of a poll message (UTC, null = none): the node refuses votes after it.
-- `poll_votes` holds one vote record per user and poll message (the last device to vote wins): `content` is the
-- ciphertext (encrypted conversations, with its `epoch`) or the plaintext vote object with its optional device
-- `signature`. Votes go with their message (cascade: deletion, purge, retention) and with their user.
ALTER TABLE messages ADD COLUMN poll_closes_at TEXT;
CREATE TABLE poll_votes (
    message_id      TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL,
    device_id       TEXT,
    epoch           BIGINT,
    content         TEXT NOT NULL,
    signature       TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (message_id, user_id)
);
