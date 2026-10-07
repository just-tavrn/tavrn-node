-- Threads, forum and announcement channels (protocol/PROTOCOL.md §7e). Portable SQL.

-- Threads of a channel are archived after this many minutes without a message (default 7 days).
ALTER TABLE channels ADD COLUMN auto_archive_minutes BIGINT NOT NULL DEFAULT 10080;
-- Forum channels: the tag list, JSON `[{ "id", "name", "emoji" }]` (at most 20).
ALTER TABLE channels ADD COLUMN forum_tags TEXT NOT NULL DEFAULT '[]';

-- A thread is a sub-conversation inside its channel: its messages are messages of the channel with `thread_id`.
CREATE TABLE threads (
    id              TEXT PRIMARY KEY,
    channel_id      TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- The channel message the thread was started from (text channels); NULL for standalone threads and forum
    -- posts. Deleting the root keeps the thread (no foreign key).
    root_message_id TEXT UNIQUE,
    -- Plaintext (unencrypted channels) or content-format ciphertext (encrypted channels, title_epoch set).
    title           TEXT NOT NULL,
    title_epoch     BIGINT,
    title_author_id TEXT NOT NULL REFERENCES users(id),
    title_device_id TEXT,
    -- Forum posts: JSON list of tag ids of the channel.
    tags            TEXT NOT NULL DEFAULT '[]',
    created_by      TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    last_message_id TEXT,
    last_message_at TEXT NOT NULL,
    message_count   BIGINT NOT NULL DEFAULT 0,
    archived_at     TEXT,
    locked          BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX threads_channel_activity ON threads(channel_id, last_message_at);
CREATE INDEX threads_channel_created ON threads(channel_id, id);
CREATE INDEX messages_thread ON messages(thread_id, id);

-- Per user and thread: following (notifications and unread counts) and the per-thread read marker.
CREATE TABLE thread_members (
    thread_id            TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following            BIGINT NOT NULL DEFAULT 1,
    followed_at          TEXT NOT NULL,
    last_read_message_id TEXT,
    PRIMARY KEY (thread_id, user_id)
);
CREATE INDEX thread_members_user ON thread_members(user_id, following);
