-- Anhänge (Blobs), Reaktionen (Tabelle existiert), angepinnte Nachrichten.
CREATE TABLE blobs (
    id              TEXT PRIMARY KEY,
    uploader_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    room_id         TEXT REFERENCES rooms(id) ON DELETE CASCADE,
    message_id      TEXT REFERENCES messages(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    mime            TEXT NOT NULL,
    size            BIGINT NOT NULL,
    sha256          TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX blobs_message ON blobs(message_id);
CREATE INDEX blobs_room ON blobs(room_id);
CREATE INDEX blobs_unbound ON blobs(created_at) WHERE message_id IS NULL;

CREATE TABLE pins (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id      TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pinned_at       TEXT NOT NULL,
    PRIMARY KEY (conversation_id, message_id)
);
