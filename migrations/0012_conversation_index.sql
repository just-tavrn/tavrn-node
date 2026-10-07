-- Conversation index (FEDERATION.md §4): per local user the client-maintained list of rooms and
-- conversations on any node, stored in plaintext as one JSON array. `version` grows with every write
-- and is the ETag for optimistic concurrency (`If-Match`).
CREATE TABLE conversation_index (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version    BIGINT NOT NULL,
    items      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
