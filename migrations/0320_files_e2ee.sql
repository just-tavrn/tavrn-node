-- End-to-end encrypted files channels (protocol/FILES.md §8) and the queue of pending external deletes (§6, §9).
-- Portable SQL: TEXT ids (ULID), RFC 3339 timestamps, BIGINT integers.

-- Entry records of encrypted channels: content format 1 ciphertext with the name, type and file key, its epoch,
-- the writing user's address and device, and when it was written (the history window is measured on it).
-- Entries of encrypted channels keep `name` and `mime` empty and `name_key` = id.
ALTER TABLE file_entries ADD COLUMN record TEXT;
ALTER TABLE file_entries ADD COLUMN record_epoch BIGINT;
ALTER TABLE file_entries ADD COLUMN record_author TEXT;
ALTER TABLE file_entries ADD COLUMN record_device_id TEXT;
ALTER TABLE file_entries ADD COLUMN record_at TEXT;
-- The client-made thumbnail (ciphertext) in the node's own storage, and its size.
ALTER TABLE file_entries ADD COLUMN thumbnail_id TEXT;
ALTER TABLE file_entries ADD COLUMN thumbnail_size BIGINT NOT NULL DEFAULT 0;

CREATE INDEX file_entries_records ON file_entries(channel_id, record_at, id);
CREATE INDEX file_entries_owner ON file_entries(channel_id, created_by, id);
CREATE INDEX file_entries_thumbnail ON file_entries(thumbnail_id);

-- Objects on external stores that still have to be deleted (deleted entries, channels and rooms). The store's
-- configuration is copied sealed (secrets.key, bound to `channel_id`), so it outlives the channel; no foreign
-- keys for the same reason. `object_key` is the entry id (the store adds its prefix).
CREATE TABLE file_pending_deletes (
    id         TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    kind       TEXT NOT NULL,
    config     TEXT NOT NULL,
    object_key TEXT NOT NULL,
    attempts   BIGINT NOT NULL DEFAULT 0,
    next_at    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX file_pending_deletes_next ON file_pending_deletes(next_at);
