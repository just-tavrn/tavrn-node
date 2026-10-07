-- Files channels (PLAN.md 4.13 item 9, protocol/FILES.md): a folder tree per channel of kind `files`.
-- Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT integers.

-- Entries of a files channel: folders and files. Names are NFC-normalised; `name_key` is the lowercase name,
-- unique per parent (case-insensitive). `storage_id` names the stored file in the node's blob storage
-- (internal backend, equal to `id`); files on an external backend have none, their object key is the channel's
-- prefix + `id` (so renames and moves are metadata-only). `encrypted`: the external object is wrapped with the
-- storage format of PLAN.md 4.12 (its file key is the `blob_keys` row of `id`).
CREATE TABLE file_entries (
    id         TEXT PRIMARY KEY,
    room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    parent_id  TEXT REFERENCES file_entries(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,                     -- folder | file
    name       TEXT NOT NULL,
    name_key   TEXT NOT NULL,
    storage_id TEXT,
    backend    TEXT NOT NULL DEFAULT 'internal',  -- internal | webdav | s3 (where the bytes are)
    encrypted  BIGINT NOT NULL DEFAULT 0,
    mime       TEXT NOT NULL DEFAULT '',
    size       BIGINT NOT NULL DEFAULT 0,
    sha256     TEXT NOT NULL DEFAULT '',
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX file_entries_name ON file_entries(channel_id, COALESCE(parent_id, ''), name_key);
CREATE INDEX file_entries_parent ON file_entries(parent_id);
CREATE INDEX file_entries_room ON file_entries(room_id);
CREATE INDEX file_entries_storage ON file_entries(storage_id);

-- Storage backend of a files channel (no row = internal). `config` is the backend's JSON configuration
-- (URL, credentials, bucket …) encrypted with the node's `secrets.key` (AES-256-GCM, bound to the channel id);
-- '' for internal. `encrypt_files`: new files are wrapped with the storage format before they are written to
-- the external store (unreadable outside tavrn).
CREATE TABLE file_channel_backends (
    channel_id    TEXT PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    config        TEXT NOT NULL DEFAULT '',
    encrypt_files BIGINT NOT NULL DEFAULT 0,
    created_by    TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at    TEXT NOT NULL
);
