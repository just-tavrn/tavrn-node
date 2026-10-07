-- Attachment safety and encryption at rest (PLAN.md 4.12).
-- Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT integers.

-- Encryption at rest of the blob storage. Every file in `<data>/blobs` (attachments, profile media, custom
-- emojis and soundboard sounds share one namespace of storage ids) is encrypted with its own random 32-byte
-- key (AES-256-GCM in 64 KiB chunks); that key is wrapped with the node's storage key
-- (`<data>/keys/storage.key`, AES-256-GCM, AAD = storage id). One row per encrypted file; a file without a
-- row is plaintext (written before encryption existed or with TAVRN_STORAGE_ENCRYPTION=off) and is
-- encrypted in place by housekeeping.
CREATE TABLE blob_keys (
    storage_id  TEXT PRIMARY KEY,
    -- base64url of AES-256-GCM(storage key, blob key) including the tag (48 bytes).
    wrapped_key TEXT NOT NULL,
    -- base64url of the 12-byte wrap nonce.
    wrap_nonce  TEXT NOT NULL,
    -- Fingerprint of the storage key that wrapped it (the rotation re-wraps row by row).
    key_id      TEXT NOT NULL,
    -- File format: 1 = magic header + AES-256-GCM chunks of 64 KiB (nonce = chunk counter + last flag).
    enc_version BIGINT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX blob_keys_key_id ON blob_keys (key_id);

-- Per-user privacy setting: load image previews automatically `always`, only from friends and members of
-- shared rooms (`friends_and_shared`, the default) or `never`.
ALTER TABLE users ADD COLUMN auto_preview TEXT NOT NULL DEFAULT 'friends_and_shared';
