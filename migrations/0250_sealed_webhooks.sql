-- Write-only webhooks for encrypted channels (protocol/APPLICATIONS.md §6.1a, ENCRYPTION.md §5b). Portable SQL.

-- How a webhook in an encrypted channel seals its messages: 'sender' (the service seals, the node accepts only
-- sealed bodies) or 'node' (the node seals the plaintext body in memory). NULL in unencrypted channels.
ALTER TABLE webhooks ADD COLUMN sealing TEXT;

-- The newest published inbox public key per conversation (only channels with webhooks get one). A member device
-- derives it from the epoch's content key and signs it; the node checks the signature and keeps the newest epoch.
CREATE TABLE inbox_keys (
    conversation_id TEXT PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL,
    public_key      TEXT NOT NULL,   -- base64url, 32 bytes X25519
    signature       TEXT NOT NULL,   -- base64url, 64 bytes Ed25519 of the publishing device
    user_id         TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

-- Webhooks suspended because their channel was switched to encrypted resume, sealed by the sender and waiting for
-- an inbox key (`suspended` is no longer set by the node).
UPDATE webhooks SET sealing = 'sender', suspended = 0
 WHERE channel_id IN (SELECT id FROM conversations WHERE encrypted = 1);
