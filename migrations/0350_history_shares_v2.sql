-- Device share keys and history shares v2 (protocol ENCRYPTION.md §3.1 "Share key", §7b "Format v2"). Portable SQL:
-- TEXT ids, base64url keys, BIGINT integers.

-- The X25519 share key of a device and the device key's signature over it (base64url). Set once for a local device
-- (immutable afterwards, an identity reset keeps it like the device key); mirrored from the home node for the device
-- rows of remote users (the key cache, FEDERATION.md §3.5).
ALTER TABLE devices ADD COLUMN share_public_key TEXT;
ALTER TABLE devices ADD COLUMN share_key_signature TEXT;

-- Format of a share: 1 (encrypted under the epoch's content key) or 2 (under a fresh key sealed per recipient device).
ALTER TABLE history_key_shares ADD COLUMN version BIGINT NOT NULL DEFAULT 1;

-- The sealed key of a v2 share for one recipient device (its public device id, as in the MLS identity). Each device
-- is served only its own box; acknowledging the share and housekeeping delete the boxes with it.
CREATE TABLE history_share_boxes (
    share_id  TEXT NOT NULL REFERENCES history_key_shares(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    sealed    TEXT NOT NULL,
    PRIMARY KEY (share_id, device_id)
);
