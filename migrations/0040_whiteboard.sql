-- Phase 4D (PLAN.md 4.10, protocol/WHITEBOARD.md): the personal whiteboard scene library on the home node.
-- `id` is a ULID chosen by the client (it is part of the encryption AAD), unique per user. `scene` and
-- `thumbnail` are blobs encrypted by the client under the backup key (`version || nonce || AES-GCM`); the
-- node checks only their size and version byte. `name` is plaintext (at most 64 characters).
-- Ephemeral whiteboard events and the session state are never stored.
CREATE TABLE whiteboard_scenes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id         TEXT NOT NULL,
    name       TEXT NOT NULL,
    scene      BYTEA NOT NULL,
    thumbnail  BYTEA,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
);
CREATE INDEX whiteboard_scenes_updated ON whiteboard_scenes(user_id, updated_at);
