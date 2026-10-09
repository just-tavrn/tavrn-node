-- History restore after a key reset (protocol/ENCRYPTION.md §7b "History after a key reset"). Portable SQL: TEXT ids,
-- RFC 3339 timestamps, BIGINT integers.

-- The member's identity key changed without continuity (a reset) at this time: the history window and the automatic
-- key shares start here. `history_restored_at`: a member with `restore_history` approved a restore of this
-- membership (cleared by a further reset).
ALTER TABLE room_members ADD COLUMN key_reset_at TEXT;
ALTER TABLE room_members ADD COLUMN history_restored_at TEXT;

-- Room setting: `request` (members may ask for a restore) or `off`.
ALTER TABLE rooms ADD COLUMN history_restore TEXT NOT NULL DEFAULT 'request';

-- The epoch the group of an encrypted channel had when the member's key was reset: epochs up to it are the
-- pre-reset range, which only restore shares may carry.
CREATE TABLE history_reset_epochs (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

-- Requests to restore the history of a membership. `status`: open | approved | denied | cancelled. At most one
-- open request per room and user (checked by the node; the partial index keeps it so under concurrency).
CREATE TABLE history_requests (
    id           TEXT PRIMARY KEY,
    room_id      TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    member_since TEXT NOT NULL,         -- the membership's joined_at
    message      TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    decided_at   TEXT,
    decided_by   TEXT,                  -- address of the deciding member
    reason       TEXT,
    partial      BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX history_requests_room ON history_requests(room_id, status, created_at);
CREATE INDEX history_requests_user ON history_requests(user_id, room_id, created_at);
CREATE UNIQUE INDEX history_requests_one_open ON history_requests(room_id, user_id) WHERE status = 'open';
