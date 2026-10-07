-- Phase 3, steps 3 and 4 (FEDERATION.md §3–§6): direct invites, the invite list, friends across nodes
-- and push hints. The key cache of remote users lives on their device rows (devices.public_key,
-- identity_signature, attested_identity_key) and users.identity_pubkey, with remote_users.keys_fetched_at.

-- Direct invites (§3.4): a single-use invite bound to one user address.
ALTER TABLE invites ADD COLUMN bound_to TEXT;

-- The request id the other home node uses for a request between a local and a remote user (§6.2).
ALTER TABLE friend_requests ADD COLUMN remote_request_id TEXT;

-- Last applied friend message per (local user, remote user), for ordering (§5.4).
CREATE TABLE friend_sync (
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    other_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_at        TEXT NOT NULL,
    PRIMARY KEY (user_id, other_id)
);

-- Pending invitations of local users (§4 "invite list"): rooms and conversations on any node.
-- `target_id` is the room or conversation id on `node`; `summary` the JSON of the room or conversation.
CREATE TABLE user_invites (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    node        TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    summary     TEXT NOT NULL,
    inviter     TEXT NOT NULL,
    invite_code TEXT,
    received_at TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    UNIQUE (user_id, kind, node, target_id)
);
CREATE INDEX user_invites_user ON user_invites(user_id, received_at);

-- `notify` push hints for local users (§5.2), kept for web push (phase 5).
CREATE TABLE push_hints (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node            TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    room_id         TEXT,
    mention         BIGINT NOT NULL,
    received_at     TEXT NOT NULL
);
CREATE INDEX push_hints_user ON push_hints(user_id, received_at);
