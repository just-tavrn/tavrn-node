-- Feature round 3, item 11 (PLAN.md 4.13): history for new members of encrypted channels
-- (protocol/ENCRYPTION.md §7b). Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT integers.

-- Channel policy: `since_join`, `days:<n>` or `all`; NULL = the default `since_join`.
ALTER TABLE channels ADD COLUMN history_for_new_members TEXT;

-- Shares of past epoch keys for one member, encrypted under the conversation's current content key
-- (the node cannot read them). Acknowledged shares are kept a day for the rate limit; housekeeping deletes
-- them after that and every share after 30 days.
CREATE TABLE history_key_shares (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    to_user         TEXT NOT NULL,          -- recipient address `name@domain`
    from_user       TEXT NOT NULL,          -- sharing user's address
    from_device     TEXT NOT NULL,          -- sharing device id (public id, as in the MLS identity)
    epoch_from      BIGINT NOT NULL,
    epoch_to        BIGINT NOT NULL,
    ciphertext      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    acked_at        TEXT
);
CREATE INDEX history_key_shares_recipient ON history_key_shares(conversation_id, to_user, created_at);
CREATE INDEX history_key_shares_created ON history_key_shares(created_at);

-- Members who still wait for a share (the "history_pending" flag of a membership, per conversation):
-- set when a member's first device of a membership joins the group and the policy grants history, cleared
-- (pending = 0) when the member acknowledges a share. `member_since` is the membership's `joined_at`, so a
-- re-join starts over.
CREATE TABLE history_pending (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    member_since    TEXT NOT NULL,
    pending         BIGINT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);
