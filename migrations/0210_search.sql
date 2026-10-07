-- Node-side message search (PLAN.md 4.4 "Search", PROTOCOL.md §7d): one row per plaintext text message of
-- an unencrypted room channel with its normalized search terms (lowercase NFKC words plus diacritic-folded
-- variants, computed by the node in `search.rs`). Encrypted content never gets here.
--
-- This part is portable. The full-text structures differ per database and are created at startup by
-- `search::ensure_schema` (idempotent): PostgreSQL gets a sequence default for `rid`, a generated
-- `tsvector` column (`simple` configuration, no extensions) and a GIN index; SQLite (`--dev`) gets an FTS5
-- external-content table `message_search_fts` over `terms` with the triggers that keep it in sync.
-- `rid` is the stable integer rowid the FTS5 table refers to (an INTEGER PRIMARY KEY is SQLite's rowid).
CREATE TABLE message_search (
    rid             INTEGER PRIMARY KEY,
    message_id      TEXT NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL,
    author_id       TEXT NOT NULL,
    terms           TEXT NOT NULL
);
CREATE INDEX message_search_conversation ON message_search(conversation_id, message_id);
CREATE INDEX message_search_author ON message_search(author_id, message_id);
