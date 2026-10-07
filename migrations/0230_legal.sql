-- Legal compliance (PLAN.md 4.14 items 1–3, protocol/LEGAL.md): takedown notices with their audit trail and
-- counter-notices, the node's legal documents (imprint, privacy policy, terms) with their published versions,
-- terms acceptances, and account deletion (tombstones, 30-day undo, background content deletion).
-- Portable SQL: TEXT ids (ULID), RFC 3339 timestamps, booleans as BIGINT 0/1, JSON as TEXT.

-- One takedown notice (DMCA §512(c)(3) / DSA Art. 16) = one case. `origin` is NULL for notices submitted on this
-- node and the forwarding node's domain for a case opened by S2S `legal.notice` (`origin_case` = its case id).
-- The reporter's status page needs the token from the confirmation mail (`reporter_token_hash`, SHA-256).
-- `locations` is the JSON list of the reported places as resolved by the node; `target_user_id` the uploader of the
-- first local target (the repeat-infringer counter counts actioned cases per target). Cases are deleted after
-- `retain_until` (`TAVRN_LEGAL_NOTICE_RETENTION_DAYS` after the last activity).
CREATE TABLE legal_notices (
    id                  TEXT PRIMARY KEY,
    state               TEXT NOT NULL,              -- received | in_review | actioned | rejected | counter_notice
    basis               TEXT NOT NULL,              -- copyright | illegal | terms
    origin              TEXT,
    origin_case         TEXT,
    reporter_name       TEXT NOT NULL,
    reporter_email      TEXT NOT NULL,
    reporter_address    TEXT NOT NULL DEFAULT '',
    reporter_phone      TEXT NOT NULL DEFAULT '',
    reporter_token_hash TEXT,
    work                TEXT NOT NULL,
    explanation         TEXT NOT NULL DEFAULT '',
    locations           TEXT NOT NULL DEFAULT '[]',
    target_user_id      TEXT,
    target_address      TEXT,
    good_faith          BIGINT NOT NULL DEFAULT 0,
    accuracy            BIGINT NOT NULL DEFAULT 0,
    perjury             BIGINT NOT NULL DEFAULT 0,
    signature           TEXT NOT NULL,
    decision_reason     TEXT NOT NULL DEFAULT '',
    statement           TEXT,
    statement_at        TEXT,
    forwarded_to        TEXT,
    counter_deadline    TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    decided_at          TEXT,
    retain_until        TEXT NOT NULL
);
CREATE INDEX legal_notices_state ON legal_notices(state, id);
CREATE INDEX legal_notices_target ON legal_notices(target_user_id, state);
CREATE INDEX legal_notices_retain ON legal_notices(retain_until);

-- Every step of a case (received, actions, mails, counter-notices, decisions): the audit trail exported with it.
CREATE TABLE legal_notice_events (
    id         TEXT PRIMARY KEY,
    notice_id  TEXT NOT NULL REFERENCES legal_notices(id) ON DELETE CASCADE,
    actor_id   TEXT,
    action     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX legal_notice_events_notice ON legal_notice_events(notice_id, id);

-- The uploader's answer (DMCA §512(g)(3), DSA Art. 20) and the operator's decision on it.
CREATE TABLE legal_counter_notices (
    id         TEXT PRIMARY KEY,
    notice_id  TEXT NOT NULL REFERENCES legal_notices(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    address    TEXT NOT NULL DEFAULT '',
    statement  TEXT NOT NULL,
    consent    BIGINT NOT NULL DEFAULT 0,
    signature  TEXT NOT NULL,
    decision   TEXT,                                -- restore | uphold
    reason     TEXT NOT NULL DEFAULT '',
    decided_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX legal_counter_notices_notice ON legal_counter_notices(notice_id);

-- The published legal documents of the node: imprint | privacy | terms | cookies. `html` is the sanitized rendering
-- of `markdown` (no raw HTML, safe links only); every publish is a new version (kept in the history below).
CREATE TABLE legal_documents (
    kind         TEXT PRIMARY KEY,
    markdown     TEXT NOT NULL,
    html         TEXT NOT NULL,
    lang         TEXT NOT NULL DEFAULT '',
    version      BIGINT NOT NULL,
    published_at TEXT NOT NULL,
    updated_by   TEXT
);

CREATE TABLE legal_document_versions (
    kind         TEXT NOT NULL,
    version      BIGINT NOT NULL,
    markdown     TEXT NOT NULL,
    lang         TEXT NOT NULL DEFAULT '',
    published_at TEXT NOT NULL,
    published_by TEXT,
    PRIMARY KEY (kind, version)
);

-- Accepted terms versions per local user (registration, the acceptance dialog after a new version, SSO first login).
CREATE TABLE terms_acceptances (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version     BIGINT NOT NULL,
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, version)
);

-- Deleted accounts (tombstones). The account row stays disabled with its username reserved until `purge_after`
-- (`TAVRN_ACCOUNT_DELETE_GRACE_DAYS`) so a node admin can undo; its messages and other kept content point at the
-- tombstone row `tombstone_id` ("Deleted user"). Remote stubs of deleted users get a tombstone without undo.
ALTER TABLE users ADD COLUMN deleted_at TEXT;

CREATE TABLE account_deletions (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    tombstone_id      TEXT NOT NULL REFERENCES users(id),
    address           TEXT NOT NULL,
    requested_by      TEXT,                         -- NULL = the user, else the admin's user id
    delete_messages   BIGINT NOT NULL DEFAULT 0,
    state             TEXT NOT NULL,                -- processing | done | undone | purged
    messages_total    BIGINT NOT NULL DEFAULT 0,
    messages_done     BIGINT NOT NULL DEFAULT 0,
    status_token_hash TEXT,
    created_at        TEXT NOT NULL,
    purge_after       TEXT NOT NULL,
    finished_at       TEXT,
    undone_at         TEXT,
    purged_at         TEXT
);
CREATE INDEX account_deletions_user ON account_deletions(user_id);
CREATE INDEX account_deletions_state ON account_deletions(state, purge_after);
