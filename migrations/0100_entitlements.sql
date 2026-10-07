-- Feature round 3 (PLAN.md 4.13 items 1 and 2): entitlements (plans and grants on top of the node's fixed
-- limits, protocol/ENTITLEMENTS.md), admin API tokens and attachment retention.
-- Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT integers, JSON objects and arrays as TEXT.

-- Named bundles of limits. `limits` is a JSON object `{"<key>": <integer>}` with known keys only.
CREATE TABLE entitlement_plans (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    limits     TEXT NOT NULL,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- A grant extends the limits of one subject: a local user or a room of this node. The values are the plan's
-- limits with `overrides` on top. Expired grants are ignored at evaluation time; housekeeping deletes them a
-- week after `expires_at`. No foreign key on the subject (two kinds); grants of deleted subjects are
-- removed by housekeeping as well.
CREATE TABLE entitlement_grants (
    id           TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,          -- user | room
    subject_id   TEXT NOT NULL,
    plan_id      TEXT REFERENCES entitlement_plans(id),
    overrides    TEXT NOT NULL DEFAULT '{}',
    expires_at   TEXT,
    note         TEXT NOT NULL DEFAULT '',
    created_by   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX entitlement_grants_subject ON entitlement_grants(subject_kind, subject_id);
CREATE INDEX entitlement_grants_expiry ON entitlement_grants(expires_at);
CREATE INDEX entitlement_grants_plan ON entitlement_grants(plan_id);

-- Bearer tokens for the admin API (`tavrn_adm_<id>.<secret>`): valid for `/api/v1/admin/*` routes only,
-- limited by `scopes` (JSON array). Only the SHA-256 of the whole token is stored. A token acts with the
-- rights of its creator, who must still be an enabled node admin. Revoking deletes the row.
CREATE TABLE admin_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    created_by   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at   TEXT,
    last_used_at TEXT,
    created_at   TEXT NOT NULL
);

-- Attachment retention: a room may shorten the node's `TAVRN_ATTACHMENT_RETENTION_DAYS` (NULL = node value).
ALTER TABLE rooms ADD COLUMN attachment_retention_days BIGINT;
-- Set when housekeeping deleted the file of an expired attachment; the row stays so that the message still
-- lists the attachment (`expired: true`) and downloads answer `410 attachment.expired`.
ALTER TABLE blobs ADD COLUMN expired_at TEXT;
CREATE INDEX blobs_retention ON blobs(created_at) WHERE expired_at IS NULL AND message_id IS NOT NULL;
