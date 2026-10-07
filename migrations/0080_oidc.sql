-- Phase 5 step 6: single sign-on via OpenID Connect (protocol/APPLICATIONS.md §8).
-- Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT booleans.

-- An external identity `(issuer, subject)` is linked to at most one account, and an account to at most one
-- identity of an issuer (§8.3). Only the provider's stable subject is kept, never a token.
CREATE TABLE external_identities (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    linked_at     TEXT NOT NULL,
    last_login_at TEXT,
    PRIMARY KEY (issuer, subject),
    UNIQUE (user_id, issuer)
);

-- What a group sync granted (§8.5), so `TAVRN_OIDC_GROUP_SYNC=sync` revokes only those rights and never
-- one granted by hand. `kind`: node_admin | room_creation | room | role; `room_id`/`role_id` are '' when
-- they do not apply; `grp` is the provider group the right came from.
CREATE TABLE sso_grants (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    room_id    TEXT NOT NULL DEFAULT '',
    role_id    TEXT NOT NULL DEFAULT '',
    grp        TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, kind, room_id, role_id)
);
CREATE INDEX sso_grants_room ON sso_grants(room_id);

-- Sessions started by an SSO login: capped by `TAVRN_OIDC_SESSION_DAYS` (through `max_expires_at`) and
-- answered with the provider's logout URL at `POST /auth/logout` (§8.6).
ALTER TABLE sessions ADD COLUMN sso BIGINT NOT NULL DEFAULT 0;
