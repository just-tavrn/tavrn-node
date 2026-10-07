-- Mandatory second factor (PLAN.md 4.2a, PROTOCOL.md §5a) and secret storage (ENCRYPTION.md §2.4).
-- Booleans are BIGINT 0/1, timestamps RFC 3339 TEXT, binary values BYTEA (BLOB in SQLite).

-- TOTP (RFC 6238). `secret` is nonce(12) || AES-256-GCM(key derived from the node secret
-- <data_dir>/keys/secrets.key, AAD = user id, 20-byte secret). `confirmed_at` NULL = enrolled but not confirmed.
-- `last_step` is the 30-second step of the last accepted code (replay guard).
CREATE TABLE totp_secrets (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret       BYTEA NOT NULL,
    confirmed_at TEXT,
    last_step    BIGINT NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

-- Single-use recovery codes: SHA-256(salt || normalized code), one salt per generated set.
CREATE TABLE recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    salt       TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

-- WebAuthn credentials (webauthn-rs `Passkey` as JSON: public key, counter, flags).
-- `credential_id` is the base64url WebAuthn credential id; unique across all accounts.
CREATE TABLE webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    passkey       TEXT NOT NULL,
    prf_supported BIGINT NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

-- Server-side WebAuthn ceremony state, single use, 5 minutes. `user_id` is NULL for the
-- discoverable (passkey-only) login. kind: register | second_factor | passkey
CREATE TABLE webauthn_challenges (
    id         TEXT PRIMARY KEY,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    state      TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Spent pre-auth tokens (`jti`), kept until they expire: a pre-auth token completes one login.
CREATE TABLE preauth_used (
    jti        TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);

-- Secret storage: the master secret wrapped per unlock method (`recovery`,
-- `passkey:<credential id>`). The node never sees a key that unwraps it.
CREATE TABLE secret_storage (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method     TEXT NOT NULL,
    wrapped    BYTEA NOT NULL,
    params     TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, method)
);

-- Sessions created before the second factor became mandatory end now; every account goes
-- through the second factor (or its enrollment) at the next login.
UPDATE sessions SET revoked_at = '2026-10-04T00:00:00.000Z' WHERE revoked_at IS NULL;
