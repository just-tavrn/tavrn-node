-- Konto-Einladungen (Registrierung im Modus "invite") und Passwort-Reset per E-Mail.
CREATE TABLE account_invites (
    code       TEXT PRIMARY KEY,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note       TEXT NOT NULL DEFAULT '',
    max_uses   BIGINT NOT NULL DEFAULT 1,
    uses       BIGINT NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE password_resets (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL
);
