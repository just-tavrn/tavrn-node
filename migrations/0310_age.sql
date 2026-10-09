-- Date of birth, the private age status and age gates (protocol PROTOCOL.md §5e, `age.v1`).
-- Portable SQL: TEXT dates (ISO 8601 `YYYY-MM-DD`), booleans as BIGINT 0/1.

-- Local users: the self-declared date of birth (NULL = not given yet: accounts from before `age.v1` and SSO
-- provisioning complete it with `PUT /users/me/date-of-birth`). Never federated, never shown to others.
ALTER TABLE users ADD COLUMN date_of_birth TEXT;
-- Remote users: the `age_over_18` claim of their home node's latest federation token (1 = 18 or older, 0 = younger,
-- NULL = unknown or never logged in). Both NULL and 0 count as "below 18" (FEDERATION.md §2.2).
ALTER TABLE users ADD COLUMN age_over_18 BIGINT;

-- Age gates: `none` or `adults_only`. A channel's effective gate is the stricter of its own and its room's.
ALTER TABLE rooms ADD COLUMN age_gate TEXT NOT NULL DEFAULT 'none';
ALTER TABLE channels ADD COLUMN age_gate TEXT NOT NULL DEFAULT 'none';
