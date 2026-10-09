-- Localized mails (templates/mail/<language>/): the language of a local user's mails (a lowercase language tag such as
-- `de` or `pt-br`, set by the client through PATCH /users/me or from Accept-Language at registration; NULL = English)
-- and the language of a notice reporter (Accept-Language of the notice form; reporters have no account).
ALTER TABLE users ADD COLUMN locale TEXT;
ALTER TABLE legal_notices ADD COLUMN reporter_locale TEXT;
