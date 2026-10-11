-- Peer cache hardening (protocol FEDERATION.md §1.4).
-- `source`: where the cached document came from (`well_known` or `srv`): a document from another source that shares
-- no key with the keys seen before is a key conflict. `verified_at`: when a signed request of the peer last verified
-- with its keys. `origin`: `request` when the row was created to check the signature of a request naming the peer
-- (before that signature was checked); such peers without `verified_at` are capped and pruned.
ALTER TABLE federation_peers ADD COLUMN source TEXT;
ALTER TABLE federation_peers ADD COLUMN verified_at TEXT;
ALTER TABLE federation_peers ADD COLUMN origin TEXT;
