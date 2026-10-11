-- Peer cache hardening (protocol FEDERATION.md §1.4).
-- `source`: where the cached document came from (`well_known` or `srv`): a document from another source that shares
-- no key with the keys seen before is a key conflict. `verified_at`: when a signed request of the peer last verified
-- with its keys; peers without one are only known from unverified requests and are capped and pruned.
ALTER TABLE federation_peers ADD COLUMN source TEXT;
ALTER TABLE federation_peers ADD COLUMN verified_at TEXT;
