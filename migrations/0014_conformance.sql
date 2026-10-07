-- Phase 3 step 7 (FEDERATION.md §9): conformance checks against peers and their reputation record.
-- Portable SQL: TEXT ids and RFC 3339 timestamps, BIGINT booleans/counters.
--
-- The reputation record lives on the peer cache row (`federation_peers`, the `known_nodes` of the spec):
-- `conformance` (reserved in 0010) holds the JSON record of the latest run (checks and the last 10
-- results), `conformance_checked_at` its time. `status` gains `blocked` (operator) and `blocked_auto`
-- (hard failure or observed spoofing) next to `ok` and `key_conflict`.
ALTER TABLE federation_peers ADD COLUMN conformance_result TEXT;
ALTER TABLE federation_peers ADD COLUMN hard_failures BIGINT NOT NULL DEFAULT 0;
ALTER TABLE federation_peers ADD COLUMN soft_failures BIGINT NOT NULL DEFAULT 0;
ALTER TABLE federation_peers ADD COLUMN violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE federation_peers ADD COLUMN blocked_at TEXT;
ALTER TABLE federation_peers ADD COLUMN blocked_reason TEXT;

-- Live-traffic violations of peers (§9.4): `issuer_mismatch`, `type_forbidden`, `body_hash`,
-- `key_conflict`. Kept 30 days; three `body_hash` entries within 10 minutes block the peer.
CREATE TABLE federation_violations (
    id     TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    kind   TEXT NOT NULL,
    at     TEXT NOT NULL
);
CREATE INDEX federation_violations_domain ON federation_violations(domain, kind, at);

-- Throwaway rooms created for the probe of a checking node (§9.1). The room itself is deleted after
-- 15 minutes (`deleted_at` set); the row stays 24 hours for the limit of 4 rooms per day and domain.
CREATE TABLE conformance_rooms (
    room_id    TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE INDEX conformance_rooms_domain ON conformance_rooms(domain, created_at);

-- The conformance worker asks every minute which peers this node federates with (remote users of the
-- domain, federation tokens issued for it).
CREATE INDEX users_domain ON users(domain);
CREATE INDEX federation_targets_target ON federation_targets(target);
