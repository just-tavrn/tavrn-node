-- Phase 3 step 6 (FEDERATION.md §7): peer directory and Discover. Portable SQL: TEXT ids and RFC 3339
-- timestamps, BIGINT booleans/counters.

-- Rooms whose owner (or a holder of manage_room) listed them in the directory. Only public rooms.
ALTER TABLE rooms ADD COLUMN discoverable BIGINT NOT NULL DEFAULT 0;

-- Nodes this node lists (§7.1): verified through their own discovery document, either because they
-- announced themselves here (`source = announce`) or because a reference node listed them
-- (`source = relay`). The descriptive fields are copied from the verified document. Nodes not seen for
-- 48 hours are removed by the directory worker.
CREATE TABLE directory_nodes (
    domain           TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL,
    software_name    TEXT NOT NULL,
    software_version TEXT NOT NULL,
    capabilities     TEXT NOT NULL,
    registration     TEXT NOT NULL,
    public_rooms     BIGINT NOT NULL DEFAULT 0,
    users            BIGINT,
    source           TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_announce    TEXT,
    rooms_fetched_at TEXT
);
CREATE INDEX directory_nodes_last_seen ON directory_nodes(last_seen);

-- Discoverable rooms of listed nodes (§7.3), each with the listing JWT its node signed. The values shown
-- are the signed ones; rows disappear when the listing expires (48 hours) or the node is removed.
CREATE TABLE directory_rooms (
    node         TEXT NOT NULL,
    room_id      TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL,
    member_count BIGINT NOT NULL,
    listing      TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    PRIMARY KEY (node, room_id)
);
CREATE INDEX directory_rooms_expires ON directory_rooms(expires_at);

-- Admin delisting (§7.4): a whole node (`room_id = ''`) or a single room. Delisted entries are neither
-- shown nor passed on, also when the node announces itself again.
CREATE TABLE directory_delisted (
    node       TEXT NOT NULL,
    room_id    TEXT NOT NULL DEFAULT '',
    created_by TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (node, room_id)
);
