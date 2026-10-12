-- Reports v2 (protocol MODERATION.md §1.6): forwarding a report about a user of another node to that user's home node.
-- On the forwarding node: `forwarded_to` (the home node), `forwarded_at` and `forwarded_by` (the admin's address) once a
-- node admin forwarded the report. On the home node a forwarded report has `source = 'forward'` and its origin:
-- `origin` (the sending node), `origin_report_id` (the report's id there, unique per origin: duplicates are ignored),
-- `origin_reporter` (the reporter's pseudonym, never an address) and `origin_reported_at` (the original time).
ALTER TABLE reports ADD COLUMN forwarded_to TEXT;
ALTER TABLE reports ADD COLUMN forwarded_at TEXT;
ALTER TABLE reports ADD COLUMN forwarded_by TEXT;
ALTER TABLE reports ADD COLUMN origin TEXT;
ALTER TABLE reports ADD COLUMN origin_report_id TEXT;
ALTER TABLE reports ADD COLUMN origin_reporter TEXT;
ALTER TABLE reports ADD COLUMN origin_reported_at TEXT;
CREATE UNIQUE INDEX reports_origin ON reports(origin, origin_report_id);
