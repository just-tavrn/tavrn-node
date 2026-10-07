-- Erste Migration: nur eine Tabelle für Knoten-Metadaten.
-- Alle weiteren Tabellen kommen mit Phase 1. SQL bleibt bewusst auf den gemeinsamen
-- Nenner von PostgreSQL und SQLite beschränkt (SQLite nur im Entwicklungsmodus).
CREATE TABLE IF NOT EXISTS node_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
