-- Migration 005: Local conflict records schema (ZK-053)
-- Enforces zero-knowledge local persistence (SEC-009):
-- All four conflict versions (BASE, LOCAL, REMOTE, CANDIDATE) are stored strictly as encrypted envelopes.
-- No plaintext title, body, or tags columns.

CREATE TABLE IF NOT EXISTS conflict_records (
    conflict_id TEXT PRIMARY KEY NOT NULL,
    object_id TEXT NOT NULL,
    object_kind INTEGER NOT NULL,
    base_revision INTEGER NOT NULL,
    remote_revision INTEGER NOT NULL,
    base_envelope TEXT,
    local_envelope TEXT NOT NULL,
    remote_envelope TEXT NOT NULL,
    candidate_envelope TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_conflict_records_object ON conflict_records (object_id);
CREATE INDEX IF NOT EXISTS idx_conflict_records_resolved ON conflict_records (resolved);

INSERT OR IGNORE INTO _schema_migrations (version, applied_at)
VALUES (2, datetime('now'));
