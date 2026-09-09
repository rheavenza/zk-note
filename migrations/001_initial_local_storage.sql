-- Migration 001: Initial local SQLite encrypted cache schema
-- Enforces zero-knowledge local persistence (SEC-009):
-- Note content, titles, bodies, and tags MUST ONLY be stored within encrypted envelopes.

CREATE TABLE IF NOT EXISTS local_objects (
    object_id TEXT PRIMARY KEY NOT NULL,
    object_kind INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    server_seq INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    envelope TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_local_objects_kind ON local_objects (object_kind);
CREATE INDEX IF NOT EXISTS idx_local_objects_deleted ON local_objects (is_deleted);

CREATE TABLE IF NOT EXISTS pending_mutations (
    mutation_id TEXT PRIMARY KEY NOT NULL,
    object_id TEXT NOT NULL,
    expected_revision INTEGER NOT NULL,
    object_kind INTEGER NOT NULL,
    mutation_type TEXT NOT NULL,
    envelope TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Pending'
);

CREATE INDEX IF NOT EXISTS idx_pending_mutations_object ON pending_mutations (object_id);
CREATE INDEX IF NOT EXISTS idx_pending_mutations_created ON pending_mutations (created_at);

CREATE TABLE IF NOT EXISTS encrypted_base_versions (
    object_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    envelope TEXT NOT NULL,
    stored_at TEXT NOT NULL,
    PRIMARY KEY (object_id, revision)
);

CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    sync_cursor INTEGER NOT NULL DEFAULT 0,
    last_sync_at TEXT,
    device_id TEXT
);

INSERT OR IGNORE INTO sync_state (id, sync_cursor, last_sync_at, device_id)
VALUES (1, 0, NULL, NULL);

CREATE TABLE IF NOT EXISTS _schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO _schema_migrations (version, applied_at)
VALUES (1, datetime('now'));
