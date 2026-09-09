-- Migration 006: Conflict records deletion flags (ZK-056)
-- Adds remote_is_deleted and local_is_deleted flags to conflict_records
-- to distinguish delete-vs-edit and edit-vs-delete conflicts (MASTER_SPEC.md § 11, SEC-008).

ALTER TABLE conflict_records ADD COLUMN remote_is_deleted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE conflict_records ADD COLUMN local_is_deleted INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO _schema_migrations (version, applied_at)
VALUES (3, datetime('now'));
