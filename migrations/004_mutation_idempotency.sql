-- Migration 004: Mutation idempotency payload hash tracking (ZK-035)
-- Enables exact mutation payload comparison to detect and reject replay mismatches (SEC-007).

ALTER TABLE processed_mutations ADD COLUMN request_hash BYTEA;

INSERT INTO schema_migrations (version, name, applied_at)
VALUES (4, '004_mutation_idempotency', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;
