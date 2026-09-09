-- Migration 003: Account sequence allocator table (ZK-033)
-- Monotonic transactional sequence tracking per account (MASTER_SPEC.md §8, §9).

CREATE TABLE IF NOT EXISTS account_sequences (
    account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    current_seq BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed any existing accounts from encrypted_objects
INSERT INTO account_sequences (account_id, current_seq, updated_at)
SELECT account_id, COALESCE(MAX(server_seq), 0), CURRENT_TIMESTAMP
FROM encrypted_objects
GROUP BY account_id
ON CONFLICT (account_id) DO UPDATE SET
    current_seq = EXCLUDED.current_seq;

INSERT INTO schema_migrations (version, name, applied_at)
VALUES (3, '003_account_sequences', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;
