-- Migration 007: Server authentication sessions (ZK-070)
-- Zero-knowledge server authentication sessions and token management (MASTER_SPEC.md §4).
--
-- In accordance with SEC-001, SEC-002, and SEC-003:
-- - Server authentication is completely independent of the client's vault passphrase and encryption keys.
-- - Raw access tokens are NEVER stored in plaintext in the database (only cryptographically secure digests are stored).
-- - Sessions can be individually revoked or expired without altering encrypted object data.

CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id UUID,
    token_hash BYTEA NOT NULL UNIQUE,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_account_id
ON sessions(account_id);

CREATE INDEX IF NOT EXISTS idx_sessions_device_id
ON sessions(account_id, device_id);

-- Record migration in schema_migrations
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (7, '007_server_sessions', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;
