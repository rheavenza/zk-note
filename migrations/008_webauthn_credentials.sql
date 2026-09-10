-- Migration 008: WebAuthn / Passkey credentials (ZK-071)
-- Stores public credentials for WebAuthn authentication.
-- In accordance with SEC-001, SEC-002:
-- - Stores ONLY public keys, credential IDs, and sign counters.
-- - Contains ZERO vault keys, passphrases, or note content.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id BYTEA PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    device_id UUID,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webauthn_account_id
ON webauthn_credentials(account_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id UUID PRIMARY KEY,
    challenge BYTEA NOT NULL,
    account_id UUID,
    purpose TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
ON webauthn_challenges(expires_at);

-- Record migration in schema_migrations
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (8, '008_webauthn_credentials', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;
