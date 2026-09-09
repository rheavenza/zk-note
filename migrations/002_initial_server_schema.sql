-- Migration 002: Initial server PostgreSQL schema (ZK-031)
-- Zero-knowledge ciphertext store and sync coordination server schema (MASTER_SPEC.md §8).
--
-- In accordance with SEC-001 and SEC-002:
-- Note plaintext, titles, tags, and decrypted keys are never transmitted or stored on the server.
-- The server stores only opaque encrypted envelopes, KDF parameters, wrapped keys, and revision metadata.

-- Schema migration tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
);

-- Vaults table (stores only KDF params and wrapped keys, no passphrase or plaintext keys)
CREATE TABLE IF NOT EXISTS vaults (
    account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    crypto_version INTEGER NOT NULL,
    kdf_algorithm TEXT NOT NULL,
    kdf_params JSONB NOT NULL,
    kdf_salt BYTEA NOT NULL,
    wrapped_vault_key BYTEA NOT NULL,
    recovery_wrapped_vault_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Encrypted objects table (active latest revisions)
CREATE TABLE IF NOT EXISTS encrypted_objects (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    object_id UUID NOT NULL,
    object_kind SMALLINT NOT NULL,
    revision BIGINT NOT NULL,
    server_seq BIGINT NOT NULL,
    envelope_version INTEGER NOT NULL,
    wrapped_key BYTEA NOT NULL,
    payload BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, object_id)
);

-- Unique index enforcing per-account sequence monotonicity and accelerating sync pull reads
CREATE UNIQUE INDEX IF NOT EXISTS encrypted_objects_account_seq_idx
ON encrypted_objects(account_id, server_seq);

-- Object history table (prior revisions retained for CAS audit / conflict history)
CREATE TABLE IF NOT EXISTS object_history (
    account_id UUID NOT NULL,
    object_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    server_seq BIGINT NOT NULL,
    envelope_version INTEGER NOT NULL,
    wrapped_key BYTEA NOT NULL,
    payload BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, object_id, revision)
);

-- Index supporting history inspection and sync reads by sequence
CREATE INDEX IF NOT EXISTS idx_object_history_account_seq
ON object_history(account_id, server_seq);

-- Processed mutations table (for idempotent retry handling)
CREATE TABLE IF NOT EXISTS processed_mutations (
    account_id UUID NOT NULL,
    mutation_id UUID NOT NULL,
    object_id UUID NOT NULL,
    resulting_revision BIGINT,
    resulting_server_seq BIGINT,
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, mutation_id)
);

-- Index supporting lookup of mutations by object_id
CREATE INDEX IF NOT EXISTS idx_processed_mutations_account_object
ON processed_mutations(account_id, object_id);

-- Devices table (device registration and sync acknowledgment tracking)
CREATE TABLE IF NOT EXISTS devices (
    account_id UUID NOT NULL,
    device_id UUID NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ,
    last_ack_server_seq BIGINT NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (account_id, device_id)
);

-- Index supporting active device lookups and ack tracking
CREATE INDEX IF NOT EXISTS idx_devices_account_last_ack
ON devices(account_id, last_ack_server_seq);

-- Record migration in schema_migrations
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (2, '002_initial_server_schema', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;
