-- Migration 009: Ciphertext blob storage (ZK-082)
-- Stores opaque ciphertext chunks for encrypted attachments.
--
-- In accordance with SEC-001, SEC-002, and SEC-003:
-- The server NEVER sees note plaintext, attachment filenames, MIME types, or Attachment Keys.
-- Only opaque blob IDs, ciphertext data bytes, and size metadata are persisted.

CREATE TABLE IF NOT EXISTS blobs (
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL,
    size BIGINT NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, blob_id)
);

CREATE INDEX IF NOT EXISTS idx_blobs_account_id
ON blobs(account_id);
