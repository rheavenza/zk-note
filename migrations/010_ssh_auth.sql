-- ZK-109: Public machine credentials and single-use HTTPS authentication challenges.
CREATE TABLE ssh_credentials (
    credential_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    label TEXT,
    device_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, device_id)
);
CREATE INDEX ssh_credentials_owner ON ssh_credentials(account_id);
CREATE TABLE ssh_challenges (
    challenge_id TEXT PRIMARY KEY NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose = 'login-v1'),
    credential_id TEXT REFERENCES ssh_credentials(credential_id),
    -- Canonical request/device/audience/nonce/expiry fields, never private data.
    challenge_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX ssh_challenges_expiry ON ssh_challenges(expires_at);
ALTER TABLE sessions ADD COLUMN ssh_credential_id TEXT REFERENCES ssh_credentials(credential_id);
CREATE INDEX sessions_ssh_credential ON sessions(ssh_credential_id);
