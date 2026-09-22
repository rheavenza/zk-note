-- Cloudflare-only schema. UUID/timestamps/JSON use TEXT; counters use INTEGER.
PRAGMA foreign_keys = ON;
CREATE TABLE accounts (id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, status TEXT NOT NULL DEFAULT 'active', blob_bytes INTEGER NOT NULL DEFAULT 0 CHECK(blob_bytes >= 0), reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0));
CREATE TABLE vaults (account_id TEXT PRIMARY KEY REFERENCES accounts(id), bootstrap TEXT NOT NULL CHECK(json_valid(bootstrap)));
CREATE TABLE account_sequences (account_id TEXT PRIMARY KEY REFERENCES accounts(id), current_seq INTEGER NOT NULL DEFAULT 0 CHECK(current_seq BETWEEN 0 AND 9007199254740991));
CREATE TABLE encrypted_objects (account_id TEXT NOT NULL REFERENCES accounts(id), object_id TEXT NOT NULL, revision INTEGER NOT NULL, server_seq INTEGER NOT NULL, object_kind INTEGER NOT NULL, envelope TEXT NOT NULL CHECK(json_valid(envelope)), is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0,1)), PRIMARY KEY(account_id,object_id));
CREATE UNIQUE INDEX encrypted_objects_account_seq_idx ON encrypted_objects(account_id,server_seq);
CREATE TABLE object_history (account_id TEXT NOT NULL, object_id TEXT NOT NULL, revision INTEGER NOT NULL, server_seq INTEGER NOT NULL, object_kind INTEGER NOT NULL, envelope TEXT NOT NULL, is_deleted INTEGER NOT NULL, PRIMARY KEY(account_id,object_id,revision));
CREATE INDEX object_history_account_seq_idx ON object_history(account_id,server_seq);
CREATE TABLE processed_mutations (account_id TEXT NOT NULL, mutation_id TEXT NOT NULL, request_hash TEXT NOT NULL, response_body TEXT NOT NULL, PRIMARY KEY(account_id,mutation_id));
-- Ephemeral within a single D1 batch: insert -> select captured result -> delete.
CREATE TABLE mutation_attempts (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, mutation_id TEXT NOT NULL, object_id TEXT NOT NULL, wire_object_id TEXT NOT NULL, expected_revision INTEGER NOT NULL, object_kind INTEGER NOT NULL, envelope TEXT NOT NULL, is_deleted INTEGER NOT NULL, request_hash TEXT NOT NULL, status INTEGER, response TEXT);
CREATE TRIGGER apply_mutation AFTER INSERT ON mutation_attempts BEGIN
  UPDATE mutation_attempts SET status = CASE
    WHEN EXISTS(SELECT 1 FROM processed_mutations WHERE account_id=NEW.account_id AND mutation_id=NEW.mutation_id AND request_hash != NEW.request_hash) THEN 409
    WHEN EXISTS(SELECT 1 FROM processed_mutations WHERE account_id=NEW.account_id AND mutation_id=NEW.mutation_id) THEN 200
    WHEN EXISTS(SELECT 1 FROM encrypted_objects WHERE account_id=NEW.account_id AND object_id=NEW.object_id AND revision != NEW.expected_revision) THEN 409
    WHEN NOT EXISTS(SELECT 1 FROM encrypted_objects WHERE account_id=NEW.account_id AND object_id=NEW.object_id) AND NEW.expected_revision != 0 THEN 404
    ELSE 201 END WHERE id=NEW.id;
  UPDATE mutation_attempts SET response = CASE
    WHEN EXISTS(SELECT 1 FROM processed_mutations WHERE account_id=NEW.account_id AND mutation_id=NEW.mutation_id AND request_hash != NEW.request_hash)
      THEN json_object('code','MUTATION_REPLAY_MISMATCH','message','Mutation ID reused with a different request')
    WHEN status=200 THEN (SELECT response_body FROM processed_mutations WHERE account_id=NEW.account_id AND mutation_id=NEW.mutation_id)
    WHEN status=409 THEN (SELECT json_object('error','REVISION_CONFLICT','object_id',NEW.wire_object_id,'expected_revision',NEW.expected_revision,'current_revision',revision,'current_server_seq',server_seq,'current_envelope',json(envelope),'is_deleted',json(CASE is_deleted WHEN 1 THEN 'true' ELSE 'false' END)) FROM encrypted_objects WHERE account_id=NEW.account_id AND object_id=NEW.object_id)
    WHEN status=404 THEN json_object('code','OBJECT_NOT_FOUND','message','Object not found') END WHERE id=NEW.id;
  INSERT INTO object_history SELECT account_id,object_id,revision,server_seq,object_kind,envelope,is_deleted FROM encrypted_objects
    WHERE account_id=NEW.account_id AND object_id=NEW.object_id AND (SELECT status FROM mutation_attempts WHERE id=NEW.id)=201;
  INSERT INTO account_sequences(account_id,current_seq) SELECT NEW.account_id,1 WHERE (SELECT status FROM mutation_attempts WHERE id=NEW.id)=201
    ON CONFLICT(account_id) DO UPDATE SET current_seq=current_seq+1;
  INSERT INTO encrypted_objects(account_id,object_id,revision,server_seq,object_kind,envelope,is_deleted)
    SELECT NEW.account_id,NEW.object_id,NEW.expected_revision+1,(SELECT current_seq FROM account_sequences WHERE account_id=NEW.account_id),NEW.object_kind,NEW.envelope,NEW.is_deleted WHERE (SELECT status FROM mutation_attempts WHERE id=NEW.id)=201
    ON CONFLICT(account_id,object_id) DO UPDATE SET revision=excluded.revision,server_seq=excluded.server_seq,object_kind=excluded.object_kind,envelope=excluded.envelope,is_deleted=excluded.is_deleted;
  INSERT INTO processed_mutations SELECT NEW.account_id,NEW.mutation_id,NEW.request_hash,json_object('object_id',NEW.wire_object_id,'revision',NEW.expected_revision+1,'server_seq',(SELECT current_seq FROM account_sequences WHERE account_id=NEW.account_id)) WHERE (SELECT status FROM mutation_attempts WHERE id=NEW.id)=201;
  UPDATE mutation_attempts SET status=200,response=(SELECT response_body FROM processed_mutations WHERE account_id=NEW.account_id AND mutation_id=NEW.mutation_id) WHERE id=NEW.id AND status=201;
END;
CREATE TABLE devices (account_id TEXT NOT NULL REFERENCES accounts(id), device_id TEXT NOT NULL, display_name TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT, last_ack_server_seq INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, PRIMARY KEY(account_id,device_id));
CREATE TABLE sessions (session_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), device_id TEXT, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT, revoked_at TEXT);
CREATE INDEX sessions_account_idx ON sessions(account_id,session_id);
CREATE INDEX sessions_device_idx ON sessions(account_id,device_id);
CREATE TABLE webauthn_credentials (credential_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), public_key TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, device_id TEXT, display_name TEXT);
CREATE INDEX credentials_account_idx ON webauthn_credentials(account_id);
CREATE TABLE webauthn_challenges (challenge_id TEXT PRIMARY KEY, challenge TEXT NOT NULL, account_id TEXT, purpose TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE INDEX challenges_expiration_idx ON webauthn_challenges(expires_at);
CREATE TABLE blobs (account_id TEXT NOT NULL REFERENCES accounts(id), blob_id TEXT NOT NULL, storage_key TEXT NOT NULL UNIQUE, size INTEGER NOT NULL CHECK(size>=0), PRIMARY KEY(account_id,blob_id));
CREATE TABLE blob_uploads (storage_key TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), blob_id TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), expires_at TEXT NOT NULL);
CREATE INDEX uploads_expiration_idx ON blob_uploads(expires_at);
CREATE TABLE blob_garbage (storage_key TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, retry_forever INTEGER NOT NULL DEFAULT 0, next_attempt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX garbage_age_idx ON blob_garbage(next_attempt);
CREATE TRIGGER reserve_blob AFTER INSERT ON blob_uploads BEGIN
  UPDATE accounts SET reserved_bytes=reserved_bytes+NEW.size WHERE id=NEW.account_id;
END;
CREATE TRIGGER release_reservation AFTER DELETE ON blob_uploads BEGIN
  UPDATE accounts SET reserved_bytes=reserved_bytes-OLD.size WHERE id=OLD.account_id;
END;
CREATE TRIGGER blob_created AFTER INSERT ON blobs BEGIN
  UPDATE accounts SET blob_bytes=blob_bytes+NEW.size WHERE id=NEW.account_id;
END;
CREATE TRIGGER blob_replaced AFTER UPDATE ON blobs BEGIN
  UPDATE accounts SET blob_bytes=blob_bytes+NEW.size-OLD.size WHERE id=NEW.account_id;
  INSERT OR IGNORE INTO blob_garbage(storage_key) VALUES(OLD.storage_key);
END;
CREATE TRIGGER blob_deleted AFTER DELETE ON blobs BEGIN
  UPDATE accounts SET blob_bytes=blob_bytes-OLD.size WHERE id=OLD.account_id;
  INSERT OR IGNORE INTO blob_garbage(storage_key) VALUES(OLD.storage_key);
END;
