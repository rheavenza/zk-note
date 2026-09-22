//! Server database handle and vault bootstrap persistence.

use crate::db::migrations::create_in_memory_db;
use crate::db::schema::{
    DeviceRow, EncryptedObjectRow, ObjectHistoryRow, SessionRow, WebAuthnChallengeRecord,
    WebAuthnCredentialRecord,
};
use crate::error::DbError;
use base64ct::{Base64, Encoding};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zk_protocol::auth::{AuthToken, AuthenticatedSession};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{
    ConflictResponse, ObjectChange, PullChangesResponse, PushRequest, PushResponse,
};
use zk_protocol::vault::{KdfParams, VaultBootstrap, WrappedVaultKey};

use blake2::{Blake2s256, Digest};

/// Result of attempting a compare-and-swap push mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Mutation accepted and committed.
    Success(PushResponse),
    /// Compare-and-swap rejected due to revision mismatch.
    Conflict(ConflictResponse),
    /// Target object was not found for an expected_revision > 0.
    ObjectNotFound(String),
    /// Mutation ID was previously processed with an incompatible payload.
    ReplayMismatch(String),
}

/// Result of validating a bearer session token against the database (ZK-070).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionValidationResult {
    /// Token is valid and maps to an active session.
    Valid {
        /// Account ID owning the session.
        account_id: Uuid,
        /// Optional associated device ID.
        device_id: Option<Uuid>,
        /// Session unique identifier.
        session_id: Uuid,
    },
    /// Token exists but has expired.
    Expired,
    /// Token exists but has been explicitly revoked.
    Revoked,
    /// Associated device has been revoked.
    DeviceRevoked,
}

/// Computes a deterministic 32-byte cryptographic digest of the mutation request payload.
///
/// Enforces SEC-007 idempotency verification by binding:
/// - object_id
/// - expected_revision
/// - object_kind
/// - is_deleted
/// - envelope_version
/// - envelope.object_id
/// - envelope.object_kind
/// - envelope.wrapped_key (nonce + ciphertext)
/// - envelope.payload (nonce + ciphertext)
pub fn compute_mutation_request_hash(request: &PushRequest) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(request.object_id.as_bytes());
    hasher.update(request.expected_revision.to_le_bytes());
    hasher.update(request.object_kind.to_le_bytes());
    hasher.update([request.is_deleted as u8]);
    hasher.update(request.envelope.envelope_version.to_le_bytes());
    hasher.update(request.envelope.object_id.as_bytes());
    hasher.update(request.envelope.object_kind.to_le_bytes());
    hasher.update(request.envelope.wrapped_key.nonce.as_bytes());
    hasher.update(request.envelope.wrapped_key.ciphertext.as_bytes());
    hasher.update(request.envelope.payload.nonce.as_bytes());
    hasher.update(request.envelope.payload.ciphertext.as_bytes());
    hasher.finalize().into()
}

/// Internal JSON schema for stored KDF parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

/// Thread-safe database handle for zero-knowledge server operations.
#[derive(Debug, Clone)]
pub struct ServerDb {
    conn: Arc<Mutex<Connection>>,
}

impl ServerDb {
    /// Creates a new in-memory server database initialized with all migrations.
    pub fn new_in_memory() -> Result<Self, DbError> {
        let conn = create_in_memory_db()?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens an SQLite database file at `path` and executes all migrations.
    pub fn open_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, DbError> {
        let mut conn = Connection::open(path)?;
        crate::db::migrations::run_server_migrations(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Wraps an existing rusqlite connection in a [`ServerDb`].
    pub fn from_connection(conn: Connection) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Returns a cloned reference to the database connection mutex.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Ensures an account record exists in the database.
    pub async fn ensure_account(&self, account_id: Uuid) -> Result<(), DbError> {
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();
        conn.execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')
             ON CONFLICT (id) DO NOTHING",
            [&acc_str],
        )?;
        Ok(())
    }

    /// Stores the initial vault bootstrap record for an account.
    ///
    /// Fails closed if a vault has already been bootstrapped for this account.
    pub async fn create_vault_bootstrap(
        &self,
        account_id: Uuid,
        bootstrap: &VaultBootstrap,
    ) -> Result<(), DbError> {
        self.ensure_account(account_id).await?;

        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();

        // Check if vault already exists
        let existing_count: i64 = conn.query_row(
            "SELECT count(*) FROM vaults WHERE account_id = ?1",
            [&acc_str],
            |row| row.get(0),
        )?;
        if existing_count > 0 {
            return Err(DbError::VaultAlreadyExists(account_id));
        }

        let kdf_params = StoredKdfParams {
            memory_kib: bootstrap.kdf.memory_kib,
            iterations: bootstrap.kdf.iterations,
            parallelism: bootstrap.kdf.parallelism,
        };
        let kdf_params_json = serde_json::to_string(&kdf_params)?;

        let kdf_salt_bytes = Base64::decode_vec(&bootstrap.kdf.salt)
            .map_err(|e| DbError::InvalidBase64(format!("invalid KDF salt base64: {e}")))?;

        let wrapped_key_bytes = serde_json::to_vec(&bootstrap.wrapped_vault_key)?;
        let recovery_key_bytes = serde_json::to_vec(&bootstrap.recovery_wrapped_vault_key)?;

        conn.execute(
            "INSERT INTO vaults (
                account_id,
                crypto_version,
                kdf_algorithm,
                kdf_params,
                kdf_salt,
                wrapped_vault_key,
                recovery_wrapped_vault_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                acc_str,
                bootstrap.crypto_version as i64,
                bootstrap.kdf.algorithm,
                kdf_params_json,
                kdf_salt_bytes,
                wrapped_key_bytes,
                recovery_key_bytes,
            ],
        )?;

        Ok(())
    }

    /// Retrieves the vault bootstrap record for an account.
    pub async fn get_vault_bootstrap(
        &self,
        account_id: Uuid,
    ) -> Result<Option<VaultBootstrap>, DbError> {
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT
                crypto_version,
                kdf_algorithm,
                kdf_params,
                kdf_salt,
                wrapped_vault_key,
                recovery_wrapped_vault_key
             FROM vaults
             WHERE account_id = ?1",
        )?;

        let mut rows = stmt.query([&acc_str])?;

        if let Some(row) = rows.next()? {
            let crypto_version: i64 = row.get(0)?;
            let kdf_algorithm: String = row.get(1)?;
            let kdf_params_str: String = row.get(2)?;
            let kdf_salt_bytes: Vec<u8> = row.get(3)?;
            let wrapped_key_bytes: Vec<u8> = row.get(4)?;
            let recovery_key_bytes: Vec<u8> = row.get(5)?;

            let kdf_params: StoredKdfParams = serde_json::from_str(&kdf_params_str)?;
            let kdf_salt_base64 = Base64::encode_string(&kdf_salt_bytes);

            let wrapped_vault_key: WrappedVaultKey = serde_json::from_slice(&wrapped_key_bytes)?;
            let recovery_wrapped_vault_key: WrappedVaultKey =
                serde_json::from_slice(&recovery_key_bytes)?;

            Ok(Some(VaultBootstrap {
                crypto_version: crypto_version as u32,
                kdf: KdfParams {
                    algorithm: kdf_algorithm,
                    salt: kdf_salt_base64,
                    memory_kib: kdf_params.memory_kib,
                    iterations: kdf_params.iterations,
                    parallelism: kdf_params.parallelism,
                },
                wrapped_vault_key,
                recovery_wrapped_vault_key,
            }))
        } else {
            Ok(None)
        }
    }

    /// Allocates the next monotonic server sequence number for an account within an active transaction.
    ///
    /// The operation is atomic, transactional, and strictly monotonic per account (MASTER_SPEC.md §8, §9).
    pub fn allocate_sequence_in_tx(
        tx: &rusqlite::Transaction<'_>,
        account_id: Uuid,
    ) -> Result<u64, DbError> {
        let acc_str = account_id.to_string();

        // Ensure account exists
        tx.execute(
            "INSERT INTO accounts (id, status) VALUES (?1, 'active')
             ON CONFLICT (id) DO NOTHING",
            [&acc_str],
        )?;

        // Atomically increment and return the next sequence number
        let next_seq: i64 = tx.query_row(
            "INSERT INTO account_sequences (account_id, current_seq, updated_at)
             VALUES (?1, 1, CURRENT_TIMESTAMP)
             ON CONFLICT (account_id) DO UPDATE SET
                 current_seq = account_sequences.current_seq + 1,
                 updated_at = CURRENT_TIMESTAMP
             RETURNING current_seq",
            [&acc_str],
            |row| row.get(0),
        )?;

        Ok(next_seq as u64)
    }

    /// Atomically allocates the next monotonic sequence number for an account.
    pub async fn allocate_next_sequence(&self, account_id: Uuid) -> Result<u64, DbError> {
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let next_seq = Self::allocate_sequence_in_tx(&tx, account_id)?;
        tx.commit()?;
        Ok(next_seq)
    }

    /// Returns the current (highest allocated) sequence number for an account using an active connection or transaction.
    /// Returns 0 if no sequence has been allocated yet.
    pub fn current_sequence_on_conn(conn: &Connection, account_id: Uuid) -> Result<u64, DbError> {
        let acc_str = account_id.to_string();
        let mut stmt =
            conn.prepare("SELECT current_seq FROM account_sequences WHERE account_id = ?1")?;
        let mut rows = stmt.query([&acc_str])?;

        if let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            Ok(seq as u64)
        } else {
            Ok(0)
        }
    }

    /// Returns the current sequence number for an account inside an active transaction.
    pub fn current_sequence_in_tx(
        tx: &rusqlite::Transaction<'_>,
        account_id: Uuid,
    ) -> Result<u64, DbError> {
        Self::current_sequence_on_conn(tx, account_id)
    }

    /// Returns the current (highest allocated) sequence number for an account.
    /// Returns 0 if no sequence has been allocated yet.
    pub async fn current_sequence(&self, account_id: Uuid) -> Result<u64, DbError> {
        let conn = self.conn.lock().await;
        Self::current_sequence_on_conn(&conn, account_id)
    }

    /// Executes a compare-and-swap push mutation inside an active transaction.
    ///
    /// Implements MASTER_SPEC.md §9.3 11-step transaction model:
    /// 1. Check if mutation ID already processed;
    /// 2. If yes, return original result;
    /// 3. Lock/read object row;
    /// 4. Compare current revision to expected_revision;
    /// 5. If unequal, reject with conflict metadata/current ciphertext;
    /// 6. Allocate next server sequence;
    /// 7. Append previous state to history;
    /// 8. Write new encrypted object;
    /// 9. Increment revision;
    /// 10. Persist processed mutation result;
    /// 11. Caller commits or rolls back based on outcome.
    pub fn push_mutation_in_tx(
        tx: &rusqlite::Transaction<'_>,
        account_id: Uuid,
        request: &PushRequest,
    ) -> Result<PushOutcome, DbError> {
        let acc_str = account_id.to_string();
        let obj_uuid = Uuid::parse_str(&request.object_id)
            .map_err(|e| DbError::InvalidUuid(format!("invalid object_id: {e}")))?;
        let mut_uuid = Uuid::parse_str(&request.mutation_id)
            .map_err(|e| DbError::InvalidUuid(format!("invalid mutation_id: {e}")))?;
        let obj_str = obj_uuid.to_string();
        let mut_str = mut_uuid.to_string();
        let req_hash = compute_mutation_request_hash(request);

        // 1 & 2. Check if mutation ID has already been processed (idempotency check)
        {
            let mut stmt_mut = tx.prepare(
                "SELECT object_id, response_body, request_hash
                 FROM processed_mutations
                 WHERE account_id = ?1 AND mutation_id = ?2",
            )?;
            let mut rows_mut = stmt_mut.query([&acc_str, &mut_str])?;
            if let Some(row) = rows_mut.next()? {
                let stored_obj_str: String = row.get(0)?;
                let resp_str: String = row.get(1)?;
                let stored_hash: Option<Vec<u8>> = row.get(2)?;

                if stored_obj_str != obj_str {
                    return Ok(PushOutcome::ReplayMismatch(format!(
                        "mutation_id '{}' was previously processed for object '{}', not '{}'",
                        request.mutation_id, stored_obj_str, obj_str
                    )));
                }

                if let Some(hash) = stored_hash {
                    if hash.as_slice() != req_hash.as_slice() {
                        return Ok(PushOutcome::ReplayMismatch(format!(
                            "mutation_id '{}' was previously processed with an incompatible payload",
                            request.mutation_id
                        )));
                    }
                }

                let push_resp: PushResponse = serde_json::from_str(&resp_str)?;
                return Ok(PushOutcome::Success(push_resp));
            }
        }

        // 3. Read current object row from encrypted_objects
        let existing_obj = {
            let mut stmt_obj = tx.prepare(
                "SELECT object_kind, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted
                 FROM encrypted_objects
                 WHERE account_id = ?1 AND object_id = ?2",
            )?;
            let mut rows_obj = stmt_obj.query([&acc_str, &obj_str])?;
            if let Some(row) = rows_obj.next()? {
                let cur_kind: i16 = row.get(0)?;
                let cur_rev: i64 = row.get(1)?;
                let cur_seq: i64 = row.get(2)?;
                let cur_env_ver: i32 = row.get(3)?;
                let cur_wrapped_key: Vec<u8> = row.get(4)?;
                let cur_payload: Vec<u8> = row.get(5)?;
                let is_deleted: bool = row.get(6)?;
                Some((
                    cur_kind,
                    cur_rev,
                    cur_seq,
                    cur_env_ver,
                    cur_wrapped_key,
                    cur_payload,
                    is_deleted,
                ))
            } else {
                None
            }
        };

        match existing_obj {
            Some((
                cur_kind,
                cur_rev,
                cur_seq,
                cur_env_ver,
                cur_wrapped_key,
                cur_payload,
                is_deleted,
            )) => {
                let cur_rev_u64 = cur_rev as u64;

                // 4 & 5. Compare current revision to expected_revision
                if request.expected_revision != cur_rev_u64 {
                    let wrapped_key: EncryptedKeyContainer =
                        serde_json::from_slice(&cur_wrapped_key)?;
                    let payload: EncryptedPayloadContainer = serde_json::from_slice(&cur_payload)?;
                    let current_envelope = EncryptedEnvelope {
                        envelope_version: cur_env_ver as u32,
                        object_id: request.object_id.clone(),
                        object_kind: cur_kind as u16,
                        wrapped_key,
                        payload,
                    };

                    return Ok(PushOutcome::Conflict(ConflictResponse {
                        error: zk_protocol::ERROR_REVISION_CONFLICT.to_string(),
                        object_id: request.object_id.clone(),
                        expected_revision: request.expected_revision,
                        current_revision: cur_rev_u64,
                        current_server_seq: cur_seq as u64,
                        current_envelope,
                        is_deleted,
                    }));
                }

                // 7. Append previous state to history
                tx.execute(
                    "INSERT INTO object_history (
                        account_id,
                        object_id,
                        revision,
                        server_seq,
                        envelope_version,
                        wrapped_key,
                        payload,
                        is_deleted,
                        created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)",
                    rusqlite::params![
                        acc_str,
                        obj_str,
                        cur_rev,
                        cur_seq,
                        cur_env_ver,
                        cur_wrapped_key,
                        cur_payload,
                        is_deleted,
                    ],
                )?;

                // 6. Allocate next server sequence
                let next_seq = Self::allocate_sequence_in_tx(tx, account_id)?;

                // 8 & 9. Increment revision and write new encrypted object
                let new_revision = cur_rev_u64 + 1;
                let new_wrapped_key = serde_json::to_vec(&request.envelope.wrapped_key)?;
                let new_payload = serde_json::to_vec(&request.envelope.payload)?;

                tx.execute(
                    "UPDATE encrypted_objects SET
                        object_kind = ?3,
                        revision = ?4,
                        server_seq = ?5,
                        envelope_version = ?6,
                        wrapped_key = ?7,
                        payload = ?8,
                        is_deleted = ?9,
                        updated_at = CURRENT_TIMESTAMP
                     WHERE account_id = ?1 AND object_id = ?2",
                    rusqlite::params![
                        acc_str,
                        obj_str,
                        request.object_kind as i16,
                        new_revision as i64,
                        next_seq as i64,
                        request.envelope.envelope_version as i32,
                        new_wrapped_key,
                        new_payload,
                        request.is_deleted,
                    ],
                )?;

                // 10. Persist processed mutation result
                let push_resp = PushResponse {
                    object_id: request.object_id.clone(),
                    revision: new_revision,
                    server_seq: next_seq,
                };
                let resp_json = serde_json::to_string(&push_resp)?;
                tx.execute(
                    "INSERT INTO processed_mutations (
                        account_id,
                        mutation_id,
                        object_id,
                        resulting_revision,
                        resulting_server_seq,
                        response_body,
                        created_at,
                        request_hash
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, ?7)",
                    rusqlite::params![
                        acc_str,
                        mut_str,
                        obj_str,
                        new_revision as i64,
                        next_seq as i64,
                        resp_json,
                        &req_hash[..],
                    ],
                )?;

                Ok(PushOutcome::Success(push_resp))
            }
            None => {
                // Object does not exist yet
                if request.expected_revision != 0 {
                    return Ok(PushOutcome::ObjectNotFound(format!(
                        "object '{}' not found, expected revision {}",
                        request.object_id, request.expected_revision
                    )));
                }

                // 6. Allocate next server sequence
                let next_seq = Self::allocate_sequence_in_tx(tx, account_id)?;
                let new_revision = 1u64;
                let new_wrapped_key = serde_json::to_vec(&request.envelope.wrapped_key)?;
                let new_payload = serde_json::to_vec(&request.envelope.payload)?;

                // 8 & 9. Insert new object at revision 1
                tx.execute(
                    "INSERT INTO encrypted_objects (
                        account_id,
                        object_id,
                        object_kind,
                        revision,
                        server_seq,
                        envelope_version,
                        wrapped_key,
                        payload,
                        is_deleted,
                        created_at,
                        updated_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                    rusqlite::params![
                        acc_str,
                        obj_str,
                        request.object_kind as i16,
                        new_revision as i64,
                        next_seq as i64,
                        request.envelope.envelope_version as i32,
                        new_wrapped_key,
                        new_payload,
                        request.is_deleted,
                    ],
                )?;

                // 10. Persist processed mutation result
                let push_resp = PushResponse {
                    object_id: request.object_id.clone(),
                    revision: new_revision,
                    server_seq: next_seq,
                };
                let resp_json = serde_json::to_string(&push_resp)?;
                tx.execute(
                    "INSERT INTO processed_mutations (
                        account_id,
                        mutation_id,
                        object_id,
                        resulting_revision,
                        resulting_server_seq,
                        response_body,
                        created_at,
                        request_hash
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, ?7)",
                    rusqlite::params![
                        acc_str,
                        mut_str,
                        obj_str,
                        new_revision as i64,
                        next_seq as i64,
                        resp_json,
                        &req_hash[..],
                    ],
                )?;

                Ok(PushOutcome::Success(push_resp))
            }
        }
    }

    /// Atomically executes a push mutation for the given account.
    pub async fn push_mutation(
        &self,
        account_id: Uuid,
        request: &PushRequest,
    ) -> Result<PushOutcome, DbError> {
        self.ensure_account(account_id).await?;
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let outcome = Self::push_mutation_in_tx(&tx, account_id, request)?;
        if matches!(outcome, PushOutcome::Success(_)) {
            tx.commit()?;
        }
        Ok(outcome)
    }

    /// Retrieves the current latest revision of an encrypted object.
    pub async fn get_encrypted_object(
        &self,
        account_id: Uuid,
        object_id: Uuid,
    ) -> Result<Option<EncryptedObjectRow>, DbError> {
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();
        let obj_str = object_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT account_id, object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted, created_at, updated_at
             FROM encrypted_objects
             WHERE account_id = ?1 AND object_id = ?2",
        )?;
        let mut rows = stmt.query([&acc_str, &obj_str])?;

        if let Some(row) = rows.next()? {
            let acc_id: String = row.get(0)?;
            let obj_id: String = row.get(1)?;
            let object_kind: i16 = row.get(2)?;
            let revision: i64 = row.get(3)?;
            let server_seq: i64 = row.get(4)?;
            let envelope_version: i32 = row.get(5)?;
            let wrapped_key: Vec<u8> = row.get(6)?;
            let payload: Vec<u8> = row.get(7)?;
            let is_deleted: bool = row.get(8)?;
            let created_at: String = row.get(9)?;
            let updated_at: String = row.get(10)?;

            Ok(Some(EncryptedObjectRow {
                account_id: Uuid::parse_str(&acc_id).unwrap_or(account_id),
                object_id: Uuid::parse_str(&obj_id).unwrap_or(object_id),
                object_kind,
                revision,
                server_seq,
                envelope_version,
                wrapped_key,
                payload,
                is_deleted,
                created_at,
                updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// Retrieves all historical revisions stored for an encrypted object.
    pub async fn get_object_history(
        &self,
        account_id: Uuid,
        object_id: Uuid,
    ) -> Result<Vec<ObjectHistoryRow>, DbError> {
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();
        let obj_str = object_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT account_id, object_id, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted, created_at
             FROM object_history
             WHERE account_id = ?1 AND object_id = ?2
             ORDER BY revision ASC",
        )?;

        let rows = stmt
            .query_map([&acc_str, &obj_str], |row| {
                let acc_id: String = row.get(0)?;
                let obj_id: String = row.get(1)?;
                let revision: i64 = row.get(2)?;
                let server_seq: i64 = row.get(3)?;
                let envelope_version: i32 = row.get(4)?;
                let wrapped_key: Vec<u8> = row.get(5)?;
                let payload: Vec<u8> = row.get(6)?;
                let is_deleted: bool = row.get(7)?;
                let created_at: String = row.get(8)?;

                Ok(ObjectHistoryRow {
                    account_id: Uuid::parse_str(&acc_id).unwrap_or(account_id),
                    object_id: Uuid::parse_str(&obj_id).unwrap_or(object_id),
                    revision,
                    server_seq,
                    envelope_version,
                    wrapped_key,
                    payload,
                    is_deleted,
                    created_at,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Pulls current object changes for the given account strictly after the specified cursor.
    ///
    /// Fetches up to `limit + 1` rows to determine `has_more` and calculates `next_cursor`.
    /// Returned changes are ordered strictly ascending by `server_seq`.
    /// Includes tombstones (`is_deleted = true`).
    pub async fn pull_changes(
        &self,
        account_id: Uuid,
        after: u64,
        limit: usize,
    ) -> Result<PullChangesResponse, DbError> {
        self.ensure_account(account_id).await?;
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();

        let mut stmt = conn.prepare(
            "SELECT object_id, object_kind, revision, server_seq, envelope_version, wrapped_key, payload, is_deleted
             FROM encrypted_objects
             WHERE account_id = ?1 AND server_seq > ?2
             ORDER BY server_seq ASC
             LIMIT ?3",
        )?;

        let fetch_limit = (limit.saturating_add(1)) as i64;
        let mut rows = stmt.query(rusqlite::params![acc_str, after as i64, fetch_limit])?;

        let mut items = Vec::with_capacity(limit);
        let mut has_more = false;

        while let Some(row) = rows.next()? {
            if items.len() >= limit {
                has_more = true;
                break;
            }

            let obj_id_str: String = row.get(0)?;
            let object_kind: i16 = row.get(1)?;
            let revision: i64 = row.get(2)?;
            let server_seq: i64 = row.get(3)?;
            let envelope_version: i32 = row.get(4)?;
            let wrapped_key_bytes: Vec<u8> = row.get(5)?;
            let payload_bytes: Vec<u8> = row.get(6)?;
            let is_deleted: bool = row.get(7)?;

            let wrapped_key: EncryptedKeyContainer = serde_json::from_slice(&wrapped_key_bytes)?;
            let payload: EncryptedPayloadContainer = serde_json::from_slice(&payload_bytes)?;

            let envelope = EncryptedEnvelope {
                envelope_version: envelope_version as u32,
                object_id: obj_id_str.clone(),
                object_kind: object_kind as u16,
                wrapped_key,
                payload,
            };

            items.push(ObjectChange {
                server_seq: server_seq as u64,
                object_id: obj_id_str,
                revision: revision as u64,
                object_kind: object_kind as u16,
                is_deleted,
                envelope,
            });
        }

        let next_cursor = items.last().map(|c| c.server_seq).unwrap_or(after);

        Ok(PullChangesResponse {
            changes: items,
            next_cursor,
            has_more,
        })
    }

    /// Creates a new authentication session for `account_id` and returns the session metadata and secret token.
    ///
    /// In accordance with SEC-003, only the BLAKE2s digest (`token_hash`) is persisted in the database;
    /// the secret token is returned to the client once.
    pub async fn create_session(
        &self,
        account_id: Uuid,
        device_id: Option<Uuid>,
        display_name: Option<String>,
        expires_in_secs: Option<i64>,
    ) -> Result<(AuthenticatedSession, AuthToken), DbError> {
        self.ensure_account(account_id).await?;

        // If device_id is provided, ensure device is registered and not revoked
        if let Some(dev_id) = device_id {
            self.register_device(account_id, dev_id, display_name.as_deref())
                .await?;
            if self.is_device_revoked(account_id, dev_id).await? {
                return Err(DbError::SchemaVerificationFailed(
                    "cannot create session for a revoked device".to_string(),
                ));
            }
        }

        let session_id = Uuid::new_v4();
        let tok1 = Uuid::new_v4().simple();
        let tok2 = Uuid::new_v4().simple();
        let raw_token = format!("zk_sess_{tok1}{tok2}");
        let token_hash: [u8; 32] = Blake2s256::digest(raw_token.as_bytes()).into();

        let conn = self.conn.lock().await;

        let acc_str = account_id.to_string();
        let sess_str = session_id.to_string();
        let dev_str = device_id.map(|d| d.to_string());

        let expires_sql = match expires_in_secs {
            Some(secs) => {
                if secs >= 0 {
                    format!("datetime('now', '+{secs} seconds')")
                } else {
                    format!("datetime('now', '{secs} seconds')")
                }
            }
            None => "NULL".to_string(),
        };

        let insert_sql = format!(
            "INSERT INTO sessions (
                session_id, account_id, device_id, token_hash, display_name, created_at, expires_at, revoked_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, {expires_sql}, NULL)"
        );

        conn.execute(
            &insert_sql,
            rusqlite::params![
                sess_str,
                acc_str,
                dev_str,
                token_hash.as_slice(),
                display_name,
            ],
        )?;

        let (created_at, expires_at): (String, Option<String>) = conn.query_row(
            "SELECT created_at, expires_at FROM sessions WHERE session_id = ?1",
            [&sess_str],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let session = AuthenticatedSession {
            session_id,
            account_id,
            device_id,
            display_name,
            created_at,
            expires_at,
            is_revoked: false,
        };

        Ok((session, AuthToken::new(raw_token)))
    }

    /// Validates a raw bearer token against stored session digests.
    pub async fn validate_session_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<SessionValidationResult>, DbError> {
        let token_hash: [u8; 32] = Blake2s256::digest(raw_token.as_bytes()).into();
        let conn = self.conn.lock().await;

        let query = "SELECT session_id, account_id, device_id, revoked_at,
                            (expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP) AS is_expired
                     FROM sessions WHERE token_hash = ?1";

        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query([token_hash.as_slice()])?;

        if let Some(row) = rows.next()? {
            let session_id: String = row.get(0)?;
            let account_id: String = row.get(1)?;
            let device_id: Option<String> = row.get(2)?;
            let revoked_at: Option<String> = row.get(3)?;
            let is_expired: bool = row.get(4)?;

            let session_id =
                Uuid::parse_str(&session_id).map_err(|e| DbError::InvalidUuid(e.to_string()))?;
            let account_id =
                Uuid::parse_str(&account_id).map_err(|e| DbError::InvalidUuid(e.to_string()))?;
            let device_id = match device_id {
                Some(d) => {
                    Some(Uuid::parse_str(&d).map_err(|e| DbError::InvalidUuid(e.to_string()))?)
                }
                None => None,
            };

            // If device_id is present, check whether device is revoked first
            if let Some(dev_id) = device_id {
                let dev_revoked: bool = conn
                    .query_row(
                        "SELECT (revoked_at IS NOT NULL) FROM devices WHERE account_id = ?1 AND device_id = ?2",
                        rusqlite::params![account_id.to_string(), dev_id.to_string()],
                        |r| r.get(0),
                    )
                    .unwrap_or(false);

                if dev_revoked {
                    return Ok(Some(SessionValidationResult::DeviceRevoked));
                }
            }

            if revoked_at.is_some() {
                return Ok(Some(SessionValidationResult::Revoked));
            }

            if is_expired {
                return Ok(Some(SessionValidationResult::Expired));
            }

            return Ok(Some(SessionValidationResult::Valid {
                account_id,
                device_id,
                session_id,
            }));
        }

        Ok(None)
    }

    /// Revokes a specific session.
    pub async fn revoke_session(
        &self,
        account_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, DbError> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
             WHERE account_id = ?1 AND session_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![account_id.to_string(), session_id.to_string()],
        )?;
        Ok(changed > 0)
    }

    /// Revokes all active sessions for an account.
    pub async fn revoke_all_sessions_for_account(
        &self,
        account_id: Uuid,
    ) -> Result<usize, DbError> {
        let conn = self.conn.lock().await;
        let count = conn.execute(
            "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
             WHERE account_id = ?1 AND revoked_at IS NULL",
            [account_id.to_string()],
        )?;
        Ok(count)
    }

    /// Revokes all active sessions associated with a specific device.
    pub async fn revoke_device_sessions(
        &self,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<usize, DbError> {
        let conn = self.conn.lock().await;
        let count = conn.execute(
            "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
             WHERE account_id = ?1 AND device_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![account_id.to_string(), device_id.to_string()],
        )?;
        Ok(count)
    }

    /// Registers or updates a device for an account.
    pub async fn register_device(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        display_name: Option<&str>,
    ) -> Result<DeviceRow, DbError> {
        self.ensure_account(account_id).await?;
        let conn = self.conn.lock().await;

        let acc_str = account_id.to_string();
        let dev_str = device_id.to_string();

        conn.execute(
            "INSERT INTO devices (account_id, device_id, display_name, created_at, last_seen, last_ack_server_seq)
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
             ON CONFLICT (account_id, device_id) DO UPDATE SET
                 display_name = COALESCE(excluded.display_name, devices.display_name),
                 last_seen = CURRENT_TIMESTAMP",
            rusqlite::params![acc_str, dev_str, display_name],
        )?;

        let row = conn.query_row(
            "SELECT account_id, device_id, display_name, created_at, last_seen, last_ack_server_seq, revoked_at
             FROM devices WHERE account_id = ?1 AND device_id = ?2",
            rusqlite::params![acc_str, dev_str],
            |r| {
                let acc: String = r.get(0)?;
                let dev: String = r.get(1)?;
                Ok(DeviceRow {
                    account_id: Uuid::parse_str(&acc).unwrap_or_default(),
                    device_id: Uuid::parse_str(&dev).unwrap_or_default(),
                    display_name: r.get(2)?,
                    created_at: r.get(3)?,
                    last_seen: r.get(4)?,
                    last_ack_server_seq: r.get(5)?,
                    revoked_at: r.get(6)?,
                })
            },
        )?;

        Ok(row)
    }

    /// Revokes a device and all its active sessions.
    pub async fn revoke_device(&self, account_id: Uuid, device_id: Uuid) -> Result<(), DbError> {
        let conn = self.conn.lock().await;
        let acc_str = account_id.to_string();
        let dev_str = device_id.to_string();

        conn.execute(
            "UPDATE devices SET revoked_at = CURRENT_TIMESTAMP
             WHERE account_id = ?1 AND device_id = ?2",
            rusqlite::params![acc_str, dev_str],
        )?;

        conn.execute(
            "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP
             WHERE account_id = ?1 AND device_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![acc_str, dev_str],
        )?;

        Ok(())
    }

    /// Returns true if the device is revoked.
    pub async fn is_device_revoked(
        &self,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, DbError> {
        let conn = self.conn.lock().await;
        let revoked: bool = conn.query_row(
            "SELECT (revoked_at IS NOT NULL) FROM devices WHERE account_id = ?1 AND device_id = ?2",
            rusqlite::params![account_id.to_string(), device_id.to_string()],
            |r| r.get(0),
        ).unwrap_or(false);

        Ok(revoked)
    }

    /// Lists all devices for an account.
    pub async fn list_devices(&self, account_id: Uuid) -> Result<Vec<DeviceRow>, DbError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT account_id, device_id, display_name, created_at, last_seen, last_ack_server_seq, revoked_at
             FROM devices WHERE account_id = ?1 ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map([account_id.to_string()], |r| {
            let acc: String = r.get(0)?;
            let dev: String = r.get(1)?;
            Ok(DeviceRow {
                account_id: Uuid::parse_str(&acc).unwrap_or_default(),
                device_id: Uuid::parse_str(&dev).unwrap_or_default(),
                display_name: r.get(2)?,
                created_at: r.get(3)?,
                last_seen: r.get(4)?,
                last_ack_server_seq: r.get(5)?,
                revoked_at: r.get(6)?,
            })
        })?;

        let mut devices = Vec::new();
        for d in rows {
            devices.push(d?);
        }
        Ok(devices)
    }

    /// Lists all sessions for an account.
    pub async fn list_sessions(&self, account_id: Uuid) -> Result<Vec<SessionRow>, DbError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT session_id, account_id, device_id, token_hash, display_name, created_at, expires_at, revoked_at
             FROM sessions WHERE account_id = ?1 ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([account_id.to_string()], |r| {
            let sess: String = r.get(0)?;
            let acc: String = r.get(1)?;
            let dev: Option<String> = r.get(2)?;
            Ok(SessionRow {
                session_id: Uuid::parse_str(&sess).unwrap_or_default(),
                account_id: Uuid::parse_str(&acc).unwrap_or_default(),
                device_id: dev.and_then(|d| Uuid::parse_str(&d).ok()),
                token_hash: r.get(3)?,
                display_name: r.get(4)?,
                created_at: r.get(5)?,
                expires_at: r.get(6)?,
                revoked_at: r.get(7)?,
            })
        })?;

        let mut sessions = Vec::new();
        for s in rows {
            sessions.push(s?);
        }
        Ok(sessions)
    }

    /// Creates and persists a WebAuthn challenge for registration or login.
    pub async fn create_webauthn_challenge(
        &self,
        challenge_id: Uuid,
        challenge: &[u8],
        account_id: Option<Uuid>,
        purpose: &str,
        ttl_seconds: i64,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().await;
        let expires_sql = if ttl_seconds >= 0 {
            format!("datetime('now', '+{ttl_seconds} seconds')")
        } else {
            format!("datetime('now', '{ttl_seconds} seconds')")
        };
        let acc_str = account_id.map(|id| id.to_string());

        conn.execute(
            &format!(
                "INSERT INTO webauthn_challenges (
                    challenge_id, challenge, account_id, purpose, created_at, expires_at
                ) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, {expires_sql})"
            ),
            rusqlite::params![challenge_id.to_string(), challenge, acc_str, purpose,],
        )?;

        Ok(())
    }

    /// Consumes and deletes a WebAuthn challenge, verifying that it exists, matches the expected purpose, and has not expired.
    pub async fn consume_webauthn_challenge(
        &self,
        challenge_id: Uuid,
        expected_purpose: &str,
    ) -> Result<WebAuthnChallengeRecord, DbError> {
        let conn = self.conn.lock().await;
        let id_str = challenge_id.to_string();

        let query = "DELETE FROM webauthn_challenges WHERE challenge_id = ?1 AND purpose = ?2
                     RETURNING challenge, account_id, purpose, created_at, expires_at,
                               (expires_at <= CURRENT_TIMESTAMP) AS is_expired";

        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query([id_str.as_str(), expected_purpose])?;

        if let Some(row) = rows.next()? {
            let challenge: Vec<u8> = row.get(0)?;
            let account_id_str: Option<String> = row.get(1)?;
            let purpose: String = row.get(2)?;
            let created_at: String = row.get(3)?;
            let expires_at: String = row.get(4)?;
            let is_expired: bool = row.get(5)?;

            if is_expired {
                return Err(DbError::ChallengeExpired);
            }

            if purpose != expected_purpose {
                return Err(DbError::ChallengeNotFound);
            }

            let account_id = match account_id_str {
                Some(s) => {
                    Some(Uuid::parse_str(&s).map_err(|e| DbError::InvalidUuid(e.to_string()))?)
                }
                None => None,
            };

            Ok(WebAuthnChallengeRecord {
                challenge_id,
                challenge,
                account_id,
                purpose,
                created_at,
                expires_at,
            })
        } else {
            Err(DbError::ChallengeNotFound)
        }
    }

    /// Registers a new WebAuthn credential for an account.
    pub async fn register_webauthn_credential(
        &self,
        credential_id: &[u8],
        account_id: Uuid,
        public_key: &[u8],
        device_id: Option<Uuid>,
        display_name: Option<String>,
    ) -> Result<(), DbError> {
        self.ensure_account(account_id).await?;
        let conn = self.conn.lock().await;

        let acc_str = account_id.to_string();
        let dev_str = device_id.map(|d| d.to_string());

        let res = conn.execute(
            "INSERT INTO webauthn_credentials (
                credential_id, account_id, public_key, sign_count, device_id, display_name, created_at, last_used_at
            ) VALUES (?1, ?2, ?3, 0, ?4, ?5, CURRENT_TIMESTAMP, NULL)",
            rusqlite::params![
                credential_id,
                acc_str,
                public_key,
                dev_str,
                display_name,
            ],
        );

        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(DbError::CredentialAlreadyExists)
            }
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    /// Looks up a WebAuthn credential by its credential ID.
    pub async fn get_webauthn_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<WebAuthnCredentialRecord>, DbError> {
        let conn = self.conn.lock().await;
        let query = "SELECT account_id, public_key, sign_count, device_id, display_name, created_at, last_used_at
                     FROM webauthn_credentials WHERE credential_id = ?1";

        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query([credential_id])?;

        if let Some(row) = rows.next()? {
            let account_id_str: String = row.get(0)?;
            let public_key: Vec<u8> = row.get(1)?;
            let sign_count: i64 = row.get(2)?;
            let device_id_str: Option<String> = row.get(3)?;
            let display_name: Option<String> = row.get(4)?;
            let created_at: String = row.get(5)?;
            let last_used_at: Option<String> = row.get(6)?;

            let account_id = Uuid::parse_str(&account_id_str)
                .map_err(|e| DbError::InvalidUuid(e.to_string()))?;
            let device_id = match device_id_str {
                Some(d) => {
                    Some(Uuid::parse_str(&d).map_err(|e| DbError::InvalidUuid(e.to_string()))?)
                }
                None => None,
            };

            Ok(Some(WebAuthnCredentialRecord {
                credential_id: credential_id.to_vec(),
                account_id,
                public_key,
                sign_count: sign_count as u64,
                device_id,
                display_name,
                created_at,
                last_used_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// Atomically rejects concurrent stale signature counters; zero counters remain valid for synced passkeys.
    pub async fn advance_webauthn_counter(
        &self,
        credential_id: &[u8],
        old: u64,
        new: u32,
    ) -> Result<bool, DbError> {
        let conn = self.conn.lock().await;
        Ok(conn.execute("UPDATE webauthn_credentials SET sign_count = ?1, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?2 AND sign_count = ?3", rusqlite::params![new, credential_id, old])? == 1)
    }

    /// Updates the usage timestamp and signature counter for a WebAuthn credential.
    pub async fn update_webauthn_credential_usage(
        &self,
        credential_id: &[u8],
        new_sign_count: u64,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE webauthn_credentials
             SET sign_count = ?1, last_used_at = CURRENT_TIMESTAMP
             WHERE credential_id = ?2",
            rusqlite::params![new_sign_count as i64, credential_id],
        )?;

        if changed == 0 {
            return Err(DbError::CredentialNotFound);
        }

        Ok(())
    }

    /// Stores an opaque ciphertext blob for the given account (ZK-082).
    ///
    /// In accordance with SEC-001, SEC-002, and SEC-003:
    /// - The server NEVER receives or persists note plaintext, attachment filenames, or MIME types.
    /// - Blobs are strictly isolated by `account_id` and identified by opaque `blob_id`.
    /// - Enforces single blob size limit (`max_blob_size`) and account aggregate storage quota (`account_blob_quota`).
    pub async fn put_blob(
        &self,
        account_id: Uuid,
        blob_id: &str,
        data: &[u8],
        account_blob_quota: u64,
        max_blob_size: usize,
    ) -> Result<u64, DbError> {
        if data.len() > max_blob_size {
            return Err(DbError::BlobSizeExceeded {
                max: max_blob_size,
                actual: data.len(),
            });
        }

        self.ensure_account(account_id).await?;

        let conn = self.conn.lock().await;

        // Check if blob already exists to compute net storage delta
        let existing_size: i64 = conn
            .query_row(
                "SELECT size FROM blobs WHERE account_id = ?1 AND blob_id = ?2",
                rusqlite::params![account_id.to_string(), blob_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Check current aggregate usage
        let current_usage: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE account_id = ?1",
            rusqlite::params![account_id.to_string()],
            |row| row.get(0),
        )?;

        let current_usage_u64 = if current_usage < 0 {
            0
        } else {
            current_usage as u64
        };
        let existing_size_u64 = if existing_size < 0 {
            0
        } else {
            existing_size as u64
        };
        let new_size_u64 = data.len() as u64;

        let projected_usage = current_usage_u64.saturating_sub(existing_size_u64) + new_size_u64;
        if projected_usage > account_blob_quota {
            return Err(DbError::AccountQuotaExceeded {
                quota: account_blob_quota,
                requested: projected_usage,
            });
        }

        conn.execute(
            "INSERT INTO blobs (account_id, blob_id, size, data, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
             ON CONFLICT (account_id, blob_id) DO UPDATE SET
                 size = excluded.size,
                 data = excluded.data,
                 updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![account_id.to_string(), blob_id, new_size_u64 as i64, data],
        )?;

        Ok(new_size_u64)
    }

    /// Retrieves an opaque ciphertext blob by ID, strictly scoped to the authenticated account (ZK-082).
    ///
    /// Returns `None` if the blob does not exist or belongs to another account.
    pub async fn get_blob(
        &self,
        account_id: Uuid,
        blob_id: &str,
    ) -> Result<Option<Vec<u8>>, DbError> {
        let conn = self.conn.lock().await;

        let mut stmt =
            conn.prepare("SELECT data FROM blobs WHERE account_id = ?1 AND blob_id = ?2")?;

        let mut rows = stmt.query(rusqlite::params![account_id.to_string(), blob_id])?;
        if let Some(row) = rows.next()? {
            let data: Vec<u8> = row.get(0)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Deletes a ciphertext blob by ID, strictly scoped to the authenticated account (ZK-082).
    ///
    /// Returns `true` if a blob was deleted, or `false` if it did not exist.
    pub async fn delete_blob(&self, account_id: Uuid, blob_id: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock().await;

        let rows_affected = conn.execute(
            "DELETE FROM blobs WHERE account_id = ?1 AND blob_id = ?2",
            rusqlite::params![account_id.to_string(), blob_id],
        )?;

        Ok(rows_affected > 0)
    }

    /// Returns the total storage bytes consumed by an account's ciphertext blobs (ZK-082).
    pub async fn get_account_blob_usage(&self, account_id: Uuid) -> Result<u64, DbError> {
        let conn = self.conn.lock().await;

        let current_usage: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE account_id = ?1",
            rusqlite::params![account_id.to_string()],
            |row| row.get(0),
        )?;

        Ok(if current_usage < 0 {
            0
        } else {
            current_usage as u64
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_bootstrap() -> VaultBootstrap {
        VaultBootstrap {
            crypto_version: 1,
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: "cmFuZG9tLXNhbHQtMTZieXRlcw==".to_string(),
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1,
            },
            wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA==".to_string(),
            },
            recovery_wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==".to_string(),
                ciphertext: "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk=".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_store_round_trip() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        // Initially None
        assert!(db.get_vault_bootstrap(acc_id).await.unwrap().is_none());

        // Create bootstrap
        let original = sample_bootstrap();
        db.create_vault_bootstrap(acc_id, &original).await.unwrap();

        // Retrieve bootstrap
        let retrieved = db
            .get_vault_bootstrap(acc_id)
            .await
            .unwrap()
            .expect("should exist");
        assert_eq!(retrieved, original);

        // Duplicate creation fails
        let err = db
            .create_vault_bootstrap(acc_id, &original)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::VaultAlreadyExists(_)));
    }

    #[tokio::test]
    async fn test_sequence_allocator_monotonic_and_isolated() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_a = Uuid::new_v4();
        let acc_b = Uuid::new_v4();

        // Initially 0 for both
        assert_eq!(db.current_sequence(acc_a).await.unwrap(), 0);
        assert_eq!(db.current_sequence(acc_b).await.unwrap(), 0);

        // Account A allocates 1, 2, 3
        assert_eq!(db.allocate_next_sequence(acc_a).await.unwrap(), 1);
        assert_eq!(db.allocate_next_sequence(acc_a).await.unwrap(), 2);
        assert_eq!(db.allocate_next_sequence(acc_a).await.unwrap(), 3);

        // Account B is still 0
        assert_eq!(db.current_sequence(acc_b).await.unwrap(), 0);

        // Account B allocates 1, 2
        assert_eq!(db.allocate_next_sequence(acc_b).await.unwrap(), 1);
        assert_eq!(db.allocate_next_sequence(acc_b).await.unwrap(), 2);

        // Account A allocates 4
        assert_eq!(db.allocate_next_sequence(acc_a).await.unwrap(), 4);

        // Check current sequences
        assert_eq!(db.current_sequence(acc_a).await.unwrap(), 4);
        assert_eq!(db.current_sequence(acc_b).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_sequence_allocator_transaction_rollback() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        // Initial sequence is 0
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 0);

        // 1. Transaction commits sequence 1
        {
            let conn_lock = db.connection();
            let mut conn = conn_lock.lock().await;
            let tx = conn.transaction().unwrap();
            let seq = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();
            assert_eq!(seq, 1);
            tx.commit().unwrap();
        }
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 1);

        // 2. Transaction allocates sequence 2 but rolls back
        {
            let conn_lock = db.connection();
            let mut conn = conn_lock.lock().await;
            let tx = conn.transaction().unwrap();
            let seq = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();
            assert_eq!(seq, 2);
            tx.rollback().unwrap();
        }

        // Sequence must remain 1 after rollback
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 1);

        // 3. Next transaction allocates sequence 2 and commits
        {
            let conn_lock = db.connection();
            let mut conn = conn_lock.lock().await;
            let tx = conn.transaction().unwrap();
            let seq = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();
            assert_eq!(seq, 2);
            tx.commit().unwrap();
        }

        // Current sequence is now 2
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_sequence_allocator_multiple_allocations_in_same_tx() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        let conn_lock = db.connection();
        let mut conn = conn_lock.lock().await;
        let tx = conn.transaction().unwrap();

        let s1 = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();
        let s2 = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();
        let s3 = ServerDb::allocate_sequence_in_tx(&tx, acc_id).unwrap();

        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);

        assert_eq!(ServerDb::current_sequence_in_tx(&tx, acc_id).unwrap(), 3);

        tx.commit().unwrap();
        drop(conn);

        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 3);
    }

    fn sample_envelope(object_id: &str, payload_text: &str) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: 1,
            object_id: object_id.to_string(),
            object_kind: 1,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
                ciphertext: Base64::encode_string(payload_text.as_bytes()),
            },
        }
    }

    fn sample_push_req(object_id: &str, expected_revision: u64, payload_text: &str) -> PushRequest {
        sample_push_req_with_mut_id(
            &Uuid::new_v4().to_string(),
            object_id,
            expected_revision,
            payload_text,
        )
    }

    fn sample_push_req_with_mut_id(
        mutation_id: &str,
        object_id: &str,
        expected_revision: u64,
        payload_text: &str,
    ) -> PushRequest {
        PushRequest {
            mutation_id: mutation_id.to_string(),
            object_id: object_id.to_string(),
            expected_revision,
            object_kind: 1,
            envelope: sample_envelope(object_id, payload_text),
            is_deleted: false,
        }
    }

    #[tokio::test]
    async fn test_push_mutation_create_and_update_with_history() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let obj_id = Uuid::new_v4();
        let obj_str = obj_id.to_string();

        // 1. Initial create with expected_revision = 0
        let req1 = sample_push_req(&obj_str, 0, "payload v1");
        let outcome1 = db.push_mutation(acc_id, &req1).await.unwrap();
        match outcome1 {
            PushOutcome::Success(resp) => {
                assert_eq!(resp.object_id, obj_str);
                assert_eq!(resp.revision, 1);
                assert_eq!(resp.server_seq, 1);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        // Verify history is empty after initial create
        let hist = db.get_object_history(acc_id, obj_id).await.unwrap();
        assert!(
            hist.is_empty(),
            "initial create must not produce history entries"
        );

        // Verify current object state
        let obj = db
            .get_encrypted_object(acc_id, obj_id)
            .await
            .unwrap()
            .expect("object exists");
        assert_eq!(obj.revision, 1);
        assert_eq!(obj.server_seq, 1);

        // 2. Update 1: expected_revision = 1 -> revision 2
        let req2 = sample_push_req(&obj_str, 1, "payload v2");
        let outcome2 = db.push_mutation(acc_id, &req2).await.unwrap();
        match outcome2 {
            PushOutcome::Success(resp) => {
                assert_eq!(resp.object_id, obj_str);
                assert_eq!(resp.revision, 2);
                assert_eq!(resp.server_seq, 2);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        // Verify history has revision 1
        let hist2 = db.get_object_history(acc_id, obj_id).await.unwrap();
        assert_eq!(hist2.len(), 1);
        assert_eq!(hist2[0].revision, 1);
        assert_eq!(hist2[0].server_seq, 1);

        // Verify current object state is at revision 2
        let obj2 = db
            .get_encrypted_object(acc_id, obj_id)
            .await
            .unwrap()
            .expect("object exists");
        assert_eq!(obj2.revision, 2);
        assert_eq!(obj2.server_seq, 2);

        // 3. Update 2: expected_revision = 2 -> revision 3
        let req3 = sample_push_req(&obj_str, 2, "payload v3");
        let outcome3 = db.push_mutation(acc_id, &req3).await.unwrap();
        match outcome3 {
            PushOutcome::Success(resp) => {
                assert_eq!(resp.object_id, obj_str);
                assert_eq!(resp.revision, 3);
                assert_eq!(resp.server_seq, 3);
            }
            other => panic!("expected Success, got {:?}", other),
        }

        // Verify history has revisions 1 and 2
        let hist3 = db.get_object_history(acc_id, obj_id).await.unwrap();
        assert_eq!(hist3.len(), 2);
        assert_eq!(hist3[0].revision, 1);
        assert_eq!(hist3[1].revision, 2);

        // Verify current object state is at revision 3
        let obj3 = db
            .get_encrypted_object(acc_id, obj_id)
            .await
            .unwrap()
            .expect("object exists");
        assert_eq!(obj3.revision, 3);
        assert_eq!(obj3.server_seq, 3);
    }

    #[tokio::test]
    async fn test_push_mutation_conflict_rejection() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let obj_id = Uuid::new_v4();
        let obj_str = obj_id.to_string();

        // 1. Create object at revision 1
        let req1 = sample_push_req(&obj_str, 0, "original payload");
        db.push_mutation(acc_id, &req1).await.unwrap();
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 1);

        // 2. Duplicate create (expected_revision = 0) must be rejected with Conflict
        let dup_create = sample_push_req(&obj_str, 0, "duplicate create payload");
        let outcome = db.push_mutation(acc_id, &dup_create).await.unwrap();
        match outcome {
            PushOutcome::Conflict(conflict) => {
                assert_eq!(conflict.error, zk_protocol::ERROR_REVISION_CONFLICT);
                assert_eq!(conflict.object_id, obj_str);
                assert_eq!(conflict.expected_revision, 0);
                assert_eq!(conflict.current_revision, 1);
                assert_eq!(conflict.current_server_seq, 1);
            }
            other => panic!("expected Conflict, got {:?}", other),
        }

        // 3. Stale update (expected_revision = 99 when current is 1) rejected with Conflict
        let stale_update = sample_push_req(&obj_str, 99, "stale update payload");
        let outcome_stale = db.push_mutation(acc_id, &stale_update).await.unwrap();
        match outcome_stale {
            PushOutcome::Conflict(conflict) => {
                assert_eq!(conflict.error, zk_protocol::ERROR_REVISION_CONFLICT);
                assert_eq!(conflict.expected_revision, 99);
                assert_eq!(conflict.current_revision, 1);
            }
            other => panic!("expected Conflict, got {:?}", other),
        }

        // 4. Update for non-existent object with expected_revision > 0 returns ObjectNotFound
        let non_existent_id = Uuid::new_v4().to_string();
        let not_found_req = sample_push_req(&non_existent_id, 1, "phantom update");
        let outcome_nf = db.push_mutation(acc_id, &not_found_req).await.unwrap();
        assert!(matches!(outcome_nf, PushOutcome::ObjectNotFound(_)));

        // Verify sequence did NOT advance after rejections
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_push_mutation_idempotent_replay() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let obj_id = Uuid::new_v4();
        let obj_str = obj_id.to_string();

        let req = sample_push_req(&obj_str, 0, "idempotent payload");

        // First push
        let outcome1 = db.push_mutation(acc_id, &req).await.unwrap();
        let (rev1, seq1) = match outcome1 {
            PushOutcome::Success(resp) => (resp.revision, resp.server_seq),
            other => panic!("expected Success, got {:?}", other),
        };
        assert_eq!(rev1, 1);
        assert_eq!(seq1, 1);

        // Replay exact same mutation
        let outcome2 = db.push_mutation(acc_id, &req).await.unwrap();
        match outcome2 {
            PushOutcome::Success(resp) => {
                assert_eq!(resp.revision, rev1, "replayed revision must match original");
                assert_eq!(
                    resp.server_seq, seq1,
                    "replayed server_seq must match original"
                );
            }
            other => panic!("expected Success on replay, got {:?}", other),
        }

        // Current sequence is still 1 (no extra sequence allocated)
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_push_mutation_idempotent_replay_update() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let obj_id = Uuid::new_v4();
        let obj_str = obj_id.to_string();

        // 1. Create object at revision 1
        let create_req = sample_push_req(&obj_str, 0, "initial");
        let create_resp = match db.push_mutation(acc_id, &create_req).await.unwrap() {
            PushOutcome::Success(resp) => resp,
            other => panic!("expected Success, got {:?}", other),
        };
        assert_eq!(create_resp.revision, 1);
        assert_eq!(create_resp.server_seq, 1);

        // 2. Update object to revision 2
        let update_mut_id = Uuid::new_v4().to_string();
        let update_req =
            sample_push_req_with_mut_id(&update_mut_id, &obj_str, 1, "updated content");
        let update_resp = match db.push_mutation(acc_id, &update_req).await.unwrap() {
            PushOutcome::Success(resp) => resp,
            other => panic!("expected Success, got {:?}", other),
        };
        assert_eq!(update_resp.revision, 2);
        assert_eq!(update_resp.server_seq, 2);

        // History contains revision 1
        let hist = db.get_object_history(acc_id, obj_id).await.unwrap();
        assert_eq!(hist.len(), 1);

        // 3. Replay exact same update mutation
        let replay_resp = match db.push_mutation(acc_id, &update_req).await.unwrap() {
            PushOutcome::Success(resp) => resp,
            other => panic!("expected Success on replay, got {:?}", other),
        };
        assert_eq!(replay_resp.revision, 2);
        assert_eq!(replay_resp.server_seq, 2);

        // Sequence and revision must NOT advance
        assert_eq!(db.current_sequence(acc_id).await.unwrap(), 2);
        let obj = db
            .get_encrypted_object(acc_id, obj_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(obj.revision, 2);
        assert_eq!(obj.server_seq, 2);

        // History must NOT duplicate previous revision
        let hist2 = db.get_object_history(acc_id, obj_id).await.unwrap();
        assert_eq!(hist2.len(), 1);
    }

    #[tokio::test]
    async fn test_push_mutation_replay_mismatch_object_id() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let mut_id = Uuid::new_v4().to_string();
        let obj1 = Uuid::new_v4().to_string();
        let obj2 = Uuid::new_v4().to_string();

        let req1 = sample_push_req_with_mut_id(&mut_id, &obj1, 0, "obj1 payload");
        let outcome1 = db.push_mutation(acc_id, &req1).await.unwrap();
        assert!(matches!(outcome1, PushOutcome::Success(_)));

        // Attempt replay of same mutation_id with different object_id
        let req2 = sample_push_req_with_mut_id(&mut_id, &obj2, 0, "obj2 payload");
        let outcome2 = db.push_mutation(acc_id, &req2).await.unwrap();
        match outcome2 {
            PushOutcome::ReplayMismatch(msg) => {
                assert!(msg.contains("previously processed for object"));
            }
            other => panic!("expected ReplayMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_push_mutation_replay_mismatch_expected_revision() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let mut_id = Uuid::new_v4().to_string();
        let obj_str = Uuid::new_v4().to_string();

        let req1 = sample_push_req_with_mut_id(&mut_id, &obj_str, 0, "payload");
        let outcome1 = db.push_mutation(acc_id, &req1).await.unwrap();
        assert!(matches!(outcome1, PushOutcome::Success(_)));

        // Attempt replay of same mutation_id but with different expected_revision
        let mut req2 = sample_push_req_with_mut_id(&mut_id, &obj_str, 1, "payload");
        req2.expected_revision = 1;
        let outcome2 = db.push_mutation(acc_id, &req2).await.unwrap();
        match outcome2 {
            PushOutcome::ReplayMismatch(msg) => {
                assert!(msg.contains("incompatible payload"));
            }
            other => panic!("expected ReplayMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_push_mutation_replay_mismatch_payload() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let mut_id = Uuid::new_v4().to_string();
        let obj_str = Uuid::new_v4().to_string();

        let req1 = sample_push_req_with_mut_id(&mut_id, &obj_str, 0, "payload A");
        let outcome1 = db.push_mutation(acc_id, &req1).await.unwrap();
        assert!(matches!(outcome1, PushOutcome::Success(_)));

        // Attempt replay of same mutation_id but with different payload
        let req2 = sample_push_req_with_mut_id(&mut_id, &obj_str, 0, "payload B");
        let outcome2 = db.push_mutation(acc_id, &req2).await.unwrap();
        match outcome2 {
            PushOutcome::ReplayMismatch(msg) => {
                assert!(msg.contains("incompatible payload"));
            }
            other => panic!("expected ReplayMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_push_mutation_replay_mismatch_is_deleted() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let mut_id = Uuid::new_v4().to_string();
        let obj_str = Uuid::new_v4().to_string();

        let mut req1 = sample_push_req_with_mut_id(&mut_id, &obj_str, 0, "payload");
        req1.is_deleted = false;
        let outcome1 = db.push_mutation(acc_id, &req1).await.unwrap();
        assert!(matches!(outcome1, PushOutcome::Success(_)));

        // Attempt replay of same mutation_id but with is_deleted = true
        let mut req2 = sample_push_req_with_mut_id(&mut_id, &obj_str, 0, "payload");
        req2.is_deleted = true;
        let outcome2 = db.push_mutation(acc_id, &req2).await.unwrap();
        match outcome2 {
            PushOutcome::ReplayMismatch(msg) => {
                assert!(msg.contains("incompatible payload"));
            }
            other => panic!("expected ReplayMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_pull_changes_empty_account() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        let resp = db.pull_changes(acc_id, 0, 50).await.unwrap();
        assert!(resp.changes.is_empty());
        assert_eq!(resp.next_cursor, 0);
        assert!(!resp.has_more);
    }

    #[tokio::test]
    async fn test_pull_changes_ordering_and_pagination() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        let obj1 = Uuid::new_v4().to_string();
        let obj2 = Uuid::new_v4().to_string();
        let obj3 = Uuid::new_v4().to_string();

        db.push_mutation(acc_id, &sample_push_req(&obj1, 0, "n1"))
            .await
            .unwrap();
        db.push_mutation(acc_id, &sample_push_req(&obj2, 0, "n2"))
            .await
            .unwrap();
        db.push_mutation(acc_id, &sample_push_req(&obj3, 0, "n3"))
            .await
            .unwrap();

        // Page 1: limit 2
        let page1 = db.pull_changes(acc_id, 0, 2).await.unwrap();
        assert_eq!(page1.changes.len(), 2);
        assert_eq!(page1.changes[0].server_seq, 1);
        assert_eq!(page1.changes[0].object_id, obj1);
        assert_eq!(page1.changes[1].server_seq, 2);
        assert_eq!(page1.changes[1].object_id, obj2);
        assert_eq!(page1.next_cursor, 2);
        assert!(page1.has_more);

        // Page 2: after cursor 2, limit 2
        let page2 = db.pull_changes(acc_id, page1.next_cursor, 2).await.unwrap();
        assert_eq!(page2.changes.len(), 1);
        assert_eq!(page2.changes[0].server_seq, 3);
        assert_eq!(page2.changes[0].object_id, obj3);
        assert_eq!(page2.next_cursor, 3);
        assert!(!page2.has_more);

        // Page 3: after cursor 3
        let page3 = db.pull_changes(acc_id, page2.next_cursor, 2).await.unwrap();
        assert!(page3.changes.is_empty());
        assert_eq!(page3.next_cursor, 3);
        assert!(!page3.has_more);
    }

    #[tokio::test]
    async fn test_pull_changes_includes_tombstones() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let obj_id = Uuid::new_v4().to_string();

        // 1. Create note
        db.push_mutation(acc_id, &sample_push_req(&obj_id, 0, "initial note"))
            .await
            .unwrap();

        // 2. Delete note (is_deleted = true, expected_revision = 1)
        let mut del_req = sample_push_req(&obj_id, 1, "tombstone");
        del_req.is_deleted = true;
        db.push_mutation(acc_id, &del_req).await.unwrap();

        // 3. Pull changes
        let pull = db.pull_changes(acc_id, 0, 50).await.unwrap();
        assert_eq!(pull.changes.len(), 1);
        assert_eq!(pull.changes[0].object_id, obj_id);
        assert_eq!(pull.changes[0].revision, 2);
        assert_eq!(pull.changes[0].server_seq, 2);
        assert!(
            pull.changes[0].is_deleted,
            "tombstone must be marked deleted"
        );
    }

    #[tokio::test]
    async fn test_pull_changes_cross_account_isolation() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_a = Uuid::new_v4();
        let acc_b = Uuid::new_v4();

        let obj_a = Uuid::new_v4().to_string();
        db.push_mutation(acc_a, &sample_push_req(&obj_a, 0, "note for A"))
            .await
            .unwrap();

        let pull_b = db.pull_changes(acc_b, 0, 50).await.unwrap();
        assert!(
            pull_b.changes.is_empty(),
            "account B must not see account A's changes"
        );
    }

    #[tokio::test]
    async fn test_session_lifecycle_and_validation() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();

        // 1. Create active session
        let (sess, token) = db
            .create_session(acc_id, None, Some("CLI test".to_string()), Some(3600))
            .await
            .unwrap();

        assert_eq!(sess.account_id, acc_id);
        assert!(!sess.is_revoked);
        assert!(sess.expires_at.is_some());

        // 2. Validate token
        let res = db
            .validate_session_token(token.expose_secret())
            .await
            .unwrap();
        match res {
            Some(SessionValidationResult::Valid {
                account_id,
                device_id,
                session_id,
            }) => {
                assert_eq!(account_id, acc_id);
                assert_eq!(device_id, None);
                assert_eq!(session_id, sess.session_id);
            }
            other => panic!("expected Valid, got {other:?}"),
        }

        // 3. Revoke session
        let revoked = db.revoke_session(acc_id, sess.session_id).await.unwrap();
        assert!(revoked);

        // 4. Validate again -> Revoked
        let res_revoked = db
            .validate_session_token(token.expose_secret())
            .await
            .unwrap();
        assert_eq!(res_revoked, Some(SessionValidationResult::Revoked));
    }

    #[tokio::test]
    async fn test_device_registration_and_revocation_cascades_to_sessions() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let dev_id = Uuid::new_v4();

        // 1. Register device
        let dev_row = db
            .register_device(acc_id, dev_id, Some("Laptop"))
            .await
            .unwrap();
        assert_eq!(dev_row.device_id, dev_id);
        assert_eq!(dev_row.display_name, Some("Laptop".to_string()));

        // 2. Create session linked to device
        let (sess, token) = db
            .create_session(
                acc_id,
                Some(dev_id),
                Some("Laptop session".to_string()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(sess.device_id, Some(dev_id));

        // 3. Verify session is valid
        let res = db
            .validate_session_token(token.expose_secret())
            .await
            .unwrap();
        assert!(matches!(res, Some(SessionValidationResult::Valid { .. })));

        // 4. Revoke device
        db.revoke_device(acc_id, dev_id).await.unwrap();
        assert!(db.is_device_revoked(acc_id, dev_id).await.unwrap());

        // 5. Session validation reflects revocation (either Revoked or DeviceRevoked)
        let res_dev_rev = db
            .validate_session_token(token.expose_secret())
            .await
            .unwrap();
        assert!(
            matches!(
                res_dev_rev,
                Some(SessionValidationResult::Revoked)
                    | Some(SessionValidationResult::DeviceRevoked)
            ),
            "revoking device must invalidate session"
        );
    }
}
