//! PostgreSQL and local database schema models, table names, and index definitions.
//!
//! Defined in MASTER_SPEC.md §8 for zero-knowledge server state:
//! - accounts
//! - vaults
//! - encrypted_objects
//! - object_history
//! - processed_mutations
//! - devices
//! - schema_migrations

use crate::error::DbError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Table name constants.
pub const TABLE_ACCOUNTS: &str = "accounts";
pub const TABLE_VAULTS: &str = "vaults";
pub const TABLE_ENCRYPTED_OBJECTS: &str = "encrypted_objects";
pub const TABLE_OBJECT_HISTORY: &str = "object_history";
pub const TABLE_PROCESSED_MUTATIONS: &str = "processed_mutations";
pub const TABLE_DEVICES: &str = "devices";
pub const TABLE_ACCOUNT_SEQUENCES: &str = "account_sequences";
pub const TABLE_SESSIONS: &str = "sessions";
pub const TABLE_WEBAUTHN_CREDENTIALS: &str = "webauthn_credentials";
pub const TABLE_WEBAUTHN_CHALLENGES: &str = "webauthn_challenges";
pub const TABLE_BLOBS: &str = "blobs";
pub const TABLE_SCHEMA_MIGRATIONS: &str = "schema_migrations";

/// Index name constants.
pub const INDEX_ENCRYPTED_OBJECTS_ACCOUNT_SEQ: &str = "encrypted_objects_account_seq_idx";
pub const INDEX_OBJECT_HISTORY_ACCOUNT_SEQ: &str = "idx_object_history_account_seq";
pub const INDEX_PROCESSED_MUTATIONS_ACCOUNT_OBJECT: &str = "idx_processed_mutations_account_object";
pub const INDEX_DEVICES_ACCOUNT_LAST_ACK: &str = "idx_devices_account_last_ack";
pub const INDEX_SESSIONS_ACCOUNT_ID: &str = "idx_sessions_account_id";
pub const INDEX_SESSIONS_DEVICE_ID: &str = "idx_sessions_device_id";
pub const INDEX_WEBAUTHN_ACCOUNT_ID: &str = "idx_webauthn_account_id";
pub const INDEX_WEBAUTHN_CHALLENGES_EXPIRES: &str = "idx_webauthn_challenges_expires";
pub const INDEX_BLOBS_ACCOUNT_ID: &str = "idx_blobs_account_id";

/// All required table names defined in the schema.
pub const ALL_TABLES: &[&str] = &[
    TABLE_SCHEMA_MIGRATIONS,
    TABLE_ACCOUNTS,
    TABLE_VAULTS,
    TABLE_ENCRYPTED_OBJECTS,
    TABLE_OBJECT_HISTORY,
    TABLE_PROCESSED_MUTATIONS,
    TABLE_DEVICES,
    TABLE_ACCOUNT_SEQUENCES,
    TABLE_SESSIONS,
    TABLE_WEBAUTHN_CREDENTIALS,
    TABLE_WEBAUTHN_CHALLENGES,
    TABLE_BLOBS,
];

/// All required indexes defined in the schema.
pub const ALL_INDEXES: &[&str] = &[
    INDEX_ENCRYPTED_OBJECTS_ACCOUNT_SEQ,
    INDEX_OBJECT_HISTORY_ACCOUNT_SEQ,
    INDEX_PROCESSED_MUTATIONS_ACCOUNT_OBJECT,
    INDEX_DEVICES_ACCOUNT_LAST_ACK,
    INDEX_SESSIONS_ACCOUNT_ID,
    INDEX_SESSIONS_DEVICE_ID,
    INDEX_WEBAUTHN_ACCOUNT_ID,
    INDEX_WEBAUTHN_CHALLENGES_EXPIRES,
    INDEX_BLOBS_ACCOUNT_ID,
];

/// Account record in database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRow {
    /// Account unique identifier.
    pub id: Uuid,
    /// Account creation timestamp (RFC 3339 / ISO 8601).
    pub created_at: String,
    /// Account status (e.g. "active", "suspended").
    pub status: String,
}

/// Vault bootstrap record in database.
///
/// In accordance with SEC-001 and SEC-002, this table NEVER contains
/// passphrases, plaintext Vault Keys, or Key Encryption Keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRow {
    /// Owning account ID (1:1 with accounts).
    pub account_id: Uuid,
    /// Cryptographic version (e.g. 1).
    pub crypto_version: i32,
    /// Key derivation algorithm (e.g. "Argon2id").
    pub kdf_algorithm: String,
    /// KDF parameters formatted as JSON.
    pub kdf_params: serde_json::Value,
    /// Salt used during key derivation.
    pub kdf_salt: Vec<u8>,
    /// Wrapped vault key ciphertext and nonce envelope.
    pub wrapped_vault_key: Vec<u8>,
    /// Wrapped vault key encrypted under recovery key.
    pub recovery_wrapped_vault_key: Vec<u8>,
    /// Vault registration timestamp.
    pub created_at: String,
    /// Vault last update timestamp.
    pub updated_at: String,
}

/// Latest revision of an encrypted object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedObjectRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Random stable object identifier.
    pub object_id: Uuid,
    /// Object kind discriminant (Note, Notebook, etc.).
    pub object_kind: i16,
    /// Monotonic per-object revision.
    pub revision: i64,
    /// Monotonic per-account server sequence.
    pub server_seq: i64,
    /// Encrypted envelope format version.
    pub envelope_version: i32,
    /// Encrypted object key bytes.
    pub wrapped_key: Vec<u8>,
    /// Encrypted note content payload bytes.
    pub payload: Vec<u8>,
    /// Deletion tombstone flag.
    pub is_deleted: bool,
    /// Creation timestamp.
    pub created_at: String,
    /// Last update timestamp.
    pub updated_at: String,
}

/// Historical revision of an encrypted object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectHistoryRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Object ID.
    pub object_id: Uuid,
    /// Specific revision number.
    pub revision: i64,
    /// Server sequence at time of revision commit.
    pub server_seq: i64,
    /// Envelope version.
    pub envelope_version: i32,
    /// Encrypted object key bytes.
    pub wrapped_key: Vec<u8>,
    /// Encrypted payload bytes.
    pub payload: Vec<u8>,
    /// Deletion tombstone flag.
    pub is_deleted: bool,
    /// Commit timestamp.
    pub created_at: String,
}

/// Processed mutation record for idempotency enforcement (SEC-007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessedMutationRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Client-provided mutation ID.
    pub mutation_id: Uuid,
    /// Target object ID.
    pub object_id: Uuid,
    /// Resulting object revision, if successful.
    pub resulting_revision: Option<i64>,
    /// Resulting server sequence, if allocated.
    pub resulting_server_seq: Option<i64>,
    /// Cached JSON response body for idempotent replay.
    pub response_body: serde_json::Value,
    /// Processing timestamp.
    pub created_at: String,
    /// 32-byte cryptographic digest of the mutation request payload (ZK-035).
    pub request_hash: Option<Vec<u8>>,
}

/// Device registration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Unique device identifier.
    pub device_id: Uuid,
    /// Optional user-visible device name.
    pub display_name: Option<String>,
    /// Registration timestamp.
    pub created_at: String,
    /// Last activity timestamp.
    pub last_seen: Option<String>,
    /// Highest server sequence acknowledged by this device.
    pub last_ack_server_seq: i64,
    /// Revocation timestamp if revoked.
    pub revoked_at: Option<String>,
}

/// Migration record in schema_migrations table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationRow {
    /// Migration version number.
    pub version: i32,
    /// Migration file name / description.
    pub name: String,
    /// Timestamp when migration was applied.
    pub applied_at: String,
}

/// Account sequence record tracking monotonic server sequence per account (ZK-033).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSequenceRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Current highest allocated sequence number.
    pub current_seq: i64,
    /// Last update timestamp.
    pub updated_at: String,
}

/// Authentication session record in database (ZK-070).
///
/// In accordance with SEC-003, raw tokens are NEVER stored in this table;
/// only 32-byte cryptographic digests (`token_hash`) are persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRow {
    /// Session unique identifier.
    pub session_id: Uuid,
    /// Owning account ID.
    pub account_id: Uuid,
    /// Optional associated device identifier.
    pub device_id: Option<Uuid>,
    /// Cryptographic digest (BLAKE2s) of the bearer token.
    pub token_hash: Vec<u8>,
    /// Optional human-readable label for the session.
    pub display_name: Option<String>,
    /// Session creation timestamp.
    pub created_at: String,
    /// Expiration timestamp, if configured.
    pub expires_at: Option<String>,
    /// Revocation timestamp, if revoked.
    pub revoked_at: Option<String>,
}

/// WebAuthn / Passkey credential record in database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnCredentialRecord {
    /// Opaque credential ID issued by the authenticator.
    pub credential_id: Vec<u8>,
    /// Owning account ID.
    pub account_id: Uuid,
    /// Public key bytes.
    pub public_key: Vec<u8>,
    /// Monotonically increasing signature counter.
    pub sign_count: u64,
    /// Optional associated device identifier.
    pub device_id: Option<Uuid>,
    /// Optional human-readable name (e.g. "MacBook Touch ID").
    pub display_name: Option<String>,
    /// Credential registration timestamp.
    pub created_at: String,
    /// Timestamp of most recent authentication.
    pub last_used_at: Option<String>,
}

/// WebAuthn registration or login challenge record in database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnChallengeRecord {
    /// Challenge unique identifier.
    pub challenge_id: Uuid,
    /// Cryptographic challenge bytes.
    pub challenge: Vec<u8>,
    /// Associated account ID (if known).
    pub account_id: Option<Uuid>,
    /// Purpose: "register" or "login".
    pub purpose: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Expiration timestamp.
    pub expires_at: String,
}

/// Ciphertext blob record in database (ZK-082).
///
/// In accordance with SEC-001, SEC-002, and SEC-003:
/// - Contains ONLY opaque ciphertext data and size metadata.
/// - NEVER contains note plaintext, attachment filenames, or MIME types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRow {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Opaque blob identifier.
    pub blob_id: String,
    /// Size in bytes.
    pub size: i64,
    /// Opaque ciphertext bytes.
    pub data: Vec<u8>,
    /// Creation timestamp.
    pub created_at: String,
    /// Last update timestamp.
    pub updated_at: String,
}

/// Verifies that all expected tables and indexes exist in the connected database.
pub fn verify_database_schema(conn: &Connection) -> Result<(), DbError> {
    for table in ALL_TABLES {
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Err(DbError::SchemaVerificationFailed(format!(
                "required table '{table}' is missing from database"
            )));
        }
    }

    for index in ALL_INDEXES {
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
            [index],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Err(DbError::SchemaVerificationFailed(format!(
                "required index '{index}' is missing from database"
            )));
        }
    }

    Ok(())
}
