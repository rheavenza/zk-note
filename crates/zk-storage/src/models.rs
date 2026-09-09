//! Storage models for encrypted objects, pending mutations, base revisions, and sync state.

use serde::{Deserialize, Serialize};
use zk_protocol::envelope::EncryptedEnvelope;

/// Stored local encrypted object representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEncryptedObject {
    /// Stable object identifier (UUID v4).
    pub object_id: String,
    /// Protocol object kind discriminant (e.g. 1 = Note).
    pub object_kind: u16,
    /// Current object revision (monotonic counter).
    pub revision: u64,
    /// Server sequence at which this revision was accepted, or 0 if uncommitted.
    pub server_seq: u64,
    /// True if this object has been marked as deleted (tombstone).
    pub is_deleted: bool,
    /// Encrypted envelope containing wrapped key and ciphertext payload.
    pub envelope: EncryptedEnvelope,
    /// Last update timestamp in RFC 3339 UTC format.
    pub updated_at: String,
}

/// Query filter for listing stored encrypted objects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectFilter {
    /// If specified, limits results to this protocol kind.
    pub kind: Option<u16>,
    /// Whether to include deleted objects (tombstones). Defaults to `false`.
    pub include_deleted: bool,
}

impl ObjectFilter {
    /// Creates a filter that returns only active (non-deleted) objects of any kind.
    #[must_use]
    pub fn active_only() -> Self {
        Self {
            kind: None,
            include_deleted: false,
        }
    }

    /// Creates a filter for a specific object kind, excluding deleted objects.
    #[must_use]
    pub fn for_kind(kind: u16) -> Self {
        Self {
            kind: Some(kind),
            include_deleted: false,
        }
    }

    /// Creates a filter that includes both active and deleted objects.
    #[must_use]
    pub fn all() -> Self {
        Self {
            kind: None,
            include_deleted: true,
        }
    }

    /// Sets whether to include deleted objects.
    #[must_use]
    pub fn with_include_deleted(mut self, include_deleted: bool) -> Self {
        self.include_deleted = include_deleted;
        self
    }
}

/// Type of mutation queued for synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationType {
    /// Create or update an encrypted object.
    Upsert,
    /// Mark an object as deleted (tombstone).
    Delete,
}

/// Synchronization lifecycle status of a pending mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationStatus {
    /// Mutation is queued locally and has not yet been pushed.
    Pending,
    /// Mutation is currently being transmitted to the server.
    InFlight,
    /// Mutation encountered an unrecoverable failure or maximum retries exceeded.
    Failed,
}

/// A locally queued mutation awaiting push synchronization with the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMutation {
    /// Random UUID v4 identifying this logical mutation for idempotent retries.
    pub mutation_id: String,
    /// Target object identifier.
    pub object_id: String,
    /// Expected server revision upon which this mutation is based.
    pub expected_revision: u64,
    /// Protocol object kind discriminant.
    pub object_kind: u16,
    /// Type of mutation (Upsert or Delete).
    pub mutation_type: MutationType,
    /// Encrypted object envelope (or tombstone envelope).
    pub envelope: EncryptedEnvelope,
    /// Local timestamp when the mutation was enqueued.
    pub created_at: String,
    /// Number of push attempts made for this mutation.
    pub retry_count: u32,
    /// Current synchronization status.
    pub status: MutationStatus,
}

/// Base encrypted envelope retained for three-way conflict merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseVersion {
    /// Target object identifier.
    pub object_id: String,
    /// The base revision that was decrypted when the user started editing.
    pub revision: u64,
    /// Encrypted envelope of the base revision.
    pub envelope: EncryptedEnvelope,
}

/// Local synchronization cursor and device state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Highest contiguous server sequence processed locally.
    pub sync_cursor: u64,
    /// Last successful sync completion timestamp in RFC 3339 UTC format.
    pub last_sync_at: Option<String>,
    /// Unique local device identifier.
    pub device_id: Option<String>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            sync_cursor: zk_protocol::constants::INITIAL_SYNC_CURSOR,
            last_sync_at: None,
            device_id: None,
        }
    }
}
