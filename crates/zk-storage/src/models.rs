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

/// A persistent conflict record capturing divergent concurrent modifications (ZK-053).
///
/// In accordance with MASTER_SPEC.md § 10.3 and SEC-009:
/// - BASE, LOCAL, REMOTE, and CANDIDATE versions are stored strictly as encrypted envelopes.
/// - Contains no plaintext title, body, or tags columns.
/// - Persisted across application restarts.
/// - Contains sufficient metadata to retry push or apply resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// Unique identifier for this conflict record (UUID v4).
    pub conflict_id: String,
    /// Target object identifier.
    pub object_id: String,
    /// Protocol object kind discriminant (e.g. 1 = Note).
    pub object_kind: u16,
    /// Revision of the base object prior to divergent edits.
    pub base_revision: u64,
    /// Revision of the remote object that diverged on the server.
    pub remote_revision: u64,
    /// Encrypted envelope of the BASE revision (if available).
    pub base_envelope: Option<EncryptedEnvelope>,
    /// Encrypted envelope of the LOCAL edit.
    pub local_envelope: EncryptedEnvelope,
    /// Encrypted envelope of the REMOTE revision fetched from the server.
    pub remote_envelope: EncryptedEnvelope,
    /// Encrypted envelope of the generated 3-way merge candidate (with diff3 conflict markers if unmerged).
    pub candidate_envelope: Option<EncryptedEnvelope>,
    /// Whether this conflict has been resolved by the user or resolution policy.
    pub resolved: bool,
    /// Whether the conflicting remote version was deleted (tombstone).
    #[serde(default)]
    pub remote_is_deleted: bool,
    /// Whether the local mutation was a deletion tombstone.
    #[serde(default)]
    pub local_is_deleted: bool,
    /// Timestamp when this conflict record was created (RFC 3339 UTC).
    pub created_at: String,
    /// Timestamp when this conflict record was marked resolved, if resolved (RFC 3339 UTC).
    pub resolved_at: Option<String>,
}

impl ConflictRecord {
    /// Creates a new unresolved conflict record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conflict_id: impl Into<String>,
        object_id: impl Into<String>,
        object_kind: u16,
        base_revision: u64,
        remote_revision: u64,
        base_envelope: Option<EncryptedEnvelope>,
        local_envelope: EncryptedEnvelope,
        remote_envelope: EncryptedEnvelope,
        candidate_envelope: Option<EncryptedEnvelope>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            conflict_id: conflict_id.into(),
            object_id: object_id.into(),
            object_kind,
            base_revision,
            remote_revision,
            base_envelope,
            local_envelope,
            remote_envelope,
            candidate_envelope,
            resolved: false,
            remote_is_deleted: false,
            local_is_deleted: false,
            created_at: created_at.into(),
            resolved_at: None,
        }
    }

    /// Sets deletion flags for local and remote versions.
    pub fn with_deletion_flags(mut self, local_is_deleted: bool, remote_is_deleted: bool) -> Self {
        self.local_is_deleted = local_is_deleted;
        self.remote_is_deleted = remote_is_deleted;
        self
    }

    /// Whether this conflict involves a deletion on either remote or local side.
    pub fn is_deletion_conflict(&self) -> bool {
        self.remote_is_deleted || self.local_is_deleted
    }

    /// Whether remote deleted the note while local edited it.
    pub fn is_delete_vs_edit(&self) -> bool {
        self.remote_is_deleted && !self.local_is_deleted
    }

    /// Whether local deleted the note while remote edited it.
    pub fn is_edit_vs_delete(&self) -> bool {
        self.local_is_deleted && !self.remote_is_deleted
    }

    /// Returns a human-readable description of the conflict type.
    pub fn conflict_type_str(&self) -> &'static str {
        if self.remote_is_deleted && !self.local_is_deleted {
            "Delete-vs-Edit"
        } else if self.local_is_deleted && !self.remote_is_deleted {
            "Edit-vs-Delete"
        } else if self.local_is_deleted && self.remote_is_deleted {
            "Delete-vs-Delete"
        } else {
            "Edit-vs-Edit"
        }
    }
}
