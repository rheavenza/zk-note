//! Synchronization protocol request and response models.

use crate::envelope::EncryptedEnvelope;
use serde::{Deserialize, Serialize};

/// Push mutation request submitted by client (POST /v1/sync/push).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    /// Random UUID v4 idempotency token identifying this logical mutation.
    pub mutation_id: String,
    /// Identifier of the target encrypted object.
    pub object_id: String,
    /// Current revision the client expects (0 for object creation).
    pub expected_revision: u64,
    /// Protocol object kind discriminant.
    pub object_kind: u16,
    /// Encrypted object envelope.
    pub envelope: EncryptedEnvelope,
    /// Whether this mutation is a deletion tombstone (defaults to false).
    #[serde(default)]
    pub is_deleted: bool,
}

/// Successful push response returned by server on accepted mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// Identifier of the target encrypted object.
    pub object_id: String,
    /// Newly allocated object revision (expected_revision + 1).
    pub revision: u64,
    /// Monotonic account-level sequence allocated to this mutation.
    pub server_seq: u64,
}

/// Revision conflict error response when expected_revision != current revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictResponse {
    /// Canonical error code ("REVISION_CONFLICT").
    pub error: String,
    /// Identifier of the conflicted object.
    pub object_id: String,
    /// Revision submitted by client.
    pub expected_revision: u64,
    /// Current revision stored on server.
    pub current_revision: u64,
    /// Server sequence associated with current server revision.
    pub current_server_seq: u64,
    /// Latest encrypted envelope stored on server for client reconciliation.
    pub current_envelope: EncryptedEnvelope,
}

/// Individual object change entry in pull response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectChange {
    /// Sequence number of this change.
    pub server_seq: u64,
    /// Target object identifier.
    pub object_id: String,
    /// Committed revision number.
    pub revision: u64,
    /// Protocol object kind discriminant.
    pub object_kind: u16,
    /// Whether this object is deleted (tombstone).
    pub is_deleted: bool,
    /// Encrypted object envelope (or tombstone envelope).
    pub envelope: EncryptedEnvelope,
}

/// Pull changes response returned by server (GET /v1/sync/changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullChangesResponse {
    /// Ordered list of changes with server_seq > requested cursor.
    pub changes: Vec<ObjectChange>,
    /// Highest server_seq included in this response page.
    pub next_cursor: u64,
    /// Indicates if more changes remain after next_cursor.
    pub has_more: bool,
}

/// Query parameters for pulling changes (GET /v1/sync/changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PullChangesQuery {
    /// Cursor sequence number; changes with server_seq > after are returned.
    #[serde(default)]
    pub after: Option<u64>,
    /// Maximum number of changes to return in one page.
    #[serde(default)]
    pub limit: Option<u32>,
}
