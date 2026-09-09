//! Push pending mutations engine with CAS revision verification and conflict recovery (ZK-044).
//!
//! In accordance with SEC-006, SEC-007, SEC-009, and MASTER_SPEC.md § 9:
//! - Every mutation pushed to the server supplies its `expected_revision` for CAS safety.
//! - Accepted writes durably update local object storage and clear the mutation from the queue.
//! - Lost-response retries re-send the EXACT SAME `mutation_id` for server-side idempotency.
//! - Server revision conflicts (HTTP 409) LEAVE THE LOCAL MUTATION RECOVERABLE in the queue
//!   with its base revision, local edited envelope, and remote conflicting envelope preserved
//!   for three-way merge resolution (no silent data loss).

use crate::adapter::SyncServerAdapter;
use crate::error::SyncNetworkError;
use crate::queue::{PendingMutationQueue, QueueError};
use std::fmt;
use zk_protocol::sync::{ConflictResponse, PushRequest};
use zk_storage::error::StorageError;
use zk_storage::models::{MutationStatus, MutationType, PendingMutation};
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};

/// Configuration options for pushing pending mutations.
#[derive(Debug, Clone, Default)]
pub struct PushOptions {
    /// Maximum number of pending mutations to push in this cycle (None for all).
    pub max_mutations: Option<usize>,
    /// Whether to halt the push cycle immediately if a conflict is encountered.
    pub stop_on_conflict: bool,
}

/// A successfully accepted mutation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushItemSuccess {
    /// Identifier of the logical mutation that succeeded.
    pub mutation_id: String,
    /// Target object identifier.
    pub object_id: String,
    /// New revision accepted by server.
    pub revision: u64,
    /// Server sequence allocated to this mutation.
    pub server_seq: u64,
}

/// A conflict encountered during push, preserving the local mutation and remote conflict info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushItemConflict {
    /// The local pending mutation that was rejected by the server (retained in queue).
    pub mutation: PendingMutation,
    /// The conflict details returned by the server (expected vs current revision & envelope).
    pub conflict: ConflictResponse,
}

/// Comprehensive summary report of a push synchronization cycle.
#[derive(Debug, Clone, Default)]
pub struct PushReport {
    /// Total mutations attempted during this cycle.
    pub total_attempted: usize,
    /// Mutations accepted by the server and cleared from the queue.
    pub accepted: Vec<PushItemSuccess>,
    /// Mutations rejected due to revision conflicts, retained for resolution.
    pub conflicts: Vec<PushItemConflict>,
    /// Mutations that failed due to transient network issues, retained for retry.
    pub transient_failures: usize,
}

/// Errors that can occur during a push synchronization cycle.
#[derive(Debug)]
pub enum PushError {
    /// Network communication or protocol error.
    Network(SyncNetworkError),
    /// Local pending mutation queue error.
    Queue(QueueError),
    /// Local storage backend error.
    Storage(StorageError),
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(err) => write!(f, "push network error: {err}"),
            Self::Queue(err) => write!(f, "push queue error: {err}"),
            Self::Storage(err) => write!(f, "push storage error: {err}"),
        }
    }
}

impl std::error::Error for PushError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(err) => Some(err),
            Self::Queue(err) => Some(err),
            Self::Storage(err) => Some(err),
        }
    }
}

impl From<SyncNetworkError> for PushError {
    fn from(err: SyncNetworkError) -> Self {
        Self::Network(err)
    }
}

impl From<QueueError> for PushError {
    fn from(err: QueueError) -> Self {
        Self::Queue(err)
    }
}

impl From<StorageError> for PushError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

/// Pushes pending mutations to the server in chronological order.
///
/// Acceptance criteria implemented:
/// 1. `expected_revision` is supplied on every request.
/// 2. Accepted writes durably update local storage and clear the mutation from the queue.
/// 3. Lost-response retries re-send the exact same `mutation_id` (handled idempotently by server).
/// 4. Conflicts leave the local mutation recoverable in the queue (no silent overwrite or data loss).
pub async fn push_pending_changes<A, S>(
    adapter: &A,
    queue: &PendingMutationQueue<S>,
    options: PushOptions,
) -> Result<PushReport, PushError>
where
    A: SyncServerAdapter,
    S: MutationStore + ObjectStore + BaseVersionStore,
{
    let pending_mutations = queue.list_pending()?;
    let mut report = PushReport::default();

    for mutation in pending_mutations {
        if let Some(max) = options.max_mutations {
            if report.total_attempted >= max {
                break;
            }
        }

        // Only process mutations ready for transmission (Pending or previously InFlight retry)
        if mutation.status != MutationStatus::Pending && mutation.status != MutationStatus::InFlight
        {
            continue;
        }

        report.total_attempted += 1;

        // Requirement 1: expected_revision supplied on every request
        let push_req = PushRequest {
            mutation_id: mutation.mutation_id.clone(),
            object_id: mutation.object_id.clone(),
            expected_revision: mutation.expected_revision,
            object_kind: mutation.object_kind,
            envelope: mutation.envelope.clone(),
            is_deleted: mutation.mutation_type == MutationType::Delete,
        };

        // Mark in-flight locally (increments retry count)
        queue.mark_in_flight(&mutation.mutation_id)?;

        // Requirement 3: uses same mutation_id for idempotent retry
        match adapter.push_mutation(&push_req).await {
            Ok(resp) => {
                // Requirement 2: accepted writes clear queue only after durable local persistence
                queue.acknowledge_accepted(
                    &mutation.mutation_id,
                    resp.revision,
                    resp.server_seq,
                )?;

                report.accepted.push(PushItemSuccess {
                    mutation_id: mutation.mutation_id,
                    object_id: resp.object_id,
                    revision: resp.revision,
                    server_seq: resp.server_seq,
                });
            }
            Err(SyncNetworkError::Conflict(conflict)) => {
                // Requirement 4: conflict leaves local mutation recoverable
                // Reset status to Pending (or keep in queue) so local edits are NOT discarded
                let _ = queue.mark_pending(&mutation.mutation_id);

                report.conflicts.push(PushItemConflict {
                    mutation,
                    conflict: *conflict,
                });

                if options.stop_on_conflict {
                    break;
                }
            }
            Err(SyncNetworkError::ConnectionFailed(_))
            | Err(SyncNetworkError::ServerError { .. }) => {
                // Transient transport failure: reset to Pending so next sync or retry
                // sends the EXACT SAME mutation_id (SEC-007 retry idempotency)
                let _ = queue.mark_pending(&mutation.mutation_id);
                report.transient_failures += 1;
            }
            Err(fatal) => {
                // Mark failed locally and propagate fatal error (e.g. Unauthorized, ForbiddenPlaintext)
                let _ = queue.mark_failed(&mutation.mutation_id);
                return Err(PushError::Network(fatal));
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapter::MockSyncAdapter;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
    use zk_protocol::envelope::{
        EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer,
    };
    use zk_storage::memory::MemoryStorage;

    fn sample_envelope(obj_id: &str) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
                ciphertext: "ZW5jcnlwdGVkLXBheWxvYWQ=".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_push_accepted_writes_clear_queue() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage.clone());

        // Enqueue 2 mutations locally
        let m1 = queue
            .enqueue_local_note_upsert("note-1", sample_envelope("note-1"))
            .unwrap();
        let m2 = queue
            .enqueue_local_note_upsert("note-2", sample_envelope("note-2"))
            .unwrap();

        assert_eq!(queue.pending_count().unwrap(), 2);

        // Push pending changes
        let report = push_pending_changes(&adapter, &queue, PushOptions::default())
            .await
            .expect("push succeeds");

        assert_eq!(report.total_attempted, 2);
        assert_eq!(report.accepted.len(), 2);
        assert!(report.conflicts.is_empty());

        // Accepted writes cleared queue
        assert_eq!(queue.pending_count().unwrap(), 0);
        assert!(queue.get_mutation(&m1.mutation_id).unwrap().is_none());
        assert!(queue.get_mutation(&m2.mutation_id).unwrap().is_none());

        // Objects durably in local object store
        let obj1 = storage.get_object("note-1").unwrap().unwrap();
        assert_eq!(obj1.revision, 1);
        assert_eq!(obj1.server_seq, 1);
    }

    #[tokio::test]
    async fn test_lost_response_retry_uses_same_mutation_id() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage.clone());

        let mutation = queue
            .enqueue_local_note_upsert("note-retry", sample_envelope("note-retry"))
            .unwrap();
        let saved_mut_id = mutation.mutation_id.clone();

        // 1. Simulate server accepting mutation on first attempt
        let push_req = PushRequest {
            mutation_id: saved_mut_id.clone(),
            object_id: "note-retry".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: sample_envelope("note-retry"),
            is_deleted: false,
        };
        adapter.push_mutation(&push_req).await.unwrap();

        // But suppose response was lost: the mutation is still in queue locally!
        assert_eq!(queue.pending_count().unwrap(), 1);

        // 2. Retry pushing pending changes: must use the SAME mutation_id!
        let report = push_pending_changes(&adapter, &queue, PushOptions::default())
            .await
            .expect("retry succeeds idempotently");

        assert_eq!(report.accepted.len(), 1);
        assert_eq!(report.accepted[0].mutation_id, saved_mut_id);
        assert_eq!(report.accepted[0].revision, 1);
        assert_eq!(report.accepted[0].server_seq, 1);

        // Queue is now cleared without creating a second revision
        assert_eq!(queue.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_conflict_leaves_local_mutation_recoverable() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage.clone());

        let obj_id = "note-conflicted";

        // Remote server already has revision 1 from another client
        let remote_req = PushRequest {
            mutation_id: "remote-mut".to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: sample_envelope(obj_id),
            is_deleted: false,
        };
        adapter.push_mutation(&remote_req).await.unwrap();

        // Local client edited based on revision 0 (stale)
        let local_mutation = queue
            .enqueue_local_note_upsert(obj_id, sample_envelope(obj_id))
            .unwrap();
        assert_eq!(local_mutation.expected_revision, 0);

        // Push: encounters conflict (expected 0, current 1)
        let report = push_pending_changes(&adapter, &queue, PushOptions::default())
            .await
            .expect("push finishes");

        assert_eq!(report.accepted.len(), 0);
        assert_eq!(report.conflicts.len(), 1);

        let conflict_item = &report.conflicts[0];
        assert_eq!(conflict_item.conflict.expected_revision, 0);
        assert_eq!(conflict_item.conflict.current_revision, 1);

        // CRITICAL INVARIANT: Local mutation MUST STILL BE IN QUEUE (recoverable)!
        assert_eq!(queue.pending_count().unwrap(), 1);
        let recovered = queue
            .get_mutation(&local_mutation.mutation_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.object_id, obj_id);
        assert_eq!(recovered.expected_revision, 0);
    }
}
