//! Durable pending mutation queue for offline-first synchronization (ZK-041).
//!
//! In accordance with SEC-001, SEC-006, SEC-007, and SEC-009:
//! - Local edits generate unique mutation IDs (UUID v4) for idempotent replay protection.
//! - Base revisions (`expected_revision`) are recorded at the time of edit to support CAS writes.
//! - Base encrypted envelopes are preserved in [`BaseVersionStore`] for three-way conflict merge.
//! - Mutations survive process restarts by persisting to durable local storage ([`MutationStore`]).
//! - A pending mutation is removed from the queue ONLY AFTER its accepted result has been
//!   durably persisted to local object storage.

use std::fmt;
use uuid::Uuid;
use zk_core::time::now_utc_rfc3339;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_storage::error::StorageError;
use zk_storage::models::{MutationStatus, MutationType, PendingMutation, StoredEncryptedObject};
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};

/// Errors that can occur during queue operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// Underlying storage backend error.
    Storage(StorageError),
    /// Mutation or target object was not found.
    NotFound(String),
    /// Invalid state transition or invalid operation.
    InvalidState(String),
    /// Invariant validation failure (e.g. mismatched object ID).
    Validation(String),
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "queue storage error: {err}"),
            Self::NotFound(msg) => write!(f, "queue entity not found: {msg}"),
            Self::InvalidState(msg) => write!(f, "invalid queue state: {msg}"),
            Self::Validation(msg) => write!(f, "queue validation error: {msg}"),
        }
    }
}

impl std::error::Error for QueueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

impl From<StorageError> for QueueError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

/// A durable queue managing pending mutations for offline multi-device sync.
#[derive(Debug, Clone)]
pub struct PendingMutationQueue<S> {
    storage: S,
}

impl<S> PendingMutationQueue<S>
where
    S: MutationStore + ObjectStore + BaseVersionStore,
{
    /// Creates a new [`PendingMutationQueue`] wrapping the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Enqueues an upsert (create or edit) mutation.
    ///
    /// Generates a fresh random UUID v4 `mutation_id`, records the base `expected_revision`,
    /// retains the current envelope as base version if available, and persists the mutation.
    pub fn enqueue_upsert(
        &self,
        object_id: &str,
        object_kind: u16,
        expected_revision: u64,
        envelope: EncryptedEnvelope,
    ) -> Result<PendingMutation, QueueError> {
        if envelope.object_id != object_id {
            return Err(QueueError::Validation(format!(
                "envelope object_id '{}' does not match target object_id '{object_id}'",
                envelope.object_id
            )));
        }

        // If the object already exists locally, preserve its current envelope as the base version
        // for three-way conflict merge at this expected revision.
        if let Some(current_obj) = self.storage.get_object(object_id)? {
            if current_obj.revision == expected_revision {
                self.storage.put_base_version(
                    object_id,
                    expected_revision,
                    &current_obj.envelope,
                )?;
            }
        }

        let mutation_id = Uuid::new_v4().to_string();
        let now = now_utc_rfc3339();

        let mutation = PendingMutation {
            mutation_id,
            object_id: object_id.to_string(),
            expected_revision,
            object_kind,
            mutation_type: MutationType::Upsert,
            envelope,
            created_at: now,
            retry_count: 0,
            status: MutationStatus::Pending,
        };

        self.storage.enqueue_mutation(&mutation)?;
        Ok(mutation)
    }

    /// Enqueues a delete (tombstone) mutation.
    ///
    /// Generates a fresh random UUID v4 `mutation_id`, records the base `expected_revision`,
    /// and persists the deletion mutation.
    pub fn enqueue_delete(
        &self,
        object_id: &str,
        object_kind: u16,
        expected_revision: u64,
        envelope: EncryptedEnvelope,
    ) -> Result<PendingMutation, QueueError> {
        if envelope.object_id != object_id {
            return Err(QueueError::Validation(format!(
                "envelope object_id '{}' does not match target object_id '{object_id}'",
                envelope.object_id
            )));
        }

        if let Some(current_obj) = self.storage.get_object(object_id)? {
            if current_obj.revision == expected_revision {
                self.storage.put_base_version(
                    object_id,
                    expected_revision,
                    &current_obj.envelope,
                )?;
            }
        }

        let mutation_id = Uuid::new_v4().to_string();
        let now = now_utc_rfc3339();

        let mutation = PendingMutation {
            mutation_id,
            object_id: object_id.to_string(),
            expected_revision,
            object_kind,
            mutation_type: MutationType::Delete,
            envelope,
            created_at: now,
            retry_count: 0,
            status: MutationStatus::Pending,
        };

        self.storage.enqueue_mutation(&mutation)?;
        Ok(mutation)
    }

    /// Enqueues a local note edit or creation, automatically determining the base revision
    /// from the currently stored local object.
    ///
    /// - If the note does not exist locally, base revision is recorded as 0.
    /// - If the note exists locally, base revision is recorded as its current revision,
    ///   and its current envelope is durably recorded into [`BaseVersionStore`].
    pub fn enqueue_local_note_upsert(
        &self,
        object_id: &str,
        envelope: EncryptedEnvelope,
    ) -> Result<PendingMutation, QueueError> {
        let expected_revision = match self.storage.get_object(object_id)? {
            Some(obj) => {
                self.storage
                    .put_base_version(object_id, obj.revision, &obj.envelope)?;
                obj.revision
            }
            None => 0,
        };

        self.enqueue_upsert(object_id, OBJECT_KIND_NOTE, expected_revision, envelope)
    }

    /// Enqueues a local note deletion (tombstone), verifying the object exists and recording
    /// its base revision.
    pub fn enqueue_local_note_delete(
        &self,
        object_id: &str,
        tombstone_envelope: EncryptedEnvelope,
    ) -> Result<PendingMutation, QueueError> {
        let expected_revision = match self.storage.get_object(object_id)? {
            Some(obj) => {
                self.storage
                    .put_base_version(object_id, obj.revision, &obj.envelope)?;
                obj.revision
            }
            None => {
                return Err(QueueError::NotFound(format!(
                    "cannot delete non-existent object '{object_id}'"
                )))
            }
        };

        self.enqueue_delete(
            object_id,
            OBJECT_KIND_NOTE,
            expected_revision,
            tombstone_envelope,
        )
    }

    /// Retrieves the encrypted base envelope for an object at a specific revision (ZK-050).
    pub fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, QueueError> {
        let envelope = self.storage.get_base_version(object_id, revision)?;
        Ok(envelope)
    }

    /// Retrieves the base encrypted envelope associated with a pending mutation (ZK-050).
    ///
    /// If `mutation.expected_revision == 0` (object creation), returns `Ok(None)`.
    /// Otherwise, fetches the base version at `mutation.expected_revision` from [`BaseVersionStore`].
    pub fn get_base_version_for_mutation(
        &self,
        mutation: &PendingMutation,
    ) -> Result<Option<EncryptedEnvelope>, QueueError> {
        if mutation.expected_revision == 0 {
            return Ok(None);
        }
        self.get_base_version(&mutation.object_id, mutation.expected_revision)
    }

    /// Stores an explicit base encrypted envelope for an object at a specific revision (ZK-050).
    pub fn store_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), QueueError> {
        self.storage
            .put_base_version(object_id, revision, envelope)?;
        Ok(())
    }

    /// Retrieves a pending mutation by its unique ID.
    pub fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, QueueError> {
        let mutation = self.storage.get_mutation(mutation_id)?;
        Ok(mutation)
    }

    /// Lists all pending mutations in ascending order of creation time.
    pub fn list_pending(&self) -> Result<Vec<PendingMutation>, QueueError> {
        let list = self.storage.list_pending_mutations()?;
        Ok(list)
    }

    /// Peeks at the next pending mutation ready for synchronization.
    pub fn peek_next(&self) -> Result<Option<PendingMutation>, QueueError> {
        let list = self.list_pending()?;
        Ok(list.into_iter().next())
    }

    /// Returns the total number of pending mutations in the queue.
    pub fn pending_count(&self) -> Result<usize, QueueError> {
        let count = self.storage.pending_mutation_count()?;
        Ok(count)
    }

    /// Lists all pending mutations targeting a specific object.
    pub fn list_for_object(&self, object_id: &str) -> Result<Vec<PendingMutation>, QueueError> {
        let list = self.storage.list_mutations_for_object(object_id)?;
        Ok(list)
    }

    /// Marks a pending mutation as currently in-flight and increments its retry counter.
    pub fn mark_in_flight(&self, mutation_id: &str) -> Result<(), QueueError> {
        let mutation = self
            .storage
            .get_mutation(mutation_id)?
            .ok_or_else(|| QueueError::NotFound(format!("mutation '{mutation_id}' not found")))?;

        self.storage.update_mutation_status(
            mutation_id,
            MutationStatus::InFlight,
            mutation.retry_count.saturating_add(1),
        )?;
        Ok(())
    }

    /// Resets an in-flight mutation back to pending status (e.g. after a transient network failure).
    pub fn mark_pending(&self, mutation_id: &str) -> Result<(), QueueError> {
        let mutation = self
            .storage
            .get_mutation(mutation_id)?
            .ok_or_else(|| QueueError::NotFound(format!("mutation '{mutation_id}' not found")))?;

        self.storage.update_mutation_status(
            mutation_id,
            MutationStatus::Pending,
            mutation.retry_count,
        )?;
        Ok(())
    }

    /// Marks a mutation as failed (e.g. unrecoverable conflict or max retries exceeded).
    pub fn mark_failed(&self, mutation_id: &str) -> Result<(), QueueError> {
        let mutation = self
            .storage
            .get_mutation(mutation_id)?
            .ok_or_else(|| QueueError::NotFound(format!("mutation '{mutation_id}' not found")))?;

        self.storage.update_mutation_status(
            mutation_id,
            MutationStatus::Failed,
            mutation.retry_count,
        )?;
        Ok(())
    }

    /// Resets all mutations currently stuck in `InFlight` status back to `Pending`.
    ///
    /// This is invoked upon process restart to ensure that any push that was interrupted
    /// by a process crash or abnormal termination will be safely retried using the exact
    /// same mutation ID (enforcing SEC-007 idempotency).
    pub fn reset_in_flight(&self) -> Result<usize, QueueError> {
        let mutations = self.storage.list_pending_mutations()?;
        let mut reset_count = 0;

        for m in mutations {
            if m.status == MutationStatus::InFlight {
                self.storage.update_mutation_status(
                    &m.mutation_id,
                    MutationStatus::Pending,
                    m.retry_count,
                )?;
                reset_count += 1;
            }
        }

        Ok(reset_count)
    }

    /// Removes a mutation from the queue ONLY AFTER its accepted result has been
    /// durably persisted to local object storage.
    ///
    /// In accordance with the acceptance criteria:
    /// 1. Verifies the pending mutation exists in the queue.
    /// 2. Durably updates the local object store with `accepted_revision`, `server_seq`,
    ///    tombstone status, and the accepted envelope.
    /// 3. ONLY IF the local object store write succeeds, deletes the mutation from the queue.
    /// 4. Prunes base versions older than the accepted revision.
    pub fn acknowledge_accepted(
        &self,
        mutation_id: &str,
        accepted_revision: u64,
        server_seq: u64,
    ) -> Result<StoredEncryptedObject, QueueError> {
        let mutation = self
            .storage
            .get_mutation(mutation_id)?
            .ok_or_else(|| QueueError::NotFound(format!("mutation '{mutation_id}' not found")))?;

        let is_deleted = mutation.mutation_type == MutationType::Delete;
        let stored_obj = StoredEncryptedObject {
            object_id: mutation.object_id.clone(),
            object_kind: mutation.object_kind,
            revision: accepted_revision,
            server_seq,
            is_deleted,
            envelope: mutation.envelope.clone(),
            updated_at: now_utc_rfc3339(),
        };

        // Step 1: Durably write accepted object state to ObjectStore.
        // If this fails, the mutation is NOT removed and remains queued for retry.
        self.storage.put_object(&stored_obj)?;

        // Step 2: Remove mutation from queue only after durable local storage write succeeded.
        self.storage.remove_mutation(mutation_id)?;

        // Step 3: Prune superseded base versions up to the accepted revision.
        let _ = self
            .storage
            .prune_base_versions(&mutation.object_id, accepted_revision);

        Ok(stored_obj)
    }

    /// Removes a mutation directly from the queue (e.g. if explicitly discarded or superseded).
    pub fn remove_mutation(&self, mutation_id: &str) -> Result<bool, QueueError> {
        let removed = self.storage.remove_mutation(mutation_id)?;
        Ok(removed)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
    use zk_protocol::envelope::{
        EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer,
    };
    use zk_storage::memory::MemoryStorage;
    use zk_storage::sqlite::SqliteStorage;

    fn sample_envelope(object_id: &str) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: object_id.to_string(),
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

    #[test]
    fn test_local_edits_generate_mutation_ids_and_record_base_revision() {
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage);

        let obj_id = "test-note-1";
        let env1 = sample_envelope(obj_id);

        // 1. Initial creation generates unique mutation ID and records base revision 0
        let mut1 = queue
            .enqueue_local_note_upsert(obj_id, env1.clone())
            .expect("enqueue initial creation");
        assert!(!mut1.mutation_id.is_empty());
        assert_eq!(mut1.object_id, obj_id);
        assert_eq!(mut1.expected_revision, 0);
        assert_eq!(mut1.mutation_type, MutationType::Upsert);
        assert_eq!(mut1.status, MutationStatus::Pending);
        assert_eq!(mut1.retry_count, 0);

        // Acknowledge accepted creation at revision 1, sequence 10
        queue
            .acknowledge_accepted(&mut1.mutation_id, 1, 10)
            .expect("acknowledge creation");

        // 2. Subsequent edit records base revision 1 and generates a fresh mutation ID
        let env2 = sample_envelope(obj_id);
        let mut2 = queue
            .enqueue_local_note_upsert(obj_id, env2.clone())
            .expect("enqueue edit");
        assert_ne!(mut1.mutation_id, mut2.mutation_id);
        assert_eq!(mut2.expected_revision, 1);

        // Verify base version envelope was recorded in BaseVersionStore at revision 1
        let base_ver = queue
            .storage()
            .get_base_version(obj_id, 1)
            .expect("query base version")
            .expect("base version must exist");
        assert_eq!(base_ver.object_id, obj_id);
    }

    #[test]
    fn test_mutation_removed_only_after_durable_accepted_result() {
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage);

        let obj_id = "test-note-2";
        let env = sample_envelope(obj_id);

        let mut1 = queue
            .enqueue_local_note_upsert(obj_id, env)
            .expect("enqueue");

        assert_eq!(queue.pending_count().unwrap(), 1);

        // Acknowledge accepted result
        let stored_obj = queue
            .acknowledge_accepted(&mut1.mutation_id, 1, 42)
            .expect("acknowledge");
        assert_eq!(stored_obj.revision, 1);
        assert_eq!(stored_obj.server_seq, 42);

        // Mutation removed only after durable store
        assert_eq!(queue.pending_count().unwrap(), 0);
        let retrieved = queue.get_mutation(&mut1.mutation_id).unwrap();
        assert!(retrieved.is_none());

        // Object exists in local object store
        let local = queue.storage().get_object(obj_id).unwrap().unwrap();
        assert_eq!(local.revision, 1);
        assert_eq!(local.server_seq, 42);
    }

    #[test]
    fn test_mutations_survive_process_restart_with_sqlite() {
        let mut db_path = std::env::temp_dir();
        db_path.push(format!("zk_test_queue_restart_{}.db", Uuid::new_v4()));
        let _ = std::fs::remove_file(&db_path);

        let obj_id = "note-restart-test";
        let mutation_id_saved: String;

        // Process lifecycle 1: open storage, enqueue mutation, then drop
        {
            let storage = SqliteStorage::open(&db_path).expect("open sqlite storage");
            let queue = PendingMutationQueue::new(storage);

            let env = sample_envelope(obj_id);
            let mutation = queue
                .enqueue_local_note_upsert(obj_id, env)
                .expect("enqueue mutation");

            mutation_id_saved = mutation.mutation_id.clone();
            assert_eq!(queue.pending_count().unwrap(), 1);
            // Drop storage and queue (simulating process exit)
        }

        // Process lifecycle 2: reopen database from disk, verify mutation survived
        {
            let storage = SqliteStorage::open(&db_path).expect("reopen sqlite storage");
            let queue = PendingMutationQueue::new(storage);

            assert_eq!(queue.pending_count().unwrap(), 1);
            let restored_mutation = queue
                .get_mutation(&mutation_id_saved)
                .expect("get restored mutation")
                .expect("mutation must exist");

            assert_eq!(restored_mutation.mutation_id, mutation_id_saved);
            assert_eq!(restored_mutation.object_id, obj_id);
            assert_eq!(restored_mutation.expected_revision, 0);
            assert_eq!(restored_mutation.status, MutationStatus::Pending);

            // Acknowledge mutation in second lifecycle
            let stored = queue
                .acknowledge_accepted(&mutation_id_saved, 1, 100)
                .expect("acknowledge restored mutation");
            assert_eq!(stored.revision, 1);
            assert_eq!(queue.pending_count().unwrap(), 0);
        }

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_reset_in_flight_on_startup_preserves_idempotency_id() {
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage);

        let env = sample_envelope("note-in-flight");
        let mutation = queue
            .enqueue_local_note_upsert("note-in-flight", env)
            .unwrap();

        // Mark in-flight
        queue.mark_in_flight(&mutation.mutation_id).unwrap();
        let in_flight = queue.get_mutation(&mutation.mutation_id).unwrap().unwrap();
        assert_eq!(in_flight.status, MutationStatus::InFlight);
        assert_eq!(in_flight.retry_count, 1);

        // Reset in-flight (simulating restart after lost response or crash)
        let reset_count = queue.reset_in_flight().unwrap();
        assert_eq!(reset_count, 1);

        let pending_again = queue.get_mutation(&mutation.mutation_id).unwrap().unwrap();
        assert_eq!(pending_again.status, MutationStatus::Pending);
        // Preserves exact same mutation ID for idempotent retry!
        assert_eq!(pending_again.mutation_id, mutation.mutation_id);
        assert_eq!(pending_again.retry_count, 1);
    }

    #[test]
    fn test_enqueue_delete_records_tombstone_and_base_revision() {
        let storage = MemoryStorage::new();
        let queue = PendingMutationQueue::new(storage);

        let obj_id = "note-to-delete";
        let env = sample_envelope(obj_id);

        // First create note at revision 1
        let mut1 = queue
            .enqueue_local_note_upsert(obj_id, env.clone())
            .unwrap();
        queue.acknowledge_accepted(&mut1.mutation_id, 1, 5).unwrap();

        // Delete note
        let del_mut = queue.enqueue_local_note_delete(obj_id, env).unwrap();
        assert_eq!(del_mut.expected_revision, 1);
        assert_eq!(del_mut.mutation_type, MutationType::Delete);

        // Acknowledge delete
        let stored_tombstone = queue
            .acknowledge_accepted(&del_mut.mutation_id, 2, 6)
            .unwrap();
        assert!(stored_tombstone.is_deleted);
        assert_eq!(stored_tombstone.revision, 2);
        assert_eq!(stored_tombstone.server_seq, 6);
    }
}
