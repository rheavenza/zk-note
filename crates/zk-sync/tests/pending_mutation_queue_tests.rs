//! Integration tests for PendingMutationQueue (ZK-041).
//!
//! Acceptance criteria validated:
//! 1. Local edits generate unique mutation IDs (UUID v4);
//! 2. Mutations survive process restarts;
//! 3. Base revision recorded (`expected_revision`);
//! 4. Mutation removed ONLY AFTER durable accepted result is stored.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_storage::error::StorageError;
use zk_storage::memory::MemoryStorage;
use zk_storage::models::{
    MutationStatus, MutationType, ObjectFilter, PendingMutation, StoredEncryptedObject,
};
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};
use zk_sync::queue::PendingMutationQueue;

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
fn test_local_edits_generate_unique_mutation_ids_and_record_base_revision() {
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage);

    let obj1 = "note-uuid-1";
    let obj2 = "note-uuid-2";

    // 1. First local edit (create note 1) generates fresh mutation ID and records base revision 0
    let m1 = queue
        .enqueue_local_note_upsert(obj1, sample_envelope(obj1))
        .expect("enqueue m1");
    assert!(!m1.mutation_id.is_empty());
    assert!(Uuid::parse_str(&m1.mutation_id).is_ok());
    assert_eq!(m1.expected_revision, 0);

    // 2. Second local edit (create note 2) generates different mutation ID and records base revision 0
    let m2 = queue
        .enqueue_local_note_upsert(obj2, sample_envelope(obj2))
        .expect("enqueue m2");
    assert!(!m2.mutation_id.is_empty());
    assert!(Uuid::parse_str(&m2.mutation_id).is_ok());
    assert_ne!(m1.mutation_id, m2.mutation_id);
    assert_eq!(m2.expected_revision, 0);

    // Acknowledge note 1 accepted at revision 5
    queue
        .acknowledge_accepted(&m1.mutation_id, 5, 20)
        .expect("ack m1");

    // 3. Edit note 1 offline: base revision must be 5
    let m3 = queue
        .enqueue_local_note_upsert(obj1, sample_envelope(obj1))
        .expect("enqueue m3");
    assert_ne!(m3.mutation_id, m1.mutation_id);
    assert_ne!(m3.mutation_id, m2.mutation_id);
    assert_eq!(m3.expected_revision, 5);

    // Verify base version at revision 5 was preserved in BaseVersionStore
    let base_v5 = queue
        .storage()
        .get_base_version(obj1, 5)
        .expect("get base version")
        .expect("base version 5 must exist");
    assert_eq!(base_v5.object_id, obj1);

    // 4. Delete note 2 after acknowledging at revision 1
    queue
        .acknowledge_accepted(&m2.mutation_id, 1, 21)
        .expect("ack m2");
    let m4 = queue
        .enqueue_local_note_delete(obj2, sample_envelope(obj2))
        .expect("enqueue delete m4");
    assert_eq!(m4.expected_revision, 1);
    assert_eq!(m4.mutation_type, MutationType::Delete);
}

#[test]
fn test_mutations_survive_process_restart_with_sqlite() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("zk_test_queue_persistence_{}.db", Uuid::new_v4()));
    let _ = std::fs::remove_file(&db_path);

    let note_a = "note-persisted-a";
    let note_b = "note-persisted-b";
    let mut_a_id: String;
    let mut_b_id: String;

    // Phase 1: Client process runs, queues mutations, marks one in-flight, then exits
    {
        let storage = SqliteStorage::open(&db_path).expect("open sqlite storage");
        let queue = PendingMutationQueue::new(storage);

        let m_a = queue
            .enqueue_local_note_upsert(note_a, sample_envelope(note_a))
            .expect("enqueue m_a");
        let m_b = queue
            .enqueue_local_note_upsert(note_b, sample_envelope(note_b))
            .expect("enqueue m_b");

        mut_a_id = m_a.mutation_id;
        mut_b_id = m_b.mutation_id;

        // Mark m_a as in-flight (e.g. was pushed right when power cut occurred)
        queue.mark_in_flight(&mut_a_id).expect("mark in-flight");

        assert_eq!(queue.pending_count().unwrap(), 2);
        // Process drops / crashes
    }

    // Phase 2: Client restarts, reopens database, recovers pending mutations
    {
        let storage = SqliteStorage::open(&db_path).expect("reopen sqlite storage");
        let queue = PendingMutationQueue::new(storage);

        // Verify mutations survived process restart
        assert_eq!(queue.pending_count().unwrap(), 2);

        let retrieved_a = queue.get_mutation(&mut_a_id).unwrap().unwrap();
        assert_eq!(retrieved_a.status, MutationStatus::InFlight);
        assert_eq!(retrieved_a.retry_count, 1);
        assert_eq!(retrieved_a.object_id, note_a);
        assert_eq!(retrieved_a.expected_revision, 0);

        let retrieved_b = queue.get_mutation(&mut_b_id).unwrap().unwrap();
        assert_eq!(retrieved_b.status, MutationStatus::Pending);
        assert_eq!(retrieved_b.object_id, note_b);

        // Reset in-flight mutations on restart
        let reset_count = queue.reset_in_flight().expect("reset in flight");
        assert_eq!(reset_count, 1);

        // Retrying push will use the EXACT SAME mutation_id (SEC-007 retry idempotency)
        let ready_a = queue.get_mutation(&mut_a_id).unwrap().unwrap();
        assert_eq!(ready_a.status, MutationStatus::Pending);
        assert_eq!(ready_a.mutation_id, mut_a_id);

        // Acknowledge accepted for both
        queue.acknowledge_accepted(&mut_a_id, 1, 10).expect("ack a");
        queue.acknowledge_accepted(&mut_b_id, 1, 11).expect("ack b");

        assert_eq!(queue.pending_count().unwrap(), 0);
    }

    let _ = std::fs::remove_file(&db_path);
}

/// A wrapper around MemoryStorage that can simulate a durable write failure during put_object.
#[derive(Debug, Clone)]
struct FaultInjectableStorage {
    inner: MemoryStorage,
    fail_put_object: Arc<AtomicBool>,
}

impl FaultInjectableStorage {
    fn new() -> Self {
        Self {
            inner: MemoryStorage::new(),
            fail_put_object: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_fail_put_object(&self, fail: bool) {
        self.fail_put_object.store(fail, Ordering::SeqCst);
    }
}

impl ObjectStore for FaultInjectableStorage {
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError> {
        self.inner.get_object(object_id)
    }

    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError> {
        if self.fail_put_object.load(Ordering::SeqCst) {
            return Err(StorageError::Backend(
                "simulated disk failure during durable object write".to_string(),
            ));
        }
        self.inner.put_object(object)
    }

    fn mark_deleted(
        &self,
        object_id: &str,
        revision: u64,
        envelope: EncryptedEnvelope,
        updated_at: String,
    ) -> Result<(), StorageError> {
        self.inner
            .mark_deleted(object_id, revision, envelope, updated_at)
    }

    fn list_objects(
        &self,
        filter: &ObjectFilter,
    ) -> Result<Vec<StoredEncryptedObject>, StorageError> {
        self.inner.list_objects(filter)
    }

    fn purge_object(&self, object_id: &str) -> Result<bool, StorageError> {
        self.inner.purge_object(object_id)
    }
}

impl MutationStore for FaultInjectableStorage {
    fn enqueue_mutation(&self, mutation: &PendingMutation) -> Result<(), StorageError> {
        self.inner.enqueue_mutation(mutation)
    }

    fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, StorageError> {
        self.inner.get_mutation(mutation_id)
    }

    fn list_pending_mutations(&self) -> Result<Vec<PendingMutation>, StorageError> {
        self.inner.list_pending_mutations()
    }

    fn list_mutations_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<PendingMutation>, StorageError> {
        self.inner.list_mutations_for_object(object_id)
    }

    fn remove_mutation(&self, mutation_id: &str) -> Result<bool, StorageError> {
        self.inner.remove_mutation(mutation_id)
    }

    fn update_mutation_status(
        &self,
        mutation_id: &str,
        status: MutationStatus,
        retry_count: u32,
    ) -> Result<(), StorageError> {
        self.inner
            .update_mutation_status(mutation_id, status, retry_count)
    }

    fn pending_mutation_count(&self) -> Result<usize, StorageError> {
        self.inner.pending_mutation_count()
    }
}

impl BaseVersionStore for FaultInjectableStorage {
    fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, StorageError> {
        self.inner.get_base_version(object_id, revision)
    }

    fn put_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StorageError> {
        self.inner.put_base_version(object_id, revision, envelope)
    }

    fn prune_base_versions(
        &self,
        object_id: &str,
        before_revision: u64,
    ) -> Result<usize, StorageError> {
        self.inner.prune_base_versions(object_id, before_revision)
    }

    fn clear_base_versions(&self, object_id: &str) -> Result<usize, StorageError> {
        self.inner.clear_base_versions(object_id)
    }

    fn list_base_versions(
        &self,
        object_id: &str,
    ) -> Result<Vec<(u64, EncryptedEnvelope)>, StorageError> {
        self.inner.list_base_versions(object_id)
    }
}

#[test]
fn test_mutation_never_removed_if_durable_storage_write_fails() {
    let storage = FaultInjectableStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());

    let obj_id = "note-fail-test";
    let mutation = queue
        .enqueue_local_note_upsert(obj_id, sample_envelope(obj_id))
        .expect("enqueue");

    assert_eq!(queue.pending_count().unwrap(), 1);

    // Simulate crash or disk full during durable local_objects write
    storage.set_fail_put_object(true);

    // Acknowledge accepted fails
    let ack_result = queue.acknowledge_accepted(&mutation.mutation_id, 1, 50);
    assert!(
        ack_result.is_err(),
        "acknowledge must fail if durable write fails"
    );

    // Invariant: The mutation MUST STILL BE in the queue so it can be retried!
    assert_eq!(
        queue.pending_count().unwrap(),
        1,
        "mutation must NOT be removed when durable write fails"
    );
    let still_queued = queue.get_mutation(&mutation.mutation_id).unwrap();
    assert!(still_queued.is_some(), "mutation must remain in queue");

    // Repair storage
    storage.set_fail_put_object(false);

    // Now retry acknowledge accepted: succeeds and removes mutation
    let ack_success = queue.acknowledge_accepted(&mutation.mutation_id, 1, 50);
    assert!(
        ack_success.is_ok(),
        "acknowledge must succeed once storage is repaired"
    );
    assert_eq!(queue.pending_count().unwrap(), 0);
}

#[test]
fn test_queue_peek_and_fifo_ordering() {
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage);

    let m1 = queue
        .enqueue_local_note_upsert("note-1", sample_envelope("note-1"))
        .unwrap();
    let m2 = queue
        .enqueue_local_note_upsert("note-2", sample_envelope("note-2"))
        .unwrap();
    let m3 = queue
        .enqueue_local_note_upsert("note-3", sample_envelope("note-3"))
        .unwrap();

    let peek = queue.peek_next().unwrap().expect("peek next");
    assert_eq!(peek.mutation_id, m1.mutation_id);

    let list = queue.list_pending().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].mutation_id, m1.mutation_id);
    assert_eq!(list[1].mutation_id, m2.mutation_id);
    assert_eq!(list[2].mutation_id, m3.mutation_id);
}
