//! Integration tests for DurableSyncCursor (ZK-042).
//!
//! Acceptance criteria validated:
//! 1. Cursor advances ONLY AFTER local durable application;
//! 2. Crash simulation does not skip remote changes (Scenario E).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::ObjectChange;
use zk_storage::error::StorageError;
use zk_storage::memory::MemoryStorage;
use zk_storage::models::{ObjectFilter, StoredEncryptedObject};
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::ObjectStore;
use zk_sync::cursor::{CursorError, DurableSyncCursor};

fn sample_change(seq: u64, obj_id: &str) -> ObjectChange {
    ObjectChange {
        server_seq: seq,
        object_id: obj_id.to_string(),
        revision: 1,
        object_kind: OBJECT_KIND_NOTE,
        envelope: EncryptedEnvelope {
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
        },
        is_deleted: false,
    }
}

/// ObjectStore wrapper that can selectively fail put_object to simulate mid-stream crashes.
#[derive(Debug, Clone)]
struct FaultyObjectStore {
    inner: MemoryStorage,
    fail_on_seq: Arc<std::sync::atomic::AtomicU64>,
}

impl FaultyObjectStore {
    fn new() -> Self {
        Self {
            inner: MemoryStorage::new(),
            fail_on_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn set_fail_on_seq(&self, seq: u64) {
        self.fail_on_seq.store(seq, Ordering::SeqCst);
    }
}

impl ObjectStore for FaultyObjectStore {
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError> {
        self.inner.get_object(object_id)
    }

    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError> {
        let target_fail = self.fail_on_seq.load(Ordering::SeqCst);
        if target_fail > 0 && object.server_seq == target_fail {
            return Err(StorageError::Backend(format!(
                "simulated crash on sequence {target_fail}"
            )));
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

#[test]
fn test_cursor_advances_only_after_local_durable_application() {
    let sync_store = MemoryStorage::new();
    let obj_store = FaultyObjectStore::new();
    let cursor = DurableSyncCursor::new(sync_store.clone());

    assert_eq!(cursor.current_cursor().unwrap(), 0);

    // Change 1: succeeds
    let c1 = sample_change(1, "note-1");
    cursor.apply_change(&obj_store, &c1).expect("apply c1");
    assert_eq!(cursor.current_cursor().unwrap(), 1);

    // Change 2: succeeds
    let c2 = sample_change(2, "note-2");
    cursor.apply_change(&obj_store, &c2).expect("apply c2");
    assert_eq!(cursor.current_cursor().unwrap(), 2);

    // Change 3: object store fails!
    obj_store.set_fail_on_seq(3);
    let c3 = sample_change(3, "note-3");
    let err = cursor
        .apply_change(&obj_store, &c3)
        .expect_err("c3 must fail");
    assert!(matches!(err, CursorError::Storage(_)));

    // Invariant: Cursor MUST REMAIN at 2, NOT 3!
    assert_eq!(
        cursor.current_cursor().unwrap(),
        2,
        "cursor must not advance if local durable write failed"
    );

    // Verify note-3 was NOT stored
    assert!(obj_store.get_object("note-3").unwrap().is_none());

    // Repair storage
    obj_store.set_fail_on_seq(0);

    // Re-applying change 3 now succeeds and advances cursor
    cursor.apply_change(&obj_store, &c3).expect("retry c3");
    assert_eq!(cursor.current_cursor().unwrap(), 3);
    assert!(obj_store.get_object("note-3").unwrap().is_some());
}

#[test]
fn test_crash_simulation_does_not_skip_remote_changes_scenario_e() {
    // Scenario E from MASTER_SPEC.md:
    // client fetches through seq 100
    // local durable write fails after seq 97
    // restart cursor remains 97
    // re-fetch 98..100
    // No missed updates.

    let mut db_path = std::env::temp_dir();
    db_path.push(format!("zk_test_cursor_scenario_e_{}.db", Uuid::new_v4()));
    let _ = std::fs::remove_file(&db_path);

    let stream = [
        sample_change(95, "note-95"),
        sample_change(96, "note-96"),
        sample_change(97, "note-97"),
        sample_change(98, "note-98"),
        sample_change(99, "note-99"),
        sample_change(100, "note-100"),
    ];

    // Phase 1: Client applies 95..97, then encounters a crash on 98
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite"));
        let cursor = DurableSyncCursor::new(Arc::clone(&storage));

        // Apply 95, 96, 97
        for change in &stream[0..3] {
            cursor.apply_change(&storage, change).expect("apply change");
        }
        assert_eq!(cursor.current_cursor().unwrap(), 97);

        // Process crashes or terminates abruptly before or during 98 write
        // (storage dropped)
    }

    // Phase 2: Process restarts from disk. Verify cursor remains 97.
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("reopen sqlite"));
        let cursor = DurableSyncCursor::new(Arc::clone(&storage));

        // Invariant: cursor must be 97!
        let restart_cursor = cursor.current_cursor().expect("read restart cursor");
        assert_eq!(
            restart_cursor, 97,
            "restart cursor must remain at last durable sequence 97"
        );

        // Client queries server with `after = 97` and receives 98..100
        let refetched: Vec<_> = stream
            .iter()
            .filter(|c| c.server_seq > restart_cursor)
            .cloned()
            .collect();

        assert_eq!(refetched.len(), 3);
        assert_eq!(refetched[0].server_seq, 98);
        assert_eq!(refetched[1].server_seq, 99);
        assert_eq!(refetched[2].server_seq, 100);

        // Apply remaining changes
        cursor
            .apply_changes_sequential(&storage, &refetched)
            .expect("apply refetched");

        // Cursor now advances to 100
        assert_eq!(cursor.current_cursor().unwrap(), 100);

        // Verify all notes 95..100 exist in local storage (zero skipped changes)
        for seq in 95..=100 {
            let id = format!("note-{seq}");
            let obj = storage.get_object(&id).unwrap().expect("object must exist");
            assert_eq!(obj.server_seq, seq);
        }
    }

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_sequential_batch_stops_at_first_failure_and_cursor_matches() {
    let sync_store = MemoryStorage::new();
    let obj_store = FaultyObjectStore::new();
    let cursor = DurableSyncCursor::new(sync_store);

    let batch = [
        sample_change(10, "note-10"),
        sample_change(11, "note-11"),
        sample_change(12, "note-12"), // will fail
        sample_change(13, "note-13"),
    ];

    obj_store.set_fail_on_seq(12);

    let result = cursor.apply_changes_sequential(&obj_store, &batch);
    assert!(result.is_err());

    // Cursor must be exactly 11
    assert_eq!(cursor.current_cursor().unwrap(), 11);

    // note-10 and note-11 were persisted
    assert!(obj_store.get_object("note-10").unwrap().is_some());
    assert!(obj_store.get_object("note-11").unwrap().is_some());
    // note-12 and note-13 were NOT persisted
    assert!(obj_store.get_object("note-12").unwrap().is_none());
    assert!(obj_store.get_object("note-13").unwrap().is_none());
}

#[test]
fn test_cursor_monotonicity_rejects_regression() {
    let sync_store = MemoryStorage::new();
    let cursor = DurableSyncCursor::new(sync_store);

    cursor.advance_to(50).unwrap();
    assert_eq!(cursor.current_cursor().unwrap(), 50);

    let err = cursor.advance_to(49).unwrap_err();
    assert!(matches!(
        err,
        CursorError::Regression {
            current: 50,
            attempted: 49
        }
    ));

    // Reset for resync allows deliberate reset
    cursor.reset_cursor_for_resync().unwrap();
    assert_eq!(cursor.current_cursor().unwrap(), 0);
}
