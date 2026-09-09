//! Integration tests for Push Pending Changes (ZK-044).
//!
//! Acceptance criteria validated:
//! 1. Expected revision supplied on all push requests;
//! 2. Accepted writes clear queue and update durable storage;
//! 3. Lost-response retry uses the same mutation ID with idempotent server handling;
//! 4. Conflict leaves local mutation recoverable with base revision and envelope intact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use zk_core::note::PlaintextNote;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::sync::PushRequest;
use zk_storage::memory::MemoryStorage;
use zk_storage::models::MutationStatus;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{BaseVersionStore, ObjectStore};
use zk_sync::adapter::{MockSyncAdapter, SyncServerAdapter};
use zk_sync::push::{push_pending_changes, PushOptions};
use zk_sync::queue::PendingMutationQueue;

fn sample_encrypted_note(
    vault_key: &VaultKey,
    obj_id: &str,
    title: &str,
) -> zk_protocol::envelope::EncryptedEnvelope {
    let note = PlaintextNote::new(title, format!("Body for {title}"));
    note.encrypt(vault_key, obj_id).expect("encrypt note")
}

#[tokio::test]
async fn test_push_pending_changes_expected_revision_and_queue_clear() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    // 1. Initial creation (expected revision 0)
    let env1 = sample_encrypted_note(&vault_key, "note-cas-1", "Initial 1");
    let mut1 = queue
        .enqueue_local_note_upsert("note-cas-1", env1)
        .expect("enqueue mut1");
    assert_eq!(mut1.expected_revision, 0);

    let report1 = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push 1");

    assert_eq!(report1.total_attempted, 1);
    assert_eq!(report1.accepted.len(), 1);
    assert_eq!(report1.accepted[0].revision, 1);
    assert_eq!(report1.accepted[0].server_seq, 1);

    // Queue is cleared
    assert_eq!(queue.pending_count().unwrap(), 0);
    assert!(queue.get_mutation(&mut1.mutation_id).unwrap().is_none());

    // Durable object store is updated
    let stored1 = storage.get_object("note-cas-1").unwrap().unwrap();
    assert_eq!(stored1.revision, 1);
    assert_eq!(stored1.server_seq, 1);

    // 2. Second edit locally on top of revision 1 (expected revision should be 1)
    let env2 = sample_encrypted_note(&vault_key, "note-cas-1", "Updated 1");
    let mut2 = queue
        .enqueue_local_note_upsert("note-cas-1", env2)
        .expect("enqueue mut2");
    assert_eq!(mut2.expected_revision, 1);

    // Base version store now holds revision 1 envelope for 3-way merge conflict resolution
    let base_ver = storage.get_base_version("note-cas-1", 1).unwrap();
    assert!(base_ver.is_some());

    let report2 = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push 2");

    assert_eq!(report2.total_attempted, 1);
    assert_eq!(report2.accepted.len(), 1);
    assert_eq!(report2.accepted[0].revision, 2);
    assert_eq!(report2.accepted[0].server_seq, 2);

    assert_eq!(queue.pending_count().unwrap(), 0);
    let stored2 = storage.get_object("note-cas-1").unwrap().unwrap();
    assert_eq!(stored2.revision, 2);
    assert_eq!(stored2.server_seq, 2);
}

#[tokio::test]
async fn test_push_lost_response_retry_idempotency() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let env = sample_encrypted_note(&vault_key, "note-idempotent", "Idempotent Test");
    let mut_entry = queue
        .enqueue_local_note_upsert("note-idempotent", env.clone())
        .expect("enqueue");
    let mut_id = mut_entry.mutation_id.clone();

    // Pretend server handled the request already over network, but response was dropped
    let direct_req = PushRequest {
        mutation_id: mut_id.clone(),
        object_id: "note-idempotent".to_string(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: env,
        is_deleted: false,
    };
    let initial_resp = adapter.push_mutation(&direct_req).await.unwrap();
    assert_eq!(initial_resp.revision, 1);
    assert_eq!(initial_resp.server_seq, 1);

    // Client queue still holds this mutation as pending/in-flight
    assert_eq!(queue.pending_count().unwrap(), 1);

    // Client retries pushing: should succeed idempotently with exact same mutation ID
    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("retry push succeeds");

    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.accepted[0].mutation_id, mut_id);
    assert_eq!(report.accepted[0].revision, 1);
    assert_eq!(report.accepted[0].server_seq, 1);

    // After retry succeeds, queue is cleared
    assert_eq!(queue.pending_count().unwrap(), 0);
}

#[tokio::test]
async fn test_push_conflict_preserves_local_mutation_for_recovery() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    // Remote client created revision 1 on server
    let remote_env = sample_encrypted_note(&vault_key, "note-conflict", "Remote note title");
    let remote_req = PushRequest {
        mutation_id: "remote-mut-99".to_string(),
        object_id: "note-conflict".to_string(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: remote_env.clone(),
        is_deleted: false,
    };
    adapter.push_mutation(&remote_req).await.unwrap();

    // Local client prepared offline edit with expected_revision = 0
    let local_env = sample_encrypted_note(&vault_key, "note-conflict", "Local note title");
    let local_mut = queue
        .enqueue_local_note_upsert("note-conflict", local_env.clone())
        .expect("enqueue local");
    assert_eq!(local_mut.expected_revision, 0);

    // Push pending changes
    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push executes");

    // Must detect conflict
    assert_eq!(report.accepted.len(), 0);
    assert_eq!(report.conflicts.len(), 1);

    let conflict_info = &report.conflicts[0];
    assert_eq!(conflict_info.conflict.object_id, "note-conflict");
    assert_eq!(conflict_info.conflict.expected_revision, 0);
    assert_eq!(conflict_info.conflict.current_revision, 1);
    assert_eq!(conflict_info.conflict.current_envelope, remote_env);

    // Local mutation is STILL IN QUEUE with status Pending and base revision intact
    assert_eq!(queue.pending_count().unwrap(), 1);
    let queued = queue.get_mutation(&local_mut.mutation_id).unwrap().unwrap();
    assert_eq!(queued.status, MutationStatus::Pending);
    assert_eq!(queued.expected_revision, 0);
    assert_eq!(queued.envelope, local_env);
}

#[tokio::test]
async fn test_push_pending_changes_with_sqlite_backend() {
    use std::sync::Arc;

    let storage = Arc::new(SqliteStorage::open_in_memory().expect("open sqlite"));
    let queue = PendingMutationQueue::new(storage.clone());
    let adapter = MockSyncAdapter::new();
    let vault_key = VaultKey::generate();

    let env = sample_encrypted_note(&vault_key, "sqlite-note", "Sqlite Title");
    let mut_item = queue
        .enqueue_local_note_upsert("sqlite-note", env)
        .expect("enqueue sqlite");

    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");

    assert_eq!(report.accepted.len(), 1);
    assert_eq!(report.accepted[0].mutation_id, mut_item.mutation_id);
    assert_eq!(queue.pending_count().unwrap(), 0);

    let obj = storage.get_object("sqlite-note").unwrap().unwrap();
    assert_eq!(obj.revision, 1);
    assert_eq!(obj.server_seq, 1);
}
