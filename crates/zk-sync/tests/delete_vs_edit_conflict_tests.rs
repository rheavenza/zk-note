//! Integration tests for Delete-vs-Edit conflict handling (ZK-056).
//!
//! Acceptance criteria:
//! 1. Stale edit cannot resurrect deleted note (SEC-008, MASTER_SPEC.md § 11);
//! 2. Conflict UX distinguishes deletion;
//! 3. User can explicitly restore as new/current revision.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use zk_core::note::{NoteBuilder, PlaintextNote};
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_protocol::sync::PushRequest;
use zk_storage::memory::MemoryStorage;
use zk_storage::models::MutationType;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{ConflictStore, ObjectStore};
use zk_sync::adapter::{MockSyncAdapter, SyncServerAdapter};
use zk_sync::conflict::{
    evaluate_guarded_lww, resolve_conflict, ConflictPolicy, ConflictResolutionStrategy,
};
use zk_sync::push::{push_pending_changes, PushOptions};
use zk_sync::queue::PendingMutationQueue;

fn temp_db_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("zk_del_edit_{}_{}.db", name, std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

fn create_test_note(
    vault_key: &VaultKey,
    obj_id: &str,
    title: &str,
    body: &str,
    timestamp: &str,
) -> (PlaintextNote, EncryptedEnvelope) {
    let note = NoteBuilder::new()
        .title(title)
        .body(body)
        .created_at(timestamp)
        .updated_at(timestamp)
        .build()
        .expect("build note");
    let env = note.encrypt(vault_key, obj_id).expect("encrypt note");
    (note, env)
}

#[tokio::test]
async fn test_stale_edit_cannot_resurrect_deleted_note_and_creates_conflict_record() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-del-vs-edit-cas";

    // 1. Establish initial note revision 1 on server
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Original Note",
        "Original content at r1",
        "2026-09-10T01:00:00Z",
    );
    let init_req = PushRequest {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: obj_id.to_string(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: env_v1.clone(),
        is_deleted: false,
    };
    let init_resp = adapter.push_mutation(&init_req).await.expect("push r1");
    assert_eq!(init_resp.revision, 1);

    // 2. Client A deletes note on server -> tombstone revision 2 (is_deleted = true)
    let del_req = PushRequest {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: obj_id.to_string(),
        expected_revision: 1,
        object_kind: OBJECT_KIND_NOTE,
        envelope: env_v1.clone(),
        is_deleted: true,
    };
    let del_resp = adapter.push_mutation(&del_req).await.expect("push delete");
    assert_eq!(del_resp.revision, 2);

    // 3. Client B was offline editing based on r1.
    // Client B enqueues offline edit (expected_revision = 1, is_deleted = false).
    let (_, env_stale) = create_test_note(
        &vault_key,
        obj_id,
        "Stale Offline Edit",
        "Edited while offline",
        "2026-09-10T01:30:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_stale)
        .expect("enqueue edit");

    // 4. Client B pushes pending mutations.
    // Server strictly rejects with 409 Conflict.
    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push execute");

    assert_eq!(report.accepted.len(), 0);
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].conflict.current_revision, 2);
    assert!(
        report.conflicts[0].conflict.is_deleted,
        "conflict response must indicate remote is tombstone"
    );

    // 5. Verify local ConflictRecord captures delete-vs-edit status
    let active_conf = storage
        .get_active_conflict_for_object(obj_id)
        .expect("get conflict")
        .expect("must exist");

    assert_eq!(active_conf.remote_revision, 2);
    assert_eq!(active_conf.base_revision, 1);
    assert!(active_conf.remote_is_deleted);
    assert!(!active_conf.local_is_deleted);
    assert!(active_conf.is_delete_vs_edit());
    assert!(!active_conf.is_edit_vs_delete());
    assert_eq!(active_conf.conflict_type_str(), "Delete-vs-Edit");
    assert!(!active_conf.resolved);

    // 6. Verify server still has tombstone at r2 (NO resurrection!)
    let pull = adapter
        .pull_changes(0, Some(10))
        .await
        .expect("pull server");
    let server_obj = pull
        .changes
        .iter()
        .find(|c| c.object_id == obj_id)
        .expect("found on server");
    assert_eq!(server_obj.revision, 2);
    assert!(server_obj.is_deleted, "server must remain a tombstone");
}

#[tokio::test]
async fn test_guarded_lww_refuses_automatic_resurrection_of_tombstone() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-lww-tombstone-safe";

    // 1. Initial note at r1
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Original Note",
        "Original content",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("push r1");

    // 2. Server tombstone at r2 with timestamp 01:10
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: true,
        })
        .await
        .expect("push tombstone");

    // 3. Local offline edit with NEWER timestamp 02:00:00Z
    let (_, env_newer) = create_test_note(
        &vault_key,
        obj_id,
        "Newer Offline Edit",
        "Newer than tombstone",
        "2026-09-10T02:00:00Z",
    );
    let mutation = queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_newer)
        .expect("enqueue edit");

    // 4. Test evaluate_guarded_lww directly fails closed on tombstone
    let conflict_resp = zk_protocol::sync::ConflictResponse {
        error: zk_protocol::ERROR_REVISION_CONFLICT.to_string(),
        object_id: obj_id.to_string(),
        expected_revision: 1,
        current_revision: 2,
        current_server_seq: 2,
        current_envelope: env_v1.clone(),
        is_deleted: true,
    };
    let lww_direct = evaluate_guarded_lww(
        &storage,
        &queue,
        &mutation,
        &conflict_resp,
        Some(&vault_key),
    );
    assert!(
        lww_direct.is_err(),
        "evaluate_guarded_lww must refuse to auto-resurrect tombstones"
    );

    // 5. Test push_pending_changes with GuardedLww policy preserves conflict for manual resolution
    let options = PushOptions {
        max_mutations: None,
        vault_key: Some(vault_key),
        conflict_policy: ConflictPolicy::GuardedLww,
        stop_on_conflict: false,
    };
    let report = push_pending_changes(&adapter, &queue, options)
        .await
        .expect("push");

    assert_eq!(
        report.lww_resolved.len(),
        0,
        "LWW cannot resolve delete-vs-edit"
    );
    assert_eq!(report.conflicts.len(), 1);
    assert!(report.conflicts[0].conflict.is_deleted);

    // Conflict is preserved in ConflictStore for explicit user resolution
    let active_conf = storage
        .get_active_conflict_for_object(obj_id)
        .expect("get")
        .expect("exists");
    assert!(active_conf.is_delete_vs_edit());
    assert!(!active_conf.resolved);
}

#[tokio::test]
async fn test_user_explicitly_restores_as_current_revision() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-explicit-resurrect";

    // 1. Initial note r1
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Work in Progress",
        "Original WIP",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("push r1");

    // 2. Server tombstone at r2 (is_deleted = true)
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: true,
        })
        .await
        .expect("push tombstone");

    // 3. Local offline edit based on r1
    let (_, env_local) = create_test_note(
        &vault_key,
        obj_id,
        "Resurrected Work in Progress",
        "Significant offline additions",
        "2026-09-10T02:00:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_local)
        .expect("enqueue edit");

    // 4. Push triggers delete-vs-edit conflict
    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");
    assert_eq!(report.conflicts.len(), 1);

    let conflict = storage
        .get_active_conflict_for_object(obj_id)
        .expect("get")
        .expect("conflict exists");
    assert!(conflict.is_delete_vs_edit());

    // 5. User explicitly resolves with RestoreResurrect (or KeepLocal)
    let res = resolve_conflict(
        &storage,
        &queue,
        &vault_key,
        &conflict.conflict_id,
        ConflictResolutionStrategy::RestoreResurrect,
    )
    .expect("resolve RestoreResurrect");

    let retry_mut = res.retry_mutation.expect("retry mutation created");
    assert_eq!(
        retry_mut.expected_revision, 2,
        "CAS retry must expect current tombstone revision"
    );
    assert_eq!(retry_mut.mutation_type, MutationType::Upsert);

    // Local object visible head is active (not deleted)
    let local_obj = storage
        .get_object(obj_id)
        .expect("get")
        .expect("local object exists");
    assert_eq!(local_obj.revision, 2);
    assert!(!local_obj.is_deleted);

    // Conflict record is marked resolved
    let conf_after = storage
        .get_conflict(&conflict.conflict_id)
        .expect("get")
        .expect("exists");
    assert!(conf_after.resolved);

    // 6. Push pending changes again: retry mutation pushes to server with expected_revision = 2
    let retry_report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push retry");
    assert_eq!(retry_report.accepted.len(), 1);
    assert_eq!(retry_report.conflicts.len(), 0);

    // 7. Verify server now accepted the resurrection at revision 3!
    let pull = adapter.pull_changes(0, Some(10)).await.expect("pull");
    let server_obj = pull
        .changes
        .iter()
        .rev()
        .find(|c| c.object_id == obj_id)
        .expect("found");
    assert_eq!(server_obj.revision, 3);
    assert!(
        !server_obj.is_deleted,
        "server note is now restored and active!"
    );

    // Decrypt note from server envelope and verify contents match offline edit
    let decrypted = PlaintextNote::decrypt(&server_obj.envelope, &vault_key).expect("decrypt");
    assert_eq!(decrypted.title, "Resurrected Work in Progress");
    assert_eq!(decrypted.body, "Significant offline additions");
}

#[tokio::test]
async fn test_user_accepts_remote_deletion() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-accept-deletion";

    // 1. Initial note r1
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Old Note",
        "Old content",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("push r1");

    // 2. Server tombstone r2
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: true,
        })
        .await
        .expect("push tombstone");

    // 3. Stale local edit based on r1
    let (_, env_local) = create_test_note(
        &vault_key,
        obj_id,
        "Minor edit",
        "Not worth keeping",
        "2026-09-10T01:30:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_local)
        .expect("enqueue");

    // 4. Push conflict
    push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");
    let conflict = storage
        .get_active_conflict_for_object(obj_id)
        .expect("get")
        .expect("conflict exists");

    // 5. User accepts remote deletion via KeepRemote
    let res = resolve_conflict(
        &storage,
        &queue,
        &vault_key,
        &conflict.conflict_id,
        ConflictResolutionStrategy::KeepRemote,
    )
    .expect("resolve KeepRemote");

    assert!(res.retry_mutation.is_none());

    // Local object is marked deleted
    let local_obj = storage
        .get_object(obj_id)
        .expect("get")
        .expect("local object exists");
    assert_eq!(local_obj.revision, 2);
    assert!(local_obj.is_deleted);

    // Queue is empty (stale edit was cleared)
    assert!(queue.peek_next().expect("peek").is_none());

    // Server remains tombstone at r2
    let pull = adapter.pull_changes(0, Some(10)).await.expect("pull");
    let server_obj = pull
        .changes
        .iter()
        .rev()
        .find(|c| c.object_id == obj_id)
        .expect("found");
    assert_eq!(server_obj.revision, 2);
    assert!(server_obj.is_deleted);
}

#[tokio::test]
async fn test_user_restores_as_new_note_duplicate() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-branch-copy";

    // 1. Server note r1 deleted -> r2 tombstone
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Archived Project",
        "Original project plan",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("push r1");
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: true,
        })
        .await
        .expect("push tombstone");

    // 2. Offline client wrote new chapters on top of r1
    let (_, env_local) = create_test_note(
        &vault_key,
        obj_id,
        "Archived Project",
        "Valuable new chapter written offline",
        "2026-09-10T02:00:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_local)
        .expect("enqueue");

    // 3. Push conflict
    push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");
    let conflict = storage
        .get_active_conflict_for_object(obj_id)
        .expect("get")
        .expect("conflict exists");

    // 4. Resolve via DuplicateAsSeparate
    let new_obj_id = uuid::Uuid::new_v4().to_string();
    let res = resolve_conflict(
        &storage,
        &queue,
        &vault_key,
        &conflict.conflict_id,
        ConflictResolutionStrategy::DuplicateAsSeparate {
            new_object_id: new_obj_id.clone(),
            new_title: Some("Revived Project Chapter (Separate)".to_string()),
        },
    )
    .expect("resolve DuplicateAsSeparate");

    assert_eq!(res.duplicated_object_id, Some(new_obj_id.clone()));

    // Original note is marked deleted locally
    let orig_obj = storage.get_object(obj_id).expect("get").expect("exists");
    assert_eq!(orig_obj.revision, 2);
    assert!(orig_obj.is_deleted);

    // New note is active with revision 1 locally
    let new_obj = storage
        .get_object(&new_obj_id)
        .expect("get")
        .expect("new note exists");
    assert_eq!(new_obj.revision, 1);
    assert!(!new_obj.is_deleted);

    // 5. Push pending changes: pushes new note to server (expected_revision = 0)
    let push_rep = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");
    assert_eq!(push_rep.accepted.len(), 1);

    // Server now has original tombstone at r2 AND new note at r1
    let pull = adapter.pull_changes(0, Some(10)).await.expect("pull");
    let s_orig = pull
        .changes
        .iter()
        .find(|c| c.object_id == obj_id && c.revision == 2)
        .expect("found orig");
    assert!(s_orig.is_deleted);

    let s_new = pull
        .changes
        .iter()
        .find(|c| c.object_id == new_obj_id && c.revision == 1)
        .expect("found new note");
    assert!(!s_new.is_deleted);

    let decrypted_new = PlaintextNote::decrypt(&s_new.envelope, &vault_key).expect("decrypt");
    assert_eq!(decrypted_new.title, "Revived Project Chapter (Separate)");
    assert_eq!(decrypted_new.body, "Valuable new chapter written offline");
}

#[test]
fn test_merge_strategy_fails_closed_on_delete_conflict() {
    let storage = MemoryStorage::new();
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-del-merge-err";
    let (_, env_local) = create_test_note(
        &vault_key,
        obj_id,
        "Local Note",
        "Local body",
        "2026-09-10T01:00:00Z",
    );
    let (_, env_remote) = create_test_note(
        &vault_key,
        obj_id,
        "Remote Note",
        "Remote body",
        "2026-09-10T01:00:00Z",
    );

    let conflict = zk_storage::models::ConflictRecord::new(
        "conf-merge-del",
        obj_id,
        OBJECT_KIND_NOTE,
        1,
        2,
        None,
        env_local,
        env_remote,
        None,
        "2026-09-10T01:00:00Z",
    )
    .with_deletion_flags(false, true); // remote is deleted

    storage.put_conflict(&conflict).expect("put");

    let merged_note = PlaintextNote::new("Attempted Merge", "Body");
    let err = resolve_conflict(
        &storage,
        &queue,
        &vault_key,
        "conf-merge-del",
        ConflictResolutionStrategy::Merge(merged_note),
    )
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("cannot merge a delete-vs-edit conflict"));
}

#[tokio::test]
async fn test_delete_vs_edit_persistence_and_audit_with_sqlite() {
    let db_path = temp_db_path("sqlite_del_vs_edit");
    let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite"));
    let queue = PendingMutationQueue::new(storage.clone());
    let adapter = MockSyncAdapter::new();
    let vault_key = VaultKey::generate();

    let obj_id = "note-sqlite-del-vs-edit";

    // Establish r1 note on server and r2 tombstone
    let (_, env_v1) = create_test_note(
        &vault_key,
        obj_id,
        "Secret Document",
        "Confidential content",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("push r1");
    adapter
        .push_mutation(&PushRequest {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_v1.clone(),
            is_deleted: true,
        })
        .await
        .expect("push tombstone");

    // Offline client edits based on r1
    let (_, env_edit) = create_test_note(
        &vault_key,
        obj_id,
        "Secret Document Updated",
        "Confidential modifications",
        "2026-09-10T02:00:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_edit)
        .expect("enqueue");

    // Push conflict
    let report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push");
    assert_eq!(report.conflicts.len(), 1);

    drop(queue);
    drop(storage);

    // Reopen SQLite database after simulated process crash/restart
    {
        let reopened_storage = SqliteStorage::open(&db_path).expect("reopen");
        let active = reopened_storage
            .get_active_conflict_for_object(obj_id)
            .expect("get")
            .expect("conflict persisted across reopen");

        assert_eq!(active.remote_revision, 2);
        assert!(active.remote_is_deleted);
        assert!(!active.local_is_deleted);
        assert!(active.is_delete_vs_edit());
        assert_eq!(active.conflict_type_str(), "Delete-vs-Edit");
    }

    // Zero-knowledge audit (SEC-009): raw SQLite file must NOT leak plaintexts
    let db_bytes = fs::read(&db_path).expect("read db");
    let db_str = String::from_utf8_lossy(&db_bytes);
    assert!(!db_str.contains("Secret Document Updated"));
    assert!(!db_str.contains("Confidential modifications"));

    let _ = fs::remove_file(&db_path);
}
