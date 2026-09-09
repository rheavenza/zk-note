//! Integration tests for Pull-before-push orchestration (ZK-045).
//!
//! Acceptance criteria validated:
//! 1. Deterministic sync cycle;
//! 2. Retryable network failure handling;
//! 3. Final cursor consistency;
//! 4. No mutation silently dropped under any condition.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use zk_core::note::PlaintextNote;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::sync::PushRequest;
use zk_storage::memory::MemoryStorage;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::ObjectStore;
use zk_sync::adapter::{MockSyncAdapter, SyncServerAdapter};
use zk_sync::error::SyncNetworkError;
use zk_sync::orchestrator::{SyncCycleOptions, SyncEngine};

fn create_envelope(
    vault_key: &VaultKey,
    obj_id: &str,
    title: &str,
) -> zk_protocol::envelope::EncryptedEnvelope {
    let note = PlaintextNote::new(title, format!("Content of {title}"));
    note.encrypt(vault_key, obj_id).expect("encrypt note")
}

#[tokio::test]
async fn test_orchestrator_deterministic_cycle_and_cursor_consistency() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let engine = SyncEngine::new(adapter, storage.clone());
    let vault_key = VaultKey::generate();

    // 1. Seed 2 remote notes on server (server_seq: 1, 2)
    for i in 1..=2 {
        let id = format!("remote-note-{i}");
        let env = create_envelope(&vault_key, &id, &format!("Remote {i}"));
        let req = PushRequest {
            mutation_id: format!("remote-mut-{i}"),
            object_id: id,
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env,
            is_deleted: false,
        };
        engine.adapter().push_mutation(&req).await.unwrap();
    }

    // 2. Enqueue 2 local edits in client queue (expected_revision: 0)
    let env_loc1 = create_envelope(&vault_key, "local-note-1", "Local 1");
    let env_loc2 = create_envelope(&vault_key, "local-note-2", "Local 2");
    engine
        .queue()
        .enqueue_local_note_upsert("local-note-1", env_loc1)
        .unwrap();
    engine
        .queue()
        .enqueue_local_note_upsert("local-note-2", env_loc2)
        .unwrap();

    assert_eq!(engine.cursor().current_cursor().unwrap(), 0);
    assert_eq!(engine.queue().pending_count().unwrap(), 2);

    // 3. Run full sync cycle
    let report = engine
        .sync_with_key(Some(&vault_key), SyncCycleOptions::default())
        .await
        .expect("sync cycle succeeds");

    // Acceptance criterion 1: Deterministic sync cycle
    // Initial pull got 2 remote notes
    assert_eq!(report.initial_pull.applied_changes, 2);
    assert_eq!(report.initial_cursor, 0);

    // Push phase pushed 2 local notes (server_seq: 3, 4)
    assert_eq!(report.mutations_accepted, 2);
    assert_eq!(report.mutations_conflicted, 0);

    // Follow-up pull pulled server sequences 3 and 4
    let followup = report.followup_pull.expect("follow-up pull occurred");
    assert_eq!(followup.applied_changes, 2);

    // Acceptance criterion 3: Final cursor consistent
    assert_eq!(report.final_cursor, 4);
    assert_eq!(engine.cursor().current_cursor().unwrap(), 4);

    // Acceptance criterion 4: No mutations silently dropped; queue is cleanly cleared
    assert_eq!(report.mutations_remaining, 0);
    assert_eq!(engine.queue().pending_count().unwrap(), 0);

    // Durable storage holds all 4 notes
    assert!(storage.get_object("remote-note-1").unwrap().is_some());
    assert!(storage.get_object("remote-note-2").unwrap().is_some());
    assert!(storage.get_object("local-note-1").unwrap().is_some());
    assert!(storage.get_object("local-note-2").unwrap().is_some());
}

#[tokio::test]
async fn test_orchestrator_with_sqlite_and_active_session() {
    let storage = Arc::new(SqliteStorage::open_in_memory().expect("open sqlite"));
    let adapter = MockSyncAdapter::new();
    let engine = SyncEngine::new(adapter, storage.clone());

    let vault_key = VaultKey::generate();
    let mut session = VaultSession::from_key(vault_key.clone());

    // Remote note on server
    let remote_env = create_envelope(&vault_key, "session-remote", "Shopping List");
    let req = PushRequest {
        mutation_id: "mut-sess-1".to_string(),
        object_id: "session-remote".to_string(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: remote_env,
        is_deleted: false,
    };
    engine.adapter().push_mutation(&req).await.unwrap();

    // Local note
    let local_env = create_envelope(&vault_key, "session-local", "Meeting Notes");
    engine
        .queue()
        .enqueue_local_note_upsert("session-local", local_env)
        .unwrap();

    // Run cycle with active session
    let report = engine
        .sync_with_session(&mut session, SyncCycleOptions::default())
        .await
        .expect("sync with session");

    assert_eq!(report.mutations_accepted, 1);
    assert_eq!(report.final_cursor, 2);
    assert_eq!(engine.cursor().current_cursor().unwrap(), 2);
    assert_eq!(engine.queue().pending_count().unwrap(), 0);

    // In-memory search index was updated with decrypted content
    let search_idx = session.search_index_mut().unwrap();
    let hits = search_idx.search("Shopping");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "session-remote");
}

#[tokio::test]
async fn test_orchestrator_retryable_network_failure_handling() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let engine = SyncEngine::new(adapter, storage.clone());
    let vault_key = VaultKey::generate();

    let env = create_envelope(&vault_key, "net-fail-note", "Resilience Test");
    let mut_item = engine
        .queue()
        .enqueue_local_note_upsert("net-fail-note", env)
        .unwrap();

    // 1. Transient transport failure on initial pull
    engine
        .adapter()
        .set_fail_next(Some(SyncNetworkError::ConnectionFailed(
            "DNS timeout".to_string(),
        )));

    let err1 = engine
        .sync(SyncCycleOptions::default())
        .await
        .expect_err("network error expected");

    assert!(err1.is_retryable());
    assert_eq!(engine.cursor().current_cursor().unwrap(), 0);
    assert_eq!(engine.queue().pending_count().unwrap(), 1);

    // 2. Transient server 503 error on retry
    engine
        .adapter()
        .set_fail_next(Some(SyncNetworkError::ServerError {
            status: 503,
            message: "Service Unavailable".to_string(),
        }));

    let err2 = engine
        .sync(SyncCycleOptions::default())
        .await
        .expect_err("503 error expected");

    assert!(err2.is_retryable());
    assert_eq!(engine.cursor().current_cursor().unwrap(), 0);
    assert_eq!(engine.queue().pending_count().unwrap(), 1);

    // 3. Network restored: sync finishes cleanly without missing any mutation
    let report = engine
        .sync(SyncCycleOptions::default())
        .await
        .expect("sync succeeds");

    assert_eq!(report.mutations_accepted, 1);
    assert_eq!(report.push.accepted[0].mutation_id, mut_item.mutation_id);
    assert_eq!(report.final_cursor, 1);
    assert_eq!(engine.queue().pending_count().unwrap(), 0);
}

#[tokio::test]
async fn test_orchestrator_conflict_preserves_mutation_without_dropping() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let engine = SyncEngine::new(adapter, storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "shared-note";

    // Remote client created revision 1 on server
    let remote_env = create_envelope(&vault_key, obj_id, "Remote Version");
    let remote_req = PushRequest {
        mutation_id: "remote-mut".to_string(),
        object_id: obj_id.to_string(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: remote_env,
        is_deleted: false,
    };
    engine.adapter().push_mutation(&remote_req).await.unwrap();

    // Local client created offline edit based on revision 0 (stale)
    let local_env = create_envelope(&vault_key, obj_id, "Local Conflicting Version");
    let local_mut = engine
        .queue()
        .enqueue_local_note_upsert(obj_id, local_env.clone())
        .unwrap();
    assert_eq!(local_mut.expected_revision, 0);

    // Run sync cycle
    let report = engine
        .sync_with_key(Some(&vault_key), SyncCycleOptions::default())
        .await
        .expect("sync cycle completes without crashing");

    // Pull fetched remote change
    assert_eq!(report.initial_pull.applied_changes, 1);

    // Push detected revision conflict (expected 0, server is 1)
    assert_eq!(report.mutations_accepted, 0);
    assert_eq!(report.mutations_conflicted, 1);

    // Acceptance criterion 4: NO MUTATION SILENTLY DROPPED
    // Conflicted local mutation remains in queue for 3-way merge resolution
    assert_eq!(report.mutations_remaining, 1);
    assert_eq!(engine.queue().pending_count().unwrap(), 1);

    let queued = engine
        .queue()
        .get_mutation(&local_mut.mutation_id)
        .unwrap()
        .expect("mutation still in queue");
    assert_eq!(queued.object_id, obj_id);
    assert_eq!(queued.expected_revision, 0);
    assert_eq!(queued.envelope, local_env);
}
