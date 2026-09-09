//! Integration tests for Guarded Last-Write-Wins (LWW) policy option (ZK-055).
//!
//! Acceptance criteria validated:
//! 1. Optional policy documented (ADR 0005);
//! 2. Selected visible head uses LWW when enabled;
//! 3. Losing revision is ALWAYS recoverable (preserved in BaseVersionStore and ConflictStore);
//! 4. Server CAS remains enforced (retry mutation uses expected_revision = remote_revision);
//! 5. Not enabled by default in V1 without explicit product decision (Default is ConflictPolicy::Manual).

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
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{BaseVersionStore, ConflictStore, ObjectStore};
use zk_sync::adapter::{MockSyncAdapter, SyncServerAdapter};
use zk_sync::conflict::{ConflictPolicy, LwwWinner};
use zk_sync::push::{push_pending_changes, PushOptions};
use zk_sync::queue::PendingMutationQueue;

fn temp_db_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("zk_lww_test_{}_{}.db", name, std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

fn create_note_with_timestamp(
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

#[test]
fn test_default_conflict_policy_is_manual_v1_safe() {
    // In accordance with MASTER_SPEC.md § 10.4:
    // "Do not enable by default in V1 without explicit product decision."
    let default_options = PushOptions::default();
    assert_eq!(default_options.conflict_policy, ConflictPolicy::Manual);
    assert_eq!(ConflictPolicy::default(), ConflictPolicy::Manual);
}

#[tokio::test]
async fn test_guarded_lww_local_wins_updates_visible_head_preserves_remote_enforces_cas() {
    let adapter = MockSyncAdapter::new();
    let storage = Arc::new(MemoryStorage::new());
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-lww-local-wins";

    // 1. Establish initial revision 1 on server
    let (_, env_v1) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Original Note",
        "Original Body",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-server-1".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 0,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("setup server rev 1");

    // 2. Concurrent remote client edits note on server to revision 2 with older timestamp
    let (_, env_v2_remote) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Remote Note Revision 2",
        "Remote concurrent body edits (timestamp 02:00:00Z)",
        "2026-09-10T02:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-server-2".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 1,
            envelope: env_v2_remote.clone(),
            is_deleted: false,
        })
        .await
        .expect("server advance to rev 2");

    // 3. Local offline client was based on revision 1, edits note with a NEWER timestamp
    let (_, env_v2_local) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Local Note Revision 2",
        "Local newer body edits (timestamp 03:00:00Z)",
        "2026-09-10T03:00:00Z",
    );
    let local_mut = queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_v2_local.clone())
        .expect("enqueue local");
    assert_eq!(local_mut.expected_revision, 1);

    // 4. Push with GuardedLww policy
    let push_options = PushOptions {
        max_mutations: None,
        stop_on_conflict: false,
        conflict_policy: ConflictPolicy::GuardedLww,
        vault_key: Some(vault_key.clone()),
    };
    let report = push_pending_changes(&adapter, &queue, push_options)
        .await
        .expect("push with guarded lww");

    // Conflict was intercepted and resolved via Guarded LWW
    assert_eq!(report.lww_resolved.len(), 1);
    let outcome = &report.lww_resolved[0];
    assert_eq!(outcome.winner, LwwWinner::Local);
    assert_eq!(outcome.winning_revision, 2);

    // 5. Verification: Selected visible head in local storage is LOCAL version
    let visible_head = storage.get_object(obj_id).unwrap().expect("visible head");
    assert_eq!(visible_head.revision, 2);
    let decrypted_head = PlaintextNote::decrypt(&visible_head.envelope, &vault_key).unwrap();
    assert_eq!(decrypted_head.title, "Local Note Revision 2");
    assert_eq!(
        decrypted_head.body,
        "Local newer body edits (timestamp 03:00:00Z)"
    );

    // 6. Verification: Losing remote revision is ALWAYS recoverable in BaseVersionStore
    let remote_backup = storage
        .get_base_version(obj_id, 2)
        .unwrap()
        .expect("remote losing revision must be preserved in base version store");
    assert_eq!(remote_backup, env_v2_remote);
    let decrypted_losing = PlaintextNote::decrypt(&remote_backup, &vault_key).unwrap();
    assert_eq!(decrypted_losing.title, "Remote Note Revision 2");
    assert_eq!(
        decrypted_losing.body,
        "Remote concurrent body edits (timestamp 02:00:00Z)"
    );

    // 7. Verification: Server CAS remains strictly enforced
    // Retry mutation has expected_revision = 2 (remote revision)
    let retry_mut = outcome
        .retry_mutation
        .as_ref()
        .expect("must enqueue retry mutation");
    assert_eq!(retry_mut.expected_revision, 2);
    assert_eq!(queue.pending_count().unwrap(), 1);

    // Pushing again sends the retry mutation with expected_revision = 2, which satisfies server CAS
    let retry_report = push_pending_changes(&adapter, &queue, PushOptions::default())
        .await
        .expect("push retry mutation");
    assert_eq!(retry_report.accepted.len(), 1);
    assert_eq!(retry_report.accepted[0].revision, 3);
    assert_eq!(queue.pending_count().unwrap(), 0);
}

#[tokio::test]
async fn test_guarded_lww_remote_wins_updates_visible_head_preserves_local_clears_stale_mutation() {
    let adapter = MockSyncAdapter::new();
    let storage = Arc::new(MemoryStorage::new());
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = "note-lww-remote-wins";

    // 1. Establish initial revision 1 on server
    let (_, env_v1) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Original Note",
        "Original Body",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-server-1".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 0,
            envelope: env_v1.clone(),
            is_deleted: false,
        })
        .await
        .expect("setup server rev 1");

    // 2. Concurrent remote client edits note on server to revision 2 with NEWER timestamp
    let (_, env_v2_remote) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Remote Newer Note",
        "Remote newer content (timestamp 05:00:00Z)",
        "2026-09-10T05:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-server-2".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 1,
            envelope: env_v2_remote.clone(),
            is_deleted: false,
        })
        .await
        .expect("server advance to rev 2");

    // 3. Local client has an older edit (timestamp 03:00:00Z)
    let (_, env_v2_local) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Local Older Note",
        "Local older content (timestamp 03:00:00Z)",
        "2026-09-10T03:00:00Z",
    );
    let local_mut = queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_v2_local.clone())
        .expect("enqueue local");
    assert_eq!(local_mut.expected_revision, 1);

    // 4. Push with GuardedLww policy
    let push_options = PushOptions {
        max_mutations: None,
        stop_on_conflict: false,
        conflict_policy: ConflictPolicy::GuardedLww,
        vault_key: Some(vault_key.clone()),
    };
    let report = push_pending_changes(&adapter, &queue, push_options)
        .await
        .expect("push with guarded lww");

    assert_eq!(report.lww_resolved.len(), 1);
    let outcome = &report.lww_resolved[0];
    assert_eq!(outcome.winner, LwwWinner::Remote);
    assert_eq!(outcome.winning_revision, 2);
    assert!(outcome.retry_mutation.is_none());

    // 5. Verification: Selected visible head in local storage is REMOTE version
    let visible_head = storage.get_object(obj_id).unwrap().expect("visible head");
    assert_eq!(visible_head.revision, 2);
    let decrypted_head = PlaintextNote::decrypt(&visible_head.envelope, &vault_key).unwrap();
    assert_eq!(decrypted_head.title, "Remote Newer Note");
    assert_eq!(
        decrypted_head.body,
        "Remote newer content (timestamp 05:00:00Z)"
    );

    // 6. Verification: Losing local revision is ALWAYS recoverable in BaseVersionStore
    let local_backup = storage
        .get_base_version(obj_id, 1)
        .unwrap()
        .expect("local losing revision must be preserved in base version store");
    assert_eq!(local_backup, env_v2_local);
    let decrypted_losing = PlaintextNote::decrypt(&local_backup, &vault_key).unwrap();
    assert_eq!(decrypted_losing.title, "Local Older Note");
    assert_eq!(
        decrypted_losing.body,
        "Local older content (timestamp 03:00:00Z)"
    );

    // 7. Stale local mutation has been dequeued
    assert_eq!(queue.pending_count().unwrap(), 0);
}

#[tokio::test]
async fn test_guarded_lww_with_sqlite_backend_restart_and_audit() {
    let db_path = temp_db_path("guarded_lww_sqlite");
    let _ = fs::remove_file(&db_path);

    let adapter = MockSyncAdapter::new();
    let vault_key = VaultKey::generate();
    let obj_id = "note-lww-sqlite";

    // Setup initial server object
    let (_, env_v1) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Init SQLite Note",
        "Init Body",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-1".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 0,
            envelope: env_v1,
            is_deleted: false,
        })
        .await
        .expect("server rev 1");

    // Server advances to revision 2
    let (_, env_v2_remote) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Remote Note Rev 2",
        "Remote Body Rev 2",
        "2026-09-10T02:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-2".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 1,
            envelope: env_v2_remote,
            is_deleted: false,
        })
        .await
        .expect("server rev 2");

    let conf_id = {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite"));
        let queue = PendingMutationQueue::new(storage.clone());

        // Local edit has newer timestamp (04:00:00Z)
        let (_, env_v2_local) = create_note_with_timestamp(
            &vault_key,
            obj_id,
            "Local Newer SQLite",
            "Local Newer Content",
            "2026-09-10T04:00:00Z",
        );
        queue
            .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_v2_local)
            .expect("enqueue");

        let report = push_pending_changes(
            &adapter,
            &queue,
            PushOptions {
                max_mutations: None,
                stop_on_conflict: false,
                conflict_policy: ConflictPolicy::GuardedLww,
                vault_key: Some(vault_key.clone()),
            },
        )
        .await
        .expect("push lww");

        assert_eq!(report.lww_resolved.len(), 1);
        report.lww_resolved[0].conflict_id.clone()
    };

    // Close and reopen SQLite storage (simulating process restart)
    {
        let reopened = SqliteStorage::open(&db_path).expect("reopen sqlite");

        // Visible head survives restart
        let head = reopened.get_object(obj_id).unwrap().expect("head exists");
        assert_eq!(head.revision, 2);
        let note = PlaintextNote::decrypt(&head.envelope, &vault_key).unwrap();
        assert_eq!(note.title, "Local Newer SQLite");

        // Losing revision survives restart in BaseVersionStore
        let losing = reopened
            .get_base_version(obj_id, 2)
            .unwrap()
            .expect("losing base version exists");
        let losing_note = PlaintextNote::decrypt(&losing, &vault_key).unwrap();
        assert_eq!(losing_note.title, "Remote Note Rev 2");

        // Conflict record survives restart in ConflictStore
        let conf_record = reopened
            .get_conflict(&conf_id)
            .unwrap()
            .expect("conflict record exists");
        assert!(conf_record.resolved);
        assert!(conf_record.resolved_at.is_some());
    }

    // Zero-knowledge disk inspection: verify no plaintext note strings leaked into the SQLite file
    let db_bytes = fs::read(&db_path).expect("read db binary");
    assert!(
        !db_bytes
            .windows(b"Local Newer Content".len())
            .any(|w| w == b"Local Newer Content"),
        "SEC-009 VIOLATION: Local plaintext leaked into database file"
    );
    assert!(
        !db_bytes
            .windows(b"Remote Body Rev 2".len())
            .any(|w| w == b"Remote Body Rev 2"),
        "SEC-009 VIOLATION: Remote plaintext leaked into database file"
    );

    let _ = fs::remove_file(&db_path);
}

#[tokio::test]
async fn test_guarded_lww_opaque_mode_without_vault_key() {
    // Verifies that locked clients can still execute Guarded LWW safely without plaintext knowledge
    let adapter = MockSyncAdapter::new();
    let storage = Arc::new(MemoryStorage::new());
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();
    let obj_id = "note-lww-opaque";

    // 1. Initial server setup
    let (_, env_v1) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "V1 Note",
        "V1 Body",
        "2026-09-10T01:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-opaque-1".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 0,
            envelope: env_v1,
            is_deleted: false,
        })
        .await
        .expect("server v1");

    // 2. Server advances to revision 2
    let (_, env_v2_remote) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Remote V2 Note",
        "Remote V2 Body",
        "2026-09-10T02:00:00Z",
    );
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-opaque-2".to_string(),
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            expected_revision: 1,
            envelope: env_v2_remote.clone(),
            is_deleted: false,
        })
        .await
        .expect("server v2");

    // 3. Local mutation enqueued without passing vault_key
    let (_, env_v2_local) = create_note_with_timestamp(
        &vault_key,
        obj_id,
        "Local V2 Note",
        "Local V2 Body",
        "2026-09-10T03:00:00Z",
    );
    queue
        .enqueue_upsert(obj_id, OBJECT_KIND_NOTE, 1, env_v2_local.clone())
        .expect("enqueue");

    // 4. Push with GuardedLww and vault_key = None
    let push_options = PushOptions {
        max_mutations: None,
        stop_on_conflict: false,
        conflict_policy: ConflictPolicy::GuardedLww,
        vault_key: None,
    };
    let report = push_pending_changes(&adapter, &queue, push_options)
        .await
        .expect("push opaque lww");

    assert_eq!(report.lww_resolved.len(), 1);
    let outcome = &report.lww_resolved[0];

    // Verify visible head is updated in ObjectStore
    let head = storage.get_object(obj_id).unwrap().expect("head exists");
    assert_eq!(head.revision, outcome.winning_revision);

    // Verify losing version is preserved in BaseVersionStore
    let losing_base = storage
        .get_base_version(obj_id, outcome.losing_revision)
        .unwrap();
    assert!(losing_base.is_some());
}
