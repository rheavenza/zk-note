//! Integration tests for Pull Remote Changes (ZK-043).
//!
//! Acceptance criteria validated:
//! 1. Paginated pull;
//! 2. Encrypted changes stored first;
//! 3. Unlocked client can decrypt/apply;
//! 4. Locked sync behavior explicitly defined.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use zk_core::note::PlaintextNote;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::sync::PushRequest;
use zk_storage::memory::MemoryStorage;
use zk_storage::traits::ObjectStore;
use zk_sync::adapter::{MockSyncAdapter, SyncServerAdapter};
use zk_sync::cursor::DurableSyncCursor;
use zk_sync::pull::{
    decrypt_stored_objects_on_unlock, pull_remote_changes, pull_with_session, LockedSyncBehavior,
    PullOptions,
};

fn sample_encrypted_note(
    vault_key: &VaultKey,
    obj_id: &str,
    title: &str,
) -> zk_protocol::envelope::EncryptedEnvelope {
    let note = PlaintextNote::new(title, format!("Body of note {title}"));
    note.encrypt(vault_key, obj_id).expect("encrypt note")
}

#[tokio::test]
async fn test_paginated_pull_fetches_all_pages_and_persists_cursor() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let cursor = DurableSyncCursor::new(storage.clone());
    let vault_key = VaultKey::generate();

    // Seed 7 notes on server
    for i in 1..=7 {
        let id = format!("page-note-{i}");
        let env = sample_encrypted_note(&vault_key, &id, &format!("Note {i}"));
        let req = PushRequest {
            mutation_id: format!("m-{i}"),
            object_id: id,
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env,
            is_deleted: false,
        };
        adapter.push_mutation(&req).await.unwrap();
    }

    // Pull with page size 3 -> 3 pages: [1,2,3], [4,5,6], [7]
    let options = PullOptions {
        page_limit: Some(3),
        max_pages: None,
        locked_behavior: LockedSyncBehavior::StoreCiphertextDeferDecryption,
    };

    let report = pull_remote_changes(&adapter, &storage, &cursor, Some(&vault_key), options)
        .await
        .expect("pull succeeded");

    assert_eq!(report.pages_fetched, 3);
    assert_eq!(report.total_changes, 7);
    assert_eq!(report.applied_changes, 7);
    assert_eq!(report.final_cursor, 7);
    assert_eq!(cursor.current_cursor().unwrap(), 7);

    // Verify all 7 stored in local ObjectStore
    for i in 1..=7 {
        let id = format!("page-note-{i}");
        let obj = storage.get_object(&id).unwrap().expect("object stored");
        assert_eq!(obj.server_seq, i as u64);
    }
}

#[tokio::test]
async fn test_encrypted_changes_stored_first_even_if_decryption_fails_closed() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let cursor = DurableSyncCursor::new(storage.clone());
    let vault_key = VaultKey::generate();

    // 1. Valid note 1
    let env1 = sample_encrypted_note(&vault_key, "note-1", "Valid Note 1");
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-1".to_string(),
            object_id: "note-1".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env1,
            is_deleted: false,
        })
        .await
        .unwrap();

    // 2. Corrupted note 2 (tampered ciphertext)
    let mut env2 = sample_encrypted_note(&vault_key, "note-2", "Note 2 to tamper");
    env2.payload.ciphertext = "dGFtcGVyZWQtY2lwaGVydGV4dA==".to_string();
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "mut-2".to_string(),
            object_id: "note-2".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env2,
            is_deleted: false,
        })
        .await
        .unwrap();

    // Pull unlocked: must fail closed with decryption error
    let result = pull_remote_changes(
        &adapter,
        &storage,
        &cursor,
        Some(&vault_key),
        PullOptions::default(),
    )
    .await;

    assert!(
        result.is_err(),
        "must fail closed on tampered ciphertext (SEC-010)"
    );

    // BUT: In accordance with criterion "encrypted changes stored first",
    // both encrypted envelopes were already durably persisted to ObjectStore!
    assert!(storage.get_object("note-1").unwrap().is_some());
    assert!(storage.get_object("note-2").unwrap().is_some());
    assert_eq!(cursor.current_cursor().unwrap(), 2);
}

#[tokio::test]
async fn test_unlocked_client_applies_tombstones_and_updates_search() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let cursor = DurableSyncCursor::new(storage.clone());
    let vault_key = VaultKey::generate();
    let mut session = VaultSession::from_key(vault_key.clone());

    // Create note 1 and note 2
    let env1 = sample_encrypted_note(&vault_key, "note-alpha", "Alpha Project");
    let env2 = sample_encrypted_note(&vault_key, "note-beta", "Beta Testing");

    adapter
        .push_mutation(&PushRequest {
            mutation_id: "m-1".to_string(),
            object_id: "note-alpha".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env1,
            is_deleted: false,
        })
        .await
        .unwrap();

    adapter
        .push_mutation(&PushRequest {
            mutation_id: "m-2".to_string(),
            object_id: "note-beta".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env2.clone(),
            is_deleted: false,
        })
        .await
        .unwrap();

    // Delete note 2 (tombstone)
    adapter
        .push_mutation(&PushRequest {
            mutation_id: "m-3".to_string(),
            object_id: "note-beta".to_string(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env2,
            is_deleted: true,
        })
        .await
        .unwrap();

    // Pull with session
    let report = pull_with_session(
        &adapter,
        &storage,
        &cursor,
        &mut session,
        PullOptions::default(),
    )
    .await
    .expect("pull with session succeeds");

    assert!(report.was_unlocked);
    assert_eq!(report.applied_changes, 2);
    assert_eq!(report.final_cursor, 3);

    // Alpha note is active; Beta note was tombstoned
    let alpha_item = report
        .decrypted_items
        .iter()
        .find(|i| i.object_id == "note-alpha")
        .expect("alpha item");
    assert!(!alpha_item.is_deleted);
    assert_eq!(alpha_item.note.as_ref().unwrap().title, "Alpha Project");

    let beta_tombstone = report
        .decrypted_items
        .iter()
        .rfind(|i| i.object_id == "note-beta")
        .expect("beta tombstone");
    assert!(beta_tombstone.is_deleted);
    assert!(beta_tombstone.note.is_none());

    // Search index finds Alpha, does NOT find Beta
    let search_idx = session.search_index().unwrap();
    let alpha_results = search_idx.search("Alpha");
    assert_eq!(alpha_results.len(), 1);
    assert_eq!(alpha_results[0].id, "note-alpha");

    let beta_results = search_idx.search("Beta");
    assert!(
        beta_results.is_empty(),
        "tombstone must not appear in search results"
    );
}

#[tokio::test]
async fn test_locked_sync_behavior_defers_decryption_until_unlock() {
    let adapter = MockSyncAdapter::new();
    let storage = MemoryStorage::new();
    let cursor = DurableSyncCursor::new(storage.clone());
    let vault_key = VaultKey::generate();

    // Push notes to server
    for i in 1..=4 {
        let id = format!("locked-test-{i}");
        let env = sample_encrypted_note(&vault_key, &id, &format!("Deferred Note {i}"));
        adapter
            .push_mutation(&PushRequest {
                mutation_id: format!("l-m-{i}"),
                object_id: id,
                expected_revision: 0,
                object_kind: OBJECT_KIND_NOTE,
                envelope: env,
                is_deleted: false,
            })
            .await
            .unwrap();
    }

    // 1. Pull while LOCKED
    let mut locked_session = VaultSession::new();
    assert!(!locked_session.is_unlocked());

    let report = pull_with_session(
        &adapter,
        &storage,
        &cursor,
        &mut locked_session,
        PullOptions::default(),
    )
    .await
    .expect("pull while locked succeeds");

    assert!(!report.was_unlocked);
    assert_eq!(report.applied_changes, 4);
    assert_eq!(report.final_cursor, 4);
    assert!(report.decrypted_items.is_empty());

    // All 4 notes are durably in storage as ciphertext
    for i in 1..=4 {
        let id = format!("locked-test-{i}");
        let stored = storage.get_object(&id).unwrap().unwrap();
        assert_eq!(stored.server_seq, i as u64);
    }

    // 2. User unlocks vault later
    locked_session.unlock(vault_key);
    assert!(locked_session.is_unlocked());

    // Deferral reconciliation
    let decrypted = decrypt_stored_objects_on_unlock(&storage, &mut locked_session)
        .expect("decrypt stored objects on unlock");
    assert_eq!(decrypted.len(), 4);

    // Search index now populated
    let results = locked_session.search_index().unwrap().search("Deferred");
    assert_eq!(results.len(), 4);
}
