//! Integration tests for Persisting Encrypted BASE Versions (ZK-050).
//!
//! Acceptance criteria validated:
//! 1. Pending edit stores reference (`expected_revision`) and base ciphertext (`encrypted_base_versions`);
//! 2. Process restart preserves merge capability (BASE, LOCAL, and REMOTE all decryptable);
//! 3. Plaintext BASE is NEVER persisted to disk or database (SEC-009).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_crypto::keys::VaultKey;
use zk_storage::models::StoredEncryptedObject;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::ObjectStore;
use zk_sync::queue::PendingMutationQueue;

fn sample_note(title: &str, body: &str, tags: &[&str]) -> PlaintextNote {
    let mut note = PlaintextNote::new(title, body);
    note.tags = tags.iter().map(|&s| s.to_string()).collect();
    note.canonicalize();
    note
}

#[test]
fn test_pending_edit_stores_reference_and_base_ciphertext() {
    let storage = Arc::new(SqliteStorage::open_in_memory().expect("open in-memory sqlite"));
    let queue = PendingMutationQueue::new(storage.clone());
    let vault_key = VaultKey::generate();

    let obj_id = Uuid::new_v4().to_string();

    // 1. Initial object creation at revision 1
    let note_v1 = sample_note(
        "Base Note Title",
        "Base note body content",
        &["tag1", "tag2"],
    );
    let env_v1 = note_v1.encrypt(&vault_key, &obj_id).expect("encrypt v1");

    let initial_stored = StoredEncryptedObject {
        object_id: obj_id.clone(),
        object_kind: zk_protocol::constants::OBJECT_KIND_NOTE,
        revision: 1,
        server_seq: 1,
        is_deleted: false,
        envelope: env_v1.clone(),
        updated_at: "2026-09-10T00:00:00Z".to_string(),
    };
    storage
        .put_object(&initial_stored)
        .expect("store initial object");

    // 2. Client performs offline edit based on revision 1
    let note_v2 = sample_note(
        "Local Edit Title",
        "Local edited body content",
        &["tag1", "edited"],
    );
    let env_v2 = note_v2.encrypt(&vault_key, &obj_id).expect("encrypt v2");

    let pending_edit = queue
        .enqueue_local_note_upsert(&obj_id, env_v2.clone())
        .expect("enqueue edit");

    // Acceptance criterion 1: Pending edit stores reference (`expected_revision`)
    assert_eq!(pending_edit.expected_revision, 1);
    assert_eq!(pending_edit.envelope, env_v2);

    // Acceptance criterion 1: Base ciphertext is durably stored in BaseVersionStore
    let base_env = queue
        .get_base_version_for_mutation(&pending_edit)
        .expect("get base version")
        .expect("base version must exist for expected_revision > 0");

    assert_eq!(base_env, env_v1);

    // Decrypting base envelope yields the exact BASE note
    let decrypted_base = PlaintextNote::decrypt(&base_env, &vault_key).expect("decrypt base");
    assert_eq!(decrypted_base.title, "Base Note Title");
    assert_eq!(decrypted_base.body, "Base note body content");
    assert_eq!(decrypted_base.tags, vec!["tag1", "tag2"]);
}

#[test]
fn test_restart_preserves_merge_capability_base_local_remote() {
    let db_dir = std::env::temp_dir().join(format!("zk_restart_test_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&db_dir).expect("create temp dir");
    let db_path = db_dir.join("test_storage.db");
    let vault_key = VaultKey::generate();
    let obj_id = Uuid::new_v4().to_string();

    // Session 1: Create note at revision 1, then enqueue offline edit based on revision 1
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite 1"));
        let queue = PendingMutationQueue::new(storage.clone());

        let base_note = sample_note(
            "Project Plan",
            "Initial architecture outline and milestones.",
            &["planning", "v1"],
        );
        let base_env = base_note
            .encrypt(&vault_key, &obj_id)
            .expect("encrypt base");

        let stored = StoredEncryptedObject {
            object_id: obj_id.clone(),
            object_kind: zk_protocol::constants::OBJECT_KIND_NOTE,
            revision: 1,
            server_seq: 10,
            is_deleted: false,
            envelope: base_env.clone(),
            updated_at: "2026-09-10T00:00:00Z".to_string(),
        };
        storage.put_object(&stored).expect("store object");

        let local_edited_note = sample_note(
            "Project Plan (Local Edit)",
            "Initial architecture outline with security invariants.",
            &["planning", "v1", "security"],
        );
        let local_env = local_edited_note
            .encrypt(&vault_key, &obj_id)
            .expect("encrypt local");

        let mutation = queue
            .enqueue_local_note_upsert(&obj_id, local_env)
            .expect("enqueue local");
        assert_eq!(mutation.expected_revision, 1);
    } // Storage connection closed here (simulating process restart)

    // Session 2: Fresh process start, reopen SQLite database from disk
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite 2"));
        let queue = PendingMutationQueue::new(storage.clone());

        // Reload pending mutations from disk
        let pending = queue.list_pending().expect("list pending");
        assert_eq!(pending.len(), 1);
        let mutation = &pending[0];
        assert_eq!(mutation.object_id, obj_id);
        assert_eq!(mutation.expected_revision, 1);

        // Reload base encrypted envelope from disk (survived process restart)
        let base_env = queue
            .get_base_version_for_mutation(mutation)
            .expect("get base version")
            .expect("base envelope survived restart");

        // Simulate conflicting remote note arriving from server (revision 2)
        let remote_note = sample_note(
            "Project Plan (Remote Team)",
            "Initial architecture outline with server API endpoints.",
            &["planning", "v1", "api"],
        );
        let remote_env = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("encrypt remote");

        // Acceptance criterion 2: Process restart preserves full 3-way merge capability!
        // 1. BASE is decryptable
        let base_decrypted =
            PlaintextNote::decrypt(&base_env, &vault_key).expect("decrypt base after restart");
        assert_eq!(base_decrypted.title, "Project Plan");
        assert_eq!(
            base_decrypted.body,
            "Initial architecture outline and milestones."
        );
        assert_eq!(base_decrypted.tags, vec!["planning", "v1"]);

        // 2. LOCAL is decryptable
        let local_decrypted = PlaintextNote::decrypt(&mutation.envelope, &vault_key)
            .expect("decrypt local after restart");
        assert_eq!(local_decrypted.title, "Project Plan (Local Edit)");
        assert_eq!(
            local_decrypted.body,
            "Initial architecture outline with security invariants."
        );
        assert_eq!(local_decrypted.tags, vec!["planning", "security", "v1"]);

        // 3. REMOTE is decryptable
        let remote_decrypted =
            PlaintextNote::decrypt(&remote_env, &vault_key).expect("decrypt remote");
        assert_eq!(remote_decrypted.title, "Project Plan (Remote Team)");
        assert_eq!(
            remote_decrypted.body,
            "Initial architecture outline with server API endpoints."
        );
        assert_eq!(remote_decrypted.tags, vec!["api", "planning", "v1"]);
    }

    let _ = std::fs::remove_dir_all(db_dir);
}

#[test]
fn test_zero_knowledge_audit_plaintext_base_is_not_persisted() {
    let db_dir = std::env::temp_dir().join(format!("zk_sec_audit_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&db_dir).expect("create temp dir");
    let db_path = db_dir.join("audit.db");
    let vault_key = VaultKey::generate();
    let obj_id = Uuid::new_v4().to_string();

    let sensitive_title = "UltraSecretFinancialPlans2026";
    let sensitive_body = "The secret bank account number is 9876-5432-1098-7654";
    let sensitive_tag = "confidentialpasscode99";

    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open sqlite for audit"));
        let queue = PendingMutationQueue::new(storage.clone());

        // Create base note
        let note = sample_note(sensitive_title, sensitive_body, &[sensitive_tag]);
        let base_env = note.encrypt(&vault_key, &obj_id).expect("encrypt base");

        let stored = StoredEncryptedObject {
            object_id: obj_id.clone(),
            object_kind: zk_protocol::constants::OBJECT_KIND_NOTE,
            revision: 1,
            server_seq: 5,
            is_deleted: false,
            envelope: base_env,
            updated_at: "2026-09-10T00:00:00Z".to_string(),
        };
        storage.put_object(&stored).expect("store object");

        // Enqueue edit: causes base version to be recorded into encrypted_base_versions
        let edited_note = sample_note(
            "DifferentTitleAfterEdit",
            "Different body after edit",
            &["differenttag"],
        );
        let edit_env = edited_note
            .encrypt(&vault_key, &obj_id)
            .expect("encrypt edit");
        queue
            .enqueue_local_note_upsert(&obj_id, edit_env)
            .expect("enqueue edit");
    }

    // Acceptance criterion 3: Plaintext BASE is NOT persisted to disk (SEC-009)
    // Read the raw binary database file from disk
    let db_bytes = std::fs::read(&db_path).expect("read raw db file");

    let forbidden_strings = [
        sensitive_title,
        sensitive_body,
        sensitive_tag,
        "9876-5432-1098-7654",
        "UltraSecret",
        "confidentialpasscode",
    ];

    for forbidden in &forbidden_strings {
        let pattern = forbidden.as_bytes();
        let found = db_bytes
            .windows(pattern.len())
            .any(|window| window == pattern);
        assert!(
            !found,
            "SEC-009 VIOLATION: plaintext base secret '{forbidden}' was found unencrypted in database file!"
        );
    }

    let _ = std::fs::remove_dir_all(db_dir);
}
