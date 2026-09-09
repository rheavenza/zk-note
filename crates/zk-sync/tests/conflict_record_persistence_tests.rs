//! Comprehensive integration tests for Conflict Record Model (ZK-053).
//!
//! Validates:
//! 1. Survives process restart with SQLite persistence;
//! 2. Contains enough information to retry after resolution (KeepLocal, KeepRemote, Merge, Duplicate);
//! 3. Zero-knowledge persistence (SEC-009): no plaintext durable conflict body in SQLite on disk.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_storage::models::ConflictRecord;
use zk_storage::sqlite::SqliteStorage;
use zk_storage::traits::{ConflictStore, ObjectStore};
use zk_sync::conflict::{generate_merge_candidate, resolve_conflict, ConflictResolutionStrategy};
use zk_sync::queue::PendingMutationQueue;

fn temp_db_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("zk_conflict_test_{}_{}.db", name, Uuid::new_v4()));
    path
}

#[test]
fn test_conflict_record_survives_restart_with_sqlite() {
    let db_path = temp_db_path("survives_restart");
    let _ = fs::remove_file(&db_path);

    let vault_key = VaultKey::generate();
    let object_id = Uuid::new_v4().to_string();

    // 1. Create base, local, and remote plaintext notes
    let base_note = PlaintextNote::new("Project Roadmap", "# Q3 Roadmap\nOriginal plan.");
    let local_note = PlaintextNote::new("Project Roadmap", "# Q3 Roadmap\nAlice local update.");
    let remote_note = PlaintextNote::new("Project Roadmap", "# Q3 Roadmap\nBob remote update.");

    let base_envelope = base_note
        .encrypt(&vault_key, &object_id)
        .expect("encrypt base");
    let local_envelope = local_note
        .encrypt(&vault_key, &object_id)
        .expect("encrypt local");
    let remote_envelope = remote_note
        .encrypt(&vault_key, &object_id)
        .expect("encrypt remote");

    let (merge_outcome, candidate_envelope) = generate_merge_candidate(
        Some(&base_envelope),
        &local_envelope,
        &remote_envelope,
        &vault_key,
    )
    .expect("generate candidate");

    assert!(!merge_outcome.is_clean()); // divergent body lines

    let conflict_id = Uuid::new_v4().to_string();
    let created_at = "2026-09-10T03:00:00Z".to_string();

    let record = ConflictRecord::new(
        &conflict_id,
        &object_id,
        OBJECT_KIND_NOTE,
        5, // base revision
        6, // remote revision
        Some(base_envelope.clone()),
        local_envelope.clone(),
        remote_envelope.clone(),
        Some(candidate_envelope.clone()),
        &created_at,
    );

    // 2. Persist to SQLite and close connection
    {
        let storage = SqliteStorage::open(&db_path).expect("open initial");
        storage.put_conflict(&record).expect("put conflict");

        let active = storage
            .get_active_conflict_for_object(&object_id)
            .expect("get active")
            .expect("must exist");
        assert_eq!(active.conflict_id, conflict_id);
        assert_eq!(active.base_revision, 5);
        assert_eq!(active.remote_revision, 6);
        assert!(!active.resolved);
    }

    // 3. Reopen SQLite database (simulating full process restart)
    {
        let reopened = SqliteStorage::open(&db_path).expect("reopen");

        let fetched = reopened
            .get_conflict(&conflict_id)
            .expect("get conflict")
            .expect("conflict record must survive restart");

        assert_eq!(fetched.conflict_id, conflict_id);
        assert_eq!(fetched.object_id, object_id);
        assert_eq!(fetched.object_kind, OBJECT_KIND_NOTE);
        assert_eq!(fetched.base_revision, 5);
        assert_eq!(fetched.remote_revision, 6);
        assert_eq!(fetched.base_envelope, Some(base_envelope.clone()));
        assert_eq!(fetched.local_envelope, local_envelope);
        assert_eq!(fetched.remote_envelope, remote_envelope);
        assert_eq!(fetched.candidate_envelope, Some(candidate_envelope.clone()));
        assert!(!fetched.resolved);
        assert_eq!(fetched.created_at, created_at);
        assert_eq!(fetched.resolved_at, None);

        // Verify decrypted candidate contains diff3 conflict markers
        let cand_note = PlaintextNote::decrypt(&fetched.candidate_envelope.unwrap(), &vault_key)
            .expect("decrypt candidate");
        assert!(cand_note.body.contains("<<<<<<< LOCAL"));
        assert!(cand_note.body.contains("Alice local update"));
        assert!(cand_note.body.contains("||||||| BASE"));
        assert!(cand_note.body.contains("Original plan"));
        assert!(cand_note.body.contains("======="));
        assert!(cand_note.body.contains("Bob remote update"));
        assert!(cand_note.body.contains(">>>>>>> REMOTE"));
    }

    let _ = fs::remove_file(&db_path);
}

#[test]
fn test_conflict_resolution_strategies_provide_sufficient_retry_information() {
    let db_path = temp_db_path("resolution_retry");
    let _ = fs::remove_file(&db_path);

    let vault_key = VaultKey::generate();

    // Scenario A: KeepLocal resolution creates mutation with expected_revision = remote_revision
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open"));
        let queue = PendingMutationQueue::new(storage.clone());

        let obj_id = Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Local Note", "Local Body");
        let remote_note = PlaintextNote::new("Remote Note", "Remote Body");

        let local_env = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let remote_env = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = Uuid::new_v4().to_string();
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            2,
            3,
            None,
            local_env.clone(),
            remote_env.clone(),
            None,
            "2026-09-10T03:00:00Z",
        );
        storage.put_conflict(&record).expect("put");

        let res = resolve_conflict(
            &storage,
            &queue,
            &vault_key,
            &conf_id,
            ConflictResolutionStrategy::KeepLocal,
        )
        .expect("resolve keep local");

        assert_eq!(res.conflict_id, conf_id);
        assert_eq!(res.object_id, obj_id);

        let retry_mut = res.retry_mutation.expect("retry mutation created");
        assert_eq!(retry_mut.object_id, obj_id);
        assert_eq!(
            retry_mut.expected_revision, 3,
            "must use remote_revision as expected_revision for CAS retry"
        );
        assert_eq!(retry_mut.envelope, local_env);

        let active = storage
            .get_active_conflict_for_object(&obj_id)
            .expect("active");
        assert!(active.is_none(), "conflict must be marked resolved");
    }

    // Scenario B: KeepRemote resolution accepts remote revision and discards local mutation
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open"));
        let queue = PendingMutationQueue::new(storage.clone());

        let obj_id = Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Local Note", "Local Body");
        let remote_note = PlaintextNote::new("Remote Note", "Remote Body");

        let local_env = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let remote_env = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = Uuid::new_v4().to_string();
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            2,
            3,
            None,
            local_env,
            remote_env.clone(),
            None,
            "2026-09-10T03:00:00Z",
        );
        storage.put_conflict(&record).expect("put");

        let res = resolve_conflict(
            &storage,
            &queue,
            &vault_key,
            &conf_id,
            ConflictResolutionStrategy::KeepRemote,
        )
        .expect("resolve keep remote");

        assert!(
            res.retry_mutation.is_none(),
            "no push needed for KeepRemote"
        );

        // Local head object is updated to remote revision
        let local_head = storage
            .get_object(&obj_id)
            .expect("get")
            .expect("head exists");
        assert_eq!(local_head.revision, 3);
        assert_eq!(local_head.envelope, remote_env);
    }

    // Scenario C: Merge resolution creates mutation with merged candidate and expected_revision = remote_revision
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open"));
        let queue = PendingMutationQueue::new(storage.clone());

        let obj_id = Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Note", "Part A\nBase B");
        let remote_note = PlaintextNote::new("Note", "Base A\nPart B");

        let local_env = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let remote_env = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = Uuid::new_v4().to_string();
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            1,
            2,
            None,
            local_env,
            remote_env,
            None,
            "2026-09-10T03:00:00Z",
        );
        storage.put_conflict(&record).expect("put");

        let merged_note = PlaintextNote::new("Note Resolved", "Part A\nPart B merged by user");
        let res = resolve_conflict(
            &storage,
            &queue,
            &vault_key,
            &conf_id,
            ConflictResolutionStrategy::Merge(merged_note.clone()),
        )
        .expect("resolve merge");

        let retry_mut = res.retry_mutation.expect("retry mutation created");
        assert_eq!(retry_mut.expected_revision, 2);

        let decrypted = PlaintextNote::decrypt(&retry_mut.envelope, &vault_key).expect("dec");
        assert_eq!(decrypted.title, "Note Resolved");
        assert_eq!(decrypted.body, "Part A\nPart B merged by user");
    }

    // Scenario D: DuplicateAsSeparate creates new note and preserves remote on original
    {
        let storage = Arc::new(SqliteStorage::open(&db_path).expect("open"));
        let queue = PendingMutationQueue::new(storage.clone());

        let obj_id = Uuid::new_v4().to_string();
        let local_note = PlaintextNote::new("Original Title", "Alice local work");
        let remote_note = PlaintextNote::new("Original Title", "Bob remote work");

        let local_env = local_note.encrypt(&vault_key, &obj_id).expect("enc local");
        let remote_env = remote_note
            .encrypt(&vault_key, &obj_id)
            .expect("enc remote");

        let conf_id = Uuid::new_v4().to_string();
        let record = ConflictRecord::new(
            &conf_id,
            &obj_id,
            OBJECT_KIND_NOTE,
            4,
            5,
            None,
            local_env,
            remote_env.clone(),
            None,
            "2026-09-10T03:00:00Z",
        );
        storage.put_conflict(&record).expect("put");

        let new_id = Uuid::new_v4().to_string();
        let res = resolve_conflict(
            &storage,
            &queue,
            &vault_key,
            &conf_id,
            ConflictResolutionStrategy::DuplicateAsSeparate {
                new_object_id: new_id.clone(),
                new_title: Some("Original Title (Local Copy)".to_string()),
            },
        )
        .expect("resolve duplicate");

        assert_eq!(res.duplicated_object_id, Some(new_id.clone()));

        // Check original note is now at remote revision 5
        let orig_head = storage.get_object(&obj_id).expect("get").expect("exists");
        assert_eq!(orig_head.revision, 5);
        assert_eq!(orig_head.envelope, remote_env);

        // Check new note has a pending mutation at expected_revision = 0
        let dup_mut = res.retry_mutation.expect("duplicate mutation created");
        assert_eq!(dup_mut.object_id, new_id);
        assert_eq!(dup_mut.expected_revision, 0);

        let dup_note = PlaintextNote::decrypt(&dup_mut.envelope, &vault_key).expect("dec dup");
        assert_eq!(dup_note.title, "Original Title (Local Copy)");
        assert_eq!(dup_note.body, "Alice local work");
    }

    let _ = fs::remove_file(&db_path);
}

#[test]
fn test_conflict_records_zero_knowledge_audit_no_plaintext_leakage() {
    let db_path = temp_db_path("zk_audit_no_leakage");
    let _ = fs::remove_file(&db_path);

    let vault_key = VaultKey::generate();
    let object_id = Uuid::new_v4().to_string();

    let canary_base_title = "CANARY_BASE_TITLE_TOP_SECRET_1111";
    let canary_base_body = "CANARY_BASE_BODY_TOP_SECRET_2222";
    let canary_local_title = "CANARY_LOCAL_TITLE_TOP_SECRET_3333";
    let canary_local_body = "CANARY_LOCAL_BODY_TOP_SECRET_4444";
    let canary_remote_title = "CANARY_REMOTE_TITLE_TOP_SECRET_5555";
    let canary_remote_body = "CANARY_REMOTE_BODY_TOP_SECRET_6666";
    let canary_cand_body = "CANARY_CANDIDATE_BODY_TOP_SECRET_7777";

    let base_note = PlaintextNote::new(canary_base_title, canary_base_body);
    let local_note = PlaintextNote::new(canary_local_title, canary_local_body);
    let remote_note = PlaintextNote::new(canary_remote_title, canary_remote_body);
    let cand_note = PlaintextNote::new("Cand Title", canary_cand_body);

    let base_env = base_note.encrypt(&vault_key, &object_id).expect("base");
    let local_env = local_note.encrypt(&vault_key, &object_id).expect("local");
    let remote_env = remote_note.encrypt(&vault_key, &object_id).expect("remote");
    let cand_env = cand_note.encrypt(&vault_key, &object_id).expect("cand");

    let conflict = ConflictRecord::new(
        "conf-canary-1",
        &object_id,
        OBJECT_KIND_NOTE,
        1,
        2,
        Some(base_env),
        local_env,
        remote_env,
        Some(cand_env),
        "2026-09-10T03:00:00Z",
    );

    {
        let storage = SqliteStorage::open(&db_path).expect("open");
        storage.put_conflict(&conflict).expect("put conflict");
    }

    // Read raw binary disk image of SQLite file
    let file_bytes = fs::read(&db_path).expect("read db file");
    let file_str = String::from_utf8_lossy(&file_bytes);

    assert!(
        !file_str.contains(canary_base_title),
        "SEC-009 violation: base title leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_base_body),
        "SEC-009 violation: base body leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_local_title),
        "SEC-009 violation: local title leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_local_body),
        "SEC-009 violation: local body leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_remote_title),
        "SEC-009 violation: remote title leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_remote_body),
        "SEC-009 violation: remote body leaked into SQLite on disk!"
    );
    assert!(
        !file_str.contains(canary_cand_body),
        "SEC-009 violation: candidate body leaked into SQLite on disk!"
    );

    let _ = fs::remove_file(&db_path);
}
