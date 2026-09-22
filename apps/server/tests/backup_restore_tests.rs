//! Backup and Restore Verification Test Suite (ZK-096).
//!
//! Enforces:
//! 1. Database backup capture (transactionally consistent SQLite snapshot);
//! 2. Zero-Knowledge backup audit: Server backup contains ONLY ciphertext and opaque metadata,
//!    with ZERO note titles, bodies, tags, attachment plaintexts, or passphrases (SEC-001, SEC-002);
//! 3. Database restoration into a completely fresh server instance;
//! 4. Fresh authorized client synchronization and in-memory decryption using user-held secrets;
//! 5. Continued operational integrity: Sequence allocator and CAS mutations continue seamlessly on restored DB.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_crypto::attachment::{decrypt_chunk, encrypt_chunk};
use zk_crypto::keys::{AttachmentKey, RecoveryKey, VaultKey};
use zk_crypto::vault::{unwrap_vault_key, wrap_vault_key, wrap_vault_key_recovery};
use zk_protocol::attachment::EncryptedChunk;
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::sync::{PullChangesResponse, PushRequest};
use zk_protocol::vault::VaultBootstrap;
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_server::db::migrations::run_server_migrations;
use zk_server::db::store::ServerDb;

const CANARY_PASSPHRASE: &str = "correct-battery-horse-staple-vault-2026!";
const CANARY_NOTE_TITLE_1: &str = "CANARY_CONFIDENTIAL_ROADMAP_TITLE";
const CANARY_NOTE_BODY_1: &str = "CANARY_HIGHLY_SECRET_NOTE_BODY_DATA_998877";
const CANARY_NOTE_TAG_1: &str = "canary-tag-strategy";

const CANARY_NOTE_TITLE_2: &str = "CANARY_PERSONAL_FINANCIAL_RECORD";
const CANARY_NOTE_BODY_2: &str = "CANARY_SAVINGS_ACCOUNT_DETAILS_1234_5678";

const CANARY_NOTE_TITLE_3: &str = "CANARY_DELETE_ME_SOON";
const CANARY_NOTE_BODY_3: &str = "CANARY_EPHEMERAL_BODY_CONTENT";

const CANARY_ATTACHMENT_PLAINTEXT: &[u8] =
    b"CANARY_SECRET_ATTACHMENT_EMBEDDED_DOCUMENT_BYTES_XYZ_999";

const ALL_CANARIES: &[&str] = &[
    CANARY_PASSPHRASE,
    CANARY_NOTE_TITLE_1,
    CANARY_NOTE_BODY_1,
    CANARY_NOTE_TAG_1,
    CANARY_NOTE_TITLE_2,
    CANARY_NOTE_BODY_2,
    CANARY_NOTE_TITLE_3,
    CANARY_NOTE_BODY_3,
];

fn assert_no_canaries_in_bytes(data: &[u8], context: &str) {
    for canary in ALL_CANARIES {
        assert!(
            !data.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "SECURITY VIOLATION ({context}): Prohibited plaintext canary '{canary}' found in backup!"
        );
    }
    assert!(
        !data
            .windows(CANARY_ATTACHMENT_PLAINTEXT.len())
            .any(|w| w == CANARY_ATTACHMENT_PLAINTEXT),
        "SECURITY VIOLATION ({context}): Prohibited plaintext attachment bytes found in backup!"
    );
}

#[tokio::test]
async fn test_full_server_backup_restore_and_client_decryption_lifecycle() {
    let temp_dir = std::env::temp_dir();
    let run_id = Uuid::new_v4();
    let original_db_path = temp_dir.join(format!("zk-original-{run_id}.sqlite"));
    let backup_db_path = temp_dir.join(format!("zk-backup-{run_id}.sqlite"));
    let restored_db_path = temp_dir.join(format!("zk-restored-{run_id}.sqlite"));

    let account_id = Uuid::new_v4();
    let auth_header;

    let attachment_key = AttachmentKey::generate();
    let note_id_1 = Uuid::new_v4().to_string();

    // ------------------------------------------------------------------------
    // Phase 1: Initialize Original Server Instance
    // ------------------------------------------------------------------------
    {
        let mut conn = rusqlite::Connection::open(&original_db_path).unwrap();
        run_server_migrations(&mut conn).unwrap();
        let server_db = ServerDb::from_connection(conn);
        let state = AppState {
            config: ServerConfig::default(),
            db: server_db,
        };
        auth_header = common::bearer(&state, account_id).await;
        let app = create_app(state.clone());

        // 1.1 Client-side Key Derivation & Vault Bootstrap
        let vault_key = VaultKey::generate();
        let crypto_kdf = zk_crypto::kdf::KdfParams::new_production();
        let kek = zk_crypto::kdf::derive_kek(CANARY_PASSPHRASE.as_bytes(), &crypto_kdf).unwrap();

        let wrapped_vault_key = wrap_vault_key(&vault_key, &kek).unwrap();
        let recovery_key = RecoveryKey::generate();
        let recovery_wrapped_vault_key =
            wrap_vault_key_recovery(&vault_key, &recovery_key).unwrap();

        let bootstrap_payload = VaultBootstrap {
            crypto_version: 1,
            kdf: crypto_kdf.into(),
            wrapped_vault_key: wrapped_vault_key.into(),
            recovery_wrapped_vault_key: recovery_wrapped_vault_key.into(),
        };

        let resp_boot = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/vault/bootstrap")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bootstrap_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_boot.status(), StatusCode::CREATED);

        // 1.2 Push Note 1 (Created, Rev 1)
        let note_1 = PlaintextNote::builder()
            .title(CANARY_NOTE_TITLE_1)
            .body(CANARY_NOTE_BODY_1)
            .tag(CANARY_NOTE_TAG_1)
            .build()
            .unwrap();
        let env_1 = note_1.encrypt(&vault_key, &note_id_1).unwrap();

        let push_1 = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: note_id_1.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_1,
            is_deleted: false,
        };
        let resp_p1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_p1.status(), StatusCode::OK);

        // 1.3 Push Note 2 (Created, Rev 1, then Updated to Rev 2)
        let note_id_2 = Uuid::new_v4().to_string();
        let note_2_v1 = PlaintextNote::builder()
            .title("Note 2 Initial")
            .body("Initial body")
            .build()
            .unwrap();
        let env_2_v1 = note_2_v1.encrypt(&vault_key, &note_id_2).unwrap();
        let push_2_v1 = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: note_id_2.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_2_v1,
            is_deleted: false,
        };
        let resp_p2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_2_v1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_p2.status(), StatusCode::OK);

        // Note 2 Update to Rev 2 with Canary 2 Content
        let note_2_v2 = PlaintextNote::builder()
            .title(CANARY_NOTE_TITLE_2)
            .body(CANARY_NOTE_BODY_2)
            .build()
            .unwrap();
        let env_2_v2 = note_2_v2.encrypt(&vault_key, &note_id_2).unwrap();
        let push_2_v2 = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: note_id_2.clone(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_2_v2,
            is_deleted: false,
        };
        let resp_p2_v2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_2_v2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_p2_v2.status(), StatusCode::OK);

        // 1.4 Push Note 3 (Created, then Deleted to Rev 2 tombstone)
        let note_id_3 = Uuid::new_v4().to_string();
        let note_3 = PlaintextNote::builder()
            .title(CANARY_NOTE_TITLE_3)
            .body(CANARY_NOTE_BODY_3)
            .build()
            .unwrap();
        let env_3 = note_3.encrypt(&vault_key, &note_id_3).unwrap();
        let push_3_v1 = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: note_id_3.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_3.clone(),
            is_deleted: false,
        };
        let resp_p3 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_3_v1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_p3.status(), StatusCode::OK);

        let push_3_del = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: note_id_3.clone(),
            expected_revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: env_3,
            is_deleted: true,
        };
        let resp_p3_del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_3_del).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_p3_del.status(), StatusCode::OK);

        // 1.5 Upload Ciphertext Blob Attachment
        let chunk = encrypt_chunk(
            CANARY_ATTACHMENT_PLAINTEXT,
            &attachment_key,
            &note_id_1,
            0,
            1,
        )
        .unwrap();
        let chunk_bytes = chunk.to_bytes().unwrap();
        let blob_id = "canary-backup-attachment-blob-1";
        let resp_blob = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/blobs/{blob_id}"))
                    .header("authorization", &auth_header)
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(chunk_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_blob.status(), StatusCode::CREATED);

        // --------------------------------------------------------------------
        // Phase 2: Create Transactionally Consistent Database Backup
        // --------------------------------------------------------------------
        let backup_snap_conn = rusqlite::Connection::open(&original_db_path).unwrap();
        let backup_sql = format!("VACUUM INTO '{}'", backup_db_path.to_str().unwrap());
        backup_snap_conn.execute(&backup_sql, []).unwrap();
    } // Original connection and app closed here

    // ------------------------------------------------------------------------
    // Phase 3: Zero-Knowledge Audit on Backup Snapshot File
    // ------------------------------------------------------------------------
    {
        // 3.1 Inspect all database rows and columns in the backup SQLite file
        let backup_conn = rusqlite::Connection::open(&backup_db_path).unwrap();

        let mut tables_stmt = backup_conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let tables: Vec<String> = tables_stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        for table in &tables {
            let mut stmt = backup_conn
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap();
            let col_count = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();

            while let Some(row) = rows.next().unwrap() {
                for col_idx in 0..col_count {
                    let val: rusqlite::types::Value = row.get(col_idx).unwrap();
                    match val {
                        rusqlite::types::Value::Text(s) => {
                            assert_no_canaries_in_bytes(
                                s.as_bytes(),
                                &format!("Backup Table '{table}', Column {col_idx}"),
                            );
                        }
                        rusqlite::types::Value::Blob(b) => {
                            assert_no_canaries_in_bytes(
                                &b,
                                &format!("Backup Table '{table}', Column {col_idx} (blob)"),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        // 3.2 Audit the raw disk bytes of the backup file
        let raw_backup_bytes = fs::read(&backup_db_path).unwrap();
        assert_no_canaries_in_bytes(&raw_backup_bytes, "Raw Backup .sqlite file on disk");
    }

    // ------------------------------------------------------------------------
    // Phase 4: Restore Backup into Fresh Server Instance
    // ------------------------------------------------------------------------
    fs::copy(&backup_db_path, &restored_db_path).unwrap();

    let restored_conn = rusqlite::Connection::open(&restored_db_path).unwrap();
    let restored_server_db = ServerDb::from_connection(restored_conn);
    let restored_state = AppState {
        config: ServerConfig::default(),
        db: restored_server_db,
    };
    let restored_app = create_app(restored_state);

    // ------------------------------------------------------------------------
    // Phase 5: Fresh Authorized Client Synchronization & Decryption
    // ------------------------------------------------------------------------
    {
        // 5.1 Fresh Client fetches Vault Bootstrap from Restored Server
        let resp_boot = restored_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/vault/bootstrap")
                    .header("authorization", &auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_boot.status(), StatusCode::OK);
        let boot_bytes = axum::body::to_bytes(resp_boot.into_body(), usize::MAX)
            .await
            .unwrap();
        let restored_bootstrap: VaultBootstrap = serde_json::from_slice(&boot_bytes).unwrap();

        // 5.2 Client derives KEK from passphrase and unwraps VaultKey
        let restored_crypto_kdf: zk_crypto::kdf::KdfParams = restored_bootstrap.kdf.into();
        let restored_kek =
            zk_crypto::kdf::derive_kek(CANARY_PASSPHRASE.as_bytes(), &restored_crypto_kdf).unwrap();

        let restored_wrapped: zk_crypto::vault::WrappedVaultKey =
            restored_bootstrap.wrapped_vault_key.into();
        let restored_vault_key = unwrap_vault_key(&restored_wrapped, &restored_kek).unwrap();

        // 5.3 Client pulls all changes from Restored Server
        let resp_changes = restored_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/sync/changes?since=0&limit=50")
                    .header("authorization", &auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_changes.status(), StatusCode::OK);
        let changes_bytes = axum::body::to_bytes(resp_changes.into_body(), usize::MAX)
            .await
            .unwrap();
        let changes_resp: PullChangesResponse = serde_json::from_slice(&changes_bytes).unwrap();

        // Must receive all 3 objects
        assert_eq!(changes_resp.changes.len(), 3);

        // Find Note 1
        let ch_1 = changes_resp
            .changes
            .iter()
            .find(|c| !c.is_deleted && c.revision == 1)
            .unwrap();
        let decrypted_note_1 = PlaintextNote::decrypt(&ch_1.envelope, &restored_vault_key).unwrap();
        assert_eq!(decrypted_note_1.title, CANARY_NOTE_TITLE_1);
        assert_eq!(decrypted_note_1.body, CANARY_NOTE_BODY_1);
        assert!(decrypted_note_1
            .tags
            .contains(&CANARY_NOTE_TAG_1.to_string()));

        // Find Note 2 (Must be Rev 2 with updated content)
        let ch_2 = changes_resp
            .changes
            .iter()
            .find(|c| !c.is_deleted && c.revision == 2)
            .unwrap();
        let decrypted_note_2 = PlaintextNote::decrypt(&ch_2.envelope, &restored_vault_key).unwrap();
        assert_eq!(decrypted_note_2.title, CANARY_NOTE_TITLE_2);
        assert_eq!(decrypted_note_2.body, CANARY_NOTE_BODY_2);

        // Find Note 3 (Must be Tombstone)
        let ch_3 = changes_resp.changes.iter().find(|c| c.is_deleted).unwrap();
        assert_eq!(ch_3.revision, 2);
        assert!(ch_3.is_deleted);

        // 5.4 Download and Decrypt Attachment Blob from Restored Server
        let blob_id = "canary-backup-attachment-blob-1";
        let resp_blob = restored_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/blobs/{blob_id}"))
                    .header("authorization", &auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_blob.status(), StatusCode::OK);
        let blob_bytes = axum::body::to_bytes(resp_blob.into_body(), usize::MAX)
            .await
            .unwrap();

        let restored_chunk = EncryptedChunk::from_bytes(&blob_bytes).unwrap();
        let decrypted_attachment_bytes = decrypt_chunk(&restored_chunk, &attachment_key).unwrap();
        assert_eq!(decrypted_attachment_bytes, CANARY_ATTACHMENT_PLAINTEXT);

        // 5.5 Seamless Mutation Continuation on Restored Database (CAS and Sequence Monotonicity)
        let new_note_id = Uuid::new_v4().to_string();
        let new_note = PlaintextNote::builder()
            .title("Post-Restore New Note")
            .body("Created after database restoration")
            .build()
            .unwrap();
        let new_env = new_note.encrypt(&restored_vault_key, &new_note_id).unwrap();
        let new_push = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: new_note_id.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: new_env,
            is_deleted: false,
        };

        let resp_new = restored_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_header)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&new_push).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_new.status(), StatusCode::OK);

        // Pull again and verify new note is returned with sequence > previous max
        let resp_pull_final = restored_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v1/sync/changes?since={}&limit=10",
                        changes_resp.next_cursor
                    ))
                    .header("authorization", &auth_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_pull_final.status(), StatusCode::OK);
        let final_bytes = axum::body::to_bytes(resp_pull_final.into_body(), usize::MAX)
            .await
            .unwrap();
        let final_changes: PullChangesResponse = serde_json::from_slice(&final_bytes).unwrap();
        assert_eq!(final_changes.changes.len(), 1);
        assert_eq!(final_changes.changes[0].object_id, new_note_id);
        assert_eq!(final_changes.changes[0].revision, 1);
    }

    // Clean up temporary test files
    let _ = fs::remove_file(original_db_path);
    let _ = fs::remove_file(backup_db_path);
    let _ = fs::remove_file(restored_db_path);
}

mod common;
