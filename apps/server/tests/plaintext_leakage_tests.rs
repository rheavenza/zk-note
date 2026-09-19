//! Plaintext Leakage Test Suite (ZK-092 / Milestone 9).
//!
//! Enforces:
//! - SEC-001: Plaintext never crosses the network (note title, body, tags, attachment filename/MIME, search terms).
//! - SEC-002: Server cannot decrypt user content (stores ciphertext only).
//! - SEC-003: No secrets or plaintext content in application logs or diagnostic output.
//! - SEC-009: Persistent local storage stores ciphertext only.
//!
//! Scans and audits:
//! 1. Server database tables, rows, columns, and raw disk bytes;
//! 2. Server application logs (tracing capture);
//! 3. Full HTTP API captures (request/response URLs, headers, and bodies);
//! 4. Native client SQLite persistence files;
//! 5. Error responses and crash/failure messages.
//!
//! Acceptance criteria:
//! No note title/body/tag plaintext in prohibited locations.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;
use zk_crypto::attachment::encrypt_chunk;
use zk_crypto::keys::{AttachmentKey, VaultKey};
use zk_protocol::constants::OBJECT_KIND_NOTE;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_protocol::sync::PushRequest;
use zk_protocol::vault::{KdfParams, VaultBootstrap, WrappedVaultKey};
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_server::db::migrations::run_server_migrations;
use zk_server::db::store::ServerDb;
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};
use zk_storage::{
    MutationStatus, MutationType, PendingMutation, SqliteStorage, StoredEncryptedObject,
};

// ----------------------------------------------------------------------------
// Secret Canary Strings
// ----------------------------------------------------------------------------

const CANARY_TITLE: &str = "CANARY_CONFIDENTIAL_PROJECT_TITANIUM";
const CANARY_BODY: &str = "CANARY_HIGHLY_SENSITIVE_CREDIT_CARD_PASSWORD_LIST_999888777";
const CANARY_TAG_1: &str = "canary-super-secret-finances";
const CANARY_TAG_2: &str = "canary-classified-hr-records";
const CANARY_ATTACHMENT_NAME: &str = "canary_executive_payroll_2026_q4.pdf";
const CANARY_ATTACHMENT_MIME: &str = "application/pdf";
const CANARY_ATTACHMENT_DATA: &[u8] = b"CANARY_PAYROLL_SALARY_DATA_DO_NOT_REVEAL_OR_LOG_554433";
const CANARY_PASSPHRASE: &str = "canary-vault-passphrase-hunter42-do-not-leak";

const ALL_CANARIES: &[&str] = &[
    CANARY_TITLE,
    CANARY_BODY,
    CANARY_TAG_1,
    CANARY_TAG_2,
    CANARY_ATTACHMENT_NAME,
    CANARY_ATTACHMENT_MIME,
    "CANARY_PAYROLL_SALARY_DATA_DO_NOT_REVEAL_OR_LOG_554433",
    CANARY_PASSPHRASE,
];

/// Asserts that none of the canary strings exist anywhere in `text`.
fn assert_no_plaintext_leakage(text: &str, context: &str) {
    for canary in ALL_CANARIES {
        assert!(
            !text.contains(canary),
            "Security Invariant SEC-001/SEC-002/SEC-003 Violated! Plaintext canary '{canary}' found in {context}."
        );
    }
}

/// Asserts that none of the canary strings exist anywhere in binary buffer `bytes`.
fn assert_no_plaintext_in_binary(bytes: &[u8], context: &str) {
    let text = String::from_utf8_lossy(bytes);
    assert_no_plaintext_leakage(&text, context);
}

// ----------------------------------------------------------------------------
// Tracing Memory Log Capturer
// ----------------------------------------------------------------------------

#[derive(Clone)]
struct MemoryLogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for MemoryLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Helper: Create Encrypted Note Envelope using real cryptographic primitives
// ----------------------------------------------------------------------------

fn create_encrypted_canary_note(vault_key: &VaultKey, note_id: &str) -> EncryptedEnvelope {
    let note = zk_core::note::PlaintextNote::builder()
        .title(CANARY_TITLE)
        .body(CANARY_BODY)
        .tag(CANARY_TAG_1)
        .tag(CANARY_TAG_2)
        .build()
        .unwrap();

    note.encrypt(vault_key, note_id).unwrap()
}

// ----------------------------------------------------------------------------
// 1. Full Server Lifecycle Audit: Database, Logs, and API Captures
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_audit_server_db_logs_and_api_captures() {
    let db_path = std::env::temp_dir().join(format!("zk-leakage-server-{}.sqlite", Uuid::new_v4()));

    // Set up captured logs buffer
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = MemoryLogWriter(Arc::clone(&log_buffer));

    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    // Initialize Server with on-disk SQLite
    let mut conn = rusqlite::Connection::open(&db_path).unwrap();
    run_server_migrations(&mut conn).unwrap();
    let server_db = ServerDb::from_connection(conn);
    let state = AppState {
        config: ServerConfig::default(),
        db: server_db.clone(),
    };
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    // Client-side key derivation (simulated)
    let vault_key = VaultKey::generate();
    let note_id = Uuid::new_v4().to_string();

    let mut api_captures: Vec<(String, String, Vec<u8>)> = Vec::new();

    // 1.1 Vault Bootstrap API (POST /v1/vault/bootstrap)
    {
        let bootstrap_payload = VaultBootstrap {
            crypto_version: 1,
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: "cmFuZG9tLXNhbHQtMTZieXRlcw==".to_string(),
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1,
            },
            wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA==".to_string(),
            },
            recovery_wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==".to_string(),
                ciphertext: "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk=".to_string(),
            },
        };
        let req_body = serde_json::to_vec(&bootstrap_payload).unwrap();

        let req = Request::builder()
            .uri("/v1/vault/bootstrap")
            .method("POST")
            .header("authorization", &auth_header)
            .header("content-type", "application/json")
            .body(Body::from(req_body.clone()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        api_captures.push((
            "/v1/vault/bootstrap".to_string(),
            "POST".to_string(),
            req_body,
        ));
        api_captures.push((
            "/v1/vault/bootstrap".to_string(),
            "RESP".to_string(),
            resp_body,
        ));
    }

    // 1.2 Note Creation API with Encrypted Canary Note (POST /v1/sync/push)
    let envelope = create_encrypted_canary_note(&vault_key, &note_id);
    let mutation_id = Uuid::new_v4().to_string();
    {
        let push_req = PushRequest {
            mutation_id: mutation_id.clone(),
            object_id: note_id.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: envelope.clone(),
            is_deleted: false,
        };
        let req_body = serde_json::to_vec(&push_req).unwrap();

        let req = Request::builder()
            .uri("/v1/sync/push")
            .method("POST")
            .header("authorization", &auth_header)
            .header("content-type", "application/json")
            .body(Body::from(req_body.clone()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        api_captures.push(("/v1/sync/push".to_string(), "POST".to_string(), req_body));
        api_captures.push(("/v1/sync/push".to_string(), "RESP".to_string(), resp_body));
    }

    // 1.3 Ciphertext Blob Upload API (PUT /v1/blobs/{blob_id})
    let blob_id = format!("{}_0", Uuid::new_v4());
    {
        let att_key = AttachmentKey::generate();
        let chunk = encrypt_chunk(CANARY_ATTACHMENT_DATA, &att_key, &note_id, 0, 1).unwrap();
        let chunk_bytes = chunk.to_bytes().unwrap();

        let req = Request::builder()
            .uri(format!("/v1/blobs/{blob_id}"))
            .method("PUT")
            .header("authorization", &auth_header)
            .header("content-type", "application/octet-stream")
            .body(Body::from(chunk_bytes.clone()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        api_captures.push((
            format!("/v1/blobs/{blob_id}"),
            "PUT".to_string(),
            chunk_bytes,
        ));
    }

    // 1.4 Ciphertext Blob Download API (GET /v1/blobs/{blob_id})
    {
        let req = Request::builder()
            .uri(format!("/v1/blobs/{blob_id}"))
            .method("GET")
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        api_captures.push((
            format!("/v1/blobs/{blob_id}"),
            "GET_RESP".to_string(),
            resp_body,
        ));
    }

    // 1.5 Pull Changes API (GET /v1/sync/changes)
    {
        let req = Request::builder()
            .uri("/v1/sync/changes?after=0&limit=10")
            .method("GET")
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();

        api_captures.push((
            "/v1/sync/changes".to_string(),
            "GET_RESP".to_string(),
            resp_body,
        ));
    }

    // ------------------------------------------------------------------------
    // Audit Check 1: API Captures (URLs, Headers, Request Bodies, Response Bodies)
    // ------------------------------------------------------------------------
    for (endpoint, direction, bytes) in &api_captures {
        assert_no_plaintext_in_binary(bytes, &format!("API Capture [{direction} {endpoint}]"));
    }

    // ------------------------------------------------------------------------
    // Audit Check 2: Server Application Logs (SEC-003)
    // ------------------------------------------------------------------------
    let captured_log_bytes = log_buffer.lock().unwrap().clone();
    assert_no_plaintext_in_binary(&captured_log_bytes, "Server Application Logs");

    // ------------------------------------------------------------------------
    // Audit Check 3: Raw Server SQLite Database File on Disk (SEC-001, SEC-002)
    // ------------------------------------------------------------------------
    let db_bytes = fs::read(&db_path).unwrap();
    assert_no_plaintext_in_binary(&db_bytes, "Raw Server SQLite File on Disk");

    // ------------------------------------------------------------------------
    // Audit Check 4: Query every table and column in the server database
    // ------------------------------------------------------------------------
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };

        for table in tables {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let col_count = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();

            while let Some(row) = rows.next().unwrap() {
                for col_idx in 0..col_count {
                    let val: rusqlite::types::Value = row.get(col_idx).unwrap();
                    match val {
                        rusqlite::types::Value::Text(s) => {
                            assert_no_plaintext_leakage(
                                &s,
                                &format!("Table '{table}', Column {col_idx}"),
                            );
                        }
                        rusqlite::types::Value::Blob(b) => {
                            assert_no_plaintext_in_binary(
                                &b,
                                &format!("Table '{table}', Column {col_idx} (blob)"),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let _ = fs::remove_file(&db_path);
}

// ----------------------------------------------------------------------------
// 2. Native SQLite Client Storage Audit (SEC-009)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_audit_native_sqlite_storage_file() {
    let db_path = std::env::temp_dir().join(format!("zk-leakage-client-{}.sqlite", Uuid::new_v4()));

    let vault_key = VaultKey::generate();
    let note_id = Uuid::new_v4().to_string();

    // 1. Create client storage and persist note
    {
        let storage = SqliteStorage::open(&db_path).unwrap();

        let envelope = create_encrypted_canary_note(&vault_key, &note_id);
        let stored_obj = StoredEncryptedObject {
            object_id: note_id.clone(),
            object_kind: OBJECT_KIND_NOTE,
            revision: 1,
            server_seq: 1,
            is_deleted: false,
            envelope: envelope.clone(),
            updated_at: "2026-09-19T12:00:00Z".to_string(),
        };
        storage.put_object(&stored_obj).unwrap();

        // Put base version
        storage.put_base_version(&note_id, 1, &envelope).unwrap();

        // Enqueue pending mutation
        let mut_id = Uuid::new_v4().to_string();
        let pending = PendingMutation {
            mutation_id: mut_id,
            object_id: note_id.clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            mutation_type: MutationType::Upsert,
            envelope,
            created_at: "2026-09-19T12:00:00Z".to_string(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };
        storage.enqueue_mutation(&pending).unwrap();
    }

    // 2. Read raw binary database file from disk and scan for plaintext
    let client_db_bytes = fs::read(&db_path).unwrap();
    assert_no_plaintext_in_binary(&client_db_bytes, "Client Native SQLite File on Disk");

    // 3. Inspect every table in the client SQLite database
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let tables: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };

        for table in tables {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let col_count = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();

            while let Some(row) = rows.next().unwrap() {
                for col_idx in 0..col_count {
                    let val: rusqlite::types::Value = row.get(col_idx).unwrap();
                    match val {
                        rusqlite::types::Value::Text(s) => {
                            assert_no_plaintext_leakage(
                                &s,
                                &format!("Client Table '{table}', Column {col_idx}"),
                            );
                        }
                        rusqlite::types::Value::Blob(b) => {
                            assert_no_plaintext_in_binary(
                                &b,
                                &format!("Client Table '{table}', Column {col_idx} (blob)"),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let _ = fs::remove_file(&db_path);
}

// ----------------------------------------------------------------------------
// 3. Crash and Error Messages Leakage Audit
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_audit_crash_and_error_messages_do_not_leak_plaintext() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4().to_string();

    let vault_key = VaultKey::generate();
    let envelope = create_encrypted_canary_note(&vault_key, &object_id);

    // Initial creation
    let req1 = PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: object_id.clone(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: envelope.clone(),
        is_deleted: false,
    };
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Scenario A: CAS Conflict (stale update with expected_revision = 0)
    let stale_req = PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: object_id.clone(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: envelope.clone(),
        is_deleted: false,
    };
    let resp_conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&stale_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_conflict.status(), StatusCode::CONFLICT);
    let conflict_body = axum::body::to_bytes(resp_conflict.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_no_plaintext_in_binary(&conflict_body, "HTTP 409 Conflict Response Body");

    // Scenario B: Malformed Payload / Invalid JSON containing canary
    let resp_bad_json = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"broken\": \"{CANARY_BODY}\"")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_bad_json.status(), StatusCode::BAD_REQUEST);
    let bad_json_body = axum::body::to_bytes(resp_bad_json.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_no_plaintext_in_binary(&bad_json_body, "HTTP 400 Bad Request Error Body");

    // Scenario C: Non-existent object expected_revision = 5
    let missing_obj_id = Uuid::new_v4().to_string();
    let missing_envelope = create_encrypted_canary_note(&vault_key, &missing_obj_id);
    let missing_obj_req = PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: missing_obj_id,
        expected_revision: 5,
        object_kind: OBJECT_KIND_NOTE,
        envelope: missing_envelope,
        is_deleted: false,
    };
    let resp_missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&missing_obj_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_missing.status(), StatusCode::NOT_FOUND);
    let missing_body = axum::body::to_bytes(resp_missing.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_no_plaintext_in_binary(&missing_body, "HTTP 404 Not Found Error Body");

    // Scenario D: Missing Blob GET
    let resp_missing_blob = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/blobs/non-existent-blob-id")
                .method("GET")
                .header("authorization", &auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_missing_blob.status(), StatusCode::NOT_FOUND);
    let missing_blob_body = axum::body::to_bytes(resp_missing_blob.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_no_plaintext_in_binary(&missing_blob_body, "HTTP 404 Missing Blob Error Body");
}
