//! Integration tests for NativeHttpSyncAdapter (ZK-040).
//!
//! Validates:
//! 1. Protocol models shared from `zk-protocol`;
//! 2. Authenticated requests abstracted;
//! 3. Network errors strongly typed;
//! 4. Zero-knowledge enforcement: no plaintext payload fields.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64ct::{Base64, Encoding};
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::PushRequest;
use zk_protocol::vault::{KdfParams, VaultBootstrap, WrappedVaultKey};
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_sync::adapter::{validate_no_plaintext_secrets, NativeHttpSyncAdapter, SyncServerAdapter};
use zk_sync::error::SyncNetworkError;

struct TestServer {
    base_url: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_test_server() -> TestServer {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init test app state");
    let app = create_app(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("get local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    TestServer {
        base_url: format!("http://{}", local_addr),
        shutdown_tx: Some(shutdown_tx),
    }
}

fn sample_envelope(object_id: &str) -> EncryptedEnvelope {
    EncryptedEnvelope {
        envelope_version: ENVELOPE_VERSION_V1,
        object_id: object_id.to_string(),
        object_kind: OBJECT_KIND_NOTE,
        wrapped_key: EncryptedKeyContainer {
            nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
            ciphertext: "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==".to_string(),
        },
        payload: EncryptedPayloadContainer {
            nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
            ciphertext: Base64::encode_string(b"opaque-encrypted-content-sample"),
        },
    }
}

fn sample_bootstrap() -> VaultBootstrap {
    VaultBootstrap {
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
    }
}

#[tokio::test]
async fn test_adapter_auth_token_abstraction_and_unauthorized() {
    let server = start_test_server().await;
    let adapter = NativeHttpSyncAdapter::new(&server.base_url, None).expect("init adapter");

    // 1. Unauthenticated request fails closed with typed Unauthorized error
    let err = adapter.get_vault_bootstrap().await.expect_err("must fail");
    assert!(
        matches!(err, SyncNetworkError::Unauthorized(_)),
        "expected Unauthorized error, got {err:?}"
    );

    // 2. Malformed token fails closed
    adapter.set_auth_token(Some("not-a-valid-uuid".to_string()));
    let malformed_err = adapter.get_vault_bootstrap().await.expect_err("must fail");
    assert!(
        matches!(malformed_err, SyncNetworkError::Unauthorized(_)),
        "expected Unauthorized error on malformed token, got {malformed_err:?}"
    );

    // 3. Valid UUID token succeeds and abstracts Authorization header
    let account_token = Uuid::new_v4().to_string();
    adapter.set_auth_token(Some(account_token));
    let bootstrap_opt = adapter
        .get_vault_bootstrap()
        .await
        .expect("authorized call succeeds");
    assert!(
        bootstrap_opt.is_none(),
        "bootstrap should be empty for new account"
    );
}

#[tokio::test]
async fn test_adapter_vault_bootstrap_round_trip() {
    let server = start_test_server().await;
    let account_token = Uuid::new_v4().to_string();
    let adapter =
        NativeHttpSyncAdapter::new(&server.base_url, Some(account_token)).expect("init adapter");

    let initial = adapter.get_vault_bootstrap().await.unwrap();
    assert!(initial.is_none());

    let bootstrap = sample_bootstrap();
    adapter
        .post_vault_bootstrap(&bootstrap)
        .await
        .expect("post bootstrap");

    let retrieved = adapter
        .get_vault_bootstrap()
        .await
        .expect("get bootstrap")
        .expect("bootstrap must exist");

    assert_eq!(retrieved.crypto_version, bootstrap.crypto_version);
    assert_eq!(retrieved.kdf, bootstrap.kdf);
    assert_eq!(
        retrieved.wrapped_vault_key.ciphertext,
        bootstrap.wrapped_vault_key.ciphertext
    );
    assert_eq!(
        retrieved.recovery_wrapped_vault_key.ciphertext,
        bootstrap.recovery_wrapped_vault_key.ciphertext
    );
}

#[tokio::test]
async fn test_adapter_cas_push_and_typed_conflicts() {
    let server = start_test_server().await;
    let account_token = Uuid::new_v4().to_string();
    let adapter = NativeHttpSyncAdapter::new(&server.base_url, Some(account_token)).unwrap();

    let obj_id = Uuid::new_v4().to_string();
    let mutation_1 = Uuid::new_v4().to_string();

    let push_req = PushRequest {
        mutation_id: mutation_1.clone(),
        object_id: obj_id.clone(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: sample_envelope(&obj_id),
        is_deleted: false,
    };

    // 1. Initial push
    let resp1 = adapter.push_mutation(&push_req).await.unwrap();
    assert_eq!(resp1.object_id, obj_id);
    assert_eq!(resp1.revision, 1);
    assert_eq!(resp1.server_seq, 1);

    // 2. Idempotent replay returns same response
    let resp1_replay = adapter.push_mutation(&push_req).await.unwrap();
    assert_eq!(resp1_replay.revision, 1);
    assert_eq!(resp1_replay.server_seq, 1);

    // 3. Stale revision (expected_revision: 0) causes typed Conflict
    let stale_req = PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: obj_id.clone(),
        expected_revision: 0,
        object_kind: OBJECT_KIND_NOTE,
        envelope: sample_envelope(&obj_id),
        is_deleted: false,
    };
    let conflict_err = adapter.push_mutation(&stale_req).await.unwrap_err();
    match conflict_err {
        SyncNetworkError::Conflict(c) => {
            assert_eq!(c.object_id, obj_id);
            assert_eq!(c.expected_revision, 0);
            assert_eq!(c.current_revision, 1);
            assert_eq!(c.current_server_seq, 1);
        }
        other => panic!("expected Conflict, got {:?}", other),
    }

    // 4. Replay with mismatched payload causes typed ReplayMismatch
    let tampered_replay = PushRequest {
        mutation_id: mutation_1,
        object_id: obj_id.clone(),
        expected_revision: 99,
        object_kind: OBJECT_KIND_NOTE,
        envelope: sample_envelope(&obj_id),
        is_deleted: false,
    };
    let replay_err = adapter.push_mutation(&tampered_replay).await.unwrap_err();
    assert!(
        matches!(replay_err, SyncNetworkError::ReplayMismatch(_)),
        "expected ReplayMismatch, got {:?}",
        replay_err
    );
}

#[tokio::test]
async fn test_adapter_pull_changes_pagination_and_tombstones() {
    let server = start_test_server().await;
    let account_token = Uuid::new_v4().to_string();
    let adapter = NativeHttpSyncAdapter::new(&server.base_url, Some(account_token)).unwrap();

    let obj1 = Uuid::new_v4().to_string();
    let obj2 = Uuid::new_v4().to_string();
    let obj3 = Uuid::new_v4().to_string();

    for id in [&obj1, &obj2, &obj3] {
        let req = PushRequest {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: (*id).clone(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: sample_envelope(id),
            is_deleted: false,
        };
        adapter.push_mutation(&req).await.unwrap();
    }

    // Delete obj2 (tombstone)
    let delete_req = PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: obj2.clone(),
        expected_revision: 1,
        object_kind: OBJECT_KIND_NOTE,
        envelope: sample_envelope(&obj2),
        is_deleted: true,
    };
    let del_resp = adapter.push_mutation(&delete_req).await.unwrap();
    assert_eq!(del_resp.revision, 2);
    assert_eq!(del_resp.server_seq, 4);

    // Pull page 1: limit 2
    let page1 = adapter.pull_changes(0, Some(2)).await.unwrap();
    assert_eq!(page1.changes.len(), 2);
    assert!(page1.has_more);
    assert_eq!(page1.next_cursor, 3);
    assert_eq!(page1.changes[0].server_seq, 1);
    assert_eq!(page1.changes[1].server_seq, 3);

    // Pull page 2: after cursor 2
    let page2 = adapter
        .pull_changes(page1.next_cursor, Some(10))
        .await
        .unwrap();
    assert_eq!(page2.changes.len(), 1);
    assert!(!page2.has_more);
    assert_eq!(page2.next_cursor, 4);

    // Verify tombstone is present and typed
    let tombstone_change = page2
        .changes
        .iter()
        .find(|c| c.object_id == obj2)
        .expect("obj2 tombstone must be present");
    assert!(tombstone_change.is_deleted);
    assert_eq!(tombstone_change.revision, 2);
    assert_eq!(tombstone_change.server_seq, 4);
}

#[tokio::test]
async fn test_adapter_zero_knowledge_enforcement_sec_001_sec_002() {
    let leaked_title = serde_json::json!({
        "object_id": "test",
        "title": "Secret leaked title",
    });
    let result = validate_no_plaintext_secrets(&leaked_title);
    assert!(matches!(
        result,
        Err(SyncNetworkError::ForbiddenPlaintext(_))
    ));

    let leaked_passphrase = serde_json::json!({
        "bootstrap": {
            "passphrase": "user-password-here"
        }
    });
    let result2 = validate_no_plaintext_secrets(&leaked_passphrase);
    assert!(matches!(
        result2,
        Err(SyncNetworkError::ForbiddenPlaintext(_))
    ));
}
