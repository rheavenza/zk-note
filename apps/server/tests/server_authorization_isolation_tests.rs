//! Integration tests for cross-account authorization and data isolation (ZK-038).
//!
//! Validates acceptance criteria:
//! 1. Account A cannot fetch or mutate Account B objects;
//! 2. Guessed object IDs do not bypass ownership;
//! 3. History access is strictly isolated;
//! 4. Vault bootstrap and sync streams are completely separated across accounts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{
    ENVELOPE_VERSION_V1, ERROR_AUTH_REQUIRED, ERROR_OBJECT_NOT_FOUND, OBJECT_KIND_NOTE,
};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{PullChangesResponse, PushRequest};
use zk_protocol::vault::{KdfParams, VaultBootstrap, WrappedVaultKey};
use zk_server::app::{create_app, AppState, ErrorResponse};
use zk_server::config::ServerConfig;

fn helper_envelope(object_id: &str, payload_bytes: &[u8]) -> EncryptedEnvelope {
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
            ciphertext: Base64::encode_string(payload_bytes),
        },
    }
}

fn helper_push_request(
    object_id: &str,
    expected_revision: u64,
    payload_bytes: &[u8],
    is_deleted: bool,
) -> PushRequest {
    PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: object_id.to_string(),
        expected_revision,
        object_kind: OBJECT_KIND_NOTE,
        envelope: helper_envelope(object_id, payload_bytes),
        is_deleted,
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
            nonce: "dGhpcyBpcyAyNC1ieXRlIG5vbmNlIQ==".to_string(),
            ciphertext: "ZW5jcnlwdGVkLXZhdWx0LWtleQ==".to_string(),
        },
        recovery_wrapped_vault_key: WrappedVaultKey {
            cipher_suite: "xchacha20poly1305".to_string(),
            nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
            ciphertext: "cmVjb3Zlcnktd3JhcHBlZC1rZXk=".to_string(),
        },
    }
}

#[tokio::test]
async fn test_auth_isolation_cannot_mutate_another_account_object() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let auth_a = common::bearer(&state, acc_a).await;
    let auth_b = common::bearer(&state, acc_b).await;

    let obj_b = Uuid::new_v4();
    let obj_b_str = obj_b.to_string();

    // 1. Account B creates object
    let req_b = helper_push_request(&obj_b_str, 0, b"secret note belonging to B", false);
    let resp_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::OK);

    // 2. Account A attempts to update Account B's object with expected_revision = 1
    let req_a = helper_push_request(&obj_b_str, 1, b"malicious overwrite by A", false);
    let resp_a = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_a)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Must return 404 NOT FOUND (no leak of B's existence or revision)
    assert_eq!(resp_a.status(), StatusCode::NOT_FOUND);
    let body_a = axum::body::to_bytes(resp_a.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_a: ErrorResponse = serde_json::from_slice(&body_a).unwrap();
    assert_eq!(err_a.code, ERROR_OBJECT_NOT_FOUND);

    // 3. Verify Account B's object remains intact and untouched
    let b_stored = state
        .db
        .get_encrypted_object(acc_b, obj_b)
        .await
        .unwrap()
        .expect("B object exists");
    assert_eq!(b_stored.revision, 1);
    assert_eq!(b_stored.server_seq, 1);
    let b_payload: EncryptedPayloadContainer = serde_json::from_slice(&b_stored.payload).unwrap();
    assert_eq!(
        b_payload.ciphertext,
        Base64::encode_string(b"secret note belonging to B")
    );
}

#[tokio::test]
async fn test_auth_isolation_cannot_delete_another_account_object() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let auth_a = common::bearer(&state, acc_a).await;
    let auth_b = common::bearer(&state, acc_b).await;

    let obj_b = Uuid::new_v4();
    let obj_b_str = obj_b.to_string();

    // 1. Account B creates object
    let req_b = helper_push_request(&obj_b_str, 0, b"important note", false);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Account A attempts to delete Account B's object
    let del_a = helper_push_request(&obj_b_str, 1, b"malicious delete", true);
    let resp_del = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_a)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&del_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp_del.status(), StatusCode::NOT_FOUND);

    // 3. Verify Account B's object is NOT deleted
    let b_stored = state
        .db
        .get_encrypted_object(acc_b, obj_b)
        .await
        .unwrap()
        .expect("B object still exists");
    assert_eq!(b_stored.revision, 1);
    assert!(!b_stored.is_deleted, "B object must not be deleted");
}

#[tokio::test]
async fn test_auth_isolation_guessed_object_id_does_not_bypass_ownership() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let auth_a = common::bearer(&state, acc_a).await;
    let auth_b = common::bearer(&state, acc_b).await;

    let shared_id = Uuid::new_v4();
    let shared_str = shared_id.to_string();

    // 1. Account B creates object at shared_id
    let req_b = helper_push_request(&shared_str, 0, b"B content", false);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Account A guesses shared_id and tries expected_revision = 99 -> returns 404, not 409
    let req_a_guess = helper_push_request(&shared_str, 99, b"A guessed probe", false);
    let resp_guess = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_a)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_a_guess).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_guess.status(), StatusCode::NOT_FOUND);

    // 3. Account A creates its own note with shared_id (expected_revision = 0)
    let req_a_create = helper_push_request(&shared_str, 0, b"A content", false);
    let resp_a_create = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_a)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_a_create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_a_create.status(), StatusCode::OK);

    // 4. Verify Account A and Account B have completely separate records
    let stored_a = state
        .db
        .get_encrypted_object(acc_a, shared_id)
        .await
        .unwrap()
        .unwrap();
    let stored_b = state
        .db
        .get_encrypted_object(acc_b, shared_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(stored_a.account_id, acc_a);
    assert_eq!(stored_b.account_id, acc_b);

    let payload_a: EncryptedPayloadContainer = serde_json::from_slice(&stored_a.payload).unwrap();
    let payload_b: EncryptedPayloadContainer = serde_json::from_slice(&stored_b.payload).unwrap();

    assert_eq!(payload_a.ciphertext, Base64::encode_string(b"A content"));
    assert_eq!(payload_b.ciphertext, Base64::encode_string(b"B content"));
}

#[tokio::test]
async fn test_auth_isolation_history_strictly_isolated() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let auth_b = common::bearer(&state, acc_b).await;

    let obj_id = Uuid::new_v4();
    let obj_str = obj_id.to_string();

    // 1. Account B creates (rev 1) and updates twice (rev 2, rev 3)
    let req1 = helper_push_request(&obj_str, 0, b"rev 1", false);
    let req2 = helper_push_request(&obj_str, 1, b"rev 2", false);
    let req3 = helper_push_request(&obj_str, 2, b"rev 3", false);

    for r in [&req1, &req2, &req3] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sync/push")
                    .method("POST")
                    .header("authorization", &auth_b)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(r).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 2. Account B has 2 history records
    let hist_b = state.db.get_object_history(acc_b, obj_id).await.unwrap();
    assert_eq!(hist_b.len(), 2);
    assert_eq!(hist_b[0].revision, 1);
    assert_eq!(hist_b[1].revision, 2);

    // 3. Account A querying history for obj_id MUST return empty list
    let hist_a = state.db.get_object_history(acc_a, obj_id).await.unwrap();
    assert!(
        hist_a.is_empty(),
        "Account A must have zero access to Account B's object history"
    );
}

#[tokio::test]
async fn test_auth_isolation_sync_pull_never_crosses_accounts() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let acc_c = Uuid::new_v4();

    // Accounts write independent objects
    for (acc, prefix, count) in [(&acc_a, "A", 3), (&acc_b, "B", 5), (&acc_c, "C", 2)] {
        let auth = common::bearer(&state, *acc).await;
        for i in 1..=count {
            let obj_id = Uuid::new_v4().to_string();
            let req =
                helper_push_request(&obj_id, 0, format!("{prefix} note {i}").as_bytes(), false);
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/sync/push")
                        .method("POST")
                        .header("authorization", &auth)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&req).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    // Pull as A: exactly 3 items, server_seq 1..=3
    let pull_a = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", common::bearer(&state, acc_a).await)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_a.status(), StatusCode::OK);
    let body_a = axum::body::to_bytes(pull_a.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_a: PullChangesResponse = serde_json::from_slice(&body_a).unwrap();
    assert_eq!(resp_a.changes.len(), 3);
    assert_eq!(resp_a.next_cursor, 3);
    for (idx, c) in resp_a.changes.iter().enumerate() {
        assert_eq!(c.server_seq, (idx + 1) as u64);
    }

    // Pull as B: exactly 5 items, server_seq 1..=5
    let pull_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", common::bearer(&state, acc_b).await)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_b.status(), StatusCode::OK);
    let body_b = axum::body::to_bytes(pull_b.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_b: PullChangesResponse = serde_json::from_slice(&body_b).unwrap();
    assert_eq!(resp_b.changes.len(), 5);
    assert_eq!(resp_b.next_cursor, 5);

    // Pull as C: exactly 2 items, server_seq 1..=2
    let pull_c = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", common::bearer(&state, acc_c).await)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_c.status(), StatusCode::OK);
    let body_c = axum::body::to_bytes(pull_c.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_c: PullChangesResponse = serde_json::from_slice(&body_c).unwrap();
    assert_eq!(resp_c.changes.len(), 2);
    assert_eq!(resp_c.next_cursor, 2);
}

#[tokio::test]
async fn test_auth_isolation_vault_bootstrap_cross_account_forbidden() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();
    let auth_a = common::bearer(&state, acc_a).await;
    let auth_b = common::bearer(&state, acc_b).await;

    // 1. Account B creates bootstrap
    let bootstrap = sample_bootstrap();
    let post_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/vault/bootstrap")
                .method("POST")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&bootstrap).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_resp.status(), StatusCode::CREATED);

    // 2. Account A requests bootstrap -> 404 NOT FOUND
    let get_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/vault/bootstrap")
                .method("GET")
                .header("authorization", &auth_a)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_auth_isolation_unauthenticated_requests_fail_closed() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    // 1. Push without auth -> 401
    let req1 = helper_push_request(&Uuid::new_v4().to_string(), 0, b"unauthenticated", false);
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);
    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let err1: ErrorResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(err1.code, ERROR_AUTH_REQUIRED);

    // 2. Pull without auth -> 401
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

    // 3. Vault bootstrap without auth -> 401
    let resp3 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/vault/bootstrap")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::UNAUTHORIZED);

    // 4. Invalid bearer token (non-UUID) -> 401
    let resp4 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", "Bearer not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp4.status(), StatusCode::UNAUTHORIZED);
}

mod common;
