//! Integration tests for the Vault Bootstrap API (ZK-032).
//!
//! Validates:
//! 1. Server stores only KDF params + wrapped keys;
//! 2. No passphrase API field (and explicit rejection if attempted);
//! 3. Get / bootstrap round-trip;
//! 4. Cross-account access denied;
//! 5. Authentication requirement (SEC-001/SEC-002/SEC-003).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::vault::{KdfParams, VaultBootstrap, WrappedVaultKey};
use zk_server::app::ErrorResponse;
use zk_server::config::ServerConfig;
use zk_server::{create_app, AppState};

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
async fn test_vault_bootstrap_get_and_post_round_trip() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();
    let original = sample_bootstrap();

    // 1. GET before bootstrap returns 404 OBJECT_NOT_FOUND
    let get_req_before = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_id}"))
        .body(Body::empty())
        .expect("build request");

    let resp = app.clone().oneshot(get_req_before).await.expect("execute");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let err: ErrorResponse = serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(err.code, zk_protocol::ERROR_OBJECT_NOT_FOUND);

    // 2. POST /v1/vault/bootstrap creates the vault
    let post_req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&original).expect("serialize"),
        ))
        .expect("build request");

    let post_resp = app.clone().oneshot(post_req).await.expect("execute");
    assert_eq!(post_resp.status(), StatusCode::CREATED);

    let post_body = axum::body::to_bytes(post_resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let created: VaultBootstrap = serde_json::from_slice(&post_body).expect("parse json");
    assert_eq!(created, original);

    // 3. GET /v1/vault/bootstrap returns the exact same VaultBootstrap
    let get_req_after = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_id}"))
        .body(Body::empty())
        .expect("build request");

    let get_resp = app.clone().oneshot(get_req_after).await.expect("execute");
    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let retrieved: VaultBootstrap = serde_json::from_slice(&get_body).expect("parse json");
    assert_eq!(retrieved, original);

    // 4. Duplicate POST /v1/vault/bootstrap returns 409 Conflict
    let dup_req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&original).expect("serialize"),
        ))
        .expect("build request");

    let dup_resp = app.oneshot(dup_req).await.expect("execute");
    assert_eq!(dup_resp.status(), StatusCode::CONFLICT);
    let dup_bytes = axum::body::to_bytes(dup_resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let dup_err: ErrorResponse = serde_json::from_slice(&dup_bytes).expect("parse json");
    assert_eq!(dup_err.code, "VAULT_ALREADY_EXISTS");
}

#[tokio::test]
async fn test_server_stores_only_kdf_params_and_wrapped_keys_no_passphrase() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();
    let original = sample_bootstrap();

    let post_req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&original).expect("serialize"),
        ))
        .expect("build request");

    let post_resp = app.oneshot(post_req).await.expect("execute");
    assert_eq!(post_resp.status(), StatusCode::CREATED);

    // Verify directly from the database that no plaintext keys or passphrases exist
    let stored = state
        .db
        .get_vault_bootstrap(acc_id)
        .await
        .expect("query db")
        .expect("vault must exist");
    assert_eq!(stored.crypto_version, 1);
    assert_eq!(stored.kdf.algorithm, "argon2id");
    assert_eq!(stored.kdf.memory_kib, 65536);
    assert_eq!(stored.kdf.iterations, 3);
    assert_eq!(stored.kdf.parallelism, 1);
    assert_eq!(stored.wrapped_vault_key.cipher_suite, "xchacha20poly1305");
    assert_eq!(
        stored.recovery_wrapped_vault_key.cipher_suite,
        "xchacha20poly1305"
    );
}

#[tokio::test]
async fn test_rejection_of_passphrase_fields_sec_001() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state);

    let acc_id = Uuid::new_v4();

    // 1. Attempt to transmit passphrase in payload
    let malicious_payload = serde_json::json!({
        "crypto_version": 1,
        "passphrase": "super_secret_user_passphrase",
        "kdf": {
            "algorithm": "argon2id",
            "salt": "cmFuZG9tLXNhbHQtMTZieXRlcw==",
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 1
        },
        "wrapped_vault_key": {
            "cipher_suite": "xchacha20poly1305",
            "nonce": "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=",
            "ciphertext": "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA=="
        },
        "recovery_wrapped_vault_key": {
            "cipher_suite": "xchacha20poly1305",
            "nonce": "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==",
            "ciphertext": "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk="
        }
    });

    let req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&malicious_payload).expect("serialize"),
        ))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("execute");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let err: ErrorResponse = serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(err.code, "INVALID_VAULT_BOOTSTRAP");
    assert!(err.message.contains("Passphrase"));

    // 2. Attempt to transmit password in nested object
    let nested_password = serde_json::json!({
        "crypto_version": 1,
        "kdf": {
            "algorithm": "argon2id",
            "salt": "cmFuZG9tLXNhbHQtMTZieXRlcw==",
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 1,
            "password": "leak"
        },
        "wrapped_vault_key": {
            "cipher_suite": "xchacha20poly1305",
            "nonce": "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=",
            "ciphertext": "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA=="
        },
        "recovery_wrapped_vault_key": {
            "cipher_suite": "xchacha20poly1305",
            "nonce": "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==",
            "ciphertext": "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk="
        }
    });

    let req2 = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&nested_password).expect("serialize"),
        ))
        .expect("build request");

    let resp2 = app.oneshot(req2).await.expect("execute");
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authentication_enforcement_sec_003() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state);

    // 1. Missing Authorization header -> 401 AUTH_REQUIRED
    let req_no_auth = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .body(Body::empty())
        .expect("build request");

    let resp = app.clone().oneshot(req_no_auth).await.expect("execute");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let err: ErrorResponse = serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(err.code, zk_protocol::ERROR_AUTH_REQUIRED);

    // 2. Invalid authorization scheme -> 401 AUTH_REQUIRED
    let req_bad_scheme = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", "Basic abc12345")
        .body(Body::empty())
        .expect("build request");

    let resp2 = app.clone().oneshot(req_bad_scheme).await.expect("execute");
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

    // 3. Invalid token (not a UUID) -> 401 AUTH_REQUIRED
    let req_bad_token = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", "Bearer invalid-non-uuid-token")
        .body(Body::empty())
        .expect("build request");

    let resp3 = app.oneshot(req_bad_token).await.expect("execute");
    assert_eq!(resp3.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_cross_account_access_denied() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state.clone());

    let acc_a = Uuid::new_v4();
    let acc_b = Uuid::new_v4();

    // 1. Account A bootstraps vault
    let bootstrap_a = sample_bootstrap();
    let post_a = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_a}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&bootstrap_a).expect("serialize"),
        ))
        .expect("build request");

    let resp_post_a = app.clone().oneshot(post_a).await.expect("execute");
    assert_eq!(resp_post_a.status(), StatusCode::CREATED);

    // 2. Account B requests GET /v1/vault/bootstrap -> gets 404 NOT_FOUND (cannot see Account A's vault)
    let get_b = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_b}"))
        .body(Body::empty())
        .expect("build request");

    let resp_get_b = app.clone().oneshot(get_b).await.expect("execute");
    assert_eq!(resp_get_b.status(), StatusCode::NOT_FOUND);

    // 3. Account B attempts cross-account query with x-account-id pointing to Account A -> 403 FORBIDDEN
    let cross_acc_req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_b}"))
        .header("x-account-id", acc_a.to_string())
        .body(Body::empty())
        .expect("build request");

    let resp_cross = app.clone().oneshot(cross_acc_req).await.expect("execute");
    assert_eq!(resp_cross.status(), StatusCode::FORBIDDEN);
    let cross_bytes = axum::body::to_bytes(resp_cross.into_body(), usize::MAX)
        .await
        .expect("read body");
    let cross_err: ErrorResponse = serde_json::from_slice(&cross_bytes).expect("parse json");
    assert_eq!(cross_err.code, zk_protocol::ERROR_AUTH_FORBIDDEN);

    // 4. Account B attempts cross-account POST targeting Account A -> 403 FORBIDDEN
    let cross_post = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_b}"))
        .header("x-account-id", acc_a.to_string())
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&bootstrap_a).expect("serialize"),
        ))
        .expect("build request");

    let resp_cross_post = app.clone().oneshot(cross_post).await.expect("execute");
    assert_eq!(resp_cross_post.status(), StatusCode::FORBIDDEN);

    // 5. Account B can independently bootstrap their own vault
    let mut bootstrap_b = sample_bootstrap();
    bootstrap_b.kdf.memory_kib = 131072; // distinct parameter

    let post_b = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_b}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&bootstrap_b).expect("serialize"),
        ))
        .expect("build request");

    let resp_post_b = app.clone().oneshot(post_b).await.expect("execute");
    assert_eq!(resp_post_b.status(), StatusCode::CREATED);

    // 6. Verify each account reads their own distinct vault
    let get_a_final = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_a}"))
        .body(Body::empty())
        .expect("build request");
    let resp_a_final = app.clone().oneshot(get_a_final).await.expect("execute");
    let body_a_final: VaultBootstrap = serde_json::from_slice(
        &axum::body::to_bytes(resp_a_final.into_body(), usize::MAX)
            .await
            .expect("read"),
    )
    .expect("parse");
    assert_eq!(body_a_final.kdf.memory_kib, 65536);

    let get_b_final = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("Authorization", format!("Bearer {acc_b}"))
        .body(Body::empty())
        .expect("build request");
    let resp_b_final = app.oneshot(get_b_final).await.expect("execute");
    let body_b_final: VaultBootstrap = serde_json::from_slice(
        &axum::body::to_bytes(resp_b_final.into_body(), usize::MAX)
            .await
            .expect("read"),
    )
    .expect("parse");
    assert_eq!(body_b_final.kdf.memory_kib, 131072);
}

#[tokio::test]
async fn test_validation_crypto_version_and_kdf_params() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state);
    let acc_id = Uuid::new_v4();

    // 1. Unsupported crypto version
    let mut bad_version = sample_bootstrap();
    bad_version.crypto_version = 99;

    let req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&bad_version).expect("serialize"),
        ))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("execute");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read");
    let err: ErrorResponse = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(err.code, zk_protocol::ERROR_CRYPTO_UNSUPPORTED_VERSION);

    // 2. Invalid salt (not Base64)
    let mut bad_salt = sample_bootstrap();
    bad_salt.kdf.salt = "not-valid-base64-!@#$%^&*()".to_string();

    let req2 = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&bad_salt).expect("serialize"),
        ))
        .expect("build request");

    let resp2 = app.clone().oneshot(req2).await.expect("execute");
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

    // 3. Zero KDF memory
    let mut zero_mem = sample_bootstrap();
    zero_mem.kdf.memory_kib = 0;

    let req3 = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("POST")
        .header("Authorization", format!("Bearer {acc_id}"))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&zero_mem).expect("serialize"),
        ))
        .expect("build request");

    let resp3 = app.oneshot(req3).await.expect("execute");
    assert_eq!(resp3.status(), StatusCode::BAD_REQUEST);
}
