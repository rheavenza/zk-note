//! Integration tests for WebAuthn / Passkey web authentication (ZK-071).
//!
//! Enforces:
//! - Complete registration and login lifecycle (register, sign in, revoke session);
//! - Rejection of expired or replayed challenges;
//! - Strict separation of server authentication from vault encryption (no passphrase reuse - SEC-001, SEC-002);
//! - Session revocation invalidates tokens immediately.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{
    ERROR_AUTH_REVOKED, ERROR_CRYPTO_AUTH_FAILED, ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND,
    ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND,
};
use zk_protocol::webauthn::{
    RevokeSessionResponse, WebAuthnLoginFinishResponse, WebAuthnLoginStartResponse,
    WebAuthnRegisterFinishResponse, WebAuthnRegisterStartResponse,
};
use zk_server::{create_app, AppState, ErrorResponse, ServerConfig};

fn setup_test_app() -> axum::Router {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("create test app state");
    create_app(state)
}

#[tokio::test]
async fn test_webauthn_registration_and_login_full_lifecycle() {
    let app = setup_test_app();

    // 1. Start WebAuthn registration
    let start_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "username": "alice" }).to_string()))
        .unwrap();

    let resp = app.clone().oneshot(start_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg_start: WebAuthnRegisterStartResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!reg_start.challenge_b64.is_empty());

    // 2. Finish WebAuthn registration
    let cred_id = Base64UrlUnpadded::encode_string(b"credential-alice-macbook-touchid");
    let pub_key = Base64UrlUnpadded::encode_string(b"cose-public-key-bytes-p256-mock");

    let finish_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": reg_start.challenge_id,
                "credential_id": cred_id,
                "public_key": pub_key,
                "display_name": "Alice MacBook TouchID",
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(finish_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg_finish: WebAuthnRegisterFinishResponse = serde_json::from_slice(&body_bytes).unwrap();
    let account_id = reg_finish.session.account_id;
    let initial_token = reg_finish.session.token.expose_secret().to_string();
    assert!(!initial_token.is_empty());

    // 3. Verify initial token grants access to protected routes
    let sync_req = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes")
        .header("authorization", format!("Bearer {initial_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(sync_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 4. Start WebAuthn login (sign-in)
    let login_start_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/login/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "account_id": account_id }).to_string()))
        .unwrap();

    let resp = app.clone().oneshot(login_start_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_start: WebAuthnLoginStartResponse = serde_json::from_slice(&body_bytes).unwrap();

    // 5. Finish WebAuthn login
    let signature = Base64UrlUnpadded::encode_string(b"assertion-signature-mock-bytes");
    let login_finish_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": login_start.challenge_id,
                "credential_id": cred_id,
                "signature": signature,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(login_finish_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_finish: WebAuthnLoginFinishResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(login_finish.session.account_id, account_id);
    let login_token = login_finish.session.token.expose_secret().to_string();
    assert!(!login_token.is_empty());

    // 6. Verify sign-in token grants access to protected routes
    let sync_req2 = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes")
        .header("authorization", format!("Bearer {login_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(sync_req2).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_webauthn_session_revocation() {
    let app = setup_test_app();

    // 1. Register a passkey to obtain an active session
    let start_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(start_req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg_start: WebAuthnRegisterStartResponse = serde_json::from_slice(&body_bytes).unwrap();

    let cred_id = Base64UrlUnpadded::encode_string(b"cred-revoke-test");
    let pub_key = Base64UrlUnpadded::encode_string(b"pubkey-revoke-test");

    let finish_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": reg_start.challenge_id,
                "credential_id": cred_id,
                "public_key": pub_key,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(finish_req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg_finish: WebAuthnRegisterFinishResponse = serde_json::from_slice(&body_bytes).unwrap();
    let token = reg_finish.session.token.expose_secret().to_string();

    // 2. Verify active session works
    let req = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Explicitly revoke the session via POST /v1/auth/session/revoke
    let revoke_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/session/revoke")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
        .unwrap();

    let resp = app.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let revoke_resp: RevokeSessionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(revoke_resp.status, "revoked");

    // 4. Verify subsequent requests with revoked token are rejected with 401 (AUTH_REVOKED)
    let req2 = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_resp.code, ERROR_AUTH_REVOKED);
}

#[tokio::test]
async fn test_webauthn_rejects_vault_passphrase_or_keys_sec_001_sec_002() {
    let app = setup_test_app();

    // 1. Rejects registration payload with passphrase
    let bad_finish_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": Uuid::new_v4(),
                "credential_id": "YWJj",
                "public_key": "ZGVm",
                "passphrase": "ForbiddenVaultPassphrase123!",
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(bad_finish_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err.code, ERROR_CRYPTO_AUTH_FAILED);

    // 2. Rejects login payload with vault_key
    let bad_login_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": Uuid::new_v4(),
                "credential_id": "YWJj",
                "signature": "ZGVm",
                "vault_key": "ForbiddenVaultKeySecret",
            })
            .to_string(),
        ))
        .unwrap();

    let resp2 = app.clone().oneshot(bad_login_req).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err2: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err2.code, ERROR_CRYPTO_AUTH_FAILED);
}

#[tokio::test]
async fn test_webauthn_replayed_challenge_fails_closed() {
    let app = setup_test_app();

    // Start registration
    let start_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(start_req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reg_start: WebAuthnRegisterStartResponse = serde_json::from_slice(&body_bytes).unwrap();

    let cred_id = Base64UrlUnpadded::encode_string(b"cred-replay-test");
    let pub_key = Base64UrlUnpadded::encode_string(b"pubkey-replay-test");

    let finish_payload = json!({
        "challenge_id": reg_start.challenge_id,
        "credential_id": cred_id,
        "public_key": pub_key,
    })
    .to_string();

    // First finish succeeds
    let finish_req1 = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(finish_payload.clone()))
        .unwrap();
    let resp1 = app.clone().oneshot(finish_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Replay finish with exact same challenge fails closed (single-use challenge consumed)
    let finish_req2 = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/register/finish")
        .header("content-type", "application/json")
        .body(Body::from(finish_payload))
        .unwrap();
    let resp2 = app.clone().oneshot(finish_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

    let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err.code, ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND);
}

#[tokio::test]
async fn test_webauthn_unknown_credential_rejected() {
    let app = setup_test_app();

    // Start login
    let login_start_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/login/start")
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(login_start_req).await.unwrap();
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_start: WebAuthnLoginStartResponse = serde_json::from_slice(&body_bytes).unwrap();

    // Attempt finish with unknown credential ID
    let unknown_cred_id = Base64UrlUnpadded::encode_string(b"non-existent-credential-id");
    let sig = Base64UrlUnpadded::encode_string(b"mock-sig");

    let login_finish_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/webauthn/login/finish")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "challenge_id": login_start.challenge_id,
                "credential_id": unknown_cred_id,
                "signature": sig,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(login_finish_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err.code, ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND);
}
