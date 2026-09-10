//! Integration tests for server authentication abstraction (ZK-070).
//!
//! Validates acceptance criteria:
//! 1. Server auth independent of vault passphrase (SEC-001, SEC-002);
//! 2. Access tokens never logged or reflected in errors (SEC-003);
//! 3. Auth middleware owns account identity and enforces cross-account/device boundaries.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::auth::{AuthToken, REDACTED_TOKEN};
use zk_protocol::constants::{
    ERROR_AUTH_EXPIRED, ERROR_AUTH_FORBIDDEN, ERROR_AUTH_REQUIRED, ERROR_AUTH_REVOKED,
    ERROR_DEVICE_REVOKED,
};
use zk_server::app::{create_app, AppState, ErrorResponse};
use zk_server::config::ServerConfig;
use zk_server::logging::{is_sensitive_header, redact_header_value, sanitize_headers};

#[tokio::test]
async fn test_auth_independent_of_vault_passphrase() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).unwrap();
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();
    let vault_passphrase = "my-secret-vault-passphrase-2026";

    // 1. A client has an independent server authentication session
    let (_sess, token) = state
        .db
        .create_session(acc_id, None, Some("Test Client".to_string()), Some(3600))
        .await
        .unwrap();

    // Verify token is completely distinct from the vault passphrase
    assert_ne!(token.expose_secret(), vault_passphrase);
    assert!(!token.expose_secret().contains("passphrase"));

    // 2. Authenticating with valid server session token succeeds
    let req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    // 404 because no bootstrap is stored yet, but auth succeeded (not 401 or 403)
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 3. Attempting to use the vault passphrase directly as server auth token fails closed
    let bad_auth_req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {vault_passphrase}"))
        .body(Body::empty())
        .unwrap();

    let resp_bad = app.oneshot(bad_auth_req).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::UNAUTHORIZED);

    let bytes = axum::body::to_bytes(resp_bad.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_REQUIRED);
    // Ensure the rejected passphrase is never echoed back
    assert!(!err.message.contains(vault_passphrase));
}

#[tokio::test]
async fn test_access_tokens_never_logged_sec_003() {
    let secret = "zk_sess_live_super_secret_bearer_token_987654321";
    let token = AuthToken::new(secret);

    // 1. Debug and Display redaction
    assert_eq!(format!("{token:?}"), REDACTED_TOKEN);
    assert_eq!(format!("{token}"), REDACTED_TOKEN);

    // 2. Logging redaction helper verification
    assert!(is_sensitive_header("authorization"));
    assert!(is_sensitive_header("x-auth-token"));
    assert!(is_sensitive_header("x-session-token"));

    let header_val = format!("Bearer {secret}");
    let redacted = redact_header_value("authorization", &header_val);
    assert_eq!(redacted, "Bearer [REDACTED]");
    assert!(!redacted.contains(secret));

    // 3. HeaderMap sanitization verification
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&header_val).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );

    let sanitized = sanitize_headers(&headers);
    for (k, v) in sanitized {
        if k == "authorization" {
            assert_eq!(v, "Bearer [REDACTED]");
            assert!(!v.contains(secret));
        }
    }
}

#[tokio::test]
async fn test_auth_middleware_owns_account_identity_lifecycle() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).unwrap();
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();
    let dev_id = Uuid::new_v4();

    // Register device
    state
        .db
        .register_device(acc_id, dev_id, Some("CLI Terminal"))
        .await
        .unwrap();

    // Create session
    let (sess, token) = state
        .db
        .create_session(
            acc_id,
            Some(dev_id),
            Some("Active Session".to_string()),
            Some(3600),
        )
        .await
        .unwrap();

    // 1. Missing Authorization header -> 401 Unauthorized
    let req_missing = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_missing).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_REQUIRED);

    // 2. Invalid scheme (Basic) -> 401 Unauthorized
    let req_scheme = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_scheme).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Invalid token -> 401 Unauthorized
    let req_invalid = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", "Bearer not-a-valid-token-string")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_invalid).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Valid session token -> Access granted (404 because bootstrap is empty, but auth verified)
    let req_valid = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_valid).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 5. Cross-account attempt with mismatching x-account-id -> 403 Forbidden
    let other_acc = Uuid::new_v4();
    let req_cross = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .header("x-account-id", other_acc.to_string())
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_cross).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_FORBIDDEN);

    // 6. Cross-device attempt with mismatching x-device-id -> 403 Forbidden
    let other_dev = Uuid::new_v4();
    let req_cross_dev = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .header("x-device-id", other_dev.to_string())
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_cross_dev).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 7. Revoke session -> Subsequent requests rejected with 401 AUTH_REVOKED
    state
        .db
        .revoke_session(acc_id, sess.session_id)
        .await
        .unwrap();

    let req_revoked = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req_revoked).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_REVOKED);
}

#[tokio::test]
async fn test_auth_expired_session_token_rejected() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).unwrap();
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();

    // Create session that expired in the past (-10 seconds)
    let (_sess, token) = state
        .db
        .create_session(acc_id, None, Some("Expired Session".to_string()), Some(-10))
        .await
        .unwrap();

    let req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_EXPIRED);
}

#[tokio::test]
async fn test_auth_middleware_device_revocation_invalidates_session() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).unwrap();
    let app = create_app(state.clone());

    let acc_id = Uuid::new_v4();
    let dev_id = Uuid::new_v4();

    state
        .db
        .register_device(acc_id, dev_id, Some("Tablet"))
        .await
        .unwrap();

    let (_sess, token) = state
        .db
        .create_session(
            acc_id,
            Some(dev_id),
            Some("Tablet Session".to_string()),
            None,
        )
        .await
        .unwrap();

    // Active
    let req = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Revoke device
    state.db.revoke_device(acc_id, dev_id).await.unwrap();

    // Now rejected
    let req_rev = Request::builder()
        .uri("/v1/vault/bootstrap")
        .method("GET")
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req_rev).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(
        err.code == ERROR_AUTH_REVOKED || err.code == ERROR_DEVICE_REVOKED,
        "expected revocation error code, got {}",
        err.code
    );
}

#[tokio::test]
async fn test_public_health_endpoints_bypass_auth_middleware() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).unwrap();
    let app = create_app(state);

    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req_v1 = Request::builder()
        .uri("/v1/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp_v1 = app.oneshot(req_v1).await.unwrap();
    assert_eq!(resp_v1.status(), StatusCode::OK);
}
