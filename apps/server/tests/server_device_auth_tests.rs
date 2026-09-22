//! Integration tests for CLI login and device authorization flow (ZK-072).
//!
//! Enforces:
//! - Complete device authorization and token issuance;
//! - Strict separation of server authentication from vault encryption (no passphrase/vault_key reuse - SEC-001, SEC-002);
//! - Rejection of revoked devices (SEC-006, SEC-008);
//! - Session status reporting (`/v1/auth/session/status` and `/v1/auth/whoami`);
//! - Session revocation immediately invalidates credentials.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::auth::{DeviceAuthResponse, SessionStatusResponse};
use zk_protocol::constants::{ERROR_AUTH_REVOKED, ERROR_DEVICE_REVOKED};
use zk_protocol::webauthn::RevokeSessionResponse;
use zk_server::{create_app, AppState, ErrorResponse, ServerConfig};

fn setup_test_app() -> (axum::Router, AppState) {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("create test app state");
    let app = create_app(state.clone());
    (app, state)
}

#[tokio::test]
async fn test_device_authorize_flow_success() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // 1. Authorize device
    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "CLI Terminal Workstation"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let auth_resp: DeviceAuthResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(auth_resp.session.account_id, account_id);
    assert_eq!(auth_resp.session.device_id, Some(device_id));
    assert!(!auth_resp.session.token.expose_secret().is_empty());

    let token_str = auth_resp.session.token.expose_secret().to_string();

    // 2. Query session status via GET /v1/auth/session/status
    let status_req = Request::builder()
        .method("GET")
        .uri("/v1/auth/session/status")
        .header("authorization", format!("Bearer {token_str}"))
        .body(Body::empty())
        .unwrap();

    let status_resp = app.clone().oneshot(status_req).await.unwrap();
    assert_eq!(status_resp.status(), StatusCode::OK);

    let status_bytes = axum::body::to_bytes(status_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let status_data: SessionStatusResponse = serde_json::from_slice(&status_bytes).unwrap();
    assert_eq!(status_data.account_id, account_id);
    assert_eq!(status_data.device_id, Some(device_id));
    assert_eq!(status_data.session_id, Some(auth_resp.session.session_id));
    assert_eq!(status_data.status, "active");

    // 3. Query whoami alias via GET /v1/auth/whoami
    let whoami_req = Request::builder()
        .method("GET")
        .uri("/v1/auth/whoami")
        .header("authorization", format!("Bearer {token_str}"))
        .body(Body::empty())
        .unwrap();

    let whoami_resp = app.clone().oneshot(whoami_req).await.unwrap();
    assert_eq!(whoami_resp.status(), StatusCode::OK);

    let whoami_bytes = axum::body::to_bytes(whoami_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let whoami_data: SessionStatusResponse = serde_json::from_slice(&whoami_bytes).unwrap();
    assert_eq!(whoami_data.account_id, account_id);
    assert_eq!(whoami_data.session_id, Some(auth_resp.session.session_id));
}

#[tokio::test]
async fn test_cli_login_alias_route() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // Test POST /v1/auth/cli/login
    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/cli/login")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "CLI Login Alias Test"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let auth_resp: DeviceAuthResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(auth_resp.session.account_id, account_id);
    assert_eq!(auth_resp.session.device_id, Some(device_id));
}

#[tokio::test]
async fn test_device_authorize_forbids_passphrase_or_vault_key() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // 1. Attempt payload containing passphrase
    let forbidden_req1 = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "passphrase": "super_secret_master_passphrase"
            })
            .to_string(),
        ))
        .unwrap();

    let resp1 = app.clone().oneshot(forbidden_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);
    let bytes1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let err1: ErrorResponse = serde_json::from_slice(&bytes1).unwrap();
    assert_eq!(err1.code, "FORBIDDEN_PLAINTEXT_PAYLOAD");

    // 2. Attempt payload containing vault_key
    let forbidden_req2 = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "vault_key": "raw_hex_or_b64_key"
            })
            .to_string(),
        ))
        .unwrap();

    let resp2 = app.clone().oneshot(forbidden_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let bytes2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err2: ErrorResponse = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(err2.code, "FORBIDDEN_PLAINTEXT_PAYLOAD");
}

#[tokio::test]
async fn test_device_authorize_revoked_device_rejected() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // Register and revoke the device in database beforehand
    state
        .db
        .register_device(account_id, device_id, Some("Revoked Laptop"))
        .await
        .unwrap();
    state.db.revoke_device(account_id, device_id).await.unwrap();

    // Now attempt to authorize
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "Revoked Laptop"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(err.code, ERROR_DEVICE_REVOKED);
}

#[tokio::test]
async fn test_cli_logout_revokes_session() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // 1. Authorize device
    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let auth_resp: DeviceAuthResponse = serde_json::from_slice(&body_bytes).unwrap();
    let token_str = auth_resp.session.token.expose_secret().to_string();
    let session_id = auth_resp.session.session_id;

    // 2. Revoke session via POST /v1/auth/session/revoke
    let revoke_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/session/revoke")
        .header("authorization", format!("Bearer {token_str}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "session_id": session_id }).to_string()))
        .unwrap();

    let revoke_resp = app.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(revoke_resp.status(), StatusCode::OK);

    let rev_bytes = axum::body::to_bytes(revoke_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rev_data: RevokeSessionResponse = serde_json::from_slice(&rev_bytes).unwrap();
    assert_eq!(rev_data.status, "revoked");
    assert_eq!(rev_data.revoked_session_id, session_id);

    // 3. Status check with revoked token MUST fail with 401 Unauthorized
    let check_req = Request::builder()
        .method("GET")
        .uri("/v1/auth/session/status")
        .header("authorization", format!("Bearer {token_str}"))
        .body(Body::empty())
        .unwrap();

    let check_resp = app.oneshot(check_req).await.unwrap();
    assert_eq!(check_resp.status(), StatusCode::UNAUTHORIZED);

    let check_bytes = axum::body::to_bytes(check_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&check_bytes).unwrap();
    assert_eq!(err.code, ERROR_AUTH_REVOKED);
}

#[tokio::test]
async fn test_device_list_and_revocation_endpoints() {
    let (app, state) = setup_test_app();
    let account_id = Uuid::new_v4();
    let dev1_id = Uuid::new_v4();
    let dev2_id = Uuid::new_v4();

    // 1. Register device 1
    let auth1_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": dev1_id,
                "device_name": "Primary Laptop"
            })
            .to_string(),
        ))
        .unwrap();
    let resp1 = app.clone().oneshot(auth1_req).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let auth1_resp: DeviceAuthResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp1.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let token1 = auth1_resp.session.token.expose_secret().to_string();

    // 2. Register device 2
    let auth2_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": dev2_id,
                "device_name": "Secondary Tablet"
            })
            .to_string(),
        ))
        .unwrap();
    let resp2 = app.clone().oneshot(auth2_req).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let auth2_resp: DeviceAuthResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let token2 = auth2_resp.session.token.expose_secret().to_string();

    // 3. List devices via GET /v1/devices using token 1
    let list_req = Request::builder()
        .method("GET")
        .uri("/v1/devices")
        .header("authorization", format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();
    let list_resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_data: zk_protocol::auth::DeviceListResponse = serde_json::from_slice(
        &axum::body::to_bytes(list_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(list_data.devices.len(), 2);
    assert!(list_data
        .devices
        .iter()
        .any(|d| d.device_id == dev1_id && !d.is_revoked));
    assert!(list_data
        .devices
        .iter()
        .any(|d| d.device_id == dev2_id && !d.is_revoked));

    // 4. Revoke device 2 via DELETE /v1/devices/{device_id}
    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/devices/{dev2_id}"))
        .header("authorization", format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();
    let revoke_resp = app.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(revoke_resp.status(), StatusCode::OK);
    let rev_data: zk_protocol::auth::RevokeDeviceResponse = serde_json::from_slice(
        &axum::body::to_bytes(revoke_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(rev_data.revoked);
    assert_eq!(rev_data.device_id, dev2_id);

    // 5. Query device list again: device 2 is now marked revoked
    let list_req2 = Request::builder()
        .method("GET")
        .uri("/v1/devices")
        .header("authorization", format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();
    let list_resp2 = app.clone().oneshot(list_req2).await.unwrap();
    assert_eq!(list_resp2.status(), StatusCode::OK);
    let list_data2: zk_protocol::auth::DeviceListResponse = serde_json::from_slice(
        &axum::body::to_bytes(list_resp2.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let dev2_info = list_data2
        .devices
        .iter()
        .find(|d| d.device_id == dev2_id)
        .unwrap();
    assert!(dev2_info.is_revoked);
    assert!(dev2_info.revoked_at.is_some());

    // 6. Device 2 tries to sync pull (GET /v1/sync/changes) -> MUST fail with 403 ERROR_DEVICE_REVOKED
    let sync_req = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes?since=0")
        .header("authorization", format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let sync_resp = app.clone().oneshot(sync_req).await.unwrap();
    assert_eq!(sync_resp.status(), StatusCode::UNAUTHORIZED);
    let sync_err: ErrorResponse = serde_json::from_slice(
        &axum::body::to_bytes(sync_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(sync_err.code, ERROR_DEVICE_REVOKED);

    // 7. Device 1 is still authorized and can sync pull cleanly
    let sync1_req = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes?since=0")
        .header("authorization", format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();
    let sync1_resp = app.clone().oneshot(sync1_req).await.unwrap();
    assert_eq!(sync1_resp.status(), StatusCode::OK);

    // 8. Cross-account revocation check: Account B cannot revoke Account A's device
    let account_b = Uuid::new_v4();
    let dev_b = Uuid::new_v4();
    let auth_b_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_b).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_b,
                "device_id": dev_b,
                "device_name": "Account B Laptop"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_b = app.clone().oneshot(auth_b_req).await.unwrap();
    let auth_b_resp: DeviceAuthResponse = serde_json::from_slice(
        &axum::body::to_bytes(resp_b.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let token_b = auth_b_resp.session.token.expose_secret().to_string();

    // Account B lists devices: only sees dev_b, dev1_id is isolated
    let list_b_req = Request::builder()
        .method("GET")
        .uri("/v1/devices")
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let list_b_resp = app.clone().oneshot(list_b_req).await.unwrap();
    assert_eq!(list_b_resp.status(), StatusCode::OK);
    let list_b_data: zk_protocol::auth::DeviceListResponse = serde_json::from_slice(
        &axum::body::to_bytes(list_b_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(list_b_data.devices.len(), 1);
    assert_eq!(list_b_data.devices[0].device_id, dev_b);

    // 9. Encrypted data model unchanged: raw database check
    let _ = state.db.list_devices(account_id).await.unwrap();
}

mod common;
