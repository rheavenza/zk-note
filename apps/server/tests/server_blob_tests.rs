//! Integration tests for server ciphertext blob storage API (ZK-082).
//!
//! Validates:
//! - Opaque blob IDs (UUIDs or alphanumeric identifiers);
//! - Authorization: strict isolation per account with Bearer authentication;
//! - Size quotas: single blob limits and aggregate account quotas fail closed (HTTP 413);
//! - SEC-001/SEC-002: no note plaintext, attachment filenames, or MIME types permitted.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::auth::DeviceAuthResponse;
use zk_protocol::constants::{ERROR_BLOB_NOT_FOUND, ERROR_PAYLOAD_TOO_LARGE, ERROR_QUOTA_EXCEEDED};
use zk_server::{create_app, AppState, ErrorResponse, ServerConfig};

fn setup_test_app(
    max_blob_size: Option<usize>,
    account_blob_quota: Option<u64>,
) -> (axum::Router, AppState) {
    let mut config = ServerConfig::default();
    if let Some(m) = max_blob_size {
        config.max_blob_size = m;
    }
    if let Some(q) = account_blob_quota {
        config.account_blob_quota = q;
    }
    let state = AppState::new_in_memory(config).expect("create test app state");
    let app = create_app(state.clone());
    (app, state)
}

async fn authorize_account(
    app: &axum::Router,
    state: &AppState,
    account_id: Uuid,
    device_id: Uuid,
) -> (String, DeviceAuthResponse) {
    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "Test Client"
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
    let token = auth_resp.session.token.expose_secret().to_string();
    (token, auth_resp)
}

#[tokio::test]
async fn test_blob_put_get_delete_lifecycle_round_trip() {
    let (app, state) = setup_test_app(None, None);
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    let blob_id = "test-opaque-blob-001";
    let ciphertext_data = vec![0x42u8; 1024];

    // 1. Upload ciphertext blob via PUT /v1/blobs/{blob_id}
    let put_req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{blob_id}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Body::from(ciphertext_data.clone()))
        .unwrap();

    let put_resp = app.clone().oneshot(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::CREATED);

    let put_body = axum::body::to_bytes(put_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let put_json: serde_json::Value = serde_json::from_slice(&put_body).unwrap();
    assert_eq!(put_json["blob_id"], blob_id);
    assert_eq!(put_json["size"], 1024);

    // 2. Download ciphertext blob via GET /v1/blobs/{blob_id}
    let get_req = Request::builder()
        .method("GET")
        .uri(format!("/v1/blobs/{blob_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let get_resp = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(
        get_resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );

    let downloaded_bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(downloaded_bytes.as_ref(), ciphertext_data.as_slice());

    // 3. Delete ciphertext blob via DELETE /v1/blobs/{blob_id}
    let del_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/blobs/{blob_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let del_resp = app.clone().oneshot(del_req).await.unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);

    // 4. Subsequent GET returns 404 Not Found
    let get_again_req = Request::builder()
        .method("GET")
        .uri(format!("/v1/blobs/{blob_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let get_again_resp = app.clone().oneshot(get_again_req).await.unwrap();
    assert_eq!(get_again_resp.status(), StatusCode::NOT_FOUND);

    let err_bytes = axum::body::to_bytes(get_again_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&err_bytes).unwrap();
    assert_eq!(err.code, ERROR_BLOB_NOT_FOUND);
}

#[tokio::test]
async fn test_cross_account_blob_isolation() {
    let (app, state) = setup_test_app(None, None);

    let account_a = Uuid::new_v4();
    let device_a = Uuid::new_v4();
    let (token_a, _) = authorize_account(&app, &state, account_a, device_a).await;

    let account_b = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let (token_b, _) = authorize_account(&app, &state, account_b, device_b).await;

    let shared_blob_id = "shared-blob-id-uuid";
    let data_a = b"ciphertext-belonging-to-account-a".to_vec();
    let data_b = b"different-ciphertext-for-account-b".to_vec();

    // 1. Account A uploads blob
    let put_a = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_a}"))
        .body(Body::from(data_a.clone()))
        .unwrap();
    let resp_a = app.clone().oneshot(put_a).await.unwrap();
    assert_eq!(resp_a.status(), StatusCode::CREATED);

    // 2. Account B cannot GET Account A's blob (must return 404)
    let get_b = Request::builder()
        .method("GET")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let resp_get_b = app.clone().oneshot(get_b).await.unwrap();
    assert_eq!(resp_get_b.status(), StatusCode::NOT_FOUND);

    // 3. Account B cannot DELETE Account A's blob (must return 404)
    let del_b = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let resp_del_b = app.clone().oneshot(del_b).await.unwrap();
    assert_eq!(resp_del_b.status(), StatusCode::NOT_FOUND);

    // 4. Account B uploads same blob ID for their own account
    let put_b = Request::builder()
        .method("PUT")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::from(data_b.clone()))
        .unwrap();
    let resp_put_b = app.clone().oneshot(put_b).await.unwrap();
    assert_eq!(resp_put_b.status(), StatusCode::CREATED);

    // 5. Account A reads their original data intact
    let get_a = Request::builder()
        .method("GET")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_a}"))
        .body(Body::empty())
        .unwrap();
    let resp_get_a = app.clone().oneshot(get_a).await.unwrap();
    let read_a = axum::body::to_bytes(resp_get_a.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(read_a.as_ref(), data_a.as_slice());

    // 6. Account B reads their separate data intact
    let get_b2 = Request::builder()
        .method("GET")
        .uri(format!("/v1/blobs/{shared_blob_id}"))
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let resp_get_b2 = app.clone().oneshot(get_b2).await.unwrap();
    let read_b = axum::body::to_bytes(resp_get_b2.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(read_b.as_ref(), data_b.as_slice());
}

#[tokio::test]
async fn test_unauthenticated_and_revoked_blob_access_denied() {
    let (app, state) = setup_test_app(None, None);

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    // 1. Missing Authorization header fails with 401
    let unauth_req = Request::builder()
        .method("GET")
        .uri("/v1/blobs/any-blob")
        .body(Body::empty())
        .unwrap();
    let unauth_resp = app.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid Bearer token fails with 401
    let bad_token_req = Request::builder()
        .method("GET")
        .uri("/v1/blobs/any-blob")
        .header("authorization", "Bearer invalid-token-string")
        .body(Body::empty())
        .unwrap();
    let bad_resp = app.clone().oneshot(bad_token_req).await.unwrap();
    assert_eq!(bad_resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Revoke device then attempt blob operation
    let revoke_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/devices/{device_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let revoke_resp = app.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(revoke_resp.status(), StatusCode::OK);

    let blob_req = Request::builder()
        .method("GET")
        .uri("/v1/blobs/any-blob")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let blob_resp = app.clone().oneshot(blob_req).await.unwrap();
    assert_eq!(blob_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_single_blob_size_limit_enforced() {
    // 512 bytes limit
    let (app, state) = setup_test_app(Some(512), None);

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    // Oversize blob: 513 bytes
    let oversize_data = vec![0xaa; 513];
    let put_req = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/oversize-blob")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(oversize_data))
        .unwrap();

    let put_resp = app.clone().oneshot(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let err_bytes = axum::body::to_bytes(put_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&err_bytes).unwrap();
    assert_eq!(err.code, ERROR_PAYLOAD_TOO_LARGE);

    // Within limit blob: 512 bytes
    let ok_data = vec![0xaa; 512];
    let ok_put_req = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/valid-size-blob")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(ok_data))
        .unwrap();

    let ok_resp = app.clone().oneshot(ok_put_req).await.unwrap();
    assert_eq!(ok_resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_account_aggregate_storage_quota_enforced() {
    // 1000 bytes max per blob, 2000 bytes total account quota
    let (app, state) = setup_test_app(Some(1000), Some(2000));

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    // 1. Upload first blob: 900 bytes (usage: 900)
    let put_1 = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-1")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x01; 900]))
        .unwrap();
    let resp_1 = app.clone().oneshot(put_1).await.unwrap();
    assert_eq!(resp_1.status(), StatusCode::CREATED);

    // 2. Upload second blob: 900 bytes (usage: 1800 <= 2000)
    let put_2 = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-2")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x02; 900]))
        .unwrap();
    let resp_2 = app.clone().oneshot(put_2).await.unwrap();
    assert_eq!(resp_2.status(), StatusCode::CREATED);

    // 3. Upload third blob: 300 bytes (projected: 1800 + 300 = 2100 > 2000 quota) -> fails
    let put_3 = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-3")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x03; 300]))
        .unwrap();
    let resp_3 = app.clone().oneshot(put_3).await.unwrap();
    assert_eq!(resp_3.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let err_bytes = axum::body::to_bytes(resp_3.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&err_bytes).unwrap();
    assert_eq!(err.code, ERROR_QUOTA_EXCEEDED);

    // 4. Overwrite blob-1 with smaller blob: 400 bytes (new usage: 400 + 900 = 1300)
    let put_1_small = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-1")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x01; 400]))
        .unwrap();
    let resp_1_small = app.clone().oneshot(put_1_small).await.unwrap();
    assert_eq!(resp_1_small.status(), StatusCode::CREATED);

    // 5. Now blob-3 (300 bytes) fits within remaining quota (1300 + 300 = 1600 <= 2000)
    let put_3_retry = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-3")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x03; 300]))
        .unwrap();
    let resp_3_retry = app.clone().oneshot(put_3_retry).await.unwrap();
    assert_eq!(resp_3_retry.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_forbidden_plaintext_metadata_headers_rejected() {
    let (app, state) = setup_test_app(None, None);

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    // Forbidden header: x-filename
    let bad_hdr_req = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-meta-leak")
        .header("authorization", format!("Bearer {token}"))
        .header("x-filename", "secret_financials.pdf")
        .body(Body::from(vec![0x01; 100]))
        .unwrap();

    let resp = app.clone().oneshot(bad_hdr_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let err_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&err_bytes).unwrap();
    assert_eq!(err.code, "PLAINTEXT_METADATA_FORBIDDEN");

    // Forbidden header: x-mime-type
    let bad_mime_req = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/blob-meta-leak-2")
        .header("authorization", format!("Bearer {token}"))
        .header("x-mime-type", "application/pdf")
        .body(Body::from(vec![0x01; 100]))
        .unwrap();

    let resp2 = app.clone().oneshot(bad_mime_req).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_invalid_blob_id_format_rejected() {
    let (app, state) = setup_test_app(None, None);

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (token, _) = authorize_account(&app, &state, account_id, device_id).await;

    // Blob ID with spaces or illegal characters
    let bad_id_req = Request::builder()
        .method("PUT")
        .uri("/v1/blobs/bad%20id%20with%20spaces")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![0x01; 10]))
        .unwrap();

    let resp = app.clone().oneshot(bad_id_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

mod common;
