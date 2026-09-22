//! Authorization and IDOR Penetration Test Suite (ZK-095).
//!
//! Validates:
//! 1. IDOR prevention on objects and mutations (Account A vs Account B);
//! 2. Cross-account object ID guessing returns 404 without leaking existence;
//! 3. Ciphertext blob storage authorization and isolation (GET, HEAD, PUT);
//! 4. History and sync changes stream isolation (Account B never receives Account A changes);
//! 5. Revoked credentials and devices fail closed immediately (HTTP 401 Unauthorized);
//! 6. Malformed and forged tokens fail closed.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::auth::DeviceAuthResponse;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, ERROR_OBJECT_NOT_FOUND, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{PullChangesResponse, PushRequest};
use zk_server::app::{create_app, AppState, ErrorResponse};
use zk_server::config::ServerConfig;

fn setup_test_app() -> (axum::Router, AppState) {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("create test app state");
    let app = create_app(state.clone());
    (app, state)
}

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

// ----------------------------------------------------------------------------
// 1. IDOR on Objects and Mutations
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_idor_object_mutation_and_deletion() {
    let (app, state) = setup_test_app();

    let account_a = Uuid::new_v4();
    let auth_a = common::bearer(&state, account_a).await;

    let account_b = Uuid::new_v4();
    let auth_b = common::bearer(&state, account_b).await;

    let obj_id = Uuid::new_v4().to_string();

    // 1. Account A creates object
    let push_a = helper_push_request(&obj_id, 0, b"Account A secret content v1", false);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("authorization", &auth_a)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&push_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Account B attempts IDOR update on Account A's object
    let push_b_update = helper_push_request(&obj_id, 1, b"Account B malicious overwrite", false);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&push_b_update).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Account B update on Account A object must return 404 ObjectNotFound"
    );
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err.code, ERROR_OBJECT_NOT_FOUND);

    // 3. Account B attempts IDOR deletion of Account A's object
    let push_b_delete = helper_push_request(&obj_id, 1, b"", true);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&push_b_delete).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 4. Verify Account A's object was unaffected
    let pull_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/sync/changes?since=0&limit=10")
                .header("authorization", &auth_a)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_resp.status(), StatusCode::OK);
    let pull_body = axum::body::to_bytes(pull_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull_data: PullChangesResponse = serde_json::from_slice(&pull_body).unwrap();
    assert_eq!(pull_data.changes.len(), 1);
    assert_eq!(pull_data.changes[0].object_id, obj_id);
    assert_eq!(pull_data.changes[0].revision, 1);
    assert!(!pull_data.changes[0].is_deleted);
}

// ----------------------------------------------------------------------------
// 2. Cross-Account Object Guesses & Enumeration
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_object_enumeration_attempts() {
    let (app, state) = setup_test_app();

    let attacker = Uuid::new_v4();
    let auth_attacker = common::bearer(&state, attacker).await;

    // Attacker attempts to update 20 randomly generated UUIDs
    for _ in 0..20 {
        let guessed_id = Uuid::new_v4().to_string();
        let push_guess = helper_push_request(&guessed_id, 1, b"probe", false);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_attacker)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_guess).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// ----------------------------------------------------------------------------
// 3. Ciphertext Blob Access Control & IDOR
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_blob_access_and_isolation() {
    let (app, state) = setup_test_app();

    let account_a = Uuid::new_v4();
    let auth_a = common::bearer(&state, account_a).await;

    let account_b = Uuid::new_v4();
    let auth_b = common::bearer(&state, account_b).await;

    let blob_id = "target-blob-attachment-xyz-123";
    let blob_data_a = b"CIPHERTEXT_BLOB_OWNED_BY_ACCOUNT_A";

    // 1. Account A uploads blob
    let put_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_a)
                .header("content-type", "application/octet-stream")
                .body(Body::from(blob_data_a.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_a.status(), StatusCode::CREATED);

    // 2. Account B attempts to GET Account A's blob -> 404
    let get_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        get_b.status(),
        StatusCode::NOT_FOUND,
        "Account B GET on Account A blob must return 404"
    );

    // 3. Account B attempts to HEAD Account A's blob -> 404
    let head_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        head_b.status(),
        StatusCode::NOT_FOUND,
        "Account B HEAD on Account A blob must return 404"
    );

    // 4. Account B uploads blob with same blob_id (isolated per account)
    let blob_data_b = b"CIPHERTEXT_BLOB_OWNED_BY_ACCOUNT_B";
    let put_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_b)
                .header("content-type", "application/octet-stream")
                .body(Body::from(blob_data_b.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_b.status(), StatusCode::CREATED);

    // 5. Verify Account A re-downloads and receives Account A's data unchanged
    let get_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_a)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_a.status(), StatusCode::OK);
    let body_a = axum::body::to_bytes(get_a.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body_a.as_ref(), blob_data_a);

    // 6. Verify Account B downloads and receives Account B's data
    let get_b2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/blobs/{blob_id}"))
                .header("authorization", &auth_b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_b2.status(), StatusCode::OK);
    let body_b = axum::body::to_bytes(get_b2.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body_b.as_ref(), blob_data_b);
}

// ----------------------------------------------------------------------------
// 4. History and Sync Changes Stream Isolation
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_sync_changes_stream_isolation() {
    let (app, state) = setup_test_app();

    let account_a = Uuid::new_v4();
    let auth_a = common::bearer(&state, account_a).await;

    let account_b = Uuid::new_v4();
    let auth_b = common::bearer(&state, account_b).await;

    // Account A creates 5 objects
    for i in 0..5 {
        let obj_id = Uuid::new_v4().to_string();
        let push_req = helper_push_request(&obj_id, 0, format!("Note {i}").as_bytes(), false);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sync/push")
                    .header("authorization", &auth_a)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&push_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Account B creates 1 object
    let b_obj_id = Uuid::new_v4().to_string();
    let push_b = helper_push_request(&b_obj_id, 0, b"Account B sole note", false);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync/push")
                .header("authorization", &auth_b)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&push_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Account B calls sync changes
    let pull_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/sync/changes?since=0&limit=50")
                .header("authorization", &auth_b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_b.status(), StatusCode::OK);
    let body_b = axum::body::to_bytes(pull_b.into_body(), usize::MAX)
        .await
        .unwrap();
    let changes_b: PullChangesResponse = serde_json::from_slice(&body_b).unwrap();

    assert_eq!(changes_b.changes.len(), 1);
    assert_eq!(changes_b.changes[0].object_id, b_obj_id);
}

// ----------------------------------------------------------------------------
// 5. Revoked Credentials & Device Penetration Tests
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_revoked_session_and_device_credentials() {
    let (app, state) = setup_test_app();

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // 1. Authorize device and obtain valid session token
    let auth_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "Penetration Test Rig"
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
    let session_id = auth_resp.session.session_id;

    let auth_header = format!("Bearer {token}");

    // 2. Verify token is active
    let check_req = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes?since=0&limit=10")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let check_resp = app.clone().oneshot(check_req).await.unwrap();
    assert_eq!(check_resp.status(), StatusCode::OK);

    // 3. Explicitly revoke the session token
    let revoked = state
        .db
        .revoke_session(account_id, session_id)
        .await
        .unwrap();
    assert!(revoked, "session revocation should succeed");

    // 4. Test revoked session fails closed on all endpoints (HTTP 401)
    let endpoints = [
        ("GET", "/v1/sync/changes?since=0&limit=10"),
        ("GET", "/v1/devices"),
        ("GET", "/v1/auth/session/status"),
        ("GET", "/v1/blobs/dummy-blob"),
    ];

    for (method, uri) in endpoints {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &auth_header)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Revoked session must be rejected with 401 on {method} {uri}"
        );
    }

    // 5. Test Revoked Device
    // Create new session on device_id
    let auth_req2 = Request::builder()
        .method("POST")
        .uri("/v1/auth/device/authorize")
        .header("authorization", common::bearer(&state, account_id).await)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "device_name": "Penetration Test Rig 2"
            })
            .to_string(),
        ))
        .unwrap();
    let resp2 = app.clone().oneshot(auth_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body_bytes2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let auth_resp2: DeviceAuthResponse = serde_json::from_slice(&body_bytes2).unwrap();
    let token2 = auth_resp2.session.token.expose_secret().to_string();
    let auth_header2 = format!("Bearer {token2}");

    // Revoke the entire device via DELETE /v1/devices/{device_id}
    let del_dev_req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/devices/{device_id}"))
        .header("authorization", &auth_header2)
        .body(Body::empty())
        .unwrap();
    let del_dev_resp = app.clone().oneshot(del_dev_req).await.unwrap();
    assert_eq!(del_dev_resp.status(), StatusCode::OK);

    // Any request using credentials from the revoked device must now fail with 401
    let req_after = Request::builder()
        .method("GET")
        .uri("/v1/sync/changes?since=0&limit=10")
        .header("authorization", &auth_header2)
        .body(Body::empty())
        .unwrap();
    let resp_after = app.clone().oneshot(req_after).await.unwrap();
    assert_eq!(
        resp_after.status(),
        StatusCode::UNAUTHORIZED,
        "Credentials on revoked device must fail closed with 401"
    );
}

// ----------------------------------------------------------------------------
// 6. Malformed and Forged Token Penetration
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_penetration_forged_and_malformed_tokens() {
    let (app, _state) = setup_test_app();

    let bad_auth_headers = [
        "",                                            // Missing/empty
        "Bearer",                                      // Missing token
        "Bearer ",                                     // Empty bearer
        "Basic dXNlcjpwYXNz",                          // Wrong scheme
        "Bearer not-a-valid-token-str",                // Invalid token
        "Bearer fake.jwt.token.format",                // Forged JWT-like string
        "Bearer !@#$%^&*()_+",                         // Special characters
        "Bearer ' OR '1'='1",                          // SQL injection attempt
        "Bearer dGhpcyBpcyBub3QgYSB2YWxpZCBzZXNzaW9u", // Base64 non-existent session
    ];

    for header in bad_auth_headers {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/v1/sync/changes?since=0&limit=10");

        if !header.is_empty() {
            builder = builder.header("authorization", header);
        }

        let resp = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Forged/malformed header '{header}' must return 401"
        );
    }
}

mod common;
