//! Integration tests for mutation idempotency and duplicate retry handling (POST /v1/sync/push) (ZK-035).
//!
//! Validates acceptance criteria:
//! 1. Same mutation ID/same request returns original result;
//! 2. No additional revision/server sequence on replay;
//! 3. Same mutation ID with incompatible payload returns explicit replay mismatch error;
//! 4. Concurrency test for duplicate simultaneous retries.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{
    ENVELOPE_VERSION_V1, ERROR_MUTATION_REPLAY_MISMATCH, OBJECT_KIND_NOTE,
};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{PushRequest, PushResponse};
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

fn helper_push_request_with_id(
    mutation_id: &str,
    object_id: &str,
    expected_revision: u64,
    payload_bytes: &[u8],
) -> PushRequest {
    PushRequest {
        mutation_id: mutation_id.to_string(),
        object_id: object_id.to_string(),
        expected_revision,
        object_kind: OBJECT_KIND_NOTE,
        envelope: helper_envelope(object_id, payload_bytes),
        is_deleted: false,
    }
}

#[tokio::test]
async fn test_mutation_idempotency_same_create_request_returns_original_result() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();
    let mutation_id = Uuid::new_v4().to_string();

    let req = helper_push_request_with_id(&mutation_id, &obj_str, 0, b"secret initial note");
    let req_bytes = serde_json::to_vec(&req).unwrap();

    // First request
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(req_bytes.clone()))
        .unwrap();

    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp1: PushResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(push_resp1.object_id, obj_str);
    assert_eq!(push_resp1.revision, 1);
    assert_eq!(push_resp1.server_seq, 1);

    // Replay exact same request
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(req_bytes.clone()))
        .unwrap();

    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp2: PushResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(
        push_resp2, push_resp1,
        "replayed create must return original response"
    );

    // Verify DB state: no additional sequence or revision
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
    let stored_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object exists");
    assert_eq!(stored_obj.revision, 1);
    assert_eq!(stored_obj.server_seq, 1);

    // History is empty
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_mutation_idempotency_same_update_request_returns_original_result() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Initial create
    let create_mut_id = Uuid::new_v4().to_string();
    let create_req =
        helper_push_request_with_id(&create_mut_id, &obj_str, 0, b"revision 1 payload");
    let create_http = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let create_resp = app.clone().oneshot(create_http).await.unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);

    // 2. Perform update (revision 1 -> 2)
    let update_mut_id = Uuid::new_v4().to_string();
    let update_req =
        helper_push_request_with_id(&update_mut_id, &obj_str, 1, b"revision 2 payload");
    let update_bytes = serde_json::to_vec(&update_req).unwrap();

    let update_http1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(update_bytes.clone()))
        .unwrap();
    let update_resp1 = app.clone().oneshot(update_http1).await.unwrap();
    assert_eq!(update_resp1.status(), StatusCode::OK);
    let body1 = axum::body::to_bytes(update_resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp1: PushResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(push_resp1.revision, 2);
    assert_eq!(push_resp1.server_seq, 2);

    // 3. Replay exact same update
    let update_http2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(update_bytes.clone()))
        .unwrap();
    let update_resp2 = app.clone().oneshot(update_http2).await.unwrap();
    assert_eq!(update_resp2.status(), StatusCode::OK);
    let body2 = axum::body::to_bytes(update_resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp2: PushResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(
        push_resp2, push_resp1,
        "replayed update must return original PushResponse"
    );

    // 4. Replay once more
    let update_http3 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(update_bytes.clone()))
        .unwrap();
    let update_resp3 = app.clone().oneshot(update_http3).await.unwrap();
    assert_eq!(update_resp3.status(), StatusCode::OK);
    let body3 = axum::body::to_bytes(update_resp3.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp3: PushResponse = serde_json::from_slice(&body3).unwrap();
    assert_eq!(push_resp3, push_resp1);

    // Verify DB state: revision is still 2, server_seq is still 2
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 2);
    let stored_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object exists");
    assert_eq!(stored_obj.revision, 2);
    assert_eq!(stored_obj.server_seq, 2);

    // History has exactly 1 entry (revision 1)
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].revision, 1);
}

#[tokio::test]
async fn test_mutation_idempotency_replay_mismatch_object_id() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let obj1 = Uuid::new_v4().to_string();
    let obj2 = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    // Push for object 1
    let req1 = helper_push_request_with_id(&mutation_id, &obj1, 0, b"content 1");
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Attempt replay of same mutation_id for object 2
    let req2 = helper_push_request_with_id(&mutation_id, &obj2, 0, b"content 2");
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);

    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err_resp.code, ERROR_MUTATION_REPLAY_MISMATCH);
    assert!(
        err_resp.message.contains("previously processed for object"),
        "error message should detail object ID mismatch"
    );

    // Ensure sequence did not increment
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_mutation_idempotency_replay_mismatch_expected_revision() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let obj = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    // Push with expected_revision = 0
    let req1 = helper_push_request_with_id(&mutation_id, &obj, 0, b"content");
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Replay same mutation_id with expected_revision = 1
    let mut req2 = helper_push_request_with_id(&mutation_id, &obj, 1, b"content");
    req2.expected_revision = 1;
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);

    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err_resp.code, ERROR_MUTATION_REPLAY_MISMATCH);
    assert!(
        err_resp.message.contains("incompatible payload"),
        "error message should detail incompatible payload"
    );

    // Ensure sequence did not increment
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_mutation_idempotency_replay_mismatch_payload_tampered() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let obj = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    // Push with original payload
    let req1 = helper_push_request_with_id(&mutation_id, &obj, 0, b"original payload");
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Replay same mutation_id with altered payload ciphertext
    let req2 = helper_push_request_with_id(&mutation_id, &obj, 0, b"altered payload");
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);

    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err_resp.code, ERROR_MUTATION_REPLAY_MISMATCH);
    assert!(err_resp.message.contains("incompatible payload"));

    // Ensure sequence did not increment
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_mutation_idempotency_replay_mismatch_is_deleted_flag() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let obj = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    // Push with is_deleted = false
    let mut req1 = helper_push_request_with_id(&mutation_id, &obj, 0, b"active payload");
    req1.is_deleted = false;
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Replay same mutation_id with is_deleted = true
    let mut req2 = helper_push_request_with_id(&mutation_id, &obj, 0, b"active payload");
    req2.is_deleted = true;
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);

    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err_resp: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err_resp.code, ERROR_MUTATION_REPLAY_MISMATCH);
    assert!(err_resp.message.contains("incompatible payload"));

    // Ensure sequence did not increment
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_mutation_idempotency_concurrency_duplicate_simultaneous_retries() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();
    let mutation_id = Uuid::new_v4().to_string();

    let push_req =
        helper_push_request_with_id(&mutation_id, &obj_str, 0, b"concurrent duplicate payload");
    let req_bytes = serde_json::to_vec(&push_req).unwrap();

    const NUM_TASKS: usize = 50;
    let mut handles = Vec::with_capacity(NUM_TASKS);

    for _ in 0..NUM_TASKS {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let payload = req_bytes.clone();

        handles.push(tokio::spawn(async move {
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap();

            let resp = app_clone.oneshot(http_req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let push_resp: PushResponse = serde_json::from_slice(&body).unwrap();
            (status, push_resp)
        }));
    }

    let mut results = Vec::with_capacity(NUM_TASKS);
    for h in handles {
        let res = h.await.unwrap();
        results.push(res);
    }

    // Assert ALL 50 tasks returned HTTP 200 OK
    for (status, push_resp) in &results {
        assert_eq!(*status, StatusCode::OK);
        assert_eq!(push_resp.object_id, obj_str);
        assert_eq!(push_resp.revision, 1);
        assert_eq!(push_resp.server_seq, 1);
    }

    // Assert DB state has exactly 1 sequence and revision 1
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
    let stored_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object exists");
    assert_eq!(stored_obj.revision, 1);
    assert_eq!(stored_obj.server_seq, 1);

    // History must be empty
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_mutation_idempotency_concurrency_update_simultaneous_retries() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Create initial object
    let create_req =
        helper_push_request_with_id(&Uuid::new_v4().to_string(), &obj_str, 0, b"initial version");
    let create_http = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();
    let create_resp = app.clone().oneshot(create_http).await.unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);

    // 2. Perform concurrent retries of update (revision 1 -> 2) with the same mutation ID
    let update_mut_id = Uuid::new_v4().to_string();
    let update_req =
        helper_push_request_with_id(&update_mut_id, &obj_str, 1, b"updated version concurrently");
    let req_bytes = serde_json::to_vec(&update_req).unwrap();

    const NUM_TASKS: usize = 50;
    let mut handles = Vec::with_capacity(NUM_TASKS);

    for _ in 0..NUM_TASKS {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let payload = req_bytes.clone();

        handles.push(tokio::spawn(async move {
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap();

            let resp = app_clone.oneshot(http_req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let push_resp: PushResponse = serde_json::from_slice(&body).unwrap();
            (status, push_resp)
        }));
    }

    let mut results = Vec::with_capacity(NUM_TASKS);
    for h in handles {
        let res = h.await.unwrap();
        results.push(res);
    }

    // All tasks must have returned 200 OK with revision 2, sequence 2
    for (status, push_resp) in &results {
        assert_eq!(*status, StatusCode::OK);
        assert_eq!(push_resp.object_id, obj_str);
        assert_eq!(push_resp.revision, 2);
        assert_eq!(push_resp.server_seq, 2);
    }

    // Assert DB state: sequence is 2, object revision is 2
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 2);
    let stored_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object exists");
    assert_eq!(stored_obj.revision, 2);
    assert_eq!(stored_obj.server_seq, 2);

    // History must contain exactly 1 entry (for revision 1)
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].revision, 1);
}
