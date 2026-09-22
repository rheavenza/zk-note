//! Integration tests for CAS push mutation endpoint (POST /v1/sync/push) (ZK-034).
//!
//! Validates acceptance criteria:
//! 1. Create expected revision 0 (first write creates object at revision 1, duplicate create rejected);
//! 2. Update requires exact current revision (CAS matching passes);
//! 3. Stale update rejected (stale revision returns HTTP 409 Conflict with ConflictResponse);
//! 4. Successful update increments revision exactly once;
//! 5. Previous revision stored in history (object_history retains prior revisions with complete metadata);
//! 6. Zero-knowledge security invariants (SEC-001/SEC-002: no plaintext secrets, authentication required, cross-account isolated).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{
    ENVELOPE_VERSION_V1, ERROR_AUTH_REQUIRED, ERROR_INVALID_ENVELOPE, ERROR_OBJECT_NOT_FOUND,
    ERROR_REVISION_CONFLICT, OBJECT_KIND_NOTE,
};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{ConflictResponse, PushRequest, PushResponse};
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
) -> PushRequest {
    PushRequest {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: object_id.to_string(),
        expected_revision,
        object_kind: OBJECT_KIND_NOTE,
        envelope: helper_envelope(object_id, payload_bytes),
        is_deleted: false,
    }
}

#[tokio::test]
async fn test_cas_push_create_revision_zero_and_update_lifecycle() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Initial creation with expected_revision = 0
    let req1 = helper_push_request(&obj_str, 0, b"first draft content");
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();

    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp1: PushResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(push_resp1.object_id, obj_str);
    assert_eq!(push_resp1.revision, 1, "first revision must be 1");
    assert_eq!(push_resp1.server_seq, 1, "first server sequence must be 1");

    // History is empty after create
    let hist1 = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert!(
        hist1.is_empty(),
        "history must be empty after initial creation"
    );

    // 2. Successful update 1: expected_revision = 1 -> revision 2
    let req2 = helper_push_request(&obj_str, 1, b"second draft content");
    let http_req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req2).unwrap()))
        .unwrap();

    let resp2 = app.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp2: PushResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(push_resp2.revision, 2, "update increments revision to 2");
    assert_eq!(push_resp2.server_seq, 2, "server sequence increments to 2");

    // Previous revision 1 is now archived in history
    let hist2 = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(
        hist2.len(),
        1,
        "previous revision must be archived in history"
    );
    assert_eq!(hist2[0].revision, 1);
    assert_eq!(hist2[0].server_seq, 1);
    assert_eq!(
        hist2[0].payload,
        serde_json::to_vec(&req1.envelope.payload).unwrap()
    );

    // 3. Successful update 2: expected_revision = 2 -> revision 3
    let req3 = helper_push_request(&obj_str, 2, b"third draft content");
    let http_req3 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req3).unwrap()))
        .unwrap();

    let resp3 = app.clone().oneshot(http_req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);

    let body3 = axum::body::to_bytes(resp3.into_body(), usize::MAX)
        .await
        .unwrap();
    let push_resp3: PushResponse = serde_json::from_slice(&body3).unwrap();
    assert_eq!(push_resp3.revision, 3);
    assert_eq!(push_resp3.server_seq, 3);

    // History contains revisions 1 and 2 in order
    let hist3 = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(hist3.len(), 2);
    assert_eq!(hist3[0].revision, 1);
    assert_eq!(hist3[1].revision, 2);

    // Active object in encrypted_objects is at revision 3
    let cur_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object must exist");
    assert_eq!(cur_obj.revision, 3);
    assert_eq!(cur_obj.server_seq, 3);
}

#[tokio::test]
async fn test_cas_push_stale_update_rejected_with_conflict() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Create object at revision 1
    let req1 = helper_push_request(&obj_str, 0, b"original content");
    let http_req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req1).unwrap()))
        .unwrap();
    let resp1 = app.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // 2. Duplicate create attempt (expected_revision = 0) must be rejected with 409 Conflict
    let dup_create = helper_push_request(&obj_str, 0, b"competing create");
    let http_dup = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&dup_create).unwrap()))
        .unwrap();

    let resp_dup = app.clone().oneshot(http_dup).await.unwrap();
    assert_eq!(resp_dup.status(), StatusCode::CONFLICT);

    let body_dup = axum::body::to_bytes(resp_dup.into_body(), usize::MAX)
        .await
        .unwrap();
    let conflict_dup: ConflictResponse = serde_json::from_slice(&body_dup).unwrap();
    assert_eq!(conflict_dup.error, ERROR_REVISION_CONFLICT);
    assert_eq!(conflict_dup.object_id, obj_str);
    assert_eq!(conflict_dup.expected_revision, 0);
    assert_eq!(conflict_dup.current_revision, 1);
    assert_eq!(conflict_dup.current_server_seq, 1);
    assert_eq!(conflict_dup.current_envelope.object_id, obj_str);

    // 3. Stale update attempt (expected_revision = 42 when current is 1) rejected with 409 Conflict
    let stale_req = helper_push_request(&obj_str, 42, b"stale edit");
    let http_stale = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&stale_req).unwrap()))
        .unwrap();

    let resp_stale = app.clone().oneshot(http_stale).await.unwrap();
    assert_eq!(resp_stale.status(), StatusCode::CONFLICT);

    let body_stale = axum::body::to_bytes(resp_stale.into_body(), usize::MAX)
        .await
        .unwrap();
    let conflict_stale: ConflictResponse = serde_json::from_slice(&body_stale).unwrap();
    assert_eq!(conflict_stale.error, ERROR_REVISION_CONFLICT);
    assert_eq!(conflict_stale.expected_revision, 42);
    assert_eq!(conflict_stale.current_revision, 1);

    // Current sequence must remain 1 after conflicts
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

#[tokio::test]
async fn test_cas_push_update_nonexistent_object_returns_not_found() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let non_existent_id = Uuid::new_v4().to_string();

    let req = helper_push_request(&non_existent_id, 1, b"update non-existent");
    let http_req = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req).unwrap()))
        .unwrap();

    let resp = app.oneshot(http_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ERROR_OBJECT_NOT_FOUND);
}

#[tokio::test]
async fn test_cas_push_strict_security_rejection_sec_001_and_sec_002() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let obj_id = Uuid::new_v4().to_string();

    // 1. Passphrase in payload is strictly rejected
    let bad_payload_json = serde_json::json!({
        "mutation_id": Uuid::new_v4().to_string(),
        "object_id": obj_id,
        "expected_revision": 0,
        "object_kind": 1,
        "passphrase": "user-super-secret-password",
        "envelope": {
            "envelope_version": 1,
            "object_id": obj_id,
            "object_kind": 1,
            "wrapped_key": {
                "nonce": "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=",
                "ciphertext": "d3JhcHBlZC1rZXk="
            },
            "payload": {
                "nonce": "YW5vdGhlciAyNC1ieXRlIG5vbmNl",
                "ciphertext": "ZW5jcnlwdGVkLXBheWxvYWQ="
            }
        }
    });

    let req1 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&bad_payload_json).unwrap()))
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);

    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let err1: ErrorResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(err1.code, ERROR_INVALID_ENVELOPE);

    // 2. Missing authorization header is rejected with 401 AUTH_REQUIRED
    let req2 = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&helper_push_request(&obj_id, 0, b"data")).unwrap(),
        ))
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err2: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err2.code, ERROR_AUTH_REQUIRED);
}

#[tokio::test]
async fn test_cas_push_cross_account_isolation() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let auth_a = common::bearer(&state, account_a).await;
    let auth_b = common::bearer(&state, account_b).await;

    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // Account A creates object
    let req_a = helper_push_request(&obj_str, 0, b"account A data");
    let http_a = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_a)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_a).unwrap()))
        .unwrap();
    let resp_a = app.clone().oneshot(http_a).await.unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);

    // Account B tries to update Account A's object with expected_revision = 1
    // For Account B, this object does NOT exist! (returns 404 OBJECT_NOT_FOUND)
    let req_b = helper_push_request(&obj_str, 1, b"account B attempting update");
    let http_b = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_b)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_b).unwrap()))
        .unwrap();
    let resp_b = app.clone().oneshot(http_b).await.unwrap();
    assert_eq!(
        resp_b.status(),
        StatusCode::NOT_FOUND,
        "cross-account object update must not see another account's objects"
    );

    // Account B can create its OWN object with the same object_id without colliding
    let req_b_create = helper_push_request(&obj_str, 0, b"account B independent object");
    let http_b_create = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_b)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_b_create).unwrap()))
        .unwrap();
    let resp_b_create = app.clone().oneshot(http_b_create).await.unwrap();
    assert_eq!(resp_b_create.status(), StatusCode::OK);

    // Account A's object is still at revision 1 and unchanged
    let obj_a = state
        .db
        .get_encrypted_object(account_a, object_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(obj_a.revision, 1);
    assert_eq!(obj_a.server_seq, 1);

    // Account B's object is at revision 1 and server_seq 1
    let obj_b = state
        .db
        .get_encrypted_object(account_b, object_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(obj_b.revision, 1);
    assert_eq!(obj_b.server_seq, 1);
}

mod common;
