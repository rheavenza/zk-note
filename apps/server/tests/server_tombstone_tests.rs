//! Integration tests for server-side tombstone persistence and revisioning (ZK-037).
//!
//! Validates acceptance criteria:
//! 1. Delete mutation is revisioned (revision increments by 1, sequence allocated, prior state archived);
//! 2. Stale edit against tombstone conflicts (stale revision and duplicate create both reject with HTTP 409);
//! 3. Deleted object remains sync-visible (tombstone with is_deleted=true returned in GET /v1/sync/changes);
//! 4. Explicit resurrection preserves audit history (un-delete at current revision succeeds and records history).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, ERROR_REVISION_CONFLICT, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{ConflictResponse, PullChangesResponse, PushRequest, PushResponse};
use zk_server::app::{create_app, AppState};
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

#[tokio::test]
async fn test_tombstone_delete_is_revisioned_and_history_preserved() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Create note at revision 1 (seq 1)
    let create_req = helper_push_request(&obj_str, 0, b"active content", false);
    let create_http = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
        .unwrap();

    let create_resp = app.clone().oneshot(create_http).await.unwrap();
    assert_eq!(create_resp.status(), StatusCode::OK);
    let body1 = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let push1: PushResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(push1.revision, 1);
    assert_eq!(push1.server_seq, 1);

    // 2. Delete note: expected_revision = 1, is_deleted = true
    let del_req = helper_push_request(&obj_str, 1, b"tombstone envelope", true);
    let del_http = Request::builder()
        .uri("/v1/sync/push")
        .method("POST")
        .header("authorization", &auth_header)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&del_req).unwrap()))
        .unwrap();

    let del_resp = app.clone().oneshot(del_http).await.unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);
    let body2 = axum::body::to_bytes(del_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let push2: PushResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(
        push2.revision, 2,
        "delete mutation increments revision to 2"
    );
    assert_eq!(
        push2.server_seq, 2,
        "delete mutation allocates next server sequence"
    );

    // 3. Verify current object row in DB is marked is_deleted = true
    let stored_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("tombstone row must exist in encrypted_objects");
    assert_eq!(stored_obj.revision, 2);
    assert_eq!(stored_obj.server_seq, 2);
    assert!(stored_obj.is_deleted, "object must be marked as deleted");

    // 4. Verify history preserves prior active revision 1
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(
        history.len(),
        1,
        "prior active state must be archived in history"
    );
    assert_eq!(history[0].revision, 1);
    assert_eq!(history[0].server_seq, 1);
    assert!(!history[0].is_deleted, "prior state was active");
}

#[tokio::test]
async fn test_tombstone_stale_edit_and_duplicate_create_conflict() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Create (rev 1)
    let create_req = helper_push_request(&obj_str, 0, b"v1", false);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Delete (rev 1 -> rev 2 tombstone)
    let del_req = helper_push_request(&obj_str, 1, b"tombstone", true);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&del_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Stale offline edit based on revision 1 (is_deleted = false) MUST conflict (SEC-008)
    let stale_edit = helper_push_request(&obj_str, 1, b"stale edit content", false);
    let stale_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&stale_edit).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_resp.status(), StatusCode::CONFLICT);

    let stale_body = axum::body::to_bytes(stale_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let conflict: ConflictResponse = serde_json::from_slice(&stale_body).unwrap();
    assert_eq!(conflict.error, ERROR_REVISION_CONFLICT);
    assert_eq!(conflict.expected_revision, 1);
    assert_eq!(
        conflict.current_revision, 2,
        "current revision is tombstone rev 2"
    );
    assert_eq!(conflict.current_server_seq, 2);

    // 4. Stale client trying to create with expected_revision = 0 MUST conflict
    let duplicate_create = helper_push_request(&obj_str, 0, b"resurrect without revision", false);
    let dup_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&duplicate_create).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

    let dup_body = axum::body::to_bytes(dup_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let dup_conflict: ConflictResponse = serde_json::from_slice(&dup_body).unwrap();
    assert_eq!(dup_conflict.error, ERROR_REVISION_CONFLICT);
    assert_eq!(dup_conflict.expected_revision, 0);
    assert_eq!(dup_conflict.current_revision, 2);
}

#[tokio::test]
async fn test_tombstone_remains_sync_visible() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    let obj1 = Uuid::new_v4().to_string();
    let obj2 = Uuid::new_v4().to_string();

    // 1. Create obj1 (seq 1, rev 1)
    let req1 = helper_push_request(&obj1, 0, b"note 1", false);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Create obj2 (seq 2, rev 1)
    let req2 = helper_push_request(&obj2, 0, b"note 2", false);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 3. Delete obj1 (seq 3, rev 2 tombstone)
    let del1 = helper_push_request(&obj1, 1, b"tombstone 1", true);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&del1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 4. Peer client pulling from cursor 0 sees both obj2 (active) and obj1 (tombstone)
    let pull_http = Request::builder()
        .uri("/v1/sync/changes?after=0&limit=50")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();

    let pull_resp = app.clone().oneshot(pull_http).await.unwrap();
    assert_eq!(pull_resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(pull_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull: PullChangesResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pull.changes.len(), 2);

    // obj2 at seq 2
    assert_eq!(pull.changes[0].object_id, obj2);
    assert_eq!(pull.changes[0].server_seq, 2);
    assert!(!pull.changes[0].is_deleted);

    // obj1 at seq 3 (tombstone)
    assert_eq!(pull.changes[1].object_id, obj1);
    assert_eq!(pull.changes[1].server_seq, 3);
    assert_eq!(pull.changes[1].revision, 2);
    assert!(
        pull.changes[1].is_deleted,
        "tombstone must be visible with is_deleted=true"
    );

    // 5. Peer client pulling incrementally from cursor 2 sees only the tombstone at seq 3
    let inc_http = Request::builder()
        .uri("/v1/sync/changes?after=2&limit=50")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();

    let inc_resp = app.oneshot(inc_http).await.unwrap();
    assert_eq!(inc_resp.status(), StatusCode::OK);

    let inc_body = axum::body::to_bytes(inc_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let inc_pull: PullChangesResponse = serde_json::from_slice(&inc_body).unwrap();
    assert_eq!(inc_pull.changes.len(), 1);
    assert_eq!(inc_pull.changes[0].object_id, obj1);
    assert_eq!(inc_pull.changes[0].server_seq, 3);
    assert!(inc_pull.changes[0].is_deleted);
}

#[tokio::test]
async fn test_tombstone_explicit_resurrection_lifecycle() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let object_id = Uuid::new_v4();
    let obj_str = object_id.to_string();

    // 1. Create note (rev 1)
    let create_req = helper_push_request(&obj_str, 0, b"v1 active", false);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&create_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Delete note (rev 1 -> rev 2 tombstone)
    let del_req = helper_push_request(&obj_str, 1, b"tombstone envelope", true);
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&del_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // 3. Client explicitly resurrects the note with expected_revision = 2, is_deleted = false
    let resurrect_req = helper_push_request(&obj_str, 2, b"resurrected active note", false);
    let res_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&resurrect_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_resp.status(), StatusCode::OK);

    let res_body = axum::body::to_bytes(res_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let push3: PushResponse = serde_json::from_slice(&res_body).unwrap();
    assert_eq!(push3.revision, 3, "resurrected note is at revision 3");
    assert_eq!(push3.server_seq, 3);

    // 4. Verify DB state: object is active (is_deleted = false) at revision 3
    let current_obj = state
        .db
        .get_encrypted_object(account_id, object_id)
        .await
        .unwrap()
        .expect("object must exist");
    assert_eq!(current_obj.revision, 3);
    assert!(!current_obj.is_deleted, "object is active again");

    // 5. Verify complete history audit trail:
    // Rev 1: active
    // Rev 2: tombstone (is_deleted = true)
    let history = state
        .db
        .get_object_history(account_id, object_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].revision, 1);
    assert!(!history[0].is_deleted);
    assert_eq!(history[1].revision, 2);
    assert!(
        history[1].is_deleted,
        "tombstone state preserved in history"
    );
}
