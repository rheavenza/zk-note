//! Integration tests for Pull Changes endpoint (GET /v1/sync/changes) (ZK-036).
//!
//! Validates acceptance criteria:
//! 1. Ordered `server_seq` (changes returned strictly ascending);
//! 2. Pagination (paginates via `after` cursor and `limit`, `has_more`, `next_cursor`);
//! 3. Cursor semantics documented;
//! 4. Tombstones included (`is_deleted: true` objects returned in stream);
//! 5. No missed rows under concurrent writes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use std::collections::HashSet;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{
    ENVELOPE_VERSION_V1, ERROR_AUTH_REQUIRED, ERROR_SYNC_CURSOR_INVALID, OBJECT_KIND_NOTE,
};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{PullChangesResponse, PushRequest, PushResponse};
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
async fn test_pull_changes_empty_account() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    let req = Request::builder()
        .uri("/v1/sync/changes")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull_resp: PullChangesResponse = serde_json::from_slice(&body).unwrap();
    assert!(pull_resp.changes.is_empty());
    assert_eq!(pull_resp.next_cursor, 0);
    assert!(!pull_resp.has_more);
}

#[tokio::test]
async fn test_pull_changes_ordered_server_seq() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    // Create 5 distinct objects
    let mut obj_ids = Vec::new();
    for i in 1..=5 {
        let obj_id = Uuid::new_v4().to_string();
        obj_ids.push(obj_id.clone());
        let push_req = helper_push_request(&obj_id, 0, format!("note {i}").as_bytes());

        let http_req = Request::builder()
            .uri("/v1/sync/push")
            .method("POST")
            .header("authorization", &auth_header)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&push_req).unwrap()))
            .unwrap();

        let push_resp = app.clone().oneshot(http_req).await.unwrap();
        assert_eq!(push_resp.status(), StatusCode::OK);
    }

    // Pull all changes
    let pull_http = Request::builder()
        .uri("/v1/sync/changes?after=0&limit=50")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(pull_http).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull_resp: PullChangesResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(pull_resp.changes.len(), 5);
    assert_eq!(pull_resp.next_cursor, 5);
    assert!(!pull_resp.has_more);

    // Assert strictly ascending sequence order
    for (idx, change) in pull_resp.changes.iter().enumerate() {
        assert_eq!(change.server_seq, (idx + 1) as u64);
        assert_eq!(change.object_id, obj_ids[idx]);
        assert_eq!(change.revision, 1);
        assert!(!change.is_deleted);
    }
}

#[tokio::test]
async fn test_pull_changes_pagination_flow() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    // Create 7 objects
    for i in 1..=7 {
        let obj_id = Uuid::new_v4().to_string();
        let push_req = helper_push_request(&obj_id, 0, format!("item {i}").as_bytes());

        let http_req = Request::builder()
            .uri("/v1/sync/push")
            .method("POST")
            .header("authorization", &auth_header)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&push_req).unwrap()))
            .unwrap();

        let push_resp = app.clone().oneshot(http_req).await.unwrap();
        assert_eq!(push_resp.status(), StatusCode::OK);
    }

    // Page 1: limit 3
    let req1 = Request::builder()
        .uri("/v1/sync/changes?after=0&limit=3")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let page1: PullChangesResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(page1.changes.len(), 3);
    assert_eq!(page1.changes[0].server_seq, 1);
    assert_eq!(page1.changes[1].server_seq, 2);
    assert_eq!(page1.changes[2].server_seq, 3);
    assert_eq!(page1.next_cursor, 3);
    assert!(page1.has_more);

    // Page 2: after cursor 3, limit 3
    let req2 = Request::builder()
        .uri(format!(
            "/v1/sync/changes?after={}&limit=3",
            page1.next_cursor
        ))
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let page2: PullChangesResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(page2.changes.len(), 3);
    assert_eq!(page2.changes[0].server_seq, 4);
    assert_eq!(page2.changes[1].server_seq, 5);
    assert_eq!(page2.changes[2].server_seq, 6);
    assert_eq!(page2.next_cursor, 6);
    assert!(page2.has_more);

    // Page 3: after cursor 6, limit 3
    let req3 = Request::builder()
        .uri(format!(
            "/v1/sync/changes?after={}&limit=3",
            page2.next_cursor
        ))
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp3 = app.clone().oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = axum::body::to_bytes(resp3.into_body(), usize::MAX)
        .await
        .unwrap();
    let page3: PullChangesResponse = serde_json::from_slice(&body3).unwrap();
    assert_eq!(page3.changes.len(), 1);
    assert_eq!(page3.changes[0].server_seq, 7);
    assert_eq!(page3.next_cursor, 7);
    assert!(!page3.has_more);

    // Page 4: after cursor 7 -> empty
    let req4 = Request::builder()
        .uri(format!(
            "/v1/sync/changes?after={}&limit=3",
            page3.next_cursor
        ))
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp4 = app.clone().oneshot(req4).await.unwrap();
    assert_eq!(resp4.status(), StatusCode::OK);
    let body4 = axum::body::to_bytes(resp4.into_body(), usize::MAX)
        .await
        .unwrap();
    let page4: PullChangesResponse = serde_json::from_slice(&body4).unwrap();
    assert!(page4.changes.is_empty());
    assert_eq!(page4.next_cursor, 7);
    assert!(!page4.has_more);
}

#[tokio::test]
async fn test_pull_changes_includes_tombstones() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    let obj1 = Uuid::new_v4().to_string();
    let obj2 = Uuid::new_v4().to_string();

    // 1. Create obj1 (seq 1, rev 1)
    let req1 = helper_push_request(&obj1, 0, b"note 1 content");
    let resp1 = app
        .clone()
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
    assert_eq!(resp1.status(), StatusCode::OK);

    // 2. Create obj2 (seq 2, rev 1)
    let req2 = helper_push_request(&obj2, 0, b"note 2 content");
    let resp2 = app
        .clone()
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
    assert_eq!(resp2.status(), StatusCode::OK);

    // 3. Delete obj1 (seq 3, rev 2, is_deleted: true)
    let mut del_req = helper_push_request(&obj1, 1, b"tombstone envelope");
    del_req.is_deleted = true;
    let del_resp = app
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
    assert_eq!(del_resp.status(), StatusCode::OK);

    // 4. Pull all changes
    let pull_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", &auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(pull_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull: PullChangesResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(pull.changes.len(), 2);
    // obj2 was at seq 2
    assert_eq!(pull.changes[0].object_id, obj2);
    assert_eq!(pull.changes[0].server_seq, 2);
    assert!(!pull.changes[0].is_deleted);

    // obj1 was updated with tombstone at seq 3
    assert_eq!(pull.changes[1].object_id, obj1);
    assert_eq!(pull.changes[1].server_seq, 3);
    assert_eq!(pull.changes[1].revision, 2);
    assert!(
        pull.changes[1].is_deleted,
        "tombstone must be flagged is_deleted"
    );
}

#[tokio::test]
async fn test_pull_changes_endpoint_aliases() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");
    let obj_id = Uuid::new_v4().to_string();

    let push_req = helper_push_request(&obj_id, 0, b"note");
    let push_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_header)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&push_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(push_resp.status(), StatusCode::OK);

    // Pull via /v1/sync/changes
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
                .header("authorization", &auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull1: PullChangesResponse = serde_json::from_slice(&body1).unwrap();

    // Pull via /v1/sync/pull
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/pull")
                .method("GET")
                .header("authorization", &auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let pull2: PullChangesResponse = serde_json::from_slice(&body2).unwrap();

    assert_eq!(pull1, pull2, "aliases must return identical pull responses");
}

#[tokio::test]
async fn test_pull_changes_cross_account_isolation() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_a = Uuid::new_v4();
    let account_b = Uuid::new_v4();
    let auth_a = format!("Bearer {account_a}");
    let auth_b = format!("Bearer {account_b}");

    // Account A creates 3 objects
    for i in 1..=3 {
        let obj_id = Uuid::new_v4().to_string();
        let push_req = helper_push_request(&obj_id, 0, format!("account A note {i}").as_bytes());
        let http_req = Request::builder()
            .uri("/v1/sync/push")
            .method("POST")
            .header("authorization", &auth_a)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&push_req).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(http_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Account B pulls changes -> must see 0 changes
    let pull_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/sync/changes")
                .method("GET")
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
    let pull_resp_b: PullChangesResponse = serde_json::from_slice(&body_b).unwrap();
    assert!(
        pull_resp_b.changes.is_empty(),
        "account B must not see any changes from account A"
    );
}

#[tokio::test]
async fn test_pull_changes_auth_required() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let req = Request::builder()
        .uri("/v1/sync/changes")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ERROR_AUTH_REQUIRED);
}

#[tokio::test]
async fn test_pull_changes_invalid_query_parameters() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = format!("Bearer {account_id}");

    // Invalid 'after' cursor parameter
    let req1 = Request::builder()
        .uri("/v1/sync/changes?after=abc")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::BAD_REQUEST);
    let body1 = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .unwrap();
    let err1: ErrorResponse = serde_json::from_slice(&body1).unwrap();
    assert_eq!(err1.code, ERROR_SYNC_CURSOR_INVALID);

    // Invalid 'limit' parameter
    let req2 = Request::builder()
        .uri("/v1/sync/changes?limit=xyz")
        .method("GET")
        .header("authorization", &auth_header)
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let err2: ErrorResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(err2.code, ERROR_SYNC_CURSOR_INVALID);
}

#[tokio::test]
async fn test_pull_changes_concurrency_no_missed_rows() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state);

    let account_id = Uuid::new_v4();
    let auth_header = Arc::new(format!("Bearer {account_id}"));

    const NUM_WRITES: usize = 30;
    let mut write_handles = Vec::with_capacity(NUM_WRITES);

    // 1. Spawn 30 concurrent push mutation writes
    for i in 0..NUM_WRITES {
        let app_clone = app.clone();
        let auth_clone = Arc::clone(&auth_header);
        let obj_id = Uuid::new_v4().to_string();

        write_handles.push(tokio::spawn(async move {
            let req = helper_push_request(&obj_id, 0, format!("concurrent note {i}").as_bytes());
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", auth_clone.as_str())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap();

            let resp = app_clone.oneshot(http_req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let push_resp: PushResponse = serde_json::from_slice(&body).unwrap();
            (obj_id, push_resp.server_seq)
        }));
    }

    // Await all writes
    let mut pushed_objects = HashSet::new();
    let mut max_seq = 0u64;
    for h in write_handles {
        let (obj_id, seq) = h.await.unwrap();
        pushed_objects.insert(obj_id);
        if seq > max_seq {
            max_seq = seq;
        }
    }
    assert_eq!(pushed_objects.len(), NUM_WRITES);
    assert_eq!(max_seq, NUM_WRITES as u64);

    // 2. Concurrently pull changes in pages from 5 different reader tasks
    const NUM_READERS: usize = 5;
    let mut reader_handles = Vec::with_capacity(NUM_READERS);

    for _ in 0..NUM_READERS {
        let app_clone = app.clone();
        let auth_clone = Arc::clone(&auth_header);

        reader_handles.push(tokio::spawn(async move {
            let mut cursor = 0u64;
            let mut read_objects = Vec::new();
            let mut read_sequences = Vec::new();

            loop {
                let http_req = Request::builder()
                    .uri(format!("/v1/sync/changes?after={cursor}&limit=7"))
                    .method("GET")
                    .header("authorization", auth_clone.as_str())
                    .body(Body::empty())
                    .unwrap();

                let resp = app_clone.clone().oneshot(http_req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let pull_resp: PullChangesResponse = serde_json::from_slice(&body).unwrap();

                for c in pull_resp.changes {
                    read_sequences.push(c.server_seq);
                    read_objects.push(c.object_id);
                }

                cursor = pull_resp.next_cursor;
                if !pull_resp.has_more {
                    break;
                }
            }

            (read_objects, read_sequences)
        }));
    }

    // Verify all readers observed all 30 items in strict sequence 1..=30 without missing rows
    for h in reader_handles {
        let (read_objects, read_sequences) = h.await.unwrap();
        assert_eq!(read_objects.len(), NUM_WRITES);
        assert_eq!(read_sequences.len(), NUM_WRITES);

        // Sequence must be strictly contiguous 1..=30
        for (idx, seq) in read_sequences.iter().enumerate() {
            assert_eq!(*seq, (idx + 1) as u64);
        }

        // All pushed objects must have been read
        let read_set: HashSet<String> = read_objects.into_iter().collect();
        assert_eq!(read_set, pushed_objects);
    }
}
