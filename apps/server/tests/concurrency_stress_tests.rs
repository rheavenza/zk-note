//! Concurrency Stress Suite (ZK-091 / Milestone 9).
//!
//! Acceptance criteria:
//! - Concurrent writers;
//! - Duplicate mutation races;
//! - Server restart;
//! - Network retry;
//! - No duplicate accepted logical mutation.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::{Base64, Encoding};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{ConflictResponse, PushRequest, PushResponse};
use zk_server::app::{create_app, AppState};
use zk_server::config::ServerConfig;
use zk_server::db::migrations::run_server_migrations;
use zk_server::db::store::{PushOutcome, ServerDb};

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
    mutation_id: &str,
    object_id: &str,
    expected_revision: u64,
    is_deleted: bool,
    payload_bytes: &[u8],
) -> PushRequest {
    PushRequest {
        mutation_id: mutation_id.to_string(),
        object_id: object_id.to_string(),
        expected_revision,
        object_kind: OBJECT_KIND_NOTE,
        envelope: helper_envelope(object_id, payload_bytes),
        is_deleted,
    }
}

// ----------------------------------------------------------------------------
// 1. Concurrent Writers: Race on the exact same object
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_concurrent_writers_same_object_cas_race() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let object_id = Uuid::new_v4().to_string();

    // Initial creation -> revision 1
    let create_req =
        helper_push_request(&Uuid::new_v4().to_string(), &object_id, 0, false, b"rev-1");
    let create_resp = app
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
    assert_eq!(create_resp.status(), StatusCode::OK);

    // 50 concurrent writers all attempt to update object_id from revision 1 -> 2
    const NUM_WRITERS: usize = 50;
    let mut handles = Vec::with_capacity(NUM_WRITERS);

    for i in 0..NUM_WRITERS {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let obj_str = object_id.clone();
        let payload = format!("concurrent-writer-{i}").into_bytes();
        let mut_id = Uuid::new_v4().to_string();

        handles.push(tokio::spawn(async move {
            let req = helper_push_request(&mut_id, &obj_str, 1, false, &payload);
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
                .unwrap();

            let resp = app_clone.oneshot(http_req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, body)
        }));
    }

    let mut successes = 0;
    let mut conflicts = 0;

    for h in handles {
        let (status, body) = h.await.unwrap();
        if status == StatusCode::OK {
            successes += 1;
            let push_resp: PushResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(push_resp.revision, 2);
        } else if status == StatusCode::CONFLICT {
            conflicts += 1;
            let conflict_resp: ConflictResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(conflict_resp.current_revision, 2);
        } else {
            panic!("Unexpected status: {status}");
        }
    }

    // Invariant: EXACTLY 1 writer wins CAS race; exactly 49 receive Conflict
    assert_eq!(successes, 1, "Exactly one writer must succeed");
    assert_eq!(
        conflicts,
        NUM_WRITERS - 1,
        "All other writers must receive 409 Conflict"
    );

    // Invariant: Server sequence allocated is exactly 2
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 2);
    let stored = state
        .db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 2);
    assert_eq!(stored.server_seq, 2);
}

// ----------------------------------------------------------------------------
// 2. Concurrent Writers: 50 writers creating 50 distinct objects concurrently
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_concurrent_writers_distinct_objects() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;

    const NUM_OBJECTS: usize = 50;
    let mut handles = Vec::with_capacity(NUM_OBJECTS);

    for i in 0..NUM_OBJECTS {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let obj_str = Uuid::new_v4().to_string();
        let mut_id = Uuid::new_v4().to_string();
        let payload = format!("distinct-obj-{i}").into_bytes();

        handles.push(tokio::spawn(async move {
            let req = helper_push_request(&mut_id, &obj_str, 0, false, &payload);
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req).unwrap()))
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

    let mut allocated_sequences = Vec::with_capacity(NUM_OBJECTS);
    for h in handles {
        let (status, push_resp) = h.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(push_resp.revision, 1);
        allocated_sequences.push(push_resp.server_seq);
    }

    // Invariant: All 50 allocations must be unique and strictly in 1..=50
    assert_eq!(allocated_sequences.len(), NUM_OBJECTS);
    let unique_sequences: HashSet<_> = allocated_sequences.iter().copied().collect();
    assert_eq!(
        unique_sequences.len(),
        NUM_OBJECTS,
        "No duplicate sequence numbers allowed"
    );
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 50);

    // Pull changes from 0 -> must yield all 50 objects in sequence order
    let pull = state.db.pull_changes(account_id, 0, 100).await.unwrap();
    assert_eq!(pull.changes.len(), NUM_OBJECTS);
    assert_eq!(pull.next_cursor, 50);
}

// ----------------------------------------------------------------------------
// 3. Duplicate Mutation Races (50 tasks firing exact same mutation simultaneously)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_duplicate_mutation_races() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;
    let object_id = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    let req = helper_push_request(&mutation_id, &object_id, 0, false, b"exact-same-content");
    let req_bytes = Arc::new(serde_json::to_vec(&req).unwrap());

    const NUM_CONCURRENT_RETRIES: usize = 50;
    let mut handles = Vec::with_capacity(NUM_CONCURRENT_RETRIES);

    for _ in 0..NUM_CONCURRENT_RETRIES {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let bytes = Arc::clone(&req_bytes);

        handles.push(tokio::spawn(async move {
            let http_req = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from((*bytes).clone()))
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

    let mut first_resp: Option<PushResponse> = None;
    for h in handles {
        let (status, push_resp) = h.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        if let Some(ref first) = first_resp {
            assert_eq!(push_resp.revision, first.revision);
            assert_eq!(push_resp.server_seq, first.server_seq);
            assert_eq!(push_resp.object_id, first.object_id);
        } else {
            assert_eq!(push_resp.revision, 1);
            assert_eq!(push_resp.server_seq, 1);
            first_resp = Some(push_resp);
        }
    }

    // Invariant: Exactly 1 sequence allocated
    assert_eq!(state.db.current_sequence(account_id).await.unwrap(), 1);
}

// ----------------------------------------------------------------------------
// 4. Network Retry (Lost Response Simulation)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_network_retry_lost_response() {
    let db = ServerDb::new_in_memory().unwrap();
    let account_id = Uuid::new_v4();
    let object_id = Uuid::new_v4().to_string();

    // 1. Client sends mutation M1
    let m1_id = Uuid::new_v4().to_string();
    let req1 = helper_push_request(&m1_id, &object_id, 0, false, b"v1");
    let outcome1 = db.push_mutation(account_id, &req1).await.unwrap();
    let PushOutcome::Success(resp1) = outcome1 else {
        panic!("M1 failed");
    };

    // Simulate lost response: Client retries M1 with exact same payload
    let outcome1_retry = db.push_mutation(account_id, &req1).await.unwrap();
    let PushOutcome::Success(resp1_retry) = outcome1_retry else {
        panic!("M1 retry failed");
    };
    assert_eq!(resp1_retry.revision, resp1.revision);
    assert_eq!(resp1_retry.server_seq, resp1.server_seq);

    // 2. Client sends mutation M2
    let m2_id = Uuid::new_v4().to_string();
    let req2 = helper_push_request(&m2_id, &object_id, resp1.revision, false, b"v2");
    let outcome2 = db.push_mutation(account_id, &req2).await.unwrap();
    let PushOutcome::Success(resp2) = outcome2 else {
        panic!("M2 failed");
    };

    // Simulate lost response: Client retries M2 with exact same payload
    let outcome2_retry = db.push_mutation(account_id, &req2).await.unwrap();
    let PushOutcome::Success(resp2_retry) = outcome2_retry else {
        panic!("M2 retry failed");
    };
    assert_eq!(resp2_retry.revision, resp2.revision);
    assert_eq!(resp2_retry.server_seq, resp2.server_seq);

    // Invariant: Exactly 2 logical mutations committed
    assert_eq!(db.current_sequence(account_id).await.unwrap(), 2);
    let stored = db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 2);
}

// ----------------------------------------------------------------------------
// 5. Server Restart: Persistence across database reopen & sequence continuity
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_server_restart_persistence_and_sequence_continuity() {
    let db_path = std::env::temp_dir().join(format!("zk-stress-restart-{}.sqlite", Uuid::new_v4()));

    let account_id = Uuid::new_v4();
    let object_id = Uuid::new_v4().to_string();
    let m1_id = Uuid::new_v4().to_string();
    let m2_id = Uuid::new_v4().to_string();

    let m1_req = helper_push_request(&m1_id, &object_id, 0, false, b"data-v1");
    let m2_req = helper_push_request(&m2_id, &object_id, 1, false, b"data-v2");

    // Phase 1: Boot server 1 on disk
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        run_server_migrations(&mut conn).unwrap();
        let db1 = ServerDb::from_connection(conn);

        let out1 = db1.push_mutation(account_id, &m1_req).await.unwrap();
        assert!(matches!(
            out1,
            PushOutcome::Success(PushResponse {
                revision: 1,
                server_seq: 1,
                ..
            })
        ));

        let out2 = db1.push_mutation(account_id, &m2_req).await.unwrap();
        assert!(matches!(
            out2,
            PushOutcome::Success(PushResponse {
                revision: 2,
                server_seq: 2,
                ..
            })
        ));

        assert_eq!(db1.current_sequence(account_id).await.unwrap(), 2);
        // db1 drops here, connection closes
    }

    // Phase 2: Simulate Server Crash / Restart: Boot server 2 on the exact same database file
    {
        let mut conn = rusqlite::Connection::open(&db_path).unwrap();
        let newly_applied = run_server_migrations(&mut conn).unwrap();
        assert!(
            newly_applied.is_empty(),
            "Migrations should already be applied"
        );
        let db2 = ServerDb::from_connection(conn);

        // Invariant 1: State intact after restart
        let stored = db2
            .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.server_seq, 2);

        // Invariant 2: Processed mutation idempotency cache survived restart
        let retry_m1 = db2.push_mutation(account_id, &m1_req).await.unwrap();
        assert!(matches!(
            retry_m1,
            PushOutcome::Success(PushResponse {
                revision: 1,
                server_seq: 1,
                ..
            })
        ));

        let retry_m2 = db2.push_mutation(account_id, &m2_req).await.unwrap();
        assert!(matches!(
            retry_m2,
            PushOutcome::Success(PushResponse {
                revision: 2,
                server_seq: 2,
                ..
            })
        ));

        // Invariant 3: Sequence allocator continues monotonically (starts at 3, not 1)
        let m3_id = Uuid::new_v4().to_string();
        let m3_req = helper_push_request(&m3_id, &object_id, 2, false, b"data-v3");
        let out3 = db2.push_mutation(account_id, &m3_req).await.unwrap();
        let PushOutcome::Success(resp3) = out3 else {
            panic!("M3 failed after restart");
        };
        assert_eq!(resp3.revision, 3);
        assert_eq!(resp3.server_seq, 3);

        assert_eq!(db2.current_sequence(account_id).await.unwrap(), 3);

        // Invariant 4: Pull changes from cursor 0 yields all 3 revisions in sequence
        let pull = db2.pull_changes(account_id, 0, 10).await.unwrap();
        assert_eq!(pull.changes.len(), 1); // 1 active object row
        assert_eq!(pull.changes[0].revision, 3);
        assert_eq!(pull.changes[0].server_seq, 3);
    }

    // Cleanup temp db file
    let _ = fs::remove_file(&db_path);
}

// ----------------------------------------------------------------------------
// 6. Global Invariant: Mixed Concurrent Workload -> No Duplicate Accepted Logical Mutations
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_stress_mixed_concurrent_workload_no_duplicate_logical_mutations() {
    let state = AppState::new_in_memory(ServerConfig::default()).unwrap();
    let app = create_app(state.clone());

    let account_id = Uuid::new_v4();
    let auth_header = common::bearer(&state, account_id).await;

    // Create 10 base objects first
    let mut object_ids = Vec::with_capacity(10);
    for i in 0..10 {
        let obj_id = Uuid::new_v4().to_string();
        let req = helper_push_request(
            &Uuid::new_v4().to_string(),
            &obj_id,
            0,
            false,
            format!("base-{i}").as_bytes(),
        );
        let http_req = Request::builder()
            .uri("/v1/sync/push")
            .method("POST")
            .header("authorization", &auth_header)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&req).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(http_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        object_ids.push(obj_id);
    }

    // Launch 30 concurrent workers performing random operations:
    // Some retrying known mutations, some attempting CAS updates
    const NUM_WORKERS: usize = 30;
    let mut handles = Vec::with_capacity(NUM_WORKERS);

    for worker_id in 0..NUM_WORKERS {
        let app_clone = app.clone();
        let auth_str = auth_header.clone();
        let obj_id = object_ids[worker_id % object_ids.len()].clone();
        let mut_id = Uuid::new_v4().to_string();

        handles.push(tokio::spawn(async move {
            let req = helper_push_request(
                &mut_id,
                &obj_id,
                1,
                false,
                format!("worker-{worker_id}").as_bytes(),
            );
            let req_bytes = serde_json::to_vec(&req).unwrap();

            // Attempt write
            let http_req1 = Request::builder()
                .uri("/v1/sync/push")
                .method("POST")
                .header("authorization", &auth_str)
                .header("content-type", "application/json")
                .body(Body::from(req_bytes.clone()))
                .unwrap();
            let resp1 = app_clone.clone().oneshot(http_req1).await.unwrap();
            let status1 = resp1.status();

            // If success, immediately retry with same mutation ID
            if status1 == StatusCode::OK {
                let http_req2 = Request::builder()
                    .uri("/v1/sync/push")
                    .method("POST")
                    .header("authorization", &auth_str)
                    .header("content-type", "application/json")
                    .body(Body::from(req_bytes))
                    .unwrap();
                let resp2 = app_clone.oneshot(http_req2).await.unwrap();
                assert_eq!(resp2.status(), StatusCode::OK);
            }

            status1
        }));
    }

    let mut success_count = 0;
    let mut conflict_count = 0;

    for h in handles {
        let status = h.await.unwrap();
        if status == StatusCode::OK {
            success_count += 1;
        } else if status == StatusCode::CONFLICT {
            conflict_count += 1;
        }
    }

    // For 10 objects, at most 10 workers could succeed in updating from revision 1 -> 2
    assert!(success_count <= 10);
    assert_eq!(success_count + conflict_count, NUM_WORKERS);

    // Invariant: Total sequence allocated equals exactly:
    // 10 (base creates) + success_count (successful updates)
    let expected_final_seq = 10 + (success_count as u64);
    assert_eq!(
        state.db.current_sequence(account_id).await.unwrap(),
        expected_final_seq
    );

    // Pull changes from 0 to verify every allocated sequence number is strictly unique
    let pull = state.db.pull_changes(account_id, 0, 100).await.unwrap();
    let mut seen_seqs = HashSet::new();
    for change in &pull.changes {
        assert!(
            seen_seqs.insert(change.server_seq),
            "Duplicate sequence number found: {}",
            change.server_seq
        );
    }
}

mod common;
