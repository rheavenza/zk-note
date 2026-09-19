//! Protocol Property Tests (ZK-090 / Milestone 9).
//!
//! Acceptance criteria:
//! - Random object/revision sequences;
//! - No invalid silent state transitions (CAS correctness, tombstone invariants);
//! - Idempotency property (replays preserve revision, server sequence, and database state);
//! - Cursor monotonicity property (strictly increasing sequences, no gaps, paging integrity).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use base64ct::{Base64, Encoding};
use std::collections::HashMap;
use uuid::Uuid;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
use zk_protocol::sync::{ConflictResponse, PushRequest, PushResponse};
use zk_server::db::store::{PushOutcome, ServerDb};

/// Fast, deterministic, reproducible pseudo-random number generator (XorShift64).
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdeadbeefcafe } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }
}

fn make_envelope(object_id: &str, content: &[u8]) -> EncryptedEnvelope {
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
            ciphertext: Base64::encode_string(content),
        },
    }
}

fn make_push_request(
    mutation_id: &str,
    object_id: &str,
    expected_revision: u64,
    is_deleted: bool,
    content: &[u8],
) -> PushRequest {
    PushRequest {
        mutation_id: mutation_id.to_string(),
        object_id: object_id.to_string(),
        expected_revision,
        object_kind: OBJECT_KIND_NOTE,
        envelope: make_envelope(object_id, content),
        is_deleted,
    }
}

// ----------------------------------------------------------------------------
// Property 1: State Transition Invariants (No Invalid Silent State Transitions)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_property_no_invalid_silent_state_transitions() {
    let db = ServerDb::new_in_memory().unwrap();
    let account_id = Uuid::new_v4();

    let object_id = Uuid::new_v4().to_string();

    // 1. Non-existent object: expected_revision != 0 MUST return ObjectNotFound
    for invalid_rev in [1, 2, 5, 10, 100] {
        let req = make_push_request(
            &Uuid::new_v4().to_string(),
            &object_id,
            invalid_rev,
            false,
            b"v1",
        );
        let outcome = db.push_mutation(account_id, &req).await.unwrap();
        assert!(
            matches!(outcome, PushOutcome::ObjectNotFound(_)),
            "Expected ObjectNotFound for non-existent object with rev {invalid_rev}, got {outcome:?}"
        );
        // Ensure object was not created silently
        let stored = db
            .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "Object must not exist after rejected creation"
        );
    }

    // 2. Initial creation: expected_revision = 0 succeeds and transitions to revision 1
    let create_req = make_push_request(&Uuid::new_v4().to_string(), &object_id, 0, false, b"v1");
    let outcome = db.push_mutation(account_id, &create_req).await.unwrap();
    let PushOutcome::Success(resp1) = outcome else {
        panic!("Initial creation failed: {outcome:?}");
    };
    assert_eq!(resp1.revision, 1);
    assert_eq!(resp1.object_id, object_id);
    let first_seq = resp1.server_seq;

    // 3. Existing object: expected_revision = 0 MUST return Conflict (never silent create/overwrite)
    let dup_create = make_push_request(&Uuid::new_v4().to_string(), &object_id, 0, false, b"dup");
    let outcome = db.push_mutation(account_id, &dup_create).await.unwrap();
    assert!(
        matches!(
            outcome,
            PushOutcome::Conflict(ConflictResponse {
                current_revision: 1,
                ..
            })
        ),
        "Expected Conflict with current_revision=1, got {outcome:?}"
    );

    // 4. Existing object at revision 1: stale revision (< 1) or future revision (> 1) MUST reject
    for wrong_rev in [0, 2, 3, 10, 999] {
        let req = make_push_request(
            &Uuid::new_v4().to_string(),
            &object_id,
            wrong_rev,
            false,
            b"wrong",
        );
        let outcome = db.push_mutation(account_id, &req).await.unwrap();
        assert!(
            matches!(
                outcome,
                PushOutcome::Conflict(ConflictResponse {
                    current_revision: 1,
                    ..
                })
            ),
            "Expected Conflict for expected_revision={wrong_rev}, got {outcome:?}"
        );
        // Verify stored object remains intact at revision 1
        let stored = db
            .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.server_seq as u64, first_seq);
    }

    // 5. Valid update: expected_revision = 1 transitions to revision 2
    let update_req = make_push_request(&Uuid::new_v4().to_string(), &object_id, 1, false, b"v2");
    let outcome = db.push_mutation(account_id, &update_req).await.unwrap();
    let PushOutcome::Success(resp2) = outcome else {
        panic!("Valid update failed: {outcome:?}");
    };
    assert_eq!(resp2.revision, 2);
    assert!(resp2.server_seq > first_seq);

    // 6. Tombstone transition: is_deleted = true with expected_revision = 2 transitions to revision 3
    let delete_req = make_push_request(
        &Uuid::new_v4().to_string(),
        &object_id,
        2,
        true,
        b"tombstone",
    );
    let outcome = db.push_mutation(account_id, &delete_req).await.unwrap();
    let PushOutcome::Success(resp3) = outcome else {
        panic!("Deletion failed: {outcome:?}");
    };
    assert_eq!(resp3.revision, 3);
    assert!(resp3.server_seq > resp2.server_seq);

    let stored = db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, 3);
    assert!(
        stored.is_deleted,
        "Object must be marked is_deleted=true in storage"
    );

    // 7. Stale update after deletion: stale write with rev < 3 MUST reject and NEVER silently resurrect
    for stale_rev in [0, 1, 2] {
        let req = make_push_request(
            &Uuid::new_v4().to_string(),
            &object_id,
            stale_rev,
            false,
            b"resurrect-stale",
        );
        let outcome = db.push_mutation(account_id, &req).await.unwrap();
        assert!(
            matches!(
                outcome,
                PushOutcome::Conflict(ConflictResponse {
                    current_revision: 3,
                    ..
                })
            ),
            "Expected Conflict with current_revision=3 for stale rev {stale_rev}"
        );
        let stored = db
            .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.is_deleted,
            "Stale mutation must not resurrect deleted object"
        );
    }

    // 8. Explicit un-deletion / update after deletion requires exact current revision (3)
    let revive_req = make_push_request(
        &Uuid::new_v4().to_string(),
        &object_id,
        3,
        false,
        b"revived",
    );
    let outcome = db.push_mutation(account_id, &revive_req).await.unwrap();
    let PushOutcome::Success(resp4) = outcome else {
        panic!("Explicit resurrection failed: {outcome:?}");
    };
    assert_eq!(resp4.revision, 4);
    let stored = db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.is_deleted);
    assert_eq!(stored.revision, 4);
}

// ----------------------------------------------------------------------------
// Property 2: Idempotency Invariants (Duplicate Mutation Safety)
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_property_idempotency_exact_replay_preserves_state() {
    let db = ServerDb::new_in_memory().unwrap();
    let account_id = Uuid::new_v4();

    let object_id = Uuid::new_v4().to_string();
    let mutation_id = Uuid::new_v4().to_string();

    let req = make_push_request(&mutation_id, &object_id, 0, false, b"initial payload");

    // First attempt -> Success
    let outcome1 = db.push_mutation(account_id, &req).await.unwrap();
    let PushOutcome::Success(resp1) = outcome1 else {
        panic!("First push failed: {outcome1:?}");
    };

    // Replay 10 times consecutively (simulating network retries)
    for _ in 0..10 {
        let outcome_replay = db.push_mutation(account_id, &req).await.unwrap();
        let PushOutcome::Success(resp_replay) = outcome_replay else {
            panic!("Replay push failed: {outcome_replay:?}");
        };

        // Invariant: Exact same revision and server_seq returned
        assert_eq!(resp_replay.revision, resp1.revision);
        assert_eq!(resp_replay.server_seq, resp1.server_seq);
        assert_eq!(resp_replay.object_id, resp1.object_id);
    }

    // Verify stored object was updated exactly once
    let stored = db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.revision, resp1.revision as i64);
    assert_eq!(stored.server_seq, resp1.server_seq as i64);

    // Invariant: Replay with SAME mutation_id but TAMPERED payload returns ReplayMismatch
    let tampered_req = make_push_request(&mutation_id, &object_id, 0, false, b"tampered content");
    let outcome_tampered = db.push_mutation(account_id, &tampered_req).await.unwrap();
    assert!(
        matches!(outcome_tampered, PushOutcome::ReplayMismatch(_)),
        "Expected ReplayMismatch for altered payload, got {outcome_tampered:?}"
    );

    // Verify stored object was NOT modified by the tampered replay
    let stored_after = db
        .get_encrypted_object(account_id, Uuid::parse_str(&object_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_after.revision, resp1.revision as i64);
    assert_eq!(stored_after.server_seq, resp1.server_seq as i64);
}

// ----------------------------------------------------------------------------
// Property 3: Cursor Monotonicity and Pagination Completeness
// ----------------------------------------------------------------------------

#[tokio::test]
async fn test_property_cursor_monotonicity_and_pagination() {
    let db = ServerDb::new_in_memory().unwrap();
    let account_id = Uuid::new_v4();

    // Commit 25 sequential mutations across multiple objects
    let mut expected_sequences = Vec::new();
    let num_mutations = 25;

    for i in 0..num_mutations {
        let object_id = Uuid::new_v4().to_string();
        let req = make_push_request(
            &Uuid::new_v4().to_string(),
            &object_id,
            0,
            false,
            format!("content-{i}").as_bytes(),
        );
        let outcome = db.push_mutation(account_id, &req).await.unwrap();
        let PushOutcome::Success(resp) = outcome else {
            panic!("Mutation {i} failed: {outcome:?}");
        };
        expected_sequences.push(resp.server_seq);
    }

    // Invariant: Sequences must be strictly monotonically increasing
    for window in expected_sequences.windows(2) {
        assert!(
            window[1] > window[0],
            "Sequence monotonicity violated: {} <= {}",
            window[1],
            window[0]
        );
    }

    // Invariant: Pull changes with different page limits (1, 2, 3, 5, 7, 10, 25, 50)
    // must return EVERY item in identical, strictly increasing order without omission or duplication
    for page_limit in [1, 2, 3, 5, 7, 10, 25, 50] {
        let mut cursor = 0u64;
        let mut collected_sequences = Vec::new();

        loop {
            let page = db
                .pull_changes(account_id, cursor, page_limit)
                .await
                .unwrap();
            assert!(
                page.changes.len() <= page_limit,
                "Page limit exceeded: {} > {}",
                page.changes.len(),
                page_limit
            );

            for item in &page.changes {
                // Item server_seq must be strictly greater than query cursor
                assert!(
                    item.server_seq > cursor,
                    "Item server_seq {} not > query cursor {}",
                    item.server_seq,
                    cursor
                );
                collected_sequences.push(item.server_seq);
            }

            if !page.has_more {
                break;
            }

            // Invariant: Next cursor must advance strictly
            assert!(
                page.next_cursor > cursor,
                "Cursor did not advance: next_cursor {} <= cursor {}",
                page.next_cursor,
                cursor
            );
            cursor = page.next_cursor;
        }

        assert_eq!(
            collected_sequences, expected_sequences,
            "Pagination with limit {page_limit} did not match expected sequence stream"
        );
    }

    // Invariant: Pulling after max sequence returns empty list, has_more=false
    let max_seq = *expected_sequences.last().unwrap();
    let empty_page = db.pull_changes(account_id, max_seq, 10).await.unwrap();
    assert!(empty_page.changes.is_empty());
    assert!(!empty_page.has_more);
    assert_eq!(empty_page.next_cursor, max_seq);
}

// ----------------------------------------------------------------------------
// Property 4: Randomized Multi-Object Sequence Simulation (State Machine Fuzz)
// ----------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ModelObject {
    revision: u64,
    server_seq: u64,
    is_deleted: bool,
    payload: Vec<u8>,
}

#[tokio::test]
async fn test_property_randomized_multi_object_sequence_simulation() {
    let mut rng = SimpleRng::new(0x42_1337_cafe_babe);
    let db = ServerDb::new_in_memory().unwrap();
    let account_id = Uuid::new_v4();

    // 10 distinct object IDs
    let object_pool: Vec<String> = (0..10).map(|_| Uuid::new_v4().to_string()).collect();

    // Reference model tracking ground truth state
    let mut model: HashMap<String, ModelObject> = HashMap::new();
    // Cache of processed mutations: mutation_id -> (PushResponse, PushRequest)
    let mut accepted_mutations: HashMap<String, (PushResponse, PushRequest)> = HashMap::new();

    let mut last_allocated_seq = 0u64;

    // Run 500 randomized state transitions
    for step in 0..500 {
        let obj_idx = rng.next_usize(object_pool.len());
        let obj_id = object_pool[obj_idx].clone();

        let action_type = rng.next_usize(5);
        match action_type {
            // Action 0: Valid Update or Create
            0 => {
                let current = model.get(&obj_id);
                let expected_rev = current.map(|m| m.revision).unwrap_or(0);
                let is_delete = current.is_some() && rng.next_usize(4) == 0; // 25% chance delete if exists
                let payload = format!("step-{step}-payload").into_bytes();
                let mut_id = Uuid::new_v4().to_string();

                let req = make_push_request(&mut_id, &obj_id, expected_rev, is_delete, &payload);
                let outcome = db.push_mutation(account_id, &req).await.unwrap();

                let PushOutcome::Success(resp) = outcome else {
                    panic!("Step {step}: Expected success for valid rev {expected_rev}, got {outcome:?}");
                };

                // Invariants:
                let expected_new_rev = expected_rev + 1;
                assert_eq!(resp.revision, expected_new_rev);
                assert!(
                    resp.server_seq > last_allocated_seq,
                    "Server sequence must be strictly monotonic: {} <= {}",
                    resp.server_seq,
                    last_allocated_seq
                );
                last_allocated_seq = resp.server_seq;

                // Update model
                model.insert(
                    obj_id.clone(),
                    ModelObject {
                        revision: expected_new_rev,
                        server_seq: resp.server_seq,
                        is_deleted: is_delete,
                        payload: payload.clone(),
                    },
                );
                accepted_mutations.insert(mut_id, (resp, req));
            }

            // Action 1: Stale Update (expected_revision < current)
            1 => {
                if let Some(current) = model.get(&obj_id) {
                    if current.revision > 0 {
                        let stale_rev = rng.next_usize(current.revision as usize) as u64;
                        let payload = b"stale-write";
                        let mut_id = Uuid::new_v4().to_string();
                        let req = make_push_request(&mut_id, &obj_id, stale_rev, false, payload);
                        let outcome = db.push_mutation(account_id, &req).await.unwrap();

                        assert!(
                            matches!(outcome, PushOutcome::Conflict(ConflictResponse { current_revision, .. }) if current_revision == current.revision),
                            "Step {step}: Expected conflict with rev {}, got {outcome:?}",
                            current.revision
                        );
                    }
                }
            }

            // Action 2: Future Update (expected_revision > current)
            2 => {
                let current_rev = model.get(&obj_id).map(|m| m.revision).unwrap_or(0);
                let future_rev = current_rev + 2 + (rng.next_u64() % 10);
                let payload = b"future-write";
                let mut_id = Uuid::new_v4().to_string();
                let req = make_push_request(&mut_id, &obj_id, future_rev, false, payload);
                let outcome = db.push_mutation(account_id, &req).await.unwrap();

                if model.contains_key(&obj_id) {
                    assert!(
                        matches!(outcome, PushOutcome::Conflict(ConflictResponse { current_revision, .. }) if current_revision == current_rev),
                        "Step {step}: Expected Conflict for future rev on existing object"
                    );
                } else {
                    assert!(
                        matches!(outcome, PushOutcome::ObjectNotFound(_)),
                        "Step {step}: Expected ObjectNotFound for future rev on non-existent object"
                    );
                }
            }

            // Action 3: Exact Replay (Idempotency)
            3 => {
                if !accepted_mutations.is_empty() {
                    let keys: Vec<_> = accepted_mutations.keys().cloned().collect();
                    let chosen_key = &keys[rng.next_usize(keys.len())];
                    let (original_resp, original_req) =
                        accepted_mutations.get(chosen_key).unwrap().clone();

                    let outcome = db.push_mutation(account_id, &original_req).await.unwrap();

                    let PushOutcome::Success(resp) = outcome else {
                        panic!("Step {step}: Replay must succeed idempotently: {outcome:?}");
                    };

                    assert_eq!(resp.revision, original_resp.revision);
                    assert_eq!(resp.server_seq, original_resp.server_seq);
                }
            }

            // Action 4: Tampered Replay (Replay Mismatch)
            _ => {
                if !accepted_mutations.is_empty() {
                    let keys: Vec<_> = accepted_mutations.keys().cloned().collect();
                    let chosen_key = &keys[rng.next_usize(keys.len())];
                    let (_, original_req) = accepted_mutations.get(chosen_key).unwrap().clone();

                    let mut tampered_req = original_req;
                    tampered_req.envelope.payload.ciphertext =
                        Base64::encode_string(format!("tampered-payload-{step}").as_bytes());

                    let outcome = db.push_mutation(account_id, &tampered_req).await.unwrap();

                    assert!(
                        matches!(outcome, PushOutcome::ReplayMismatch(_)),
                        "Step {step}: Tampered replay must reject with ReplayMismatch: {outcome:?}"
                    );
                }
            }
        }
    }

    // Final verification: Model state matches database state for all objects
    for (obj_id, model_obj) in &model {
        let uuid = Uuid::parse_str(obj_id).unwrap();
        // Pull direct object state from DB
        let stored = db.get_encrypted_object(account_id, uuid).await.unwrap();
        assert!(stored.is_some(), "Object {obj_id} must exist in DB");
        let stored = stored.unwrap();
        assert_eq!(stored.revision as u64, model_obj.revision);
        assert_eq!(stored.server_seq as u64, model_obj.server_seq);
        assert_eq!(stored.is_deleted, model_obj.is_deleted);
    }
}
