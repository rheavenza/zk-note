//! Deterministic synchronization state machine and action driver (ZK-106).
//!
//! In accordance with MASTER_SPEC.md § 9.6, AGENTS.md § 5, SEC-006, SEC-007, SEC-008:
//! - Shared Rust core owns the sync state machine, queue transitions, conflict gating,
//!   cursor sequencing, and retry loop.
//! - Platform drivers (TypeScript / Native) provide only storage and network I/O execution.
//! - Emits discrete, verifiable [`SyncAction`] steps that guarantee no mutation is dropped
//!   and no dependent edit is pushed after a revision conflict.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zk_core::time::now_utc_rfc3339;
use zk_protocol::sync::{PullChangesResponse, PushRequest, PushResponse};
use zk_storage::models::{
    ConflictRecord, MutationStatus, MutationType, PendingMutation, StoredEncryptedObject,
};

/// Phase of the synchronization cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    /// Initialized but not yet started.
    Initial,
    /// Executing the initial pull phase.
    PullingInitial,
    /// Pushing pending local mutations.
    Pushing,
    /// Executing the follow-up pull phase (after accepted writes).
    PullingFollowup,
    /// Successfully completed synchronization round.
    Complete,
    /// Failed closed due to a fatal error.
    Failed,
}

/// An instruction from the sync state machine to the storage and network driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum SyncAction {
    /// Perform a GET /v1/sync/changes?after=...&limit=...
    FetchPull { after: u64, limit: u32 },
    /// Store an encrypted object durably in local storage.
    StoreObject { object: StoredEncryptedObject },
    /// Advance durable sync cursor in local storage.
    AdvanceCursor { cursor: u64 },
    /// Reset any in-flight mutations in queue back to Pending status (SEC-007).
    ResetInFlightMutations,
    /// Mark a specific mutation as InFlight and increment its retry count.
    MarkMutationInFlight {
        mutation_id: String,
        retry_count: u32,
    },
    /// Send POST /v1/sync/push to the server with expected_revision.
    SendPush { request: PushRequest },
    /// Successfully accepted mutation: write object to storage and remove mutation from queue.
    AcknowledgeAccepted {
        object: StoredEncryptedObject,
        mutation_id: String,
    },
    /// Revision conflict: persist ConflictRecord and keep mutation in queue marked Pending.
    RecordConflict {
        conflict_record: ConflictRecord,
        mutation_id: String,
    },
    /// Reset mutation status to Pending (e.g. transient network error).
    ResetMutationToPending { mutation_id: String },
    /// Mark mutation as Failed in queue (fatal error).
    MarkMutationFailed { mutation_id: String },
    /// Complete sync cycle: record final cursor and last_sync_at timestamp.
    UpdateSyncState { cursor: u64, last_sync_at: String },
}

/// Options configuring the sync state machine cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateMachineOptions {
    /// Maximum changes per pull page.
    pub page_limit: u32,
    /// Whether to halt pushing if a conflict is encountered.
    pub stop_on_conflict: bool,
    /// Whether to always run a follow-up pull.
    pub always_followup_pull: bool,
}

impl Default for SyncStateMachineOptions {
    fn default() -> Self {
        Self {
            page_limit: 50,
            stop_on_conflict: false,
            always_followup_pull: false,
        }
    }
}

/// Pull phase summary statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullSummary {
    pub pages_fetched: usize,
    pub total_changes: usize,
    pub applied_changes: usize,
    pub initial_cursor: u64,
    pub final_cursor: u64,
}

/// Push phase summary statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSummary {
    pub total_attempted: usize,
    pub accepted: Vec<PushResponse>,
    pub conflicts: Vec<ConflictRecord>,
    pub transient_failures: usize,
}

/// Final summary report of a completed sync cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineReport {
    pub initial_pull: PullSummary,
    pub push: PushSummary,
    pub followup_pull: Option<PullSummary>,
    pub initial_cursor: u64,
    pub final_cursor: u64,
    pub mutations_accepted: usize,
    pub mutations_conflicted: usize,
    pub mutations_remaining: usize,
}

/// Deterministic, platform-agnostic sync state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateMachine {
    phase: SyncPhase,
    initial_cursor: u64,
    current_cursor: u64,
    pending_mutations: Vec<PendingMutation>,
    mutation_index: usize,
    conflicted_objects: HashSet<String>,
    page_limit: u32,
    stop_on_conflict: bool,
    always_followup_pull: bool,
    initial_pull: PullSummary,
    followup_pull: Option<PullSummary>,
    push: PushSummary,
    completed: bool,
}

impl SyncStateMachine {
    /// Creates a new [`SyncStateMachine`] initialized with the local durable cursor and queue.
    pub fn new(
        initial_cursor: u64,
        pending_mutations: Vec<PendingMutation>,
        options: SyncStateMachineOptions,
    ) -> Self {
        Self {
            phase: SyncPhase::Initial,
            initial_cursor,
            current_cursor: initial_cursor,
            pending_mutations,
            mutation_index: 0,
            conflicted_objects: HashSet::new(),
            page_limit: options.page_limit.clamp(1, 500),
            stop_on_conflict: options.stop_on_conflict,
            always_followup_pull: options.always_followup_pull,
            initial_pull: PullSummary {
                initial_cursor,
                final_cursor: initial_cursor,
                ..Default::default()
            },
            followup_pull: None,
            push: PushSummary::default(),
            completed: false,
        }
    }

    /// Current phase of the state machine.
    pub fn phase(&self) -> SyncPhase {
        self.phase
    }

    /// Current durable sync cursor.
    pub fn current_cursor(&self) -> u64 {
        self.current_cursor
    }

    /// Starts the sync cycle, emitting crash-recovery reset and the initial pull action.
    pub fn start(&mut self) -> Vec<SyncAction> {
        self.phase = SyncPhase::PullingInitial;
        vec![
            SyncAction::ResetInFlightMutations,
            SyncAction::FetchPull {
                after: self.current_cursor,
                limit: self.page_limit,
            },
        ]
    }

    /// Handles a paginated pull changes response from the server.
    pub fn handle_pull_response(&mut self, resp: PullChangesResponse) -> Vec<SyncAction> {
        let mut actions = Vec::new();

        let is_initial = self.phase == SyncPhase::PullingInitial;
        let summary = if is_initial {
            &mut self.initial_pull
        } else {
            self.followup_pull.get_or_insert_with(|| PullSummary {
                initial_cursor: self.current_cursor,
                final_cursor: self.current_cursor,
                ..Default::default()
            })
        };

        summary.pages_fetched += 1;
        summary.total_changes += resp.changes.len();

        for change in resp.changes {
            // Monotonic sequencing: skip already processed server sequences
            if change.server_seq <= self.current_cursor && self.current_cursor > 0 {
                continue;
            }

            let stored_obj = StoredEncryptedObject {
                object_id: change.object_id,
                object_kind: change.object_kind,
                revision: change.revision,
                server_seq: change.server_seq,
                is_deleted: change.is_deleted,
                envelope: change.envelope,
                updated_at: now_utc_rfc3339(),
            };

            // Requirement: durably store encrypted object FIRST, advance cursor AFTER
            actions.push(SyncAction::StoreObject { object: stored_obj });

            self.current_cursor = change.server_seq;
            summary.applied_changes += 1;
            summary.final_cursor = self.current_cursor;
            actions.push(SyncAction::AdvanceCursor {
                cursor: self.current_cursor,
            });
        }

        if resp.has_more {
            actions.push(SyncAction::FetchPull {
                after: self.current_cursor,
                limit: self.page_limit,
            });
        } else if is_initial {
            // Initial pull finished -> transition to push pending mutations
            self.phase = SyncPhase::Pushing;
            actions.extend(self.step_push());
        } else {
            // Followup pull finished -> complete sync cycle
            self.phase = SyncPhase::Complete;
            self.completed = true;
            actions.push(SyncAction::UpdateSyncState {
                cursor: self.current_cursor,
                last_sync_at: now_utc_rfc3339(),
            });
        }

        actions
    }

    /// Steps the push phase to process the next eligible pending mutation.
    fn step_push(&mut self) -> Vec<SyncAction> {
        while self.mutation_index < self.pending_mutations.len() {
            let mutation = &self.pending_mutations[self.mutation_index];

            // Only process ready mutations
            if mutation.status != MutationStatus::Pending
                && mutation.status != MutationStatus::InFlight
            {
                self.mutation_index += 1;
                continue;
            }

            // Conflict gating: do not push dependent edits if an earlier mutation for this object conflicted (SEC-006)
            if self.conflicted_objects.contains(&mutation.object_id) {
                self.mutation_index += 1;
                continue;
            }

            self.push.total_attempted += 1;
            let retry_count = mutation.retry_count + 1;
            let push_req = PushRequest {
                mutation_id: mutation.mutation_id.clone(),
                object_id: mutation.object_id.clone(),
                expected_revision: mutation.expected_revision,
                object_kind: mutation.object_kind,
                envelope: mutation.envelope.clone(),
                is_deleted: mutation.mutation_type == MutationType::Delete,
            };

            return vec![
                SyncAction::MarkMutationInFlight {
                    mutation_id: mutation.mutation_id.clone(),
                    retry_count,
                },
                SyncAction::SendPush { request: push_req },
            ];
        }

        // All pending mutations processed
        if !self.push.accepted.is_empty() || self.always_followup_pull {
            self.phase = SyncPhase::PullingFollowup;
            vec![SyncAction::FetchPull {
                after: self.current_cursor,
                limit: self.page_limit,
            }]
        } else {
            self.phase = SyncPhase::Complete;
            self.completed = true;
            vec![SyncAction::UpdateSyncState {
                cursor: self.current_cursor,
                last_sync_at: now_utc_rfc3339(),
            }]
        }
    }

    /// Handles a successful push mutation response from the server.
    pub fn handle_push_success(
        &mut self,
        mutation_id: &str,
        resp: PushResponse,
    ) -> Result<Vec<SyncAction>, String> {
        if self.mutation_index >= self.pending_mutations.len() {
            return Err("no mutation currently in flight".to_string());
        }
        let mutation = &self.pending_mutations[self.mutation_index];
        if mutation.mutation_id != mutation_id {
            return Err(format!(
                "mutation ID mismatch: expected '{}', got '{mutation_id}'",
                mutation.mutation_id
            ));
        }

        let stored_obj = StoredEncryptedObject {
            object_id: resp.object_id.clone(),
            object_kind: mutation.object_kind,
            revision: resp.revision,
            server_seq: resp.server_seq,
            is_deleted: mutation.mutation_type == MutationType::Delete,
            envelope: mutation.envelope.clone(),
            updated_at: now_utc_rfc3339(),
        };

        self.push.accepted.push(resp);
        let mut actions = vec![SyncAction::AcknowledgeAccepted {
            object: stored_obj,
            mutation_id: mutation_id.to_string(),
        }];

        self.mutation_index += 1;
        actions.extend(self.step_push());
        Ok(actions)
    }

    /// Handles a revision conflict (HTTP 409) from the server.
    pub fn handle_push_conflict(
        &mut self,
        mutation_id: &str,
        conflict_record: ConflictRecord,
    ) -> Result<Vec<SyncAction>, String> {
        if self.mutation_index >= self.pending_mutations.len() {
            return Err("no mutation currently in flight".to_string());
        }
        let mutation = &self.pending_mutations[self.mutation_index];
        if mutation.mutation_id != mutation_id {
            return Err(format!(
                "mutation ID mismatch: expected '{}', got '{mutation_id}'",
                mutation.mutation_id
            ));
        }

        // Conflict gating: halt subsequent edits for this object
        self.conflicted_objects
            .insert(conflict_record.object_id.clone());

        self.push.conflicts.push(conflict_record.clone());

        // In accordance with zk-sync push_pending_changes:
        // 1. Commit conflict record FIRST
        // 2. Reset local mutation status to Pending (kept in queue for resolution)
        let mut actions = vec![
            SyncAction::RecordConflict {
                conflict_record,
                mutation_id: mutation_id.to_string(),
            },
            SyncAction::ResetMutationToPending {
                mutation_id: mutation_id.to_string(),
            },
        ];

        self.mutation_index += 1;
        if self.stop_on_conflict {
            if !self.push.accepted.is_empty() || self.always_followup_pull {
                self.phase = SyncPhase::PullingFollowup;
                actions.push(SyncAction::FetchPull {
                    after: self.current_cursor,
                    limit: self.page_limit,
                });
            } else {
                self.phase = SyncPhase::Complete;
                self.completed = true;
                actions.push(SyncAction::UpdateSyncState {
                    cursor: self.current_cursor,
                    last_sync_at: now_utc_rfc3339(),
                });
            }
        } else {
            actions.extend(self.step_push());
        }

        Ok(actions)
    }

    /// Handles a transient network/server failure during push (retries later with same mutation ID).
    pub fn handle_push_transient_error(
        &mut self,
        mutation_id: &str,
    ) -> Result<Vec<SyncAction>, String> {
        if self.mutation_index >= self.pending_mutations.len() {
            return Err("no mutation currently in flight".to_string());
        }
        let mutation = &self.pending_mutations[self.mutation_index];
        if mutation.mutation_id != mutation_id {
            return Err(format!(
                "mutation ID mismatch: expected '{}', got '{mutation_id}'",
                mutation.mutation_id
            ));
        }

        self.push.transient_failures += 1;
        let mut actions = vec![SyncAction::ResetMutationToPending {
            mutation_id: mutation_id.to_string(),
        }];

        self.mutation_index += 1;
        actions.extend(self.step_push());
        Ok(actions)
    }

    /// Handles a fatal error (unauthorized, crypto corruption, etc.) and fails closed.
    pub fn handle_push_fatal_error(
        &mut self,
        mutation_id: &str,
        _error: &str,
    ) -> Result<Vec<SyncAction>, String> {
        self.phase = SyncPhase::Failed;
        Ok(vec![SyncAction::MarkMutationFailed {
            mutation_id: mutation_id.to_string(),
        }])
    }

    /// Produces the final [`StateMachineReport`] after synchronization completes.
    pub fn get_report(&self) -> StateMachineReport {
        let mutations_remaining = self
            .pending_mutations
            .iter()
            .filter(|m| {
                !self
                    .push
                    .accepted
                    .iter()
                    .any(|a| a.object_id == m.object_id && !m.mutation_id.is_empty())
            })
            .count()
            .saturating_sub(self.push.accepted.len());

        StateMachineReport {
            initial_pull: self.initial_pull.clone(),
            push: self.push.clone(),
            followup_pull: self.followup_pull.clone(),
            initial_cursor: self.initial_cursor,
            final_cursor: self.current_cursor,
            mutations_accepted: self.push.accepted.len(),
            mutations_conflicted: self.push.conflicts.len(),
            mutations_remaining,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
    use zk_protocol::envelope::{
        EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer,
    };
    use zk_protocol::sync::ObjectChange;

    fn sample_envelope(obj_id: &str) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: obj_id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
                ciphertext: "ZW5jcnlwdGVkLXBheWxvYWQ=".to_string(),
            },
        }
    }

    #[test]
    fn test_sync_state_machine_deterministic_pull_push_cycle() {
        let env = sample_envelope("note-1");
        let mutation = PendingMutation {
            mutation_id: "mut-1".to_string(),
            object_id: "note-1".to_string(),
            expected_revision: 0,
            object_kind: 1,
            mutation_type: MutationType::Upsert,
            envelope: env.clone(),
            created_at: now_utc_rfc3339(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };

        let mut sm = SyncStateMachine::new(0, vec![mutation], SyncStateMachineOptions::default());
        assert_eq!(sm.phase(), SyncPhase::Initial);

        // 1. Start cycle
        let actions = sm.start();
        assert_eq!(sm.phase(), SyncPhase::PullingInitial);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], SyncAction::ResetInFlightMutations);
        assert_eq!(
            actions[1],
            SyncAction::FetchPull {
                after: 0,
                limit: 50
            }
        );

        // 2. Server returns pull response with 1 remote note (seq 1)
        let pull_resp = PullChangesResponse {
            changes: vec![ObjectChange {
                server_seq: 1,
                object_id: "remote-1".to_string(),
                revision: 1,
                object_kind: 1,
                is_deleted: false,
                envelope: sample_envelope("remote-1"),
            }],
            next_cursor: 1,
            has_more: false,
        };

        let pull_actions = sm.handle_pull_response(pull_resp);
        // Expect StoreObject, AdvanceCursor, and then transitions to Pushing (MarkMutationInFlight, SendPush)
        assert_eq!(sm.phase(), SyncPhase::Pushing);
        assert_eq!(pull_actions.len(), 4);
        assert!(matches!(pull_actions[0], SyncAction::StoreObject { .. }));
        assert_eq!(pull_actions[1], SyncAction::AdvanceCursor { cursor: 1 });
        assert_eq!(
            pull_actions[2],
            SyncAction::MarkMutationInFlight {
                mutation_id: "mut-1".to_string(),
                retry_count: 1
            }
        );
        assert!(matches!(pull_actions[3], SyncAction::SendPush { .. }));

        // 3. Push accepted by server
        let push_resp = PushResponse {
            object_id: "note-1".to_string(),
            revision: 1,
            server_seq: 2,
        };
        let push_actions = sm.handle_push_success("mut-1", push_resp).unwrap();
        // Accepted write triggers followup pull because pushes were accepted!
        assert_eq!(sm.phase(), SyncPhase::PullingFollowup);
        assert_eq!(push_actions.len(), 2);
        assert!(matches!(
            push_actions[0],
            SyncAction::AcknowledgeAccepted { .. }
        ));
        assert_eq!(
            push_actions[1],
            SyncAction::FetchPull {
                after: 1,
                limit: 50
            }
        );

        // 4. Followup pull finishes
        let followup_resp = PullChangesResponse {
            changes: vec![ObjectChange {
                server_seq: 2,
                object_id: "note-1".to_string(),
                revision: 1,
                object_kind: 1,
                is_deleted: false,
                envelope: env,
            }],
            next_cursor: 2,
            has_more: false,
        };
        let final_actions = sm.handle_pull_response(followup_resp);
        assert_eq!(sm.phase(), SyncPhase::Complete);
        assert_eq!(final_actions.len(), 3);
        assert!(matches!(final_actions[0], SyncAction::StoreObject { .. }));
        assert_eq!(final_actions[1], SyncAction::AdvanceCursor { cursor: 2 });
        assert!(matches!(
            final_actions[2],
            SyncAction::UpdateSyncState { cursor: 2, .. }
        ));

        let report = sm.get_report();
        assert_eq!(report.mutations_accepted, 1);
        assert_eq!(report.final_cursor, 2);
    }

    #[test]
    fn test_sync_state_machine_conflict_gating_stops_dependent_edits() {
        let env1 = sample_envelope("note-conflict");
        let env2 = sample_envelope("note-conflict");
        let env_other = sample_envelope("note-other");

        // Two edits for note-conflict, one for note-other
        let mut1 = PendingMutation {
            mutation_id: "mut-conf-1".to_string(),
            object_id: "note-conflict".to_string(),
            expected_revision: 1,
            object_kind: 1,
            mutation_type: MutationType::Upsert,
            envelope: env1.clone(),
            created_at: now_utc_rfc3339(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };
        let mut2 = PendingMutation {
            mutation_id: "mut-conf-2".to_string(),
            object_id: "note-conflict".to_string(),
            expected_revision: 2,
            object_kind: 1,
            mutation_type: MutationType::Upsert,
            envelope: env2,
            created_at: now_utc_rfc3339(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };
        let mut3 = PendingMutation {
            mutation_id: "mut-other-1".to_string(),
            object_id: "note-other".to_string(),
            expected_revision: 0,
            object_kind: 1,
            mutation_type: MutationType::Upsert,
            envelope: env_other,
            created_at: now_utc_rfc3339(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };

        let mut sm = SyncStateMachine::new(
            0,
            vec![mut1, mut2, mut3],
            SyncStateMachineOptions::default(),
        );
        sm.start();

        // Empty initial pull
        let empty_pull = PullChangesResponse {
            changes: vec![],
            next_cursor: 0,
            has_more: false,
        };
        let actions = sm.handle_pull_response(empty_pull);
        // Expect push for mut-conf-1
        assert_eq!(
            actions[0],
            SyncAction::MarkMutationInFlight {
                mutation_id: "mut-conf-1".to_string(),
                retry_count: 1
            }
        );

        // Encounter conflict for mut-conf-1
        let conflict_record = ConflictRecord::new(
            "conf-1".to_string(),
            "note-conflict",
            1,
            1,
            3,
            None,
            env1.clone(),
            env1,
            None,
            now_utc_rfc3339(),
        );

        let conflict_actions = sm
            .handle_push_conflict("mut-conf-1", conflict_record)
            .unwrap();

        // Should commit RecordConflict, ResetMutationToPending,
        // and due to conflict gating, mut-conf-2 MUST BE SKIPPED!
        // It must step directly to mut-other-1!
        assert!(matches!(
            conflict_actions[0],
            SyncAction::RecordConflict { .. }
        ));
        assert_eq!(
            conflict_actions[1],
            SyncAction::ResetMutationToPending {
                mutation_id: "mut-conf-1".to_string()
            }
        );
        assert_eq!(
            conflict_actions[2],
            SyncAction::MarkMutationInFlight {
                mutation_id: "mut-other-1".to_string(),
                retry_count: 1
            }
        );
        assert!(matches!(conflict_actions[3], SyncAction::SendPush { .. }));
    }
}
