//! Conflict record management, automated three-way merge candidate generation,
//! and conflict resolution strategies (ZK-053).
//!
//! In accordance with MASTER_SPEC.md § 10.3 and SEC-009:
//! - BASE, LOCAL, REMOTE, and CANDIDATE versions are stored strictly as encrypted envelopes.
//! - ZERO plaintext note titles, bodies, tags, or search metadata persist in conflict records.
//! - Contains sufficient metadata (object ID, remote revision, encrypted envelopes) to retry
//!   push synchronization cleanly after resolution.
//! - Supports resolution strategies: KeepLocal, KeepRemote, Merge, DuplicateAsSeparate.

use crate::merge::{three_way_merge_note, NoteMergeOutcome};
use crate::push::PushItemConflict;
use crate::queue::{PendingMutationQueue, QueueError};
use uuid::Uuid;
use zk_core::note::PlaintextNote;
use zk_core::time::now_utc_rfc3339;
use zk_crypto::keys::VaultKey;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_protocol::sync::ConflictResponse;
use zk_storage::error::StorageError;
use zk_storage::models::{
    ConflictRecord, MutationStatus, MutationType, PendingMutation, StoredEncryptedObject,
};
use zk_storage::traits::{BaseVersionStore, ConflictStore, MutationStore, ObjectStore};

/// Conflict handling policy for synchronization operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    /// Default V1 policy: preserve conflict in local storage and queue, requiring explicit resolution.
    #[default]
    Manual,
    /// Guarded Last-Write-Wins (LWW) policy option (ZK-055).
    ///
    /// Automatically selects the latest write (by timestamp) as the visible head in local storage.
    /// Crucially, the losing revision is always preserved in [`BaseVersionStore`] for historical recovery.
    /// Compare-and-swap (CAS) semantics on the server remain strictly enforced.
    GuardedLww,
}

/// Winner of a Guarded LWW conflict evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LwwWinner {
    /// Local edit won the LWW comparison (local timestamp > remote timestamp).
    Local,
    /// Remote edit won the LWW comparison (remote timestamp >= local timestamp).
    Remote,
}

/// Detailed outcome of evaluating Guarded LWW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedLwwOutcome {
    /// ID of the conflict record created and resolved.
    pub conflict_id: String,
    /// Object identifier.
    pub object_id: String,
    /// The winner of the LWW comparison.
    pub winner: LwwWinner,
    /// The revision of the winning version.
    pub winning_revision: u64,
    /// The revision of the losing version (retained in BaseVersionStore).
    pub losing_revision: u64,
    /// Retry mutation enqueued for server sync retry, if Local won.
    pub retry_mutation: Option<PendingMutation>,
}

/// User or policy strategy for resolving an active conflict record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolutionStrategy {
    /// Overwrite remote with local edit by queueing a push with `expected_revision = remote_revision`.
    KeepLocal,
    /// Accept remote version as the winner, discarding local edit.
    KeepRemote,
    /// Apply a merged note (e.g. diff3 candidate or user-edited note) with `expected_revision = remote_revision`.
    Merge(PlaintextNote),
    /// Preserve both: keep remote version for the current note, and create a brand-new note with a new ID
    /// containing the local edits.
    DuplicateAsSeparate {
        /// New stable UUID v4 for the duplicate note.
        new_object_id: String,
        /// Optional modified title for the duplicate note (e.g. "My Note (Local Copy)").
        new_title: Option<String>,
    },
}

/// The result of executing a conflict resolution strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictResolutionResult {
    /// The ID of the conflict record that was resolved.
    pub conflict_id: String,
    /// The target object ID.
    pub object_id: String,
    /// New mutation enqueued for sync retry, if applicable.
    pub retry_mutation: Option<PendingMutation>,
    /// Optional newly created note object ID if `DuplicateAsSeparate` was chosen.
    pub duplicated_object_id: Option<String>,
}

/// Generates a three-way merge candidate from encrypted envelopes.
///
/// Decrypts BASE (if available), LOCAL, and REMOTE notes using the supplied `vault_key`,
/// executes structured three-way merge with line-level diff3 for body content,
/// and returns the merge outcome along with the encrypted candidate envelope.
pub fn generate_merge_candidate(
    base_envelope: Option<&EncryptedEnvelope>,
    local_envelope: &EncryptedEnvelope,
    remote_envelope: &EncryptedEnvelope,
    vault_key: &VaultKey,
) -> Result<(NoteMergeOutcome, EncryptedEnvelope), StorageError> {
    let local_note = PlaintextNote::decrypt(local_envelope, vault_key)
        .map_err(|e| StorageError::Backend(format!("failed to decrypt local note: {e}")))?;

    let remote_note = PlaintextNote::decrypt(remote_envelope, vault_key)
        .map_err(|e| StorageError::Backend(format!("failed to decrypt remote note: {e}")))?;

    let base_note = match base_envelope {
        Some(env) => PlaintextNote::decrypt(env, vault_key)
            .map_err(|e| StorageError::Backend(format!("failed to decrypt base note: {e}")))?,
        None => PlaintextNote::new("", ""),
    };

    let outcome = three_way_merge_note(&base_note, &local_note, &remote_note);

    let candidate_envelope = outcome
        .candidate
        .encrypt(vault_key, &local_envelope.object_id)
        .map_err(|e| StorageError::Backend(format!("failed to encrypt merge candidate: {e}")))?;

    Ok((outcome, candidate_envelope))
}

/// Records a conflict encountered during push synchronization.
///
/// Looks up the BASE envelope from [`BaseVersionStore`], optionally generates an encrypted
/// merge candidate if the `vault_key` is available, and persists the [`ConflictRecord`]
/// into [`ConflictStore`].
pub fn record_conflict<S>(
    storage: &S,
    push_conflict: &PushItemConflict,
    vault_key: Option<&VaultKey>,
) -> Result<(ConflictRecord, Option<NoteMergeOutcome>), StorageError>
where
    S: BaseVersionStore + ConflictStore,
{
    let base_envelope = storage.get_base_version(
        &push_conflict.mutation.object_id,
        push_conflict.mutation.expected_revision,
    )?;

    let (merge_outcome, candidate_envelope) = match vault_key {
        Some(key) => {
            let (outcome, env) = generate_merge_candidate(
                base_envelope.as_ref(),
                &push_conflict.mutation.envelope,
                &push_conflict.conflict.current_envelope,
                key,
            )?;
            (Some(outcome), Some(env))
        }
        None => (None, None),
    };

    let conflict_record = ConflictRecord::new(
        Uuid::new_v4().to_string(),
        &push_conflict.mutation.object_id,
        push_conflict.mutation.object_kind,
        push_conflict.mutation.expected_revision,
        push_conflict.conflict.current_revision,
        base_envelope,
        push_conflict.mutation.envelope.clone(),
        push_conflict.conflict.current_envelope.clone(),
        candidate_envelope,
        now_utc_rfc3339(),
    );

    storage.put_conflict(&conflict_record)?;

    Ok((conflict_record, merge_outcome))
}

/// Resolves an active conflict using the specified strategy.
///
/// Enforces all security and conflict safety rules:
/// - Fails closed if the conflict does not exist or was already resolved.
/// - Keeps all persisted data strictly within encrypted envelopes (SEC-009).
/// - Enqueues a retry mutation with `expected_revision = remote_revision` for CAS safety.
/// - Marks the conflict record resolved in [`ConflictStore`].
pub fn resolve_conflict<S>(
    storage: &S,
    queue: &PendingMutationQueue<S>,
    vault_key: &VaultKey,
    conflict_id: &str,
    strategy: ConflictResolutionStrategy,
) -> Result<ConflictResolutionResult, QueueError>
where
    S: ObjectStore + MutationStore + BaseVersionStore + ConflictStore,
{
    let conflict = storage
        .get_conflict(conflict_id)?
        .ok_or_else(|| QueueError::NotFound(format!("conflict record {conflict_id} not found")))?;

    if conflict.resolved {
        return Err(QueueError::InvalidState(format!(
            "conflict record {conflict_id} has already been resolved"
        )));
    }

    let resolved_at = now_utc_rfc3339();

    match strategy {
        ConflictResolutionStrategy::KeepLocal => {
            // Remove any stale mutation for this object
            let existing_mutations = storage.list_mutations_for_object(&conflict.object_id)?;
            for m in existing_mutations {
                let _ = storage.remove_mutation(&m.mutation_id);
            }

            // Update local object to reflect the chosen local version at remote revision
            let local_obj = StoredEncryptedObject {
                object_id: conflict.object_id.clone(),
                object_kind: conflict.object_kind,
                revision: conflict.remote_revision,
                server_seq: 0,
                is_deleted: false,
                envelope: conflict.local_envelope.clone(),
                updated_at: resolved_at.clone(),
            };
            storage.put_object(&local_obj)?;

            // Enqueue new mutation based on remote revision (so CAS will succeed)
            let retry_mutation = PendingMutation {
                mutation_id: Uuid::new_v4().to_string(),
                object_id: conflict.object_id.clone(),
                expected_revision: conflict.remote_revision,
                object_kind: conflict.object_kind,
                mutation_type: MutationType::Upsert,
                envelope: conflict.local_envelope.clone(),
                created_at: resolved_at.clone(),
                retry_count: 0,
                status: zk_storage::models::MutationStatus::Pending,
            };
            storage.enqueue_mutation(&retry_mutation)?;

            storage.resolve_conflict(
                conflict_id,
                Some(conflict.local_envelope.clone()),
                resolved_at,
            )?;

            Ok(ConflictResolutionResult {
                conflict_id: conflict_id.to_string(),
                object_id: conflict.object_id,
                retry_mutation: Some(retry_mutation),
                duplicated_object_id: None,
            })
        }
        ConflictResolutionStrategy::KeepRemote => {
            // Remove any stale mutation for this object
            let existing_mutations = storage.list_mutations_for_object(&conflict.object_id)?;
            for m in existing_mutations {
                let _ = storage.remove_mutation(&m.mutation_id);
            }

            // Update local object to remote revision
            let remote_obj = StoredEncryptedObject {
                object_id: conflict.object_id.clone(),
                object_kind: conflict.object_kind,
                revision: conflict.remote_revision,
                server_seq: 0,
                is_deleted: false,
                envelope: conflict.remote_envelope.clone(),
                updated_at: resolved_at.clone(),
            };
            storage.put_object(&remote_obj)?;

            storage.resolve_conflict(
                conflict_id,
                Some(conflict.remote_envelope.clone()),
                resolved_at,
            )?;

            Ok(ConflictResolutionResult {
                conflict_id: conflict_id.to_string(),
                object_id: conflict.object_id,
                retry_mutation: None,
                duplicated_object_id: None,
            })
        }
        ConflictResolutionStrategy::Merge(merged_note) => {
            // Encrypt merged note for conflict object ID
            let merged_envelope = merged_note
                .encrypt(vault_key, &conflict.object_id)
                .map_err(|e| {
                    QueueError::Storage(StorageError::Backend(format!(
                        "failed to encrypt merged note: {e}"
                    )))
                })?;

            // Remove any stale mutation for this object
            let existing_mutations = storage.list_mutations_for_object(&conflict.object_id)?;
            for m in existing_mutations {
                let _ = storage.remove_mutation(&m.mutation_id);
            }

            // Update local object to reflect the merged version at remote revision
            let merged_obj = StoredEncryptedObject {
                object_id: conflict.object_id.clone(),
                object_kind: conflict.object_kind,
                revision: conflict.remote_revision,
                server_seq: 0,
                is_deleted: false,
                envelope: merged_envelope.clone(),
                updated_at: resolved_at.clone(),
            };
            storage.put_object(&merged_obj)?;

            // Enqueue new mutation based on remote revision
            let retry_mutation = PendingMutation {
                mutation_id: Uuid::new_v4().to_string(),
                object_id: conflict.object_id.clone(),
                expected_revision: conflict.remote_revision,
                object_kind: conflict.object_kind,
                mutation_type: MutationType::Upsert,
                envelope: merged_envelope.clone(),
                created_at: resolved_at.clone(),
                retry_count: 0,
                status: zk_storage::models::MutationStatus::Pending,
            };
            storage.enqueue_mutation(&retry_mutation)?;

            storage.resolve_conflict(conflict_id, Some(merged_envelope), resolved_at)?;

            Ok(ConflictResolutionResult {
                conflict_id: conflict_id.to_string(),
                object_id: conflict.object_id,
                retry_mutation: Some(retry_mutation),
                duplicated_object_id: None,
            })
        }
        ConflictResolutionStrategy::DuplicateAsSeparate {
            new_object_id,
            new_title,
        } => {
            // 1. Accept remote as winner for existing note
            let existing_mutations = storage.list_mutations_for_object(&conflict.object_id)?;
            for m in existing_mutations {
                let _ = storage.remove_mutation(&m.mutation_id);
            }

            let remote_obj = StoredEncryptedObject {
                object_id: conflict.object_id.clone(),
                object_kind: conflict.object_kind,
                revision: conflict.remote_revision,
                server_seq: 0,
                is_deleted: false,
                envelope: conflict.remote_envelope.clone(),
                updated_at: resolved_at.clone(),
            };
            storage.put_object(&remote_obj)?;

            // 2. Decrypt local note and duplicate with new ID
            let mut local_note = PlaintextNote::decrypt(&conflict.local_envelope, vault_key)
                .map_err(|e| {
                    QueueError::Storage(StorageError::Backend(format!(
                        "failed to decrypt local note for duplicate: {e}"
                    )))
                })?;

            if let Some(title) = new_title {
                local_note.title = title;
            }

            let dup_envelope = local_note.encrypt(vault_key, &new_object_id).map_err(|e| {
                QueueError::Storage(StorageError::Backend(format!(
                    "failed to encrypt duplicated note: {e}"
                )))
            })?;

            let dup_mutation = queue.enqueue_upsert(
                &new_object_id,
                conflict.object_kind,
                0,
                dup_envelope.clone(),
            )?;

            let dup_obj = StoredEncryptedObject {
                object_id: new_object_id.clone(),
                object_kind: conflict.object_kind,
                revision: 1,
                server_seq: 0,
                is_deleted: false,
                envelope: dup_envelope,
                updated_at: resolved_at.clone(),
            };
            storage.put_object(&dup_obj)?;

            storage.resolve_conflict(
                conflict_id,
                Some(conflict.remote_envelope.clone()),
                resolved_at,
            )?;

            Ok(ConflictResolutionResult {
                conflict_id: conflict_id.to_string(),
                object_id: conflict.object_id,
                retry_mutation: Some(dup_mutation),
                duplicated_object_id: Some(new_object_id),
            })
        }
    }
}

/// Evaluates and applies the Guarded Last-Write-Wins (LWW) policy to a push conflict (ZK-055).
///
/// In accordance with MASTER_SPEC.md § 10.4:
/// 1. Compares timestamps between local edit and remote conflict (using decrypted `updated_at`
///    if `vault_key` is supplied, or mutation/envelope metadata timestamps otherwise).
/// 2. If local wins: local version becomes current visible head in [`ObjectStore`], the losing
///    remote version is archived in [`BaseVersionStore`], and a retry mutation is enqueued with
///    `expected_revision = remote_revision` to satisfy server CAS.
/// 3. If remote wins: remote version becomes current visible head in [`ObjectStore`], the losing
///    local version is archived in [`BaseVersionStore`], and the stale local mutation is dequeued.
/// 4. An audit record is stored in [`ConflictStore`] marked as resolved.
/// 5. Never silently drops or overwrites data without preserving the losing revision.
pub fn evaluate_guarded_lww<S>(
    storage: &S,
    _queue: &PendingMutationQueue<S>,
    mutation: &PendingMutation,
    conflict: &ConflictResponse,
    vault_key: Option<&VaultKey>,
) -> Result<GuardedLwwOutcome, QueueError>
where
    S: ObjectStore + MutationStore + BaseVersionStore + ConflictStore,
{
    let resolved_at = now_utc_rfc3339();
    let conflict_id = Uuid::new_v4().to_string();

    // 1. Determine local and remote timestamps
    let (local_ts, remote_ts) = match vault_key {
        Some(key) => {
            let local_res = PlaintextNote::decrypt(&mutation.envelope, key);
            let remote_res = PlaintextNote::decrypt(&conflict.current_envelope, key);
            match (local_res, remote_res) {
                (Ok(l), Ok(r)) => (Some(l.updated_at), Some(r.updated_at)),
                _ => (None, None),
            }
        }
        None => (None, None),
    };

    // 2. Decide winner: local wins strictly if local_ts > remote_ts.
    // If equal or opaque, break tie deterministically.
    let local_wins = match (local_ts, remote_ts) {
        (Some(l), Some(r)) => {
            if l != r {
                l > r
            } else {
                mutation.envelope.payload.ciphertext > conflict.current_envelope.payload.ciphertext
            }
        }
        _ => {
            let remote_stored_ts = storage
                .get_object(&mutation.object_id)
                .ok()
                .flatten()
                .filter(|o| o.revision == conflict.current_revision)
                .map(|o| o.updated_at);

            match remote_stored_ts {
                Some(r) if mutation.created_at != r => mutation.created_at > r,
                _ => {
                    mutation.envelope.payload.ciphertext
                        > conflict.current_envelope.payload.ciphertext
                }
            }
        }
    };

    // Look up existing base envelope if available
    let base_envelope = storage
        .get_base_version(&mutation.object_id, mutation.expected_revision)
        .unwrap_or(None);

    if local_wins {
        // --- LOCAL WINS ---
        // 1. Archive losing remote version in BaseVersionStore so it is NEVER lost
        storage.put_base_version(
            &mutation.object_id,
            conflict.current_revision,
            &conflict.current_envelope,
        )?;

        // 2. Local version becomes visible head in ObjectStore
        let winning_obj = StoredEncryptedObject {
            object_id: mutation.object_id.clone(),
            object_kind: mutation.object_kind,
            revision: conflict.current_revision,
            server_seq: 0,
            is_deleted: false,
            envelope: mutation.envelope.clone(),
            updated_at: resolved_at.clone(),
        };
        storage.put_object(&winning_obj)?;

        // 3. Remove stale mutation and enqueue retry mutation with expected_revision = remote_revision
        let existing = storage.list_mutations_for_object(&mutation.object_id)?;
        for m in existing {
            let _ = storage.remove_mutation(&m.mutation_id);
        }

        let retry_mutation = PendingMutation {
            mutation_id: Uuid::new_v4().to_string(),
            object_id: mutation.object_id.clone(),
            expected_revision: conflict.current_revision,
            object_kind: mutation.object_kind,
            mutation_type: MutationType::Upsert,
            envelope: mutation.envelope.clone(),
            created_at: resolved_at.clone(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };
        storage.enqueue_mutation(&retry_mutation)?;

        // 4. Record resolved conflict in ConflictStore
        let mut record = ConflictRecord::new(
            &conflict_id,
            &mutation.object_id,
            mutation.object_kind,
            mutation.expected_revision,
            conflict.current_revision,
            base_envelope,
            mutation.envelope.clone(),
            conflict.current_envelope.clone(),
            Some(mutation.envelope.clone()),
            resolved_at.clone(),
        );
        record.resolved = true;
        record.resolved_at = Some(resolved_at);
        storage.put_conflict(&record)?;

        Ok(GuardedLwwOutcome {
            conflict_id,
            object_id: mutation.object_id.clone(),
            winner: LwwWinner::Local,
            winning_revision: conflict.current_revision,
            losing_revision: conflict.current_revision,
            retry_mutation: Some(retry_mutation),
        })
    } else {
        // --- REMOTE WINS ---
        // 1. Archive losing local version in BaseVersionStore so it is NEVER lost
        storage.put_base_version(
            &mutation.object_id,
            mutation.expected_revision,
            &mutation.envelope,
        )?;

        // 2. Remote version becomes visible head in ObjectStore
        let winning_obj = StoredEncryptedObject {
            object_id: mutation.object_id.clone(),
            object_kind: mutation.object_kind,
            revision: conflict.current_revision,
            server_seq: 0,
            is_deleted: false,
            envelope: conflict.current_envelope.clone(),
            updated_at: resolved_at.clone(),
        };
        storage.put_object(&winning_obj)?;

        // 3. Remove stale local mutation
        let existing = storage.list_mutations_for_object(&mutation.object_id)?;
        for m in existing {
            let _ = storage.remove_mutation(&m.mutation_id);
        }

        // 4. Record resolved conflict in ConflictStore
        let mut record = ConflictRecord::new(
            &conflict_id,
            &mutation.object_id,
            mutation.object_kind,
            mutation.expected_revision,
            conflict.current_revision,
            base_envelope,
            mutation.envelope.clone(),
            conflict.current_envelope.clone(),
            Some(conflict.current_envelope.clone()),
            resolved_at.clone(),
        );
        record.resolved = true;
        record.resolved_at = Some(resolved_at);
        storage.put_conflict(&record)?;

        Ok(GuardedLwwOutcome {
            conflict_id,
            object_id: mutation.object_id.clone(),
            winner: LwwWinner::Remote,
            winning_revision: conflict.current_revision,
            losing_revision: mutation.expected_revision,
            retry_mutation: None,
        })
    }
}
