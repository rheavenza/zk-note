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
use zk_storage::error::StorageError;
use zk_storage::models::{ConflictRecord, MutationType, PendingMutation, StoredEncryptedObject};
use zk_storage::traits::{BaseVersionStore, ConflictStore, MutationStore, ObjectStore};

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

            let dup_mutation =
                queue.enqueue_upsert(&new_object_id, conflict.object_kind, 0, dup_envelope)?;

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
