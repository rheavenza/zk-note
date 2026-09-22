//! Reusable conflict inspection and resolution services (ZK-101).

use crate::config::{db_file, resolve_data_dir, vault_file};
use crate::error::CliError;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use zk_core::note::PlaintextNote;
use zk_crypto::keys::VaultKey;
use zk_storage::models::ConflictRecord;
use zk_storage::traits::ConflictStore;
use zk_storage::SqliteStorage;
use zk_sync::{
    generate_merge_candidate, resolve_conflict, ConflictResolutionResult,
    ConflictResolutionStrategy, PendingMutationQueue,
};

/// High-level conflict summary for listing and status display.
///
/// Plaintext note titles are redacted in `Debug` output (SEC-003).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientConflictSummary {
    pub conflict_id: String,
    pub object_id: String,
    pub base_revision: u64,
    pub remote_revision: u64,
    pub resolved: bool,
    pub remote_is_deleted: bool,
    pub local_is_deleted: bool,
    pub conflict_type: String,
    pub title: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

impl fmt::Debug for ClientConflictSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConflictSummary")
            .field("conflict_id", &self.conflict_id)
            .field("object_id", &self.object_id)
            .field("base_revision", &self.base_revision)
            .field("remote_revision", &self.remote_revision)
            .field("resolved", &self.resolved)
            .field("remote_is_deleted", &self.remote_is_deleted)
            .field("local_is_deleted", &self.local_is_deleted)
            .field("conflict_type", &self.conflict_type)
            .field("title", &"[REDACTED]")
            .finish()
    }
}

/// Detailed conflict model containing decrypted local, remote, and candidate notes.
///
/// Plaintext note representations are redacted in `Debug` output (SEC-003).
#[derive(Clone)]
pub struct ClientConflictDetail {
    pub conflict_id: String,
    pub object_id: String,
    pub base_revision: u64,
    pub remote_revision: u64,
    pub resolved: bool,
    pub remote_is_deleted: bool,
    pub local_is_deleted: bool,
    pub conflict_type: String,
    pub local_note: Option<PlaintextNote>,
    pub remote_note: Option<PlaintextNote>,
    pub candidate_note: Option<PlaintextNote>,
}

impl fmt::Debug for ClientConflictDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConflictDetail")
            .field("conflict_id", &self.conflict_id)
            .field("object_id", &self.object_id)
            .field("base_revision", &self.base_revision)
            .field("remote_revision", &self.remote_revision)
            .field("remote_is_deleted", &self.remote_is_deleted)
            .field("local_is_deleted", &self.local_is_deleted)
            .field("conflict_type", &self.conflict_type)
            .field(
                "local_note",
                &self.local_note.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "remote_note",
                &self.remote_note.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "candidate_note",
                &self.candidate_note.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Resolves a stored conflict record by exact ID or unique >=4 character prefix.
pub fn find_conflict_record(
    storage: &SqliteStorage,
    conflict_id: &str,
) -> Result<ConflictRecord, CliError> {
    if let Some(record) = storage.get_conflict(conflict_id)? {
        return Ok(record);
    }

    if conflict_id.len() >= 4 {
        let all = storage.list_conflicts(None)?;
        let mut matches: Vec<_> = all
            .into_iter()
            .filter(|c| c.conflict_id.starts_with(conflict_id))
            .collect();
        if matches.len() == 1 {
            Ok(matches.remove(0))
        } else if matches.len() > 1 {
            Err(CliError::Io(format!(
                "ambiguous conflict id prefix '{conflict_id}' matches {} conflicts",
                matches.len()
            )))
        } else {
            Err(CliError::ConflictNotFound(conflict_id.to_string()))
        }
    } else {
        Err(CliError::ConflictNotFound(conflict_id.to_string()))
    }
}

/// Lists conflicts, optionally decrypting titles if the vault key is available.
pub fn list_conflicts(
    custom_data_dir: Option<&Path>,
    vault_key: Option<&VaultKey>,
    include_resolved: bool,
) -> Result<Vec<ClientConflictSummary>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let filter = if include_resolved { None } else { Some(false) };
    let raw_conflicts = storage.list_conflicts(filter)?;

    let mut items = Vec::with_capacity(raw_conflicts.len());
    for c in raw_conflicts {
        let title = match vault_key {
            Some(key) => {
                let env = if c.remote_is_deleted {
                    &c.local_envelope
                } else if c.local_is_deleted {
                    &c.remote_envelope
                } else {
                    c.candidate_envelope.as_ref().unwrap_or(&c.local_envelope)
                };
                PlaintextNote::decrypt(env, key)
                    .map(|n| n.title)
                    .unwrap_or_else(|_| "[decryption error]".to_string())
            }
            None => "[locked]".to_string(),
        };

        let conflict_type = c.conflict_type_str().to_string();

        items.push(ClientConflictSummary {
            conflict_id: c.conflict_id,
            object_id: c.object_id,
            base_revision: c.base_revision,
            remote_revision: c.remote_revision,
            resolved: c.resolved,
            remote_is_deleted: c.remote_is_deleted,
            local_is_deleted: c.local_is_deleted,
            conflict_type,
            title,
            created_at: c.created_at,
            resolved_at: c.resolved_at,
        });
    }

    Ok(items)
}

/// Retrieves and decrypts the details of a conflict record.
pub fn get_conflict_detail(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    conflict_id: &str,
) -> Result<ClientConflictDetail, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let record = find_conflict_record(&storage, conflict_id)?;

    let local_note = if record.local_is_deleted {
        None
    } else {
        PlaintextNote::decrypt(&record.local_envelope, vault_key).ok()
    };

    let remote_note = if record.remote_is_deleted {
        None
    } else {
        PlaintextNote::decrypt(&record.remote_envelope, vault_key).ok()
    };

    let candidate_note = if record.remote_is_deleted || record.local_is_deleted {
        None
    } else if let Some(cand_env) = &record.candidate_envelope {
        PlaintextNote::decrypt(cand_env, vault_key).ok()
    } else {
        generate_merge_candidate(
            record.base_envelope.as_ref(),
            &record.local_envelope,
            &record.remote_envelope,
            vault_key,
        )
        .ok()
        .map(|(outcome, _)| outcome.candidate)
    };

    let conflict_type = record.conflict_type_str().to_string();

    Ok(ClientConflictDetail {
        conflict_id: record.conflict_id,
        object_id: record.object_id,
        base_revision: record.base_revision,
        remote_revision: record.remote_revision,
        resolved: record.resolved,
        remote_is_deleted: record.remote_is_deleted,
        local_is_deleted: record.local_is_deleted,
        conflict_type,
        local_note,
        remote_note,
        candidate_note,
    })
}

/// Resolves an active conflict using the specified strategy.
pub fn resolve_conflict_item(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    conflict_id: &str,
    strategy: ConflictResolutionStrategy,
) -> Result<ConflictResolutionResult, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = Arc::new(SqliteStorage::open(&db_path)?);
    let conflict = find_conflict_record(&storage, conflict_id)?;

    if conflict.resolved {
        return Err(CliError::ConflictAlreadyResolved(conflict.conflict_id));
    }

    let queue = PendingMutationQueue::new(Arc::clone(&storage));
    let result = resolve_conflict(&storage, &queue, vault_key, &conflict.conflict_id, strategy)?;

    Ok(result)
}
