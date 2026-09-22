//! Reusable note operations for zero-knowledge note client (ZK-101).

use crate::config::{db_file, resolve_data_dir, vault_file};
use crate::error::CliError;
use std::fmt;
use std::path::Path;
use uuid::Uuid;
use zk_core::note::{NoteBuilder, PlaintextNote};
use zk_core::search::{InMemorySearchIndex, SearchResult};
use zk_core::time::now_utc_rfc3339;
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::{
    INITIAL_EXPECTED_REVISION, INITIAL_OBJECT_REVISION, INITIAL_SERVER_SEQ, OBJECT_KIND_NOTE,
};
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};
use zk_storage::{
    MutationStatus, MutationType, ObjectFilter, PendingMutation, SqliteStorage,
    StoredEncryptedObject,
};

use serde::Serialize;

/// High-level note summary for listings and views.
///
/// Plaintext note titles and tags are redacted in `Debug` output to prevent secret leakage (SEC-003).
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ClientNoteSummary {
    pub id: String,
    pub title: String,
    pub tags: Vec<String>,
    pub updated_at: String,
    pub created_at: String,
    pub revision: u64,
    pub is_deleted: bool,
}

impl fmt::Debug for ClientNoteSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientNoteSummary")
            .field("id", &self.id)
            .field("title", &"[REDACTED]")
            .field("tags", &"[REDACTED]")
            .field("updated_at", &self.updated_at)
            .field("created_at", &self.created_at)
            .field("revision", &self.revision)
            .field("is_deleted", &self.is_deleted)
            .finish()
    }
}

/// Detailed note model containing decrypted body and metadata.
///
/// Plaintext note titles, tags, and bodies are redacted in `Debug` output (SEC-003).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientNoteDetail {
    pub id: String,
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub revision: u64,
    pub is_deleted: bool,
}

impl fmt::Debug for ClientNoteDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientNoteDetail")
            .field("id", &self.id)
            .field("title", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .field("tags", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("revision", &self.revision)
            .field("is_deleted", &self.is_deleted)
            .finish()
    }
}

/// Helper to resolve a stored note object by exact ID or unique >=4 character prefix.
pub fn find_note_object(
    storage: &SqliteStorage,
    note_id: &str,
    include_deleted: bool,
) -> Result<StoredEncryptedObject, CliError> {
    let stored_opt = storage.get_object(note_id)?;
    if let Some(obj) = stored_opt {
        if obj.object_kind == OBJECT_KIND_NOTE {
            if obj.is_deleted && !include_deleted {
                return Err(CliError::NoteAlreadyDeleted(obj.object_id));
            }
            return Ok(obj);
        }
    }

    if note_id.len() >= 4 {
        let all = storage.list_objects(&ObjectFilter {
            kind: Some(OBJECT_KIND_NOTE),
            include_deleted,
        })?;
        let mut matches: Vec<_> = all
            .into_iter()
            .filter(|o| o.object_id.starts_with(note_id))
            .collect();
        if matches.len() == 1 {
            let obj = matches.remove(0);
            if obj.is_deleted && !include_deleted {
                return Err(CliError::NoteAlreadyDeleted(obj.object_id));
            }
            Ok(obj)
        } else if matches.len() > 1 {
            Err(CliError::Io(format!(
                "ambiguous note id prefix '{note_id}' matches {} notes",
                matches.len()
            )))
        } else {
            if !include_deleted {
                let all_deleted = storage.list_objects(&ObjectFilter {
                    kind: Some(OBJECT_KIND_NOTE),
                    include_deleted: true,
                })?;
                let deleted_matches: Vec<_> = all_deleted
                    .into_iter()
                    .filter(|o| o.object_id.starts_with(note_id) && o.is_deleted)
                    .collect();
                if !deleted_matches.is_empty() {
                    return Err(CliError::NoteAlreadyDeleted(
                        deleted_matches[0].object_id.clone(),
                    ));
                }
            }
            Err(CliError::NoteNotFound(note_id.to_string()))
        }
    } else {
        Err(CliError::NoteNotFound(note_id.to_string()))
    }
}

/// Lists notes, decrypting titles and tags in-memory using the active [`VaultKey`].
pub fn list_notes(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    include_deleted: bool,
    tag_filter: Option<&str>,
) -> Result<Vec<ClientNoteSummary>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let filter = ObjectFilter {
        kind: Some(OBJECT_KIND_NOTE),
        include_deleted,
    };
    let stored_objects = storage.list_objects(&filter)?;

    let mut summaries = Vec::with_capacity(stored_objects.len());
    for obj in stored_objects {
        match PlaintextNote::decrypt(&obj.envelope, vault_key) {
            Ok(note) => {
                if let Some(target_tag) = tag_filter {
                    let canonical_target = target_tag.trim().to_lowercase();
                    if !note.tags.iter().any(|t| t == &canonical_target) {
                        continue;
                    }
                }

                summaries.push(ClientNoteSummary {
                    id: obj.object_id,
                    title: note.title,
                    tags: note.tags,
                    updated_at: note.updated_at,
                    created_at: note.created_at,
                    revision: obj.revision,
                    is_deleted: obj.is_deleted,
                });
            }
            Err(_) => {
                summaries.push(ClientNoteSummary {
                    id: obj.object_id,
                    title: "[Decryption failed: corrupted envelope or wrong key]".to_string(),
                    tags: vec![],
                    updated_at: String::new(),
                    created_at: String::new(),
                    revision: obj.revision,
                    is_deleted: obj.is_deleted,
                });
            }
        }
    }

    // Sort newest updated_at first
    summaries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    Ok(summaries)
}

/// Retrieves and decrypts a specific note, returning both the stored object metadata and plaintext note.
pub fn get_plaintext_note(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    id_or_prefix: &str,
) -> Result<(StoredEncryptedObject, PlaintextNote), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let obj = find_note_object(&storage, id_or_prefix, false)?;
    let note = PlaintextNote::decrypt(&obj.envelope, vault_key)?;

    Ok((obj, note))
}

/// Retrieves and decrypts a specific note by full UUID or unique prefix.
pub fn get_note(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    id_or_prefix: &str,
) -> Result<ClientNoteDetail, CliError> {
    let (obj, note) = get_plaintext_note(custom_data_dir, vault_key, id_or_prefix)?;

    Ok(ClientNoteDetail {
        id: obj.object_id,
        title: note.title,
        body: note.body,
        tags: note.tags,
        created_at: note.created_at,
        updated_at: note.updated_at,
        revision: obj.revision,
        is_deleted: obj.is_deleted,
    })
}

/// Creates a new encrypted note, saving it to SQLite and enqueuing an upsert mutation.
pub fn create_note(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    title: &str,
    body: &str,
    tags: Vec<String>,
) -> Result<String, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let mut note = NoteBuilder::new()
        .title(title)
        .body(body)
        .tags(tags)
        .build()?;
    note.canonicalize();

    let object_id = Uuid::new_v4().to_string();
    let envelope = note.encrypt(vault_key, &object_id)?;
    let now = now_utc_rfc3339();

    let storage = SqliteStorage::open(&db_path)?;
    let stored = StoredEncryptedObject {
        object_id: object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: INITIAL_OBJECT_REVISION,
        envelope: envelope.clone(),
        server_seq: INITIAL_SERVER_SEQ,
        is_deleted: false,
        updated_at: now.clone(),
    };
    storage.put_object(&stored)?;

    let mutation = PendingMutation {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        expected_revision: INITIAL_EXPECTED_REVISION,
        envelope,
        created_at: now,
        status: MutationStatus::Pending,
        retry_count: 0,
    };
    storage.enqueue_mutation(&mutation)?;

    Ok(object_id)
}

/// Updates an existing note, archiving its prior revision and enqueuing an upsert mutation.
pub fn update_note(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    id_or_prefix: &str,
    title: &str,
    body: &str,
    tags: Vec<String>,
) -> Result<u64, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, id_or_prefix, false)?;
    let prior_note = PlaintextNote::decrypt(&stored.envelope, vault_key)?;

    let mut note = NoteBuilder::new()
        .title(title)
        .body(body)
        .tags(tags)
        .created_at(&prior_note.created_at)
        .build()?;
    note.canonicalize();

    // Archive prior revision envelope for conflict resolution
    storage.put_base_version(&stored.object_id, stored.revision, &stored.envelope)?;

    let new_revision = stored.revision + 1;
    let envelope = note.encrypt(vault_key, &stored.object_id)?;
    let now = now_utc_rfc3339();

    let updated_stored = StoredEncryptedObject {
        object_id: stored.object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: new_revision,
        envelope: envelope.clone(),
        server_seq: stored.server_seq,
        is_deleted: false,
        updated_at: now.clone(),
    };
    storage.put_object(&updated_stored)?;

    let mutation = PendingMutation {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: stored.object_id,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        expected_revision: stored.revision,
        envelope,
        created_at: now,
        status: MutationStatus::Pending,
        retry_count: 0,
    };
    storage.enqueue_mutation(&mutation)?;

    Ok(new_revision)
}

/// Deletes a note by creating a revisioned tombstone or hard-purging it.
pub fn delete_note(
    custom_data_dir: Option<&Path>,
    id_or_prefix: &str,
    purge: bool,
) -> Result<(String, u64), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, id_or_prefix, purge)?;

    if purge {
        storage.purge_object(&stored.object_id)?;
        storage.clear_base_versions(&stored.object_id)?;
        return Ok((stored.object_id, stored.revision));
    }

    let prior_revision = stored.revision;
    let tombstone_revision = prior_revision + 1;
    let now = now_utc_rfc3339();

    storage.put_base_version(&stored.object_id, prior_revision, &stored.envelope)?;

    storage.mark_deleted(
        &stored.object_id,
        tombstone_revision,
        stored.envelope.clone(),
        now.clone(),
    )?;

    let mutation = PendingMutation {
        mutation_id: Uuid::new_v4().to_string(),
        object_id: stored.object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Delete,
        expected_revision: prior_revision,
        envelope: stored.envelope,
        created_at: now,
        status: MutationStatus::Pending,
        retry_count: 0,
    };
    storage.enqueue_mutation(&mutation)?;

    Ok((stored.object_id, tombstone_revision))
}

/// Searches local notes using an in-memory index built on the fly while unlocked.
///
/// Search text and decrypted content are volatile and not persisted (SEC-001, SEC-009).
pub fn search_notes(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    query: &str,
) -> Result<Vec<SearchResult>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let filter = ObjectFilter {
        kind: Some(OBJECT_KIND_NOTE),
        include_deleted: false,
    };
    let stored_objects = storage.list_objects(&filter)?;

    let mut index = InMemorySearchIndex::new();
    for obj in stored_objects {
        if let Ok(note) = PlaintextNote::decrypt(&obj.envelope, vault_key) {
            index.insert(&obj.object_id, &note);
        }
    }

    let results = index.search(query);
    index.clear();

    Ok(results)
}
