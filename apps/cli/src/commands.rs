//! Command execution implementations for `zk-note init`, `unlock`, `lock`, `status`,
//! `new`, `edit`, `show`, `search`, `delete`, `history`, and `list`.

use crate::config::{db_file, resolve_data_dir, session_file, vault_file};
use crate::edit::{note_to_edit_buffer, parse_edit_buffer, run_editor, TempFileGuard};
use crate::error::CliError;
use crate::session::{clear_session, has_active_session, load_session_key, save_session_key};
use serde::Serialize;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use zk_core::note::{NoteBuilder, NoteHistoryItem, PlaintextNote};
use zk_core::search::{InMemorySearchIndex, SearchResult};
use zk_core::time::now_utc_rfc3339;
use zk_core::vault::VaultManager;
use zk_crypto::kdf::KdfParams;
use zk_protocol::constants::{
    INITIAL_EXPECTED_REVISION, INITIAL_OBJECT_REVISION, INITIAL_SERVER_SEQ, OBJECT_KIND_NOTE,
};
use zk_protocol::vault::VaultBootstrap;
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};
use zk_storage::{
    MutationStatus, MutationType, ObjectFilter, PendingMutation, SqliteStorage,
    StoredEncryptedObject,
};

/// Initializes a new zero-knowledge note vault.
pub fn cmd_init(
    custom_data_dir: Option<&Path>,
    explicit_passphrase: Option<String>,
    test_kdf: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if vault_path.exists() {
        return Err(CliError::VaultAlreadyInitialized);
    }

    // Obtain master passphrase
    let passphrase = if let Some(pass) = explicit_passphrase {
        pass
    } else {
        let p1 = rpassword::prompt_password("Enter new vault passphrase: ")
            .map_err(|e| CliError::Io(format!("failed to read passphrase: {e}")))?;
        let p2 = rpassword::prompt_password("Confirm vault passphrase: ")
            .map_err(|e| CliError::Io(format!("failed to read confirmation: {e}")))?;

        if p1 != p2 {
            return Err(CliError::PassphraseMismatch);
        }
        if p1.is_empty() {
            return Err(CliError::Io("passphrase cannot be empty".to_string()));
        }
        p1
    };

    let kdf_params = if test_kdf {
        KdfParams::new_test()
    } else {
        KdfParams::new_production()
    };

    println!("Initializing vault with Argon2id key derivation...");
    let (bootstrap, recovery_key_str, vault_key) =
        VaultManager::init_vault(passphrase.as_bytes(), &kdf_params)?;

    // Persist vault.json
    std::fs::create_dir_all(&data_dir).map_err(|e| {
        CliError::Io(format!(
            "failed to create directory {}: {e}",
            data_dir.display()
        ))
    })?;

    let bootstrap_json = serde_json::to_string_pretty(&bootstrap)
        .map_err(|e| CliError::Io(format!("serialize vault bootstrap: {e}")))?;

    std::fs::write(&vault_path, bootstrap_json).map_err(|e| {
        CliError::Io(format!(
            "failed to write vault file {}: {e}",
            vault_path.display()
        ))
    })?;

    // Initialize local SQLite database
    let _ = SqliteStorage::open(&db_path)?;

    // Automatically unlock the freshly created vault for this session
    let sess_path = session_file(&data_dir);
    save_session_key(&sess_path, &vault_key)?;

    println!("\n=== VAULT CREATED SUCCESSFULLY ===");
    println!("Data directory: {}", data_dir.display());
    println!("\nRECOVERY KEY:");
    println!("  {}", recovery_key_str);
    println!("\nIMPORTANT:");
    println!("  - Store this recovery key in a secure, offline location.");
    println!(
        "  - If you lose your passphrase, this recovery key is the ONLY way to recover notes."
    );
    println!("  - The server CANNOT decrypt your notes or reset your passphrase.");
    println!("  - Vault is currently unlocked for this session.\n");

    Ok(())
}

/// Unlocks the vault using either the master passphrase or recovery key.
pub fn cmd_unlock(
    custom_data_dir: Option<&Path>,
    explicit_passphrase: Option<String>,
    explicit_recovery_key: Option<String>,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    if has_active_session(&sess_path) {
        println!("Vault is already unlocked.");
        return Ok(());
    }

    let vault_bytes = std::fs::read(&vault_path).map_err(|e| {
        CliError::Io(format!(
            "failed to read vault file {}: {e}",
            vault_path.display()
        ))
    })?;

    let bootstrap: VaultBootstrap = serde_json::from_slice(&vault_bytes)
        .map_err(|e| CliError::Io(format!("corrupted vault.json: {e}")))?;

    let vault_key = if let Some(rec_key) = explicit_recovery_key {
        println!("Unlocking vault with recovery key...");
        VaultManager::unlock_with_recovery_key(&bootstrap, &rec_key)?
    } else {
        let pass = if let Some(p) = explicit_passphrase {
            p
        } else {
            rpassword::prompt_password("Enter vault passphrase: ")
                .map_err(|e| CliError::Io(format!("failed to read passphrase: {e}")))?
        };

        println!("Deriving key and unlocking vault...");
        VaultManager::unlock_with_passphrase(&bootstrap, pass.as_bytes())?
    };

    save_session_key(&sess_path, &vault_key)?;
    println!("Vault unlocked successfully.");

    Ok(())
}

/// Locks the vault and clears active session key material.
pub fn cmd_lock(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);

    clear_session(&sess_path)?;
    println!("Vault locked.");
    Ok(())
}

/// Displays the current vault status (UNINITIALIZED, LOCKED, or UNLOCKED).
pub fn cmd_status(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        println!("Vault status: UNINITIALIZED");
        println!("Path: {}", data_dir.display());
        println!("Run 'zk-note init' to create a new vault.");
    } else if has_active_session(&sess_path) {
        match load_session_key(&sess_path) {
            Ok(_) => {
                println!("Vault status: UNLOCKED");
                println!("Path: {}", data_dir.display());
            }
            Err(_) => {
                println!("Vault status: LOCKED (corrupted session file)");
                println!("Path: {}", data_dir.display());
            }
        }
    } else {
        println!("Vault status: LOCKED");
        println!("Path: {}", data_dir.display());
        println!("Run 'zk-note unlock' to unlock the vault.");
    }

    Ok(())
}

/// Creates a new encrypted note and persists it locally.
pub fn cmd_new(
    custom_data_dir: Option<&Path>,
    title_opt: Option<String>,
    body_opt: Option<String>,
    tags: Vec<String>,
) -> Result<String, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to create and encrypt note
    let vault_key = load_session_key(&sess_path)?;

    // Resolve title: argument -> interactive prompt -> error if empty
    let title = if let Some(t) = title_opt {
        t
    } else {
        let stdin = io::stdin();
        if stdin.is_terminal() {
            print!("Enter note title: ");
            io::stdout()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;
            let mut line = String::new();
            stdin
                .lock()
                .read_line(&mut line)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return Err(CliError::Io("note title cannot be empty".to_string()));
            }
            trimmed
        } else {
            return Err(CliError::Io(
                "note title is required (provide via --title or interactive prompt)".to_string(),
            ));
        }
    };

    // Resolve body: argument -> stdin (if piped) -> empty string
    let body = if let Some(b) = body_opt {
        b
    } else {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            let mut buffer = String::new();
            stdin
                .lock()
                .read_to_string(&mut buffer)
                .map_err(|e| CliError::Io(e.to_string()))?;
            buffer
        } else {
            String::new()
        }
    };

    let note_id = uuid::Uuid::new_v4().to_string();
    let now = now_utc_rfc3339();

    let note = NoteBuilder::new()
        .title(title)
        .body(body)
        .tags(tags)
        .created_at(now.clone())
        .updated_at(now.clone())
        .build()?;

    // Encrypt note using the unlocked VaultKey
    let envelope = note.encrypt(&vault_key, &note_id)?;

    // Store in SqliteStorage
    let storage = SqliteStorage::open(&db_path)?;

    let stored_obj = StoredEncryptedObject {
        object_id: note_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: INITIAL_OBJECT_REVISION,
        server_seq: INITIAL_SERVER_SEQ,
        is_deleted: false,
        envelope: envelope.clone(),
        updated_at: now.clone(),
    };
    storage.put_object(&stored_obj)?;

    // Enqueue pending mutation for future sync
    let mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: note_id.clone(),
        expected_revision: INITIAL_EXPECTED_REVISION,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        envelope,
        created_at: now,
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&mutation)?;

    println!("Created note: {note_id}");
    println!("Title: {}", note.title);
    if !note.tags.is_empty() {
        println!("Tags: {}", note.tags.join(", "));
    }

    Ok(note_id)
}

/// Helper to resolve a stored note object by exact ID or unique >=4 character prefix.
fn find_note_object(
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
            // Check if it matched a deleted note when include_deleted was false
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

/// Displays the decrypted contents of a note by its ID.
pub fn cmd_show(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    json_output: bool,
) -> Result<PlaintextNote, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to decrypt note
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, false)?;

    let note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    if json_output {
        let json = serde_json::to_string_pretty(&note)
            .map_err(|e| CliError::Io(format!("serialize note json: {e}")))?;
        println!("{json}");
    } else {
        println!(
            "================================================================================"
        );
        println!("ID:       {}", stored.object_id);
        println!("Title:    {}", note.title);
        if !note.tags.is_empty() {
            println!("Tags:     {}", note.tags.join(", "));
        }
        println!("Updated:  {}", note.updated_at);
        println!("Created:  {}", note.created_at);
        println!("Revision: {}", stored.revision);
        println!(
            "================================================================================\n"
        );
        println!("{}", note.body);
    }

    Ok(note)
}

/// Searches notes across title, body, and tags using volatile in-memory indexing while unlocked.
pub fn cmd_search(
    custom_data_dir: Option<&Path>,
    query: &str,
    json_output: bool,
) -> Result<Vec<SearchResult>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to decrypt note contents into volatile memory index
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    // List only active (non-tombstoned) notes
    let stored_objects = storage.list_objects(&ObjectFilter::for_kind(OBJECT_KIND_NOTE))?;

    let mut index = InMemorySearchIndex::new();
    for stored in stored_objects {
        if stored.is_deleted {
            continue;
        }

        let note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;
        index.insert(&stored.object_id, &note);
    }

    let results = index.search(query);

    if json_output {
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| CliError::Io(format!("serialize search json: {e}")))?;
        println!("{json}");
    } else if results.is_empty() {
        println!("No notes matched query: \"{query}\"");
    } else {
        println!(
            "Found {} matching note(s) for \"{}\":",
            results.len(),
            query
        );
        println!("{:<36}  {:<24}  {:<20}  TITLE", "ID", "UPDATED", "TAGS");
        println!("{}", "-".repeat(95));
        for r in &results {
            let tags_str = if r.tags.is_empty() {
                "-".to_string()
            } else {
                format!("[{}]", r.tags.join(", "))
            };
            println!(
                "{:<36}  {:<24}  {:<20}  {}",
                r.id,
                r.updated_at,
                if tags_str.len() > 20 {
                    format!("{}...", &tags_str[..17])
                } else {
                    tags_str
                },
                r.title
            );
            if !r.snippet.is_empty() {
                println!("    snippet: {}", r.snippet);
            }
        }
    }

    Ok(results)
}

/// Edits an existing note using $EDITOR or programmatic overrides.
pub fn cmd_edit(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    editor_override: Option<&str>,
    title_override: Option<String>,
    body_override: Option<String>,
    tag_override: Option<Vec<String>>,
) -> Result<PlaintextNote, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, false)?;

    // Decrypt current note
    let current_note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    let (new_title, new_tags, new_body) =
        if title_override.is_some() || body_override.is_some() || tag_override.is_some() {
            // Programmatic edit mode (useful for scripts and fast test execution)
            let title = title_override.unwrap_or_else(|| current_note.title.clone());
            let tags = tag_override.unwrap_or_else(|| current_note.tags.clone());
            let body = body_override.unwrap_or_else(|| current_note.body.clone());
            (title, tags, body)
        } else {
            // Interactive $EDITOR flow
            let editor_cmd = if let Some(e) = editor_override {
                e.to_string()
            } else if let Ok(e) = std::env::var("VISUAL") {
                e
            } else if let Ok(e) = std::env::var("EDITOR") {
                e
            } else {
                "nano".to_string()
            };

            let initial_text =
                note_to_edit_buffer(&current_note.title, &current_note.tags, &current_note.body);
            let guard = TempFileGuard::create("zk-note-edit", initial_text.as_bytes())?;

            if guard.is_ram_backed() {
                println!("Editing note in RAM-backed temporary buffer (/dev/shm)...");
            } else {
                println!("Editing note in temporary buffer...");
            }

            // Run editor - if it fails (non-zero exit), guard drops, wipes temp file, and returns Err
            run_editor(&editor_cmd, guard.path())?;

            // Read edited content
            let edited_bytes = guard.read_bytes()?;
            if edited_bytes == initial_text.as_bytes() {
                println!("No changes made to note.");
                guard.cleanup();
                return Ok(current_note);
            }

            let edited_str = String::from_utf8(edited_bytes)
                .map_err(|e| CliError::Io(format!("invalid UTF-8 in edited note: {e}")))?;

            let parsed = parse_edit_buffer(&edited_str, &current_note.title, &current_note.tags)?;

            // Explicit cleanup after successful read
            guard.cleanup();

            (parsed.title, parsed.tags, parsed.body)
        };

    // Check if actually modified compared to current_note
    if new_title == current_note.title
        && new_tags == current_note.tags
        && new_body == current_note.body
    {
        println!("No changes made to note.");
        return Ok(current_note);
    }

    let now = now_utc_rfc3339();
    let updated_note = NoteBuilder::new()
        .title(new_title)
        .body(new_body)
        .tags(new_tags)
        .created_at(current_note.created_at.clone())
        .updated_at(now.clone())
        .build()?;

    // Encrypt updated note
    let new_envelope = updated_note.encrypt(&vault_key, &stored.object_id)?;

    // Archive base version for three-way merge
    storage.put_base_version(&stored.object_id, stored.revision, &stored.envelope)?;

    // Save updated object
    let new_revision = stored.revision + 1;
    let updated_stored_obj = StoredEncryptedObject {
        object_id: stored.object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: new_revision,
        server_seq: stored.server_seq,
        is_deleted: false,
        envelope: new_envelope.clone(),
        updated_at: now.clone(),
    };
    storage.put_object(&updated_stored_obj)?;

    // Enqueue pending mutation
    let mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: stored.object_id.clone(),
        expected_revision: stored.revision,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        envelope: new_envelope,
        created_at: now,
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&mutation)?;

    println!("Updated note: {}", stored.object_id);
    println!("Title:    {}", updated_note.title);
    println!("Revision: {new_revision}");
    if !updated_note.tags.is_empty() {
        println!("Tags:     {}", updated_note.tags.join(", "));
    }

    Ok(updated_note)
}

/// Deletes an existing note, creating a revisioned tombstone and archiving base version.
/// If `purge` is true, completely removes the note and its history from the local database.
pub fn cmd_delete(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    purge: bool,
) -> Result<u64, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to delete note
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, purge)?;

    if purge {
        storage.purge_object(&stored.object_id)?;
        storage.clear_base_versions(&stored.object_id)?;
        println!("Purged note: {}", stored.object_id);
        return Ok(stored.revision);
    }

    // Decrypt to verify key authenticity and obtain title for confirmation
    let note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    // Archive current version as base version before creating tombstone
    storage.put_base_version(&stored.object_id, stored.revision, &stored.envelope)?;

    // Increment revision for the tombstone mutation (monotonic revision bump)
    let new_revision = stored.revision + 1;
    let now = now_utc_rfc3339();

    // Mark as deleted in local_objects (tombstone)
    storage.mark_deleted(
        &stored.object_id,
        new_revision,
        stored.envelope.clone(),
        now.clone(),
    )?;

    // Enqueue pending delete mutation for sync (expected_revision = prior revision)
    let mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: stored.object_id.clone(),
        expected_revision: stored.revision,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Delete,
        envelope: stored.envelope,
        created_at: now,
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&mutation)?;

    println!("Deleted note: {} (\"{}\")", stored.object_id, note.title);
    println!("Tombstone revision: {new_revision}");

    Ok(new_revision)
}

/// Note summary row for decrypted list display and JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteSummary {
    /// Object identifier (UUID v4 string).
    pub id: String,
    /// Note title.
    pub title: String,
    /// Canonicalized note tags.
    pub tags: Vec<String>,
    /// Last update timestamp (RFC 3339 UTC).
    pub updated_at: String,
    /// Creation timestamp (RFC 3339 UTC).
    pub created_at: String,
    /// Current local revision counter.
    pub revision: u64,
    /// True if this note has been marked as deleted (tombstone).
    pub is_deleted: bool,
}

/// Lists notes using locally decrypted state while unlocked.
pub fn cmd_list(
    custom_data_dir: Option<&Path>,
    tag_filter: Option<String>,
    include_deleted: bool,
    json_output: bool,
) -> Result<Vec<NoteSummary>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to decrypt note titles/tags
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    let stored_objects = storage.list_objects(&ObjectFilter {
        kind: Some(OBJECT_KIND_NOTE),
        include_deleted,
    })?;

    let mut notes = Vec::new();
    let normalized_filter = tag_filter.as_ref().map(|t| t.trim().to_lowercase());

    for stored in stored_objects {
        if stored.is_deleted && !include_deleted {
            continue;
        }

        let note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

        if let Some(ref tag) = normalized_filter {
            if !note.tags.contains(tag) {
                continue;
            }
        }

        notes.push(NoteSummary {
            id: stored.object_id,
            title: note.title,
            tags: note.tags,
            updated_at: note.updated_at,
            created_at: note.created_at,
            revision: stored.revision,
            is_deleted: stored.is_deleted,
        });
    }

    // Sort by updated_at descending
    notes.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    if json_output {
        let json = serde_json::to_string_pretty(&notes)
            .map_err(|e| CliError::Io(format!("serialize list json: {e}")))?;
        println!("{json}");
    } else if notes.is_empty() {
        println!("No notes found.");
    } else {
        println!("{:<36}  {:<24}  {:<20}  TITLE", "ID", "UPDATED", "TAGS");
        println!("{}", "-".repeat(95));
        for n in &notes {
            let tags_str = if n.tags.is_empty() {
                "-".to_string()
            } else {
                format!("[{}]", n.tags.join(", "))
            };
            let title_display = if n.is_deleted {
                format!("[DELETED] {}", n.title)
            } else {
                n.title.clone()
            };
            println!(
                "{:<36}  {:<24}  {:<20}  {}",
                n.id,
                n.updated_at,
                if tags_str.len() > 20 {
                    format!("{}...", &tags_str[..17])
                } else {
                    tags_str
                },
                title_display
            );
        }
    }

    Ok(notes)
}

/// Displays the revision history or a specific historical revision of a note.
pub fn cmd_history(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    revision_opt: Option<u64>,
    json_output: bool,
) -> Result<Vec<NoteHistoryItem>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked to decrypt historical envelopes
    let vault_key = load_session_key(&sess_path)?;

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, true)?;

    let base_versions = storage.list_base_versions(&stored.object_id)?;
    let mut history = Vec::new();

    for (rev, env) in base_versions {
        let note = PlaintextNote::decrypt(&env, &vault_key)?;
        history.push(NoteHistoryItem {
            revision: rev,
            title: note.title,
            tags: note.tags,
            body: note.body,
            updated_at: note.updated_at,
            is_deleted: false,
        });
    }

    // Add current head version if not already present
    if !history.iter().any(|h| h.revision == stored.revision) {
        let current_note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;
        history.push(NoteHistoryItem {
            revision: stored.revision,
            title: current_note.title,
            tags: current_note.tags,
            body: current_note.body,
            updated_at: stored.updated_at.clone(),
            is_deleted: stored.is_deleted,
        });
    }

    history.sort_by_key(|h| h.revision);

    if let Some(target_rev) = revision_opt {
        let item = history
            .iter()
            .find(|h| h.revision == target_rev)
            .ok_or_else(|| CliError::RevisionNotFound {
                note_id: stored.object_id.clone(),
                revision: target_rev,
            })?;

        if json_output {
            let json = serde_json::to_string_pretty(item)
                .map_err(|e| CliError::Io(format!("serialize history item json: {e}")))?;
            println!("{json}");
        } else {
            println!(
                "================================================================================"
            );
            println!("ID:       {}", stored.object_id);
            println!("Title:    {}", item.title);
            if !item.tags.is_empty() {
                println!("Tags:     {}", item.tags.join(", "));
            }
            println!(
                "Revision: {}{}",
                item.revision,
                if item.is_deleted { " (tombstone)" } else { "" }
            );
            println!("Updated:  {}", item.updated_at);
            println!(
                "================================================================================\n"
            );
            println!("{}", item.body);
        }
        return Ok(vec![item.clone()]);
    }

    if json_output {
        let json = serde_json::to_string_pretty(&history)
            .map_err(|e| CliError::Io(format!("serialize history json: {e}")))?;
        println!("{json}");
    } else if history.is_empty() {
        println!("No history found for note: {}", stored.object_id);
    } else {
        println!("History for note: {}", stored.object_id);
        println!(
            "{:<10}  {:<24}  {:<10}  TITLE",
            "REVISION", "UPDATED", "STATUS"
        );
        println!("{}", "-".repeat(75));
        for h in &history {
            let status = if h.is_deleted { "Deleted" } else { "Active" };
            println!(
                "{:<10}  {:<24}  {:<10}  {}",
                h.revision, h.updated_at, status, h.title
            );
        }
    }

    Ok(history)
}
