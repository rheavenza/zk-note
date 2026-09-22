//! External editor integration using secure temporary file guards (ZK-101).

use super::notes::{find_note_object, update_note};
use crate::config::{db_file, resolve_data_dir, vault_file};
use crate::edit::{note_to_edit_buffer, parse_edit_buffer, run_editor, TempFileGuard};
use crate::error::CliError;
use std::path::Path;
use zk_core::note::PlaintextNote;
use zk_crypto::keys::VaultKey;
use zk_storage::SqliteStorage;

/// Launches the user's external editor ($EDITOR or $VISUAL) to edit a note securely.
///
/// Plaintext note buffers are stored only in RAM/tmpfs via [`TempFileGuard`] and wiped on exit.
pub fn edit_note_external(
    custom_data_dir: Option<&Path>,
    vault_key: &VaultKey,
    note_id_or_prefix: &str,
    custom_editor: Option<&str>,
) -> Result<u64, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id_or_prefix, false)?;
    let current_note = PlaintextNote::decrypt(&stored.envelope, vault_key)?;

    let editor_cmd = if let Some(e) = custom_editor {
        e.to_string()
    } else if let Ok(e) = std::env::var("VISUAL") {
        e
    } else if let Ok(e) = std::env::var("EDITOR") {
        e
    } else {
        "nano".to_string()
    };

    let initial_content =
        note_to_edit_buffer(&current_note.title, &current_note.tags, &current_note.body);

    let guard = TempFileGuard::create("zk-note-edit", initial_content.as_bytes())?;
    run_editor(&editor_cmd, guard.path())?;

    let edited_bytes = guard.read_bytes()?;
    let edited_str = String::from_utf8(edited_bytes)
        .map_err(|e| CliError::Io(format!("invalid UTF-8 in edited note: {e}")))?;

    let parsed = parse_edit_buffer(&edited_str, &current_note.title, &current_note.tags)?;
    guard.cleanup();

    update_note(
        custom_data_dir,
        vault_key,
        &stored.object_id,
        &parsed.title,
        &parsed.body,
        parsed.tags,
    )
}
