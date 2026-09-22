//! Command execution implementations for `zk-note init`, `unlock`, `lock`, `status`,
//! `new`, `edit`, `show`, `search`, `delete`, `history`, and `list`.

use crate::auth::{
    api_device_authorize, api_list_devices, api_query_status, api_revoke_device,
    api_revoke_session, api_verify_token, clear_auth_session, get_or_create_device_id,
    has_auth_session, load_auth_session, save_auth_session,
};
use crate::config::{auth_session_file, db_file, resolve_data_dir, session_file, vault_file};
use crate::edit::{note_to_edit_buffer, parse_edit_buffer, run_editor, TempFileGuard};
use crate::error::CliError;
use crate::session::{
    get_session_info, has_active_session, load_session_key, save_session_key,
    save_session_key_with_timeout, update_session_timeout,
};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;
use zk_core::note::{NoteBuilder, NoteHistoryItem, PlaintextNote};
use zk_core::search::SearchResult;
use zk_core::time::now_utc_rfc3339;
use zk_core::vault::VaultManager;
use zk_crypto::kdf::{KdfParams, TEST_MEMORY_KIB};
use zk_protocol::constants::{
    INITIAL_EXPECTED_REVISION, INITIAL_OBJECT_REVISION, INITIAL_SERVER_SEQ,
    OBJECT_KIND_ATTACHMENT_MANIFEST, OBJECT_KIND_NOTE,
};
use zk_protocol::vault::VaultBootstrap;
use zk_storage::traits::{BaseVersionStore, MutationStore, ObjectStore};
use zk_storage::{
    MutationStatus, MutationType, PendingMutation, SqliteStorage, StoredEncryptedObject,
};
use zk_sync::{generate_merge_candidate, ConflictResolutionResult, ConflictResolutionStrategy};

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
/// Optionally sets a new master passphrase if provided (ZK-073).
pub fn cmd_unlock(
    custom_data_dir: Option<&Path>,
    explicit_passphrase: Option<String>,
    explicit_recovery_key: Option<String>,
    new_passphrase: Option<String>,
    idle_timeout_mins: Option<u64>,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    if has_active_session(&sess_path) && new_passphrase.is_none() {
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

    if let Some(new_pass) = new_passphrase {
        if new_pass.len() < 8 {
            return Err(CliError::Io(
                "new passphrase must be at least 8 characters long".to_string(),
            ));
        }
        let existing_kdf: KdfParams = bootstrap.kdf.clone().into();
        let kdf_params = if existing_kdf.memory_kib == TEST_MEMORY_KIB {
            KdfParams::new_test()
        } else {
            KdfParams::new_production()
        };
        let updated_bootstrap = VaultManager::set_new_passphrase(
            &bootstrap,
            &vault_key,
            new_pass.as_bytes(),
            &kdf_params,
        )?;
        let updated_json = serde_json::to_string_pretty(&updated_bootstrap)
            .map_err(|e| CliError::Io(format!("serialize vault bootstrap: {e}")))?;
        let tmp_path = data_dir.join(format!("vault.json.tmp.{}", std::process::id()));
        std::fs::write(&tmp_path, updated_json)
            .map_err(|e| CliError::Io(format!("failed to write temporary vault file: {e}")))?;
        std::fs::rename(&tmp_path, &vault_path)
            .map_err(|e| CliError::Io(format!("failed to atomically update vault.json: {e}")))?;
        println!("New master passphrase set successfully! Existing note ciphertexts remain valid.");
    }

    let timeout_secs = match idle_timeout_mins {
        Some(0) => None,
        Some(m) => Some(m * 60),
        None => crate::session::resolve_default_timeout(),
    };

    save_session_key_with_timeout(&sess_path, &vault_key, timeout_secs)?;
    println!("Vault unlocked successfully.");
    match timeout_secs {
        Some(s) => println!("Auto-lock: Active ({} minute(s) idle timeout)", s / 60),
        None => println!("Auto-lock: Disabled (never expires)"),
    }

    Ok(())
}

/// Changes the vault master passphrase (ZK-074).
///
/// Invariants:
/// - Verifies the current master passphrase fails closed before rotation.
/// - Derives a fresh KEK and wraps the same VaultKey (rewrap only).
/// - Note ciphertexts in storage are untouched (old object ciphertext unchanged).
/// - Recovery key envelope is preserved verbatim (recovery wrapper remains valid).
/// - Atomically replaces vault.json with fs::rename.
pub fn cmd_passwd(
    custom_data_dir: Option<&Path>,
    explicit_old_passphrase: Option<String>,
    explicit_new_passphrase: Option<String>,
    test_kdf: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let vault_bytes = std::fs::read(&vault_path).map_err(|e| {
        CliError::Io(format!(
            "failed to read vault file {}: {e}",
            vault_path.display()
        ))
    })?;

    let bootstrap: VaultBootstrap = serde_json::from_slice(&vault_bytes)
        .map_err(|e| CliError::Io(format!("corrupted vault.json: {e}")))?;

    // 1. Obtain and verify current master passphrase
    let old_pass = if let Some(p) = explicit_old_passphrase {
        p
    } else {
        rpassword::prompt_password("Enter current vault passphrase: ")
            .map_err(|e| CliError::Io(format!("failed to read current passphrase: {e}")))?
    };

    if old_pass.is_empty() {
        return Err(CliError::Io(
            "current passphrase cannot be empty".to_string(),
        ));
    }

    println!("Verifying current master passphrase...");
    let vault_key = VaultManager::unlock_with_passphrase(&bootstrap, old_pass.as_bytes())?;

    // 2. Obtain and validate new master passphrase
    let new_pass = if let Some(p) = explicit_new_passphrase {
        if p.len() < 8 {
            return Err(CliError::Io(
                "new passphrase must be at least 8 characters long".to_string(),
            ));
        }
        p
    } else {
        let p1 = rpassword::prompt_password("Enter new vault passphrase: ")
            .map_err(|e| CliError::Io(format!("failed to read new passphrase: {e}")))?;
        if p1.len() < 8 {
            return Err(CliError::Io(
                "new passphrase must be at least 8 characters long".to_string(),
            ));
        }
        let p2 = rpassword::prompt_password("Confirm new vault passphrase: ")
            .map_err(|e| CliError::Io(format!("failed to read confirmation: {e}")))?;
        if p1 != p2 {
            return Err(CliError::PassphraseMismatch);
        }
        p1
    };

    let existing_kdf: KdfParams = bootstrap.kdf.clone().into();
    let kdf_params = if test_kdf || existing_kdf.memory_kib == TEST_MEMORY_KIB {
        KdfParams::new_test()
    } else {
        KdfParams::new_production()
    };

    println!("Re-wrapping vault key under new master passphrase...");
    let updated_bootstrap =
        VaultManager::set_new_passphrase(&bootstrap, &vault_key, new_pass.as_bytes(), &kdf_params)?;

    // Atomic replacement of vault.json
    let updated_json = serde_json::to_string_pretty(&updated_bootstrap)
        .map_err(|e| CliError::Io(format!("serialize vault bootstrap: {e}")))?;
    let tmp_path = data_dir.join(format!("vault.json.tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, updated_json)
        .map_err(|e| CliError::Io(format!("failed to write temporary vault file: {e}")))?;
    std::fs::rename(&tmp_path, &vault_path)
        .map_err(|e| CliError::Io(format!("failed to atomically update vault.json: {e}")))?;

    // Keep active session valid if unlocked
    if has_active_session(&sess_path) {
        save_session_key(&sess_path, &vault_key)?;
    }

    println!("Master passphrase changed successfully!");
    println!("  - Re-wrapped vault key envelope with fresh salt and nonce.");
    println!("  - Existing note ciphertexts remain unchanged and decryptable.");
    println!("  - Recovery key envelope remains unchanged and valid.");

    Ok(())
}

/// Recovers vault access using a 288-bit recovery key and allows resetting the master passphrase (ZK-073).
pub fn cmd_recover(
    custom_data_dir: Option<&Path>,
    explicit_recovery_key: Option<String>,
    explicit_new_passphrase: Option<String>,
    export_receipt: Option<&Path>,
    test_kdf: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    println!("\n================================================================");
    println!("             ZERO-KNOWLEDGE VAULT RECOVERY (ZK-073)");
    println!("================================================================");
    println!("CRITICAL ZERO-KNOWLEDGE INVARIANT:");
    println!("  - The server stores ONLY encrypted ciphertext envelopes.");
    println!("  - The server CANNOT decrypt your data or reset lost keys.");
    println!("  - If both passphrase and recovery key are lost, data recovery");
    println!("    is mathematically impossible.");
    println!("================================================================\n");

    let vault_bytes = std::fs::read(&vault_path).map_err(|e| {
        CliError::Io(format!(
            "failed to read vault file {}: {e}",
            vault_path.display()
        ))
    })?;

    let bootstrap: VaultBootstrap = serde_json::from_slice(&vault_bytes)
        .map_err(|e| CliError::Io(format!("corrupted vault.json: {e}")))?;

    let interactive = explicit_recovery_key.is_none();
    let rec_key = if let Some(k) = explicit_recovery_key {
        k
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Enter your 288-bit recovery key: ")
            .map_err(|e| CliError::Io(format!("failed to read recovery key: {e}")))?
    } else {
        return Err(CliError::Io(
            "recovery key must be provided via --recovery-key in non-interactive mode".to_string(),
        ));
    };

    println!("Unwrapping vault master key with recovery key...");
    let vault_key = VaultManager::unlock_with_recovery_key(&bootstrap, rec_key.trim())?;
    println!("Vault master key restored successfully!");

    let new_pass = if let Some(p) = explicit_new_passphrase {
        if p.len() < 8 {
            return Err(CliError::Io(
                "new passphrase must be at least 8 characters long".to_string(),
            ));
        }
        Some(p)
    } else if interactive && std::io::stdin().is_terminal() {
        let p1 = rpassword::prompt_password(
            "Enter new vault passphrase (minimum 8 characters, or leave blank to skip): ",
        )
        .map_err(|e| CliError::Io(format!("failed to read passphrase: {e}")))?;
        if p1.is_empty() {
            None
        } else {
            if p1.len() < 8 {
                return Err(CliError::Io(
                    "new passphrase must be at least 8 characters long".to_string(),
                ));
            }
            let p2 = rpassword::prompt_password("Confirm new vault passphrase: ")
                .map_err(|e| CliError::Io(format!("failed to read confirmation: {e}")))?;
            if p1 != p2 {
                return Err(CliError::PassphraseMismatch);
            }
            Some(p1)
        }
    } else {
        None
    };

    let mut passphrase_reset = false;
    if let Some(ref pass) = new_pass {
        let existing_kdf: KdfParams = bootstrap.kdf.clone().into();
        let kdf_params = if test_kdf || existing_kdf.memory_kib == TEST_MEMORY_KIB {
            KdfParams::new_test()
        } else {
            KdfParams::new_production()
        };

        println!("Re-wrapping vault key under new passphrase KEK...");
        let updated_bootstrap =
            VaultManager::set_new_passphrase(&bootstrap, &vault_key, pass.as_bytes(), &kdf_params)?;

        let updated_json = serde_json::to_string_pretty(&updated_bootstrap)
            .map_err(|e| CliError::Io(format!("serialize vault bootstrap: {e}")))?;

        let tmp_path = data_dir.join(format!("vault.json.tmp.{}", std::process::id()));
        std::fs::write(&tmp_path, updated_json)
            .map_err(|e| CliError::Io(format!("failed to write temporary vault file: {e}")))?;
        std::fs::rename(&tmp_path, &vault_path)
            .map_err(|e| CliError::Io(format!("failed to atomically update vault.json: {e}")))?;

        println!("Master passphrase updated successfully!");
        println!("Existing note ciphertexts remain valid (VaultKey preserved).");
        passphrase_reset = true;
    }

    save_session_key(&sess_path, &vault_key)?;
    println!("Vault is now unlocked for this session.\n");

    if let Some(export_path) = export_receipt {
        let receipt = format!(
            "ZERO-KNOWLEDGE VAULT RECOVERY RECEIPT\n\
             =====================================\n\
             Data directory: {}\n\
             Status: Access restored successfully\n\
             Passphrase reset: {}\n\
             Note: Server stores only ciphertext. Server decryption capability: ZERO.\n",
            data_dir.display(),
            if passphrase_reset { "YES" } else { "NO" }
        );
        std::fs::write(export_path, receipt).map_err(|e| {
            CliError::Io(format!(
                "failed to write recovery receipt to {}: {e}",
                export_path.display()
            ))
        })?;
        println!("Recovery receipt written to: {}", export_path.display());
    }

    Ok(())
}

/// Locks the vault and clears active session key material.
pub fn cmd_lock(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    crate::client::vault::lock_vault(custom_data_dir)?;
    println!("Vault locked.");
    Ok(())
}

/// Displays the current vault status (UNINITIALIZED, LOCKED, or UNLOCKED).
pub fn cmd_status(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    match crate::client::vault::get_vault_status(custom_data_dir)? {
        crate::client::vault::VaultState::Uninitialized => {
            println!("Vault status: UNINITIALIZED");
            println!("Path: {}", data_dir.display());
            println!("Run 'zk-note init' to create a new vault.");
        }
        crate::client::vault::VaultState::Locked => {
            println!("Vault status: LOCKED");
            println!("Path: {}", data_dir.display());
            println!("Run 'zk-note unlock' to unlock the vault.");
        }
        crate::client::vault::VaultState::Unlocked { auto_lock_info } => {
            println!("Vault status: UNLOCKED");
            println!("Path: {}", data_dir.display());
            if let Some(info) = auto_lock_info {
                if let Some(timeout) = info.idle_timeout_secs {
                    let rem_mins = info.remaining_secs.unwrap_or(0) / 60;
                    let rem_secs = info.remaining_secs.unwrap_or(0) % 60;
                    println!(
                        "Auto-lock:    Active (timeout: {}m, idle: {}s, remaining: {}m {}s)",
                        timeout / 60,
                        info.idle_secs,
                        rem_mins,
                        rem_secs
                    );
                } else {
                    println!("Auto-lock:    Disabled (never expires)");
                }
            } else {
                println!("Auto-lock:    Disabled (never expires)");
            }
        }
    }

    let auth_path = auth_session_file(&data_dir);
    if has_auth_session(&auth_path) {
        if let Ok(auth) = load_auth_session(&auth_path) {
            println!(
                "Server auth:  Logged in as account {} (device {}) at {}",
                auth.account_id, auth.device_id, auth.server_url
            );
        } else {
            println!("Server auth:  Logged in (corrupted .auth_session file)");
        }
    } else {
        println!("Server auth:  Not logged in (run 'zk-note login' to connect)");
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

    let note_id =
        crate::client::notes::create_note(custom_data_dir, &vault_key, &title, &body, tags)?;
    let (_, note) =
        crate::client::notes::get_plaintext_note(custom_data_dir, &vault_key, &note_id)?;

    println!("Created note: {note_id}");
    println!("Title: {}", note.title);
    if !note.tags.is_empty() {
        println!("Tags: {}", note.tags.join(", "));
    }

    Ok(note_id)
}

pub use crate::client::notes::find_note_object;

/// Displays the decrypted contents of a note by its ID.
pub fn cmd_show(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    json_output: bool,
) -> Result<PlaintextNote, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);

    // Must be unlocked to decrypt note
    let vault_key = load_session_key(&sess_path)?;

    let (stored, note) =
        crate::client::notes::get_plaintext_note(custom_data_dir, &vault_key, note_id)?;

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
        if !note.attachments.is_empty() {
            println!("Attachments: {}", note.attachments.join(", "));
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
    let sess_path = session_file(&data_dir);

    // Must be unlocked to decrypt note contents into volatile memory index
    let vault_key = load_session_key(&sess_path)?;

    let results = crate::client::notes::search_notes(custom_data_dir, &vault_key, query)?;

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
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Must be unlocked
    let vault_key = load_session_key(&sess_path)?;

    let (stored, current_note) =
        crate::client::notes::get_plaintext_note(custom_data_dir, &vault_key, note_id)?;

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

    let new_revision = crate::client::notes::update_note(
        custom_data_dir,
        &vault_key,
        &stored.object_id,
        &new_title,
        &new_body,
        new_tags.clone(),
    )?;

    let mut updated_note = NoteBuilder::new()
        .title(new_title)
        .body(new_body)
        .tags(new_tags)
        .created_at(&current_note.created_at)
        .build()?;
    updated_note.canonicalize();

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
    let sess_path = session_file(&data_dir);

    // Must be unlocked to delete note
    let vault_key = load_session_key(&sess_path)?;

    if purge {
        let (obj_id, revision) = crate::client::notes::delete_note(custom_data_dir, note_id, true)?;
        println!("Purged note: {obj_id}");
        return Ok(revision);
    }

    let (stored, note) =
        crate::client::notes::get_plaintext_note(custom_data_dir, &vault_key, note_id)?;
    let (obj_id, revision) =
        crate::client::notes::delete_note(custom_data_dir, &stored.object_id, false)?;

    println!("Deleted note: {} (\"{}\")", obj_id, note.title);
    println!("Tombstone revision: {revision}");

    Ok(revision)
}

pub use crate::client::notes::ClientNoteSummary as NoteSummary;

/// Lists notes using locally decrypted state while unlocked.
pub fn cmd_list(
    custom_data_dir: Option<&Path>,
    tag_filter: Option<String>,
    include_deleted: bool,
    json_output: bool,
) -> Result<Vec<NoteSummary>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);

    // Must be unlocked to decrypt note titles/tags
    let vault_key = load_session_key(&sess_path)?;

    let notes = crate::client::notes::list_notes(
        custom_data_dir,
        &vault_key,
        include_deleted,
        tag_filter.as_deref(),
    )?;

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

pub use crate::client::conflicts::find_conflict_record;
pub use crate::client::conflicts::ClientConflictSummary as ConflictListItem;

/// Lists active or all conflict records (`zk-note conflicts`).
pub fn cmd_conflicts(
    custom_data_dir: Option<&Path>,
    include_resolved: bool,
    json_output: bool,
) -> Result<Vec<ConflictListItem>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);
    let vault_key_opt = load_session_key(&sess_path).ok();

    let items = crate::client::conflicts::list_conflicts(
        custom_data_dir,
        vault_key_opt.as_ref(),
        include_resolved,
    )?;

    if json_output {
        let json = serde_json::to_string_pretty(&items)
            .map_err(|e| CliError::Io(format!("serialize conflicts json: {e}")))?;
        println!("{json}");
    } else if items.is_empty() {
        if include_resolved {
            println!("No conflict records found.");
        } else {
            println!("No active conflicts.");
        }
    } else {
        println!(
            "{:<36}  {:<36}  {:<6}  {:<6}  {:<28}  TITLE",
            "CONFLICT ID", "NOTE ID", "BASE", "REMOTE", "STATUS"
        );
        println!("{}", "-".repeat(125));
        for item in &items {
            let status = if item.resolved {
                "Resolved".to_string()
            } else if item.is_delete_vs_edit() {
                "Unresolved (Delete-vs-Edit)".to_string()
            } else if item.is_edit_vs_delete() {
                "Unresolved (Edit-vs-Delete)".to_string()
            } else {
                "Unresolved".to_string()
            };
            println!(
                "{:<36}  {:<36}  {:<6}  {:<6}  {:<28}  {}",
                item.conflict_id,
                item.object_id,
                item.base_revision,
                item.remote_revision,
                status,
                item.title
            );
        }
    }

    Ok(items)
}

/// Resolves an active conflict record (`zk-note resolve <conflict_id>`).
#[allow(clippy::too_many_arguments)]
pub fn cmd_resolve(
    custom_data_dir: Option<&Path>,
    conflict_id: &str,
    choose_local: bool,
    choose_remote: bool,
    choose_merge: bool,
    choose_duplicate: bool,
    choose_restore: bool,
    duplicate_title: Option<String>,
    editor_override: Option<&str>,
    title_override: Option<String>,
    body_override: Option<String>,
    tag_override: Option<Vec<String>>,
) -> Result<ConflictResolutionResult, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    // Vault must be unlocked to resolve conflicts
    let vault_key = load_session_key(&sess_path)?;

    let storage = Arc::new(SqliteStorage::open(&db_path)?);
    let conflict = find_conflict_record(&storage, conflict_id)?;

    if conflict.resolved {
        return Err(CliError::ConflictAlreadyResolved(conflict.conflict_id));
    }

    let flags_count = [
        choose_local,
        choose_remote,
        choose_merge,
        choose_duplicate,
        choose_restore,
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    if flags_count > 1 {
        return Err(CliError::Io(
            "only one of --local, --remote, --merge, --duplicate, or --restore can be specified"
                .to_string(),
        ));
    }

    if choose_merge && (conflict.remote_is_deleted || conflict.local_is_deleted) {
        return Err(CliError::Io(
            "cannot merge a delete conflict; use --restore to resurrect as current revision, --duplicate to restore as a new note, or --remote to accept deletion".to_string()
        ));
    }

    let strategy = if choose_restore {
        ConflictResolutionStrategy::RestoreResurrect
    } else if choose_local {
        ConflictResolutionStrategy::KeepLocal
    } else if choose_remote {
        ConflictResolutionStrategy::KeepRemote
    } else if choose_duplicate {
        let new_object_id = uuid::Uuid::new_v4().to_string();
        ConflictResolutionStrategy::DuplicateAsSeparate {
            new_object_id,
            new_title: duplicate_title,
        }
    } else if choose_merge {
        if title_override.is_some() || body_override.is_some() || tag_override.is_some() {
            // Programmatic merge overrides
            let candidate_note = match &conflict.candidate_envelope {
                Some(cand_env) => PlaintextNote::decrypt(cand_env, &vault_key)?,
                None => {
                    let (outcome, _) = generate_merge_candidate(
                        conflict.base_envelope.as_ref(),
                        &conflict.local_envelope,
                        &conflict.remote_envelope,
                        &vault_key,
                    )?;
                    outcome.candidate
                }
            };
            let merged_title = title_override.unwrap_or(candidate_note.title);
            let merged_body = body_override.unwrap_or(candidate_note.body);
            let merged_tags = tag_override.unwrap_or(candidate_note.tags);

            let merged_note = NoteBuilder::new()
                .title(merged_title)
                .body(merged_body)
                .tags(merged_tags)
                .build()?;
            ConflictResolutionStrategy::Merge(merged_note)
        } else if editor_override.is_some() || io::stdin().is_terminal() {
            let candidate_note = match &conflict.candidate_envelope {
                Some(cand_env) => PlaintextNote::decrypt(cand_env, &vault_key)?,
                None => {
                    let (outcome, _) = generate_merge_candidate(
                        conflict.base_envelope.as_ref(),
                        &conflict.local_envelope,
                        &conflict.remote_envelope,
                        &vault_key,
                    )?;
                    outcome.candidate
                }
            };
            let editor_cmd = if let Some(e) = editor_override {
                e.to_string()
            } else if let Ok(e) = std::env::var("VISUAL") {
                e
            } else if let Ok(e) = std::env::var("EDITOR") {
                e
            } else {
                "nano".to_string()
            };

            let initial_text = note_to_edit_buffer(
                &candidate_note.title,
                &candidate_note.tags,
                &candidate_note.body,
            );
            let guard = TempFileGuard::create("zk-note-resolve-merge", initial_text.as_bytes())?;
            println!("Opening conflict merge candidate in editor ({editor_cmd})...");
            run_editor(&editor_cmd, guard.path())?;
            let edited_bytes = guard.read_bytes()?;
            let edited_str = String::from_utf8(edited_bytes)
                .map_err(|e| CliError::Io(format!("invalid UTF-8 in edited merge note: {e}")))?;
            let parsed =
                parse_edit_buffer(&edited_str, &candidate_note.title, &candidate_note.tags)?;
            guard.cleanup();

            let merged_note = NoteBuilder::new()
                .title(parsed.title)
                .body(parsed.body)
                .tags(parsed.tags)
                .build()?;
            ConflictResolutionStrategy::Merge(merged_note)
        } else {
            // Non-interactive without overrides and no terminal: accept auto-generated candidate
            let candidate_note = match &conflict.candidate_envelope {
                Some(cand_env) => PlaintextNote::decrypt(cand_env, &vault_key)?,
                None => {
                    let (outcome, _) = generate_merge_candidate(
                        conflict.base_envelope.as_ref(),
                        &conflict.local_envelope,
                        &conflict.remote_envelope,
                        &vault_key,
                    )?;
                    outcome.candidate
                }
            };
            ConflictResolutionStrategy::Merge(candidate_note)
        }
    } else {
        // No strategy flags passed
        if !io::stdin().is_terminal() {
            return Err(CliError::Io(
                "no resolution strategy specified; use --local, --remote, --merge, --duplicate, or --restore"
                    .to_string(),
            ));
        }

        if conflict.remote_is_deleted {
            // --- DELETE-VS-EDIT CONFLICT UX ---
            let local_note = PlaintextNote::decrypt(&conflict.local_envelope, &vault_key)?;

            println!("\n=== CONFLICT RESOLUTION (DELETE-VS-EDIT) ===");
            println!("Conflict ID:     {}", conflict.conflict_id);
            println!("Note ID:         {}", conflict.object_id);
            println!("Base revision:   {}", conflict.base_revision);
            println!(
                "Remote revision: {} (DELETED ON SERVER)",
                conflict.remote_revision
            );
            println!("\nLocal version (your offline changes):");
            println!("  Title:   {}", local_note.title);
            println!(
                "  Tags:    {}",
                if local_note.tags.is_empty() {
                    "-".to_string()
                } else {
                    local_note.tags.join(", ")
                }
            );
            println!("  Updated: {}", local_note.updated_at);
            println!("\nRemote status:");
            println!(
                "  The note was DELETED on the remote server (tombstone revision {}).",
                conflict.remote_revision
            );
            println!("\nResolution options:");
            println!("  [1] Restore at current revision (resurrect note on server with your local changes)");
            println!(
                "  [2] Accept remote deletion (discard local changes and delete note locally)"
            );
            println!("  [3] Restore as new note (preserve remote deletion, create new note with local content)");
            println!("  [q] Abort");
            print!("\nSelect an option [1-3, q]: ");
            io::stdout()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;

            let mut input = String::new();
            let stdin = io::stdin();
            stdin
                .lock()
                .read_line(&mut input)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let choice = input.trim();

            match choice {
                "1" => ConflictResolutionStrategy::RestoreResurrect,
                "2" => ConflictResolutionStrategy::KeepRemote,
                "3" => {
                    print!(
                        "Enter title for new note [default: \"{} (Restored)\"]: ",
                        local_note.title
                    );
                    io::stdout()
                        .flush()
                        .map_err(|e| CliError::Io(e.to_string()))?;
                    let mut title_input = String::new();
                    stdin
                        .lock()
                        .read_line(&mut title_input)
                        .map_err(|e| CliError::Io(e.to_string()))?;
                    let trimmed_title = title_input.trim();
                    let title = if trimmed_title.is_empty() {
                        Some(format!("{} (Restored)", local_note.title))
                    } else {
                        Some(trimmed_title.to_string())
                    };
                    let new_object_id = uuid::Uuid::new_v4().to_string();
                    ConflictResolutionStrategy::DuplicateAsSeparate {
                        new_object_id,
                        new_title: title,
                    }
                }
                "q" | "Q" => {
                    println!("Resolution aborted.");
                    return Err(CliError::Io("resolution aborted by user".to_string()));
                }
                other => {
                    return Err(CliError::Io(format!("invalid option: '{other}'")));
                }
            }
        } else if conflict.local_is_deleted {
            // --- EDIT-VS-DELETE CONFLICT UX ---
            let remote_note = PlaintextNote::decrypt(&conflict.remote_envelope, &vault_key)?;

            println!("\n=== CONFLICT RESOLUTION (EDIT-VS-DELETE) ===");
            println!("Conflict ID:     {}", conflict.conflict_id);
            println!("Note ID:         {}", conflict.object_id);
            println!("Base revision:   {}", conflict.base_revision);
            println!("Remote revision: {}", conflict.remote_revision);
            println!("\nLocal status:");
            println!("  You marked this note for DELETION locally.");
            println!("\nRemote version (server head):");
            println!("  Title:   {}", remote_note.title);
            println!(
                "  Tags:    {}",
                if remote_note.tags.is_empty() {
                    "-".to_string()
                } else {
                    remote_note.tags.join(", ")
                }
            );
            println!("  Updated: {}", remote_note.updated_at);
            println!("\nResolution options:");
            println!("  [1] Confirm deletion (delete note on server at current revision)");
            println!(
                "  [2] Keep remote edit (cancel local deletion and restore server's updated note)"
            );
            println!("  [q] Abort");
            print!("\nSelect an option [1-2, q]: ");
            io::stdout()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;

            let mut input = String::new();
            let stdin = io::stdin();
            stdin
                .lock()
                .read_line(&mut input)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let choice = input.trim();

            match choice {
                "1" => ConflictResolutionStrategy::KeepLocal,
                "2" => ConflictResolutionStrategy::KeepRemote,
                "q" | "Q" => {
                    println!("Resolution aborted.");
                    return Err(CliError::Io("resolution aborted by user".to_string()));
                }
                other => {
                    return Err(CliError::Io(format!("invalid option: '{other}'")));
                }
            }
        } else {
            // --- EDIT-VS-EDIT CONFLICT UX ---
            let local_note = PlaintextNote::decrypt(&conflict.local_envelope, &vault_key)?;
            let remote_note = PlaintextNote::decrypt(&conflict.remote_envelope, &vault_key)?;

            println!("\n=== CONFLICT RESOLUTION ===");
            println!("Conflict ID:     {}", conflict.conflict_id);
            println!("Note ID:         {}", conflict.object_id);
            println!("Base revision:   {}", conflict.base_revision);
            println!("Remote revision: {}", conflict.remote_revision);
            println!("\nLocal version (your offline changes):");
            println!("  Title:   {}", local_note.title);
            println!(
                "  Tags:    {}",
                if local_note.tags.is_empty() {
                    "-".to_string()
                } else {
                    local_note.tags.join(", ")
                }
            );
            println!("  Updated: {}", local_note.updated_at);
            println!("\nRemote version (server head):");
            println!("  Title:   {}", remote_note.title);
            println!(
                "  Tags:    {}",
                if remote_note.tags.is_empty() {
                    "-".to_string()
                } else {
                    remote_note.tags.join(", ")
                }
            );
            println!("  Updated: {}", remote_note.updated_at);
            println!("\nResolution options:");
            println!("  [1] Keep local version (overwrite remote on next sync)");
            println!("  [2] Keep remote version (discard local changes)");
            println!("  [3] Merge (open editor with diff3 merge candidate)");
            println!(
                "  [4] Duplicate as separate note (keep remote and preserve local as new note)"
            );
            println!("  [q] Abort");
            print!("\nSelect an option [1-4, q]: ");
            io::stdout()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;

            let mut input = String::new();
            let stdin = io::stdin();
            stdin
                .lock()
                .read_line(&mut input)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let choice = input.trim();

            match choice {
                "1" => ConflictResolutionStrategy::KeepLocal,
                "2" => ConflictResolutionStrategy::KeepRemote,
                "3" => {
                    let candidate_note = match &conflict.candidate_envelope {
                        Some(cand_env) => PlaintextNote::decrypt(cand_env, &vault_key)?,
                        None => {
                            let (outcome, _) = generate_merge_candidate(
                                conflict.base_envelope.as_ref(),
                                &conflict.local_envelope,
                                &conflict.remote_envelope,
                                &vault_key,
                            )?;
                            outcome.candidate
                        }
                    };
                    let editor_cmd = if let Some(e) = editor_override {
                        e.to_string()
                    } else if let Ok(e) = std::env::var("VISUAL") {
                        e
                    } else if let Ok(e) = std::env::var("EDITOR") {
                        e
                    } else {
                        "nano".to_string()
                    };

                    let initial_text = note_to_edit_buffer(
                        &candidate_note.title,
                        &candidate_note.tags,
                        &candidate_note.body,
                    );
                    let guard =
                        TempFileGuard::create("zk-note-resolve-merge", initial_text.as_bytes())?;
                    println!("Opening conflict merge in editor ({editor_cmd})...");
                    run_editor(&editor_cmd, guard.path())?;
                    let edited_bytes = guard.read_bytes()?;
                    let edited_str = String::from_utf8(edited_bytes).map_err(|e| {
                        CliError::Io(format!("invalid UTF-8 in edited merge note: {e}"))
                    })?;
                    let parsed = parse_edit_buffer(
                        &edited_str,
                        &candidate_note.title,
                        &candidate_note.tags,
                    )?;
                    guard.cleanup();

                    let merged_note = NoteBuilder::new()
                        .title(parsed.title)
                        .body(parsed.body)
                        .tags(parsed.tags)
                        .build()?;
                    ConflictResolutionStrategy::Merge(merged_note)
                }
                "4" => {
                    print!(
                        "Enter title for duplicate note [default: \"{} (Local Copy)\"]: ",
                        local_note.title
                    );
                    io::stdout()
                        .flush()
                        .map_err(|e| CliError::Io(e.to_string()))?;
                    let mut title_input = String::new();
                    stdin
                        .lock()
                        .read_line(&mut title_input)
                        .map_err(|e| CliError::Io(e.to_string()))?;
                    let trimmed_title = title_input.trim();
                    let title = if trimmed_title.is_empty() {
                        Some(format!("{} (Local Copy)", local_note.title))
                    } else {
                        Some(trimmed_title.to_string())
                    };
                    let new_object_id = uuid::Uuid::new_v4().to_string();
                    ConflictResolutionStrategy::DuplicateAsSeparate {
                        new_object_id,
                        new_title: title,
                    }
                }
                "q" | "Q" => {
                    println!("Resolution aborted.");
                    return Err(CliError::Io("resolution aborted by user".to_string()));
                }
                other => {
                    return Err(CliError::Io(format!("invalid option: '{other}'")));
                }
            }
        }
    };

    let result = crate::client::conflicts::resolve_conflict_item(
        custom_data_dir,
        &vault_key,
        &conflict.conflict_id,
        strategy,
    )?;

    match &result.duplicated_object_id {
        Some(dup_id) => {
            println!(
                "Conflict '{}' resolved. Local changes preserved as new note '{}'. Original note '{}' updated to remote revision {}.",
                result.conflict_id, dup_id, result.object_id, conflict.remote_revision
            );
        }
        None => match result.retry_mutation {
            Some(ref m) => {
                if conflict.remote_is_deleted {
                    println!(
                        "Conflict '{}' resolved for note '{}'. Note restored/resurrected and mutation enqueued with expected revision {} for sync retry.",
                        result.conflict_id, result.object_id, m.expected_revision
                    );
                } else {
                    println!(
                        "Conflict '{}' resolved for note '{}'. Mutation enqueued with expected revision {} for sync retry.",
                        result.conflict_id, result.object_id, m.expected_revision
                    );
                }
            }
            None => {
                if conflict.remote_is_deleted {
                    println!(
                        "Conflict '{}' resolved for note '{}'. Remote deletion accepted; note marked deleted locally.",
                        result.conflict_id, result.object_id
                    );
                } else {
                    println!(
                        "Conflict '{}' resolved for note '{}'. Remote version accepted.",
                        result.conflict_id, result.object_id
                    );
                }
            }
        },
    }

    Ok(result)
}

/// Logs in to a sync server and persists authorized session credentials (ZK-072).
pub async fn cmd_login(
    custom_data_dir: Option<&Path>,
    server_opt: Option<String>,
    account_id_opt: Option<String>,
    device_name_opt: Option<String>,
    device_id_opt: Option<String>,
    token_opt: Option<String>,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|e| CliError::Io(e.to_string()))?;

    let server_url = if let Some(s) = server_opt {
        s
    } else if let Ok(env_s) = std::env::var("ZK_SERVER_URL") {
        env_s
    } else if io::stdin().is_terminal() {
        print!("Enter server URL [http://127.0.0.1:8080]: ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            "http://127.0.0.1:8080".to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        "http://127.0.0.1:8080".to_string()
    };

    let explicit_dev_id = if let Some(d_str) = device_id_opt {
        Some(
            Uuid::parse_str(&d_str)
                .map_err(|e| CliError::AuthError(format!("invalid device-id UUID: {e}")))?,
        )
    } else {
        None
    };

    let device_id = get_or_create_device_id(&data_dir, explicit_dev_id)?;

    let token = zk_protocol::auth::AuthToken::new(match token_opt {
        Some(token) => token,
        None if io::stdin().is_terminal() => {
            rpassword::prompt_password("Existing session token to authorize this device: ")
                .map_err(|e| CliError::Io(e.to_string()))?
        }
        None => {
            return Err(CliError::AuthError(
                "An existing session token is required; use --token or interactive login".into(),
            ))
        }
    });
    let verified = api_verify_token(&server_url, token.expose_secret(), device_id).await?;
    if let Some(account) = account_id_opt {
        let account = Uuid::parse_str(&account)
            .map_err(|_| CliError::AuthError("Invalid account ID".into()))?;
        if account != verified.account_id {
            return Err(CliError::AuthError(
                "Session does not authorize the requested account".into(),
            ));
        }
    }
    let auth_session = api_device_authorize(
        &server_url,
        token.expose_secret(),
        verified.account_id,
        device_id,
        device_name_opt,
    )
    .await?;

    let auth_path = auth_session_file(&data_dir);
    save_auth_session(&auth_path, &auth_session)?;

    println!("Successfully authenticated!");
    println!("Server:     {}", auth_session.server_url);
    println!("Account ID: {}", auth_session.account_id);
    println!("Device ID:  {}", auth_session.device_id);
    if let Some(sess_id) = auth_session.session_id {
        println!("Session ID: {}", sess_id);
    }
    println!("Session credentials saved with restricted permissions (0600).");

    Ok(())
}

/// Revokes the current session on the server and clears local credentials (ZK-072).
pub async fn cmd_logout(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        println!("Not logged in.");
        return Ok(());
    }

    if let Ok(session) = load_auth_session(&auth_path) {
        println!("Revoking session with {}...", session.server_url);
        let _ = api_revoke_session(&session).await;
    }

    clear_auth_session(&auth_path)?;
    println!("Logged out successfully. Local credentials cleared.");
    Ok(())
}

/// Displays active account and session identity without leaking token (ZK-072).
pub async fn cmd_whoami(custom_data_dir: Option<&Path>, json_output: bool) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        if json_output {
            println!("{}", serde_json::json!({ "authenticated": false }));
        } else {
            println!("Not logged in. Run 'zk-note login' to authenticate.");
        }
        return Ok(());
    }

    let session = load_auth_session(&auth_path)?;

    // Verify active status with server
    let status_res = api_query_status(&session).await;

    if json_output {
        match status_res {
            Ok(status) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "authenticated": true,
                        "server_url": session.server_url,
                        "account_id": status.account_id,
                        "device_id": status.device_id.unwrap_or(session.device_id),
                        "session_id": status.session_id.or(session.session_id),
                        "status": status.status,
                    })
                );
            }
            Err(e) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "authenticated": false,
                        "server_url": session.server_url,
                        "account_id": session.account_id,
                        "device_id": session.device_id,
                        "error": e.to_string(),
                    })
                );
            }
        }
    } else {
        println!("Server:     {}", session.server_url);
        println!("Account ID: {}", session.account_id);
        println!("Device ID:  {}", session.device_id);
        if let Some(sid) = session.session_id {
            println!("Session ID: {}", sid);
        }
        match status_res {
            Ok(status) => {
                println!("Status:     Active ({})", status.status);
            }
            Err(CliError::SessionRevoked) => {
                println!("Status:     REVOKED (session or device revoked on server)");
                println!("Run 'zk-note login' to re-authenticate.");
            }
            Err(e) => {
                println!("Status:     UNREACHABLE / ERROR ({e})");
            }
        }
    }

    Ok(())
}

/// Lists registered devices and their status for the authenticated account (ZK-075).
pub async fn cmd_device_list(
    custom_data_dir: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return Err(CliError::NotLoggedIn);
    }

    let session = load_auth_session(&auth_path)?;
    let dev_list = api_list_devices(&session).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&dev_list)
                .map_err(|e| CliError::Io(format!("serialize device list: {e}")))?
        );
    } else {
        println!(
            "{:<38} {:<24} {:<10} {:<24}",
            "DEVICE ID", "NAME", "STATUS", "LAST SEEN"
        );
        println!("{}", "-".repeat(98));
        for dev in &dev_list.devices {
            let is_current = dev.device_id == session.device_id;
            let current_marker = if is_current { " (current)" } else { "" };
            let name = format!(
                "{}{}",
                dev.display_name.as_deref().unwrap_or("<unnamed>"),
                current_marker
            );
            let status = if dev.is_revoked { "REVOKED" } else { "ACTIVE" };
            let last_seen = dev.last_seen.as_deref().unwrap_or("-");
            println!(
                "{:<38} {:<24} {:<10} {:<24}",
                dev.device_id, name, status, last_seen
            );
        }
    }

    Ok(())
}

/// Revokes a device and its active sessions by device ID (ZK-075).
pub async fn cmd_device_revoke(
    custom_data_dir: Option<&Path>,
    device_id_str: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return Err(CliError::NotLoggedIn);
    }

    let target_device_id = Uuid::parse_str(device_id_str)
        .map_err(|e| CliError::Io(format!("invalid device UUID '{device_id_str}': {e}")))?;

    let session = load_auth_session(&auth_path)?;
    let resp = api_revoke_device(&session, target_device_id).await?;

    // If the revoked device was this device, clear local auth session too
    let was_current = target_device_id == session.device_id;
    if was_current {
        let _ = clear_auth_session(&auth_path);
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp)
                .map_err(|e| CliError::Io(format!("serialize revoke device response: {e}")))?
        );
    } else {
        println!("Device {} successfully revoked.", resp.device_id);
        if was_current {
            println!("Current device was revoked. Local session cleared.");
        }
    }

    Ok(())
}

/// Configures or displays the vault auto-lock idle timeout policy (ZK-076).
pub fn cmd_autolock(
    custom_data_dir: Option<&Path>,
    timeout_mins: Option<u64>,
    json_output: bool,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);

    if !sess_path.exists() {
        return Err(CliError::VaultLocked);
    }

    if let Some(mins) = timeout_mins {
        let secs = if mins == 0 { None } else { Some(mins * 60) };
        let info = update_session_timeout(&sess_path, secs)?;
        if json_output {
            let json = serde_json::to_string_pretty(&info)
                .map_err(|e| CliError::Io(format!("serialize autolock info: {e}")))?;
            println!("{json}");
        } else if mins == 0 {
            println!("Auto-lock disabled for active session (never expires).");
        } else {
            println!("Auto-lock idle timeout set to {mins} minute(s).");
        }
    } else {
        let info_opt = get_session_info(&sess_path)?;
        match info_opt {
            Some(info) => {
                if json_output {
                    let json = serde_json::to_string_pretty(&info)
                        .map_err(|e| CliError::Io(format!("serialize autolock info: {e}")))?;
                    println!("{json}");
                } else {
                    match info.idle_timeout_secs {
                        Some(timeout) => {
                            let timeout_mins = timeout / 60;
                            let rem_mins = info.remaining_secs.unwrap_or(0) / 60;
                            let rem_secs = info.remaining_secs.unwrap_or(0) % 60;
                            println!("Auto-lock: Active");
                            println!("Timeout:   {timeout_mins} minute(s) ({timeout}s)");
                            println!("Idle:      {}s", info.idle_secs);
                            println!("Remaining: {rem_mins}m {rem_secs}s");
                        }
                        None => {
                            println!("Auto-lock: Disabled (never expires)");
                        }
                    }
                }
            }
            None => return Err(CliError::VaultLocked),
        }
    }

    Ok(())
}

/// Attaches a file from disk to an existing note (ZK-083).
///
/// Chunks and encrypts the file locally with a fresh random `AttachmentKey`,
/// creates and encrypts an `AttachmentManifest` envelope (`OBJECT_KIND_ATTACHMENT_MANIFEST`),
/// updates the parent note's attachments list, and persists both in local storage.
pub fn cmd_attach(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    file_path: &Path,
    custom_name: Option<String>,
    custom_mime: Option<String>,
) -> Result<String, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    if !file_path.exists() || !file_path.is_file() {
        return Err(CliError::Io(format!(
            "attachment file '{}' does not exist or is not a regular file",
            file_path.display()
        )));
    }

    let vault_key = load_session_key(&sess_path)?;
    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, false)?;

    let mut note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    let attachment_id = uuid::Uuid::new_v4().to_string();
    let attachment_key = zk_crypto::keys::AttachmentKey::generate();

    // 1. Chunk and encrypt attachment file
    let (manifest, _chunks) = zk_core::attachment::encrypt_attachment_file(
        file_path,
        &attachment_id,
        &attachment_key,
        custom_name.as_deref(),
        custom_mime.as_deref(),
        None,
    )?;

    // 2. Encrypt attachment manifest envelope (OBJECT_KIND_ATTACHMENT_MANIFEST)
    let manifest_envelope =
        zk_core::attachment::encrypt_attachment_manifest(&manifest, &attachment_key, &vault_key)?;

    let now = now_utc_rfc3339();

    // 3. Persist manifest object in local encrypted storage
    let manifest_stored_obj = StoredEncryptedObject {
        object_id: attachment_id.clone(),
        object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
        revision: INITIAL_OBJECT_REVISION,
        server_seq: INITIAL_SERVER_SEQ,
        is_deleted: false,
        envelope: manifest_envelope.clone(),
        updated_at: now.clone(),
    };
    storage.put_object(&manifest_stored_obj)?;

    // Enqueue mutation for manifest
    let manifest_mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: attachment_id.clone(),
        expected_revision: INITIAL_EXPECTED_REVISION,
        object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
        mutation_type: MutationType::Upsert,
        envelope: manifest_envelope,
        created_at: now.clone(),
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&manifest_mutation)?;

    // 4. Update note's attachment list
    zk_core::attachment::add_attachment_to_note(&mut note, &attachment_id)?;

    let updated_note_envelope = note.encrypt(&vault_key, &stored.object_id)?;
    let new_revision = stored.revision + 1;

    let updated_note_obj = StoredEncryptedObject {
        object_id: stored.object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: new_revision,
        server_seq: stored.server_seq,
        is_deleted: false,
        envelope: updated_note_envelope.clone(),
        updated_at: now.clone(),
    };
    storage.put_object(&updated_note_obj)?;

    let note_mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: stored.object_id.clone(),
        expected_revision: stored.revision,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        envelope: updated_note_envelope,
        created_at: now,
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&note_mutation)?;

    println!("Attached file to note: {}", stored.object_id);
    println!("Attachment ID: {}", manifest.attachment_id);
    println!("Name:          {}", manifest.name);
    println!("Size:          {} bytes", manifest.size);
    println!("Chunks:        {}", manifest.chunk_count);
    if let Some(ref hash) = manifest.content_hash {
        println!("Hash:          {}", hash);
    }

    Ok(attachment_id)
}

/// Detaches an attachment from a note (ZK-083).
pub fn cmd_detach(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    attachment_id: &str,
) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let vault_key = load_session_key(&sess_path)?;
    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, false)?;

    let mut note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    let removed = zk_core::attachment::remove_attachment_from_note(&mut note, attachment_id);
    if !removed {
        return Err(CliError::Io(format!(
            "attachment '{attachment_id}' not found on note '{}'",
            stored.object_id
        )));
    }

    let now = now_utc_rfc3339();
    let updated_note_envelope = note.encrypt(&vault_key, &stored.object_id)?;
    let new_revision = stored.revision + 1;

    let updated_note_obj = StoredEncryptedObject {
        object_id: stored.object_id.clone(),
        object_kind: OBJECT_KIND_NOTE,
        revision: new_revision,
        server_seq: stored.server_seq,
        is_deleted: false,
        envelope: updated_note_envelope.clone(),
        updated_at: now.clone(),
    };
    storage.put_object(&updated_note_obj)?;

    let note_mutation = PendingMutation {
        mutation_id: uuid::Uuid::new_v4().to_string(),
        object_id: stored.object_id.clone(),
        expected_revision: stored.revision,
        object_kind: OBJECT_KIND_NOTE,
        mutation_type: MutationType::Upsert,
        envelope: updated_note_envelope,
        created_at: now.clone(),
        retry_count: 0,
        status: MutationStatus::Pending,
    };
    storage.enqueue_mutation(&note_mutation)?;

    // If attachment manifest is stored, create a tombstone for it
    if let Ok(Some(manifest_obj)) = storage.get_object(attachment_id) {
        let manifest_tombstone = StoredEncryptedObject {
            object_id: attachment_id.to_string(),
            object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
            revision: manifest_obj.revision + 1,
            server_seq: manifest_obj.server_seq,
            is_deleted: true,
            envelope: manifest_obj.envelope.clone(),
            updated_at: now.clone(),
        };
        storage.put_object(&manifest_tombstone)?;

        let tombstone_mutation = PendingMutation {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            object_id: attachment_id.to_string(),
            expected_revision: manifest_obj.revision,
            object_kind: OBJECT_KIND_ATTACHMENT_MANIFEST,
            mutation_type: MutationType::Delete,
            envelope: manifest_obj.envelope,
            created_at: now,
            retry_count: 0,
            status: MutationStatus::Pending,
        };
        storage.enqueue_mutation(&tombstone_mutation)?;
    }

    println!(
        "Detached attachment '{attachment_id}' from note '{}'.",
        stored.object_id
    );
    Ok(())
}

/// Lists attachments associated with a note (ZK-083).
pub fn cmd_attachments(
    custom_data_dir: Option<&Path>,
    note_id: &str,
    json_output: bool,
) -> Result<Vec<zk_protocol::attachment::AttachmentManifest>, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let db_path = db_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Err(CliError::VaultUninitialized);
    }

    let vault_key = load_session_key(&sess_path)?;
    let storage = SqliteStorage::open(&db_path)?;
    let stored = find_note_object(&storage, note_id, false)?;

    let note = PlaintextNote::decrypt(&stored.envelope, &vault_key)?;

    let mut manifests = Vec::new();
    for att_id in &note.attachments {
        if let Ok(Some(obj)) = storage.get_object(att_id) {
            if !obj.is_deleted {
                if let Ok((manifest, _key)) =
                    zk_core::attachment::decrypt_attachment_manifest(&obj.envelope, &vault_key)
                {
                    manifests.push(manifest);
                }
            }
        }
    }

    if json_output {
        let json = serde_json::to_string_pretty(&manifests)
            .map_err(|e| CliError::Io(format!("serialize manifests json: {e}")))?;
        println!("{json}");
    } else {
        println!("Attachments for note '{}':", stored.object_id);
        if manifests.is_empty() {
            println!("  (no attachments)");
        } else {
            for m in &manifests {
                println!("- ID:     {}", m.attachment_id);
                println!("  Name:   {}", m.name);
                println!("  Size:   {} bytes", m.size);
                println!("  Chunks: {}", m.chunk_count);
                println!("  MIME:   {}", m.mime);
            }
        }
    }

    Ok(manifests)
}
