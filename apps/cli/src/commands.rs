//! Command execution implementations for `zk-note init`, `unlock`, `lock`, and `status`.

use crate::config::{db_file, resolve_data_dir, session_file, vault_file};
use crate::error::CliError;
use crate::session::{clear_session, has_active_session, load_session_key, save_session_key};
use std::path::Path;
use zk_core::vault::VaultManager;
use zk_crypto::kdf::KdfParams;
use zk_protocol::vault::VaultBootstrap;
use zk_storage::SqliteStorage;

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
