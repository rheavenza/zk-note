//! Reusable vault lifecycle and session management services (ZK-101).

use crate::config::{resolve_data_dir, session_file, vault_file};
use crate::error::CliError;
use crate::session::{
    clear_session, get_session_info, has_active_session, load_session_key,
    load_session_key_and_touch, resolve_default_timeout, save_session_key_with_timeout,
    SessionInfo,
};
use std::path::Path;
use zk_core::vault::VaultManager;
use zk_crypto::keys::VaultKey;
use zk_protocol::vault::VaultBootstrap;

/// Current vault state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultState {
    /// Vault has not been initialized (`vault.json` missing).
    Uninitialized,
    /// Vault exists but is locked (no active valid session).
    Locked,
    /// Vault is unlocked with an active session.
    Unlocked {
        /// Auto-lock timeout and remaining time info.
        auto_lock_info: Option<SessionInfo>,
    },
}

/// Checks the current status of the vault on disk.
pub fn get_vault_status(custom_data_dir: Option<&Path>) -> Result<VaultState, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let vault_path = vault_file(&data_dir);
    let sess_path = session_file(&data_dir);

    if !vault_path.exists() {
        return Ok(VaultState::Uninitialized);
    }

    if !has_active_session(&sess_path) {
        return Ok(VaultState::Locked);
    }

    match get_session_info(&sess_path) {
        Ok(Some(info)) if info.is_active => Ok(VaultState::Unlocked {
            auto_lock_info: Some(info),
        }),
        Ok(Some(info)) if info.is_expired => {
            let _ = clear_session(&sess_path);
            Ok(VaultState::Locked)
        }
        _ => match load_session_key(&sess_path) {
            Ok(_) => Ok(VaultState::Unlocked {
                auto_lock_info: None,
            }),
            Err(_) => Ok(VaultState::Locked),
        },
    }
}

/// Unlocks the vault using the master passphrase.
///
/// Sets the active session file with appropriate auto-lock timeout and returns the [`VaultKey`].
pub fn unlock_vault(
    custom_data_dir: Option<&Path>,
    passphrase: &str,
    timeout_mins: Option<u64>,
) -> Result<VaultKey, CliError> {
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

    let vault_key = VaultManager::unlock_with_passphrase(&bootstrap, passphrase.as_bytes())?;

    let timeout_secs = match timeout_mins {
        Some(0) => None,
        Some(m) => Some(m * 60),
        None => resolve_default_timeout(),
    };

    save_session_key_with_timeout(&sess_path, &vault_key, timeout_secs)?;

    Ok(vault_key)
}

/// Unlocks the vault using a formatted 288-bit recovery key.
pub fn unlock_with_recovery_key(
    custom_data_dir: Option<&Path>,
    recovery_key: &str,
    timeout_mins: Option<u64>,
) -> Result<VaultKey, CliError> {
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

    let vault_key = VaultManager::unlock_with_recovery_key(&bootstrap, recovery_key.trim())?;

    let timeout_secs = match timeout_mins {
        Some(0) => None,
        Some(m) => Some(m * 60),
        None => resolve_default_timeout(),
    };

    save_session_key_with_timeout(&sess_path, &vault_key, timeout_secs)?;

    Ok(vault_key)
}

/// Locks the vault, clearing session files and zeroizing keys.
pub fn lock_vault(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);
    clear_session(&sess_path)
}

/// Retrieves the active [`VaultKey`], updating the last active timestamp.
pub fn get_active_vault_key(custom_data_dir: Option<&Path>) -> Result<VaultKey, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);
    load_session_key(&sess_path)
}

/// Checks whether the active session has expired without refreshing its `last_active_at` timestamp.
///
/// Returns `Ok(false)` if the session is still active and valid.
/// Returns `Ok(true)` if the session has expired due to idle timeout.
pub fn is_session_expired(custom_data_dir: Option<&Path>) -> Result<bool, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);
    if !sess_path.exists() {
        return Ok(true);
    }
    match load_session_key_and_touch(&sess_path, false) {
        Ok(_) => Ok(false),
        Err(CliError::VaultLocked) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Refreshes the last active timestamp for genuine user interactions through the shared session path.
pub fn touch_session_activity(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let sess_path = session_file(&data_dir);
    crate::session::touch_session(&sess_path)
}
