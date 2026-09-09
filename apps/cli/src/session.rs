//! Session file persistence with restricted permissions and memory scrubbing.

use crate::error::CliError;
use std::io::Write;
use std::path::Path;
use zk_crypto::keys::{VaultKey, KEY_LEN};

/// Saves an active [`VaultKey`] to the specified session file with strict `0600` permissions.
pub fn save_session_key(session_path: &Path, key: &VaultKey) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(session_path).map_err(|e| {
        CliError::Io(format!(
            "failed to create session file {}: {e}",
            session_path.display()
        ))
    })?;

    file.write_all(key.as_bytes()).map_err(|e| {
        CliError::Io(format!(
            "failed to write session file {}: {e}",
            session_path.display()
        ))
    })?;

    file.flush().map_err(|e| {
        CliError::Io(format!(
            "failed to flush session file {}: {e}",
            session_path.display()
        ))
    })?;

    Ok(())
}

/// Loads and validates the active [`VaultKey`] from the session file.
pub fn load_session_key(session_path: &Path) -> Result<VaultKey, CliError> {
    if !session_path.exists() {
        return Err(CliError::VaultLocked);
    }

    let bytes = std::fs::read(session_path).map_err(|e| {
        CliError::Io(format!(
            "failed to read session file {}: {e}",
            session_path.display()
        ))
    })?;

    if bytes.len() != KEY_LEN {
        return Err(CliError::CorruptedSession(format!(
            "expected {KEY_LEN} bytes, found {}",
            bytes.len()
        )));
    }

    VaultKey::from_slice(&bytes).map_err(|e| CliError::CorruptedSession(e.to_string()))
}

/// Returns `true` if a valid session file exists.
#[must_use]
pub fn has_active_session(session_path: &Path) -> bool {
    session_path.exists()
}

/// Overwrites the session file with zeroes, flushes it, and deletes it from disk.
pub fn clear_session(session_path: &Path) -> Result<(), CliError> {
    if session_path.exists() {
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(session_path) {
            let zeroes = [0u8; KEY_LEN];
            let _ = file.write_all(&zeroes);
            let _ = file.flush();
        }

        std::fs::remove_file(session_path).map_err(|e| {
            CliError::Io(format!(
                "failed to remove session file {}: {e}",
                session_path.display()
            ))
        })?;
    }
    Ok(())
}
