//! File paths and environment configuration for `zk-note`.

use std::path::{Path, PathBuf};

/// Resolves the base data directory for notes, vault metadata, and sessions.
///
/// Precedence:
/// 1. Explicit CLI argument (`--data-dir`)
/// 2. Environment variable `ZK_NOTE_DIR`
/// 3. Default: `~/.zk-notes`
#[must_use]
pub fn resolve_data_dir(custom: Option<&Path>) -> PathBuf {
    if let Some(p) = custom {
        p.to_path_buf()
    } else if let Ok(env_dir) = std::env::var("ZK_NOTE_DIR") {
        PathBuf::from(env_dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".zk-notes")
    }
}

/// Returns the path to the vault bootstrap JSON file.
#[must_use]
pub fn vault_file(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.json")
}

/// Returns the path to the local SQLite database.
#[must_use]
pub fn db_file(data_dir: &Path) -> PathBuf {
    data_dir.join("notes.db")
}

/// Returns the path to the active session file.
#[must_use]
pub fn session_file(data_dir: &Path) -> PathBuf {
    data_dir.join(".session")
}

/// Returns the path to the stored auth session file (ZK-072).
#[must_use]
pub fn auth_session_file(data_dir: &Path) -> PathBuf {
    data_dir.join(".auth_session")
}

/// Returns the path to the local device identity file (ZK-072).
#[must_use]
pub fn device_file(data_dir: &Path) -> PathBuf {
    data_dir.join("device.json")
}
