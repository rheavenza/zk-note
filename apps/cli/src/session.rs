//! Session file persistence with restricted permissions, memory scrubbing, and auto-lock policy (ZK-076).

use crate::error::CliError;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zk_crypto::keys::{VaultKey, KEY_LEN};

/// Default idle timeout for CLI sessions: 15 minutes (900 seconds).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 15 * 60;

/// Resolves the default idle auto-lock timeout in seconds from the environment or default.
#[must_use]
pub fn resolve_default_timeout() -> Option<u64> {
    if let Ok(env_val) = std::env::var("ZK_AUTO_LOCK_MINUTES") {
        if let Ok(mins) = env_val.trim().parse::<u64>() {
            return if mins == 0 { None } else { Some(mins * 60) };
        }
    }
    Some(DEFAULT_IDLE_TIMEOUT_SECS)
}

/// Structured session container storing key material with idle auto-lock metadata (ZK-076).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionEnvelope {
    /// Raw symmetric Vault Key bytes.
    pub key: [u8; KEY_LEN],
    /// Unix timestamp in seconds when the session was created.
    pub created_at: u64,
    /// Unix timestamp in seconds when the session was last active.
    pub last_active_at: u64,
    /// Optional idle timeout in seconds (None or 0 disables auto-lock).
    pub idle_timeout_secs: Option<u64>,
}

/// Information about an active session file's auto-lock state (ZK-076).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub is_active: bool,
    pub is_expired: bool,
    pub idle_timeout_secs: Option<u64>,
    pub idle_secs: u64,
    pub remaining_secs: Option<u64>,
    pub created_at: u64,
    pub last_active_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_session_bytes(session_path: &Path, bytes: &[u8]) -> Result<(), CliError> {
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

    file.write_all(bytes).map_err(|e| {
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

/// Saves an active [`VaultKey`] with default idle timeout to the session file with strict `0600` permissions.
pub fn save_session_key(session_path: &Path, key: &VaultKey) -> Result<(), CliError> {
    save_session_key_with_timeout(session_path, key, resolve_default_timeout())
}

/// Saves an active [`VaultKey`] with a specific idle timeout in seconds (ZK-076).
pub fn save_session_key_with_timeout(
    session_path: &Path,
    key: &VaultKey,
    timeout_secs: Option<u64>,
) -> Result<(), CliError> {
    let now = now_secs();
    let envelope = SessionEnvelope {
        key: *key.as_bytes(),
        created_at: now,
        last_active_at: now,
        idle_timeout_secs: timeout_secs.filter(|&s| s > 0),
    };

    let json = serde_json::to_string(&envelope)
        .map_err(|e| CliError::Io(format!("failed to serialize session envelope: {e}")))?;

    write_session_bytes(session_path, json.as_bytes())
}

/// Loads and validates the active [`VaultKey`], checking for idle timeout and updating last active time.
pub fn load_session_key(session_path: &Path) -> Result<VaultKey, CliError> {
    load_session_key_and_touch(session_path, true)
}

/// Loads and validates the active [`VaultKey`], optionally touching the last active timestamp.
pub fn load_session_key_and_touch(session_path: &Path, touch: bool) -> Result<VaultKey, CliError> {
    if !session_path.exists() {
        return Err(CliError::VaultLocked);
    }

    let bytes = std::fs::read(session_path).map_err(|e| {
        CliError::Io(format!(
            "failed to read session file {}: {e}",
            session_path.display()
        ))
    })?;

    // Backward compatibility: raw 32-byte key
    if bytes.len() == KEY_LEN {
        return VaultKey::from_slice(&bytes).map_err(|e| CliError::CorruptedSession(e.to_string()));
    }

    let mut envelope: SessionEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid session envelope: {e}")))?;

    let now = now_secs();

    // Check if idle timeout has expired
    if let Some(timeout) = envelope.idle_timeout_secs {
        if timeout > 0 && now.saturating_sub(envelope.last_active_at) >= timeout {
            let _ = clear_session(session_path);
            return Err(CliError::VaultLocked);
        }
    }

    if touch {
        envelope.last_active_at = now;
        if let Ok(json) = serde_json::to_string(&envelope) {
            let _ = write_session_bytes(session_path, json.as_bytes());
        }
    }

    VaultKey::from_slice(&envelope.key).map_err(|e| CliError::CorruptedSession(e.to_string()))
}

/// Inspects the current session's auto-lock state without modifying it (ZK-076).
pub fn get_session_info(session_path: &Path) -> Result<Option<SessionInfo>, CliError> {
    if !session_path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(session_path)
        .map_err(|e| CliError::Io(format!("failed to read session file: {e}")))?;

    if bytes.len() == KEY_LEN {
        return Ok(Some(SessionInfo {
            is_active: true,
            is_expired: false,
            idle_timeout_secs: None,
            idle_secs: 0,
            remaining_secs: None,
            created_at: 0,
            last_active_at: 0,
        }));
    }

    let envelope: SessionEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid session envelope: {e}")))?;

    let now = now_secs();
    let idle_secs = now.saturating_sub(envelope.last_active_at);

    let (is_expired, remaining_secs) = match envelope.idle_timeout_secs {
        Some(timeout) if timeout > 0 => {
            let expired = idle_secs >= timeout;
            let rem = timeout.saturating_sub(idle_secs);
            (expired, Some(rem))
        }
        _ => (false, None),
    };

    Ok(Some(SessionInfo {
        is_active: !is_expired,
        is_expired,
        idle_timeout_secs: envelope.idle_timeout_secs,
        idle_secs,
        remaining_secs,
        created_at: envelope.created_at,
        last_active_at: envelope.last_active_at,
    }))
}

/// Updates the idle auto-lock timeout for an active session (ZK-076).
pub fn update_session_timeout(
    session_path: &Path,
    timeout_secs: Option<u64>,
) -> Result<SessionInfo, CliError> {
    if !session_path.exists() {
        return Err(CliError::VaultLocked);
    }

    let bytes = std::fs::read(session_path)
        .map_err(|e| CliError::Io(format!("failed to read session file: {e}")))?;

    let mut envelope = if bytes.len() == KEY_LEN {
        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(&bytes);
        let now = now_secs();
        SessionEnvelope {
            key: key_arr,
            created_at: now,
            last_active_at: now,
            idle_timeout_secs: None,
        }
    } else {
        serde_json::from_slice::<SessionEnvelope>(&bytes)
            .map_err(|e| CliError::CorruptedSession(format!("invalid session envelope: {e}")))?
    };

    envelope.idle_timeout_secs = timeout_secs.filter(|&s| s > 0);
    envelope.last_active_at = now_secs();

    let json = serde_json::to_string(&envelope)
        .map_err(|e| CliError::Io(format!("serialize session envelope: {e}")))?;
    write_session_bytes(session_path, json.as_bytes())?;

    get_session_info(session_path)?
        .ok_or_else(|| CliError::Io("failed to read updated session info".to_string()))
}

/// Refreshes the last active timestamp of an active session to now (ZK-076).
pub fn touch_session(session_path: &Path) -> Result<(), CliError> {
    load_session_key_and_touch(session_path, true).map(|_| ())
}

/// Returns `true` if a valid session file exists.
#[must_use]
pub fn has_active_session(session_path: &Path) -> bool {
    session_path.exists()
}

/// Overwrites the session file with zeroes across its entire length, flushes, and unlinks it (SEC-003, SEC-009).
pub fn clear_session(session_path: &Path) -> Result<(), CliError> {
    if session_path.exists() {
        if let Ok(metadata) = std::fs::metadata(session_path) {
            let len = metadata.len();
            if len > 0 {
                if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(session_path) {
                    let zeroes = vec![0u8; len as usize];
                    let _ = file.write_all(&zeroes);
                    let _ = file.flush();
                }
            }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_save_load_legacy_key_compatibility() {
        let temp_dir = std::env::temp_dir().join(format!("zk_sess_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let sess_path = temp_dir.join(".session");

        let key = VaultKey::generate();

        // Write raw 32 bytes (simulating legacy session)
        write_session_bytes(&sess_path, key.as_bytes()).unwrap();

        let loaded = load_session_key(&sess_path).unwrap();
        assert_eq!(loaded, key);

        let info = get_session_info(&sess_path).unwrap().unwrap();
        assert!(info.is_active);
        assert_eq!(info.idle_timeout_secs, None);

        clear_session(&sess_path).unwrap();
        assert!(!sess_path.exists());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_idle_timeout_auto_lock_expiration() {
        let temp_dir = std::env::temp_dir().join(format!("zk_sess_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let sess_path = temp_dir.join(".session");

        let key = VaultKey::generate();

        // Save session with 1 second timeout
        save_session_key_with_timeout(&sess_path, &key, Some(1)).unwrap();
        assert!(sess_path.exists());

        // Immediately load -> should succeed
        let loaded = load_session_key_and_touch(&sess_path, false).unwrap();
        assert_eq!(loaded, key);

        // Manually alter last_active_at in session envelope to simulate expiration
        let bytes = std::fs::read(&sess_path).unwrap();
        let mut envelope: SessionEnvelope = serde_json::from_slice(&bytes).unwrap();
        envelope.last_active_at -= 5;
        let json = serde_json::to_string(&envelope).unwrap();
        write_session_bytes(&sess_path, json.as_bytes()).unwrap();

        // Loading now must detect expiration, zeroize & delete file, and return VaultLocked
        let err = load_session_key(&sess_path).unwrap_err();
        match err {
            CliError::VaultLocked => (),
            other => panic!("expected VaultLocked on expired session, got {other:?}"),
        }

        // File must be deleted
        assert!(!sess_path.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_update_session_timeout() {
        let temp_dir = std::env::temp_dir().join(format!("zk_sess_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let sess_path = temp_dir.join(".session");

        let key = VaultKey::generate();
        save_session_key(&sess_path, &key).unwrap();

        let updated = update_session_timeout(&sess_path, Some(3600)).unwrap();
        assert_eq!(updated.idle_timeout_secs, Some(3600));

        let updated_none = update_session_timeout(&sess_path, Some(0)).unwrap();
        assert_eq!(updated_none.idle_timeout_secs, None);

        clear_session(&sess_path).unwrap();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
