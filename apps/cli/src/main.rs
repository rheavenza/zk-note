//! Terminal/CLI client for zero-knowledge notes (`zk-note`).

mod commands;
mod config;
mod error;
mod session;

use clap::{Parser, Subcommand};
use commands::{cmd_init, cmd_lock, cmd_status, cmd_unlock};
use error::CliError;
use std::path::PathBuf;

/// Zero-knowledge encrypted note client (`zk-note`).
#[derive(Parser, Debug)]
#[command(
    name = "zk-note",
    author = "Zero-Knowledge Notes Team",
    version = "0.1.0",
    about = "Zero-knowledge, offline-first note-taking CLI"
)]
pub struct Cli {
    /// Custom data directory (defaults to ~/.zk-notes or ZK_NOTE_DIR)
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new encrypted vault
    Init {
        /// Optional passphrase (for automated scripts or tests)
        #[arg(long)]
        passphrase: Option<String>,

        /// Fast KDF test parameters (for testing only)
        #[arg(long, hide = true)]
        test_kdf: bool,
    },
    /// Unlock the vault and begin an active session
    Unlock {
        /// Master passphrase
        #[arg(long)]
        passphrase: Option<String>,

        /// Unlock using formatted recovery key instead of passphrase
        #[arg(long)]
        recovery_key: Option<String>,
    },
    /// Lock the vault and clear active session
    Lock,
    /// Display vault status (UNINITIALIZED, LOCKED, or UNLOCKED)
    Status,
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.as_deref();

    match cli.command {
        Commands::Init {
            passphrase,
            test_kdf,
        } => cmd_init(data_dir, passphrase, test_kdf),
        Commands::Unlock {
            passphrase,
            recovery_key,
        } => cmd_unlock(data_dir, passphrase, recovery_key),
        Commands::Lock => cmd_lock(data_dir),
        Commands::Status => cmd_status(data_dir),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_test_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("zk_cli_test_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test dir");
        path
    }

    #[test]
    fn test_cli_vault_init_unlock_lock_lifecycle() {
        let test_dir = temp_test_dir("lifecycle");
        let dir_path = test_dir.as_path();
        let pass = "test-master-password-456".to_string();

        // 1. Initial status is UNINITIALIZED
        let v_file = config::vault_file(dir_path);
        assert!(!v_file.exists());

        // 2. Initialize vault
        cmd_init(Some(dir_path), Some(pass.clone()), true).expect("init vault");
        assert!(v_file.exists());
        assert!(config::db_file(dir_path).exists());
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // 3. Double init fails
        let err = cmd_init(Some(dir_path), Some(pass.clone()), true).unwrap_err();
        match err {
            CliError::VaultAlreadyInitialized => (),
            other => panic!("expected VaultAlreadyInitialized, got {other:?}"),
        }

        // 4. Lock vault
        cmd_lock(Some(dir_path)).expect("lock vault");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // 5. Unlock with wrong password fails closed
        let wrong_err =
            cmd_unlock(Some(dir_path), Some("wrong-password".to_string()), None).unwrap_err();
        match wrong_err {
            CliError::AuthenticationFailed => (),
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // 6. Unlock with correct password succeeds
        cmd_unlock(Some(dir_path), Some(pass), None).expect("unlock vault");
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // 7. Verify session key can be loaded and matches valid 32-byte key
        let key = session::load_session_key(&config::session_file(dir_path)).expect("load session");
        assert_eq!(key.as_bytes().len(), 32);

        // 8. Lock again
        cmd_lock(Some(dir_path)).expect("lock");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // Cleanup
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_cli_unlock_with_recovery_key() {
        let test_dir = temp_test_dir("recovery");
        let dir_path = test_dir.as_path();
        let pass = "password-to-recover".to_string();

        // Initialize vault via VaultManager directly to capture recovery key string
        let (bootstrap, recovery_str, _vault_key) = zk_core::vault::VaultManager::init_vault(
            pass.as_bytes(),
            &zk_crypto::kdf::KdfParams::new_test(),
        )
        .expect("init vault");

        let bootstrap_json = serde_json::to_string_pretty(&bootstrap).expect("serialize");
        fs::write(config::vault_file(dir_path), bootstrap_json).expect("write vault");
        let _ = zk_storage::SqliteStorage::open(config::db_file(dir_path)).expect("open db");

        // Verify initially locked
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        // Wrong recovery key fails
        let bad_rec_err = cmd_unlock(
            Some(dir_path),
            None,
            Some("1234-5678-90AB-CDEF-1234-5678-90AB-CDEF-1234".to_string()),
        )
        .unwrap_err();

        match bad_rec_err {
            CliError::InvalidRecoveryKey(_) => (),
            other => panic!("expected InvalidRecoveryKey, got {other:?}"),
        }

        // Correct recovery key succeeds
        cmd_unlock(Some(dir_path), None, Some(recovery_str)).expect("unlock with recovery key");
        assert!(session::has_active_session(&config::session_file(dir_path)));

        // Lock
        cmd_lock(Some(dir_path)).expect("lock");
        assert!(!session::has_active_session(&config::session_file(
            dir_path
        )));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_session_file_permissions_and_clearing() {
        let test_dir = temp_test_dir("permissions");
        let sess_path = test_dir.join(".session");
        let key = zk_crypto::keys::VaultKey::generate();

        session::save_session_key(&sess_path, &key).expect("save session");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&sess_path).expect("metadata");
            let mode = metadata.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "session file permissions must be exactly 0600"
            );
        }

        let loaded = session::load_session_key(&sess_path).expect("load session");
        assert_eq!(key, loaded);

        session::clear_session(&sess_path).expect("clear session");
        assert!(!sess_path.exists());
        assert!(session::load_session_key(&sess_path).is_err());

        let _ = fs::remove_dir_all(&test_dir);
    }
}
