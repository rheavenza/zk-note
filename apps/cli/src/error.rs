//! Typed error handling for the CLI application.

use std::fmt;

/// Application errors for `zk-note` commands.
#[derive(Debug)]
pub enum CliError {
    /// Vault is locked and requires unlocking before proceeding.
    VaultLocked,
    /// Vault has not yet been initialized.
    VaultUninitialized,
    /// Vault is already initialized in this directory.
    VaultAlreadyInitialized,
    /// Passphrase confirmation did not match during initialization.
    PassphraseMismatch,
    /// Master passphrase was incorrect or envelope could not be decrypted.
    AuthenticationFailed,
    /// Recovery key was invalid or checksum failed.
    InvalidRecoveryKey(String),
    /// Active session file is corrupted.
    CorruptedSession(String),
    /// Underlying core domain error.
    Core(zk_core::error::CoreError),
    /// Underlying storage error.
    Storage(zk_storage::error::StorageError),
    /// File system or I/O error.
    Io(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VaultLocked => write!(f, "vault is locked; run 'zk-note unlock' first"),
            Self::VaultUninitialized => {
                write!(f, "vault is uninitialized; run 'zk-note init' first")
            }
            Self::VaultAlreadyInitialized => {
                write!(f, "vault is already initialized in this directory")
            }
            Self::PassphraseMismatch => write!(f, "passphrase confirmation does not match"),
            Self::AuthenticationFailed => {
                write!(
                    f,
                    "authentication failed: incorrect passphrase or corrupted vault"
                )
            }
            Self::InvalidRecoveryKey(msg) => write!(f, "invalid recovery key: {msg}"),
            Self::CorruptedSession(msg) => write!(f, "corrupted session: {msg}"),
            Self::Core(e) => write!(f, "{e}"),
            Self::Storage(e) => write!(f, "{e}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<zk_core::error::CoreError> for CliError {
    fn from(e: zk_core::error::CoreError) -> Self {
        match e {
            zk_core::error::CoreError::VaultLocked => Self::VaultLocked,
            zk_core::error::CoreError::VaultUninitialized => Self::VaultUninitialized,
            zk_core::error::CoreError::Crypto(zk_crypto::error::CryptoError::DecryptionFailed) => {
                Self::AuthenticationFailed
            }
            zk_core::error::CoreError::InvalidRecoveryKey(msg) => Self::InvalidRecoveryKey(msg),
            other => Self::Core(other),
        }
    }
}

impl From<zk_storage::error::StorageError> for CliError {
    fn from(e: zk_storage::error::StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
