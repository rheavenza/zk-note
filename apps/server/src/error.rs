//! Server error definitions.

use std::fmt;

/// Top-level error type for server configuration and execution.
#[derive(Debug)]
pub enum ServerError {
    /// Configuration loading or parsing error.
    Config(ConfigError),
    /// Server network bind or IO failure.
    Io(std::io::Error),
    /// Database operation or migration failure.
    Db(DbError),
    /// Tracing subscriber initialization failure.
    Logging(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "configuration error: {e}"),
            Self::Io(e) => write!(f, "server IO error: {e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Logging(e) => write!(f, "logging initialization error: {e}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Db(e) => Some(e),
            Self::Logging(_) => None,
        }
    }
}

impl From<ConfigError> for ServerError {
    fn from(err: ConfigError) -> Self {
        Self::Config(err)
    }
}

impl From<DbError> for ServerError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Errors occurring during database operations and migrations.
#[derive(Debug)]
pub enum DbError {
    /// SQLite query or connection failure.
    Sqlite(rusqlite::Error),
    /// Migration execution failure.
    MigrationFailed {
        /// Version that failed.
        version: u32,
        /// Failure message.
        message: String,
    },
    /// Schema verification failed.
    SchemaVerificationFailed(String),
    /// A vault already exists for the given account.
    VaultAlreadyExists(uuid::Uuid),
    /// JSON serialization or deserialization failure.
    Serialization(serde_json::Error),
    /// Base64 decoding failure.
    InvalidBase64(String),
    /// Invalid UUID string.
    InvalidUuid(String),
    /// WebAuthn challenge not found or already consumed.
    ChallengeNotFound,
    /// WebAuthn challenge expired.
    ChallengeExpired,
    /// WebAuthn credential not found.
    CredentialNotFound,
    /// WebAuthn credential already registered.
    CredentialAlreadyExists,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "database failure: {e}"),
            Self::MigrationFailed { version, message } => {
                write!(f, "migration {version} failed: {message}")
            }
            Self::SchemaVerificationFailed(msg) => {
                write!(f, "schema verification failed: {msg}")
            }
            Self::VaultAlreadyExists(id) => {
                write!(f, "vault already exists for account '{id}'")
            }
            Self::Serialization(e) => write!(f, "serialization failure: {e}"),
            Self::InvalidBase64(msg) => write!(f, "invalid base64 encoding: {msg}"),
            Self::InvalidUuid(msg) => write!(f, "invalid UUID format: {msg}"),
            Self::ChallengeNotFound => write!(f, "webauthn challenge not found or already used"),
            Self::ChallengeExpired => write!(f, "webauthn challenge has expired"),
            Self::CredentialNotFound => write!(f, "webauthn credential not found"),
            Self::CredentialAlreadyExists => write!(f, "webauthn credential already registered"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::MigrationFailed { .. }
            | Self::SchemaVerificationFailed(_)
            | Self::VaultAlreadyExists(_)
            | Self::InvalidBase64(_)
            | Self::InvalidUuid(_)
            | Self::ChallengeNotFound
            | Self::ChallengeExpired
            | Self::CredentialNotFound
            | Self::CredentialAlreadyExists => None,
        }
    }
}

impl From<rusqlite::Error> for DbError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

/// Errors occurring during server configuration loading and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Port number is invalid (e.g., 0 or cannot be parsed).
    InvalidPort(String),
    /// Host address string is invalid.
    InvalidHost(String),
    /// Socket address cannot be resolved or parsed.
    InvalidSocketAddr(String),
    /// Unsupported or invalid log format string.
    InvalidLogFormat(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort(msg) => write!(f, "invalid port configuration: {msg}"),
            Self::InvalidHost(msg) => write!(f, "invalid host configuration: {msg}"),
            Self::InvalidSocketAddr(msg) => write!(f, "invalid socket address: {msg}"),
            Self::InvalidLogFormat(msg) => write!(f, "invalid log format: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}
