//! Typed error taxonomy for core note domain model and operations.

use std::fmt;

/// Validation errors for plaintext notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteValidationError {
    /// Schema version is unsupported.
    UnsupportedSchemaVersion(u32),
    /// Title exceeds maximum permitted length.
    TitleTooLong {
        /// Maximum allowed bytes.
        max: usize,
        /// Actual length encountered.
        actual: usize,
    },
    /// Body exceeds maximum permitted size.
    BodyTooLarge {
        /// Maximum allowed bytes.
        max: usize,
        /// Actual size encountered.
        actual: usize,
    },
    /// Note exceeds maximum allowed tag count.
    TooManyTags {
        /// Maximum allowed tag count.
        max: usize,
        /// Actual tag count encountered.
        actual: usize,
    },
    /// Tag is empty.
    EmptyTag,
    /// Tag exceeds maximum permitted length.
    TagTooLong {
        /// Maximum allowed bytes per tag.
        max: usize,
        /// Actual length encountered.
        actual: usize,
    },
    /// Tag contains forbidden control characters.
    InvalidTag(String),
    /// Note exceeds maximum allowed attachment count.
    TooManyAttachments {
        /// Maximum allowed attachment count.
        max: usize,
        /// Actual attachment count encountered.
        actual: usize,
    },
    /// Attachment identifier is empty.
    EmptyAttachmentId,
    /// Attachment identifier exceeds maximum permitted length.
    AttachmentIdTooLong {
        /// Maximum allowed bytes per identifier.
        max: usize,
        /// Actual length encountered.
        actual: usize,
    },
    /// Attachment identifier contains forbidden control characters.
    InvalidAttachmentId(String),
    /// Timestamp does not conform to RFC 3339.
    InvalidTimestamp {
        /// Timestamp field name (e.g. "created_at" or "updated_at").
        field: &'static str,
        /// Value that failed validation.
        value: String,
        /// Detailed failure reason.
        details: String,
    },
    /// JSON serialization or deserialization failure.
    SerializationError(String),
}

impl fmt::Display for NoteValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported note schema version: {v} (expected 1)")
            }
            Self::TitleTooLong { max, actual } => {
                write!(
                    f,
                    "note title exceeds maximum length ({actual} > {max} bytes)"
                )
            }
            Self::BodyTooLarge { max, actual } => {
                write!(f, "note body exceeds maximum size ({actual} > {max} bytes)")
            }
            Self::TooManyTags { max, actual } => {
                write!(f, "note contains too many tags ({actual} > {max})")
            }
            Self::EmptyTag => write!(f, "tag cannot be empty"),
            Self::TagTooLong { max, actual } => {
                write!(f, "tag exceeds maximum length ({actual} > {max} bytes)")
            }
            Self::InvalidTag(tag) => {
                write!(f, "tag contains invalid characters: {tag}")
            }
            Self::TooManyAttachments { max, actual } => {
                write!(f, "note contains too many attachments ({actual} > {max})")
            }
            Self::EmptyAttachmentId => write!(f, "attachment ID cannot be empty"),
            Self::AttachmentIdTooLong { max, actual } => {
                write!(
                    f,
                    "attachment ID exceeds maximum length ({actual} > {max} bytes)"
                )
            }
            Self::InvalidAttachmentId(id) => {
                write!(f, "attachment ID contains invalid characters: {id}")
            }
            Self::InvalidTimestamp {
                field,
                value,
                details,
            } => {
                write!(
                    f,
                    "invalid RFC 3339 timestamp for '{field}' ({value:?}): {details}"
                )
            }
            Self::SerializationError(msg) => write!(f, "note serialization error: {msg}"),
        }
    }
}

impl std::error::Error for NoteValidationError {}

/// Errors occurring during attachment chunking, streaming, or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentError {
    /// Attachment size exceeds maximum permitted size.
    FileTooLarge { max: u64, actual: u64 },
    /// Chunk arrived out of sequential order.
    ChunkOutOfOrder { expected: u32, actual: u32 },
    /// Total chunk count mismatch.
    ChunkCountMismatch { expected: u32, actual: u32 },
    /// Total decrypted byte count did not match expected manifest size.
    SizeMismatch { expected: u64, actual: u64 },
    /// Content hash mismatch.
    HashMismatch { expected: String, actual: String },
    /// Attachment ID mismatch between chunk and manifest.
    AttachmentIdMismatch { expected: String, actual: String },
    /// I/O error during attachment streaming.
    Io(String),
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooLarge { max, actual } => {
                write!(
                    f,
                    "attachment exceeds maximum size ({actual} > {max} bytes)"
                )
            }
            Self::ChunkOutOfOrder { expected, actual } => {
                write!(
                    f,
                    "attachment chunk out of order (expected chunk {expected}, got {actual})"
                )
            }
            Self::ChunkCountMismatch { expected, actual } => {
                write!(
                    f,
                    "attachment chunk count mismatch (expected {expected} chunks, got {actual})"
                )
            }
            Self::SizeMismatch { expected, actual } => {
                write!(f, "attachment size mismatch (expected {expected} bytes, decrypted {actual} bytes)")
            }
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "attachment content hash mismatch (expected {expected}, computed {actual})"
                )
            }
            Self::AttachmentIdMismatch { expected, actual } => {
                write!(
                    f,
                    "attachment ID mismatch (expected {expected}, got {actual})"
                )
            }
            Self::Io(msg) => write!(f, "attachment I/O failure: {msg}"),
        }
    }
}

impl std::error::Error for AttachmentError {}

/// Top-level error type for `zk-core` domain operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Note domain validation failure.
    Validation(NoteValidationError),
    /// Underlying cryptographic failure.
    Crypto(zk_crypto::error::CryptoError),
    /// Attachment streaming or verification failure.
    Attachment(AttachmentError),
    /// Operation rejected because the vault is currently locked.
    VaultLocked,
    /// Operation rejected because the vault has not been initialized.
    VaultUninitialized,
    /// Provided recovery key string is malformed or has invalid checksum.
    InvalidRecoveryKey(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "note validation error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Attachment(e) => write!(f, "attachment error: {e}"),
            Self::VaultLocked => write!(f, "vault is locked (unlock required)"),
            Self::VaultUninitialized => write!(f, "vault is uninitialized (init required)"),
            Self::InvalidRecoveryKey(msg) => write!(f, "invalid recovery key: {msg}"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Attachment(e) => Some(e),
            Self::VaultLocked | Self::VaultUninitialized | Self::InvalidRecoveryKey(_) => None,
        }
    }
}

impl From<NoteValidationError> for CoreError {
    fn from(e: NoteValidationError) -> Self {
        Self::Validation(e)
    }
}

impl From<zk_crypto::error::CryptoError> for CoreError {
    fn from(e: zk_crypto::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<AttachmentError> for CoreError {
    fn from(e: AttachmentError) -> Self {
        Self::Attachment(e)
    }
}
