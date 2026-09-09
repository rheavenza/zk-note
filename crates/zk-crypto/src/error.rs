//! Strongly-typed error definitions for cryptographic operations.

use core::fmt;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Provided key or buffer length was invalid.
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length provided.
        actual: usize,
    },
    /// Random number generation failed.
    RngFailure(String),
    /// Data encoding (e.g. Base64) was malformed.
    InvalidEncoding(String),
    /// Cryptographic algorithm or cipher suite is unsupported.
    UnsupportedAlgorithm(String),
    /// Key derivation function failed.
    KdfFailure(String),
    /// Decryption or authentication tag verification failed (fails closed).
    DecryptionFailed,
    /// AEAD encryption operation failed.
    AeadFailure(String),
    /// Checksum verification failed (e.g. in recovery key string).
    InvalidChecksum,
    /// Cryptographic envelope or parameter version is unsupported.
    UnsupportedVersion(u32),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {actual} bytes"
                )
            }
            Self::RngFailure(msg) => write!(f, "cryptographic RNG failure: {msg}"),
            Self::InvalidEncoding(msg) => write!(f, "invalid encoding: {msg}"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported cryptographic algorithm: {alg}")
            }
            Self::KdfFailure(msg) => write!(f, "key derivation failed: {msg}"),
            Self::DecryptionFailed => {
                write!(f, "cryptographic authentication or decryption failed")
            }
            Self::AeadFailure(msg) => write!(f, "AEAD operation failed: {msg}"),
            Self::InvalidChecksum => write!(f, "checksum verification failed (typo detected)"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported cryptographic envelope version: {v}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
