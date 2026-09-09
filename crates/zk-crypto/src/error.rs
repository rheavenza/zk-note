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
        }
    }
}

impl std::error::Error for CryptoError {}
