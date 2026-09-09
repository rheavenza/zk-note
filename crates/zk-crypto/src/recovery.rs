//! Recovery key encoding, checksumming, and typo-detection.
//!
//! Provides a human-readable, typo-detecting string representation for the 256-bit [`RecoveryKey`].
//! The representation appends a 4-byte cryptographic BLAKE2b checksum to the 32-byte key
//! (36 bytes total = 72 hex digits), presented in grouped, hyphen-separated blocks.
//! Typos are detected in constant time before any cryptographic operations occur.

use crate::error::CryptoError;
use crate::keys::{RecoveryKey, KEY_LEN};
use blake2::digest::Digest;
use blake2::Blake2b512;
use subtle::ConstantTimeEq;

/// Checksum length in bytes (32 bits).
pub const CHECKSUM_LEN: usize = 4;

/// Total payload length with checksum (32-byte key + 4-byte checksum).
pub const FORMATTED_RAW_LEN: usize = KEY_LEN + CHECKSUM_LEN;

/// Formats a [`RecoveryKey`] into a typo-detecting, hyphenated hexadecimal string.
///
/// Output format: `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`
/// (9 groups of 8 hex chars, separated by 8 hyphens, 80 characters total).
#[must_use]
pub fn format_recovery_key(recovery_key: &RecoveryKey) -> String {
    let key_bytes = recovery_key.as_bytes();
    let checksum = compute_checksum(key_bytes);

    let mut combined = [0u8; FORMATTED_RAW_LEN];
    combined[..KEY_LEN].copy_from_slice(key_bytes);
    combined[KEY_LEN..].copy_from_slice(&checksum);

    let hex_chars: Vec<String> = combined
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
        })
        .collect();

    hex_chars.join("-")
}

/// Parses a formatted recovery key string, verifying its 4-byte checksum.
///
/// Strips hyphens and whitespace, is case-insensitive, and returns
/// [`CryptoError::InvalidChecksum`] if a typo is detected.
pub fn parse_recovery_key(input: &str) -> Result<RecoveryKey, CryptoError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    if cleaned.len() != FORMATTED_RAW_LEN * 2 {
        return Err(CryptoError::InvalidKeyLength {
            expected: FORMATTED_RAW_LEN * 2,
            actual: cleaned.len(),
        });
    }

    let mut raw_bytes = [0u8; FORMATTED_RAW_LEN];
    for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk)
            .map_err(|e| CryptoError::InvalidEncoding(format!("invalid utf8: {e}")))?;
        raw_bytes[i] = u8::from_str_radix(hex_str, 16)
            .map_err(|e| CryptoError::InvalidEncoding(format!("invalid hex digit: {e}")))?;
    }

    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&raw_bytes[..KEY_LEN]);

    let mut expected_checksum = [0u8; CHECKSUM_LEN];
    expected_checksum.copy_from_slice(&raw_bytes[KEY_LEN..]);

    let computed_checksum = compute_checksum(&key_bytes);

    if bool::from(expected_checksum.ct_eq(&computed_checksum)) {
        Ok(RecoveryKey::from_bytes(key_bytes))
    } else {
        Err(CryptoError::InvalidChecksum)
    }
}

fn compute_checksum(key: &[u8; KEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"zk-notes-recovery-checksum-v1");
    hasher.update(key);
    let result = hasher.finalize();
    let mut checksum = [0u8; CHECKSUM_LEN];
    checksum.copy_from_slice(&result[..CHECKSUM_LEN]);
    checksum
}
