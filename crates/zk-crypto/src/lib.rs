//! Cryptographic primitives, key derivation (Argon2id), key wrapping,
//! and envelope encryption (XChaCha20-Poly1305) for zero-knowledge notes.

pub mod error;
pub mod keys;

pub use error::CryptoError;
pub use keys::{KeyEncryptionKey, ObjectKey, RecoveryKey, VaultKey, KEY_LEN};
pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-crypto"
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;

    #[test]
    fn test_crypto_init() {
        assert_eq!(crate_name(), "zk-crypto");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }

    #[test]
    fn test_invalid_key_lengths_rejected() {
        let invalid_lengths = [0, 1, 16, 31, 33, 48, 64, 128];

        for &len in &invalid_lengths {
            let buffer = vec![0xabu8; len];

            assert_eq!(
                VaultKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                ObjectKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                RecoveryKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                KeyEncryptionKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );
        }
    }

    #[test]
    fn test_valid_key_construction() {
        let bytes = [0x42u8; KEY_LEN];

        let vk = VaultKey::from_bytes(bytes);
        assert_eq!(vk.as_bytes(), &bytes);
        assert_eq!(vk.to_bytes(), bytes);
        assert_eq!(vk.as_ref(), &bytes);

        let vk_slice = VaultKey::from_slice(&bytes).expect("valid slice");
        assert_eq!(vk, vk_slice);
    }

    #[test]
    fn test_debug_formatting_redacts_secrets() {
        let raw = [0x5au8; KEY_LEN];

        let vk = VaultKey::from_bytes(raw);
        let ok = ObjectKey::from_bytes(raw);
        let rk = RecoveryKey::from_bytes(raw);
        let kek = KeyEncryptionKey::from_bytes(raw);

        let vk_debug = format!("{vk:?}");
        let ok_debug = format!("{ok:?}");
        let rk_debug = format!("{rk:?}");
        let kek_debug = format!("{kek:?}");

        assert_eq!(vk_debug, "VaultKey([REDACTED])");
        assert_eq!(ok_debug, "ObjectKey([REDACTED])");
        assert_eq!(rk_debug, "RecoveryKey([REDACTED])");
        assert_eq!(kek_debug, "KeyEncryptionKey([REDACTED])");

        // Verify secret byte pattern 0x5a is not revealed in debug strings
        assert!(!vk_debug.contains("90"));
        assert!(!vk_debug.contains("5a"));
    }

    #[test]
    fn test_os_csprng_random_generation() {
        let vk1 = VaultKey::generate();
        let vk2 = VaultKey::generate();

        // Must not be identical (CSPRNG generated independent keys)
        assert_ne!(vk1, vk2);
        // Must not be all zeros
        assert_ne!(vk1.as_bytes(), &[0u8; KEY_LEN]);
        assert_ne!(vk2.as_bytes(), &[0u8; KEY_LEN]);

        let ok1 = ObjectKey::generate();
        let ok2 = ObjectKey::generate();
        assert_ne!(ok1, ok2);

        let rk1 = RecoveryKey::generate();
        let rk2 = RecoveryKey::generate();
        assert_ne!(rk1, rk2);

        let kek1 = KeyEncryptionKey::generate();
        let kek2 = KeyEncryptionKey::generate();
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn test_constant_time_equality() {
        let bytes_a = [0x11u8; KEY_LEN];
        let bytes_b = [0x22u8; KEY_LEN];

        let vk_a1 = VaultKey::from_bytes(bytes_a);
        let vk_a2 = VaultKey::from_bytes(bytes_a);
        let vk_b = VaultKey::from_bytes(bytes_b);

        assert!(bool::from(vk_a1.ct_eq(&vk_a2)));
        assert!(!bool::from(vk_a1.ct_eq(&vk_b)));
        assert_eq!(vk_a1, vk_a2);
        assert_ne!(vk_a1, vk_b);
    }

    #[test]
    fn test_zeroize_clears_memory() {
        let mut key = VaultKey::from_bytes([0xffu8; KEY_LEN]);
        assert_eq!(key.as_bytes(), &[0xffu8; KEY_LEN]);

        key.zeroize();
        assert_eq!(key.as_bytes(), &[0x00u8; KEY_LEN]);
    }
}
