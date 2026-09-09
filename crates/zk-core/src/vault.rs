//! Vault lifecycle management: initialization, unlocking with passphrase or recovery key,
//! and in-memory session tracking.

use crate::error::CoreError;
use zk_crypto::kdf::{derive_kek, KdfParams};
use zk_crypto::keys::{RecoveryKey, VaultKey};
use zk_crypto::recovery::{format_recovery_key, parse_recovery_key};
use zk_crypto::vault::{
    unwrap_vault_key, unwrap_vault_key_recovery, wrap_vault_key, wrap_vault_key_recovery,
};
use zk_protocol::constants::PROTOCOL_VERSION_V1;
use zk_protocol::vault::VaultBootstrap;

/// High-level vault lifecycle coordinator.
#[derive(Debug)]
pub struct VaultManager;

impl VaultManager {
    /// Initializes a new zero-knowledge vault:
    /// 1. Derives KEK from the user's master passphrase and KDF parameters.
    /// 2. Generates a fresh random 256-bit [`VaultKey`].
    /// 3. Wraps the [`VaultKey`] with the KEK using XChaCha20-Poly1305.
    /// 4. Generates a fresh random 256-bit [`RecoveryKey`].
    /// 5. Independently wraps the [`VaultKey`] with the [`RecoveryKey`].
    /// 6. Formats the [`RecoveryKey`] into a checksummed, hyphenated string.
    /// 7. Assembles and returns the [`VaultBootstrap`] metadata, formatted recovery string, and [`VaultKey`].
    pub fn init_vault(
        passphrase: &[u8],
        kdf_params: &KdfParams,
    ) -> Result<(VaultBootstrap, String, VaultKey), CoreError> {
        let kek = derive_kek(passphrase, kdf_params)?;
        let vault_key = VaultKey::generate();
        let recovery_key = RecoveryKey::generate();

        let wrapped_key = wrap_vault_key(&vault_key, &kek)?;
        let recovery_wrapped_key = wrap_vault_key_recovery(&vault_key, &recovery_key)?;

        let formatted_recovery = format_recovery_key(&recovery_key);

        let bootstrap = VaultBootstrap {
            crypto_version: PROTOCOL_VERSION_V1,
            kdf: kdf_params.clone().into(),
            wrapped_vault_key: wrapped_key.into(),
            recovery_wrapped_vault_key: recovery_wrapped_key.into(),
        };

        Ok((bootstrap, formatted_recovery, vault_key))
    }

    /// Unlocks the vault using the user's master passphrase.
    ///
    /// Re-derives the KEK from the stored KDF parameters and unwraps the [`VaultKey`].
    pub fn unlock_with_passphrase(
        bootstrap: &VaultBootstrap,
        passphrase: &[u8],
    ) -> Result<VaultKey, CoreError> {
        let kdf_params: KdfParams = bootstrap.kdf.clone().into();
        let kek = derive_kek(passphrase, &kdf_params)?;
        let wrapped: zk_crypto::vault::WrappedVaultKey = bootstrap.wrapped_vault_key.clone().into();
        let vault_key = unwrap_vault_key(&wrapped, &kek)?;
        Ok(vault_key)
    }

    /// Unlocks the vault using a formatted recovery key string.
    ///
    /// Verifies the embedded BLAKE2b checksum in constant time, parses the [`RecoveryKey`],
    /// and restores the [`VaultKey`].
    pub fn unlock_with_recovery_key(
        bootstrap: &VaultBootstrap,
        recovery_key_str: &str,
    ) -> Result<VaultKey, CoreError> {
        let recovery_key = parse_recovery_key(recovery_key_str)
            .map_err(|e| CoreError::InvalidRecoveryKey(e.to_string()))?;

        let wrapped: zk_crypto::vault::WrappedVaultKey =
            bootstrap.recovery_wrapped_vault_key.clone().into();
        let vault_key = unwrap_vault_key_recovery(&wrapped, &recovery_key)?;
        Ok(vault_key)
    }
}

/// In-memory vault session tracking the active, unlocked [`VaultKey`].
///
/// When dropped or explicitly locked, the active key is removed and its memory scrubbed.
#[derive(Default, Debug)]
pub struct VaultSession {
    active_key: Option<VaultKey>,
}

impl VaultSession {
    /// Creates an empty (locked) session.
    #[must_use]
    pub fn new() -> Self {
        Self { active_key: None }
    }

    /// Creates an unlocked session with the provided [`VaultKey`].
    #[must_use]
    pub fn from_key(key: VaultKey) -> Self {
        Self {
            active_key: Some(key),
        }
    }

    /// Unlocks the session with the provided [`VaultKey`].
    pub fn unlock(&mut self, key: VaultKey) {
        self.active_key = Some(key);
    }

    /// Locks the session and zeroes the active [`VaultKey`] from memory.
    pub fn lock(&mut self) {
        self.active_key = None;
    }

    /// Returns `true` if the session is currently unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.active_key.is_some()
    }

    /// Returns a reference to the active [`VaultKey`] if unlocked, or [`CoreError::VaultLocked`].
    pub fn active_key(&self) -> Result<&VaultKey, CoreError> {
        self.active_key.as_ref().ok_or(CoreError::VaultLocked)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_init_and_unlock_with_passphrase() {
        let passphrase = b"secure-passphrase-123";
        let kdf_params = KdfParams::new_test();

        let (bootstrap, recovery_str, vault_key) =
            VaultManager::init_vault(passphrase, &kdf_params).expect("init vault");

        assert_eq!(bootstrap.crypto_version, PROTOCOL_VERSION_V1);
        assert!(!recovery_str.is_empty());

        // Unlock with correct passphrase
        let unlocked = VaultManager::unlock_with_passphrase(&bootstrap, passphrase)
            .expect("unlock passphrase");
        assert_eq!(vault_key, unlocked);

        // Unlock with wrong passphrase fails closed
        let wrong_pass = b"wrong-passphrase";
        let err = VaultManager::unlock_with_passphrase(&bootstrap, wrong_pass).unwrap_err();
        match err {
            CoreError::Crypto(zk_crypto::error::CryptoError::DecryptionFailed) => (),
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_vault_unlock_with_recovery_key() {
        let passphrase = b"primary-passphrase";
        let kdf_params = KdfParams::new_test();

        let (bootstrap, recovery_str, vault_key) =
            VaultManager::init_vault(passphrase, &kdf_params).expect("init vault");

        // Unlock with recovery key
        let restored = VaultManager::unlock_with_recovery_key(&bootstrap, &recovery_str)
            .expect("unlock recovery");
        assert_eq!(vault_key, restored);

        // Tampered recovery key fails checksum
        let mut tampered_recovery = recovery_str.into_bytes();
        tampered_recovery[0] = if tampered_recovery[0] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered_str = String::from_utf8(tampered_recovery).expect("utf8");

        let err = VaultManager::unlock_with_recovery_key(&bootstrap, &tampered_str).unwrap_err();
        match err {
            CoreError::InvalidRecoveryKey(_) => (),
            other => panic!("expected InvalidRecoveryKey, got {other:?}"),
        }
    }

    #[test]
    fn test_vault_session_locking() {
        let key = VaultKey::generate();
        let mut session = VaultSession::new();

        assert!(!session.is_unlocked());
        assert_eq!(session.active_key().unwrap_err(), CoreError::VaultLocked);

        session.unlock(key.clone());
        assert!(session.is_unlocked());
        assert_eq!(session.active_key().expect("active"), &key);

        session.lock();
        assert!(!session.is_unlocked());
        assert_eq!(session.active_key().unwrap_err(), CoreError::VaultLocked);
    }
}
