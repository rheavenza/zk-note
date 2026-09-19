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

    /// Sets a new master passphrase for the vault using the existing [`VaultKey`] (ZK-073, ZK-074).
    ///
    /// Preserves the exact same [`VaultKey`] and existing recovery wrapping,
    /// generating a fresh salt, fresh nonce, and new wrapped vault key envelope.
    pub fn set_new_passphrase(
        bootstrap: &VaultBootstrap,
        vault_key: &VaultKey,
        new_passphrase: &[u8],
        new_kdf_params: &KdfParams,
    ) -> Result<VaultBootstrap, CoreError> {
        let new_kek = derive_kek(new_passphrase, new_kdf_params)?;
        let new_wrapped = wrap_vault_key(vault_key, &new_kek)?;

        let mut updated = bootstrap.clone();
        updated.kdf = new_kdf_params.clone().into();
        updated.wrapped_vault_key = new_wrapped.into();
        Ok(updated)
    }
}

use crate::search::InMemorySearchIndex;

/// In-memory vault session tracking the active, unlocked [`VaultKey`] and volatile search index.
///
/// When dropped or explicitly locked, the active key is removed and its memory scrubbed,
/// and any decrypted in-memory search index is wiped.
#[derive(Default, Debug)]
pub struct VaultSession {
    active_key: Option<VaultKey>,
    search_index: Option<InMemorySearchIndex>,
    last_active_secs: u64,
    idle_timeout_secs: Option<u64>,
}

impl VaultSession {
    /// Creates an empty (locked) session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_key: None,
            search_index: None,
            last_active_secs: crate::time::now_epoch_secs(),
            idle_timeout_secs: None,
        }
    }

    /// Creates an unlocked session with the provided [`VaultKey`].
    #[must_use]
    pub fn from_key(key: VaultKey) -> Self {
        Self {
            active_key: Some(key),
            search_index: Some(InMemorySearchIndex::new()),
            last_active_secs: crate::time::now_epoch_secs(),
            idle_timeout_secs: None,
        }
    }

    /// Creates an unlocked session with a specific idle timeout in seconds (ZK-076).
    #[must_use]
    pub fn with_idle_timeout(key: VaultKey, timeout_secs: Option<u64>) -> Self {
        Self {
            active_key: Some(key),
            search_index: Some(InMemorySearchIndex::new()),
            last_active_secs: crate::time::now_epoch_secs(),
            idle_timeout_secs: timeout_secs.filter(|&s| s > 0),
        }
    }

    /// Sets or updates the idle timeout in seconds (None or Some(0) disables auto-lock).
    pub fn set_idle_timeout(&mut self, timeout_secs: Option<u64>) {
        self.idle_timeout_secs = timeout_secs.filter(|&s| s > 0);
    }

    /// Returns the configured idle timeout in seconds.
    #[must_use]
    pub fn idle_timeout(&self) -> Option<u64> {
        self.idle_timeout_secs
    }

    /// Returns the Unix epoch timestamp in seconds of last recorded activity.
    #[must_use]
    pub fn last_active_secs(&self) -> u64 {
        self.last_active_secs
    }

    /// Updates the last active timestamp to the current time.
    pub fn touch(&mut self) {
        self.last_active_secs = crate::time::now_epoch_secs();
    }

    /// Checks if the session has timed out due to inactivity (ZK-076).
    ///
    /// If the idle timeout has elapsed, immediately locks the session, zeroizes key material,
    /// clears decrypted search index, and returns `true`. Returns `false` otherwise.
    pub fn check_idle_timeout(&mut self) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        if let Some(timeout) = self.idle_timeout_secs {
            let now = crate::time::now_epoch_secs();
            if now.saturating_sub(self.last_active_secs) >= timeout {
                self.lock();
                return true;
            }
        }
        false
    }

    /// Unlocks the session with the provided [`VaultKey`].
    pub fn unlock(&mut self, key: VaultKey) {
        self.active_key = Some(key);
        self.search_index = Some(InMemorySearchIndex::new());
        self.last_active_secs = crate::time::now_epoch_secs();
    }

    /// Locks the session and zeroes the active [`VaultKey`] and volatile search index from memory.
    pub fn lock(&mut self) {
        self.active_key = None;
        if let Some(mut idx) = self.search_index.take() {
            idx.clear();
        }
    }

    /// Returns `true` if the session is currently unlocked and not expired.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.active_key.is_some()
    }

    /// Returns a reference to the active [`VaultKey`] if unlocked, or [`CoreError::VaultLocked`].
    pub fn active_key(&self) -> Result<&VaultKey, CoreError> {
        self.active_key.as_ref().ok_or(CoreError::VaultLocked)
    }

    /// Returns a reference to the active in-memory search index if unlocked, or [`CoreError::VaultLocked`].
    pub fn search_index(&self) -> Result<&InMemorySearchIndex, CoreError> {
        self.search_index.as_ref().ok_or(CoreError::VaultLocked)
    }

    /// Returns a mutable reference to the active in-memory search index if unlocked, or [`CoreError::VaultLocked`].
    pub fn search_index_mut(&mut self) -> Result<&mut InMemorySearchIndex, CoreError> {
        self.search_index.as_mut().ok_or(CoreError::VaultLocked)
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
        assert_eq!(session.search_index().unwrap_err(), CoreError::VaultLocked);

        session.unlock(key.clone());
        assert!(session.is_unlocked());
        assert_eq!(session.active_key().expect("active"), &key);
        assert!(session.search_index().expect("index").is_empty());

        session.search_index_mut().expect("index_mut").insert_raw(
            "n1".to_string(),
            "Title".to_string(),
            vec![],
            "Body".to_string(),
            "2026-09-09T00:00:00Z".to_string(),
        );
        assert_eq!(session.search_index().expect("index").len(), 1);

        session.lock();
        assert!(!session.is_unlocked());
        assert_eq!(session.active_key().unwrap_err(), CoreError::VaultLocked);
        assert_eq!(session.search_index().unwrap_err(), CoreError::VaultLocked);
    }

    #[test]
    fn test_vault_set_new_passphrase_lifecycle() {
        let params = KdfParams::new_test();
        let old_passphrase = b"initial-secret-passphrase";
        let (bootstrap, recovery_key_str, vault_key) =
            VaultManager::init_vault(old_passphrase, &params).expect("init vault");

        let new_passphrase = b"new-super-secure-passphrase";
        let new_params = KdfParams::new_test();

        let updated_bootstrap =
            VaultManager::set_new_passphrase(&bootstrap, &vault_key, new_passphrase, &new_params)
                .expect("set new passphrase");

        // 1. New passphrase unlocks the same VaultKey
        let unlocked_with_new =
            VaultManager::unlock_with_passphrase(&updated_bootstrap, new_passphrase)
                .expect("unlock new");
        assert_eq!(vault_key, unlocked_with_new);

        // 2. Old passphrase fails closed
        assert!(VaultManager::unlock_with_passphrase(&updated_bootstrap, old_passphrase).is_err());

        // 3. Original recovery key STILL restores the same VaultKey
        let recovered_after_pass_change =
            VaultManager::unlock_with_recovery_key(&updated_bootstrap, &recovery_key_str)
                .expect("unlock recovery");
        assert_eq!(vault_key, recovered_after_pass_change);
    }

    #[test]
    fn test_vault_session_idle_timeout_and_auto_lock() {
        let key = VaultKey::generate();
        let mut session = VaultSession::with_idle_timeout(key.clone(), Some(3600));

        assert!(session.is_unlocked());
        assert_eq!(session.idle_timeout(), Some(3600));
        assert!(!session.check_idle_timeout());
        assert!(session.is_unlocked());

        // Update timeout to 0 (disabled)
        session.set_idle_timeout(Some(0));
        assert_eq!(session.idle_timeout(), None);

        // Update timeout to 1 second and simulate passage of time
        session.set_idle_timeout(Some(1));
        assert_eq!(session.idle_timeout(), Some(1));

        // Simulate elapsed time by rewinding last_active_secs
        session.last_active_secs -= 2;
        assert!(session.check_idle_timeout());

        // Session must be locked and zeroized
        assert!(!session.is_unlocked());
        assert_eq!(session.active_key().unwrap_err(), CoreError::VaultLocked);
        assert_eq!(session.search_index().unwrap_err(), CoreError::VaultLocked);
    }
}
