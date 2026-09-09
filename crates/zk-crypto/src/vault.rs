//! Vault key wrapping, recovery wrapping, and lifecycle operations.

use crate::error::CryptoError;
use crate::kdf::KdfParams;
use crate::keys::{KeyEncryptionKey, RecoveryKey, VaultKey, KEY_LEN};
use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Canonical cipher suite identifier for XChaCha20-Poly1305.
pub const XCHACHA20_POLY1305_CIPHER_SUITE: &str = "xchacha20poly1305";

/// Nonce length in bytes for XChaCha20-Poly1305 (192 bits).
pub const NONCE_LEN: usize = 24;

/// Wrapped vault key envelope containing cipher suite, nonce, and ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedVaultKey {
    /// Cipher suite identifier ("xchacha20poly1305").
    pub cipher_suite: String,
    /// Random 24-byte nonce encoded as Standard Base64.
    pub nonce: String,
    /// Ciphertext (wrapped 32-byte key + 16-byte Poly1305 tag) encoded as Standard Base64.
    pub ciphertext: String,
}

impl From<zk_protocol::vault::WrappedVaultKey> for WrappedVaultKey {
    fn from(w: zk_protocol::vault::WrappedVaultKey) -> Self {
        Self {
            cipher_suite: w.cipher_suite,
            nonce: w.nonce,
            ciphertext: w.ciphertext,
        }
    }
}

impl From<WrappedVaultKey> for zk_protocol::vault::WrappedVaultKey {
    fn from(w: WrappedVaultKey) -> Self {
        Self {
            cipher_suite: w.cipher_suite,
            nonce: w.nonce,
            ciphertext: w.ciphertext,
        }
    }
}

/// Wraps a [`VaultKey`] with a [`KeyEncryptionKey`] using XChaCha20-Poly1305.
pub fn wrap_vault_key(
    vault_key: &VaultKey,
    kek: &KeyEncryptionKey,
) -> Result<WrappedVaultKey, CryptoError> {
    wrap_vault_key_with_rng(vault_key, kek, &mut rand_core::OsRng)
}

/// Wraps a [`VaultKey`] with a [`KeyEncryptionKey`] using the provided CSPRNG.
pub fn wrap_vault_key_with_rng<R: RngCore + CryptoRng>(
    vault_key: &VaultKey,
    kek: &KeyEncryptionKey,
    rng: &mut R,
) -> Result<WrappedVaultKey, CryptoError> {
    wrap_key_bytes(vault_key.as_bytes(), kek.as_bytes(), rng)
}

/// Unwraps a [`WrappedVaultKey`] envelope using a [`KeyEncryptionKey`].
///
/// Fails closed if the key is incorrect, the ciphertext is tampered,
/// or the nonce is corrupted.
pub fn unwrap_vault_key(
    wrapped: &WrappedVaultKey,
    kek: &KeyEncryptionKey,
) -> Result<VaultKey, CryptoError> {
    let plaintext_bytes = unwrap_key_bytes(wrapped, kek.as_bytes())?;
    VaultKey::from_slice(&plaintext_bytes)
}

/// Wraps a [`VaultKey`] independently with a [`RecoveryKey`] using XChaCha20-Poly1305.
pub fn wrap_vault_key_recovery(
    vault_key: &VaultKey,
    recovery_key: &RecoveryKey,
) -> Result<WrappedVaultKey, CryptoError> {
    wrap_vault_key_recovery_with_rng(vault_key, recovery_key, &mut rand_core::OsRng)
}

/// Wraps a [`VaultKey`] independently with a [`RecoveryKey`] using the provided CSPRNG.
pub fn wrap_vault_key_recovery_with_rng<R: RngCore + CryptoRng>(
    vault_key: &VaultKey,
    recovery_key: &RecoveryKey,
    rng: &mut R,
) -> Result<WrappedVaultKey, CryptoError> {
    wrap_key_bytes(vault_key.as_bytes(), recovery_key.as_bytes(), rng)
}

/// Restores a [`VaultKey`] from a recovery-wrapped envelope using the [`RecoveryKey`].
///
/// Fails closed if the recovery key is wrong or the wrapper has been tampered with.
pub fn unwrap_vault_key_recovery(
    wrapped: &WrappedVaultKey,
    recovery_key: &RecoveryKey,
) -> Result<VaultKey, CryptoError> {
    let plaintext_bytes = unwrap_key_bytes(wrapped, recovery_key.as_bytes())?;
    VaultKey::from_slice(&plaintext_bytes)
}

/// Rewraps a [`VaultKey`] under a new passphrase without modifying the underlying Vault Key.
///
/// 1. Derives old KEK from `old_passphrase` and `old_params`.
/// 2. Unwraps the existing [`VaultKey`].
/// 3. Derives new KEK from `new_passphrase` and `new_params`.
/// 4. Wraps the same [`VaultKey`] under the new KEK.
/// 5. Returns the new [`KdfParams`], the new [`WrappedVaultKey`], and the preserved [`VaultKey`].
pub fn rewrap_vault_key(
    old_passphrase: &[u8],
    old_params: &KdfParams,
    wrapped_vault_key: &WrappedVaultKey,
    new_passphrase: &[u8],
    new_params: KdfParams,
) -> Result<(KdfParams, WrappedVaultKey, VaultKey), CryptoError> {
    let old_kek = crate::kdf::derive_kek(old_passphrase, old_params)?;
    let vault_key = unwrap_vault_key(wrapped_vault_key, &old_kek)?;

    let new_kek = crate::kdf::derive_kek(new_passphrase, &new_params)?;
    let new_wrapped_key = wrap_vault_key(&vault_key, &new_kek)?;

    Ok((new_params, new_wrapped_key, vault_key))
}

// Internal helper for wrapping a 32-byte key with a 32-byte wrapping key.
fn wrap_key_bytes<R: RngCore + CryptoRng>(
    key_to_wrap: &[u8; KEY_LEN],
    wrapping_key: &[u8; KEY_LEN],
    rng: &mut R,
) -> Result<WrappedVaultKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), key_to_wrap.as_slice())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    Ok(WrappedVaultKey {
        cipher_suite: XCHACHA20_POLY1305_CIPHER_SUITE.to_string(),
        nonce: Base64::encode_string(&nonce_bytes),
        ciphertext: Base64::encode_string(&ciphertext),
    })
}

// Internal helper for unwrapping a 32-byte key using a 32-byte wrapping key.
fn unwrap_key_bytes(
    wrapped: &WrappedVaultKey,
    wrapping_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    if wrapped.cipher_suite != XCHACHA20_POLY1305_CIPHER_SUITE {
        return Err(CryptoError::UnsupportedAlgorithm(
            wrapped.cipher_suite.clone(),
        ));
    }

    let nonce_bytes = Base64::decode_vec(&wrapped.nonce)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: NONCE_LEN,
            actual: nonce_bytes.len(),
        });
    }

    let ciphertext_bytes = Base64::decode_vec(&wrapped.ciphertext)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid ciphertext base64: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            ciphertext_bytes.as_slice(),
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}
