//! Vault metadata and key wrapper bootstrap models.

use serde::{Deserialize, Serialize};

/// Argon2id KDF parameters stored in vault bootstrap record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// KDF algorithm identifier (e.g. "argon2id").
    pub algorithm: String,
    /// Random salt encoded as standard Base64.
    pub salt: String,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations / time cost.
    pub iterations: u32,
    /// Degree of parallelism / thread count.
    pub parallelism: u32,
}

/// Wrapped vault key envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedVaultKey {
    /// Cipher suite identifier (e.g. "xchacha20poly1305").
    pub cipher_suite: String,
    /// Nonce encoded as standard Base64 (24 bytes).
    pub nonce: String,
    /// Ciphertext encoded as standard Base64 (wrapped key + auth tag).
    pub ciphertext: String,
}

/// Vault bootstrap payload persisted on the server and local storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultBootstrap {
    /// Cryptographic version (v1 = 1).
    pub crypto_version: u32,
    /// Argon2id parameters used to derive KEK.
    pub kdf: KdfParams,
    /// Vault key wrapped by password-derived KEK.
    pub wrapped_vault_key: WrappedVaultKey,
    /// Vault key independently wrapped by high-entropy Recovery Key.
    pub recovery_wrapped_vault_key: WrappedVaultKey,
}
