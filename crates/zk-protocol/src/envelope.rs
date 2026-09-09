//! Encrypted envelope representation and serialization models.

use crate::kind::{ObjectKind, UnknownObjectKind};
use serde::{Deserialize, Serialize};

/// Encrypted key container containing Base64-encoded nonce and ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyContainer {
    /// Nonce encoded as standard Base64 (24 bytes for XChaCha20-Poly1305).
    pub nonce: String,
    /// Ciphertext encoded as standard Base64 (wrapped key + 16-byte Poly1305 auth tag).
    pub ciphertext: String,
}

/// Encrypted payload container containing Base64-encoded nonce and ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayloadContainer {
    /// Nonce encoded as standard Base64 (24 bytes for XChaCha20-Poly1305).
    pub nonce: String,
    /// Ciphertext encoded as standard Base64 (encrypted payload + 16-byte Poly1305 auth tag).
    pub ciphertext: String,
}

/// Versioned encrypted envelope wrapping an object key and its encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Envelope format version (v1 = 1).
    pub envelope_version: u32,
    /// Canonical lowercase hyphenated UUID v4.
    pub object_id: String,
    /// Raw integer object kind discriminant.
    pub object_kind: u16,
    /// Vault-key-wrapped object key.
    pub wrapped_key: EncryptedKeyContainer,
    /// Object-key-encrypted payload.
    pub payload: EncryptedPayloadContainer,
}

impl EncryptedEnvelope {
    /// Converts the raw `object_kind` integer into a strongly-typed [`ObjectKind`].
    pub fn kind(&self) -> Result<ObjectKind, UnknownObjectKind> {
        ObjectKind::try_from(self.object_kind)
    }
}
