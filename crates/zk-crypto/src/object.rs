//! Object key wrapping, payload encryption, and complete envelope creation.
//!
//! Implements:
//! - Per-object key generation;
//! - Object Key wrapping under Vault Key with AAD binding (**ZK-014**);
//! - Payload encryption/decryption under Object Key with XChaCha20-Poly1305 (**ZK-015**);
//! - Versioned encrypted envelope assembly and disassembly (**ZK-016**).

use crate::error::CryptoError;
use crate::keys::{ObjectKey, VaultKey};
use crate::vault::NONCE_LEN;
use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};
use zk_protocol::constants::ENVELOPE_VERSION_V1;
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};

/// Builds the canonical Associated Authenticated Data (AAD) binding envelope metadata.
///
/// Binds:
/// - Envelope version;
/// - Object ID;
/// - Object kind.
#[must_use]
pub fn build_aad(envelope_version: u32, object_id: &str, object_kind: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + object_id.len());
    aad.extend_from_slice(b"zk-envelope-aad:");
    aad.extend_from_slice(&envelope_version.to_be_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(&object_kind.to_be_bytes());
    aad
}

/// Wraps a per-object [`ObjectKey`] under a [`VaultKey`] with AAD binding.
pub fn wrap_object_key(
    object_key: &ObjectKey,
    vault_key: &VaultKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
) -> Result<EncryptedKeyContainer, CryptoError> {
    wrap_object_key_with_rng(
        object_key,
        vault_key,
        envelope_version,
        object_id,
        object_kind,
        &mut rand_core::OsRng,
    )
}

/// Wraps a per-object [`ObjectKey`] under a [`VaultKey`] using the provided CSPRNG.
pub fn wrap_object_key_with_rng<R: RngCore + CryptoRng>(
    object_key: &ObjectKey,
    vault_key: &VaultKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
    rng: &mut R,
) -> Result<EncryptedKeyContainer, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let aad = build_aad(envelope_version, object_id, object_kind);
    let payload = Payload {
        msg: object_key.as_bytes().as_slice(),
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    Ok(EncryptedKeyContainer {
        nonce: Base64::encode_string(&nonce_bytes),
        ciphertext: Base64::encode_string(&ciphertext),
    })
}

/// Unwraps an [`EncryptedKeyContainer`] to retrieve the [`ObjectKey`].
///
/// Fails closed if the key is wrong, the ciphertext is tampered, or the AAD does not match.
pub fn unwrap_object_key(
    container: &EncryptedKeyContainer,
    vault_key: &VaultKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
) -> Result<ObjectKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let nonce_bytes = Base64::decode_vec(&container.nonce)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: NONCE_LEN,
            actual: nonce_bytes.len(),
        });
    }

    let ciphertext = Base64::decode_vec(&container.ciphertext)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid ciphertext base64: {e}")))?;

    let aad = build_aad(envelope_version, object_id, object_kind);
    let payload = Payload {
        msg: ciphertext.as_slice(),
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    ObjectKey::from_slice(&plaintext)
}

/// Encrypts an object payload with an [`ObjectKey`] and authenticated metadata.
pub fn encrypt_object_payload(
    plaintext: &[u8],
    object_key: &ObjectKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
) -> Result<EncryptedPayloadContainer, CryptoError> {
    encrypt_object_payload_with_rng(
        plaintext,
        object_key,
        envelope_version,
        object_id,
        object_kind,
        &mut rand_core::OsRng,
    )
}

/// Encrypts an object payload with an [`ObjectKey`] using the provided CSPRNG.
pub fn encrypt_object_payload_with_rng<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    object_key: &ObjectKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
    rng: &mut R,
) -> Result<EncryptedPayloadContainer, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(object_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let aad = build_aad(envelope_version, object_id, object_kind);
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    Ok(EncryptedPayloadContainer {
        nonce: Base64::encode_string(&nonce_bytes),
        ciphertext: Base64::encode_string(&ciphertext),
    })
}

/// Decrypts an [`EncryptedPayloadContainer`] using the [`ObjectKey`].
///
/// Fails closed if the key is wrong, the ciphertext is tampered, or the AAD does not match.
pub fn decrypt_object_payload(
    container: &EncryptedPayloadContainer,
    object_key: &ObjectKey,
    envelope_version: u32,
    object_id: &str,
    object_kind: u16,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(object_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let nonce_bytes = Base64::decode_vec(&container.nonce)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: NONCE_LEN,
            actual: nonce_bytes.len(),
        });
    }

    let ciphertext = Base64::decode_vec(&container.ciphertext)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid ciphertext base64: {e}")))?;

    let aad = build_aad(envelope_version, object_id, object_kind);
    let payload = Payload {
        msg: ciphertext.as_slice(),
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Encrypts plaintext into a complete [`EncryptedEnvelope`].
///
/// Generates a fresh random [`ObjectKey`], wraps it under the [`VaultKey`],
/// encrypts the payload, and packages them with authenticated AAD metadata.
pub fn encrypt_envelope(
    plaintext: &[u8],
    vault_key: &VaultKey,
    object_id: &str,
    object_kind: u16,
) -> Result<EncryptedEnvelope, CryptoError> {
    let object_key = ObjectKey::generate();

    let wrapped_key = wrap_object_key(
        &object_key,
        vault_key,
        ENVELOPE_VERSION_V1,
        object_id,
        object_kind,
    )?;

    let payload = encrypt_object_payload(
        plaintext,
        &object_key,
        ENVELOPE_VERSION_V1,
        object_id,
        object_kind,
    )?;

    Ok(EncryptedEnvelope {
        envelope_version: ENVELOPE_VERSION_V1,
        object_id: object_id.to_string(),
        object_kind,
        wrapped_key,
        payload,
    })
}

/// Decrypts an [`EncryptedEnvelope`] using the [`VaultKey`].
///
/// Validates envelope version, unwraps the [`ObjectKey`] using AAD,
/// and decrypts the payload. Fails closed on any error.
pub fn decrypt_envelope(
    envelope: &EncryptedEnvelope,
    vault_key: &VaultKey,
) -> Result<Vec<u8>, CryptoError> {
    if envelope.envelope_version != ENVELOPE_VERSION_V1 {
        return Err(CryptoError::UnsupportedVersion(envelope.envelope_version));
    }

    let object_key = unwrap_object_key(
        &envelope.wrapped_key,
        vault_key,
        envelope.envelope_version,
        &envelope.object_id,
        envelope.object_kind,
    )?;

    decrypt_object_payload(
        &envelope.payload,
        &object_key,
        envelope.envelope_version,
        &envelope.object_id,
        envelope.object_kind,
    )
}
