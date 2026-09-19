//! Cryptographic primitives for versioned, chunked attachment encryption (M8 / ZK-080).
//!
//! Enforces:
//! - **SEC-001**: Plaintext attachment contents, filenames, and MIME metadata never cross the network.
//! - **SEC-004**: Authenticated encryption only (XChaCha20-Poly1305).
//! - **SEC-005**: Unique 24-byte random nonce per chunk.
//! - **SEC-010**: All authentication failures fail closed without partial data leakage.
//! - Associated Authenticated Data (AAD) binds envelope version, attachment ID, chunk index, and total chunk count.

use crate::error::CryptoError;
use crate::keys::{AttachmentKey, VaultKey};
use crate::vault::NONCE_LEN;
use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};
use zk_protocol::attachment::{ChunkFormatError, EncryptedChunk};
use zk_protocol::constants::{ATTACHMENT_CHUNK_VERSION_V1, OBJECT_KIND_ATTACHMENT_MANIFEST};
use zk_protocol::envelope::EncryptedKeyContainer;

/// Builds canonical Associated Authenticated Data (AAD) for an attachment chunk.
///
/// Cryptographically binds:
/// - Format version;
/// - Attachment UUID;
/// - 0-based chunk sequence index;
/// - Total chunk count.
#[must_use]
pub fn build_chunk_aad(
    version: u32,
    attachment_id: &str,
    chunk_index: u32,
    total_chunks: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + attachment_id.len());
    aad.extend_from_slice(b"zk-attachment-chunk-aad:");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(attachment_id.as_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(&total_chunks.to_be_bytes());
    aad
}

/// Encrypts a single plaintext chunk with an [`AttachmentKey`].
///
/// Uses standard XChaCha20-Poly1305 AEAD with an OS CSPRNG-derived 24-byte nonce and chunk AAD.
pub fn encrypt_chunk(
    plaintext: &[u8],
    attachment_key: &AttachmentKey,
    attachment_id: &str,
    chunk_index: u32,
    total_chunks: u32,
) -> Result<EncryptedChunk, CryptoError> {
    encrypt_chunk_with_rng(
        plaintext,
        attachment_key,
        attachment_id,
        chunk_index,
        total_chunks,
        &mut rand_core::OsRng,
    )
}

/// Encrypts a single plaintext chunk with an [`AttachmentKey`] using the provided CSPRNG.
pub fn encrypt_chunk_with_rng<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    attachment_key: &AttachmentKey,
    attachment_id: &str,
    chunk_index: u32,
    total_chunks: u32,
    rng: &mut R,
) -> Result<EncryptedChunk, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(attachment_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let aad = build_chunk_aad(
        ATTACHMENT_CHUNK_VERSION_V1,
        attachment_id,
        chunk_index,
        total_chunks,
    );
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    Ok(EncryptedChunk {
        version: ATTACHMENT_CHUNK_VERSION_V1,
        attachment_id: attachment_id.to_string(),
        chunk_index,
        total_chunks,
        nonce: Base64::encode_string(&nonce_bytes),
        ciphertext: Base64::encode_string(&ciphertext),
    })
}

/// Decrypts an [`EncryptedChunk`] with an [`AttachmentKey`].
///
/// Fails closed if the key is incorrect, the ciphertext is corrupted, or any AAD element
/// (version, attachment ID, chunk index, total chunk count) was tampered with.
pub fn decrypt_chunk(
    chunk: &EncryptedChunk,
    attachment_key: &AttachmentKey,
) -> Result<Vec<u8>, CryptoError> {
    if chunk.version != ATTACHMENT_CHUNK_VERSION_V1 {
        return Err(CryptoError::UnsupportedVersion(chunk.version));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    let decoded_nonce = Base64::decode(&chunk.nonce, &mut nonce_bytes)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;

    if decoded_nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: NONCE_LEN,
            actual: decoded_nonce.len(),
        });
    }

    let ciphertext_bytes = Base64::decode_vec(&chunk.ciphertext)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid ciphertext base64: {e}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(attachment_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let aad = build_chunk_aad(
        chunk.version,
        &chunk.attachment_id,
        chunk.chunk_index,
        chunk.total_chunks,
    );

    let payload = Payload {
        msg: &ciphertext_bytes,
        aad: &aad,
    };

    cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypts a plaintext chunk directly to compact binary wire bytes.
pub fn encrypt_chunk_binary(
    plaintext: &[u8],
    attachment_key: &AttachmentKey,
    attachment_id: &str,
    chunk_index: u32,
    total_chunks: u32,
) -> Result<Vec<u8>, CryptoError> {
    let chunk = encrypt_chunk(
        plaintext,
        attachment_key,
        attachment_id,
        chunk_index,
        total_chunks,
    )?;
    chunk.to_bytes().map_err(|e| match e {
        ChunkFormatError::InvalidEncoding(msg) => CryptoError::InvalidEncoding(msg),
        other => CryptoError::InvalidEncoding(other.to_string()),
    })
}

/// Decrypts a compact binary wire byte buffer directly to plaintext.
pub fn decrypt_chunk_binary(
    bytes: &[u8],
    attachment_key: &AttachmentKey,
) -> Result<(u32, u32, Vec<u8>), CryptoError> {
    let chunk = EncryptedChunk::from_bytes(bytes).map_err(|e| match e {
        ChunkFormatError::Truncated { expected, actual } => {
            CryptoError::InvalidKeyLength { expected, actual }
        }
        other => CryptoError::InvalidEncoding(other.to_string()),
    })?;

    let chunk_index = chunk.chunk_index;
    let total_chunks = chunk.total_chunks;
    let plaintext = decrypt_chunk(&chunk, attachment_key)?;

    Ok((chunk_index, total_chunks, plaintext))
}

/// Wraps a per-attachment [`AttachmentKey`] under the master [`VaultKey`] with AAD binding.
pub fn wrap_attachment_key(
    attachment_key: &AttachmentKey,
    vault_key: &VaultKey,
    envelope_version: u32,
    attachment_id: &str,
) -> Result<EncryptedKeyContainer, CryptoError> {
    wrap_attachment_key_with_rng(
        attachment_key,
        vault_key,
        envelope_version,
        attachment_id,
        &mut rand_core::OsRng,
    )
}

/// Wraps a per-attachment [`AttachmentKey`] under the master [`VaultKey`] using the provided CSPRNG.
pub fn wrap_attachment_key_with_rng<R: RngCore + CryptoRng>(
    attachment_key: &AttachmentKey,
    vault_key: &VaultKey,
    envelope_version: u32,
    attachment_id: &str,
    rng: &mut R,
) -> Result<EncryptedKeyContainer, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let aad = crate::object::build_aad(
        envelope_version,
        attachment_id,
        OBJECT_KIND_ATTACHMENT_MANIFEST,
    );
    let payload = Payload {
        msg: attachment_key.as_bytes().as_slice(),
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

/// Unwraps an [`EncryptedKeyContainer`] to retrieve the [`AttachmentKey`].
///
/// Fails closed if the vault key is wrong, the key container ciphertext is corrupted,
/// or the attachment ID does not match the bound AAD.
pub fn unwrap_attachment_key(
    container: &EncryptedKeyContainer,
    vault_key: &VaultKey,
    envelope_version: u32,
    attachment_id: &str,
) -> Result<AttachmentKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(vault_key.as_bytes())
        .map_err(|e| CryptoError::AeadFailure(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    let decoded_nonce = Base64::decode(&container.nonce, &mut nonce_bytes)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;

    if decoded_nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: NONCE_LEN,
            actual: decoded_nonce.len(),
        });
    }

    let ciphertext_bytes = Base64::decode_vec(&container.ciphertext)
        .map_err(|e| CryptoError::InvalidEncoding(format!("invalid ciphertext base64: {e}")))?;

    let aad = crate::object::build_aad(
        envelope_version,
        attachment_id,
        OBJECT_KIND_ATTACHMENT_MANIFEST,
    );
    let payload = Payload {
        msg: &ciphertext_bytes,
        aad: &aad,
    };

    let key_bytes = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    AttachmentKey::from_slice(&key_bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_attachment_key_random_generation() {
        let key1 = AttachmentKey::generate();
        let key2 = AttachmentKey::generate();
        assert_ne!(key1, key2);
        assert_eq!(key1.as_bytes().len(), 32);
    }

    #[test]
    fn test_chunk_encryption_decryption_round_trip() {
        let key = AttachmentKey::generate();
        let attachment_id = "550e8400-e29b-41d4-a716-446655440000";
        let chunk_index = 0;
        let total_chunks = 2;
        let plaintext = b"Hello, Zero-Knowledge Attachment World! 1234567890";

        let chunk = encrypt_chunk(plaintext, &key, attachment_id, chunk_index, total_chunks)
            .expect("encrypt chunk");

        assert_eq!(chunk.version, ATTACHMENT_CHUNK_VERSION_V1);
        assert_eq!(chunk.attachment_id, attachment_id);
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 2);

        let decrypted = decrypt_chunk(&chunk, &key).expect("decrypt chunk");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chunk_binary_wire_round_trip() {
        let key = AttachmentKey::generate();
        let attachment_id = "550e8400-e29b-41d4-a716-446655440000";
        let plaintext = b"Binary serialized chunk payload test.";

        let binary_bytes =
            encrypt_chunk_binary(plaintext, &key, attachment_id, 1, 3).expect("encrypt binary");

        let (idx, total, decrypted) =
            decrypt_chunk_binary(&binary_bytes, &key).expect("decrypt binary");

        assert_eq!(idx, 1);
        assert_eq!(total, 3);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chunk_wrong_key_fails_closed() {
        let key1 = AttachmentKey::generate();
        let key2 = AttachmentKey::generate();
        let chunk = encrypt_chunk(b"secret payload", &key1, "att-1", 0, 1).unwrap();

        let err = decrypt_chunk(&chunk, &key2).unwrap_err();
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_chunk_tampered_ciphertext_fails_closed() {
        let key = AttachmentKey::generate();
        let mut chunk = encrypt_chunk(b"secret payload", &key, "att-1", 0, 1).unwrap();

        let mut ct_bytes = Base64::decode_vec(&chunk.ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        chunk.ciphertext = Base64::encode_string(&ct_bytes);

        let err = decrypt_chunk(&chunk, &key).unwrap_err();
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_chunk_tampered_aad_index_fails_closed() {
        let key = AttachmentKey::generate();
        let mut chunk = encrypt_chunk(b"secret payload", &key, "att-1", 0, 2).unwrap();

        // Tamper chunk index in envelope metadata
        chunk.chunk_index = 1;

        let err = decrypt_chunk(&chunk, &key).unwrap_err();
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_chunk_tampered_aad_attachment_id_fails_closed() {
        let key = AttachmentKey::generate();
        let mut chunk = encrypt_chunk(b"secret payload", &key, "att-original", 0, 1).unwrap();

        // Tamper attachment ID in envelope metadata
        chunk.attachment_id = "att-tampered".to_string();

        let err = decrypt_chunk(&chunk, &key).unwrap_err();
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_chunk_tampered_aad_total_chunks_fails_closed() {
        let key = AttachmentKey::generate();
        let mut chunk = encrypt_chunk(b"secret payload", &key, "att-1", 0, 2).unwrap();

        // Tamper total chunks
        chunk.total_chunks = 3;

        let err = decrypt_chunk(&chunk, &key).unwrap_err();
        assert_eq!(err, CryptoError::DecryptionFailed);
    }

    #[test]
    fn test_chunk_unsupported_version_rejected() {
        let key = AttachmentKey::generate();
        let mut chunk = encrypt_chunk(b"secret payload", &key, "att-1", 0, 1).unwrap();
        chunk.version = 999;

        let err = decrypt_chunk(&chunk, &key).unwrap_err();
        assert_eq!(err, CryptoError::UnsupportedVersion(999));
    }

    #[test]
    fn test_wrap_and_unwrap_attachment_key() {
        let vault_key = VaultKey::generate();
        let attachment_key = AttachmentKey::generate();
        let attachment_id = "550e8400-e29b-41d4-a716-446655440000";

        let container = wrap_attachment_key(&attachment_key, &vault_key, 1, attachment_id)
            .expect("wrap attachment key");

        let unwrapped = unwrap_attachment_key(&container, &vault_key, 1, attachment_id)
            .expect("unwrap attachment key");

        assert_eq!(unwrapped, attachment_key);

        // Wrong vault key fails closed
        let wrong_vault_key = VaultKey::generate();
        let wrong_err =
            unwrap_attachment_key(&container, &wrong_vault_key, 1, attachment_id).unwrap_err();
        assert_eq!(wrong_err, CryptoError::DecryptionFailed);

        // Wrong attachment ID AAD fails closed
        let wrong_id_err =
            unwrap_attachment_key(&container, &vault_key, 1, "different-id").unwrap_err();
        assert_eq!(wrong_id_err, CryptoError::DecryptionFailed);
    }
}
