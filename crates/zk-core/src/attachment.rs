//! Streaming, chunked native encryption and decryption for attachments (M8 / ZK-081).
//!
//! In accordance with MASTER_SPEC.md § 14, SEC-001, SEC-004, SEC-009, and SEC-010:
//! - Streaming chunked operation processes arbitrary file sizes without whole-file buffering.
//! - Maximum attachment size is enforced at 100 MiB (`MAX_ATTACHMENT_SIZE`).
//! - Each chunk is encrypted under an independent random 256-bit `AttachmentKey` with a unique nonce and AAD.
//! - Any corrupted, out-of-order, or missing chunk causes immediate, fail-closed rejection.
//! - Content integrity hash (BLAKE2b-512) is computed incrementally and validated against the manifest.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use blake2::digest::Digest;
use blake2::Blake2b512;
use zk_crypto::attachment::{decrypt_chunk, encrypt_chunk};
use zk_crypto::keys::{AttachmentKey, VaultKey};
use zk_protocol::attachment::{AttachmentManifest, EncryptedChunk};
pub use zk_protocol::constants::{
    DEFAULT_ATTACHMENT_CHUNK_SIZE, ENVELOPE_VERSION_V1, MAX_ATTACHMENT_SIZE,
    OBJECT_KIND_ATTACHMENT_MANIFEST,
};
use zk_protocol::envelope::EncryptedEnvelope;

use crate::error::{AttachmentError, CoreError};
use crate::note::PlaintextNote;

/// Default target chunk size (4 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = DEFAULT_ATTACHMENT_CHUNK_SIZE;

/// Computes the expected chunk count given total file size and chunk size.
#[must_use]
pub fn calculate_chunk_count(size: u64, chunk_size: usize) -> u32 {
    if size == 0 {
        1
    } else {
        size.div_ceil(chunk_size as u64) as u32
    }
}

/// Parameters for encrypting an attachment stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentEncryptParams<'a> {
    pub attachment_id: &'a str,
    pub name: &'a str,
    pub mime: &'a str,
    pub chunk_size: usize,
}

impl<'a> AttachmentEncryptParams<'a> {
    /// Creates a new parameter set with default chunk size (4 MiB).
    #[must_use]
    pub fn new(attachment_id: &'a str, name: &'a str, mime: &'a str) -> Self {
        Self {
            attachment_id,
            name,
            mime,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Overrides target chunk size (useful for tests).
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

/// Computes a BLAKE2b-512 hex digest of a byte slice.
#[must_use]
pub fn compute_content_hash(bytes: &[u8]) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Encrypts an input stream chunk-by-chunk using a sink callback.
///
/// **Memory Efficiency**: Only buffers a single chunk (`chunk_size` bytes) in memory at a time.
/// Emits each [`EncryptedChunk`] to the provided `on_chunk` callback.
pub fn encrypt_attachment_stream_with_sink<R: Read, F>(
    mut reader: R,
    total_size: u64,
    params: &AttachmentEncryptParams<'_>,
    key: &AttachmentKey,
    mut on_chunk: F,
) -> Result<AttachmentManifest, CoreError>
where
    F: FnMut(EncryptedChunk) -> Result<(), CoreError>,
{
    if total_size > MAX_ATTACHMENT_SIZE {
        return Err(AttachmentError::FileTooLarge {
            max: MAX_ATTACHMENT_SIZE,
            actual: total_size,
        }
        .into());
    }

    let chunk_count = calculate_chunk_count(total_size, params.chunk_size);
    let mut hasher = Blake2b512::new();

    // Special case: empty file produces 1 empty chunk with index 0 of 1
    if total_size == 0 {
        let encrypted = encrypt_chunk(&[], key, params.attachment_id, 0, 1)?;
        on_chunk(encrypted)?;
        let content_hash = compute_content_hash(&[]);
        return Ok(AttachmentManifest {
            attachment_id: params.attachment_id.to_string(),
            name: params.name.to_string(),
            mime: params.mime.to_string(),
            size: 0,
            chunk_count: 1,
            chunk_size: params.chunk_size as u32,
            content_hash: Some(content_hash),
        });
    }

    let mut buffer = vec![0u8; params.chunk_size];
    let mut bytes_read_total: u64 = 0;
    let mut chunk_index: u32 = 0;

    while chunk_index < chunk_count {
        let mut chunk_bytes_read = 0;
        while chunk_bytes_read < params.chunk_size {
            let n = reader
                .read(&mut buffer[chunk_bytes_read..])
                .map_err(|e| AttachmentError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            chunk_bytes_read += n;
        }

        if chunk_bytes_read == 0 && chunk_index > 0 {
            break;
        }

        let chunk_slice = &buffer[..chunk_bytes_read];
        hasher.update(chunk_slice);
        bytes_read_total += chunk_bytes_read as u64;

        if bytes_read_total > MAX_ATTACHMENT_SIZE {
            return Err(AttachmentError::FileTooLarge {
                max: MAX_ATTACHMENT_SIZE,
                actual: bytes_read_total,
            }
            .into());
        }

        let encrypted = encrypt_chunk(
            chunk_slice,
            key,
            params.attachment_id,
            chunk_index,
            chunk_count,
        )?;

        on_chunk(encrypted)?;
        chunk_index += 1;
    }

    if bytes_read_total != total_size {
        return Err(AttachmentError::SizeMismatch {
            expected: total_size,
            actual: bytes_read_total,
        }
        .into());
    }

    let content_hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    Ok(AttachmentManifest {
        attachment_id: params.attachment_id.to_string(),
        name: params.name.to_string(),
        mime: params.mime.to_string(),
        size: total_size,
        chunk_count,
        chunk_size: params.chunk_size as u32,
        content_hash: Some(content_hash),
    })
}

/// Encrypts an input stream and collects all [`EncryptedChunk`]s into a [`Vec`].
pub fn encrypt_attachment_stream<R: Read>(
    reader: R,
    total_size: u64,
    params: &AttachmentEncryptParams<'_>,
    key: &AttachmentKey,
) -> Result<(AttachmentManifest, Vec<EncryptedChunk>), CoreError> {
    let mut chunks = Vec::new();
    let manifest = encrypt_attachment_stream_with_sink(reader, total_size, params, key, |c| {
        chunks.push(c);
        Ok(())
    })?;
    Ok((manifest, chunks))
}

/// Encrypts a file on disk into encrypted chunks without reading the entire file into memory.
pub fn encrypt_attachment_file(
    source_path: &Path,
    attachment_id: &str,
    key: &AttachmentKey,
    name: Option<&str>,
    mime: Option<&str>,
    chunk_size: Option<usize>,
) -> Result<(AttachmentManifest, Vec<EncryptedChunk>), CoreError> {
    let file = File::open(source_path).map_err(|e| AttachmentError::Io(e.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|e| AttachmentError::Io(e.to_string()))?;
    let total_size = metadata.len();

    let resolved_name = name.unwrap_or_else(|| {
        source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment.bin")
    });

    let resolved_mime = mime.unwrap_or("application/octet-stream");
    let resolved_chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let params = AttachmentEncryptParams::new(attachment_id, resolved_name, resolved_mime)
        .with_chunk_size(resolved_chunk_size);

    encrypt_attachment_stream(file, total_size, &params, key)
}

/// Decrypts a stream of [`EncryptedChunk`]s directly into a destination writer.
///
/// **Security Invariants**:
/// - Fails closed immediately if any chunk is corrupted, out of order, or has mismatched AAD.
/// - Validates chunk sequence (0, 1, 2, ... N-1).
/// - If a manifest is provided, validates attachment ID, total chunk count, final size, and BLAKE2b hash.
/// - Streams directly to `writer` without buffering the full decrypted payload in memory.
pub fn decrypt_attachment_stream_with_source<W: Write, I>(
    chunks: I,
    key: &AttachmentKey,
    manifest: Option<&AttachmentManifest>,
    mut writer: W,
) -> Result<u64, CoreError>
where
    I: IntoIterator<Item = EncryptedChunk>,
{
    let mut expected_chunk_index: u32 = 0;
    let mut expected_total_chunks: Option<u32> = None;
    let mut total_bytes_written: u64 = 0;
    let mut hasher = Blake2b512::new();

    for chunk in chunks {
        // Enforce sequential ordering
        if chunk.chunk_index != expected_chunk_index {
            return Err(AttachmentError::ChunkOutOfOrder {
                expected: expected_chunk_index,
                actual: chunk.chunk_index,
            }
            .into());
        }

        // Enforce consistent total_chunks across all chunks
        match expected_total_chunks {
            None => expected_total_chunks = Some(chunk.total_chunks),
            Some(expected) if chunk.total_chunks != expected => {
                return Err(AttachmentError::ChunkCountMismatch {
                    expected,
                    actual: chunk.total_chunks,
                }
                .into());
            }
            _ => (),
        }

        // If manifest provided, enforce attachment_id and chunk_count match
        if let Some(m) = manifest {
            if chunk.attachment_id != m.attachment_id {
                return Err(AttachmentError::AttachmentIdMismatch {
                    expected: m.attachment_id.clone(),
                    actual: chunk.attachment_id,
                }
                .into());
            }

            if chunk.total_chunks != m.chunk_count {
                return Err(AttachmentError::ChunkCountMismatch {
                    expected: m.chunk_count,
                    actual: chunk.total_chunks,
                }
                .into());
            }
        }

        // Decrypt chunk payload (fails closed on invalid key or corrupted ciphertext/AAD)
        let plaintext = decrypt_chunk(&chunk, key)?;

        hasher.update(&plaintext);
        writer
            .write_all(&plaintext)
            .map_err(|e| AttachmentError::Io(e.to_string()))?;

        total_bytes_written += plaintext.len() as u64;
        expected_chunk_index += 1;
    }

    // Verify all chunks arrived
    if let Some(total) = expected_total_chunks {
        if expected_chunk_index != total {
            return Err(AttachmentError::ChunkCountMismatch {
                expected: total,
                actual: expected_chunk_index,
            }
            .into());
        }
    } else {
        // No chunks were provided at all
        return Err(AttachmentError::ChunkCountMismatch {
            expected: 1,
            actual: 0,
        }
        .into());
    }

    // If manifest provided, verify byte count and integrity hash
    if let Some(m) = manifest {
        if total_bytes_written != m.size {
            return Err(AttachmentError::SizeMismatch {
                expected: m.size,
                actual: total_bytes_written,
            }
            .into());
        }

        if let Some(ref expected_hash) = m.content_hash {
            let computed_hash = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();

            if computed_hash != *expected_hash {
                return Err(AttachmentError::HashMismatch {
                    expected: expected_hash.clone(),
                    actual: computed_hash,
                }
                .into());
            }
        }
    }

    writer
        .flush()
        .map_err(|e| AttachmentError::Io(e.to_string()))?;

    Ok(total_bytes_written)
}

/// Decrypts encrypted chunks directly to a destination file on disk.
///
/// Automatically removes the destination file if any chunk decryption or integrity verification fails.
pub fn decrypt_attachment_to_file(
    chunks: &[EncryptedChunk],
    key: &AttachmentKey,
    manifest: Option<&AttachmentManifest>,
    dest_path: &Path,
) -> Result<u64, CoreError> {
    let file = File::create(dest_path).map_err(|e| AttachmentError::Io(e.to_string()))?;

    match decrypt_attachment_stream_with_source(chunks.iter().cloned(), key, manifest, file) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            // Fail closed: clean up partially written destination file
            let _ = std::fs::remove_file(dest_path);
            Err(err)
        }
    }
}

/// Encrypts an [`AttachmentManifest`] into an [`EncryptedEnvelope`] using the [`AttachmentKey`]
/// and wraps the key under the master [`VaultKey`].
///
/// In accordance with SEC-001, SEC-002, and SEC-004:
/// - Manifest metadata (name, MIME, size, chunk count, integrity hash) is authenticated and encrypted.
/// - The attachment key is wrapped with AAD binding `(envelope_version, attachment_id, OBJECT_KIND_ATTACHMENT_MANIFEST)`.
pub fn encrypt_attachment_manifest(
    manifest: &AttachmentManifest,
    attachment_key: &AttachmentKey,
    vault_key: &VaultKey,
) -> Result<EncryptedEnvelope, CoreError> {
    let envelope_version = zk_protocol::constants::ENVELOPE_VERSION_V1;
    let manifest_json = serde_json::to_vec(manifest).map_err(|e| {
        CoreError::Validation(crate::error::NoteValidationError::SerializationError(
            e.to_string(),
        ))
    })?;

    let object_key = zk_crypto::keys::ObjectKey::from_bytes(*attachment_key.as_bytes());
    let payload_container = zk_crypto::object::encrypt_object_payload(
        &manifest_json,
        &object_key,
        envelope_version,
        &manifest.attachment_id,
        zk_protocol::constants::OBJECT_KIND_ATTACHMENT_MANIFEST,
    )?;

    let wrapped_key = zk_crypto::attachment::wrap_attachment_key(
        attachment_key,
        vault_key,
        envelope_version,
        &manifest.attachment_id,
    )?;

    Ok(EncryptedEnvelope {
        envelope_version,
        object_id: manifest.attachment_id.clone(),
        object_kind: zk_protocol::constants::OBJECT_KIND_ATTACHMENT_MANIFEST,
        wrapped_key,
        payload: payload_container,
    })
}

/// Decrypts an [`EncryptedEnvelope`] to recover the [`AttachmentManifest`] and unwrapped [`AttachmentKey`].
///
/// In accordance with SEC-010:
/// - Validates envelope version and object kind.
/// - Fails closed on any tampering, wrong key, or AAD mismatch.
/// - Enforces manifest attachment ID matches envelope object ID.
pub fn decrypt_attachment_manifest(
    envelope: &EncryptedEnvelope,
    vault_key: &VaultKey,
) -> Result<(AttachmentManifest, AttachmentKey), CoreError> {
    if envelope.envelope_version != zk_protocol::constants::ENVELOPE_VERSION_V1 {
        return Err(CoreError::Crypto(
            zk_crypto::error::CryptoError::UnsupportedVersion(envelope.envelope_version),
        ));
    }
    if envelope.object_kind != zk_protocol::constants::OBJECT_KIND_ATTACHMENT_MANIFEST {
        return Err(CoreError::Validation(
            crate::error::NoteValidationError::SerializationError(format!(
                "expected object kind ATTACHMENT_MANIFEST ({}), got {}",
                zk_protocol::constants::OBJECT_KIND_ATTACHMENT_MANIFEST,
                envelope.object_kind
            )),
        ));
    }

    let attachment_key = zk_crypto::attachment::unwrap_attachment_key(
        &envelope.wrapped_key,
        vault_key,
        envelope.envelope_version,
        &envelope.object_id,
    )?;

    let object_key = zk_crypto::keys::ObjectKey::from_bytes(*attachment_key.as_bytes());
    let plaintext_bytes = zk_crypto::object::decrypt_object_payload(
        &envelope.payload,
        &object_key,
        envelope.envelope_version,
        &envelope.object_id,
        envelope.object_kind,
    )?;

    let manifest: AttachmentManifest = serde_json::from_slice(&plaintext_bytes).map_err(|e| {
        CoreError::Validation(crate::error::NoteValidationError::SerializationError(
            e.to_string(),
        ))
    })?;

    if manifest.attachment_id != envelope.object_id {
        return Err(CoreError::Attachment(
            AttachmentError::AttachmentIdMismatch {
                expected: envelope.object_id.clone(),
                actual: manifest.attachment_id,
            },
        ));
    }

    Ok((manifest, attachment_key))
}

/// Attaches an attachment ID to a note, enforcing attachment count limits and updating timestamps.
pub fn add_attachment_to_note(
    note: &mut PlaintextNote,
    attachment_id: &str,
) -> Result<(), CoreError> {
    if !note.attachments.iter().any(|id| id == attachment_id) {
        if note.attachments.len() >= crate::note::MAX_ATTACHMENTS_COUNT {
            return Err(CoreError::Validation(
                crate::error::NoteValidationError::TooManyAttachments {
                    max: crate::note::MAX_ATTACHMENTS_COUNT,
                    actual: note.attachments.len() + 1,
                },
            ));
        }
        if attachment_id.is_empty() || attachment_id.len() > crate::note::MAX_ATTACHMENT_ID_LEN {
            return Err(CoreError::Validation(
                crate::error::NoteValidationError::InvalidAttachmentId(attachment_id.to_string()),
            ));
        }
        note.attachments.push(attachment_id.to_string());
        note.updated_at = crate::time::now_utc_rfc3339();
    }
    Ok(())
}

/// Detaches an attachment ID from a note, updating timestamps if removed.
pub fn remove_attachment_from_note(note: &mut PlaintextNote, attachment_id: &str) -> bool {
    let original_len = note.attachments.len();
    note.attachments.retain(|id| id != attachment_id);
    if note.attachments.len() != original_len {
        note.updated_at = crate::time::now_utc_rfc3339();
        true
    } else {
        false
    }
}

/// Identifies stored attachment IDs that are no longer referenced by any active note.
#[must_use]
pub fn find_orphaned_attachments<'a>(
    notes: &[PlaintextNote],
    stored_attachment_ids: &'a [String],
) -> Vec<&'a str> {
    let mut referenced = std::collections::HashSet::new();
    for note in notes {
        for att_id in &note.attachments {
            referenced.insert(att_id.as_str());
        }
    }
    stored_attachment_ids
        .iter()
        .map(String::as_str)
        .filter(|id| !referenced.contains(id))
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    use std::io::Cursor;

    #[test]
    fn test_calculate_chunk_count() {
        assert_eq!(calculate_chunk_count(0, 1024), 1);
        assert_eq!(calculate_chunk_count(500, 1024), 1);
        assert_eq!(calculate_chunk_count(1024, 1024), 1);
        assert_eq!(calculate_chunk_count(1025, 1024), 2);
        assert_eq!(calculate_chunk_count(2048, 1024), 2);
        assert_eq!(calculate_chunk_count(2049, 1024), 3);
    }

    #[test]
    fn test_streaming_encryption_decryption_round_trip() {
        let key = AttachmentKey::generate();
        let attachment_id = "test-uuid-streaming-1";
        let test_data =
            b"Streaming attachment chunking verification with multiple blocks of data. 0123456789";

        // Use a small chunk size (16 bytes) to verify multi-chunk streaming
        let chunk_size = 16;
        let reader = Cursor::new(test_data.to_vec());

        let params = AttachmentEncryptParams::new(attachment_id, "sample.txt", "text/plain")
            .with_chunk_size(chunk_size);
        let (manifest, chunks) =
            encrypt_attachment_stream(reader, test_data.len() as u64, &params, &key)
                .expect("encrypt stream");

        assert_eq!(manifest.size, test_data.len() as u64);
        assert_eq!(manifest.chunk_count, chunks.len() as u32);
        assert!(manifest.chunk_count > 1);

        let mut decrypted_buffer = Vec::new();
        let bytes_written = decrypt_attachment_stream_with_source(
            chunks,
            &key,
            Some(&manifest),
            &mut decrypted_buffer,
        )
        .expect("decrypt stream");

        assert_eq!(bytes_written, test_data.len() as u64);
        assert_eq!(decrypted_buffer, test_data);
    }

    #[test]
    fn test_empty_file_streaming_round_trip() {
        let key = AttachmentKey::generate();
        let attachment_id = "test-uuid-empty";
        let reader = Cursor::new(Vec::new());

        let params =
            AttachmentEncryptParams::new(attachment_id, "empty.bin", "application/octet-stream")
                .with_chunk_size(1024);
        let (manifest, chunks) =
            encrypt_attachment_stream(reader, 0, &params, &key).expect("encrypt empty stream");

        assert_eq!(manifest.size, 0);
        assert_eq!(manifest.chunk_count, 1);
        assert_eq!(chunks.len(), 1);

        let mut decrypted_buffer = Vec::new();
        let bytes_written = decrypt_attachment_stream_with_source(
            chunks,
            &key,
            Some(&manifest),
            &mut decrypted_buffer,
        )
        .expect("decrypt empty stream");

        assert_eq!(bytes_written, 0);
        assert!(decrypted_buffer.is_empty());
    }

    #[test]
    fn test_corrupted_chunk_fails_closed() {
        let key = AttachmentKey::generate();
        let attachment_id = "test-uuid-corrupt";
        let test_data = b"Testing corrupted chunk detection in streaming decryptor.";
        let reader = Cursor::new(test_data.to_vec());

        let params =
            AttachmentEncryptParams::new(attachment_id, "data.bin", "application/octet-stream")
                .with_chunk_size(8);
        let (manifest, mut chunks) =
            encrypt_attachment_stream(reader, test_data.len() as u64, &params, &key)
                .expect("encrypt stream");

        // Corrupt ciphertext in chunk 1
        use base64ct::{Base64, Encoding};
        let mut ct_bytes = Base64::decode_vec(&chunks[1].ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        chunks[1].ciphertext = Base64::encode_string(&ct_bytes);

        let mut out = Vec::new();
        let res = decrypt_attachment_stream_with_source(chunks, &key, Some(&manifest), &mut out);

        assert!(matches!(
            res,
            Err(CoreError::Crypto(
                zk_crypto::error::CryptoError::DecryptionFailed
            ))
        ));
    }

    #[test]
    fn test_out_of_order_chunk_fails_closed() {
        let key = AttachmentKey::generate();
        let attachment_id = "test-uuid-order";
        let test_data = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let reader = Cursor::new(test_data.to_vec());

        let params =
            AttachmentEncryptParams::new(attachment_id, "data.bin", "application/octet-stream")
                .with_chunk_size(8);
        let (manifest, mut chunks) =
            encrypt_attachment_stream(reader, test_data.len() as u64, &params, &key)
                .expect("encrypt stream");

        // Swap chunk 0 and chunk 1
        chunks.swap(0, 1);

        let mut out = Vec::new();
        let res = decrypt_attachment_stream_with_source(chunks, &key, Some(&manifest), &mut out);

        assert!(matches!(
            res,
            Err(CoreError::Attachment(
                AttachmentError::ChunkOutOfOrder { .. }
            ))
        ));
    }

    #[test]
    fn test_missing_chunk_fails_closed() {
        let key = AttachmentKey::generate();
        let attachment_id = "test-uuid-missing";
        let test_data = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let reader = Cursor::new(test_data.to_vec());

        let params =
            AttachmentEncryptParams::new(attachment_id, "data.bin", "application/octet-stream")
                .with_chunk_size(8);
        let (manifest, mut chunks) =
            encrypt_attachment_stream(reader, test_data.len() as u64, &params, &key)
                .expect("encrypt stream");

        // Remove last chunk
        chunks.pop();

        let mut out = Vec::new();
        let res = decrypt_attachment_stream_with_source(chunks, &key, Some(&manifest), &mut out);

        assert!(matches!(
            res,
            Err(CoreError::Attachment(
                AttachmentError::ChunkCountMismatch { .. }
            ))
        ));
    }

    #[test]
    fn test_file_size_exceeding_max_rejected() {
        let key = AttachmentKey::generate();
        let dummy = Cursor::new(Vec::new());

        let params =
            AttachmentEncryptParams::new("att-oversize", "huge.bin", "application/octet-stream")
                .with_chunk_size(1024);
        let res = encrypt_attachment_stream(dummy, MAX_ATTACHMENT_SIZE + 1, &params, &key);

        assert!(matches!(
            res,
            Err(CoreError::Attachment(AttachmentError::FileTooLarge { .. }))
        ));
    }

    #[test]
    fn test_file_to_file_streaming_round_trip() {
        let key = AttachmentKey::generate();
        let temp_dir = std::env::temp_dir().join(format!("zk_att_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let src_path = temp_dir.join("input.bin");
        let dst_path = temp_dir.join("output.bin");

        let content = b"End-to-end file streaming attachment encryption and decryption test.";
        std::fs::write(&src_path, content).unwrap();

        let (manifest, chunks) = encrypt_attachment_file(
            &src_path,
            "att-file-test",
            &key,
            Some("input.bin"),
            Some("application/octet-stream"),
            Some(16),
        )
        .expect("encrypt file");

        let written = decrypt_attachment_to_file(&chunks, &key, Some(&manifest), &dst_path)
            .expect("decrypt to file");

        assert_eq!(written, content.len() as u64);
        let read_back = std::fs::read(&dst_path).unwrap();
        assert_eq!(read_back, content);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_attachment_manifest_envelope_round_trip() {
        let vault_key = VaultKey::generate();
        let attachment_key = AttachmentKey::generate();
        let attachment_id = "test-manifest-uuid-123";

        let manifest = AttachmentManifest {
            attachment_id: attachment_id.to_string(),
            name: "design_spec.pdf".to_string(),
            mime: "application/pdf".to_string(),
            size: 2048576,
            chunk_count: 1,
            chunk_size: 4194304,
            content_hash: Some("abcdef0123456789".to_string()),
        };

        // 1. Encrypt manifest into envelope
        let envelope = encrypt_attachment_manifest(&manifest, &attachment_key, &vault_key)
            .expect("encrypt manifest");
        assert_eq!(envelope.object_id, attachment_id);
        assert_eq!(
            envelope.object_kind,
            zk_protocol::constants::OBJECT_KIND_ATTACHMENT_MANIFEST
        );

        // 2. Decrypt manifest from envelope
        let (decrypted_manifest, decrypted_key) =
            decrypt_attachment_manifest(&envelope, &vault_key).expect("decrypt manifest");
        assert_eq!(decrypted_manifest, manifest);
        assert_eq!(decrypted_key, attachment_key);

        // 3. Wrong vault key fails closed
        let wrong_vault_key = VaultKey::generate();
        let wrong_res = decrypt_attachment_manifest(&envelope, &wrong_vault_key);
        assert!(wrong_res.is_err());

        // 4. Tampered payload fails closed
        let mut tampered_envelope = envelope.clone();
        let mut ct_bytes =
            base64ct::Base64::decode_vec(&tampered_envelope.payload.ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        tampered_envelope.payload.ciphertext = base64ct::Base64::encode_string(&ct_bytes);
        assert!(decrypt_attachment_manifest(&tampered_envelope, &vault_key).is_err());

        // 5. Tampered wrapped key fails closed
        let mut tampered_key_envelope = envelope.clone();
        let mut key_ct_bytes =
            base64ct::Base64::decode_vec(&tampered_key_envelope.wrapped_key.ciphertext).unwrap();
        key_ct_bytes[0] ^= 0xff;
        tampered_key_envelope.wrapped_key.ciphertext =
            base64ct::Base64::encode_string(&key_ct_bytes);
        assert!(decrypt_attachment_manifest(&tampered_key_envelope, &vault_key).is_err());
    }

    #[test]
    fn test_note_attachment_add_remove_and_orphan_cleanup() {
        let mut note = PlaintextNote::new("Test Title", "Test Body");
        assert!(note.attachments.is_empty());

        let att_1 = "att-id-alpha";
        let att_2 = "att-id-beta";

        // 1. Add attachment 1
        add_attachment_to_note(&mut note, att_1).expect("add att_1");
        assert_eq!(note.attachments, vec![att_1]);

        // 2. Duplicate add is a no-op
        add_attachment_to_note(&mut note, att_1).expect("duplicate add");
        assert_eq!(note.attachments, vec![att_1]);

        // 3. Add attachment 2
        add_attachment_to_note(&mut note, att_2).expect("add att_2");
        assert_eq!(note.attachments, vec![att_1, att_2]);

        // 4. Orphan detection
        let stored_ids = vec![
            att_1.to_string(),
            att_2.to_string(),
            "att-id-gamma-orphaned".to_string(),
        ];
        let orphaned = find_orphaned_attachments(&[note.clone()], &stored_ids);
        assert_eq!(orphaned, vec!["att-id-gamma-orphaned"]);

        // 5. Remove attachment 1
        let removed = remove_attachment_from_note(&mut note, att_1);
        assert!(removed);
        assert_eq!(note.attachments, vec![att_2]);

        // 6. Remove again returns false
        let removed_again = remove_attachment_from_note(&mut note, att_1);
        assert!(!removed_again);

        // 7. Orphan detection now shows att_1 as orphaned
        let orphaned2 = find_orphaned_attachments(&[note], &stored_ids);
        assert_eq!(orphaned2, vec![att_1, "att-id-gamma-orphaned"]);
    }
}
