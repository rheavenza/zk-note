//! Protocol models, chunk containers, and binary serialization for encrypted attachments (M8 / ZK-080).
//!
//! In accordance with MASTER_SPEC.md § 14, SEC-001, and SEC-002:
//! - Attachment keys, plaintext filenames, MIME types, and contents NEVER cross to the server.
//! - Chunks are encrypted with unique nonces and bound to attachment ID and chunk index via AAD.
//! - Server blob store only operates on opaque IDs and ciphertext chunks.

use crate::constants::ATTACHMENT_CHUNK_VERSION_V1;
use core::fmt;
use serde::{Deserialize, Serialize};

/// 4-byte magic header for binary serialized attachment chunks ("ZKCK").
pub const CHUNK_BINARY_MAGIC: [u8; 4] = *b"ZKCK";

/// Errors occurring during binary chunk parsing or validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkFormatError {
    /// Provided buffer was too short for the required headers.
    Truncated { expected: usize, actual: usize },
    /// Magic byte sequence did not match [`CHUNK_BINARY_MAGIC`].
    InvalidMagic,
    /// Attachment ID string contained invalid UTF-8.
    InvalidUtf8,
    /// Base64 decoding or encoding failed.
    InvalidEncoding(String),
}

impl fmt::Display for ChunkFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { expected, actual } => {
                write!(
                    f,
                    "truncated chunk buffer: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::InvalidMagic => write!(f, "invalid binary chunk magic bytes (expected 'ZKCK')"),
            Self::InvalidUtf8 => write!(f, "attachment ID in binary chunk is not valid UTF-8"),
            Self::InvalidEncoding(msg) => write!(f, "invalid chunk encoding: {msg}"),
        }
    }
}

impl std::error::Error for ChunkFormatError {}

/// Versioned encrypted attachment chunk container.
///
/// Supports both JSON serialization (via Serde) and compact binary wire serialization
/// ([`EncryptedChunk::to_bytes`] / [`EncryptedChunk::from_bytes`]) for streaming high-throughput blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedChunk {
    /// Format version of the chunk envelope (e.g. 1).
    pub version: u32,
    /// Canonical attachment UUID that this chunk belongs to.
    pub attachment_id: String,
    /// 0-indexed sequence number of this chunk within the attachment.
    pub chunk_index: u32,
    /// Total number of chunks comprising this attachment.
    pub total_chunks: u32,
    /// Base64 standard encoded 24-byte XChaCha20 nonce.
    pub nonce: String,
    /// Base64 standard encoded ciphertext + 16-byte Poly1305 authentication tag.
    pub ciphertext: String,
}

impl EncryptedChunk {
    /// Creates a new [`EncryptedChunk`] with default version 1.
    #[must_use]
    pub fn new(
        attachment_id: impl Into<String>,
        chunk_index: u32,
        total_chunks: u32,
        nonce: impl Into<String>,
        ciphertext: impl Into<String>,
    ) -> Self {
        Self {
            version: ATTACHMENT_CHUNK_VERSION_V1,
            attachment_id: attachment_id.into(),
            chunk_index,
            total_chunks,
            nonce: nonce.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// Serializes this chunk to a compact binary wire format:
    ///
    /// `[magic: 4][version: 4][id_len: 2][id: N][chunk_idx: 4][total_chunks: 4][nonce: 24][ct_len: 4][ct: M]`
    pub fn to_bytes(&self) -> Result<Vec<u8>, ChunkFormatError> {
        use base64ct::{Base64, Encoding};

        let mut nonce_bytes = [0u8; 24];
        let decoded_nonce = Base64::decode(&self.nonce, &mut nonce_bytes)
            .map_err(|e| ChunkFormatError::InvalidEncoding(format!("invalid nonce base64: {e}")))?;

        let ct_bytes = Base64::decode_vec(&self.ciphertext).map_err(|e| {
            ChunkFormatError::InvalidEncoding(format!("invalid ciphertext base64: {e}"))
        })?;

        let id_bytes = self.attachment_id.as_bytes();
        let total_size =
            4 + 4 + 2 + id_bytes.len() + 4 + 4 + decoded_nonce.len() + 4 + ct_bytes.len();
        let mut out = Vec::with_capacity(total_size);

        out.extend_from_slice(&CHUNK_BINARY_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(id_bytes);
        out.extend_from_slice(&self.chunk_index.to_be_bytes());
        out.extend_from_slice(&self.total_chunks.to_be_bytes());
        out.extend_from_slice(decoded_nonce);
        out.extend_from_slice(&(ct_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct_bytes);

        Ok(out)
    }

    /// Deserializes an [`EncryptedChunk`] from binary wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChunkFormatError> {
        use base64ct::{Base64, Encoding};

        // Minimum required: 4(magic) + 4(version) + 2(id_len) + 4(idx) + 4(total) + 24(nonce) + 4(ct_len) = 46 bytes
        if bytes.len() < 46 {
            return Err(ChunkFormatError::Truncated {
                expected: 46,
                actual: bytes.len(),
            });
        }

        if bytes[0..4] != CHUNK_BINARY_MAGIC {
            return Err(ChunkFormatError::InvalidMagic);
        }

        let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let id_len = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;

        let mut offset = 10;
        if bytes.len() < offset + id_len + 8 + 24 + 4 {
            return Err(ChunkFormatError::Truncated {
                expected: offset + id_len + 36,
                actual: bytes.len(),
            });
        }

        let attachment_id = core::str::from_utf8(&bytes[offset..offset + id_len])
            .map_err(|_| ChunkFormatError::InvalidUtf8)?
            .to_string();
        offset += id_len;

        let chunk_index = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;
        let total_chunks = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let nonce = Base64::encode_string(&bytes[offset..offset + 24]);
        offset += 24;

        let ct_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if bytes.len() < offset + ct_len {
            return Err(ChunkFormatError::Truncated {
                expected: offset + ct_len,
                actual: bytes.len(),
            });
        }

        let ciphertext = Base64::encode_string(&bytes[offset..offset + ct_len]);

        Ok(Self {
            version,
            attachment_id,
            chunk_index,
            total_chunks,
            nonce,
            ciphertext,
        })
    }
}

/// Plaintext metadata manifest for an attachment (stored exclusively inside client-side encrypted envelopes).
///
/// In accordance with SEC-001 / SEC-002, the server NEVER possesses:
/// - attachment names;
/// - MIME types;
/// - plaintext size;
/// - content hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentManifest {
    /// Canonical attachment UUID.
    pub attachment_id: String,
    /// Client-side plaintext filename (e.g. "blueprint.png").
    pub name: String,
    /// Client-side plaintext MIME type (e.g. "image/png").
    pub mime: String,
    /// Total plaintext size in bytes.
    pub size: u64,
    /// Number of encrypted chunks comprising this attachment.
    pub chunk_count: u32,
    /// Standard target chunk size in bytes (e.g. 4,194,304).
    pub chunk_size: u32,
    /// Optional local integrity metadata (e.g. BLAKE2b/SHA-256 hex string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_json_round_trip() {
        let chunk = EncryptedChunk::new(
            "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            0,
            3,
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY",
            "dGVzdCBjaXBoZXJ0ZXh0IHdpdGggYXV0aCB0YWc=",
        );

        let json = serde_json::to_string(&chunk).expect("serialize");
        let parsed: EncryptedChunk = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, chunk);
    }

    #[test]
    fn test_chunk_binary_round_trip() {
        let chunk = EncryptedChunk::new(
            "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            1,
            5,
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY",
            "dGVzdCBjaXBoZXJ0ZXh0IHdpdGggYXV0aCB0YWc=",
        );

        let bytes = chunk.to_bytes().expect("to_bytes");
        assert_eq!(&bytes[0..4], &CHUNK_BINARY_MAGIC);

        let decoded = EncryptedChunk::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn test_chunk_binary_corrupted_magic_rejected() {
        let chunk = EncryptedChunk::new(
            "att-123",
            0,
            1,
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY",
            "dGVzdA==",
        );
        let mut bytes = chunk.to_bytes().unwrap();
        bytes[0] = b'X';
        assert_eq!(
            EncryptedChunk::from_bytes(&bytes).unwrap_err(),
            ChunkFormatError::InvalidMagic
        );
    }

    #[test]
    fn test_attachment_manifest_round_trip() {
        let manifest = AttachmentManifest {
            attachment_id: "att-uuid-1234".to_string(),
            name: "report.pdf".to_string(),
            mime: "application/pdf".to_string(),
            size: 1048576,
            chunk_count: 1,
            chunk_size: 4194304,
            content_hash: Some("abcd1234ef5678".to_string()),
        };

        let json = serde_json::to_string(&manifest).expect("serialize manifest");
        let parsed: AttachmentManifest = serde_json::from_str(&json).expect("deserialize manifest");
        assert_eq!(parsed, manifest);
    }
}
