//! Plaintext note domain model, validation limits, canonicalization,
//! deterministic serialization, and cryptographic envelope orchestration.

use crate::error::{CoreError, NoteValidationError};
use crate::time::{now_utc_rfc3339, validate_rfc3339};
use serde::{Deserialize, Serialize};
use zk_crypto::keys::VaultKey;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::EncryptedEnvelope;

/// Active plaintext note schema version.
pub const NOTE_SCHEMA_VERSION_V1: u32 = 1;

/// Maximum permitted length of a note title in bytes (1024 bytes / 1 KiB).
pub const MAX_TITLE_LEN: usize = 1024;

/// Maximum permitted size of a note body in bytes (10 MiB / 10,485,760 bytes).
pub const MAX_BODY_LEN: usize = 10 * 1024 * 1024;

/// Maximum number of tags allowed per note.
pub const MAX_TAGS_COUNT: usize = 100;

/// Maximum permitted length of a single tag in bytes (128 bytes).
pub const MAX_TAG_LEN: usize = 128;

/// Maximum number of attachment identifiers allowed per note.
pub const MAX_ATTACHMENTS_COUNT: usize = 100;

/// Maximum permitted length of an attachment identifier in bytes (128 bytes).
pub const MAX_ATTACHMENT_ID_LEN: usize = 128;

/// Plaintext note domain model.
///
/// Encapsulates the user's decrypted note content and client metadata.
/// All fields are encrypted end-to-end when persisted or transmitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaintextNote {
    /// Note schema version (must be [`NOTE_SCHEMA_VERSION_V1`]).
    pub schema_version: u32,
    /// Note title.
    pub title: String,
    /// Note body in Markdown format with normalized Unix newlines.
    pub body: String,
    /// Note tags (canonicalized: trimmed, lowercase, deduplicated, sorted).
    pub tags: Vec<String>,
    /// Creation timestamp in RFC 3339 UTC format.
    pub created_at: String,
    /// Last update timestamp in RFC 3339 UTC format.
    pub updated_at: String,
    /// Attachment identifiers placeholder.
    #[serde(default)]
    pub attachments: Vec<String>,
}

/// Convenience alias for [`PlaintextNote`].
pub type Note = PlaintextNote;

impl PlaintextNote {
    /// Creates a new note with default schema version (1) and timestamps set to the current UTC time.
    #[must_use]
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        let now = now_utc_rfc3339();
        Self {
            schema_version: NOTE_SCHEMA_VERSION_V1,
            title: title.into(),
            body: body.into(),
            tags: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
            attachments: Vec::new(),
        }
    }

    /// Returns a [`NoteBuilder`] to construct a note with custom fields.
    #[must_use]
    pub fn builder() -> NoteBuilder {
        NoteBuilder::new()
    }

    /// Canonicalizes the note's fields in-place according to protocol expectations:
    /// - Strips UTF-8 BOM from title and body if present.
    /// - Normalizes all newlines in body to Unix newlines (`\n`).
    /// - Canonicalizes tags: trims whitespace, converts to lowercase, filters empty strings,
    ///   deduplicates, and sorts lexicographically.
    pub fn canonicalize(&mut self) {
        // Strip UTF-8 BOM if present
        if self.title.starts_with('\u{feff}') {
            self.title = self.title.trim_start_matches('\u{feff}').to_string();
        }
        if self.body.starts_with('\u{feff}') {
            self.body = self.body.trim_start_matches('\u{feff}').to_string();
        }

        // Normalize newlines in body: \r\n -> \n, \r -> \n
        if self.body.contains('\r') {
            self.body = self.body.replace("\r\n", "\n").replace('\r', "\n");
        }

        // Canonicalize tags: trim, lowercase, filter empty, deduplicate, sort
        let mut normalized_tags = Vec::with_capacity(self.tags.len());
        for tag in &self.tags {
            let trimmed = tag.trim().to_lowercase();
            if !trimmed.is_empty() {
                normalized_tags.push(trimmed);
            }
        }
        normalized_tags.sort();
        normalized_tags.dedup();
        self.tags = normalized_tags;
    }

    /// Validates the note against all domain limits and invariants.
    ///
    /// Fails with a [`NoteValidationError`] if:
    /// - `schema_version` is not [`NOTE_SCHEMA_VERSION_V1`];
    /// - `title` exceeds [`MAX_TITLE_LEN`] bytes;
    /// - `body` exceeds [`MAX_BODY_LEN`] bytes;
    /// - `tags` count exceeds [`MAX_TAGS_COUNT`];
    /// - any tag is empty, exceeds [`MAX_TAG_LEN`] bytes, or contains control characters;
    /// - `attachments` count exceeds [`MAX_ATTACHMENTS_COUNT`];
    /// - any attachment identifier is empty, exceeds [`MAX_ATTACHMENT_ID_LEN`] bytes,
    ///   or contains control characters;
    /// - `created_at` or `updated_at` does not conform to RFC 3339.
    pub fn validate(&self) -> Result<(), NoteValidationError> {
        if self.schema_version != NOTE_SCHEMA_VERSION_V1 {
            return Err(NoteValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }

        if self.title.len() > MAX_TITLE_LEN {
            return Err(NoteValidationError::TitleTooLong {
                max: MAX_TITLE_LEN,
                actual: self.title.len(),
            });
        }

        if self.body.len() > MAX_BODY_LEN {
            return Err(NoteValidationError::BodyTooLarge {
                max: MAX_BODY_LEN,
                actual: self.body.len(),
            });
        }

        if self.tags.len() > MAX_TAGS_COUNT {
            return Err(NoteValidationError::TooManyTags {
                max: MAX_TAGS_COUNT,
                actual: self.tags.len(),
            });
        }

        for tag in &self.tags {
            if tag.is_empty() {
                return Err(NoteValidationError::EmptyTag);
            }
            if tag.len() > MAX_TAG_LEN {
                return Err(NoteValidationError::TagTooLong {
                    max: MAX_TAG_LEN,
                    actual: tag.len(),
                });
            }
            if tag.chars().any(|c| c.is_control()) {
                return Err(NoteValidationError::InvalidTag(tag.clone()));
            }
        }

        if self.attachments.len() > MAX_ATTACHMENTS_COUNT {
            return Err(NoteValidationError::TooManyAttachments {
                max: MAX_ATTACHMENTS_COUNT,
                actual: self.attachments.len(),
            });
        }

        for att in &self.attachments {
            if att.is_empty() {
                return Err(NoteValidationError::EmptyAttachmentId);
            }
            if att.len() > MAX_ATTACHMENT_ID_LEN {
                return Err(NoteValidationError::AttachmentIdTooLong {
                    max: MAX_ATTACHMENT_ID_LEN,
                    actual: att.len(),
                });
            }
            if att.chars().any(|c| c.is_control()) {
                return Err(NoteValidationError::InvalidAttachmentId(att.clone()));
            }
        }

        validate_rfc3339("created_at", &self.created_at)?;
        validate_rfc3339("updated_at", &self.updated_at)?;

        Ok(())
    }

    /// Serializes the note to a deterministic canonical JSON string.
    ///
    /// Canonicalizes fields and performs validation before serialization.
    pub fn to_canonical_json(&self) -> Result<String, NoteValidationError> {
        let mut note = self.clone();
        note.canonicalize();
        note.validate()?;
        serde_json::to_string(&note)
            .map_err(|e| NoteValidationError::SerializationError(e.to_string()))
    }

    /// Serializes the note to deterministic canonical JSON bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, NoteValidationError> {
        let json = self.to_canonical_json()?;
        Ok(json.into_bytes())
    }

    /// Parses and validates a [`PlaintextNote`] from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, NoteValidationError> {
        let note: Self = serde_json::from_str(json_str)
            .map_err(|e| NoteValidationError::SerializationError(e.to_string()))?;
        note.validate()?;
        Ok(note)
    }

    /// Parses and validates a [`PlaintextNote`] from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoteValidationError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|e| NoteValidationError::SerializationError(format!("invalid UTF-8: {e}")))?;
        Self::from_json(s)
    }

    /// Encrypts this note into an [`EncryptedEnvelope`].
    ///
    /// Canonicalizes and validates the note, serializes it to canonical JSON bytes,
    /// and encrypts it using [`zk_crypto::object::encrypt_envelope`].
    pub fn encrypt(
        &self,
        vault_key: &VaultKey,
        object_id: &str,
    ) -> Result<EncryptedEnvelope, CoreError> {
        let plaintext_bytes = self.to_canonical_bytes()?;
        let envelope = zk_crypto::object::encrypt_envelope(
            &plaintext_bytes,
            vault_key,
            object_id,
            OBJECT_KIND_NOTE,
        )?;
        Ok(envelope)
    }

    /// Decrypts an [`EncryptedEnvelope`] into a [`PlaintextNote`].
    ///
    /// Decrypts the payload using [`zk_crypto::object::decrypt_envelope`],
    /// parses the canonical JSON, and validates the note domain model.
    pub fn decrypt(envelope: &EncryptedEnvelope, vault_key: &VaultKey) -> Result<Self, CoreError> {
        if envelope.envelope_version != ENVELOPE_VERSION_V1 {
            return Err(CoreError::Crypto(
                zk_crypto::error::CryptoError::UnsupportedVersion(envelope.envelope_version),
            ));
        }
        if envelope.object_kind != OBJECT_KIND_NOTE {
            return Err(CoreError::Validation(
                NoteValidationError::SerializationError(format!(
                    "expected object kind NOTE ({OBJECT_KIND_NOTE}), got {}",
                    envelope.object_kind
                )),
            ));
        }

        let decrypted_bytes = zk_crypto::object::decrypt_envelope(envelope, vault_key)?;
        let note = Self::from_bytes(&decrypted_bytes)?;
        Ok(note)
    }
}

impl From<zk_protocol::note::PlaintextNote> for PlaintextNote {
    fn from(proto: zk_protocol::note::PlaintextNote) -> Self {
        Self {
            schema_version: proto.schema_version,
            title: proto.title,
            body: proto.body,
            tags: proto.tags,
            created_at: proto.created_at,
            updated_at: proto.updated_at,
            attachments: proto.attachments,
        }
    }
}

impl From<PlaintextNote> for zk_protocol::note::PlaintextNote {
    fn from(note: PlaintextNote) -> Self {
        Self {
            schema_version: note.schema_version,
            title: note.title,
            body: note.body,
            tags: note.tags,
            created_at: note.created_at,
            updated_at: note.updated_at,
            attachments: note.attachments,
        }
    }
}

/// Fluent builder for creating validated [`PlaintextNote`] instances.
#[derive(Debug, Default, Clone)]
pub struct NoteBuilder {
    schema_version: Option<u32>,
    title: String,
    body: String,
    tags: Vec<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    attachments: Vec<String>,
}

impl NoteBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the note title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Sets the note body (Markdown format).
    #[must_use]
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the note tags.
    #[must_use]
    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a single tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Sets the creation timestamp in RFC 3339 format.
    #[must_use]
    pub fn created_at(mut self, timestamp: impl Into<String>) -> Self {
        self.created_at = Some(timestamp.into());
        self
    }

    /// Sets the update timestamp in RFC 3339 format.
    #[must_use]
    pub fn updated_at(mut self, timestamp: impl Into<String>) -> Self {
        self.updated_at = Some(timestamp.into());
        self
    }

    /// Sets the attachment identifiers.
    #[must_use]
    pub fn attachments(mut self, attachments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.attachments = attachments.into_iter().map(Into::into).collect();
        self
    }

    /// Overrides the schema version (for testing version rejection).
    #[must_use]
    pub fn schema_version(mut self, version: u32) -> Self {
        self.schema_version = Some(version);
        self
    }

    /// Builds, canonicalizes, and validates the [`PlaintextNote`].
    pub fn build(self) -> Result<PlaintextNote, NoteValidationError> {
        let now = now_utc_rfc3339();
        let mut note = PlaintextNote {
            schema_version: self.schema_version.unwrap_or(NOTE_SCHEMA_VERSION_V1),
            title: self.title,
            body: self.body,
            tags: self.tags,
            created_at: self.created_at.unwrap_or_else(|| now.clone()),
            updated_at: self.updated_at.unwrap_or(now),
            attachments: self.attachments,
        };
        note.canonicalize();
        note.validate()?;
        Ok(note)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_note_new_and_defaults() {
        let note = PlaintextNote::new("Default Title", "Default Body");
        assert_eq!(note.schema_version, NOTE_SCHEMA_VERSION_V1);
        assert_eq!(note.title, "Default Title");
        assert_eq!(note.body, "Default Body");
        assert!(note.tags.is_empty());
        assert!(note.attachments.is_empty());
        assert!(note.validate().is_ok());
    }

    #[test]
    fn test_note_builder() {
        let note = PlaintextNote::builder()
            .title("Builder Title")
            .body("# Heading\n\nContent.")
            .tag("rust")
            .tag("zero-knowledge")
            .created_at("2026-09-09T05:00:00.000Z")
            .updated_at("2026-09-09T05:30:00.000Z")
            .attachments(vec!["att-1", "att-2"])
            .build()
            .expect("valid build");

        assert_eq!(note.schema_version, 1);
        assert_eq!(note.title, "Builder Title");
        assert_eq!(note.tags, vec!["rust", "zero-knowledge"]);
        assert_eq!(note.attachments, vec!["att-1", "att-2"]);
    }

    #[test]
    fn test_canonicalization_newlines_and_tags() {
        let mut note = PlaintextNote::builder()
            .title("\u{feff}BOM Title")
            .body("\u{feff}Line 1\r\nLine 2\rLine 3\nLine 4")
            .tags(vec![
                "  Security  ",
                "SECURITY",
                "architecture",
                "  ",
                "alpha",
            ])
            .created_at("2026-09-09T05:00:00Z")
            .updated_at("2026-09-09T05:00:00Z")
            .build()
            .expect("build");

        note.canonicalize();

        // Title and body BOM stripped
        assert_eq!(note.title, "BOM Title");
        assert_eq!(note.body, "Line 1\nLine 2\nLine 3\nLine 4");

        // Tags trimmed, lowercase, deduplicated, sorted alphabetically
        assert_eq!(note.tags, vec!["alpha", "architecture", "security"]);
    }

    #[test]
    fn test_deterministic_serialization() {
        let note1 = PlaintextNote::builder()
            .title("Deterministic Note")
            .body("Same body content.")
            .tags(vec!["zebra", "apple", "banana"])
            .created_at("2026-09-09T05:00:00.000Z")
            .updated_at("2026-09-09T05:30:00.000Z")
            .build()
            .expect("note1 build");

        let note2 = PlaintextNote::builder()
            .title("Deterministic Note")
            .body("Same body content.")
            .tags(vec!["banana", "zebra", "apple"]) // different tag insertion order
            .created_at("2026-09-09T05:00:00.000Z")
            .updated_at("2026-09-09T05:30:00.000Z")
            .build()
            .expect("note2 build");

        let json1 = note1.to_canonical_json().expect("json1");
        let json2 = note2.to_canonical_json().expect("json2");

        assert_eq!(json1, json2);

        // Verify round-trip parsing
        let parsed = PlaintextNote::from_json(&json1).expect("parse json");
        assert_eq!(note1, parsed);
    }

    #[test]
    fn test_validation_unsupported_schema_version() {
        let err = PlaintextNote::builder()
            .schema_version(2)
            .title("Bad Version")
            .body("Body")
            .build()
            .unwrap_err();

        assert_eq!(err, NoteValidationError::UnsupportedSchemaVersion(2));
    }

    #[test]
    fn test_validation_title_length_limit() {
        let long_title = "A".repeat(MAX_TITLE_LEN + 1);
        let err = PlaintextNote::builder()
            .title(long_title)
            .body("Body")
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            NoteValidationError::TitleTooLong {
                max: MAX_TITLE_LEN,
                actual: MAX_TITLE_LEN + 1,
            }
        );
    }

    #[test]
    fn test_validation_body_size_limit() {
        let mut note = PlaintextNote::new("Large Body", "");
        note.body = "A".repeat(MAX_BODY_LEN + 1);
        let err = note.validate().unwrap_err();

        assert_eq!(
            err,
            NoteValidationError::BodyTooLarge {
                max: MAX_BODY_LEN,
                actual: MAX_BODY_LEN + 1,
            }
        );
    }

    #[test]
    fn test_validation_tags_limits() {
        // Exceed max tags count
        let mut note = PlaintextNote::new("Tags limit", "body");
        note.tags = (0..MAX_TAGS_COUNT + 1).map(|i| format!("tag{i}")).collect();
        assert_eq!(
            note.validate().unwrap_err(),
            NoteValidationError::TooManyTags {
                max: MAX_TAGS_COUNT,
                actual: MAX_TAGS_COUNT + 1,
            }
        );

        // Tag too long
        let mut note2 = PlaintextNote::new("Long tag", "body");
        note2.tags = vec!["A".repeat(MAX_TAG_LEN + 1)];
        assert_eq!(
            note2.validate().unwrap_err(),
            NoteValidationError::TagTooLong {
                max: MAX_TAG_LEN,
                actual: MAX_TAG_LEN + 1,
            }
        );

        // Tag with control characters
        let mut note3 = PlaintextNote::new("Bad tag", "body");
        note3.tags = vec!["tag\nwith\nnewline".to_string()];
        assert_eq!(
            note3.validate().unwrap_err(),
            NoteValidationError::InvalidTag("tag\nwith\nnewline".to_string())
        );
    }

    #[test]
    fn test_validation_attachments_limits() {
        // Exceed max attachments
        let mut note = PlaintextNote::new("Attachments limit", "body");
        note.attachments = (0..MAX_ATTACHMENTS_COUNT + 1)
            .map(|i| format!("att{i}"))
            .collect();
        assert_eq!(
            note.validate().unwrap_err(),
            NoteValidationError::TooManyAttachments {
                max: MAX_ATTACHMENTS_COUNT,
                actual: MAX_ATTACHMENTS_COUNT + 1,
            }
        );

        // Empty attachment ID
        let mut note2 = PlaintextNote::new("Empty att", "body");
        note2.attachments = vec!["".to_string()];
        assert_eq!(
            note2.validate().unwrap_err(),
            NoteValidationError::EmptyAttachmentId
        );

        // Attachment ID too long
        let mut note3 = PlaintextNote::new("Long att", "body");
        note3.attachments = vec!["X".repeat(MAX_ATTACHMENT_ID_LEN + 1)];
        assert_eq!(
            note3.validate().unwrap_err(),
            NoteValidationError::AttachmentIdTooLong {
                max: MAX_ATTACHMENT_ID_LEN,
                actual: MAX_ATTACHMENT_ID_LEN + 1,
            }
        );
    }

    #[test]
    fn test_validation_invalid_timestamp() {
        let err = PlaintextNote::builder()
            .title("Bad Timestamp")
            .body("Body")
            .created_at("invalid-date")
            .build()
            .unwrap_err();

        match err {
            NoteValidationError::InvalidTimestamp { field, .. } => {
                assert_eq!(field, "created_at");
            }
            other => panic!("expected InvalidTimestamp error, got {other:?}"),
        }
    }

    #[test]
    fn test_note_encryption_round_trip() {
        let vault_key = VaultKey::generate();
        let object_id = "550e8400-e29b-41d4-a716-446655440000";

        let note = PlaintextNote::builder()
            .title("Encrypted Note")
            .body("Confidential zero-knowledge note body.")
            .tags(vec!["crypto", "privacy"])
            .attachments(vec!["attachment-123"])
            .build()
            .expect("build note");

        // Encrypt into protocol envelope
        let envelope = note.encrypt(&vault_key, object_id).expect("encrypt note");

        assert_eq!(envelope.envelope_version, ENVELOPE_VERSION_V1);
        assert_eq!(envelope.object_id, object_id);
        assert_eq!(envelope.object_kind, OBJECT_KIND_NOTE);

        // Decrypt from protocol envelope
        let decrypted = PlaintextNote::decrypt(&envelope, &vault_key).expect("decrypt note");
        assert_eq!(note, decrypted);

        // Wrong vault key fails closed
        let wrong_vk = VaultKey::generate();
        assert!(PlaintextNote::decrypt(&envelope, &wrong_vk).is_err());
    }

    #[test]
    fn test_protocol_conversion_round_trip() {
        let note = PlaintextNote::new("Conversion Title", "Conversion Body");
        let proto: zk_protocol::note::PlaintextNote = note.clone().into();
        let back: PlaintextNote = proto.into();
        assert_eq!(note, back);
    }
}
