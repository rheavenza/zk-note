//! Kind-aware validation of restored active ciphertext, without retaining plaintext.
//! Reserved notebook/settings kinds have no shipped plaintext model yet and fail closed.
use crate::{attachment::decrypt_attachment_manifest, PlaintextNote};
use std::fmt;
use zeroize::Zeroize;
use zk_crypto::keys::VaultKey;
use zk_protocol::{
    constants::{OBJECT_KIND_ATTACHMENT_MANIFEST, OBJECT_KIND_NOTE},
    envelope::EncryptedEnvelope,
};

/// Safe diagnostics: underlying decoder errors can contain decrypted metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectValidationError {
    UnsupportedKind(u16),
    InvalidEnvelope,
}
impl fmt::Display for ObjectValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKind(_) => f.write_str("unsupported restored object kind"),
            Self::InvalidEnvelope => f.write_str("restored object validation failed"),
        }
    }
}
impl std::error::Error for ObjectValidationError {}

/// Authenticate and decode each shipped object kind with its existing typed decoder.
/// Successfully decoded metadata exists only temporarily in memory and is scrubbed.
pub fn validate_active_object(
    envelope: &EncryptedEnvelope,
    key: &VaultKey,
) -> Result<(), ObjectValidationError> {
    match envelope.object_kind {
        OBJECT_KIND_NOTE => {
            let mut note = PlaintextNote::decrypt(envelope, key)
                .map_err(|_| ObjectValidationError::InvalidEnvelope)?;
            note.title.zeroize();
            note.body.zeroize();
            note.tags.zeroize();
            note.attachments.zeroize();
            note.created_at.zeroize();
            note.updated_at.zeroize();
        }
        OBJECT_KIND_ATTACHMENT_MANIFEST => {
            let (mut manifest, _attachment_key) = decrypt_attachment_manifest(envelope, key)
                .map_err(|_| ObjectValidationError::InvalidEnvelope)?;
            manifest.attachment_id.zeroize();
            manifest.name.zeroize();
            manifest.mime.zeroize();
            manifest.content_hash.zeroize();
            // AttachmentKey implements zeroization on drop.
        }
        kind => return Err(ObjectValidationError::UnsupportedKind(kind)),
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::attachment::encrypt_attachment_manifest;
    use zk_crypto::keys::AttachmentKey;
    use zk_protocol::attachment::AttachmentManifest;

    fn envelopes(key: &VaultKey) -> Vec<EncryptedEnvelope> {
        let id = "11111111-1111-4111-8111-111111111111";
        let manifest = AttachmentManifest {
            attachment_id: id.into(),
            name: "SECRET-NAME".into(),
            mime: "SECRET-MIME".into(),
            size: 3,
            chunk_count: 1,
            chunk_size: 3,
            content_hash: None,
        };
        vec![
            PlaintextNote::new("SECRET-TITLE", "SECRET-BODY")
                .encrypt(key, id)
                .unwrap(),
            encrypt_attachment_manifest(&manifest, &AttachmentKey::generate(), key).unwrap(),
        ]
    }

    #[test]
    fn shipped_kinds_validate_and_wrong_keys_fail_safely() {
        let key = VaultKey::generate();
        for envelope in envelopes(&key) {
            assert_eq!(validate_active_object(&envelope, &key), Ok(()));
            let error = validate_active_object(&envelope, &VaultKey::generate()).unwrap_err();
            assert_eq!(error, ObjectValidationError::InvalidEnvelope);
            assert_eq!(
                format!("{error:?}: {error}"),
                "InvalidEnvelope: restored object validation failed"
            );
        }
    }

    #[test]
    fn both_kinds_reject_tampered_payload_key_aad_and_version() {
        let key = VaultKey::generate();
        for envelope in envelopes(&key) {
            for field in 0..5 {
                let mut changed = envelope.clone();
                match field {
                    0 => changed.payload.ciphertext.replace_range(
                        0..1,
                        if changed.payload.ciphertext.starts_with('A') {
                            "B"
                        } else {
                            "A"
                        },
                    ),
                    1 => changed.wrapped_key.ciphertext.replace_range(
                        0..1,
                        if changed.wrapped_key.ciphertext.starts_with('A') {
                            "B"
                        } else {
                            "A"
                        },
                    ),
                    2 => changed.object_id = "22222222-2222-4222-8222-222222222222".into(),
                    3 => changed.envelope_version = 99,
                    _ => changed.payload.nonce = "malformed".into(),
                }
                assert_eq!(
                    validate_active_object(&changed, &key),
                    Err(ObjectValidationError::InvalidEnvelope)
                );
            }
        }
    }

    #[test]
    fn reserved_and_unknown_kinds_fail_closed() {
        let key = VaultKey::generate();
        let mut envelope = envelopes(&key).remove(0);
        for kind in [2, 3, 5, 65535] {
            envelope.object_kind = kind;
            assert_eq!(
                validate_active_object(&envelope, &key),
                Err(ObjectValidationError::UnsupportedKind(kind))
            );
        }
    }
}
