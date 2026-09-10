//! Protocol types, constants, error codes, and serialization models
//! for the zero-knowledge notes system.

pub mod auth;
pub mod constants;
pub mod envelope;
pub mod kind;
pub mod note;
pub mod sync;
pub mod vault;
pub mod webauthn;

pub use auth::{AuthToken, AuthenticatedSession, SessionResponse, REDACTED_TOKEN};
pub use constants::*;
pub use envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};
pub use kind::{ObjectKind, UnknownObjectKind};
pub use note::PlaintextNote;
pub use sync::{
    ConflictResponse, ObjectChange, PullChangesQuery, PullChangesResponse, PushRequest,
    PushResponse,
};
pub use vault::{KdfParams, VaultBootstrap, WrappedVaultKey};
pub use webauthn::*;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-protocol"
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_init() {
        assert_eq!(crate_name(), "zk-protocol");
    }

    #[test]
    fn test_protocol_v1_constants() {
        assert_eq!(PROTOCOL_VERSION_V1, 1);
        assert_eq!(ENVELOPE_VERSION_V1, 1);
        assert_eq!(INITIAL_EXPECTED_REVISION, 0);
        assert_eq!(INITIAL_OBJECT_REVISION, 1);
        assert_eq!(INITIAL_SERVER_SEQ, 0);
        assert_eq!(INITIAL_SYNC_CURSOR, 0);
    }

    #[test]
    fn test_object_kind_round_trip() {
        let cases = [
            (ObjectKind::Note, OBJECT_KIND_NOTE, "NOTE"),
            (ObjectKind::Notebook, OBJECT_KIND_NOTEBOOK, "NOTEBOOK"),
            (
                ObjectKind::UserSettings,
                OBJECT_KIND_USER_SETTINGS,
                "USER_SETTINGS",
            ),
            (
                ObjectKind::AttachmentManifest,
                OBJECT_KIND_ATTACHMENT_MANIFEST,
                "ATTACHMENT_MANIFEST",
            ),
            (ObjectKind::Reserved, OBJECT_KIND_RESERVED, "RESERVED"),
        ];

        for (kind, raw, display) in cases {
            assert_eq!(kind.as_u16(), raw);
            assert_eq!(u16::from(kind), raw);
            assert_eq!(ObjectKind::try_from(raw).ok(), Some(kind));
            assert_eq!(format!("{kind}"), display);
        }

        assert!(ObjectKind::try_from(0).is_err());
        assert!(ObjectKind::try_from(6).is_err());
        assert!(ObjectKind::try_from(999).is_err());
    }

    #[test]
    fn test_error_constants() {
        assert_eq!(ERROR_AUTH_REQUIRED, "AUTH_REQUIRED");
        assert_eq!(ERROR_AUTH_FORBIDDEN, "AUTH_FORBIDDEN");
        assert_eq!(ERROR_AUTH_EXPIRED, "AUTH_EXPIRED");
        assert_eq!(ERROR_AUTH_REVOKED, "AUTH_REVOKED");
        assert_eq!(ERROR_DEVICE_REVOKED, "DEVICE_REVOKED");
        assert_eq!(ERROR_VAULT_LOCKED, "VAULT_LOCKED");
        assert_eq!(
            ERROR_CRYPTO_UNSUPPORTED_VERSION,
            "CRYPTO_UNSUPPORTED_VERSION"
        );
        assert_eq!(ERROR_CRYPTO_AUTH_FAILED, "CRYPTO_AUTH_FAILED");
        assert_eq!(ERROR_INVALID_ENVELOPE, "INVALID_ENVELOPE");
        assert_eq!(ERROR_REVISION_CONFLICT, "REVISION_CONFLICT");
        assert_eq!(ERROR_MUTATION_REPLAY_MISMATCH, "MUTATION_REPLAY_MISMATCH");
        assert_eq!(ERROR_OBJECT_NOT_FOUND, "OBJECT_NOT_FOUND");
        assert_eq!(ERROR_OBJECT_DELETED, "OBJECT_DELETED");
        assert_eq!(ERROR_SYNC_CURSOR_INVALID, "SYNC_CURSOR_INVALID");
        assert_eq!(ERROR_RATE_LIMITED, "RATE_LIMITED");
        assert_eq!(ERROR_NETWORK_UNAVAILABLE, "NETWORK_UNAVAILABLE");
        assert_eq!(ERROR_LOCAL_STORAGE_FAILURE, "LOCAL_STORAGE_FAILURE");
        assert_eq!(ERROR_SERVER_FAILURE, "SERVER_FAILURE");
    }

    #[test]
    fn test_encrypted_envelope_serialization_round_trip() {
        let envelope = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "c29tZSBjaXBoZXJ0ZXh0IGJ5dGVzIHdpdGggYXV0aCB0YWc=".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
                ciphertext: "ZW5jcnlwdGVkIHBheWxvYWQgYnl0ZXMgd2l0aCBhdXRoIHRhZw==".to_string(),
            },
        };

        let json = serde_json::to_string_pretty(&envelope).expect("serialize envelope");
        let parsed: EncryptedEnvelope = serde_json::from_str(&json).expect("deserialize envelope");

        assert_eq!(envelope, parsed);
        assert_eq!(parsed.kind().ok(), Some(ObjectKind::Note));
    }

    #[test]
    fn test_vault_bootstrap_serialization_round_trip() {
        let bootstrap = VaultBootstrap {
            crypto_version: 1,
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt: "cmFuZG9tLXNhbHQtMTZieXRlcw==".to_string(),
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1,
            },
            wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA==".to_string(),
            },
            recovery_wrapped_vault_key: WrappedVaultKey {
                cipher_suite: "xchacha20poly1305".to_string(),
                nonce: "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==".to_string(),
                ciphertext: "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk=".to_string(),
            },
        };

        let json = serde_json::to_string(&bootstrap).expect("serialize bootstrap");
        let parsed: VaultBootstrap = serde_json::from_str(&json).expect("deserialize bootstrap");

        assert_eq!(bootstrap, parsed);
    }

    #[test]
    fn test_sync_models_serialization_round_trip() {
        let envelope = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "bm9uY2UtMjQtYnl0ZXM=".to_string(),
                ciphertext: "d3JhcHBlZC1rZXk=".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "cGF5bG9hZC1ub25jZQ==".to_string(),
                ciphertext: "ZW5jcnlwdGVkLXBheWxvYWQ=".to_string(),
            },
        };

        // Push Request
        let push_req = PushRequest {
            mutation_id: "c73bcdcc-2669-4bf6-81d3-e4ae73fb11fd".to_string(),
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: envelope.clone(),
            is_deleted: false,
        };
        let push_json = serde_json::to_string(&push_req).expect("serialize push request");
        let parsed_push: PushRequest =
            serde_json::from_str(&push_json).expect("deserialize push request");
        assert_eq!(push_req, parsed_push);

        // Push Response
        let push_resp = PushResponse {
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            revision: 1,
            server_seq: 42,
        };
        let resp_json = serde_json::to_string(&push_resp).expect("serialize push response");
        let parsed_resp: PushResponse =
            serde_json::from_str(&resp_json).expect("deserialize push response");
        assert_eq!(push_resp, parsed_resp);

        // Conflict Response
        let conflict = ConflictResponse {
            error: ERROR_REVISION_CONFLICT.to_string(),
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            expected_revision: 3,
            current_revision: 5,
            current_server_seq: 108,
            current_envelope: envelope.clone(),
            is_deleted: false,
        };
        let conflict_json = serde_json::to_string(&conflict).expect("serialize conflict response");
        let parsed_conflict: ConflictResponse =
            serde_json::from_str(&conflict_json).expect("deserialize conflict response");
        assert_eq!(conflict, parsed_conflict);

        // Pull Changes Response
        let pull_resp = PullChangesResponse {
            changes: vec![ObjectChange {
                server_seq: 109,
                object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                revision: 5,
                object_kind: OBJECT_KIND_NOTE,
                is_deleted: false,
                envelope,
            }],
            next_cursor: 109,
            has_more: false,
        };
        let pull_json = serde_json::to_string(&pull_resp).expect("serialize pull changes response");
        let parsed_pull: PullChangesResponse =
            serde_json::from_str(&pull_json).expect("deserialize pull changes response");
        assert_eq!(pull_resp, parsed_pull);

        // Pull Changes Query
        let query = PullChangesQuery {
            after: Some(108),
            limit: Some(50),
        };
        let query_json = serde_json::to_string(&query).expect("serialize pull query");
        let parsed_query: PullChangesQuery =
            serde_json::from_str(&query_json).expect("deserialize pull query");
        assert_eq!(query, parsed_query);
    }

    #[test]
    fn test_plaintext_note_serialization_round_trip() {
        let note = PlaintextNote {
            schema_version: 1,
            title: "Meeting Notes".to_string(),
            body: "# Architecture Review\n\nAll security invariants hold.".to_string(),
            tags: vec!["architecture".to_string(), "security".to_string()],
            created_at: "2026-09-09T05:00:00.000Z".to_string(),
            updated_at: "2026-09-09T05:30:00.000Z".to_string(),
            attachments: vec![],
        };

        let json = serde_json::to_string_pretty(&note).expect("serialize note");
        let parsed: PlaintextNote = serde_json::from_str(&json).expect("deserialize note");

        assert_eq!(note, parsed);
    }

    #[test]
    fn test_malformed_envelope_rejected() {
        assert!(serde_json::from_str::<EncryptedEnvelope>("not valid json").is_err());
        assert!(serde_json::from_str::<EncryptedEnvelope>("{}").is_err());
        assert!(serde_json::from_str::<EncryptedEnvelope>(
            r#"{"envelope_version": 1, "object_id": "test"}"#
        )
        .is_err());
    }
}
