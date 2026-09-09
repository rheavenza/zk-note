//! Protocol types, constants, error codes, and serialization models
//! for the zero-knowledge notes system.

pub mod constants;
pub mod kind;

pub use constants::*;
pub use kind::{ObjectKind, UnknownObjectKind};

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-protocol"
}

#[cfg(test)]
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
}
