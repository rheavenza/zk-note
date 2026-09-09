//! Typed errors for synchronization and network adapter operations.

use std::fmt;
use zk_protocol::sync::ConflictResponse;

/// Typed network and protocol errors encountered during synchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncNetworkError {
    /// Authentication required or token rejected by server (HTTP 401).
    Unauthorized(String),
    /// Caller is forbidden from accessing the target resource or account (HTTP 403).
    Forbidden(String),
    /// Target object was not found on the server (HTTP 404).
    NotFound(String),
    /// Compare-and-swap conflict when current revision does not match expected revision (HTTP 409).
    Conflict(Box<ConflictResponse>),
    /// Mutation ID was previously processed with an incompatible payload (HTTP 409).
    ReplayMismatch(String),
    /// Sync cursor or query parameter is invalid (HTTP 400).
    InvalidCursor(String),
    /// Request payload or envelope is malformed or invalid (HTTP 400).
    InvalidPayload(String),
    /// Internal server error (HTTP 500+).
    ServerError {
        /// HTTP status code returned by server.
        status: u16,
        /// Diagnostic message.
        message: String,
    },
    /// Network connection or transport failure (connection refused, timeout, host unreachable).
    ConnectionFailed(String),
    /// JSON serialization or deserialization failure.
    Serialization(String),
    /// SEC-001/SEC-002 invariant violation: plaintext note content or keys detected in outgoing payload.
    ForbiddenPlaintext(String),
}

impl fmt::Display for SyncNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "authentication required: {msg}"),
            Self::Forbidden(msg) => write!(f, "access forbidden: {msg}"),
            Self::NotFound(msg) => write!(f, "resource not found: {msg}"),
            Self::Conflict(conflict) => write!(
                f,
                "revision conflict on object '{}': expected {}, current is {}",
                conflict.object_id, conflict.expected_revision, conflict.current_revision
            ),
            Self::ReplayMismatch(msg) => write!(f, "mutation replay mismatch: {msg}"),
            Self::InvalidCursor(msg) => write!(f, "invalid sync cursor: {msg}"),
            Self::InvalidPayload(msg) => write!(f, "invalid request payload: {msg}"),
            Self::ServerError { status, message } => {
                write!(f, "server error ({status}): {message}")
            }
            Self::ConnectionFailed(msg) => write!(f, "connection failed: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
            Self::ForbiddenPlaintext(msg) => {
                write!(
                    f,
                    "security invariant violation: plaintext transmitted: {msg}"
                )
            }
        }
    }
}

impl SyncNetworkError {
    /// Returns true if this error represents a transient transport or server error
    /// that is safe to retry automatically without client-side credential or payload changes.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ConnectionFailed(_) => true,
            Self::ServerError { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

impl std::error::Error for SyncNetworkError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
    use zk_protocol::envelope::{
        EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer,
    };

    #[test]
    fn test_error_display_formatting() {
        let err_unauth = SyncNetworkError::Unauthorized("missing token".to_string());
        assert!(err_unauth.to_string().contains("authentication required"));

        let err_conflict = SyncNetworkError::Conflict(Box::new(ConflictResponse {
            error: "REVISION_CONFLICT".to_string(),
            object_id: "obj-1".to_string(),
            expected_revision: 2,
            current_revision: 3,
            current_server_seq: 10,
            current_envelope: EncryptedEnvelope {
                envelope_version: ENVELOPE_VERSION_V1,
                object_id: "obj-1".to_string(),
                object_kind: OBJECT_KIND_NOTE,
                wrapped_key: EncryptedKeyContainer {
                    nonce: "nonce".to_string(),
                    ciphertext: "cipher".to_string(),
                },
                payload: EncryptedPayloadContainer {
                    nonce: "nonce".to_string(),
                    ciphertext: "cipher".to_string(),
                },
            },
        }));
        assert!(err_conflict.to_string().contains("revision conflict"));
        assert!(err_conflict
            .to_string()
            .contains("expected 2, current is 3"));

        let err_sec = SyncNetworkError::ForbiddenPlaintext("title leaked".to_string());
        assert!(err_sec.to_string().contains("security invariant violation"));
    }

    #[test]
    fn test_error_retryability() {
        assert!(SyncNetworkError::ConnectionFailed("timed out".to_string()).is_retryable());
        assert!(SyncNetworkError::ServerError {
            status: 503,
            message: "unavailable".to_string()
        }
        .is_retryable());
        assert!(SyncNetworkError::ServerError {
            status: 429,
            message: "rate limited".to_string()
        }
        .is_retryable());

        assert!(!SyncNetworkError::Unauthorized("bad token".to_string()).is_retryable());
        assert!(!SyncNetworkError::Forbidden("no access".to_string()).is_retryable());
        assert!(!SyncNetworkError::InvalidPayload("bad json".to_string()).is_retryable());
    }
}
