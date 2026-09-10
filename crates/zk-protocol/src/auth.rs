//! Authentication protocol models, session representations, and zeroize token wrappers (ZK-070).
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - Server authentication credentials are completely decoupled from vault passphrases and encryption keys.
//! - Access tokens and session credentials MUST NEVER be logged or leaked in error strings.
//! - Token containers clear secret material from memory on drop using [`zeroize`].

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Placeholder text used when formatting redacted credentials for display or debugging.
pub const REDACTED_TOKEN: &str = "[REDACTED]";

/// Strongly typed, zeroizing container for server authentication access and session tokens.
///
/// Implements SEC-003:
/// - Custom [`fmt::Debug`] and [`fmt::Display`] implementations unconditionally redact token material.
/// - Implements [`Zeroize`] and [`ZeroizeOnDrop`] to ensure token bytes are cleared from RAM upon drop.
/// - Plaintext token string can only be accessed through explicit methods like [`AuthToken::expose_secret`].
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AuthToken {
    inner: String,
}

impl AuthToken {
    /// Constructs a new [`AuthToken`] from a secret string.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            inner: token.into(),
        }
    }

    /// Exposes the underlying secret token string for explicit network transmissions or hashing.
    ///
    /// # Security
    /// Never pass the result of this call to format strings, log macros, or error responses.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    /// Borrows the secret token as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Returns true if the token is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the character length of the token string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED_TOKEN}")
    }
}

impl fmt::Display for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED_TOKEN}")
    }
}

impl From<String> for AuthToken {
    fn from(token: String) -> Self {
        Self::new(token)
    }
}

impl From<&str> for AuthToken {
    fn from(token: &str) -> Self {
        Self::new(token)
    }
}

impl Serialize for AuthToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for AuthToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

/// Representation of an active server authentication session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    /// Unique identifier for this session.
    pub session_id: Uuid,
    /// Owning account ID.
    pub account_id: Uuid,
    /// Optional associated device ID.
    pub device_id: Option<Uuid>,
    /// Human-readable label for the session or device (e.g. "Firefox on Linux").
    pub display_name: Option<String>,
    /// RFC 3339 timestamp of when the session was issued.
    pub created_at: String,
    /// RFC 3339 timestamp when the session expires, if time-limited.
    pub expires_at: Option<String>,
    /// Flag indicating whether the session has been explicitly revoked.
    pub is_revoked: bool,
}

/// Response returned when a new server authentication session is provisioned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The issued secret bearer token (redacted on display).
    pub token: AuthToken,
    /// Session unique identifier.
    pub session_id: Uuid,
    /// Account unique identifier.
    pub account_id: Uuid,
    /// Associated device unique identifier, if linked.
    pub device_id: Option<Uuid>,
    /// RFC 3339 timestamp when the session expires, if time-limited.
    pub expires_at: Option<String>,
}

/// Request to authorize and register a client device (ZK-072).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Device identifier for this client.
    pub device_id: Uuid,
    /// Human-readable device name or hostname.
    pub device_name: Option<String>,
}

/// Response returned when a device is authorized (ZK-072).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    /// Provisioned session details and bearer token.
    pub session: SessionResponse,
}

/// Status of the current authentication session (ZK-072).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStatusResponse {
    /// Owning account ID.
    pub account_id: Uuid,
    /// Active session ID, if present.
    pub session_id: Option<Uuid>,
    /// Associated device ID, if present.
    pub device_id: Option<Uuid>,
    /// Status description ("active", etc.).
    pub status: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_never_logged_in_debug_or_display() {
        let secret = "zk_live_secret_token_1234567890abcdef";
        let token = AuthToken::new(secret);

        // SEC-003 verification: format!("{:?}") and format!("{}", ...) MUST NOT leak the secret
        let debug_str = format!("{token:?}");
        let display_str = format!("{token}");

        assert_eq!(debug_str, REDACTED_TOKEN);
        assert_eq!(display_str, REDACTED_TOKEN);
        assert!(!debug_str.contains("secret"));
        assert!(!display_str.contains("secret"));

        // Controlled explicit access works
        assert_eq!(token.expose_secret(), secret);
        assert_eq!(token.as_str(), secret);
        assert_eq!(token.len(), secret.len());
        assert!(!token.is_empty());
    }

    #[test]
    fn test_auth_token_serialization_round_trip() {
        let secret = "zk_sess_abc123xyz";
        let token = AuthToken::new(secret);

        let json = serde_json::to_string(&token).unwrap();
        assert_eq!(json, format!("\"{secret}\""));

        let deserialized: AuthToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expose_secret(), secret);
    }

    #[test]
    fn test_session_response_serialization_redacts_in_debug() {
        let resp = SessionResponse {
            token: AuthToken::new("super_secret_session_token"),
            session_id: Uuid::new_v4(),
            account_id: Uuid::new_v4(),
            device_id: Some(Uuid::new_v4()),
            expires_at: Some("2026-10-01T00:00:00Z".to_string()),
        };

        let debug_output = format!("{resp:?}");
        assert!(!debug_output.contains("super_secret_session_token"));
        assert!(debug_output.contains(REDACTED_TOKEN));

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: SessionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, resp.session_id);
        assert_eq!(parsed.token.expose_secret(), "super_secret_session_token");
    }

    #[test]
    fn test_device_auth_models_serialization() {
        let acc_id = Uuid::new_v4();
        let dev_id = Uuid::new_v4();
        let req = DeviceAuthRequest {
            account_id: acc_id,
            device_id: dev_id,
            device_name: Some("laptop-cli".to_string()),
        };

        let req_json = serde_json::to_string(&req).unwrap();
        let parsed_req: DeviceAuthRequest = serde_json::from_str(&req_json).unwrap();
        assert_eq!(parsed_req, req);

        let resp = DeviceAuthResponse {
            session: SessionResponse {
                token: AuthToken::new("cli_tok_12345"),
                session_id: Uuid::new_v4(),
                account_id: acc_id,
                device_id: Some(dev_id),
                expires_at: None,
            },
        };

        let resp_json = serde_json::to_string(&resp).unwrap();
        let parsed_resp: DeviceAuthResponse = serde_json::from_str(&resp_json).unwrap();
        assert_eq!(parsed_resp.session.account_id, acc_id);
        assert_eq!(parsed_resp.session.token.expose_secret(), "cli_tok_12345");

        let status = SessionStatusResponse {
            account_id: acc_id,
            session_id: Some(resp.session.session_id),
            device_id: Some(dev_id),
            status: "active".to_string(),
        };
        let status_json = serde_json::to_string(&status).unwrap();
        let parsed_status: SessionStatusResponse = serde_json::from_str(&status_json).unwrap();
        assert_eq!(parsed_status, status);
    }
}
