//! WebAuthn / Passkey protocol models and challenge representations (ZK-071).
//!
//! In accordance with SEC-001 and SEC-002:
//! - WebAuthn credentials authenticate server account access ONLY.
//! - WebAuthn credentials and public keys CANNOT decrypt note ciphertext.
//! - Vault passphrases and Vault Keys MUST NEVER be passed into or reused by WebAuthn flows.

use crate::auth::SessionResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Relying party metadata communicated to WebAuthn clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRpInfo {
    /// Human-readable relying party name (e.g. "Zero-Knowledge Notes").
    pub name: String,
    /// Relying party ID / origin domain (e.g. "localhost" or "notes.example.com").
    pub id: String,
}

impl Default for WebAuthnRpInfo {
    fn default() -> Self {
        Self {
            name: "Zero-Knowledge Notes".to_string(),
            id: "localhost".to_string(),
        }
    }
}

/// User identity metadata communicated to WebAuthn authenticators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnUserInfo {
    /// Stable opaque user/account identifier.
    pub id: String,
    /// Account username or handle.
    pub name: String,
    /// Display name shown by authenticator dialogs.
    pub display_name: String,
}

/// Request to begin a new WebAuthn registration (passkey creation).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebAuthnRegisterStartRequest {
    /// Optional existing account ID to attach the passkey to.
    pub account_id: Option<Uuid>,
    /// Optional username or handle for the user.
    pub username: Option<String>,
    /// Optional user display name.
    pub display_name: Option<String>,
}

/// Server challenge and options to initiate passkey creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegisterStartResponse {
    /// Unique identifier for this registration challenge.
    pub challenge_id: Uuid,
    /// Cryptographic challenge nonce (base64url-encoded).
    pub challenge_b64: String,
    /// Relying party metadata.
    pub rp: WebAuthnRpInfo,
    /// User identity metadata.
    pub user: WebAuthnUserInfo,
}

/// Request to complete WebAuthn registration with the authenticator credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegisterFinishRequest {
    /// Challenge identifier returned from start.
    pub challenge_id: Uuid,
    /// Opaque credential ID issued by the authenticator (base64url-encoded).
    pub credential_id: String,
    /// Authenticator public key bytes or COSE key representation (base64url-encoded).
    pub public_key: String,
    /// Optional raw attestation object bytes from the authenticator.
    pub attestation_object: Option<String>,
    /// Optional clientDataJSON bytes from the browser.
    pub client_data_json: Option<String>,
    /// Optional human-readable name for this device/passkey (e.g. "MacBook Touch ID").
    pub display_name: Option<String>,
    /// Optional device identifier.
    pub device_id: Option<Uuid>,
}

/// Response returned upon successful WebAuthn passkey registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegisterFinishResponse {
    /// Authenticated session provisioned for the new passkey.
    pub session: SessionResponse,
}

/// Request to begin WebAuthn authentication (passkey sign-in).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebAuthnLoginStartRequest {
    /// Optional account ID if user identification was previously established.
    pub account_id: Option<Uuid>,
}

/// Server challenge to initiate passkey authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnLoginStartResponse {
    /// Unique identifier for this login challenge.
    pub challenge_id: Uuid,
    /// Cryptographic challenge nonce (base64url-encoded).
    pub challenge_b64: String,
    /// Relying party identifier.
    pub rp_id: String,
}

/// Request to complete WebAuthn authentication with authenticator assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnLoginFinishRequest {
    /// Challenge identifier returned from start.
    pub challenge_id: Uuid,
    /// Credential ID selected by authenticator (base64url-encoded).
    pub credential_id: String,
    /// Authenticator data bytes from assertion.
    pub authenticator_data: Option<String>,
    /// ClientDataJSON bytes from browser.
    pub client_data_json: Option<String>,
    /// Authenticator assertion signature (base64url-encoded).
    pub signature: String,
    /// Optional device identifier.
    pub device_id: Option<Uuid>,
}

/// Response returned upon successful WebAuthn sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnLoginFinishResponse {
    /// Authenticated session provisioned for the sign-in.
    pub session: SessionResponse,
}

/// Request to explicitly revoke an active session.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RevokeSessionRequest {
    /// Optional target session ID to revoke (defaults to caller's active session).
    pub session_id: Option<Uuid>,
}

/// Response returned when a session is successfully revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    /// Status message.
    pub status: String,
    /// Revoked session ID.
    pub revoked_session_id: Uuid,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::AuthToken;

    #[test]
    fn test_webauthn_register_models_round_trip() {
        let req = WebAuthnRegisterStartRequest {
            account_id: Some(Uuid::new_v4()),
            username: Some("alice".to_string()),
            display_name: Some("Alice Smith".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: WebAuthnRegisterStartRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);

        let resp = WebAuthnRegisterStartResponse {
            challenge_id: Uuid::new_v4(),
            challenge_b64: "dGVzdC1jaGFsbGVuZ2UtMTIz".to_string(),
            rp: WebAuthnRpInfo::default(),
            user: WebAuthnUserInfo {
                id: Uuid::new_v4().to_string(),
                name: "alice".to_string(),
                display_name: "Alice Smith".to_string(),
            },
        };
        let json_resp = serde_json::to_string(&resp).unwrap();
        let parsed_resp: WebAuthnRegisterStartResponse = serde_json::from_str(&json_resp).unwrap();
        assert_eq!(parsed_resp, resp);
    }

    #[test]
    fn test_webauthn_finish_models_round_trip() {
        let finish_req = WebAuthnRegisterFinishRequest {
            challenge_id: Uuid::new_v4(),
            credential_id: "Y3JlZGVudGlhbC0xMjM".to_string(),
            public_key: "cHVibGljLWtleS00NTY".to_string(),
            attestation_object: None,
            client_data_json: None,
            display_name: Some("MacBook Touch ID".to_string()),
            device_id: Some(Uuid::new_v4()),
        };
        let json = serde_json::to_string(&finish_req).unwrap();
        let parsed: WebAuthnRegisterFinishRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, finish_req);

        let finish_resp = WebAuthnRegisterFinishResponse {
            session: SessionResponse {
                token: AuthToken::new("zk_sess_abc123"),
                session_id: Uuid::new_v4(),
                account_id: Uuid::new_v4(),
                device_id: finish_req.device_id,
                expires_at: None,
            },
        };
        let json_resp = serde_json::to_string(&finish_resp).unwrap();
        let parsed_resp: WebAuthnRegisterFinishResponse = serde_json::from_str(&json_resp).unwrap();
        assert_eq!(
            parsed_resp.session.session_id,
            finish_resp.session.session_id
        );
    }
}
