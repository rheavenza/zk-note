//! CLI authentication, device registration, and platform-restricted credential storage (ZK-072).
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - Plaintext notes, vault keys, and vault passphrases NEVER cross the network in auth flows.
//! - The vault passphrase is NOT the server account password.
//! - Bearer tokens and session secrets are NEVER printed in logs or formatted debug strings.
//! - Credentials are saved with POSIX permissions `0600` and scrubbed with zeroes on logout.

use crate::error::CliError;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use uuid::Uuid;
use zk_protocol::auth::{
    AuthToken, DeviceAuthRequest, DeviceAuthResponse, SessionStatusResponse, REDACTED_TOKEN,
};
use zk_protocol::constants::{ERROR_AUTH_REVOKED, ERROR_DEVICE_REVOKED};
use zk_protocol::webauthn::RevokeSessionRequest;

/// Persisted client authentication session details.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAuthSession {
    /// Base URL of the sync server (e.g. `http://127.0.0.1:8080`).
    pub server_url: String,
    /// Owning account ID.
    pub account_id: Uuid,
    /// Client device ID.
    pub device_id: Uuid,
    /// Active session ID issued by the server.
    pub session_id: Option<Uuid>,
    /// Secret bearer token (redacted on display).
    pub token: AuthToken,
    /// Optional RFC 3339 timestamp when the session expires.
    pub expires_at: Option<String>,
}

impl fmt::Debug for StoredAuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredAuthSession")
            .field("server_url", &self.server_url)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("session_id", &self.session_id)
            .field("token", &REDACTED_TOKEN)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Persistent device identity representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Unique identifier for this client device.
    pub device_id: Uuid,
}

/// Retrieves an existing device UUID or generates and persists a new one.
pub fn get_or_create_device_id(
    data_dir: &Path,
    explicit_id: Option<Uuid>,
) -> Result<Uuid, CliError> {
    if let Some(id) = explicit_id {
        return Ok(id);
    }

    let dev_path = crate::config::device_file(data_dir);
    if dev_path.exists() {
        if let Ok(bytes) = std::fs::read(&dev_path) {
            if let Ok(ident) = serde_json::from_slice::<DeviceIdentity>(&bytes) {
                return Ok(ident.device_id);
            }
        }
    }

    let new_id = Uuid::new_v4();
    let ident = DeviceIdentity { device_id: new_id };
    if let Ok(json) = serde_json::to_string_pretty(&ident) {
        let _ = std::fs::write(&dev_path, json);
    }
    Ok(new_id)
}

/// Saves the active authentication session with strict `0600` permissions.
pub fn save_auth_session(path: &Path, session: &StoredAuthSession) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(session)
        .map_err(|e| CliError::Io(format!("failed to serialize session: {e}")))?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    use std::io::Write;
    let mut file = options.open(path).map_err(|e| {
        CliError::Io(format!(
            "failed to open auth session file {}: {e}",
            path.display()
        ))
    })?;

    file.write_all(json.as_bytes()).map_err(|e| {
        CliError::Io(format!(
            "failed to write auth session file {}: {e}",
            path.display()
        ))
    })?;
    file.flush().map_err(|e| {
        CliError::Io(format!(
            "failed to flush auth session file {}: {e}",
            path.display()
        ))
    })?;

    Ok(())
}

/// Loads the active authentication session from disk.
pub fn load_auth_session(path: &Path) -> Result<StoredAuthSession, CliError> {
    if !path.exists() {
        return Err(CliError::NotLoggedIn);
    }

    let bytes = std::fs::read(path).map_err(|e| {
        CliError::Io(format!(
            "failed to read auth session file {}: {e}",
            path.display()
        ))
    })?;

    serde_json::from_slice(&bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid auth session JSON: {e}")))
}

/// Returns true if an auth session file exists on disk.
#[must_use]
pub fn has_auth_session(path: &Path) -> bool {
    path.exists()
}

/// Overwrites the auth session file with zeroes and unlinks it.
pub fn clear_auth_session(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if let Ok(metadata) = std::fs::metadata(path) {
            let len = metadata.len();
            if len > 0 {
                if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
                    use std::io::Write;
                    let zeroes = vec![0u8; len as usize];
                    let _ = file.write_all(&zeroes);
                    let _ = file.flush();
                }
            }
        }
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// Normalizes server URL by trimming whitespace and trailing slashes.
fn clean_server_url(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

/// Authenticates a device directly with the server via `POST /v1/auth/device/authorize`.
pub async fn api_device_authorize(
    server_url: &str,
    account_id: Uuid,
    device_id: Uuid,
    device_name: Option<String>,
) -> Result<StoredAuthSession, CliError> {
    let clean_url = clean_server_url(server_url);
    let endpoint = format!("{clean_url}/v1/auth/device/authorize");

    let req_payload = DeviceAuthRequest {
        account_id,
        device_id,
        device_name,
    };

    let client = Client::new();
    let resp = client
        .post(&endpoint)
        .header(CONTENT_TYPE, "application/json")
        .json(&req_payload)
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!("failed to connect to server at {clean_url}: {e}"))
        })?;

    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| CliError::Network(format!("failed to read response body: {e}")))?;

    if !status.is_success() {
        if let Ok(err_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let code = err_val
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN_ERROR");
            let msg = err_val
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown server error");
            if code == ERROR_DEVICE_REVOKED {
                return Err(CliError::SessionRevoked);
            }
            return Err(CliError::AuthError(format!("{code}: {msg}")));
        }
        return Err(CliError::AuthError(format!(
            "Server returned HTTP {status}"
        )));
    }

    let auth_resp: DeviceAuthResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        CliError::CorruptedSession(format!("invalid device authorization response: {e}"))
    })?;

    Ok(StoredAuthSession {
        server_url: clean_url,
        account_id: auth_resp.session.account_id,
        device_id: auth_resp.session.device_id.unwrap_or(device_id),
        session_id: Some(auth_resp.session.session_id),
        token: auth_resp.session.token,
        expires_at: auth_resp.session.expires_at,
    })
}

/// Verifies a pre-provisioned personal access token or session token with the server.
pub async fn api_verify_token(
    server_url: &str,
    token: &str,
    device_id: Uuid,
) -> Result<StoredAuthSession, CliError> {
    let clean_url = clean_server_url(server_url);
    let endpoint = format!("{clean_url}/v1/auth/session/status");

    let client = Client::new();
    let auth_header = format!("Bearer {token}");
    let resp = client
        .get(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|e| CliError::AuthError(format!("invalid token string: {e}")))?,
        )
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!("failed to connect to server at {clean_url}: {e}"))
        })?;

    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| CliError::Network(format!("failed to read response body: {e}")))?;

    if !status.is_success() {
        if let Ok(err_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let code = err_val
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN_ERROR");
            let msg = err_val
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown server error");
            if code == ERROR_AUTH_REVOKED || code == ERROR_DEVICE_REVOKED {
                return Err(CliError::SessionRevoked);
            }
            return Err(CliError::AuthError(format!("{code}: {msg}")));
        }
        return Err(CliError::AuthError(format!(
            "Server returned HTTP {status}"
        )));
    }

    let status_resp: SessionStatusResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid session status response: {e}")))?;

    Ok(StoredAuthSession {
        server_url: clean_url,
        account_id: status_resp.account_id,
        device_id: status_resp.device_id.unwrap_or(device_id),
        session_id: status_resp.session_id,
        token: AuthToken::new(token),
        expires_at: None,
    })
}

/// Revokes the active session on the server via `POST /v1/auth/session/revoke`.
pub async fn api_revoke_session(session: &StoredAuthSession) -> Result<(), CliError> {
    let clean_url = clean_server_url(&session.server_url);
    let endpoint = format!("{clean_url}/v1/auth/session/revoke");

    let req_payload = RevokeSessionRequest {
        session_id: session.session_id,
    };

    let client = Client::new();
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .post(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|e| CliError::AuthError(format!("invalid token string: {e}")))?,
        )
        .header(CONTENT_TYPE, "application/json")
        .json(&req_payload)
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!("failed to connect to server at {clean_url}: {e}"))
        })?;

    let status = resp.status();
    let _ = status;
    Ok(())
}

/// Queries active session status from the server via `GET /v1/auth/session/status`.
pub async fn api_query_status(
    session: &StoredAuthSession,
) -> Result<SessionStatusResponse, CliError> {
    let clean_url = clean_server_url(&session.server_url);
    let endpoint = format!("{clean_url}/v1/auth/session/status");

    let client = Client::new();
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .get(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|e| CliError::AuthError(format!("invalid token string: {e}")))?,
        )
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!("failed to connect to server at {clean_url}: {e}"))
        })?;

    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| CliError::Network(format!("failed to read response body: {e}")))?;

    if !status.is_success() {
        if let Ok(err_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            let code = err_val
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN_ERROR");
            let msg = err_val
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            if code == ERROR_AUTH_REVOKED || code == ERROR_DEVICE_REVOKED {
                return Err(CliError::SessionRevoked);
            }
            return Err(CliError::AuthError(format!("{code}: {msg}")));
        }
        return Err(CliError::AuthError(format!("HTTP {status}")));
    }

    serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid session status response: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_auth_session_debug_redaction() {
        let session = StoredAuthSession {
            server_url: "https://sync.example.com".to_string(),
            account_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
            token: AuthToken::new("live_secret_auth_token_999"),
            expires_at: Some("2026-10-01T00:00:00Z".to_string()),
        };

        let debug_str = format!("{session:?}");
        assert!(!debug_str.contains("live_secret_auth_token_999"));
        assert!(debug_str.contains(REDACTED_TOKEN));
    }

    #[test]
    fn test_save_load_clear_auth_session() {
        let temp_dir = std::env::temp_dir().join(format!("zk_auth_test_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let sess_file = temp_dir.join(".auth_session");

        let session = StoredAuthSession {
            server_url: "http://127.0.0.1:8080".to_string(),
            account_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
            token: AuthToken::new("test_secret_tok"),
            expires_at: None,
        };

        save_auth_session(&sess_file, &session).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&sess_file).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "session file must have strict 0600 permissions"
            );
        }

        assert!(has_auth_session(&sess_file));

        let loaded = load_auth_session(&sess_file).unwrap();
        assert_eq!(loaded.server_url, session.server_url);
        assert_eq!(loaded.account_id, session.account_id);
        assert_eq!(loaded.device_id, session.device_id);
        assert_eq!(loaded.token.expose_secret(), "test_secret_tok");

        clear_auth_session(&sess_file).unwrap();
        assert!(!has_auth_session(&sess_file));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_device_id_generation_and_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("zk_dev_test_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let dev_id1 = get_or_create_device_id(&temp_dir, None).unwrap();
        let dev_id2 = get_or_create_device_id(&temp_dir, None).unwrap();
        assert_eq!(dev_id1, dev_id2, "device ID must persist stably");

        let explicit = Uuid::new_v4();
        let dev_id3 = get_or_create_device_id(&temp_dir, Some(explicit)).unwrap();
        assert_eq!(dev_id3, explicit);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
