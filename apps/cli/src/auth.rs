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
    AuthToken, DeviceAuthRequest, DeviceAuthResponse, DeviceListResponse, RevokeDeviceResponse,
    SessionStatusResponse, REDACTED_TOKEN,
};
use zk_protocol::constants::{
    ERROR_AUTH_EXPIRED, ERROR_AUTH_FORBIDDEN, ERROR_AUTH_REQUIRED, ERROR_AUTH_REVOKED,
    ERROR_DEVICE_REVOKED, ERROR_OBJECT_NOT_FOUND, ERROR_RATE_LIMITED, ERROR_SERVER_FAILURE,
};
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
    let json = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(session)
            .map_err(|_| CliError::Io("Failed to serialize auth session".into()))?,
    );

    // Replace atomically: a failed new login/write must preserve the saved session.
    let temporary = path.with_file_name(format!(".auth_session-{}.tmp", Uuid::new_v4()));
    let result: Result<(), CliError> = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options
            .open(&temporary)
            .map_err(|_| CliError::Io("Failed to create restricted auth session file".into()))?;
        file.write_all(json.as_bytes())
            .map_err(|_| CliError::Io("Failed to write auth session".into()))?;
        file.sync_all()
            .map_err(|_| CliError::Io("Failed to flush auth session".into()))?;
        drop(file);
        std::fs::rename(&temporary, path)
            .map_err(|_| CliError::Io("Failed to replace auth session".into()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;

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
    path.exists() || std::fs::symlink_metadata(path).is_ok()
}

/// Overwrites the auth session file with zeroes and unlinks it.
///
/// Fails closed: propagates any inspection, write, flush, or unlink errors,
/// and verifies absence before reporting success.
pub fn clear_auth_session(path: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_file() {
                let len = metadata.len();
                if len > 0 {
                    let mut file =
                        std::fs::OpenOptions::new()
                            .write(true)
                            .open(path)
                            .map_err(|e| {
                                CliError::Io(format!(
                                    "failed to open auth session file {} for zeroization: {e}",
                                    path.display()
                                ))
                            })?;
                    use std::io::Write;
                    let zeroes = vec![0u8; len as usize];
                    file.write_all(&zeroes).map_err(|e| {
                        CliError::Io(format!(
                            "failed to overwrite auth session file {} with zeroes: {e}",
                            path.display()
                        ))
                    })?;
                    file.flush().map_err(|e| {
                        CliError::Io(format!(
                            "failed to flush zeroed auth session file {}: {e}",
                            path.display()
                        ))
                    })?;
                }
            }
            std::fs::remove_file(path).map_err(|e| {
                CliError::Io(format!(
                    "failed to remove auth session file {}: {e}",
                    path.display()
                ))
            })?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(e) => {
            return Err(CliError::Io(format!(
                "failed to inspect auth session file {}: {e}",
                path.display()
            )));
        }
    }

    // Verify absence before reporting success
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        return Err(CliError::Io(format!(
            "auth session file {} still exists after removal attempt",
            path.display()
        )));
    }

    Ok(())
}

/// Default timeout for authentication HTTP requests: 5 seconds.
pub const DEFAULT_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default connect timeout for authentication HTTP requests: 3 seconds.
pub const DEFAULT_AUTH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Resolves the auth request timeout, allowing fast test overrides via `ZK_AUTH_TIMEOUT_MS`.
pub fn resolve_auth_timeout() -> std::time::Duration {
    if let Ok(ms_str) = std::env::var("ZK_AUTH_TIMEOUT_MS") {
        if let Ok(ms) = ms_str.parse::<u64>() {
            return std::time::Duration::from_millis(ms);
        }
    }
    DEFAULT_AUTH_TIMEOUT
}

/// Resolves the auth connect timeout, allowing fast test overrides via `ZK_AUTH_CONNECT_TIMEOUT_MS`.
pub fn resolve_auth_connect_timeout() -> std::time::Duration {
    if let Ok(ms_str) = std::env::var("ZK_AUTH_CONNECT_TIMEOUT_MS") {
        if let Ok(ms) = ms_str.parse::<u64>() {
            return std::time::Duration::from_millis(ms);
        }
    }
    DEFAULT_AUTH_CONNECT_TIMEOUT
}

/// Constructs a bounded reqwest [`Client`] for authentication requests.
pub fn auth_http_client() -> Result<Client, CliError> {
    auth_http_client_with_timeout(resolve_auth_connect_timeout(), resolve_auth_timeout())
}

/// Constructs a bounded reqwest [`Client`] with custom connect and request timeouts.
pub fn auth_http_client_with_timeout(
    connect_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
) -> Result<Client, CliError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|e| CliError::Network(format!("failed to initialize HTTP client: {e}")))
}

fn is_safe_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 32
        && code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Canonical, fixed user-facing messages for known protocol error codes.
///
/// In accordance with SEC-003:
/// Raw server error messages MUST NOT be interpolated into error representations
/// on token-bearing authentication endpoints, preventing a rogue or compromised
/// server from reflecting or leaking bearer tokens or session secrets back to the user.
pub fn parse_safe_auth_error(status: reqwest::StatusCode, body_bytes: &[u8]) -> CliError {
    let parsed_code = serde_json::from_slice::<serde_json::Value>(body_bytes)
        .ok()
        .and_then(|val| {
            val.get("code")
                .and_then(|c| c.as_str())
                .map(ToString::to_string)
        });

    let code = match parsed_code.as_deref() {
        Some(c) if is_safe_error_code(c) => c,
        _ => return CliError::AuthError(format!("Server returned HTTP {status}")),
    };

    if code == ERROR_DEVICE_REVOKED || code == ERROR_AUTH_REVOKED {
        return CliError::SessionRevoked;
    }
    if code == ERROR_AUTH_EXPIRED {
        return CliError::SessionExpired;
    }

    let safe_message = match code {
        ERROR_AUTH_REQUIRED
        | "AUTH_INVALID"
        | "INVALID_TOKEN"
        | "INVALID_CREDENTIALS"
        | "UNAUTHORIZED" => "Authentication failed: invalid token or credentials",
        ERROR_AUTH_FORBIDDEN | "FORBIDDEN" | "ACCESS_DENIED" => "Access denied by server",
        ERROR_RATE_LIMITED | "TOO_MANY_REQUESTS" => "Rate limit exceeded. Please try again later.",
        ERROR_OBJECT_NOT_FOUND | "NOT_FOUND" | "DEVICE_NOT_FOUND" | "SESSION_NOT_FOUND" => {
            "Requested authentication resource not found"
        }
        ERROR_SERVER_FAILURE | "INTERNAL_ERROR" | "SERVER_ERROR" => {
            return CliError::AuthError(format!("Server error (HTTP {status})"));
        }
        _ => {
            return CliError::AuthError(format!(
                "Authentication request rejected: {code} (HTTP {status})"
            ))
        }
    };

    CliError::AuthError(safe_message.to_string())
}

/// Parses an error response safely and ensures any sensitive secret is redacted.
pub fn parse_safe_auth_error_with_redaction(
    status: reqwest::StatusCode,
    body_bytes: &[u8],
    sensitive_secret: Option<&str>,
) -> CliError {
    let err = parse_safe_auth_error(status, body_bytes);
    if let Some(secret) = sensitive_secret {
        if !secret.is_empty() {
            if let CliError::AuthError(msg) = err {
                return CliError::AuthError(msg.replace(secret, "[REDACTED]"));
            }
        }
    }
    err
}

/// Normalizes server URL by trimming whitespace and trailing slashes.
fn clean_server_url(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

/// Authenticates a device directly with the server via `POST /v1/auth/device/authorize`.
pub async fn api_device_authorize(
    server_url: &str,
    authorizing_token: &str,
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

    let client = auth_http_client()?;
    let resp = client
        .post(&endpoint)
        .bearer_auth(authorizing_token)
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
        return Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(authorizing_token),
        ));
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

    let client = auth_http_client()?;
    let auth_header = format!("Bearer {token}");
    let resp = client
        .get(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|_| CliError::AuthError("invalid token string".to_string()))?,
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
        return Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(token),
        ));
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

    let client = auth_http_client()?;
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .post(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|_| CliError::AuthError("invalid token string".to_string()))?,
        )
        .header(CONTENT_TYPE, "application/json")
        .json(&req_payload)
        .send()
        .await
        .map_err(|e| {
            CliError::Network(format!("failed to connect to server at {clean_url}: {e}"))
        })?;

    let status = resp.status();
    if status.is_success() || status.as_u16() == 401 || status.as_u16() == 404 {
        Ok(())
    } else {
        let body_bytes = resp.bytes().await.unwrap_or_default();
        Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(session.token.expose_secret()),
        ))
    }
}

/// Queries active session status from the server via `GET /v1/auth/session/status`.
pub async fn api_query_status(
    session: &StoredAuthSession,
) -> Result<SessionStatusResponse, CliError> {
    let clean_url = clean_server_url(&session.server_url);
    let endpoint = format!("{clean_url}/v1/auth/session/status");

    let client = auth_http_client()?;
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .get(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|_| CliError::AuthError("invalid token string".to_string()))?,
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
        return Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(session.token.expose_secret()),
        ));
    }

    serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid session status response: {e}")))
}

/// Lists registered devices for the authenticated account via `GET /v1/devices` (ZK-075).
pub async fn api_list_devices(session: &StoredAuthSession) -> Result<DeviceListResponse, CliError> {
    let clean_url = clean_server_url(&session.server_url);
    let endpoint = format!("{clean_url}/v1/devices");

    let client = auth_http_client()?;
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .get(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|_| CliError::AuthError("invalid token string".to_string()))?,
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
        return Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(session.token.expose_secret()),
        ));
    }

    serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid device list response: {e}")))
}

/// Revokes a device and all its active sessions via `DELETE /v1/devices/{device_id}` (ZK-075).
pub async fn api_revoke_device(
    session: &StoredAuthSession,
    device_id: Uuid,
) -> Result<RevokeDeviceResponse, CliError> {
    let clean_url = clean_server_url(&session.server_url);
    let endpoint = format!("{clean_url}/v1/devices/{device_id}");

    let client = auth_http_client()?;
    let auth_header = format!("Bearer {}", session.token.expose_secret());
    let resp = client
        .delete(&endpoint)
        .header(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_header)
                .map_err(|_| CliError::AuthError("invalid token string".to_string()))?,
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
        return Err(parse_safe_auth_error_with_redaction(
            status,
            &body_bytes,
            Some(session.token.expose_secret()),
        ));
    }

    serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::CorruptedSession(format!("invalid revoke device response: {e}")))
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

    #[test]
    fn test_clear_auth_session_fails_closed_on_non_removable_target() {
        let temp_dir =
            std::env::temp_dir().join(format!("zk_auth_cleanup_test_{}", Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // Subcase 1: Target is an invalid/non-removable target (directory instead of file)
        let dir_target = temp_dir.join("auth_session.json");
        std::fs::create_dir(&dir_target).unwrap();
        assert!(has_auth_session(&dir_target));

        let dir_err = clear_auth_session(&dir_target).unwrap_err();
        assert!(
            has_auth_session(&dir_target),
            "target must not be reported cleared when cleanup fails"
        );
        let err_msg = dir_err.to_string();
        assert!(
            err_msg.contains("failed to remove") || err_msg.contains("still exists"),
            "unexpected error message: {err_msg}"
        );
        let _ = std::fs::remove_dir(&dir_target);

        // Subcase 2: Target is in a read-only directory where unlinking is forbidden (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro_dir = temp_dir.join("ro_dir");
            std::fs::create_dir_all(&ro_dir).unwrap();
            let ro_file = ro_dir.join("auth_session.json");
            std::fs::write(&ro_file, b"test session data").unwrap();
            assert!(has_auth_session(&ro_file));

            // Remove write permissions on enclosing directory to block unlink
            let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
            perms.set_mode(0o500);
            std::fs::set_permissions(&ro_dir, perms).unwrap();

            let ro_err = clear_auth_session(&ro_file).unwrap_err();
            assert!(
                has_auth_session(&ro_file),
                "credential file must remain when unlink fails"
            );
            let ro_err_msg = ro_err.to_string();
            assert!(
                ro_err_msg.contains("Permission denied") || ro_err_msg.contains("failed to remove"),
                "unexpected error message: {ro_err_msg}"
            );

            // Restore write permissions for cleanup
            let mut restore_perms = std::fs::metadata(&ro_dir).unwrap().permissions();
            restore_perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&ro_dir, restore_perms);
        }

        // Subcase 3: Absent target succeeds cleanly
        let absent_target = temp_dir.join("does_not_exist.json");
        assert!(!has_auth_session(&absent_target));
        assert!(clear_auth_session(&absent_target).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
