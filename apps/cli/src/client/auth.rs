//! Shared, non-printing native client authentication services (ZK-101 addendum).
//!
//! Provides server URL validation, device authorization, session status verification,
//! and truthful sign-out / revocation without shelling out or leaking credentials.
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - Note plaintext, vault keys, and vault passphrases NEVER cross the network in auth flows.
//! - The session token is never printed in logs or formatted debug strings.
//! - Session credentials are saved with restricted `0600` POSIX permissions.
//! - Incomplete or failed auth operations fail closed and preserve local session state.

use crate::auth::{
    api_device_authorize, api_query_status, api_revoke_session, api_verify_token,
    clear_auth_session, get_or_create_device_id, has_auth_session, load_auth_session,
    save_auth_session, StoredAuthSession,
};
use crate::config::{auth_session_file, resolve_data_dir};
use crate::error::CliError;
use reqwest::Url;
use std::fmt;
use std::path::Path;
use uuid::Uuid;

/// High-level client authentication and server connectivity state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthState {
    /// No server session is configured (offline local vault).
    LocalOnly,
    /// A session is saved locally, but has not yet been verified online with the sync server.
    Unverified {
        server_url: String,
        account_id: Uuid,
        device_id: Uuid,
        session_id: Option<Uuid>,
        expires_at: Option<String>,
    },
    /// Device is authenticated with an active server session verified online.
    Authenticated {
        server_url: String,
        account_id: Uuid,
        device_id: Uuid,
        session_id: Option<Uuid>,
        expires_at: Option<String>,
    },
    /// A session is saved locally, but the sync server is currently unreachable.
    Offline {
        server_url: String,
        account_id: Uuid,
        device_id: Uuid,
        session_id: Option<Uuid>,
        error: String,
    },
    /// The stored session token has expired according to server or timestamp.
    Expired {
        server_url: String,
        account_id: Uuid,
        device_id: Uuid,
        session_id: Option<Uuid>,
    },
    /// The device or session was explicitly revoked by the server.
    Revoked {
        server_url: String,
        account_id: Uuid,
        device_id: Uuid,
        session_id: Option<Uuid>,
    },
    /// Encountered an unexpected error while querying server auth status.
    Error { server_url: String, error: String },
}

impl fmt::Display for ClientAuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientAuthState::LocalOnly => write!(f, "Local vault only (not signed in)"),
            ClientAuthState::Unverified { account_id, .. } => {
                write!(f, "Saved session ({account_id}) — unverified")
            }
            ClientAuthState::Authenticated { account_id, .. } => {
                write!(f, "Signed in ({account_id})")
            }
            ClientAuthState::Offline { .. } => write!(f, "Offline — local vault available"),
            ClientAuthState::Expired { .. } => write!(f, "Session expired — sign in again"),
            ClientAuthState::Revoked { .. } => write!(f, "Session revoked — sign in again"),
            ClientAuthState::Error { error, .. } => write!(f, "Auth error: {error}"),
        }
    }
}

impl ClientAuthState {
    /// Returns true if currently authenticated with an active session verified online.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self, ClientAuthState::Authenticated { .. })
    }

    /// Returns true if running strictly local-only without an account session.
    #[must_use]
    pub fn is_local_only(&self) -> bool {
        matches!(self, ClientAuthState::LocalOnly)
    }

    /// Returns true if saved credentials exist but have not yet been verified online.
    #[must_use]
    pub fn is_unverified(&self) -> bool {
        matches!(self, ClientAuthState::Unverified { .. })
    }

    /// Returns true if currently offline / unreachable.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self, ClientAuthState::Offline { .. })
    }

    /// Returns true if session is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        matches!(self, ClientAuthState::Expired { .. })
    }

    /// Returns true if session or device was revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, ClientAuthState::Revoked { .. })
    }

    /// Returns the associated server URL, if any.
    #[must_use]
    pub fn server_url(&self) -> Option<&str> {
        match self {
            ClientAuthState::LocalOnly => None,
            ClientAuthState::Unverified { server_url, .. }
            | ClientAuthState::Authenticated { server_url, .. }
            | ClientAuthState::Offline { server_url, .. }
            | ClientAuthState::Expired { server_url, .. }
            | ClientAuthState::Revoked { server_url, .. }
            | ClientAuthState::Error { server_url, .. } => Some(server_url),
        }
    }

    /// Returns the authenticated account ID, if known.
    #[must_use]
    pub fn account_id(&self) -> Option<Uuid> {
        match self {
            ClientAuthState::Unverified { account_id, .. }
            | ClientAuthState::Authenticated { account_id, .. }
            | ClientAuthState::Offline { account_id, .. }
            | ClientAuthState::Expired { account_id, .. }
            | ClientAuthState::Revoked { account_id, .. } => Some(*account_id),
            _ => None,
        }
    }

    /// Returns the device ID, if known.
    #[must_use]
    pub fn device_id(&self) -> Option<Uuid> {
        match self {
            ClientAuthState::Unverified { device_id, .. }
            | ClientAuthState::Authenticated { device_id, .. }
            | ClientAuthState::Offline { device_id, .. }
            | ClientAuthState::Expired { device_id, .. }
            | ClientAuthState::Revoked { device_id, .. } => Some(*device_id),
            _ => None,
        }
    }

    /// Returns the session ID, if known.
    #[must_use]
    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            ClientAuthState::Unverified { session_id, .. }
            | ClientAuthState::Authenticated { session_id, .. }
            | ClientAuthState::Offline { session_id, .. }
            | ClientAuthState::Expired { session_id, .. }
            | ClientAuthState::Revoked { session_id, .. } => *session_id,
            _ => None,
        }
    }
}

/// Helper to check if a parsed URL targets a local loopback interface.
fn is_loopback_host(url: &Url) -> bool {
    if let Some(host_str) = url.host_str() {
        if host_str.eq_ignore_ascii_case("localhost") {
            return true;
        }
        // Check for IPv6 bracketed format like "[::1]" or bare IP
        let bare_host = host_str.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare_host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    false
}

/// Validates and normalizes a sync server URL (AC-04).
///
/// Security rules:
/// - Rejects malformed URLs and unsupported schemes (only HTTP and HTTPS are permitted).
/// - HTTPS is strictly required for non-loopback servers to prevent token disclosure.
/// - HTTP is permitted only for local loopback development (`localhost`, `127.0.0.1`, `::1`).
/// - Rejects URLs with userinfo/credentials, queries, fragments, or path components.
/// - Canonicalizes into origin format without trailing slashes.
pub fn validate_and_normalize_server_url(raw: &str) -> Result<String, CliError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::AuthError(
            "Server URL cannot be empty".to_string(),
        ));
    }

    // Auto-prefix bare host/port inputs (e.g. "localhost:8080" or "sync.example.com")
    let url_to_parse = if !trimmed.contains("://") {
        let is_local = trimmed.starts_with("localhost")
            || trimmed.starts_with("127.")
            || trimmed.starts_with("[::1]")
            || trimmed.starts_with("::1");
        if is_local {
            format!("http://{trimmed}")
        } else {
            format!("https://{trimmed}")
        }
    } else {
        trimmed.to_string()
    };

    let parsed = Url::parse(&url_to_parse)
        .map_err(|e| CliError::AuthError(format!("Invalid server URL '{trimmed}': {e}")))?;

    // 1. Scheme validation
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(CliError::AuthError(format!(
            "Unsupported server URL scheme '{scheme}'. Only HTTP and HTTPS are supported."
        )));
    }

    // 2. Prohibit credentials in URL
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::AuthError(
            "Server URL must not contain credentials (username or password).".to_string(),
        ));
    }

    // 3. Prohibit query string
    if parsed.query().is_some() {
        return Err(CliError::AuthError(
            "Server URL must not contain query parameters.".to_string(),
        ));
    }

    // 4. Prohibit fragments
    if parsed.fragment().is_some() {
        return Err(CliError::AuthError(
            "Server URL must not contain URL fragments.".to_string(),
        ));
    }

    // 5. Prohibit path components (other than empty or root "/")
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err(CliError::AuthError(
            "Server URL must be an origin without a path component.".to_string(),
        ));
    }

    // 6. Host validation and HTTPS requirement for non-loopback
    if parsed.host().is_none() {
        return Err(CliError::AuthError(
            "Server URL must specify a valid host.".to_string(),
        ));
    }

    let is_loopback = is_loopback_host(&parsed);
    if scheme == "http" && !is_loopback {
        return Err(CliError::AuthError(
            "HTTPS is required for remote servers. Insecure HTTP is only permitted for local loopback development (localhost, 127.0.0.1, [::1]).".to_string(),
        ));
    }

    let serialized = parsed.origin().ascii_serialization();
    if serialized == "null" {
        return Err(CliError::AuthError(
            "Server URL produced an opaque origin.".to_string(),
        ));
    }

    Ok(serialized)
}

/// Reads the local authentication session state without performing network operations.
///
/// If a saved session file exists, returns `ClientAuthState::Unverified` because
/// its active status has not yet been verified online with the server.
pub fn get_local_auth_state(custom_data_dir: Option<&Path>) -> Result<ClientAuthState, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return Ok(ClientAuthState::LocalOnly);
    }

    let session = load_auth_session(&auth_path)?;
    Ok(ClientAuthState::Unverified {
        server_url: session.server_url,
        account_id: session.account_id,
        device_id: session.device_id,
        session_id: session.session_id,
        expires_at: session.expires_at,
    })
}

/// Queries the sync server to verify active session and device status (ZK-072).
///
/// Returns an honest connection state:
/// - `LocalOnly` if no credentials exist.
/// - `Authenticated` if the session is explicitly verified active on the server.
/// - `Offline` if network connection fails.
/// - `Revoked` if session or device was revoked.
/// - `Expired` if session token has expired.
/// - `Error` if status is unrecognized or server error occurs.
pub async fn check_auth_state_online(
    custom_data_dir: Option<&Path>,
) -> Result<ClientAuthState, CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return Ok(ClientAuthState::LocalOnly);
    }

    let session = load_auth_session(&auth_path)?;
    let status_res = api_query_status(&session).await;

    match status_res {
        Ok(status) => match status.status.as_str() {
            "active" => Ok(ClientAuthState::Authenticated {
                server_url: session.server_url,
                account_id: status.account_id,
                device_id: status.device_id.unwrap_or(session.device_id),
                session_id: status.session_id.or(session.session_id),
                expires_at: session.expires_at,
            }),
            "revoked" => Ok(ClientAuthState::Revoked {
                server_url: session.server_url,
                account_id: session.account_id,
                device_id: session.device_id,
                session_id: session.session_id,
            }),
            "expired" => Ok(ClientAuthState::Expired {
                server_url: session.server_url,
                account_id: session.account_id,
                device_id: session.device_id,
                session_id: session.session_id,
            }),
            other => Ok(ClientAuthState::Error {
                server_url: session.server_url,
                error: format!("unrecognized session status '{other}'"),
            }),
        },
        Err(CliError::SessionRevoked) => Ok(ClientAuthState::Revoked {
            server_url: session.server_url,
            account_id: session.account_id,
            device_id: session.device_id,
            session_id: session.session_id,
        }),
        Err(CliError::SessionExpired) => Ok(ClientAuthState::Expired {
            server_url: session.server_url,
            account_id: session.account_id,
            device_id: session.device_id,
            session_id: session.session_id,
        }),
        Err(CliError::Network(msg)) => Ok(ClientAuthState::Offline {
            server_url: session.server_url,
            account_id: session.account_id,
            device_id: session.device_id,
            session_id: session.session_id,
            error: msg,
        }),
        Err(e) => Ok(ClientAuthState::Error {
            server_url: session.server_url,
            error: e.to_string(),
        }),
    }
}

/// Connects to a sync server and authorizes this terminal device (AC-02, AC-04).
///
/// Security and safety invariants:
/// - Server URL is validated and normalized prior to any network request.
/// - If verification or authorization fails, the prior valid local session is NOT modified.
/// - New session credentials are written with strict POSIX `0600` permissions.
pub async fn authorize_terminal_device(
    custom_data_dir: Option<&Path>,
    server_url_raw: &str,
    authorizing_token: &str,
    account_id_opt: Option<Uuid>,
    device_name_opt: Option<String>,
    device_id_opt: Option<Uuid>,
) -> Result<StoredAuthSession, CliError> {
    let clean_url = validate_and_normalize_server_url(server_url_raw)?;

    let token_trimmed = authorizing_token.trim();
    if token_trimmed.is_empty() {
        return Err(CliError::AuthError(
            "An existing session token is required to authorize this device.".to_string(),
        ));
    }

    let data_dir = resolve_data_dir(custom_data_dir);
    std::fs::create_dir_all(&data_dir).map_err(|e| CliError::Io(e.to_string()))?;

    let device_id = get_or_create_device_id(&data_dir, device_id_opt)?;

    // 1. Verify token with server
    let verified = api_verify_token(&clean_url, token_trimmed, device_id).await?;

    if let Some(expected_account) = account_id_opt {
        if expected_account != verified.account_id {
            return Err(CliError::AuthError(
                "Session token does not authorize the requested account ID".to_string(),
            ));
        }
    }

    // 2. Authorize device
    let auth_session = api_device_authorize(
        &clean_url,
        token_trimmed,
        verified.account_id,
        device_id,
        device_name_opt,
    )
    .await?;

    // 3. Persist session credentials with 0600 permissions
    let auth_path = auth_session_file(&data_dir);
    save_auth_session(&auth_path, &auth_session)?;

    Ok(auth_session)
}

/// Revokes the active session on the server and clears local credentials (AC-05).
///
/// Truthful revocation behavior:
/// - If server is unreachable or revocation fails, local credentials are NOT silently purged.
///   Instead, returns an error so credentials remain available for retry when online.
/// - If revocation succeeds, local credentials file is zeroed and deleted.
/// - Fails closed: propagates any cleanup/unlink errors and verifies absence before reporting success.
pub async fn sign_out(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);

    if !has_auth_session(&auth_path) {
        return Ok(());
    }

    let session = load_auth_session(&auth_path)?;

    // Attempt remote revocation (preserves local credentials on failure)
    api_revoke_session(&session).await?;

    // On successful revocation, zero and unlink local session file (fails closed)
    clear_auth_session(&auth_path)?;

    // Fail-closed verification: ensure credential file is completely gone
    if has_auth_session(&auth_path) {
        return Err(CliError::Io(format!(
            "auth session file {} still exists after sign-out cleanup",
            auth_path.display()
        )));
    }

    Ok(())
}

/// Explicitly purges local credentials without contacting server.
///
/// Fails closed: propagates any cleanup/unlink errors and verifies absence before reporting success.
pub fn force_clear_session(custom_data_dir: Option<&Path>) -> Result<(), CliError> {
    let data_dir = resolve_data_dir(custom_data_dir);
    let auth_path = auth_session_file(&data_dir);
    clear_auth_session(&auth_path)?;

    // Fail-closed verification: ensure credential file is completely gone
    if has_auth_session(&auth_path) {
        return Err(CliError::Io(format!(
            "auth session file {} still exists after force cleanup",
            auth_path.display()
        )));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use zk_protocol::auth::AuthToken;

    #[test]
    fn test_server_url_validation_loopback_allowed() {
        assert_eq!(
            validate_and_normalize_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_and_normalize_server_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_and_normalize_server_url("http://localhost:3000").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            validate_and_normalize_server_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        assert_eq!(
            validate_and_normalize_server_url("localhost:8080").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            validate_and_normalize_server_url("127.0.0.1:9090").unwrap(),
            "http://127.0.0.1:9090"
        );
    }

    #[test]
    fn test_server_url_validation_remote_https_required() {
        assert_eq!(
            validate_and_normalize_server_url("https://notes.example.com").unwrap(),
            "https://notes.example.com"
        );
        assert_eq!(
            validate_and_normalize_server_url("https://notes.example.com:8443/").unwrap(),
            "https://notes.example.com:8443"
        );
        assert_eq!(
            validate_and_normalize_server_url("notes.example.com").unwrap(),
            "https://notes.example.com"
        );

        // Insecure HTTP on remote host MUST fail
        let err = validate_and_normalize_server_url("http://notes.example.com").unwrap_err();
        assert!(err.to_string().contains("HTTPS is required"));

        // Insecure HTTP on LAN host MUST fail
        let lan_err = validate_and_normalize_server_url("http://192.168.1.100:8080").unwrap_err();
        assert!(lan_err.to_string().contains("HTTPS is required"));
    }

    #[test]
    fn test_server_url_validation_rejects_credentials_paths_queries() {
        // Empty
        assert!(validate_and_normalize_server_url("").is_err());
        assert!(validate_and_normalize_server_url("   ").is_err());

        // Credentials
        let user_err =
            validate_and_normalize_server_url("https://user:pass@example.com").unwrap_err();
        assert!(user_err.to_string().contains("credentials"));

        // Path
        let path_err = validate_and_normalize_server_url("https://example.com/api").unwrap_err();
        assert!(path_err.to_string().contains("path"));

        // Query
        let query_err =
            validate_and_normalize_server_url("https://example.com?foo=bar").unwrap_err();
        assert!(query_err.to_string().contains("query"));

        // Fragment
        let frag_err =
            validate_and_normalize_server_url("https://example.com#section").unwrap_err();
        assert!(frag_err.to_string().contains("fragment"));

        // Unsupported scheme
        let ftp_err = validate_and_normalize_server_url("ftp://example.com").unwrap_err();
        assert!(ftp_err.to_string().contains("Unsupported"));
    }

    pub(crate) async fn start_test_server() -> (
        String,
        zk_server::AppState,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let config = zk_server::ServerConfig::default();
        let state = zk_server::AppState::new_in_memory(config).expect("create test app state");
        let app = zk_server::create_app(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let local_addr = listener.local_addr().expect("get local addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (format!("http://{}", local_addr), state, shutdown_tx)
    }

    struct TempDataDir(std::path::PathBuf);

    impl TempDataDir {
        fn new(prefix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "zk_auth_srv_test_{}_{}",
                prefix,
                Uuid::new_v4()
            ));
            let _ = std::fs::create_dir_all(&path);
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn test_authorize_terminal_device_success_and_status() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("auth_success");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        let session = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Test Terminal".to_string()),
            None,
        )
        .await
        .expect("authorization succeeds");

        assert_eq!(session.account_id, account_id);
        assert_eq!(session.server_url, server_url);

        // Verify status online reports Authenticated
        let auth_state = check_auth_state_online(Some(dir_path))
            .await
            .expect("query status succeeds");
        match auth_state {
            ClientAuthState::Authenticated {
                server_url: s_url,
                account_id: a_id,
                device_id: d_id,
                session_id: s_id,
                ..
            } => {
                assert_eq!(s_url, server_url);
                assert_eq!(a_id, account_id);
                assert_eq!(d_id, session.device_id);
                assert!(s_id.is_some());
            }
            other => panic!("expected Authenticated state, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_authorize_terminal_device_invalid_token_fails_closed() {
        let (server_url, _state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("auth_invalid");
        let dir_path = test_dir.path();

        let result = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            "invalid_nonexistent_token_string",
            None,
            None,
            None,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            get_local_auth_state(Some(dir_path)).unwrap(),
            ClientAuthState::LocalOnly
        );
    }

    #[tokio::test]
    async fn test_failed_authorization_preserves_prior_valid_session() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("auth_preserve");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        // 1. Establish valid session
        let initial_session = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Original Device".to_string()),
            None,
        )
        .await
        .expect("initial auth succeeds");

        // 2. Attempt failed authorization with bad token
        let fail_res = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            "corrupted_bad_token",
            None,
            None,
            None,
        )
        .await;
        assert!(fail_res.is_err());

        // 3. Verify prior session is completely intact
        let loaded = crate::auth::load_auth_session(&auth_session_file(dir_path))
            .expect("load session succeeds");
        assert_eq!(loaded.account_id, initial_session.account_id);
        assert_eq!(loaded.device_id, initial_session.device_id);
        assert_eq!(loaded.session_id, initial_session.session_id);
        assert_eq!(
            loaded.token.expose_secret(),
            initial_session.token.expose_secret()
        );
    }

    #[tokio::test]
    async fn test_server_change_isolation() {
        let (server1_url, state1, _shutdown1) = start_test_server().await;
        let (server2_url, _state2, _shutdown2) = start_test_server().await;
        let test_dir = TempDataDir::new("srv_isolation");
        let dir_path = test_dir.path();

        let account_id1 = Uuid::new_v4();
        let (_, authorizer1) = state1
            .db
            .create_session(account_id1, None, None, Some(3600))
            .await
            .unwrap();

        // Authorize with server 1
        let session1 = authorize_terminal_device(
            Some(dir_path),
            &server1_url,
            authorizer1.expose_secret(),
            Some(account_id1),
            Some("Device 1".to_string()),
            None,
        )
        .await
        .expect("auth 1 succeeds");

        // Attempt to connect to server 2 with an invalid token
        let fail_res = authorize_terminal_device(
            Some(dir_path),
            &server2_url,
            "invalid_server2_token",
            None,
            None,
            None,
        )
        .await;
        assert!(fail_res.is_err());

        // Verify local session still points to server 1
        let current = crate::auth::load_auth_session(&auth_session_file(dir_path)).unwrap();
        assert_eq!(current.server_url, session1.server_url);
        assert_eq!(current.account_id, session1.account_id);
    }

    #[tokio::test]
    async fn test_sign_out_offline_preserves_credentials() {
        let (server_url, state, shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("sign_out_offline");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        let session = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Signout Test".to_string()),
            None,
        )
        .await
        .expect("auth succeeds");

        let auth_path = auth_session_file(dir_path);
        assert!(has_auth_session(&auth_path));

        // Terminate server to simulate offline / network partition
        let _ = shutdown.send(());
        // Wait a tiny bit for listener to close
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt sign-out while server is offline
        let sign_out_res = sign_out(Some(dir_path)).await;
        assert!(sign_out_res.is_err(), "offline sign out must return error");

        // Credentials MUST NOT be deleted so user can retry when online (AC-05)
        assert!(
            has_auth_session(&auth_path),
            "credentials must be preserved on offline sign-out failure"
        );
        let preserved = load_auth_session(&auth_path).unwrap();
        assert_eq!(preserved.account_id, session.account_id);

        // Status check reports Offline
        let st = check_auth_state_online(Some(dir_path)).await.unwrap();
        assert!(st.is_offline(), "must report Offline state");
    }

    #[tokio::test]
    async fn test_sign_out_online_revokes_and_clears_credentials() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("sign_out_online");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Signout Success".to_string()),
            None,
        )
        .await
        .expect("auth succeeds");

        let auth_path = auth_session_file(dir_path);
        assert!(has_auth_session(&auth_path));

        // Sign out online
        sign_out(Some(dir_path)).await.expect("sign out succeeds");

        // Credentials file must be zeroed and deleted
        assert!(!has_auth_session(&auth_path));
        assert_eq!(
            get_local_auth_state(Some(dir_path)).unwrap(),
            ClientAuthState::LocalOnly
        );
    }

    #[tokio::test]
    async fn test_revoked_session_reporting() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("revoked_reporting");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        let session = authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Revoke Test".to_string()),
            None,
        )
        .await
        .expect("auth succeeds");

        // Revoke device on server
        state
            .db
            .revoke_device(account_id, session.device_id)
            .await
            .unwrap();

        // Status check reports Revoked
        let st = check_auth_state_online(Some(dir_path)).await.unwrap();
        assert!(st.is_revoked(), "must report Revoked state");
    }

    #[test]
    fn test_force_clear_session_fails_closed_on_cleanup_failure() {
        let test_dir = TempDataDir::new("force_clear_fail");
        let dir_path = test_dir.path();
        let auth_path = auth_session_file(dir_path);

        // Make auth_session.json an invalid/non-removable target (directory)
        std::fs::create_dir(&auth_path).unwrap();
        assert!(has_auth_session(&auth_path));

        let res = force_clear_session(Some(dir_path));
        assert!(
            res.is_err(),
            "force_clear_session must fail closed on cleanup error"
        );
        assert!(
            has_auth_session(&auth_path),
            "credential target must remain present on failure"
        );

        let _ = std::fs::remove_dir(&auth_path);
    }

    #[tokio::test]
    async fn test_sign_out_fails_closed_when_credential_cleanup_fails() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("sign_out_cleanup_fail");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        let (_, authorizer) = state
            .db
            .create_session(account_id, None, None, Some(3600))
            .await
            .unwrap();

        authorize_terminal_device(
            Some(dir_path),
            &server_url,
            authorizer.expose_secret(),
            Some(account_id),
            Some("Cleanup Failure Test".to_string()),
            None,
        )
        .await
        .expect("auth succeeds");

        let auth_path = auth_session_file(dir_path);
        assert!(has_auth_session(&auth_path));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Prevent deletion of auth_session.json by removing write permissions from enclosing directory
            let mut perms = std::fs::metadata(dir_path).unwrap().permissions();
            perms.set_mode(0o500);
            std::fs::set_permissions(dir_path, perms).unwrap();

            let sign_out_res = sign_out(Some(dir_path)).await;
            assert!(
                sign_out_res.is_err(),
                "sign_out must fail closed when local file cleanup fails"
            );
            assert!(
                has_auth_session(&auth_path),
                "credentials must not be falsely reported deleted"
            );

            // Restore permissions for cleanup
            let mut restore_perms = std::fs::metadata(dir_path).unwrap().permissions();
            restore_perms.set_mode(0o700);
            let _ = std::fs::set_permissions(dir_path, restore_perms);
        }
    }

    #[tokio::test]
    async fn test_expired_session_reporting_server_401() {
        let (server_url, state, _shutdown) = start_test_server().await;
        let test_dir = TempDataDir::new("expired_reporting");
        let dir_path = test_dir.path();

        let account_id = Uuid::new_v4();
        // Create session expired in the past (-10 seconds TTL)
        let (server_sess, token) = state
            .db
            .create_session(
                account_id,
                None,
                Some("Expired Session".to_string()),
                Some(-10),
            )
            .await
            .unwrap();

        let session = StoredAuthSession {
            server_url: server_url.clone(),
            account_id,
            device_id: server_sess.device_id.unwrap_or_else(Uuid::new_v4),
            session_id: Some(server_sess.session_id),
            token,
            expires_at: None,
        };
        save_auth_session(&auth_session_file(dir_path), &session).unwrap();

        let st = check_auth_state_online(Some(dir_path)).await.unwrap();
        assert!(
            st.is_expired(),
            "must report Expired state on server 401 AUTH_EXPIRED"
        );
        match st {
            ClientAuthState::Expired {
                server_url: s_url,
                account_id: a_id,
                ..
            } => {
                assert_eq!(s_url, server_url);
                assert_eq!(a_id, account_id);
            }
            other => panic!("expected Expired state, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_session_status_fails_closed() {
        use axum::routing::get;
        let app = axum::Router::new().route(
            "/v1/auth/session/status",
            get(|| async {
                axum::Json(serde_json::json!({
                    "account_id": Uuid::new_v4(),
                    "device_id": Uuid::new_v4(),
                    "status": "suspended" // unrecognized status
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let local_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let test_dir = TempDataDir::new("unknown_status_fail");
        let dir_path = test_dir.path();
        let session = StoredAuthSession {
            server_url: format!("http://{}", local_addr),
            account_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
            token: AuthToken::new("mock_token"),
            expires_at: None,
        };
        save_auth_session(&auth_session_file(dir_path), &session).unwrap();

        let st = check_auth_state_online(Some(dir_path)).await.unwrap();
        assert!(
            !st.is_authenticated(),
            "unknown status must not be treated as Authenticated"
        );
        match st {
            ClientAuthState::Error { error, .. } => {
                assert!(error.contains("unrecognized session status 'suspended'"));
            }
            other => panic!("expected Error state, got {other:?}"),
        }
        let _ = shutdown_tx.send(());
    }

    #[test]
    fn test_local_auth_state_returns_unverified_when_credentials_exist() {
        let test_dir = TempDataDir::new("local_unverified");
        let dir_path = test_dir.path();

        // When no credentials exist
        assert_eq!(
            get_local_auth_state(Some(dir_path)).unwrap(),
            ClientAuthState::LocalOnly
        );

        // When credentials exist
        let session = StoredAuthSession {
            server_url: "https://notes.example.com".to_string(),
            account_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            session_id: Some(Uuid::new_v4()),
            token: AuthToken::new("test_tok"),
            expires_at: None,
        };
        save_auth_session(&auth_session_file(dir_path), &session).unwrap();

        let state = get_local_auth_state(Some(dir_path)).unwrap();
        assert!(
            state.is_unverified(),
            "saved credentials must initialize as unverified"
        );
        assert_eq!(state.server_url(), Some("https://notes.example.com"));
        assert_eq!(state.account_id(), Some(session.account_id));
    }
}
