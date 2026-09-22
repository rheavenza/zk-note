//! Authentication and authorization extractors, token validators, and auth middleware (ZK-070).
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - Server authentication is completely decoupled from the client's vault passphrase and encryption keys.
//! - The server verifies opaque bearer tokens (cryptographic session digests or account tokens).
//! - Access tokens and credentials MUST NEVER be logged or reflected in error responses.
//! - The authentication middleware owns account identity and verifies callers before request handlers run.

use crate::app::ErrorResponse;
use crate::db::SessionValidationResult;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use uuid::Uuid;

/// An authenticated account extracted from the HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedAccount {
    /// Unique account ID of the caller.
    pub account_id: Uuid,
    /// Optional associated device ID, if authenticated via device-bound session.
    pub device_id: Option<Uuid>,
    /// Optional associated session ID, if authenticated via session token.
    pub session_id: Option<Uuid>,
}

impl AuthenticatedAccount {
    /// Creates a new authenticated account identity with just an account ID.
    #[must_use]
    pub fn new(account_id: Uuid) -> Self {
        Self {
            account_id,
            device_id: None,
            session_id: None,
        }
    }

    /// Creates an authenticated account identity with device and session details.
    #[must_use]
    pub fn with_details(
        account_id: Uuid,
        device_id: Option<Uuid>,
        session_id: Option<Uuid>,
    ) -> Self {
        Self {
            account_id,
            device_id,
            session_id,
        }
    }
}

/// Authentication and authorization errors returned by [`AuthenticatedAccount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Authorization header is missing.
    MissingHeader,
    /// Authorization scheme is not Bearer.
    InvalidScheme,
    /// Bearer token is not a valid account or session identifier.
    InvalidToken,
    /// Session token has expired.
    ExpiredToken,
    /// Session token has been explicitly revoked.
    RevokedToken,
    /// Associated device has been revoked.
    DeviceRevoked,
    /// Caller attempted to access a different account or device than authorized.
    ForbiddenAccountAccess,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            Self::MissingHeader => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_REQUIRED.to_string(),
                    message: "Authorization header is required".to_string(),
                }),
            )
                .into_response(),
            Self::InvalidScheme => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_REQUIRED.to_string(),
                    message: "Authorization scheme must be Bearer".to_string(),
                }),
            )
                .into_response(),
            Self::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_REQUIRED.to_string(),
                    message: "Invalid or malformed authorization token".to_string(),
                }),
            )
                .into_response(),
            Self::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_EXPIRED.to_string(),
                    message: "Authorization token has expired".to_string(),
                }),
            )
                .into_response(),
            Self::RevokedToken => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_REVOKED.to_string(),
                    message: "Authorization token has been revoked".to_string(),
                }),
            )
                .into_response(),
            Self::DeviceRevoked => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_DEVICE_REVOKED.to_string(),
                    message: "Associated device has been revoked".to_string(),
                }),
            )
                .into_response(),
            Self::ForbiddenAccountAccess => (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    code: zk_protocol::ERROR_AUTH_FORBIDDEN.to_string(),
                    message: "Cross-account access denied".to_string(),
                }),
            )
                .into_response(),
        }
    }
}

/// Authenticates an opaque bearer token against the server database.
///
/// In accordance with SEC-001 and SEC-002:
/// - Server authentication is completely decoupled from the vault passphrase.
/// - Validates cryptographic session token digests and/or legacy account UUID tokens.
/// - Checks expiration, revocation, and device status.
/// - Never logs or reflects raw token strings.
pub async fn authenticate_bearer_token(
    db: &crate::db::ServerDb,
    token: &str,
) -> Result<AuthenticatedAccount, AuthError> {
    // 1. Check if token matches an active session (by BLAKE2s digest)
    match db.validate_session_token(token).await {
        Ok(Some(SessionValidationResult::Valid {
            account_id,
            device_id,
            session_id,
        })) => {
            return Ok(AuthenticatedAccount::with_details(
                account_id,
                device_id,
                Some(session_id),
            ));
        }
        Ok(Some(SessionValidationResult::Expired)) => {
            return Err(AuthError::ExpiredToken);
        }
        Ok(Some(SessionValidationResult::Revoked)) => {
            return Err(AuthError::RevokedToken);
        }
        Ok(Some(SessionValidationResult::DeviceRevoked)) => {
            return Err(AuthError::DeviceRevoked);
        }
        Ok(None) => {}
        Err(_) => return Err(AuthError::InvalidToken),
    }

    Err(AuthError::InvalidToken)
}

/// Axum middleware that intercepts protected requests, validates authentication,
/// enforces cross-account boundaries, and injects [`AuthenticatedAccount`] into request extensions.
///
/// Acceptance criterion: "auth middleware owns account identity"
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<crate::app::AppState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let auth_header = match req.headers().get(axum::http::header::AUTHORIZATION) {
        Some(val) => match val.to_str() {
            Ok(s) => s,
            Err(_) => return AuthError::InvalidToken.into_response(),
        },
        None => return AuthError::MissingHeader.into_response(),
    };

    let token = match auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
    {
        Some(t) => t.trim(),
        None => return AuthError::InvalidScheme.into_response(),
    };

    if token.is_empty() {
        return AuthError::InvalidToken.into_response();
    }

    let authenticated = match authenticate_bearer_token(&state.db, token).await {
        Ok(auth) => auth,
        Err(err) => return err.into_response(),
    };

    // Cross-account boundary check if explicit target account header is supplied
    if let Some(target_acc_header) = req.headers().get("x-account-id") {
        if let Ok(target_acc_str) = target_acc_header.to_str() {
            if let Ok(target_acc_id) = Uuid::parse_str(target_acc_str.trim()) {
                if target_acc_id != authenticated.account_id {
                    return AuthError::ForbiddenAccountAccess.into_response();
                }
            }
        }
    }

    // Cross-device boundary check if explicit target device header is supplied
    if let Some(target_dev_header) = req.headers().get("x-device-id") {
        if let Ok(target_dev_str) = target_dev_header.to_str() {
            if let Ok(target_dev_id) = Uuid::parse_str(target_dev_str.trim()) {
                if let Some(auth_dev_id) = authenticated.device_id {
                    if target_dev_id != auth_dev_id {
                        return AuthError::ForbiddenAccountAccess.into_response();
                    }
                }
            }
        }
    }

    // Inject verified identity into request extensions for handlers to consume
    req.extensions_mut().insert(authenticated);

    next.run(req).await
}

impl<S> FromRequestParts<S> for AuthenticatedAccount
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // First check if auth middleware already verified and attached AuthenticatedAccount
        if let Some(account) = parts.extensions.get::<AuthenticatedAccount>() {
            return Ok(*account);
        }

        Err(AuthError::MissingHeader)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::db::ServerDb;
    use axum::http::Request;

    #[tokio::test]
    async fn account_id_is_not_a_credential() {
        let db = ServerDb::new_in_memory().unwrap();
        let account = Uuid::new_v4();
        assert!(authenticate_bearer_token(&db, &account.to_string())
            .await
            .is_err());
        let (mut parts, _) = Request::builder()
            .header("Authorization", format!("Bearer {account}"))
            .body(())
            .unwrap()
            .into_parts();
        assert!(AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_auth_with_session_token_and_revocation() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let dev_id = Uuid::new_v4();

        // 1. Create a session
        let (sess, token) = db
            .create_session(
                acc_id,
                Some(dev_id),
                Some("Web Client".to_string()),
                Some(3600),
            )
            .await
            .unwrap();

        // 2. Authenticate token
        let auth = authenticate_bearer_token(&db, token.expose_secret())
            .await
            .unwrap();
        assert_eq!(auth.account_id, acc_id);
        assert_eq!(auth.device_id, Some(dev_id));
        assert_eq!(auth.session_id, Some(sess.session_id));

        // 3. Revoke session
        db.revoke_session(acc_id, sess.session_id).await.unwrap();

        // 4. Authenticate again -> RevokedToken error
        let err = authenticate_bearer_token(&db, token.expose_secret())
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::RevokedToken);
    }

    #[tokio::test]
    async fn test_auth_revoked_device_fails_closed() {
        let db = ServerDb::new_in_memory().unwrap();
        let acc_id = Uuid::new_v4();
        let dev_id = Uuid::new_v4();

        db.register_device(acc_id, dev_id, Some("Phone"))
            .await
            .unwrap();

        let (_sess, token) = db
            .create_session(
                acc_id,
                Some(dev_id),
                Some("Phone Session".to_string()),
                None,
            )
            .await
            .unwrap();

        // Active
        assert!(authenticate_bearer_token(&db, token.expose_secret())
            .await
            .is_ok());

        // Revoke device
        db.revoke_device(acc_id, dev_id).await.unwrap();

        // Must fail closed
        let err = authenticate_bearer_token(&db, token.expose_secret())
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::RevokedToken | AuthError::DeviceRevoked),
            "revoked device must reject authentication"
        );
    }

    #[tokio::test]
    async fn test_error_responses_never_leak_token_sec_003() {
        let secret = "super_secret_token_12345";
        let err_resp = AuthError::InvalidToken.into_response();
        assert_eq!(err_resp.status(), StatusCode::UNAUTHORIZED);

        let bytes = axum::body::to_bytes(err_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_str = String::from_utf8_lossy(&bytes);

        assert!(!json_str.contains(secret));
        assert!(json_str.contains(zk_protocol::ERROR_AUTH_REQUIRED));
    }
}
