//! Authentication and authorization extractors.

use crate::app::ErrorResponse;
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
}

/// Authentication and authorization errors returned by [`AuthenticatedAccount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Authorization header is missing.
    MissingHeader,
    /// Authorization scheme is not Bearer.
    InvalidScheme,
    /// Bearer token is not a valid account identifier.
    InvalidToken,
    /// Caller attempted to access a different account than authorized.
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

impl<S> FromRequestParts<S> for AuthenticatedAccount
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingHeader)?
            .to_str()
            .map_err(|_| AuthError::InvalidToken)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or(AuthError::InvalidScheme)?
            .trim();

        if token.is_empty() {
            return Err(AuthError::InvalidToken);
        }

        let account_id = Uuid::parse_str(token).map_err(|_| AuthError::InvalidToken)?;

        // Enforce cross-account boundary if explicit target account header is supplied
        if let Some(target_acc_header) = parts.headers.get("x-account-id") {
            if let Ok(target_acc_str) = target_acc_header.to_str() {
                if let Ok(target_acc_id) = Uuid::parse_str(target_acc_str.trim()) {
                    if target_acc_id != account_id {
                        return Err(AuthError::ForbiddenAccountAccess);
                    }
                }
            }
        }

        Ok(AuthenticatedAccount { account_id })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn test_auth_valid_bearer() {
        let acc_id = Uuid::new_v4();
        let req = Request::builder()
            .header("Authorization", format!("Bearer {acc_id}"))
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        let auth = AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(auth.account_id, acc_id);
    }

    #[tokio::test]
    async fn test_auth_missing_header() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::MissingHeader);
    }

    #[tokio::test]
    async fn test_auth_invalid_scheme() {
        let req = Request::builder()
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::InvalidScheme);
    }

    #[tokio::test]
    async fn test_auth_invalid_token() {
        let req = Request::builder()
            .header("Authorization", "Bearer not-a-uuid")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::InvalidToken);
    }

    #[tokio::test]
    async fn test_auth_cross_account_forbidden() {
        let acc_id = Uuid::new_v4();
        let other_acc = Uuid::new_v4();
        let req = Request::builder()
            .header("Authorization", format!("Bearer {acc_id}"))
            .header("x-account-id", other_acc.to_string())
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let err = AuthenticatedAccount::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::ForbiddenAccountAccess);
    }
}
