//! WebAuthn / Passkey authentication endpoints and session revocation (ZK-071).
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - WebAuthn routes handle server identity and account session provisioning.
//! - Vault passphrases and Vault Keys MUST NOT be accepted or handled in auth endpoints.
//! - Access tokens are returned in the response payload and are NEVER emitted to logs.

use crate::app::{AppState, ErrorResponse};
use crate::auth::AuthenticatedAccount;
use crate::error::DbError;
use crate::routes::vault::contains_forbidden_keys;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use uuid::Uuid;
use zk_protocol::auth::SessionResponse;
use zk_protocol::constants::{
    ERROR_AUTH_REQUIRED, ERROR_CRYPTO_AUTH_FAILED, ERROR_WEBAUTHN_CHALLENGE_EXPIRED,
    ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND, ERROR_WEBAUTHN_CREDENTIAL_EXISTS,
    ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND, ERROR_WEBAUTHN_VERIFICATION_FAILED,
};
use zk_protocol::webauthn::{
    RevokeSessionRequest, RevokeSessionResponse, WebAuthnLoginFinishRequest,
    WebAuthnLoginFinishResponse, WebAuthnLoginStartRequest, WebAuthnLoginStartResponse,
    WebAuthnRegisterFinishRequest, WebAuthnRegisterFinishResponse, WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse, WebAuthnRpInfo, WebAuthnUserInfo,
};

/// Helper to decode base64 or base64url strings into raw bytes.
fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, ()> {
    let trimmed = input.trim();
    if let Ok(bytes) = Base64UrlUnpadded::decode_vec(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = Base64::decode_vec(trimmed) {
        return Ok(bytes);
    }
    // Fallback: try adding padding
    let padded = match trimmed.len() % 4 {
        2 => format!("{trimmed}=="),
        3 => format!("{trimmed}="),
        _ => trimmed.to_string(),
    };
    if let Ok(bytes) = Base64::decode_vec(&padded) {
        return Ok(bytes);
    }
    Err(())
}

/// Generates a cryptographically secure 32-byte challenge using OS CSPRNG.
fn generate_secure_challenge() -> (Uuid, [u8; 32], String) {
    let challenge_id = Uuid::new_v4();
    let c1 = Uuid::new_v4();
    let c2 = Uuid::new_v4();
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(c1.as_bytes());
    bytes[16..].copy_from_slice(c2.as_bytes());
    let b64 = Base64UrlUnpadded::encode_string(&bytes);
    (challenge_id, bytes, b64)
}

/// Handler for `POST /v1/auth/webauthn/register/start`.
pub async fn webauthn_register_start_handler(
    State(state): State<AppState>,
    Json(req): Json<WebAuthnRegisterStartRequest>,
) -> Response {
    let (challenge_id, challenge_bytes, challenge_b64) = generate_secure_challenge();

    // 5-minute challenge TTL
    if let Err(e) = state
        .db
        .create_webauthn_challenge(
            challenge_id,
            &challenge_bytes,
            req.account_id,
            "register",
            300,
        )
        .await
    {
        tracing::error!("failed to create webauthn registration challenge: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "DATABASE_ERROR".to_string(),
                message: "Failed to create registration challenge".to_string(),
            }),
        )
            .into_response();
    }

    let user_id = req.account_id.unwrap_or_else(Uuid::new_v4);
    let username = req
        .username
        .unwrap_or_else(|| format!("user_{}", &user_id.to_string()[..8]));
    let display_name = req.display_name.unwrap_or_else(|| username.clone());

    (
        StatusCode::OK,
        Json(WebAuthnRegisterStartResponse {
            challenge_id,
            challenge_b64,
            rp: WebAuthnRpInfo::default(),
            user: WebAuthnUserInfo {
                id: user_id.to_string(),
                name: username,
                display_name,
            },
        }),
    )
        .into_response()
}

/// Handler for `POST /v1/auth/webauthn/register/finish`.
pub async fn webauthn_register_finish_handler(
    State(state): State<AppState>,
    body_bytes: Bytes,
) -> Response {
    // 1. Audit payload for forbidden secrets (SEC-001, SEC-002: no passphrase reuse)
    let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "MALFORMED_JSON".to_string(),
                    message: format!("Invalid JSON payload: {e}"),
                }),
            )
                .into_response();
        }
    };

    if contains_forbidden_keys(&json_val) {
        tracing::warn!("rejected webauthn registration containing forbidden passphrase/key fields");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_CRYPTO_AUTH_FAILED.to_string(),
                message: "Passphrase or vault key material must not be submitted to authentication endpoints".to_string(),
            }),
        )
            .into_response();
    }

    // 2. Deserialize request
    let req: WebAuthnRegisterFinishRequest = match serde_json::from_value(json_val) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "MALFORMED_REQUEST".to_string(),
                    message: format!("Missing or invalid WebAuthn registration parameters: {e}"),
                }),
            )
                .into_response();
        }
    };

    // 3. Consume challenge from database (single-use, verifies TTL)
    let challenge_record = match state
        .db
        .consume_webauthn_challenge(req.challenge_id, "register")
        .await
    {
        Ok(c) => c,
        Err(DbError::ChallengeExpired) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CHALLENGE_EXPIRED.to_string(),
                    message: "WebAuthn registration challenge has expired".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND.to_string(),
                    message: "Registration challenge not found or already consumed".to_string(),
                }),
            )
                .into_response();
        }
    };

    // 4. Decode credential ID and public key
    let cred_id_bytes = match decode_base64_flexible(&req.credential_id) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_CREDENTIAL_ID".to_string(),
                    message: "Credential ID is not valid base64/base64url".to_string(),
                }),
            )
                .into_response();
        }
    };

    let pubkey_bytes = match decode_base64_flexible(&req.public_key) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_PUBLIC_KEY".to_string(),
                    message: "Public key is not valid base64/base64url".to_string(),
                }),
            )
                .into_response();
        }
    };

    let account_id = challenge_record.account_id.unwrap_or_else(Uuid::new_v4);

    // 5. Register credential in database
    if let Err(e) = state
        .db
        .register_webauthn_credential(
            &cred_id_bytes,
            account_id,
            &pubkey_bytes,
            req.device_id,
            req.display_name.clone(),
        )
        .await
    {
        return match e {
            DbError::CredentialAlreadyExists => (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CREDENTIAL_EXISTS.to_string(),
                    message: "This passkey credential is already registered".to_string(),
                }),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DATABASE_ERROR".to_string(),
                    message: "Failed to persist WebAuthn credential".to_string(),
                }),
            )
                .into_response(),
        };
    }

    // 6. Provision active authentication session
    let (session, token) = match state
        .db
        .create_session(account_id, req.device_id, req.display_name, None)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("failed to create session after webauthn registration: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "SESSION_CREATION_FAILED".to_string(),
                    message: "Failed to provision session".to_string(),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(WebAuthnRegisterFinishResponse {
            session: SessionResponse {
                token,
                session_id: session.session_id,
                account_id,
                device_id: req.device_id,
                expires_at: session.expires_at,
            },
        }),
    )
        .into_response()
}

/// Handler for `POST /v1/auth/webauthn/login/start`.
pub async fn webauthn_login_start_handler(
    State(state): State<AppState>,
    Json(req): Json<WebAuthnLoginStartRequest>,
) -> Response {
    let (challenge_id, challenge_bytes, challenge_b64) = generate_secure_challenge();

    if let Err(e) = state
        .db
        .create_webauthn_challenge(challenge_id, &challenge_bytes, req.account_id, "login", 300)
        .await
    {
        tracing::error!("failed to create webauthn login challenge: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "DATABASE_ERROR".to_string(),
                message: "Failed to create login challenge".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(WebAuthnLoginStartResponse {
            challenge_id,
            challenge_b64,
            rp_id: "localhost".to_string(),
        }),
    )
        .into_response()
}

/// Handler for `POST /v1/auth/webauthn/login/finish`.
pub async fn webauthn_login_finish_handler(
    State(state): State<AppState>,
    body_bytes: Bytes,
) -> Response {
    // 1. Audit payload for forbidden secrets
    let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "MALFORMED_JSON".to_string(),
                    message: format!("Invalid JSON payload: {e}"),
                }),
            )
                .into_response();
        }
    };

    if contains_forbidden_keys(&json_val) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_CRYPTO_AUTH_FAILED.to_string(),
                message: "Passphrase or vault key material must not be submitted to authentication endpoints".to_string(),
            }),
        )
            .into_response();
    }

    let req: WebAuthnLoginFinishRequest = match serde_json::from_value(json_val) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "MALFORMED_REQUEST".to_string(),
                    message: format!("Missing or invalid WebAuthn login parameters: {e}"),
                }),
            )
                .into_response();
        }
    };

    // 2. Consume challenge from database
    let challenge_record = match state
        .db
        .consume_webauthn_challenge(req.challenge_id, "login")
        .await
    {
        Ok(c) => c,
        Err(DbError::ChallengeExpired) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CHALLENGE_EXPIRED.to_string(),
                    message: "WebAuthn login challenge has expired".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND.to_string(),
                    message: "Login challenge not found or already consumed".to_string(),
                }),
            )
                .into_response();
        }
    };

    // 3. Decode credential ID and signature
    let cred_id_bytes = match decode_base64_flexible(&req.credential_id) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_CREDENTIAL_ID".to_string(),
                    message: "Credential ID is not valid base64/base64url".to_string(),
                }),
            )
                .into_response();
        }
    };

    if decode_base64_flexible(&req.signature).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_WEBAUTHN_VERIFICATION_FAILED.to_string(),
                message: "Signature is not valid base64/base64url".to_string(),
            }),
        )
            .into_response();
    }

    // 4. Look up registered passkey credential
    let credential = match state.db.get_webauthn_credential(&cred_id_bytes).await {
        Ok(Some(cred)) => cred,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND.to_string(),
                    message: "Passkey credential not recognized for this system".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("database lookup failure for passkey: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "DATABASE_ERROR".to_string(),
                    message: "Failed to look up credential".to_string(),
                }),
            )
                .into_response();
        }
    };

    // 5. If challenge was tied to an account, verify match
    if let Some(target_acc) = challenge_record.account_id {
        if target_acc != credential.account_id {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    code: ERROR_AUTH_REQUIRED.to_string(),
                    message: "Credential does not match requested account".to_string(),
                }),
            )
                .into_response();
        }
    }

    // 6. Update usage sign counter
    let _ = state
        .db
        .update_webauthn_credential_usage(&cred_id_bytes, credential.sign_count + 1)
        .await;

    // 7. Provision active session
    let (session, token) = match state
        .db
        .create_session(
            credential.account_id,
            req.device_id.or(credential.device_id),
            credential.display_name,
            None,
        )
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("failed to create session after webauthn login: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "SESSION_CREATION_FAILED".to_string(),
                    message: "Failed to provision session".to_string(),
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(WebAuthnLoginFinishResponse {
            session: SessionResponse {
                token,
                session_id: session.session_id,
                account_id: credential.account_id,
                device_id: req.device_id.or(credential.device_id),
                expires_at: session.expires_at,
            },
        }),
    )
        .into_response()
}

/// Handler for `POST /v1/auth/session/revoke`.
pub async fn revoke_session_handler(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    Json(req): Json<RevokeSessionRequest>,
) -> Response {
    let Some(target_session) = req.session_id.or(auth.session_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "NO_SESSION_IDENTIFIER".to_string(),
                message: "No session ID specified or present in auth token".to_string(),
            }),
        )
            .into_response();
    };

    match state
        .db
        .revoke_session(auth.account_id, target_session)
        .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(RevokeSessionResponse {
                status: "revoked".to_string(),
                revoked_session_id: target_session,
            }),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(RevokeSessionResponse {
                status: "session_not_found_or_already_revoked".to_string(),
                revoked_session_id: target_session,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("failed to revoke session {target_session}: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RevokeSessionResponse {
                    status: "error".to_string(),
                    revoked_session_id: target_session,
                }),
            )
                .into_response()
        }
    }
}
