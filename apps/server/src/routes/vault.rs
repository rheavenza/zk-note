//! Vault bootstrap endpoint handlers.
//!
//! In accordance with SEC-001 and SEC-002:
//! - Plaintext notes, passwords, and decrypted keys are never accepted or stored.
//! - Server stores only KDF parameters and wrapped key envelopes.

use crate::app::{AppState, ErrorResponse};
use crate::auth::AuthenticatedAccount;
use crate::error::DbError;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64ct::{Base64, Encoding};
use zk_protocol::constants::PROTOCOL_VERSION_V1;
use zk_protocol::vault::VaultBootstrap;

/// Recursively scans JSON for any forbidden secret or passphrase fields.
pub fn contains_forbidden_keys(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "passphrase"
                        | "password"
                        | "vault_passphrase"
                        | "vault_key"
                        | "plaintext"
                        | "master_key"
                        | "secret"
                ) {
                    return true;
                }
                if contains_forbidden_keys(v) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(list) => list.iter().any(contains_forbidden_keys),
        _ => false,
    }
}

/// Handler for `POST /v1/vault/bootstrap`.
pub async fn create_vault_bootstrap_handler(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    body_bytes: Bytes,
) -> impl IntoResponse {
    // 1. Parse JSON and verify absence of passphrase or plaintext secret fields
    let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_VAULT_BOOTSTRAP".to_string(),
                    message: format!("Malformed JSON payload: {e}"),
                }),
            )
                .into_response();
        }
    };

    if contains_forbidden_keys(&json_val) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_VAULT_BOOTSTRAP".to_string(),
                message: "Passphrase and plaintext secrets MUST NOT be transmitted to the server (SEC-001/SEC-002)".to_string(),
            }),
        )
            .into_response();
    }

    // 2. Deserialize into strongly-typed VaultBootstrap
    let bootstrap: VaultBootstrap = match serde_json::from_value(json_val) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "INVALID_VAULT_BOOTSTRAP".to_string(),
                    message: format!("Invalid vault bootstrap structure: {e}"),
                }),
            )
                .into_response();
        }
    };

    // 3. Cryptographic and structure validation
    if bootstrap.crypto_version != PROTOCOL_VERSION_V1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: zk_protocol::ERROR_CRYPTO_UNSUPPORTED_VERSION.to_string(),
                message: format!(
                    "Unsupported crypto_version '{}', expected {PROTOCOL_VERSION_V1}",
                    bootstrap.crypto_version
                ),
            }),
        )
            .into_response();
    }

    if bootstrap.kdf.algorithm.trim().is_empty()
        || bootstrap.kdf.memory_kib == 0
        || bootstrap.kdf.iterations == 0
        || bootstrap.kdf.parallelism == 0
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_VAULT_BOOTSTRAP".to_string(),
                message: "KDF parameters cannot be zero or empty".to_string(),
            }),
        )
            .into_response();
    }

    if Base64::decode_vec(&bootstrap.kdf.salt).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_VAULT_BOOTSTRAP".to_string(),
                message: "KDF salt must be valid standard Base64".to_string(),
            }),
        )
            .into_response();
    }

    // 4. Save to database
    match state
        .db
        .create_vault_bootstrap(auth.account_id, &bootstrap)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(bootstrap)).into_response(),
        Err(DbError::VaultAlreadyExists(_)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "VAULT_ALREADY_EXISTS".to_string(),
                message: "Vault has already been initialized for this account".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to store vault bootstrap: {e}"),
            }),
        )
            .into_response(),
    }
}

/// Handler for `GET /v1/vault/bootstrap`.
pub async fn get_vault_bootstrap_handler(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
) -> impl IntoResponse {
    match state.db.get_vault_bootstrap(auth.account_id).await {
        Ok(Some(bootstrap)) => (StatusCode::OK, Json(bootstrap)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: zk_protocol::ERROR_OBJECT_NOT_FOUND.to_string(),
                message: "Vault bootstrap not found for this account".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to retrieve vault bootstrap: {e}"),
            }),
        )
            .into_response(),
    }
}
