//! Ciphertext blob storage endpoint handlers (ZK-082).
//!
//! In accordance with MASTER_SPEC.md § 14, SEC-001, SEC-002, and SEC-003:
//! - Plaintext notes, attachment filenames, and MIME types MUST NEVER be transmitted to or stored on the server.
//! - Server stores ONLY opaque blob IDs and encrypted ciphertext chunk bytes.
//! - Access is strictly authorized and isolated per account.
//! - Quotas and maximum single blob sizes are strictly enforced.

use crate::app::{AppState, ErrorResponse};
use crate::auth::AuthenticatedAccount;
use crate::error::DbError;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{HeaderMap, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use zk_protocol::constants::{
    ERROR_BLOB_NOT_FOUND, ERROR_PAYLOAD_TOO_LARGE, ERROR_QUOTA_EXCEEDED, ERROR_SERVER_FAILURE,
};

/// Validates that an opaque blob ID meets format and safety requirements.
///
/// Blob IDs must be 1 to 128 characters of ASCII alphanumeric characters, hyphens, or underscores.
#[must_use]
pub fn is_valid_blob_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validates that incoming request headers do NOT contain forbidden plaintext metadata.
///
/// Under SEC-001/SEC-002, attachment filenames, MIME types, or note plaintext metadata
/// must never be sent to the server.
pub fn contains_forbidden_plaintext_headers(headers: &HeaderMap) -> bool {
    let forbidden_names = [
        "x-filename",
        "x-file-name",
        "x-mime-type",
        "x-mime",
        "x-content-type-original",
        "x-note-id",
        "x-note-title",
        "x-tag",
    ];

    for name in forbidden_names {
        if headers.contains_key(name) {
            return true;
        }
    }
    false
}

/// Handler for `PUT /v1/blobs/{blob_id}` (ZK-082).
///
/// Uploads an opaque ciphertext blob for the authenticated account.
pub async fn put_blob_handler(
    Path(blob_id): Path<String>,
    auth: AuthenticatedAccount,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_valid_blob_id(&blob_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_BLOB_ID".to_string(),
                message: "Blob ID must be 1-128 alphanumeric, hyphen, or underscore characters"
                    .to_string(),
            }),
        )
            .into_response();
    }

    if contains_forbidden_plaintext_headers(&headers) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "PLAINTEXT_METADATA_FORBIDDEN".to_string(),
                message: "Plaintext attachment metadata headers are strictly prohibited (SEC-001)"
                    .to_string(),
            }),
        )
            .into_response();
    }

    if body.len() > state.config.max_blob_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                code: ERROR_PAYLOAD_TOO_LARGE.to_string(),
                message: format!(
                    "Blob size ({} bytes) exceeds maximum single blob size limit ({} bytes)",
                    body.len(),
                    state.config.max_blob_size
                ),
            }),
        )
            .into_response();
    }

    match state
        .db
        .put_blob(
            auth.account_id,
            &blob_id,
            &body,
            state.config.account_blob_quota,
            state.config.max_blob_size,
        )
        .await
    {
        Ok(size) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "blob_id": blob_id,
                "size": size,
            })),
        )
            .into_response(),
        Err(DbError::BlobSizeExceeded { max, actual }) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                code: ERROR_PAYLOAD_TOO_LARGE.to_string(),
                message: format!(
                    "Blob size ({actual} bytes) exceeds maximum limit ({max} bytes)"
                ),
            }),
        )
            .into_response(),
        Err(DbError::AccountQuotaExceeded { quota, requested }) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                code: ERROR_QUOTA_EXCEEDED.to_string(),
                message: format!(
                    "Account storage quota exceeded: requested {requested} bytes, quota {quota} bytes"
                ),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("failed to store ciphertext blob: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: ERROR_SERVER_FAILURE.to_string(),
                    message: "Failed to persist ciphertext blob".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Handler for `GET /v1/blobs/{blob_id}` (ZK-082).
///
/// Downloads an opaque ciphertext blob for the authenticated account.
pub async fn get_blob_handler(
    Path(blob_id): Path<String>,
    auth: AuthenticatedAccount,
    State(state): State<AppState>,
) -> Response {
    if !is_valid_blob_id(&blob_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_BLOB_ID".to_string(),
                message: "Blob ID must be 1-128 alphanumeric, hyphen, or underscore characters"
                    .to_string(),
            }),
        )
            .into_response();
    }

    match state.db.get_blob(auth.account_id, &blob_id).await {
        Ok(Some(data)) => {
            let data_len = data.len();
            (
                StatusCode::OK,
                [
                    (CONTENT_TYPE, "application/octet-stream"),
                    (CONTENT_LENGTH, &data_len.to_string()),
                ],
                data,
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: ERROR_BLOB_NOT_FOUND.to_string(),
                message: "Ciphertext blob not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("failed to retrieve ciphertext blob: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: ERROR_SERVER_FAILURE.to_string(),
                    message: "Failed to retrieve ciphertext blob".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Handler for `DELETE /v1/blobs/{blob_id}` (ZK-082).
///
/// Deletes an opaque ciphertext blob for the authenticated account.
pub async fn delete_blob_handler(
    Path(blob_id): Path<String>,
    auth: AuthenticatedAccount,
    State(state): State<AppState>,
) -> Response {
    if !is_valid_blob_id(&blob_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "INVALID_BLOB_ID".to_string(),
                message: "Blob ID must be 1-128 alphanumeric, hyphen, or underscore characters"
                    .to_string(),
            }),
        )
            .into_response();
    }

    match state.db.delete_blob(auth.account_id, &blob_id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "blob_id": blob_id,
                "deleted": true,
            })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: ERROR_BLOB_NOT_FOUND.to_string(),
                message: "Ciphertext blob not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("failed to delete ciphertext blob: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: ERROR_SERVER_FAILURE.to_string(),
                    message: "Failed to delete ciphertext blob".to_string(),
                }),
            )
                .into_response()
        }
    }
}
