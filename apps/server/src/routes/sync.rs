//! Synchronization push and pull route handlers.
//!
//! In accordance with SEC-001, SEC-002, and SEC-006:
//! - Note plaintext, note titles, tags, and secrets NEVER cross the network or persist on server.
//! - The server cannot decrypt user content.
//! - Compare-and-swap (CAS) mutation handling prevents silent overwrite of stale edits.

use crate::app::{AppState, ErrorResponse};
use crate::auth::AuthenticatedAccount;
use crate::db::PushOutcome;
use crate::routes::vault::contains_forbidden_keys;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64ct::{Base64, Encoding};
use uuid::Uuid;
use zk_protocol::constants::{
    ENVELOPE_VERSION_V1, ERROR_CRYPTO_UNSUPPORTED_VERSION, ERROR_INVALID_ENVELOPE,
    ERROR_OBJECT_NOT_FOUND, ERROR_SERVER_FAILURE, ERROR_SYNC_CURSOR_INVALID,
};
use zk_protocol::sync::PushRequest;

/// Handler for `POST /v1/sync/push`.
pub async fn push_mutation_handler(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    body_bytes: Bytes,
) -> impl IntoResponse {
    // 1. Parse JSON and ensure no forbidden plaintext / passphrase keys
    let json_val: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_INVALID_ENVELOPE.to_string(),
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
                code: ERROR_INVALID_ENVELOPE.to_string(),
                message:
                    "Plaintext note content and secrets MUST NOT be transmitted to the server (SEC-001/SEC-002)"
                        .to_string(),
            }),
        )
            .into_response();
    }

    // 2. Deserialize into PushRequest
    let push_req: PushRequest = match serde_json::from_value(json_val) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: ERROR_INVALID_ENVELOPE.to_string(),
                    message: format!("Invalid push request structure: {e}"),
                }),
            )
                .into_response();
        }
    };

    // 3. Validate UUID formatting
    if Uuid::parse_str(&push_req.mutation_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_INVALID_ENVELOPE.to_string(),
                message: "mutation_id must be a valid UUID".to_string(),
            }),
        )
            .into_response();
    }

    if Uuid::parse_str(&push_req.object_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_INVALID_ENVELOPE.to_string(),
                message: "object_id must be a valid UUID".to_string(),
            }),
        )
            .into_response();
    }

    // 4. Validate envelope consistency
    if push_req.envelope.object_id != push_req.object_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_INVALID_ENVELOPE.to_string(),
                message: "envelope.object_id does not match request object_id".to_string(),
            }),
        )
            .into_response();
    }

    if push_req.envelope.envelope_version != ENVELOPE_VERSION_V1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_CRYPTO_UNSUPPORTED_VERSION.to_string(),
                message: format!(
                    "Unsupported envelope_version '{}', expected {ENVELOPE_VERSION_V1}",
                    push_req.envelope.envelope_version
                ),
            }),
        )
            .into_response();
    }

    // 5. Validate Base64 encoding in envelope
    if Base64::decode_vec(&push_req.envelope.wrapped_key.nonce).is_err()
        || Base64::decode_vec(&push_req.envelope.wrapped_key.ciphertext).is_err()
        || Base64::decode_vec(&push_req.envelope.payload.nonce).is_err()
        || Base64::decode_vec(&push_req.envelope.payload.ciphertext).is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: ERROR_INVALID_ENVELOPE.to_string(),
                message: "Envelope nonce and ciphertext fields must be valid standard Base64"
                    .to_string(),
            }),
        )
            .into_response();
    }

    // 6. Log operational diagnostic without secret content (SEC-003)
    tracing::info!(
        account_id = %auth.account_id,
        object_id = %push_req.object_id,
        expected_revision = push_req.expected_revision,
        "processing CAS push mutation"
    );

    // 7. Execute compare-and-swap in database
    match state.db.push_mutation(auth.account_id, &push_req).await {
        Ok(PushOutcome::Success(resp)) => (StatusCode::OK, Json(resp)).into_response(),
        Ok(PushOutcome::Conflict(conflict)) => {
            (StatusCode::CONFLICT, Json(conflict)).into_response()
        }
        Ok(PushOutcome::ObjectNotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: ERROR_OBJECT_NOT_FOUND.to_string(),
                message: msg,
            }),
        )
            .into_response(),
        Ok(PushOutcome::ReplayMismatch(msg)) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: zk_protocol::ERROR_MUTATION_REPLAY_MISMATCH.to_string(),
                message: msg,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to process push mutation: {e}"),
            }),
        )
            .into_response(),
    }
}

/// Handler for `GET /v1/sync/changes` and `GET /v1/sync/pull`.
///
/// Query parameters:
/// - `after`: u64 sequence cursor (defaults to 0); returns records where `server_seq > after`.
/// - `limit`: maximum number of records to return (defaults to 50, clamped to 1..=500).
pub async fn pull_changes_handler(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let mut after = 0u64;
    let mut limit = 50usize;

    if let Some(query_str) = raw_query {
        for pair in query_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let val = parts.next().unwrap_or("");
            match key {
                "after" | "since" | "cursor" => match val.parse::<u64>() {
                    Ok(v) => after = v,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                code: ERROR_SYNC_CURSOR_INVALID.to_string(),
                                message: format!("Invalid 'after' cursor parameter: {e}"),
                            }),
                        )
                            .into_response();
                    }
                },
                "limit" => match val.parse::<u32>() {
                    Ok(v) => {
                        limit = if v == 0 {
                            50
                        } else if v > 500 {
                            500
                        } else {
                            v as usize
                        };
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                code: ERROR_SYNC_CURSOR_INVALID.to_string(),
                                message: format!("Invalid 'limit' parameter: {e}"),
                            }),
                        )
                            .into_response();
                    }
                },
                _ => {}
            }
        }
    }

    tracing::info!(
        account_id = %auth.account_id,
        after = after,
        limit = limit,
        "processing pull changes request"
    );

    match state.db.pull_changes(auth.account_id, after, limit).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to pull changes: {e}"),
            }),
        )
            .into_response(),
    }
}
