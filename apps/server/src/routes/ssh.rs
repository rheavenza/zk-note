//! Native SSH proof endpoints. Never log proofs, keys, or request parsing errors.
use crate::{AppState, AuthenticatedAccount, ErrorResponse};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zk_protocol::ssh::{AddSshKeyRequest, SshFinishRequest, SshStartRequest};
fn failure(status: StatusCode) -> Response {
    (
        status,
        Json(ErrorResponse {
            code: "SSH_AUTH_FAILED".into(),
            message: "SSH authentication operation failed".into(),
        }),
    )
        .into_response()
}
fn parse<T: DeserializeOwned>(bytes: &Bytes) -> Option<T> {
    if bytes.len() > 8192 {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}
pub async fn start(State(state): State<AppState>, bytes: Bytes) -> Response {
    let Some(req) = parse::<SshStartRequest>(&bytes) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state
        .db
        .start_ssh_login(req, &state.config.ssh_auth_origin)
        .await
    {
        Ok(challenge) => Json(challenge).into_response(),
        Err(_) => failure(StatusCode::UNAUTHORIZED),
    }
}
pub async fn finish(State(state): State<AppState>, bytes: Bytes) -> Response {
    let Some(req) = parse::<SshFinishRequest>(&bytes) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state
        .db
        .finish_ssh_login(&req, &state.config.ssh_auth_origin)
        .await
    {
        Ok(session) => Json(session).into_response(),
        Err(_) => failure(StatusCode::UNAUTHORIZED),
    }
}
pub async fn list(State(state): State<AppState>, auth: AuthenticatedAccount) -> Response {
    match state.db.list_ssh_keys(auth.account_id).await {
        Ok(keys) => Json(keys).into_response(),
        Err(_) => failure(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
pub async fn add(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    bytes: Bytes,
) -> Response {
    let Some(req) = parse::<AddSshKeyRequest>(&bytes) else {
        return failure(StatusCode::BAD_REQUEST);
    };
    match state
        .db
        .add_ssh_key(auth.account_id, &req.public_key, req.label, false)
        .await
    {
        Ok(key) => (StatusCode::CREATED, Json(key)).into_response(),
        Err(_) => failure(StatusCode::BAD_REQUEST),
    }
}
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthenticatedAccount,
    Path(id): Path<Uuid>,
) -> Response {
    match state.db.revoke_ssh_key(auth.account_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => failure(StatusCode::NOT_FOUND),
        Err(_) => failure(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
