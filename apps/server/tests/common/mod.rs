#![allow(dead_code, clippy::unwrap_used)]
use uuid::Uuid;
use zk_server::AppState;
/// Provision fixtures through the database, never through an unauthenticated API shortcut.
pub async fn bearer(state: &AppState, account: Uuid) -> String {
    let (_, token) = state
        .db
        .create_session(account, None, None, Some(3600))
        .await
        .unwrap();
    format!("Bearer {}", token.expose_secret())
}
