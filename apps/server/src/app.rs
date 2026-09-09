//! Axum application construction and middleware wiring.

use crate::config::ServerConfig;
use crate::db::ServerDb;
use crate::logging::redacted_trace_middleware;
use crate::routes::health::health_handler;
use crate::routes::sync::{pull_changes_handler, push_mutation_handler};
use crate::routes::vault::{create_vault_bootstrap_handler, get_vault_bootstrap_handler};
use axum::http::header::HeaderName;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

/// Global shared application state.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Runtime server configuration.
    pub config: ServerConfig,
    /// Database handle for zero-knowledge data operations.
    pub db: ServerDb,
}

impl AppState {
    /// Creates a new application state with an in-memory SQLite database initialized with all migrations.
    pub fn new_in_memory(config: ServerConfig) -> Result<Self, crate::error::DbError> {
        Ok(Self {
            config,
            db: ServerDb::new_in_memory()?,
        })
    }
}

/// Standard error response payload for HTTP failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Canonical error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

/// Fallback handler for unmatched routes (HTTP 404).
async fn fallback_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            code: zk_protocol::ERROR_OBJECT_NOT_FOUND.to_string(),
            message: "The requested resource was not found".to_string(),
        }),
    )
}

/// Middleware that extracts or assigns an `x-request-id` header for request correlation.
async fn request_id_middleware(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let header_name = HeaderName::from_static("x-request-id");
    let req_id = match req.headers().get(&header_name) {
        Some(val) => val.clone(),
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            HeaderValue::try_from(id).unwrap_or_else(|_| HeaderValue::from_static("none"))
        }
    };

    req.headers_mut()
        .insert(header_name.clone(), req_id.clone());
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(header_name, req_id);
    resp
}

/// Constructs the top-level Axum [`Router`] with routes, state, and security middleware.
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .route(
            "/v1/vault/bootstrap",
            get(get_vault_bootstrap_handler).post(create_vault_bootstrap_handler),
        )
        .route("/v1/sync/push", post(push_mutation_handler))
        .route("/v1/sync/changes", get(pull_changes_handler))
        .route("/v1/sync/pull", get(pull_changes_handler))
        .fallback(fallback_not_found)
        .layer(axum::middleware::from_fn(redacted_trace_middleware))
        .layer(axum::middleware::from_fn(request_id_middleware))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::routes::health::HealthResponse;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_get_health_endpoint() {
        let config = ServerConfig::default();
        let state = AppState::new_in_memory(config).unwrap();
        let app = create_app(state);

        let req = Request::builder()
            .uri("/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check x-request-id was injected
        assert!(resp.headers().contains_key("x-request-id"));

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(health.status, "ok");
        assert_eq!(health.protocol_version, zk_protocol::PROTOCOL_VERSION_V1);
    }

    #[tokio::test]
    async fn test_get_v1_health_endpoint() {
        let config = ServerConfig::default();
        let state = AppState::new_in_memory(config).unwrap();
        let app = create_app(state);

        let req = Request::builder()
            .uri("/v1/health")
            .method("GET")
            .header("x-request-id", "test-request-id-42")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-request-id").unwrap(),
            "test-request-id-42"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(health.status, "ok");
    }

    #[tokio::test]
    async fn test_404_not_found_json_response() {
        let config = ServerConfig::default();
        let state = AppState::new_in_memory(config).unwrap();
        let app = create_app(state);

        let req = Request::builder()
            .uri("/v1/non-existent-endpoint")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(err.code, zk_protocol::ERROR_OBJECT_NOT_FOUND);
    }
}
