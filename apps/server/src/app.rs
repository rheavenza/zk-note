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

/// Middleware that injects comprehensive browser security headers and strict CSP (ZK-069).
async fn security_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // 1. Restrictive Content Security Policy (CSP)
    // - script-src 'self' 'wasm-unsafe-eval' strictly permits origin scripts + WASM compilation.
    // - default-src 'none', object-src 'none', frame-ancestors 'none'.
    // - Zero third-party scripts, zero runtime analytics.
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"
        ),
    );

    // 2. Anti-Clickjacking Hardening
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );

    // 3. MIME-Type Sniffing Protection
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // 4. Referrer Policy (Leak prevention)
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    // 5. Cross-Origin Browsing Context Isolation (Spectre / WASM memory protection)
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("require-corp"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );

    // 6. Permissions Policy (Hardware / Sensor API lock-down)
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        ),
    );

    // 7. Strict-Transport-Security (HSTS)
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );

    resp
}

/// Constructs the top-level Axum [`Router`] with routes, state, and security middleware.
pub fn create_app(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route(
            "/v1/vault/bootstrap",
            get(get_vault_bootstrap_handler).post(create_vault_bootstrap_handler),
        )
        .route("/v1/sync/push", post(push_mutation_handler))
        .route("/v1/sync/changes", get(pull_changes_handler))
        .route("/v1/sync/pull", get(pull_changes_handler))
        .route(
            "/v1/auth/session/revoke",
            post(crate::routes::auth::revoke_session_handler),
        )
        .route(
            "/v1/auth/logout",
            post(crate::routes::auth::revoke_session_handler),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_middleware,
        ));

    let public_auth_routes = Router::new()
        .route(
            "/v1/auth/webauthn/register/start",
            post(crate::routes::auth::webauthn_register_start_handler),
        )
        .route(
            "/v1/auth/webauthn/register/finish",
            post(crate::routes::auth::webauthn_register_finish_handler),
        )
        .route(
            "/v1/auth/webauthn/login/start",
            post(crate::routes::auth::webauthn_login_start_handler),
        )
        .route(
            "/v1/auth/webauthn/login/finish",
            post(crate::routes::auth::webauthn_login_finish_handler),
        );

    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .merge(public_auth_routes)
        .merge(protected_routes)
        .fallback(fallback_not_found)
        .layer(axum::middleware::from_fn(security_headers_middleware))
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

    #[tokio::test]
    async fn test_browser_security_headers_and_csp() {
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

        let headers = resp.headers();

        // 1. CSP
        let csp = headers
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("unsafe-inline") || csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));

        // 2. Clickjacking & MIME-type hardening
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");

        // 3. Spectre / Cross-Origin Isolation
        assert_eq!(
            headers.get("cross-origin-opener-policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            headers.get("cross-origin-embedder-policy").unwrap(),
            "require-corp"
        );
        assert_eq!(
            headers.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );

        // 4. Permissions Policy & HSTS
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("strict-transport-security"));
    }
}
