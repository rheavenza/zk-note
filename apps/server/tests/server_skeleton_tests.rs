//! Integration tests for the server skeleton (ZK-030).
//!
//! Validates:
//! 1. Axum server starts and gracefully shuts down;
//! 2. Configuration loading from defaults and environment;
//! 3. Health endpoints (`/health` and `/v1/health`);
//! 4. Structured logging and redaction policy.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::body::Body;

use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use tower::ServiceExt;
use zk_server::config::{LogFormat, ServerConfig};
use zk_server::logging::{
    is_sensitive_header, redact_header_value, sanitize_header_map, sanitize_headers,
    REDACTED_PLACEHOLDER,
};
use zk_server::routes::health::HealthResponse;
use zk_server::{create_app, run_server, AppState};

#[tokio::test]
async fn test_server_skeleton_health_endpoints() {
    let config = ServerConfig::default();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state);

    // Test /health
    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("execute request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/json")
    );
    assert!(resp.headers().contains_key("x-request-id"));

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let health: HealthResponse = serde_json::from_slice(&body).expect("parse json");
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(health.protocol_version, zk_protocol::PROTOCOL_VERSION_V1);

    // Test /v1/health
    let req_v1 = Request::builder()
        .uri("/v1/health")
        .method("GET")
        .body(Body::empty())
        .expect("build request");

    let resp_v1 = app.oneshot(req_v1).await.expect("execute request");
    assert_eq!(resp_v1.status(), StatusCode::OK);
    let body_v1 = axum::body::to_bytes(resp_v1.into_body(), usize::MAX)
        .await
        .expect("read body");
    let health_v1: HealthResponse = serde_json::from_slice(&body_v1).expect("parse json");
    assert_eq!(health_v1.status, "ok");
}

#[tokio::test]
async fn test_server_skeleton_real_tcp_lifecycle() {
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // OS assigns random available port
        ..Default::default()
    };

    let addr = config.socket_addr().expect("valid socket addr");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");
    let local_addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let state = AppState::new_in_memory(config).expect("init state");
    let app = create_app(state);

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Make an actual HTTP request over raw TCP stream to the live server
    let mut stream = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("connect to TCP socket");

    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write HTTP request");

    let mut response_buf = String::new();
    stream
        .read_to_string(&mut response_buf)
        .await
        .expect("read HTTP response");

    assert!(response_buf.starts_with("HTTP/1.1 200 OK"));
    assert!(response_buf.contains("\"status\":\"ok\""));
    assert!(response_buf.contains("x-request-id:"));

    // Shut down server
    shutdown_tx.send(()).expect("send shutdown");
    let server_res = server_handle.await.expect("join server");
    assert!(server_res.is_ok());
}

#[tokio::test]
async fn test_run_server_function_lifecycle() {
    let config = ServerConfig {
        port: 0,
        ..Default::default()
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_task = tokio::spawn(async move {
        run_server(config, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    shutdown_tx.send(()).expect("send shutdown");
    let res = server_task.await.expect("join task");
    assert!(res.is_ok());
}

#[test]
fn test_configuration_loading_and_precedence() {
    // Default config
    let default_cfg = ServerConfig::default();
    assert_eq!(default_cfg.host, "127.0.0.1");
    assert_eq!(default_cfg.port, 8080);
    assert_eq!(default_cfg.log_level, "info");
    assert_eq!(default_cfg.log_format, LogFormat::Json);

    // Custom configuration via lookup
    let custom_cfg = ServerConfig::from_lookup(|key| match key {
        "ZK_SERVER_HOST" => Some("0.0.0.0".to_string()),
        "ZK_SERVER_PORT" => Some("9443".to_string()),
        "ZK_SERVER_LOG_LEVEL" => Some("debug".to_string()),
        "ZK_SERVER_LOG_FORMAT" => Some("text".to_string()),
        _ => None,
    })
    .expect("load custom config");

    assert_eq!(custom_cfg.host, "0.0.0.0");
    assert_eq!(custom_cfg.port, 9443);
    assert_eq!(custom_cfg.log_level, "debug");
    assert_eq!(custom_cfg.log_format, LogFormat::Text);
    assert!(custom_cfg.socket_addr().is_ok());

    // Invalid port rejection
    let invalid_port = ServerConfig::from_lookup(|key| match key {
        "ZK_SERVER_PORT" => Some("99999".to_string()),
        _ => None,
    });
    assert!(invalid_port.is_err());
}

#[test]
fn test_strict_redaction_policy_sec_003() {
    // 1. Sensitive headers must be detected
    let sensitive = [
        "authorization",
        "Authorization",
        "cookie",
        "Set-Cookie",
        "x-auth-token",
        "X-Session-Token",
        "x-api-key",
        "x-recovery-key",
        "x-vault-passphrase",
        "x-encryption-key",
    ];
    for name in sensitive {
        assert!(
            is_sensitive_header(name),
            "Header {name} MUST be classified as sensitive"
        );
    }

    // 2. Authorization Bearer token must preserve scheme but redact secret
    let bearer_raw = "Bearer secret_jwt_payload_1234567890";
    let redacted_bearer = redact_header_value("authorization", bearer_raw);
    assert_eq!(redacted_bearer, "Bearer [REDACTED]");
    assert!(!redacted_bearer.contains("secret"));

    // 3. Cookies and other tokens must be fully redacted
    let cookie_raw = "session=super_secret_session_id; other=val";
    let redacted_cookie = redact_header_value("cookie", cookie_raw);
    assert_eq!(redacted_cookie, REDACTED_PLACEHOLDER);
    assert!(!redacted_cookie.contains("super_secret"));

    // 4. Non-sensitive headers must not be altered
    let user_agent = "zk-cli/0.1.0 (linux; x86_64)";
    assert_eq!(redact_header_value("user-agent", user_agent), user_agent);

    // 5. Header maps must sanitize all sensitive values
    let mut map = HeaderMap::new();
    map.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer token_abc123"),
    );
    map.insert(COOKIE, HeaderValue::from_static("auth_cookie=secret_xyz"));
    map.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));

    let sanitized = sanitize_headers(&map);
    for (k, v) in sanitized {
        if k.eq_ignore_ascii_case("authorization") {
            assert_eq!(v, "Bearer [REDACTED]");
        } else if k.eq_ignore_ascii_case("cookie") {
            assert_eq!(v, "[REDACTED]");
        } else if k.eq_ignore_ascii_case("user-agent") {
            assert_eq!(v, "Mozilla/5.0");
        }
    }

    let safe_map = sanitize_header_map(&map);
    assert_eq!(
        safe_map.get(AUTHORIZATION).unwrap().to_str().unwrap(),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        safe_map.get(COOKIE).unwrap().to_str().unwrap(),
        "[REDACTED]"
    );
    assert_eq!(
        safe_map.get(USER_AGENT).unwrap().to_str().unwrap(),
        "Mozilla/5.0"
    );
}
