//! Structured logging and redaction policy.
//!
//! In accordance with SEC-003, server observability MUST NOT log:
//! - passphrases;
//! - decrypted keys;
//! - plaintext notes;
//! - plaintext attachment metadata;
//! - decrypted search indexes;
//! - full authorization tokens;
//! - recovery keys.

use crate::config::{LogFormat, ServerConfig};
use crate::error::ServerError;
use axum::http::HeaderMap;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Constant placeholder string for redacted secrets.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Determines whether an HTTP header name contains sensitive credentials or key material.
#[must_use]
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-auth-token"
            | "x-session-token"
            | "x-api-key"
            | "x-recovery-key"
            | "x-vault-passphrase"
            | "x-encryption-key"
            | "x-signature"
    )
}

/// Redacts a header value if the header is deemed sensitive.
///
/// For `Authorization: Bearer <token>`, it preserves the `Bearer ` scheme prefix
/// while redacting the secret token payload.
#[must_use]
pub fn redact_header_value(name: &str, value: &str) -> String {
    if !is_sensitive_header(name) {
        return value.to_string();
    }

    if name.eq_ignore_ascii_case("authorization") {
        let trimmed = value.trim();
        if let Some((scheme, _)) = trimmed.split_once(' ') {
            return format!("{scheme} {REDACTED_PLACEHOLDER}");
        }
    }

    REDACTED_PLACEHOLDER.to_string()
}

/// Converts a [`HeaderMap`] into a vector of sanitized key-value string pairs.
///
/// Any sensitive headers are guaranteed to have their values redacted.
#[must_use]
pub fn sanitize_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(key, value)| {
            let key_str = key.as_str();
            let val_str = value.to_str().unwrap_or("[BINARY]");
            (key_str.to_string(), redact_header_value(key_str, val_str))
        })
        .collect()
}

/// Produces a safe, sanitized copy of a [`HeaderMap`] suitable for debugging.
#[must_use]
pub fn sanitize_header_map(headers: &HeaderMap) -> HeaderMap {
    let mut safe = HeaderMap::with_capacity(headers.len());
    for (k, v) in headers.iter() {
        let key_str = k.as_str();
        let val_str = v.to_str().unwrap_or("[BINARY]");
        let redacted = redact_header_value(key_str, val_str);
        if let Ok(safe_val) = redacted.parse() {
            safe.insert(k.clone(), safe_val);
        }
    }
    safe
}

/// Redacts a token string for diagnostic logging.
///
/// Returns a constant redacted identifier to prevent any partial token leakage.
#[must_use]
pub fn redact_token_for_diagnostics(_token: &str) -> &'static str {
    REDACTED_PLACEHOLDER
}

/// Initializes the global structured tracing subscriber based on [`ServerConfig`].
///
/// In tests or multiple invocations, this safely ignores already-initialized errors.
pub fn init_logging(config: &ServerConfig) -> Result<(), ServerError> {
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    match config.log_format {
        LogFormat::Json => {
            let json_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_current_span(true);
            let subscriber = registry.with(json_layer);
            let _ = subscriber.try_init();
        }
        LogFormat::Text => {
            let text_layer = tracing_subscriber::fmt::layer().compact().with_target(true);
            let subscriber = registry.with(text_layer);
            let _ = subscriber.try_init();
        }
    }

    Ok(())
}

/// Axum middleware for structured HTTP request/response logging with strict redaction.
///
/// Guarantees:
/// - No query strings or secret headers in logs;
/// - HTTP method, path, response status, and duration (ms) are logged;
/// - Errors (5xx) are logged at ERROR level; normal requests at INFO level.
pub async fn redacted_trace_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    let req_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("none")
        .to_string();

    tracing::info!(
        target: "zk_server::http",
        request_id = %req_id,
        method = %method,
        path = %path,
        "incoming request"
    );

    let response = next.run(req).await;
    let latency = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        tracing::error!(
            target: "zk_server::http",
            request_id = %req_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            latency_ms = latency.as_millis(),
            "request error"
        );
    } else {
        tracing::info!(
            target: "zk_server::http",
            request_id = %req_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            latency_ms = latency.as_millis(),
            "request completed"
        );
    }

    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::header::HeaderName;
    use axum::http::HeaderValue;

    #[test]
    fn test_sensitive_header_detection() {
        let sensitive = [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "cookie",
            "Cookie",
            "set-cookie",
            "proxy-authorization",
            "x-auth-token",
            "x-session-token",
            "x-api-key",
            "x-recovery-key",
            "x-vault-passphrase",
            "x-encryption-key",
            "x-signature",
        ];

        for h in sensitive {
            assert!(is_sensitive_header(h), "expected {h} to be sensitive");
        }

        let non_sensitive = [
            "content-type",
            "Content-Type",
            "accept",
            "host",
            "user-agent",
            "x-request-id",
            "if-none-match",
        ];

        for h in non_sensitive {
            assert!(!is_sensitive_header(h), "expected {h} to be non-sensitive");
        }
    }

    #[test]
    fn test_redact_authorization_bearer() {
        let redacted = redact_header_value("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6");
        assert_eq!(redacted, "Bearer [REDACTED]");
    }

    #[test]
    fn test_redact_authorization_basic() {
        let redacted = redact_header_value("Authorization", "Basic dXNlcjpwYXNz");
        assert_eq!(redacted, "Basic [REDACTED]");
    }

    #[test]
    fn test_redact_authorization_unknown_scheme() {
        let redacted = redact_header_value("Authorization", "RawSecretValue");
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn test_redact_cookie() {
        let redacted = redact_header_value("cookie", "session_id=secret12345; user=alice");
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn test_redact_custom_auth_headers() {
        assert_eq!(
            redact_header_value("x-auth-token", "tok_live_12345"),
            "[REDACTED]"
        );
        assert_eq!(
            redact_header_value("x-api-key", "key_secret_999"),
            "[REDACTED]"
        );
        assert_eq!(
            redact_header_value("x-recovery-key", "recov_aabbcc"),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_preserve_non_sensitive_headers() {
        assert_eq!(
            redact_header_value("content-type", "application/json"),
            "application/json"
        );
        assert_eq!(
            redact_header_value("user-agent", "zk-cli/0.1.0"),
            "zk-cli/0.1.0"
        );
    }

    #[test]
    fn test_sanitize_headers_map() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer super_secret_token"),
        );
        headers.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=abc"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("req-12345"),
        );

        let sanitized = sanitize_headers(&headers);
        let safe_map: std::collections::HashMap<_, _> = sanitized.into_iter().collect();

        assert_eq!(safe_map.get("authorization").unwrap(), "Bearer [REDACTED]");
        assert_eq!(safe_map.get("cookie").unwrap(), "[REDACTED]");
        assert_eq!(safe_map.get("content-type").unwrap(), "application/json");
        assert_eq!(safe_map.get("x-request-id").unwrap(), "req-12345");
    }

    #[test]
    fn test_sanitize_header_map_struct() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain"),
        );

        let safe = sanitize_header_map(&headers);
        assert_eq!(
            safe.get("authorization").unwrap().to_str().unwrap(),
            "Bearer [REDACTED]"
        );
        assert_eq!(
            safe.get("content-type").unwrap().to_str().unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn test_redact_token_diagnostic() {
        assert_eq!(
            redact_token_for_diagnostics("secret_token_12345"),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_init_logging_multiple_calls_safe() {
        let cfg = ServerConfig::default();
        assert!(init_logging(&cfg).is_ok());
        // Second call must not panic
        assert!(init_logging(&cfg).is_ok());
    }
}
