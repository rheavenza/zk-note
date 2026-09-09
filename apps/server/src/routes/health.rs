//! Health check endpoint handler.

use axum::Json;
use serde::{Deserialize, Serialize};

/// Standard health check response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status (always "ok" when operational).
    pub status: String,
    /// Server package version.
    pub version: String,
    /// Supported zero-knowledge protocol version.
    pub protocol_version: u32,
}

/// Handler for `GET /health` and `GET /v1/health`.
pub async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: zk_protocol::PROTOCOL_VERSION_V1,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_handler() {
        let resp = health_handler().await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.protocol_version, zk_protocol::PROTOCOL_VERSION_V1);
    }
}
