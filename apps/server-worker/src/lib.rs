//! Zero-knowledge Cloudflare Worker entry point and compatibility spike.
//!
//! In accordance with SEC-001 and SEC-002:
//! - This Worker operates exclusively on opaque ciphertext and protocol metadata.
//! - It MUST NOT depend on `zk-crypto` or `zk-core`.
//! - It must never possess or derive encryption keys, or decrypt note contents.

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use worker::*;

/// Standard health check response payload matching `apps/server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status (always "ok" when operational).
    pub status: String,
    /// Server package version.
    pub version: String,
    /// Supported zero-knowledge protocol version.
    pub protocol_version: u32,
}

/// Standard error response payload matching `apps/server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Canonical error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

/// Smoke test row model for D1 validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeRow {
    pub id: String,
    pub value: String,
}

/// Request payload for creating smoke test entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSmokeRequest {
    pub id: Option<String>,
    pub value: String,
}

/// Response payload for D1 smoke verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeResponse {
    pub status: String,
    pub inserted: SmokeRow,
    pub retrieved: SmokeRow,
    pub r2_binding_configured: bool,
}

/// Injects security hardening headers matching the authoritative native server.
fn apply_security_headers(mut resp: Response, req_id: &str) -> Result<Response> {
    let headers = resp.headers_mut();
    headers.set(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;",
    )?;
    headers.set("X-Frame-Options", "DENY")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("Referrer-Policy", "no-referrer")?;
    headers.set("Cross-Origin-Opener-Policy", "same-origin")?;
    headers.set("Cross-Origin-Embedder-Policy", "require-corp")?;
    headers.set("Cross-Origin-Resource-Policy", "same-origin")?;
    headers.set(
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    )?;
    headers.set(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    )?;
    headers.set("X-Request-Id", req_id)?;
    Ok(resp)
}

/// Handler for `GET /health` and `GET /v1/health`.
fn health_handler(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let payload = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: zk_protocol::PROTOCOL_VERSION_V1,
    };
    Response::from_json(&payload)
}

/// Handler for `GET /dev/d1-smoke`: runs an end-to-end parameterized write, read, and verification.
async fn d1_smoke_get_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = match ctx.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            return Response::from_json(&ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to acquire D1 database binding 'DB': {e}"),
            })
            .map(|r| r.with_status(500));
        }
    };

    let url = req.url()?;
    let query_id = url
        .query_pairs()
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned());

    if let Some(id) = query_id {
        // Query specific row by id using parameterized statement
        let select_stmt = db.prepare("SELECT id, value FROM worker_smoke WHERE id = ?1");
        let bound = select_stmt.bind(&[JsValue::from_str(&id)])?;
        let row: Option<SmokeRow> = bound.first(None).await?;

        return match row {
            Some(found) => Response::from_json(&found),
            None => Response::from_json(&ErrorResponse {
                code: zk_protocol::ERROR_OBJECT_NOT_FOUND.to_string(),
                message: format!("Smoke row with id '{id}' not found"),
            })
            .map(|r| r.with_status(404)),
        };
    }

    // Automated end-to-end write and read smoke test
    let id = format!("smoke-{}", uuid::Uuid::new_v4());
    let value = format!("val-{}", uuid::Uuid::new_v4());

    // 1. Parameterized INSERT
    let insert_stmt = db.prepare("INSERT INTO worker_smoke (id, value) VALUES (?1, ?2)");
    let bound_insert = insert_stmt.bind(&[JsValue::from_str(&id), JsValue::from_str(&value)])?;
    bound_insert.run().await?;

    // 2. Parameterized SELECT read back
    let select_stmt = db.prepare("SELECT id, value FROM worker_smoke WHERE id = ?1");
    let bound_select = select_stmt.bind(&[JsValue::from_str(&id)])?;
    let row: Option<SmokeRow> = bound_select.first(None).await?;

    let retrieved = match row {
        Some(r) => r,
        None => {
            return Response::from_json(&ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: "D1 smoke read-back returned None after successful insert".to_string(),
            })
            .map(|r| r.with_status(500));
        }
    };

    let r2_configured = ctx.bucket("BLOBS").is_ok();

    Response::from_json(&SmokeResponse {
        status: "ok".to_string(),
        inserted: SmokeRow {
            id: id.clone(),
            value,
        },
        retrieved,
        r2_binding_configured: r2_configured,
    })
}

/// Handler for `POST /dev/d1-smoke`: inserts caller-specified row and reads it back.
async fn d1_smoke_post_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = match ctx.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            return Response::from_json(&ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: format!("Failed to acquire D1 database binding 'DB': {e}"),
            })
            .map(|r| r.with_status(500));
        }
    };

    let payload: CreateSmokeRequest = match req.json().await {
        Ok(p) => p,
        Err(e) => {
            return Response::from_json(&ErrorResponse {
                code: "INVALID_REQUEST".to_string(),
                message: format!("Invalid JSON payload: {e}"),
            })
            .map(|r| r.with_status(400));
        }
    };

    let id = payload
        .id
        .unwrap_or_else(|| format!("smoke-{}", uuid::Uuid::new_v4()));
    let value = payload.value;

    // Parameterized INSERT
    let insert_stmt = db.prepare("INSERT INTO worker_smoke (id, value) VALUES (?1, ?2)");
    let bound_insert = insert_stmt.bind(&[JsValue::from_str(&id), JsValue::from_str(&value)])?;
    bound_insert.run().await?;

    // Parameterized SELECT read back
    let select_stmt = db.prepare("SELECT id, value FROM worker_smoke WHERE id = ?1");
    let bound_select = select_stmt.bind(&[JsValue::from_str(&id)])?;
    let retrieved: Option<SmokeRow> = bound_select.first(None).await?;

    match retrieved {
        Some(row) => Response::from_json(&row),
        None => Response::from_json(&ErrorResponse {
            code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
            message: "D1 smoke read-back failed after insert".to_string(),
        })
        .map(|r| r.with_status(500)),
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let req_id = req
        .headers()
        .get("x-request-id")
        .ok()
        .flatten()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let router = Router::new();

    let resp = router
        .get("/health", health_handler)
        .get("/v1/health", health_handler)
        .get_async("/dev/d1-smoke", d1_smoke_get_handler)
        .post_async("/dev/d1-smoke", d1_smoke_post_handler)
        .run(req, env)
        .await;

    match resp {
        Ok(res) => apply_security_headers(res, &req_id),
        Err(e) => {
            let error_resp = Response::from_json(&ErrorResponse {
                code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
                message: format!("Internal server error: {e}"),
            })?
            .with_status(500);
            apply_security_headers(error_resp, &req_id)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_contract() {
        let health = HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: zk_protocol::PROTOCOL_VERSION_V1,
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"version\":\"0.1.0\""));
        assert!(json.contains("\"protocol_version\":1"));

        let deserialized: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, health);
        assert_eq!(deserialized.protocol_version, 1);
    }

    #[test]
    fn test_smoke_models_roundtrip() {
        let row = SmokeRow {
            id: "smoke-12345".to_string(),
            value: "smoke-test-payload".to_string(),
        };

        let json = serde_json::to_string(&row).unwrap();
        let parsed: SmokeRow = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, row);

        let smoke_resp = SmokeResponse {
            status: "ok".to_string(),
            inserted: row.clone(),
            retrieved: row,
            r2_binding_configured: true,
        };

        let resp_json = serde_json::to_string(&smoke_resp).unwrap();
        assert!(resp_json.contains("\"r2_binding_configured\":true"));
    }

    #[test]
    fn test_error_response_conforms_to_protocol() {
        let err = ErrorResponse {
            code: zk_protocol::ERROR_SERVER_FAILURE.to_string(),
            message: "Test error".to_string(),
        };

        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"code\":\"SERVER_FAILURE\""));
    }
}
