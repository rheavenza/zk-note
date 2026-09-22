//! Cloudflare ciphertext server. No client cryptography or plaintext models.
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use blake2::{Blake2s256, Digest};
use futures_util::StreamExt;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::*;
use zk_protocol::{auth::*, sync::*, vault::VaultBootstrap, webauthn::*};
mod auth;
mod blobs;
mod sync;

#[derive(Debug)]
struct ApiError(u16, &'static str);
type ApiResult<T> = std::result::Result<T, ApiError>;
impl From<worker::Error> for ApiError {
    fn from(_: worker::Error) -> Self {
        Self(500, "SERVER_FAILURE")
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self(500, "SERVER_FAILURE")
    }
}
fn invalid(code: &'static str) -> ApiError {
    ApiError(400, code)
}
fn id() -> String {
    Uuid::new_v4().to_string()
}
fn digest(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(&Blake2s256::digest(bytes))
}
fn uuid(value: &str) -> ApiResult<String> {
    Uuid::parse_str(value)
        .map(|v| v.to_string())
        .map_err(|_| invalid("INVALID_REQUEST"))
}
fn encode<T: Serialize>(value: &T) -> ApiResult<String> {
    Ok(serde_json::to_string(value)?)
}
fn response<T: Serialize>(status: u16, value: &T) -> ApiResult<Response> {
    Ok(Response::from_json(value)?.with_status(status))
}
fn num(value: &Value, name: &str) -> ApiResult<u64> {
    value[name].as_u64().ok_or(ApiError(500, "SERVER_FAILURE"))
}
fn text<'a>(value: &'a Value, name: &str) -> ApiResult<&'a str> {
    value[name].as_str().ok_or(ApiError(500, "SERVER_FAILURE"))
}
fn statement(db: &D1Database, sql: &str, args: &[Value]) -> ApiResult<D1PreparedStatement> {
    let values = args
        .iter()
        .map(|v| match v {
            Value::Null => JsValue::NULL,
            Value::String(s) => JsValue::from_str(s),
            Value::Bool(b) => JsValue::from_f64(u8::from(*b) as f64),
            Value::Number(n) => JsValue::from_f64(n.as_f64().unwrap_or(f64::NAN)),
            _ => JsValue::from_str(&v.to_string()),
        })
        .collect::<Vec<_>>();
    Ok(db.prepare(sql).bind(&values)?)
}
async fn rows(db: &D1Database, sql: &str, args: &[Value]) -> ApiResult<Vec<Value>> {
    Ok(statement(db, sql, args)?.all().await?.results::<Value>()?)
}
async fn run(db: &D1Database, sql: &str, args: &[Value]) -> ApiResult<()> {
    statement(db, sql, args)?.run().await?;
    Ok(())
}
async fn batch(db: &D1Database, commands: Vec<(&str, Vec<Value>)>) -> ApiResult<Vec<D1Result>> {
    let statements = commands
        .into_iter()
        .map(|(sql, args)| statement(db, sql, &args))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(db.batch(statements).await?)
}
fn forbidden(v: &Value) -> bool {
    match v {
        Value::Object(map) => map.iter().any(|(k, v)| {
            matches!(
                k.to_ascii_lowercase().as_str(),
                "password"
                    | "passphrase"
                    | "vault_passphrase"
                    | "vault_key"
                    | "plaintext"
                    | "master_key"
                    | "secret"
                    | "title"
                    | "tags"
                    | "filename"
                    | "recovery_key"
                    | "search_text"
            ) || forbidden(v)
        }),
        Value::Array(list) => list.iter().any(forbidden),
        _ => false,
    }
}
async fn body(req: &mut Request, max: usize) -> ApiResult<Vec<u8>> {
    let mut stream = req.stream()?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > max.saturating_sub(out.len()) {
            return Err(ApiError(413, "PAYLOAD_TOO_LARGE"));
        }
        out.extend(chunk);
    }
    Ok(out)
}
async fn parse<T: DeserializeOwned>(req: &mut Request, code: &'static str) -> ApiResult<T> {
    let bytes = body(req, 128 * 1024).await?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| invalid(code))?;
    if forbidden(&v) {
        return Err(invalid(code));
    }
    serde_json::from_value(v).map_err(|_| invalid(code))
}
fn variable(env: &Env, name: &str, default: &str) -> String {
    env.var(name)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| default.into())
}

#[event(fetch)]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let request_id = req
        .headers()
        .get("x-request-id")?
        .filter(|v| v.len() <= 128)
        .unwrap_or_else(id);
    // Only fixed error codes escape adapters; request bodies/headers/DB errors are never logged.
    let mut result = match dispatch(&mut req, &env).await {
        Ok(response) => response,
        Err(ApiError(status, code)) => {
            Response::from_json(&json!({"code":code,"message":code}))?.with_status(status)
        }
    };
    for (name,value) in [
        ("x-request-id",request_id.as_str()),("cache-control","no-store"),
        ("content-security-policy","default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"),
        ("x-frame-options","DENY"),("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),
        ("cross-origin-opener-policy","same-origin"),("cross-origin-embedder-policy","require-corp"),("cross-origin-resource-policy","same-origin"),
        ("strict-transport-security","max-age=63072000; includeSubDomains; preload"),
        ("permissions-policy","accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
    ] { result.headers_mut().set(name,value)?; }
    Ok(result)
}
async fn dispatch(req: &mut Request, env: &Env) -> ApiResult<Response> {
    let path = req.path();
    let method = req.method();
    if (path == "/health" || path == "/v1/health") && method == Method::Get {
        return response(
            200,
            &json!({"status":"ok","version":env!("CARGO_PKG_VERSION"),"protocol_version":zk_protocol::PROTOCOL_VERSION_V1}),
        );
    }
    let db = env.d1("DB")?;
    if path.starts_with("/v1/auth/webauthn/") && method == Method::Post {
        return auth::webauthn(req, env, &db, &path).await;
    }
    if (path == "/v1/auth/device/authorize" || path == "/v1/auth/cli/login")
        && method == Method::Post
    {
        let request: DeviceAuthRequest = parse(req, "FORBIDDEN_PLAINTEXT_PAYLOAD").await?;
        let caller = auth::authenticate(req, &db).await?;
        if caller.account_id != request.account_id {
            return Err(ApiError(403, "AUTH_FORBIDDEN"));
        }
        return response(
            200,
            &DeviceAuthResponse {
                session: auth::session(
                    &db,
                    request.account_id,
                    Some(request.device_id),
                    request.device_name,
                )
                .await?,
            },
        );
    }
    let caller = auth::authenticate(req, &db).await?;
    let account = caller.account_id.to_string();
    match (method, path.as_str()) {
        (Method::Get, "/v1/vault/bootstrap") => {
            let result = rows(
                &db,
                "SELECT bootstrap FROM vaults WHERE account_id=?1",
                &[json!(account)],
            )
            .await?;
            let row = result.first().ok_or(ApiError(404, "OBJECT_NOT_FOUND"))?;
            let bootstrap: VaultBootstrap = serde_json::from_str(text(row, "bootstrap")?)?;
            response(200, &bootstrap)
        }
        (Method::Post, "/v1/vault/bootstrap") => {
            let bootstrap: VaultBootstrap = parse(req, "INVALID_VAULT_BOOTSTRAP").await?;
            if bootstrap.crypto_version != 1 {
                return Err(invalid("CRYPTO_UNSUPPORTED_VERSION"));
            }
            if bootstrap.kdf.algorithm.trim().is_empty()
                || bootstrap.kdf.memory_kib == 0
                || bootstrap.kdf.iterations == 0
                || bootstrap.kdf.parallelism == 0
                || Base64::decode_vec(&bootstrap.kdf.salt).is_err()
            {
                return Err(invalid("INVALID_VAULT_BOOTSTRAP"));
            }
            let result=rows(&db,"INSERT INTO vaults(account_id,bootstrap) VALUES(?1,?2) ON CONFLICT DO NOTHING RETURNING account_id",&[json!(account),json!(encode(&bootstrap)?)]).await?;
            if result.is_empty() {
                return Err(ApiError(409, "VAULT_ALREADY_EXISTS"));
            }
            response(201, &bootstrap)
        }
        (Method::Post, "/v1/sync/push") => sync::push(req, &db, &account).await,
        (Method::Get, "/v1/sync/pull" | "/v1/sync/changes") => sync::pull(req, &db, &account).await,
        (Method::Get, "/v1/auth/whoami" | "/v1/auth/session/status") => response(200, &caller),
        (Method::Post, "/v1/auth/logout" | "/v1/auth/session/revoke") => {
            let request: RevokeSessionRequest = parse(req, "INVALID_REQUEST").await?;
            let target = request
                .session_id
                .or(caller.session_id)
                .ok_or(invalid("NO_SESSION_IDENTIFIER"))?;
            let found=rows(&db,"UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE account_id=?1 AND session_id=?2 AND revoked_at IS NULL RETURNING session_id",&[json!(account),json!(target)]).await?;
            response(
                if found.is_empty() { 404 } else { 200 },
                &RevokeSessionResponse {
                    status: if found.is_empty() {
                        "session_not_found_or_already_revoked"
                    } else {
                        "revoked"
                    }
                    .into(),
                    revoked_session_id: target,
                },
            )
        }
        (Method::Get, "/v1/devices") => auth::devices(&db, &account).await,
        (Method::Post, "/v1/devices/revoke") => {
            let request: RevokeDeviceRequest = parse(req, "INVALID_REQUEST").await?;
            auth::revoke_device(&db, &account, &request.device_id.to_string()).await
        }
        (Method::Delete, _) if path.starts_with("/v1/devices/") => {
            auth::revoke_device(&db, &account, &uuid(&path[12..])?).await
        }
        (_, _) if path.starts_with("/v1/blobs/") => {
            blobs::route(req, env, &db, &account, &path[10..]).await
        }
        _ => Err(ApiError(404, "OBJECT_NOT_FOUND")),
    }
}

#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    if let Err(_error) = blobs::reconcile(&env).await {
        console_error!("RECONCILIATION_FAILED");
    }
}
