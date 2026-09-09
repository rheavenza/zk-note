//! Native HTTP and abstracted network sync adapter for zero-knowledge synchronization (ZK-040).
//!
//! In accordance with SEC-001, SEC-002, and SEC-003:
//! - Plaintext notes, note titles, tags, and decrypted keys NEVER cross the network.
//! - The adapter works exclusively with opaque `EncryptedEnvelope` payloads and `zk-protocol` models.
//! - Network and protocol errors are strongly typed.
//! - Authentication tokens and credentials are automatically abstracted without manual header handling.

use crate::error::SyncNetworkError;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zk_protocol::constants::{
    ERROR_MUTATION_REPLAY_MISMATCH, ERROR_REVISION_CONFLICT, ERROR_SYNC_CURSOR_INVALID,
};
use zk_protocol::sync::{ConflictResponse, PullChangesResponse, PushRequest, PushResponse};
use zk_protocol::vault::VaultBootstrap;

/// Scans a serialized JSON value for forbidden plaintext note content or credentials.
///
/// Enforces SEC-001 and SEC-002 client-side before any packet crosses the network.
pub fn validate_no_plaintext_secrets(value: &serde_json::Value) -> Result<(), SyncNetworkError> {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "title"
                        | "body"
                        | "tags"
                        | "plaintext"
                        | "passphrase"
                        | "password"
                        | "vault_key"
                        | "master_key"
                        | "secret"
                        | "note_key"
                ) {
                    return Err(SyncNetworkError::ForbiddenPlaintext(format!(
                        "forbidden plaintext key '{k}' detected in outgoing payload"
                    )));
                }
                validate_no_plaintext_secrets(v)?;
            }
            Ok(())
        }
        serde_json::Value::Array(list) => {
            for item in list {
                validate_no_plaintext_secrets(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Abstract contract for synchronization server interactions.
#[allow(async_fn_in_trait)]
pub trait SyncServerAdapter: Send + Sync {
    /// Retrieves vault bootstrap metadata from the server (`GET /v1/vault/bootstrap`).
    ///
    /// Returns `Ok(None)` if no vault bootstrap has been configured for the authenticated account.
    async fn get_vault_bootstrap(&self) -> Result<Option<VaultBootstrap>, SyncNetworkError>;

    /// Creates or updates vault bootstrap metadata on the server (`POST /v1/vault/bootstrap`).
    async fn post_vault_bootstrap(
        &self,
        bootstrap: &VaultBootstrap,
    ) -> Result<(), SyncNetworkError>;

    /// Submits a compare-and-swap push mutation to the server (`POST /v1/sync/push`).
    async fn push_mutation(&self, request: &PushRequest) -> Result<PushResponse, SyncNetworkError>;

    /// Pulls incremental encrypted changes from the server (`GET /v1/sync/changes`).
    async fn pull_changes(
        &self,
        after: u64,
        limit: Option<u32>,
    ) -> Result<PullChangesResponse, SyncNetworkError>;
}

/// Standard server error JSON structure.
#[derive(Debug, serde::Deserialize)]
struct ServerErrorJson {
    code: Option<String>,
    message: Option<String>,
}

/// Concrete native HTTP synchronization adapter using `reqwest`.
#[derive(Debug, Clone)]
pub struct NativeHttpSyncAdapter {
    base_url: String,
    auth_token: Arc<RwLock<Option<String>>>,
    client: Client,
}

impl NativeHttpSyncAdapter {
    /// Constructs a new [`NativeHttpSyncAdapter`] targeting `base_url` with optional initial auth token.
    pub fn new(
        base_url: impl Into<String>,
        auth_token: Option<String>,
    ) -> Result<Self, SyncNetworkError> {
        let client = Client::builder().build().map_err(|e| {
            SyncNetworkError::ConnectionFailed(format!("failed to init client: {e}"))
        })?;

        Self::with_client(base_url, auth_token, client)
    }

    /// Constructs a new [`NativeHttpSyncAdapter`] using an explicit `reqwest::Client`.
    pub fn with_client(
        base_url: impl Into<String>,
        auth_token: Option<String>,
        client: Client,
    ) -> Result<Self, SyncNetworkError> {
        let mut url = base_url.into();
        while url.ends_with('/') {
            url.pop();
        }
        if url.is_empty() {
            return Err(SyncNetworkError::ConnectionFailed(
                "base_url must not be empty".to_string(),
            ));
        }

        Ok(Self {
            base_url: url,
            auth_token: Arc::new(RwLock::new(auth_token)),
            client,
        })
    }

    /// Returns the target base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sets or updates the active authorization token.
    pub fn set_auth_token(&self, token: Option<String>) {
        if let Ok(mut lock) = self.auth_token.write() {
            *lock = token;
        }
    }

    /// Returns a copy of the current authorization token, if set.
    pub fn auth_token(&self) -> Option<String> {
        self.auth_token.read().ok().and_then(|lock| lock.clone())
    }

    /// Internal helper to construct an authenticated request builder.
    fn prepare_request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let full_url = format!("{}{path}", self.base_url);
        let mut req = self.client.request(method, full_url);

        let token = self.auth_token();
        if let Some(token_val) = token {
            let auth_header_val = if token_val.to_ascii_lowercase().starts_with("bearer ") {
                token_val
            } else {
                format!("Bearer {token_val}")
            };
            if let Ok(hv) = HeaderValue::from_str(&auth_header_val) {
                req = req.header(AUTHORIZATION, hv);
            }
        }

        req.header(CONTENT_TYPE, "application/json")
    }

    /// Parses and maps HTTP response status codes and bodies into typed [`SyncNetworkError`].
    async fn handle_response<T: DeserializeOwned>(
        &self,
        resp: Response,
    ) -> Result<T, SyncNetworkError> {
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| {
            SyncNetworkError::ConnectionFailed(format!("failed to read response body: {e}"))
        })?;

        if status.is_success() {
            let parsed: T = serde_json::from_slice(&bytes).map_err(|e| {
                SyncNetworkError::Serialization(format!(
                    "failed to deserialize server response: {e}"
                ))
            })?;
            return Ok(parsed);
        }

        // Try to parse server JSON error response
        let err_json: Option<ServerErrorJson> = serde_json::from_slice(&bytes).ok();
        let code = err_json.as_ref().and_then(|e| e.code.clone());
        let message = err_json
            .and_then(|e| e.message)
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).to_string());

        match status {
            StatusCode::UNAUTHORIZED => Err(SyncNetworkError::Unauthorized(message)),
            StatusCode::FORBIDDEN => Err(SyncNetworkError::Forbidden(message)),
            StatusCode::NOT_FOUND => Err(SyncNetworkError::NotFound(message)),
            StatusCode::CONFLICT => {
                if code.as_deref() == Some(ERROR_MUTATION_REPLAY_MISMATCH) {
                    return Err(SyncNetworkError::ReplayMismatch(message));
                }
                // Try to deserialize ConflictResponse
                if let Ok(conflict) = serde_json::from_slice::<ConflictResponse>(&bytes) {
                    return Err(SyncNetworkError::Conflict(Box::new(conflict)));
                }
                Err(SyncNetworkError::Conflict(Box::new(ConflictResponse {
                    error: ERROR_REVISION_CONFLICT.to_string(),
                    object_id: String::new(),
                    expected_revision: 0,
                    current_revision: 0,
                    current_server_seq: 0,
                    current_envelope: zk_protocol::envelope::EncryptedEnvelope {
                        envelope_version: zk_protocol::constants::ENVELOPE_VERSION_V1,
                        object_id: String::new(),
                        object_kind: zk_protocol::constants::OBJECT_KIND_NOTE,
                        wrapped_key: zk_protocol::envelope::EncryptedKeyContainer {
                            nonce: String::new(),
                            ciphertext: String::new(),
                        },
                        payload: zk_protocol::envelope::EncryptedPayloadContainer {
                            nonce: String::new(),
                            ciphertext: String::new(),
                        },
                    },
                })))
            }
            StatusCode::BAD_REQUEST => {
                if code.as_deref() == Some(ERROR_SYNC_CURSOR_INVALID) {
                    Err(SyncNetworkError::InvalidCursor(message))
                } else {
                    Err(SyncNetworkError::InvalidPayload(message))
                }
            }
            _ => Err(SyncNetworkError::ServerError {
                status: status.as_u16(),
                message,
            }),
        }
    }
}

impl SyncServerAdapter for NativeHttpSyncAdapter {
    async fn get_vault_bootstrap(&self) -> Result<Option<VaultBootstrap>, SyncNetworkError> {
        let req = self.prepare_request(Method::GET, "/v1/vault/bootstrap");
        let resp = req
            .send()
            .await
            .map_err(|e| SyncNetworkError::ConnectionFailed(e.to_string()))?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let bootstrap: VaultBootstrap = self.handle_response(resp).await?;
        Ok(Some(bootstrap))
    }

    async fn post_vault_bootstrap(
        &self,
        bootstrap: &VaultBootstrap,
    ) -> Result<(), SyncNetworkError> {
        // Enforce SEC-001/SEC-002: no passphrase or plaintext secrets
        let json_val = serde_json::to_value(bootstrap)
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;
        validate_no_plaintext_secrets(&json_val)?;

        let req = self
            .prepare_request(Method::POST, "/v1/vault/bootstrap")
            .json(bootstrap);

        let resp = req
            .send()
            .await
            .map_err(|e| SyncNetworkError::ConnectionFailed(e.to_string()))?;

        let _: serde_json::Value = self.handle_response(resp).await?;
        Ok(())
    }

    async fn push_mutation(&self, request: &PushRequest) -> Result<PushResponse, SyncNetworkError> {
        // Enforce SEC-001/SEC-002: verify no plaintext note content or keys in request
        let json_val = serde_json::to_value(request)
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;
        validate_no_plaintext_secrets(&json_val)?;

        let req = self
            .prepare_request(Method::POST, "/v1/sync/push")
            .json(request);

        let resp = req
            .send()
            .await
            .map_err(|e| SyncNetworkError::ConnectionFailed(e.to_string()))?;

        let push_resp: PushResponse = self.handle_response(resp).await?;
        Ok(push_resp)
    }

    async fn pull_changes(
        &self,
        after: u64,
        limit: Option<u32>,
    ) -> Result<PullChangesResponse, SyncNetworkError> {
        let mut path = format!("/v1/sync/changes?after={after}");
        if let Some(lim) = limit {
            path.push_str(&format!("&limit={lim}"));
        }

        let req = self.prepare_request(Method::GET, &path);
        let resp = req
            .send()
            .await
            .map_err(|e| SyncNetworkError::ConnectionFailed(e.to_string()))?;

        let pull_resp: PullChangesResponse = self.handle_response(resp).await?;
        Ok(pull_resp)
    }
}

/// In-memory mock adapter for deterministic unit testing of sync flows.
#[derive(Debug, Default)]
pub struct MockSyncAdapter {
    bootstrap: Arc<RwLock<Option<VaultBootstrap>>>,
    objects: Arc<RwLock<HashMap<String, zk_protocol::sync::ObjectChange>>>,
    sequence_counter: Arc<RwLock<u64>>,
    fail_next: Arc<RwLock<Option<SyncNetworkError>>>,
}

impl MockSyncAdapter {
    /// Creates a new empty [`MockSyncAdapter`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an explicit error to be returned on the next call.
    pub fn set_fail_next(&self, error: Option<SyncNetworkError>) {
        if let Ok(mut lock) = self.fail_next.write() {
            *lock = error;
        }
    }

    fn check_failure(&self) -> Result<(), SyncNetworkError> {
        if let Ok(mut lock) = self.fail_next.write() {
            if let Some(err) = lock.take() {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl SyncServerAdapter for MockSyncAdapter {
    async fn get_vault_bootstrap(&self) -> Result<Option<VaultBootstrap>, SyncNetworkError> {
        self.check_failure()?;
        let lock = self
            .bootstrap
            .read()
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;
        Ok(lock.clone())
    }

    async fn post_vault_bootstrap(
        &self,
        bootstrap: &VaultBootstrap,
    ) -> Result<(), SyncNetworkError> {
        self.check_failure()?;
        let mut lock = self
            .bootstrap
            .write()
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;
        *lock = Some(bootstrap.clone());
        Ok(())
    }

    async fn push_mutation(&self, request: &PushRequest) -> Result<PushResponse, SyncNetworkError> {
        self.check_failure()?;

        let mut objects = self
            .objects
            .write()
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;
        let mut seq_lock = self
            .sequence_counter
            .write()
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;

        let existing = objects.get(&request.object_id);
        let cur_rev = existing.map(|c| c.revision).unwrap_or(0);

        if request.expected_revision != cur_rev {
            let conflict_envelope = existing.map(|c| c.envelope.clone()).unwrap_or_else(|| {
                zk_protocol::envelope::EncryptedEnvelope {
                    envelope_version: zk_protocol::constants::ENVELOPE_VERSION_V1,
                    object_id: request.object_id.clone(),
                    object_kind: request.object_kind,
                    wrapped_key: zk_protocol::envelope::EncryptedKeyContainer {
                        nonce: String::new(),
                        ciphertext: String::new(),
                    },
                    payload: zk_protocol::envelope::EncryptedPayloadContainer {
                        nonce: String::new(),
                        ciphertext: String::new(),
                    },
                }
            });

            return Err(SyncNetworkError::Conflict(Box::new(ConflictResponse {
                error: ERROR_REVISION_CONFLICT.to_string(),
                object_id: request.object_id.clone(),
                expected_revision: request.expected_revision,
                current_revision: cur_rev,
                current_server_seq: existing.map(|c| c.server_seq).unwrap_or(0),
                current_envelope: conflict_envelope,
            })));
        }

        *seq_lock += 1;
        let new_seq = *seq_lock;
        let new_rev = cur_rev + 1;

        let change = zk_protocol::sync::ObjectChange {
            server_seq: new_seq,
            object_id: request.object_id.clone(),
            revision: new_rev,
            object_kind: request.object_kind,
            is_deleted: request.is_deleted,
            envelope: request.envelope.clone(),
        };

        objects.insert(request.object_id.clone(), change);

        Ok(PushResponse {
            object_id: request.object_id.clone(),
            revision: new_rev,
            server_seq: new_seq,
        })
    }

    async fn pull_changes(
        &self,
        after: u64,
        limit: Option<u32>,
    ) -> Result<PullChangesResponse, SyncNetworkError> {
        self.check_failure()?;

        let objects = self
            .objects
            .read()
            .map_err(|e| SyncNetworkError::Serialization(e.to_string()))?;

        let mut matching: Vec<_> = objects
            .values()
            .filter(|c| c.server_seq > after)
            .cloned()
            .collect();
        matching.sort_by_key(|c| c.server_seq);

        let lim = limit.unwrap_or(50) as usize;
        let has_more = matching.len() > lim;
        let changes: Vec<_> = matching.into_iter().take(lim).collect();
        let next_cursor = changes.last().map(|c| c.server_seq).unwrap_or(after);

        Ok(PullChangesResponse {
            changes,
            next_cursor,
            has_more,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
    use zk_protocol::envelope::{
        EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer,
    };

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: "obj-1".to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=".to_string(),
                ciphertext: "d3JhcHBlZC1rZXktY2lwaGVydGV4dA==".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "YW5vdGhlciAyNC1ieXRlIG5vbmNl".to_string(),
                ciphertext: "ZW5jcnlwdGVkLXBheWxvYWQ=".to_string(),
            },
        }
    }

    #[test]
    fn test_validate_no_plaintext_secrets_rejects_forbidden_fields() {
        let safe = serde_json::json!({
            "mutation_id": "uuid",
            "object_id": "uuid",
            "expected_revision": 0,
            "envelope": {
                "wrapped_key": { "nonce": "abc", "ciphertext": "def" },
                "payload": { "nonce": "abc", "ciphertext": "def" }
            }
        });
        assert!(validate_no_plaintext_secrets(&safe).is_ok());

        let leaked_title = serde_json::json!({
            "title": "Secret Meeting",
            "envelope": {}
        });
        assert!(validate_no_plaintext_secrets(&leaked_title).is_err());

        let leaked_body = serde_json::json!({
            "nested": {
                "body": "Plaintext secret notes"
            }
        });
        assert!(validate_no_plaintext_secrets(&leaked_body).is_err());

        let leaked_passphrase = serde_json::json!({
            "vault": {
                "passphrase": "super-secret-password"
            }
        });
        assert!(validate_no_plaintext_secrets(&leaked_passphrase).is_err());
    }

    #[test]
    fn test_native_adapter_url_normalization_and_token() {
        let adapter =
            NativeHttpSyncAdapter::new("http://127.0.0.1:8080///", Some("token-1".to_string()))
                .unwrap();
        assert_eq!(adapter.base_url(), "http://127.0.0.1:8080");
        assert_eq!(adapter.auth_token(), Some("token-1".to_string()));

        adapter.set_auth_token(Some("token-2".to_string()));
        assert_eq!(adapter.auth_token(), Some("token-2".to_string()));

        adapter.set_auth_token(None);
        assert_eq!(adapter.auth_token(), None);

        assert!(NativeHttpSyncAdapter::new("", None).is_err());
    }

    #[tokio::test]
    async fn test_mock_adapter_push_pull_and_conflict_lifecycle() {
        let adapter = MockSyncAdapter::new();

        // 1. Initial push (expected_revision = 0)
        let push_req = PushRequest {
            mutation_id: "mut-1".to_string(),
            object_id: "obj-1".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: sample_envelope(),
            is_deleted: false,
        };

        let push_resp = adapter.push_mutation(&push_req).await.unwrap();
        assert_eq!(push_resp.revision, 1);
        assert_eq!(push_resp.server_seq, 1);

        // 2. Pull changes
        let pull = adapter.pull_changes(0, None).await.unwrap();
        assert_eq!(pull.changes.len(), 1);
        assert_eq!(pull.changes[0].revision, 1);
        assert_eq!(pull.next_cursor, 1);
        assert!(!pull.has_more);

        // 3. Stale push (expected_revision = 0 again) causes Conflict
        let stale_req = PushRequest {
            mutation_id: "mut-2".to_string(),
            object_id: "obj-1".to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            envelope: sample_envelope(),
            is_deleted: false,
        };
        let err = adapter.push_mutation(&stale_req).await.unwrap_err();
        match err {
            SyncNetworkError::Conflict(c) => {
                assert_eq!(c.expected_revision, 0);
                assert_eq!(c.current_revision, 1);
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }
}
