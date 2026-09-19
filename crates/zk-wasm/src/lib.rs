//! WebAssembly bindings and narrow typed JS boundary for the zero-knowledge core (ZK-060).
//!
//! In accordance with MASTER_SPEC.md § 18, SEC-001, SEC-002, SEC-003, and SEC-009:
//! - Exposes a narrow, typed JavaScript boundary for browser and Web Worker execution.
//! - The raw 32-byte Vault Key is held strictly inside WASM linear memory within [`WasmVaultSession`].
//! - Zero raw Vault Key exposure to React component state or global JS objects.
//! - Memory is scrubbed via [`Zeroize`] when the vault is locked or dropped.
//! - Cryptographic failures fail closed without leaking plaintext fragments or secrets.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;
use zk_core::note::{NoteBuilder, PlaintextNote};
use zk_core::search::InMemorySearchIndex;
use zk_core::vault::VaultSession;
use zk_crypto::kdf::{derive_kek, KdfParams};
use zk_crypto::keys::{AttachmentKey, KeyEncryptionKey, RecoveryKey, VaultKey};
use zk_crypto::object::{decrypt_envelope, encrypt_envelope};
use zk_crypto::recovery::{format_recovery_key, parse_recovery_key};
use zk_crypto::vault::{
    unwrap_vault_key, unwrap_vault_key_recovery, wrap_vault_key, wrap_vault_key_recovery,
    WrappedVaultKey,
};
use zk_protocol::attachment::{AttachmentManifest, EncryptedChunk};
use zk_protocol::envelope::EncryptedEnvelope;

/// Typed errors produced across the WASM boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmError {
    /// Vault is currently locked.
    VaultLocked,
    /// Cryptographic operation failed.
    Crypto(String),
    /// Invalid or unparseable envelope.
    InvalidEnvelope(String),
    /// Invalid JSON or parameter payload.
    InvalidPayload(String),
    /// Vault session was already taken from init result.
    SessionAlreadyTaken,
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VaultLocked => write!(f, "vault is locked"),
            Self::Crypto(msg) => write!(f, "cryptographic error: {msg}"),
            Self::InvalidEnvelope(msg) => write!(f, "invalid envelope: {msg}"),
            Self::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            Self::SessionAlreadyTaken => write!(f, "session already taken"),
        }
    }
}

impl std::error::Error for WasmError {}

#[cfg(target_arch = "wasm32")]
fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    JsError::new(&err.to_string()).into()
}

#[cfg(not(target_arch = "wasm32"))]
fn to_js_error(_err: impl std::fmt::Display) -> JsValue {
    JsValue::NULL
}

/// Plaintext note model exported across the WASM boundary to JavaScript.
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPlaintextNote {
    id: String,
    title: String,
    body: String,
    tags: Vec<String>,
    attachments: Vec<String>,
    created_at: String,
    updated_at: String,
}

#[wasm_bindgen]
impl WasmPlaintextNote {
    /// Note identifier.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Note title.
    #[wasm_bindgen(getter)]
    pub fn title(&self) -> String {
        self.title.clone()
    }

    /// Note markdown body.
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> String {
        self.body.clone()
    }

    /// Note tags as an array of strings.
    #[wasm_bindgen(getter)]
    pub fn tags(&self) -> Vec<String> {
        self.tags.clone()
    }

    /// Note attachment IDs as an array of strings (ZK-084).
    #[wasm_bindgen(getter)]
    pub fn attachments(&self) -> Vec<String> {
        self.attachments.clone()
    }

    /// ISO-8601 creation timestamp.
    #[wasm_bindgen(getter)]
    pub fn created_at(&self) -> String {
        self.created_at.clone()
    }

    /// ISO-8601 last update timestamp.
    #[wasm_bindgen(getter)]
    pub fn updated_at(&self) -> String {
        self.updated_at.clone()
    }

    /// Serializes note to JSON string.
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| to_js_error(e.to_string()))
    }
}

/// Attachment metadata manifest exported across the WASM boundary to JavaScript (ZK-084).
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmAttachmentManifest {
    attachment_id: String,
    name: String,
    mime: String,
    size: f64,
    chunk_count: u32,
    chunk_size: u32,
    content_hash: Option<String>,
}

#[wasm_bindgen]
impl WasmAttachmentManifest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        attachment_id: String,
        name: String,
        mime: String,
        size: f64,
        chunk_count: u32,
        chunk_size: u32,
        content_hash: Option<String>,
    ) -> Self {
        Self {
            attachment_id,
            name,
            mime,
            size,
            chunk_count,
            chunk_size,
            content_hash,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn attachment_id(&self) -> String {
        self.attachment_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn mime(&self) -> String {
        self.mime.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.size
    }

    #[wasm_bindgen(getter)]
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    #[wasm_bindgen(getter)]
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    #[wasm_bindgen(getter)]
    pub fn content_hash(&self) -> Option<String> {
        self.content_hash.clone()
    }

    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self).map_err(|e| to_js_error(e.to_string()))
    }
}

/// Decrypted attachment manifest and key container (ZK-084).
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmDecryptedManifest {
    manifest: WasmAttachmentManifest,
    attachment_key_base64: String,
}

#[wasm_bindgen]
impl WasmDecryptedManifest {
    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> WasmAttachmentManifest {
        self.manifest.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attachment_key_base64(&self) -> String {
        self.attachment_key_base64.clone()
    }
}

/// Search match result exported to JavaScript.
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSearchResult {
    note_id: String,
    score: u32,
    matched_title: String,
    snippet: String,
}

#[wasm_bindgen]
impl WasmSearchResult {
    /// Note identifier.
    #[wasm_bindgen(getter)]
    pub fn note_id(&self) -> String {
        self.note_id.clone()
    }

    /// Search relevance score.
    #[wasm_bindgen(getter)]
    pub fn score(&self) -> u32 {
        self.score
    }

    /// Matched note title.
    #[wasm_bindgen(getter)]
    pub fn matched_title(&self) -> String {
        self.matched_title.clone()
    }

    /// Snippet highlighting matched query terms in context.
    #[wasm_bindgen(getter)]
    pub fn snippet(&self) -> String {
        self.snippet.clone()
    }
}

/// Result of changing the vault passphrase via rewrapping.
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRewrapResult {
    new_wrapped_vault_key: String,
    new_kdf_params_json: String,
}

#[wasm_bindgen]
impl WasmRewrapResult {
    /// The newly wrapped Vault Key JSON string.
    #[wasm_bindgen(getter)]
    pub fn new_wrapped_vault_key(&self) -> String {
        self.new_wrapped_vault_key.clone()
    }

    /// The new KDF parameters JSON string.
    #[wasm_bindgen(getter)]
    pub fn new_kdf_params_json(&self) -> String {
        self.new_kdf_params_json.clone()
    }
}

/// Active vault session held exclusively in WASM linear memory.
///
/// React components interact with this session exclusively via handle methods.
/// The raw Vault Key is never exposed to JavaScript (SEC-002, ZK-060).
#[derive(Debug)]
#[wasm_bindgen]
pub struct WasmVaultSession {
    inner: VaultSession,
    search_index: InMemorySearchIndex,
}

impl WasmVaultSession {
    /// Encrypt note implementation returning typed `WasmError`.
    pub fn encrypt_note_impl(
        &self,
        note_id: &str,
        title: &str,
        body: &str,
        tags: Vec<String>,
        attachments: Vec<String>,
    ) -> Result<String, WasmError> {
        let key = self
            .inner
            .active_key()
            .map_err(|e| WasmError::Crypto(e.to_string()))?;

        let mut note = NoteBuilder::new()
            .title(title)
            .body(body)
            .tags(tags)
            .attachments(attachments)
            .build()
            .map_err(|e| WasmError::InvalidPayload(e.to_string()))?;

        note.canonicalize();

        let envelope = note
            .encrypt(key, note_id)
            .map_err(|e| WasmError::Crypto(e.to_string()))?;

        serde_json::to_string(&envelope).map_err(|e| WasmError::InvalidPayload(e.to_string()))
    }

    /// Decrypt note implementation returning typed `WasmError`.
    pub fn decrypt_note_impl(&self, envelope_json: &str) -> Result<WasmPlaintextNote, WasmError> {
        let key = self
            .inner
            .active_key()
            .map_err(|e| WasmError::Crypto(e.to_string()))?;

        let envelope: EncryptedEnvelope = serde_json::from_str(envelope_json)
            .map_err(|e| WasmError::InvalidEnvelope(e.to_string()))?;

        let note = PlaintextNote::decrypt(&envelope, key)
            .map_err(|e| WasmError::Crypto(format!("decryption failed: {e}")))?;

        Ok(WasmPlaintextNote {
            id: envelope.object_id,
            title: note.title,
            body: note.body,
            tags: note.tags,
            attachments: note.attachments,
            created_at: note.created_at,
            updated_at: note.updated_at,
        })
    }

    /// Index note implementation.
    pub fn index_note_impl(
        &mut self,
        note_id: &str,
        title: &str,
        body: &str,
        tags: Vec<String>,
        updated_at: &str,
    ) -> Result<(), WasmError> {
        if !self.is_unlocked() {
            return Err(WasmError::VaultLocked);
        }
        self.search_index.insert_raw(
            note_id.to_string(),
            title.to_string(),
            tags,
            body.to_string(),
            updated_at.to_string(),
        );
        Ok(())
    }

    /// Search implementation.
    pub fn search_impl(&self, query: &str) -> Result<Vec<WasmSearchResult>, WasmError> {
        if !self.is_unlocked() {
            return Err(WasmError::VaultLocked);
        }
        let matches = self.search_index.search(query);
        let results = matches
            .into_iter()
            .map(|m| WasmSearchResult {
                note_id: m.id,
                score: m.score,
                matched_title: m.title,
                snippet: m.snippet,
            })
            .collect();
        Ok(results)
    }

    /// Rewrap passphrase implementation.
    pub fn rewrap_passphrase_impl(
        &mut self,
        new_passphrase: &str,
        params: &KdfParams,
    ) -> Result<WasmRewrapResult, WasmError> {
        let key = self
            .inner
            .active_key()
            .map_err(|e| WasmError::Crypto(e.to_string()))?;

        let new_kek = derive_kek(new_passphrase.as_bytes(), params)
            .map_err(|e| WasmError::Crypto(e.to_string()))?;

        let new_wrapped =
            wrap_vault_key(key, &new_kek).map_err(|e| WasmError::Crypto(e.to_string()))?;

        let new_wrapped_json = serde_json::to_string(&new_wrapped)
            .map_err(|e| WasmError::InvalidPayload(e.to_string()))?;
        let new_params_json =
            serde_json::to_string(params).map_err(|e| WasmError::InvalidPayload(e.to_string()))?;

        Ok(WasmRewrapResult {
            new_wrapped_vault_key: new_wrapped_json,
            new_kdf_params_json: new_params_json,
        })
    }
}

#[wasm_bindgen]
impl WasmVaultSession {
    /// Returns true if the vault session is currently unlocked and holds an active key.
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Explicitly locks the vault session, zeroizing and scrubbing all key material
    /// and plaintext search indexes from memory (SEC-003, SEC-009).
    pub fn lock(&mut self) {
        self.inner.lock();
        self.search_index.clear();
    }

    /// Sets or updates the idle auto-lock timeout in seconds (None or 0 disables) (ZK-076).
    pub fn set_idle_timeout(&mut self, timeout_secs: Option<u64>) {
        self.inner.set_idle_timeout(timeout_secs);
    }

    /// Returns the configured idle timeout in seconds, or None if disabled (ZK-076).
    pub fn idle_timeout(&self) -> Option<u64> {
        self.inner.idle_timeout()
    }

    /// Touches the session, updating the last active timestamp (ZK-076).
    pub fn touch(&mut self) {
        self.inner.touch();
    }

    /// Checks if the idle timeout has elapsed. If so, locks and zeroes session material
    /// and returns true; otherwise returns false (ZK-076).
    pub fn check_idle_timeout(&mut self) -> bool {
        let expired = self.inner.check_idle_timeout();
        if expired {
            self.search_index.clear();
        }
        expired
    }

    /// Encrypts a note into an [`EncryptedEnvelope`] JSON string using the active session key.
    ///
    /// Fails closed if the session is locked.
    pub fn encrypt_note(
        &self,
        note_id: &str,
        title: &str,
        body: &str,
        tags: Vec<String>,
    ) -> Result<String, JsValue> {
        self.encrypt_note_impl(note_id, title, body, tags, Vec::new())
            .map_err(to_js_error)
    }

    /// Encrypts a note with attachment IDs into an [`EncryptedEnvelope`] JSON string (ZK-084).
    pub fn encrypt_note_with_attachments(
        &self,
        note_id: &str,
        title: &str,
        body: &str,
        tags: Vec<String>,
        attachments: Vec<String>,
    ) -> Result<String, JsValue> {
        self.encrypt_note_impl(note_id, title, body, tags, attachments)
            .map_err(to_js_error)
    }

    /// Decrypts an [`EncryptedEnvelope`] JSON string using the active session key.
    ///
    /// Fails closed if the session is locked or if the ciphertext is tampered (SEC-010).
    pub fn decrypt_note(&self, envelope_json: &str) -> Result<WasmPlaintextNote, JsValue> {
        self.decrypt_note_impl(envelope_json).map_err(to_js_error)
    }

    /// Indexes a decrypted note into the in-memory search index inside WASM memory.
    pub fn index_note(
        &mut self,
        note_id: &str,
        title: &str,
        body: &str,
        tags: Vec<String>,
        updated_at: &str,
    ) -> Result<(), JsValue> {
        self.index_note_impl(note_id, title, body, tags, updated_at)
            .map_err(to_js_error)
    }

    /// Removes a note from the in-memory search index.
    pub fn remove_from_index(&mut self, note_id: &str) -> Result<(), JsValue> {
        if !self.is_unlocked() {
            return Err(to_js_error(WasmError::VaultLocked));
        }
        self.search_index.remove(note_id);
        Ok(())
    }

    /// Executes an in-memory search across indexed note titles, tags, and bodies.
    ///
    /// Returns search matches with relevance scores and contextual body snippets.
    pub fn search(&self, query: &str) -> Result<Vec<WasmSearchResult>, JsValue> {
        self.search_impl(query).map_err(to_js_error)
    }

    /// Changes the vault passphrase by re-wrapping the active Vault Key.
    ///
    /// The Vault Key is preserved; notes do NOT need to be re-encrypted.
    pub fn rewrap_passphrase(&mut self, new_passphrase: &str) -> Result<WasmRewrapResult, JsValue> {
        self.rewrap_passphrase_impl(new_passphrase, &KdfParams::new_production())
            .map_err(to_js_error)
    }

    /// Changes the vault passphrase by re-wrapping the active Vault Key with explicit KDF parameters.
    pub fn rewrap_passphrase_with_params(
        &mut self,
        new_passphrase: &str,
        kdf_params_json: &str,
    ) -> Result<WasmRewrapResult, JsValue> {
        let params: KdfParams =
            serde_json::from_str(kdf_params_json).map_err(|e| to_js_error(e.to_string()))?;
        self.rewrap_passphrase_impl(new_passphrase, &params)
            .map_err(to_js_error)
    }

    /// Encrypts an attachment manifest into an EncryptedEnvelope JSON string under the active Vault Key (ZK-084).
    pub fn encrypt_attachment_manifest(
        &self,
        manifest_json: &str,
        attachment_key_base64: &str,
    ) -> Result<String, JsValue> {
        let key = self
            .inner
            .active_key()
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        let manifest: AttachmentManifest = serde_json::from_str(manifest_json)
            .map_err(|e| to_js_error(WasmError::InvalidPayload(e.to_string())))?;

        let key_bytes = Base64::decode_vec(attachment_key_base64)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;
        let attachment_key = AttachmentKey::from_slice(&key_bytes)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        let envelope =
            zk_core::attachment::encrypt_attachment_manifest(&manifest, &attachment_key, key)
                .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        serde_json::to_string(&envelope)
            .map_err(|e| to_js_error(WasmError::InvalidPayload(e.to_string())))
    }

    /// Decrypts an EncryptedEnvelope JSON string containing an attachment manifest using the active Vault Key (ZK-084).
    pub fn decrypt_attachment_manifest(
        &self,
        envelope_json: &str,
    ) -> Result<WasmDecryptedManifest, JsValue> {
        let key = self
            .inner
            .active_key()
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        let envelope: EncryptedEnvelope = serde_json::from_str(envelope_json)
            .map_err(|e| to_js_error(WasmError::InvalidEnvelope(e.to_string())))?;

        let (manifest, attachment_key) =
            zk_core::attachment::decrypt_attachment_manifest(&envelope, key).map_err(|e| {
                to_js_error(WasmError::Crypto(format!(
                    "manifest decryption failed: {e}"
                )))
            })?;

        let wasm_manifest = WasmAttachmentManifest {
            attachment_id: manifest.attachment_id,
            name: manifest.name,
            mime: manifest.mime,
            size: manifest.size as f64,
            chunk_count: manifest.chunk_count,
            chunk_size: manifest.chunk_size,
            content_hash: manifest.content_hash,
        };

        let attachment_key_base64 = Base64::encode_string(attachment_key.as_bytes());

        Ok(WasmDecryptedManifest {
            manifest: wasm_manifest,
            attachment_key_base64,
        })
    }

    /// Encrypts an attachment chunk using XChaCha20-Poly1305 and returns compact binary wire format (ZKCK) (ZK-084).
    pub fn encrypt_attachment_chunk(
        &self,
        chunk_bytes: &[u8],
        attachment_id: &str,
        chunk_index: u32,
        total_chunks: u32,
        attachment_key_base64: &str,
    ) -> Result<Vec<u8>, JsValue> {
        if !self.is_unlocked() {
            return Err(to_js_error(WasmError::VaultLocked));
        }
        let key_bytes = Base64::decode_vec(attachment_key_base64)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;
        let attachment_key = AttachmentKey::from_slice(&key_bytes)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        let encrypted = zk_crypto::attachment::encrypt_chunk(
            chunk_bytes,
            &attachment_key,
            attachment_id,
            chunk_index,
            total_chunks,
        )
        .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        encrypted
            .to_bytes()
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))
    }

    /// Decrypts a binary attachment chunk (ZKCK) and verifies chunk index and AAD (ZK-084).
    pub fn decrypt_attachment_chunk(
        &self,
        chunk_binary: &[u8],
        attachment_key_base64: &str,
    ) -> Result<Vec<u8>, JsValue> {
        if !self.is_unlocked() {
            return Err(to_js_error(WasmError::VaultLocked));
        }
        let key_bytes = Base64::decode_vec(attachment_key_base64)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;
        let attachment_key = AttachmentKey::from_slice(&key_bytes)
            .map_err(|e| to_js_error(WasmError::Crypto(e.to_string())))?;

        let chunk = EncryptedChunk::from_bytes(chunk_binary)
            .map_err(|e| to_js_error(WasmError::InvalidPayload(e.to_string())))?;

        let plaintext = zk_crypto::attachment::decrypt_chunk(&chunk, &attachment_key)
            .map_err(|e| to_js_error(WasmError::Crypto(format!("chunk decryption failed: {e}"))))?;

        Ok(plaintext)
    }
}

impl Drop for WasmVaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

/// Result returned to JavaScript when initializing a brand-new vault.
#[derive(Debug)]
#[wasm_bindgen]
pub struct WasmVaultInitResult {
    wrapped_vault_key: String,
    kdf_params_json: String,
    wrapped_recovery_key: String,
    recovery_phrase: String,
    session: Option<WasmVaultSession>,
}

#[wasm_bindgen]
impl WasmVaultInitResult {
    /// Wrapped Vault Key JSON string.
    #[wasm_bindgen(getter)]
    pub fn wrapped_vault_key(&self) -> String {
        self.wrapped_vault_key.clone()
    }

    /// KDF parameters JSON string.
    #[wasm_bindgen(getter)]
    pub fn kdf_params_json(&self) -> String {
        self.kdf_params_json.clone()
    }

    /// Wrapped Vault Key via Recovery Key JSON string.
    #[wasm_bindgen(getter)]
    pub fn wrapped_recovery_key(&self) -> String {
        self.wrapped_recovery_key.clone()
    }

    /// Human-readable 24-word recovery phrase.
    #[wasm_bindgen(getter)]
    pub fn recovery_phrase(&self) -> String {
        self.recovery_phrase.clone()
    }

    /// Takes the initialized active [`WasmVaultSession`] into JavaScript.
    pub fn take_session(&mut self) -> Result<WasmVaultSession, JsValue> {
        self.session
            .take()
            .ok_or_else(|| to_js_error(WasmError::SessionAlreadyTaken))
    }
}

/// Initializes the panic hook in WebAssembly environments for detailed diagnostics.
#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

/// Initializes a new vault from a user passphrase using production KDF parameters.
///
/// Returns bootstrap data for server persistence and an active [`WasmVaultSession`].
#[wasm_bindgen]
pub fn init_vault(passphrase: &str) -> Result<WasmVaultInitResult, JsValue> {
    init_panic_hook();
    init_vault_impl(passphrase, &KdfParams::new_production()).map_err(to_js_error)
}

/// Initializes a new vault with explicit KDF parameters JSON (for tests or custom configurations).
#[wasm_bindgen]
pub fn init_vault_with_params(
    passphrase: &str,
    kdf_params_json: &str,
) -> Result<WasmVaultInitResult, JsValue> {
    init_panic_hook();
    let params: KdfParams =
        serde_json::from_str(kdf_params_json).map_err(|e| to_js_error(e.to_string()))?;
    init_vault_impl(passphrase, &params).map_err(to_js_error)
}

/// Initializes a new vault with explicit KDF parameters (useful for fast testing).
pub fn init_vault_impl(
    passphrase: &str,
    params: &KdfParams,
) -> Result<WasmVaultInitResult, WasmError> {
    let mut vault_key = VaultKey::generate();
    let recovery_key = RecoveryKey::generate();

    let kek =
        derive_kek(passphrase.as_bytes(), params).map_err(|e| WasmError::Crypto(e.to_string()))?;

    let wrapped_vault =
        wrap_vault_key(&vault_key, &kek).map_err(|e| WasmError::Crypto(e.to_string()))?;
    let wrapped_recovery = wrap_vault_key_recovery(&vault_key, &recovery_key)
        .map_err(|e| WasmError::Crypto(e.to_string()))?;

    let wrapped_vault_json = serde_json::to_string(&wrapped_vault)
        .map_err(|e| WasmError::InvalidPayload(e.to_string()))?;
    let params_json =
        serde_json::to_string(params).map_err(|e| WasmError::InvalidPayload(e.to_string()))?;
    let wrapped_rec_json = serde_json::to_string(&wrapped_recovery)
        .map_err(|e| WasmError::InvalidPayload(e.to_string()))?;

    let phrase = format_recovery_key(&recovery_key);

    let session = WasmVaultSession {
        inner: VaultSession::from_key(vault_key.clone()),
        search_index: InMemorySearchIndex::new(),
    };

    vault_key.zeroize();

    Ok(WasmVaultInitResult {
        wrapped_vault_key: wrapped_vault_json,
        kdf_params_json: params_json,
        wrapped_recovery_key: wrapped_rec_json,
        recovery_phrase: phrase,
        session: Some(session),
    })
}

/// Unlocks a vault using a user passphrase, wrapped vault key, and KDF parameters.
///
/// Returns an active [`WasmVaultSession`] without ever exposing the raw Vault Key to JavaScript.
#[wasm_bindgen]
pub fn unlock_vault(
    passphrase: &str,
    wrapped_vault_key_json: &str,
    kdf_params_json: &str,
) -> Result<WasmVaultSession, JsValue> {
    unlock_vault_impl(passphrase, wrapped_vault_key_json, kdf_params_json).map_err(to_js_error)
}

/// Unlocks a vault implementation.
pub fn unlock_vault_impl(
    passphrase: &str,
    wrapped_vault_key_json: &str,
    kdf_params_json: &str,
) -> Result<WasmVaultSession, WasmError> {
    let params: KdfParams = serde_json::from_str(kdf_params_json)
        .map_err(|e| WasmError::InvalidPayload(e.to_string()))?;

    let wrapped_key: WrappedVaultKey = serde_json::from_str(wrapped_vault_key_json)
        .map_err(|e| WasmError::InvalidEnvelope(e.to_string()))?;

    let kek =
        derive_kek(passphrase.as_bytes(), &params).map_err(|e| WasmError::Crypto(e.to_string()))?;

    let vault_key = unwrap_vault_key(&wrapped_key, &kek)
        .map_err(|e| WasmError::Crypto(format!("unlock failed: {e}")))?;

    Ok(WasmVaultSession {
        inner: VaultSession::from_key(vault_key),
        search_index: InMemorySearchIndex::new(),
    })
}

/// Unlocks a vault using a formatted recovery key string and the recovery-wrapped key.
#[wasm_bindgen]
pub fn unlock_with_recovery_key(
    recovery_phrase: &str,
    wrapped_recovery_key_json: &str,
) -> Result<WasmVaultSession, JsValue> {
    unlock_with_recovery_key_impl(recovery_phrase, wrapped_recovery_key_json).map_err(to_js_error)
}

/// Recovery unlock implementation.
pub fn unlock_with_recovery_key_impl(
    recovery_phrase: &str,
    wrapped_recovery_key_json: &str,
) -> Result<WasmVaultSession, WasmError> {
    let recovery_key = parse_recovery_key(recovery_phrase)
        .map_err(|e| WasmError::Crypto(format!("invalid recovery phrase: {e}")))?;

    let wrapped_key: WrappedVaultKey = serde_json::from_str(wrapped_recovery_key_json)
        .map_err(|e| WasmError::InvalidEnvelope(e.to_string()))?;

    let vault_key = unwrap_vault_key_recovery(&wrapped_key, &recovery_key)
        .map_err(|e| WasmError::Crypto(format!("recovery unlock failed: {e}")))?;

    Ok(WasmVaultSession {
        inner: VaultSession::from_key(vault_key),
        search_index: InMemorySearchIndex::new(),
    })
}

// ----------------------------------------------------------------------------
// Standalone Cryptographic Compatibility Functions (for ZK-061 cross-runtime suite)
// ----------------------------------------------------------------------------

/// Derives KEK and returns base64-encoded 32-byte key.
#[wasm_bindgen]
pub fn wasm_derive_kek(passphrase: &str, kdf_params_json: &str) -> Result<String, JsValue> {
    let params: KdfParams =
        serde_json::from_str(kdf_params_json).map_err(|e| to_js_error(e.to_string()))?;
    let kek = derive_kek(passphrase.as_bytes(), &params).map_err(|e| to_js_error(e.to_string()))?;
    Ok(Base64::encode_string(kek.as_bytes()))
}

/// Wraps a raw key with a KEK using authenticated envelope encryption.
#[wasm_bindgen]
pub fn wasm_wrap_key(kek_base64: &str, key_to_wrap_base64: &str) -> Result<String, JsValue> {
    let kek_bytes = Base64::decode_vec(kek_base64).map_err(|e| to_js_error(e.to_string()))?;
    let kek = KeyEncryptionKey::from_slice(&kek_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let key_bytes =
        Base64::decode_vec(key_to_wrap_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let wrapped = wrap_vault_key(&vault_key, &kek).map_err(|e| to_js_error(e.to_string()))?;

    serde_json::to_string(&wrapped).map_err(|e| to_js_error(e.to_string()))
}

/// Unwraps a wrapped key using KEK.
#[wasm_bindgen]
pub fn wasm_unwrap_key(kek_base64: &str, wrapped_json: &str) -> Result<String, JsValue> {
    let kek_bytes = Base64::decode_vec(kek_base64).map_err(|e| to_js_error(e.to_string()))?;
    let kek = KeyEncryptionKey::from_slice(&kek_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let wrapped: WrappedVaultKey =
        serde_json::from_str(wrapped_json).map_err(|e| to_js_error(e.to_string()))?;

    let unwrapped =
        unwrap_vault_key(&wrapped, &kek).map_err(|e| to_js_error(format!("unwrap failed: {e}")))?;

    Ok(Base64::encode_string(unwrapped.as_bytes()))
}

/// Encrypts note content into an envelope JSON string using a raw VaultKey base64.
#[wasm_bindgen]
pub fn wasm_encrypt_envelope(
    vault_key_base64: &str,
    object_id: &str,
    title: &str,
    body: &str,
    tags: Vec<String>,
) -> Result<String, JsValue> {
    let key_bytes = Base64::decode_vec(vault_key_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let mut note = PlaintextNote::new(title, body);
    note.tags = tags;
    note.canonicalize();

    let envelope = note
        .encrypt(&vault_key, object_id)
        .map_err(|e| to_js_error(e.to_string()))?;

    serde_json::to_string(&envelope).map_err(|e| to_js_error(e.to_string()))
}

/// Decrypts note envelope JSON string using raw VaultKey base64.
#[wasm_bindgen]
pub fn wasm_decrypt_envelope(
    vault_key_base64: &str,
    envelope_json: &str,
) -> Result<WasmPlaintextNote, JsValue> {
    let key_bytes = Base64::decode_vec(vault_key_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let envelope: EncryptedEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| to_js_error(e.to_string()))?;

    let note = PlaintextNote::decrypt(&envelope, &vault_key)
        .map_err(|e| to_js_error(format!("decrypt failed: {e}")))?;

    Ok(WasmPlaintextNote {
        id: envelope.object_id,
        title: note.title,
        body: note.body,
        tags: note.tags,
        attachments: note.attachments,
        created_at: note.created_at,
        updated_at: note.updated_at,
    })
}

/// Wraps a VaultKey with a formatted RecoveryKey phrase.
#[wasm_bindgen]
pub fn wasm_wrap_recovery(
    vault_key_base64: &str,
    recovery_phrase: &str,
) -> Result<String, JsValue> {
    let key_bytes = Base64::decode_vec(vault_key_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;
    let recovery_key =
        parse_recovery_key(recovery_phrase).map_err(|e| to_js_error(e.to_string()))?;

    let wrapped = wrap_vault_key_recovery(&vault_key, &recovery_key)
        .map_err(|e| to_js_error(e.to_string()))?;
    serde_json::to_string(&wrapped).map_err(|e| to_js_error(e.to_string()))
}

/// Unwraps a recovery-wrapped VaultKey using a formatted RecoveryKey phrase.
#[wasm_bindgen]
pub fn wasm_unwrap_recovery(
    recovery_phrase: &str,
    wrapped_recovery_key_json: &str,
) -> Result<String, JsValue> {
    let recovery_key =
        parse_recovery_key(recovery_phrase).map_err(|e| to_js_error(e.to_string()))?;
    let wrapped: WrappedVaultKey =
        serde_json::from_str(wrapped_recovery_key_json).map_err(|e| to_js_error(e.to_string()))?;

    let unwrapped = unwrap_vault_key_recovery(&wrapped, &recovery_key)
        .map_err(|e| to_js_error(format!("recovery unwrap failed: {e}")))?;
    Ok(Base64::encode_string(unwrapped.as_bytes()))
}

/// Encrypts raw bytes into an EncryptedEnvelope JSON string.
#[wasm_bindgen]
pub fn wasm_encrypt_raw(
    vault_key_base64: &str,
    object_id: &str,
    object_kind: u16,
    plaintext: &[u8],
) -> Result<String, JsValue> {
    let key_bytes = Base64::decode_vec(vault_key_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let envelope = encrypt_envelope(plaintext, &vault_key, object_id, object_kind)
        .map_err(|e| to_js_error(e.to_string()))?;
    serde_json::to_string(&envelope).map_err(|e| to_js_error(e.to_string()))
}

/// Decrypts raw bytes from an EncryptedEnvelope JSON string.
#[wasm_bindgen]
pub fn wasm_decrypt_raw(vault_key_base64: &str, envelope_json: &str) -> Result<Vec<u8>, JsValue> {
    let key_bytes = Base64::decode_vec(vault_key_base64).map_err(|e| to_js_error(e.to_string()))?;
    let vault_key = VaultKey::from_slice(&key_bytes).map_err(|e| to_js_error(e.to_string()))?;

    let envelope: EncryptedEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| to_js_error(e.to_string()))?;

    let plaintext = decrypt_envelope(&envelope, &vault_key)
        .map_err(|e| to_js_error(format!("decrypt failed: {e}")))?;
    Ok(plaintext)
}

/// Generates a fresh random 256-bit AttachmentKey and returns standard base64 (ZK-084).
#[wasm_bindgen]
pub fn wasm_generate_attachment_key() -> Result<String, JsValue> {
    let key = AttachmentKey::generate();
    Ok(Base64::encode_string(key.as_bytes()))
}

/// Computes BLAKE2b-512 content integrity hash (ZK-084).
#[wasm_bindgen]
pub fn wasm_compute_content_hash(bytes: &[u8]) -> String {
    zk_core::attachment::compute_content_hash(bytes)
}

/// Computes expected chunk count for attachment size and chunk size (ZK-084).
#[wasm_bindgen]
pub fn wasm_calculate_chunk_count(size: f64, chunk_size: u32) -> u32 {
    zk_core::attachment::calculate_chunk_count(size as u64, chunk_size as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_vault_init_unlock_and_note_crypto() {
        let params = KdfParams::new_test();
        let mut init_res = init_vault_impl("super-secret-passphrase", &params).expect("init vault");

        assert!(!init_res.wrapped_vault_key().is_empty());
        assert!(!init_res.kdf_params_json().is_empty());
        assert!(!init_res.wrapped_recovery_key().is_empty());
        assert_eq!(init_res.recovery_phrase().split('-').count(), 9);

        let mut session = init_res.take_session().expect("take session");
        assert!(session.is_unlocked());

        // Encrypt note through WASM session
        let obj_id = uuid::Uuid::new_v4().to_string();
        let env_json = session
            .encrypt_note_impl(
                &obj_id,
                "WASM Confidential Note",
                "WASM body content",
                vec!["wasm".to_string(), "crypto".to_string()],
                vec!["att-id-1".to_string()],
            )
            .expect("encrypt note");

        // Verify envelope is valid JSON
        assert!(env_json.contains(&obj_id));

        // Decrypt note through WASM session
        let decrypted = session.decrypt_note_impl(&env_json).expect("decrypt note");
        assert_eq!(decrypted.id(), obj_id);
        assert_eq!(decrypted.title(), "WASM Confidential Note");
        assert_eq!(decrypted.body(), "WASM body content");
        assert_eq!(decrypted.tags(), vec!["crypto", "wasm"]); // Canonicalized order
        assert_eq!(decrypted.attachments(), vec!["att-id-1"]);

        // Index and search in WASM memory
        session
            .index_note_impl(
                &obj_id,
                &decrypted.title(),
                &decrypted.body(),
                decrypted.tags(),
                &decrypted.updated_at(),
            )
            .expect("index note");

        let search_results = session.search_impl("confidential").expect("search");
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].note_id(), obj_id);
        assert_eq!(search_results[0].matched_title(), "WASM Confidential Note");

        // Lock session: zeroes memory and search index
        session.lock();
        assert!(!session.is_unlocked());
        assert!(session.decrypt_note_impl(&env_json).is_err());
        assert!(session.search_impl("confidential").is_err());

        // Unlock with passphrase
        let unlocked_session = unlock_vault_impl(
            "super-secret-passphrase",
            &init_res.wrapped_vault_key(),
            &init_res.kdf_params_json(),
        )
        .expect("unlock vault");
        assert!(unlocked_session.is_unlocked());

        let dec2 = unlocked_session
            .decrypt_note_impl(&env_json)
            .expect("decrypt after unlock");
        assert_eq!(dec2.title(), "WASM Confidential Note");

        // Unlock with recovery phrase
        let rec_session = unlock_with_recovery_key_impl(
            &init_res.recovery_phrase(),
            &init_res.wrapped_recovery_key(),
        )
        .expect("unlock with recovery phrase");
        assert!(rec_session.is_unlocked());
        let dec3 = rec_session
            .decrypt_note_impl(&env_json)
            .expect("decrypt after recovery unlock");
        assert_eq!(dec3.title(), "WASM Confidential Note");

        // Bad password fails closed
        let bad_unlock = unlock_vault_impl(
            "wrong-passphrase",
            &init_res.wrapped_vault_key(),
            &init_res.kdf_params_json(),
        );
        assert!(bad_unlock.is_err());
    }

    #[test]
    fn test_wasm_rewrap_passphrase() {
        let params = KdfParams::new_test();
        let mut init_res = init_vault_impl("old-passphrase", &params).expect("init vault");
        let mut session = init_res.take_session().expect("take");

        let obj_id = uuid::Uuid::new_v4().to_string();
        let env_json = session
            .encrypt_note_impl(&obj_id, "Title", "Body", vec![], vec![])
            .expect("encrypt");

        // Rewrap
        let new_params = KdfParams::new_test();
        let rewrap_res = session
            .rewrap_passphrase_impl("new-passphrase", &new_params)
            .expect("rewrap");

        // Old passphrase fails
        assert!(unlock_vault_impl(
            "old-passphrase",
            &rewrap_res.new_wrapped_vault_key(),
            &rewrap_res.new_kdf_params_json(),
        )
        .is_err());

        // New passphrase succeeds
        let new_session = unlock_vault_impl(
            "new-passphrase",
            &rewrap_res.new_wrapped_vault_key(),
            &rewrap_res.new_kdf_params_json(),
        )
        .expect("new unlock");

        // Decrypts original note without re-encryption!
        let dec = new_session.decrypt_note_impl(&env_json).expect("decrypt");
        assert_eq!(dec.title(), "Title");
    }

    #[test]
    fn test_wasm_standalone_helpers_round_trip() {
        let vault_key = VaultKey::generate();
        let vault_key_b64 = Base64::encode_string(vault_key.as_bytes());

        let obj_id = uuid::Uuid::new_v4().to_string();
        let env_json = wasm_encrypt_envelope(
            &vault_key_b64,
            &obj_id,
            "Standalone Title",
            "Standalone Body",
            vec!["tag1".to_string()],
        )
        .expect("encrypt");

        let decrypted = wasm_decrypt_envelope(&vault_key_b64, &env_json).expect("decrypt");
        assert_eq!(decrypted.title(), "Standalone Title");
        assert_eq!(decrypted.body(), "Standalone Body");

        // Test KEK and wrapping
        let params = KdfParams::new_test();
        let params_json = serde_json::to_string(&params).unwrap();
        let kek_b64 = wasm_derive_kek("passphrase", &params_json).expect("derive");

        let wrapped_json = wasm_wrap_key(&kek_b64, &vault_key_b64).expect("wrap");
        let unwrapped_b64 = wasm_unwrap_key(&kek_b64, &wrapped_json).expect("unwrap");
        assert_eq!(unwrapped_b64, vault_key_b64);
    }

    #[test]
    fn test_wasm_attachment_manifest_and_chunks() {
        let params = KdfParams::new_test();
        let mut init_res = init_vault_impl("vault-passphrase", &params).expect("init vault");
        let session = init_res.take_session().expect("take session");

        // 1. Generate attachment key
        let att_key_b64 = wasm_generate_attachment_key().expect("generate key");
        assert!(!att_key_b64.is_empty());

        let att_id = uuid::Uuid::new_v4().to_string();
        let sample_data = b"Hello from confidential Web attachment chunk!";
        let content_hash = wasm_compute_content_hash(sample_data);
        assert!(!content_hash.is_empty());

        // 2. Encrypt chunk
        let chunk_binary = session
            .encrypt_attachment_chunk(sample_data, &att_id, 0, 1, &att_key_b64)
            .expect("encrypt chunk");
        assert!(chunk_binary.starts_with(b"ZKCK"));

        // 3. Decrypt chunk
        let decrypted_bytes = session
            .decrypt_attachment_chunk(&chunk_binary, &att_key_b64)
            .expect("decrypt chunk");
        assert_eq!(decrypted_bytes, sample_data);

        // Tampered chunk fails closed
        let mut tampered_chunk = chunk_binary.clone();
        tampered_chunk[50] ^= 0x42;
        assert!(session
            .decrypt_attachment_chunk(&tampered_chunk, &att_key_b64)
            .is_err());

        // Wrong key fails closed
        let wrong_key_b64 = wasm_generate_attachment_key().expect("wrong key");
        assert!(session
            .decrypt_attachment_chunk(&chunk_binary, &wrong_key_b64)
            .is_err());

        // 4. Attachment manifest encryption and decryption
        let manifest = AttachmentManifest {
            attachment_id: att_id.clone(),
            name: "test_doc.pdf".to_string(),
            mime: "application/pdf".to_string(),
            size: sample_data.len() as u64,
            chunk_count: 1,
            chunk_size: 4096,
            content_hash: Some(content_hash.clone()),
        };
        let manifest_json = serde_json::to_string(&manifest).expect("serialize manifest");

        let manifest_envelope_json = session
            .encrypt_attachment_manifest(&manifest_json, &att_key_b64)
            .expect("encrypt manifest");
        assert!(manifest_envelope_json.contains(&att_id));

        let dec_manifest_result = session
            .decrypt_attachment_manifest(&manifest_envelope_json)
            .expect("decrypt manifest");
        assert_eq!(dec_manifest_result.manifest().attachment_id(), att_id);
        assert_eq!(dec_manifest_result.manifest().name(), "test_doc.pdf");
        assert_eq!(dec_manifest_result.manifest().mime(), "application/pdf");
        assert_eq!(
            dec_manifest_result.manifest().size(),
            sample_data.len() as f64
        );
        assert_eq!(dec_manifest_result.manifest().chunk_count(), 1);
        assert_eq!(
            dec_manifest_result.manifest().content_hash(),
            Some(content_hash)
        );
        assert_eq!(dec_manifest_result.attachment_key_base64(), att_key_b64);
    }
}
