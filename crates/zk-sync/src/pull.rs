//! Pull remote changes engine with paginated retrieval and locked/unlocked handling (ZK-043).
//!
//! In accordance with SEC-001, SEC-009, SEC-010, and MASTER_SPEC.md § 9:
//! - Remote changes are fetched via paginated requests using [`SyncServerAdapter`].
//! - Encrypted changes are DURABLY STORED FIRST into [`ObjectStore`] and the sync cursor
//!   advanced before any plaintext decryption is attempted.
//! - Locked Sync Behavior: If the vault is locked, remote ciphertext is stored durably
//!   and plaintext reconciliation is deferred until unlock.
//! - Unlocked Sync Behavior: If the vault is unlocked, incoming notes are decrypted and
//!   validated in memory, tombstones identified, and in-memory search index updated.
//! - Cryptographic errors fail closed: tampered or un-decryptable envelopes return an error.

use crate::adapter::SyncServerAdapter;
use crate::cursor::{CursorError, DurableSyncCursor};
use crate::error::SyncNetworkError;
use std::fmt;
use zk_core::error::CoreError;
use zk_core::note::PlaintextNote;
use zk_core::vault::VaultSession;
use zk_crypto::keys::VaultKey;
use zk_protocol::sync::ObjectChange;
use zk_storage::error::StorageError;
use zk_storage::models::ObjectFilter;
use zk_storage::traits::{ObjectStore, SyncStateStore};

/// Explicitly defined behavior when synchronizing while the vault is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedSyncBehavior {
    /// Recommended V1 behavior:
    /// Remote encrypted changes are stored durably into local object storage and the sync
    /// cursor is advanced. Decryption and plaintext search index updates are deferred until
    /// the user unlocks the vault.
    StoreCiphertextDeferDecryption,
}

/// Options for configuring a pull synchronization cycle.
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// Maximum number of changes requested per page from the server.
    pub page_limit: Option<u32>,
    /// Maximum number of pages to fetch in a single pull cycle (None for unlimited).
    pub max_pages: Option<usize>,
    /// Behavior when vault is locked.
    pub locked_behavior: LockedSyncBehavior,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            page_limit: Some(50),
            max_pages: None,
            locked_behavior: LockedSyncBehavior::StoreCiphertextDeferDecryption,
        }
    }
}

/// An individual decrypted note or tombstone produced by an unlocked pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPullItem {
    /// Identifier of the target object.
    pub object_id: String,
    /// Committed revision on the server.
    pub revision: u64,
    /// Server sequence allocated to this change.
    pub server_seq: u64,
    /// True if this item represents a deletion tombstone.
    pub is_deleted: bool,
    /// Decrypted plaintext note content if active, or `None` if deleted tombstone.
    pub note: Option<PlaintextNote>,
}

/// Detailed summary report of a completed pull synchronization cycle.
#[derive(Debug, Clone)]
pub struct PullReport {
    /// Total number of paginated HTTP responses received from the server.
    pub pages_fetched: usize,
    /// Total number of changes returned by the server across all pages.
    pub total_changes: usize,
    /// Total changes durably committed to local object storage.
    pub applied_changes: usize,
    /// Sync cursor before the pull started.
    pub initial_cursor: u64,
    /// Final sync cursor after all applied changes.
    pub final_cursor: u64,
    /// Whether the client had an unlocked session/key during the pull.
    pub was_unlocked: bool,
    /// Decrypted items produced if unlocked (empty if locked).
    pub decrypted_items: Vec<DecryptedPullItem>,
}

/// Errors that can occur during pull synchronization.
#[derive(Debug)]
pub enum PullError {
    /// Server or transport network communication failure.
    Network(SyncNetworkError),
    /// Local sync cursor failure.
    Cursor(CursorError),
    /// Local object storage persistence failure.
    Storage(StorageError),
    /// Decryption or validation failure (SEC-010 fail closed).
    Core(CoreError),
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(err) => write!(f, "pull network error: {err}"),
            Self::Cursor(err) => write!(f, "pull cursor error: {err}"),
            Self::Storage(err) => write!(f, "pull storage error: {err}"),
            Self::Core(err) => write!(f, "pull decryption error: {err}"),
        }
    }
}

impl std::error::Error for PullError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(err) => Some(err),
            Self::Cursor(err) => Some(err),
            Self::Storage(err) => Some(err),
            Self::Core(err) => Some(err),
        }
    }
}

impl From<SyncNetworkError> for PullError {
    fn from(err: SyncNetworkError) -> Self {
        Self::Network(err)
    }
}

impl From<CursorError> for PullError {
    fn from(err: CursorError) -> Self {
        Self::Cursor(err)
    }
}

impl From<StorageError> for PullError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<CoreError> for PullError {
    fn from(err: CoreError) -> Self {
        Self::Core(err)
    }
}

/// Pulls remote changes from the server using paginated requests, durably persists encrypted
/// changes locally, advances the sync cursor, and decrypts content if unlocked.
///
/// Steps:
/// 1. Reads the current durable cursor from `cursor`.
/// 2. Loops over paginated server responses (`GET /v1/sync/changes?after=...`).
/// 3. DURABLY STORES ENCRYPTED CHANGES FIRST into `object_store` and advances `cursor`.
/// 4. If `vault_key` is provided (unlocked), decrypts note envelopes and returns decrypted items.
/// 5. If `vault_key` is `None` (locked), defers decryption until unlock.
pub async fn pull_remote_changes<A, O, S>(
    adapter: &A,
    object_store: &O,
    cursor: &DurableSyncCursor<S>,
    vault_key: Option<&VaultKey>,
    options: PullOptions,
) -> Result<PullReport, PullError>
where
    A: SyncServerAdapter,
    O: ObjectStore,
    S: SyncStateStore,
{
    let initial_cursor = cursor.current_cursor()?;
    let mut current_seq = initial_cursor;
    let mut pages_fetched = 0;
    let mut all_applied_changes: Vec<ObjectChange> = Vec::new();

    loop {
        if let Some(max_p) = options.max_pages {
            if pages_fetched >= max_p {
                break;
            }
        }

        let resp = adapter
            .pull_changes(current_seq, options.page_limit)
            .await?;
        pages_fetched += 1;

        if resp.changes.is_empty() {
            break;
        }

        // STEP 1: Store encrypted changes first and advance cursor durably
        for change in resp.changes {
            if change.server_seq <= current_seq && current_seq > 0 {
                // Ignore duplicate changes from overlapping pages
                continue;
            }

            cursor.apply_change(object_store, &change)?;
            current_seq = change.server_seq;
            all_applied_changes.push(change);
        }

        if !resp.has_more {
            break;
        }
    }

    // Record sync success timestamp
    let _ = cursor.record_sync_success();

    // STEP 2: Decrypt if unlocked; defer if locked
    let mut decrypted_items = Vec::new();
    let was_unlocked = vault_key.is_some();

    if let Some(key) = vault_key {
        for change in &all_applied_changes {
            if change.is_deleted {
                decrypted_items.push(DecryptedPullItem {
                    object_id: change.object_id.clone(),
                    revision: change.revision,
                    server_seq: change.server_seq,
                    is_deleted: true,
                    note: None,
                });
            } else {
                let note = PlaintextNote::decrypt(&change.envelope, key)?;
                decrypted_items.push(DecryptedPullItem {
                    object_id: change.object_id.clone(),
                    revision: change.revision,
                    server_seq: change.server_seq,
                    is_deleted: false,
                    note: Some(note),
                });
            }
        }
    }

    Ok(PullReport {
        pages_fetched,
        total_changes: all_applied_changes.len(),
        applied_changes: all_applied_changes.len(),
        initial_cursor,
        final_cursor: current_seq,
        was_unlocked,
        decrypted_items,
    })
}

/// Pulls remote changes using an active [`VaultSession`], updating the session's in-memory
/// search index if unlocked.
pub async fn pull_with_session<A, O, S>(
    adapter: &A,
    object_store: &O,
    cursor: &DurableSyncCursor<S>,
    session: &mut VaultSession,
    options: PullOptions,
) -> Result<PullReport, PullError>
where
    A: SyncServerAdapter,
    O: ObjectStore,
    S: SyncStateStore,
{
    let vault_key = session.active_key().ok().cloned();
    let report =
        pull_remote_changes(adapter, object_store, cursor, vault_key.as_ref(), options).await?;

    // If unlocked, update in-memory search index with decrypted notes and tombstone removals
    if session.is_unlocked() {
        if let Ok(idx) = session.search_index_mut() {
            for item in &report.decrypted_items {
                if item.is_deleted {
                    idx.remove(&item.object_id);
                } else if let Some(ref note) = item.note {
                    idx.insert(&item.object_id, note);
                }
            }
        }
    }

    Ok(report)
}

/// Reconciles and decrypts stored local objects after unlocking the vault.
///
/// For clients that synchronized while locked:
/// Once the user unlocks the vault, this function scans local stored encrypted objects,
/// decrypts active notes, updates the session's in-memory search index, and returns decrypted items.
pub fn decrypt_stored_objects_on_unlock<O: ObjectStore>(
    object_store: &O,
    session: &mut VaultSession,
) -> Result<Vec<DecryptedPullItem>, PullError> {
    let key = session.active_key()?.clone();
    let objects = object_store.list_objects(&ObjectFilter::all())?;
    let mut decrypted_items = Vec::with_capacity(objects.len());

    for obj in objects {
        if obj.is_deleted {
            decrypted_items.push(DecryptedPullItem {
                object_id: obj.object_id.clone(),
                revision: obj.revision,
                server_seq: obj.server_seq,
                is_deleted: true,
                note: None,
            });
            if let Ok(idx) = session.search_index_mut() {
                idx.remove(&obj.object_id);
            }
        } else {
            let note = PlaintextNote::decrypt(&obj.envelope, &key)?;
            if let Ok(idx) = session.search_index_mut() {
                idx.insert(&obj.object_id, &note);
            }
            decrypted_items.push(DecryptedPullItem {
                object_id: obj.object_id,
                revision: obj.revision,
                server_seq: obj.server_seq,
                is_deleted: false,
                note: Some(note),
            });
        }
    }

    Ok(decrypted_items)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapter::MockSyncAdapter;
    use zk_core::note::PlaintextNote;
    use zk_crypto::keys::VaultKey;
    use zk_protocol::constants::OBJECT_KIND_NOTE;
    use zk_protocol::sync::PushRequest;
    use zk_storage::memory::MemoryStorage;

    fn sample_encrypted_note(
        vault_key: &VaultKey,
        obj_id: &str,
        title: &str,
    ) -> zk_protocol::envelope::EncryptedEnvelope {
        let note = PlaintextNote::new(title, "Note body content here");
        note.encrypt(vault_key, obj_id).expect("encrypt note")
    }

    #[tokio::test]
    async fn test_paginated_pull_stores_encrypted_changes_first_and_advances_cursor() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let cursor = DurableSyncCursor::new(storage.clone());
        let vault_key = VaultKey::generate();

        // Populate server with 5 notes
        for i in 1..=5 {
            let id = format!("note-{i}");
            let env = sample_encrypted_note(&vault_key, &id, &format!("Title {i}"));
            let req = PushRequest {
                mutation_id: format!("mut-{i}"),
                object_id: id,
                expected_revision: 0,
                object_kind: OBJECT_KIND_NOTE,
                envelope: env,
                is_deleted: false,
            };
            adapter.push_mutation(&req).await.unwrap();
        }

        // Pull with page_limit = 2 (requires 3 pages: [1,2], [3,4], [5])
        let options = PullOptions {
            page_limit: Some(2),
            max_pages: None,
            locked_behavior: LockedSyncBehavior::StoreCiphertextDeferDecryption,
        };

        let report = pull_remote_changes(&adapter, &storage, &cursor, Some(&vault_key), options)
            .await
            .expect("pull succeeded");

        assert_eq!(report.pages_fetched, 3);
        assert_eq!(report.total_changes, 5);
        assert_eq!(report.applied_changes, 5);
        assert_eq!(report.initial_cursor, 0);
        assert_eq!(report.final_cursor, 5);
        assert!(report.was_unlocked);
        assert_eq!(report.decrypted_items.len(), 5);

        // Verify stored in ObjectStore
        for i in 1..=5 {
            let id = format!("note-{i}");
            let stored = storage.get_object(&id).unwrap().unwrap();
            assert_eq!(stored.server_seq, i as u64);
        }

        // Verify persistent cursor
        assert_eq!(cursor.current_cursor().unwrap(), 5);
    }

    #[tokio::test]
    async fn test_locked_sync_stores_ciphertext_and_defers_decryption_until_unlock() {
        let adapter = MockSyncAdapter::new();
        let storage = MemoryStorage::new();
        let cursor = DurableSyncCursor::new(storage.clone());
        let vault_key = VaultKey::generate();

        // Populate server with notes
        for i in 1..=3 {
            let id = format!("locked-note-{i}");
            let env = sample_encrypted_note(&vault_key, &id, &format!("Locked Title {i}"));
            let req = PushRequest {
                mutation_id: format!("mut-lock-{i}"),
                object_id: id,
                expected_revision: 0,
                object_kind: OBJECT_KIND_NOTE,
                envelope: env,
                is_deleted: false,
            };
            adapter.push_mutation(&req).await.unwrap();
        }

        // 1. Pull while LOCKED (vault_key = None)
        let report = pull_remote_changes(&adapter, &storage, &cursor, None, PullOptions::default())
            .await
            .expect("locked pull succeeds");

        assert!(!report.was_unlocked);
        assert_eq!(report.applied_changes, 3);
        assert_eq!(report.final_cursor, 3);
        // Decrypted items empty because vault is locked!
        assert!(report.decrypted_items.is_empty());

        // Encrypted objects are durably present in storage!
        for i in 1..=3 {
            let id = format!("locked-note-{i}");
            let stored = storage
                .get_object(&id)
                .unwrap()
                .expect("stored object must exist");
            assert_eq!(stored.server_seq, i as u64);
        }

        // 2. User unlocks vault later: decrypt stored objects and build search index
        let mut session = VaultSession::from_key(vault_key);
        let decrypted =
            decrypt_stored_objects_on_unlock(&storage, &mut session).expect("decrypt on unlock");

        assert_eq!(decrypted.len(), 3);
        assert!(decrypted.iter().all(|d| d.note.is_some()));

        // In-memory search index now finds notes
        let results = session.search_index().unwrap().search("Locked");
        assert_eq!(results.len(), 3);
    }
}
