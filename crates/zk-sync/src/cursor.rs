//! Durable synchronization cursor management (ZK-042).
//!
//! In accordance with Scenario E and SEC-006:
//! - The sync cursor represents the highest contiguous server sequence number durably applied locally.
//! - The cursor MUST advance ONLY AFTER the corresponding remote change has been durably
//!   persisted to local object storage.
//! - If a crash, power outage, or storage failure occurs mid-stream, the cursor remains at the
//!   last successfully committed sequence, ensuring subsequent pulls re-fetch and re-apply
//!   any uncommitted changes without skipping data.
//! - Cursors are strictly monotonic: regressions are rejected unless explicitly reset.

use std::fmt;
use uuid::Uuid;
use zk_core::time::now_utc_rfc3339;
use zk_protocol::sync::ObjectChange;
use zk_storage::error::StorageError;
use zk_storage::models::{StoredEncryptedObject, SyncState};
use zk_storage::traits::{ObjectStore, SyncStateStore};

/// Errors that can occur during sync cursor tracking and advancement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorError {
    /// Underlying storage backend error.
    Storage(StorageError),
    /// Attempted cursor regression (cursor must advance monotonically).
    Regression {
        /// Current persistent cursor.
        current: u64,
        /// Attempted lower cursor value.
        attempted: u64,
    },
    /// Non-monotonic sequence encountered in incoming stream.
    NonMonotonicSequence {
        /// Current sequence.
        current: u64,
        /// Incoming out-of-order sequence.
        incoming: u64,
    },
    /// Invalid cursor parameter or invariant violation.
    InvalidInput(String),
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "sync cursor storage error: {err}"),
            Self::Regression { current, attempted } => {
                write!(
                    f,
                    "cursor regression rejected: current is {current}, attempted {attempted}"
                )
            }
            Self::NonMonotonicSequence { current, incoming } => {
                write!(
                    f,
                    "non-monotonic sequence in changes: expected > {current}, got {incoming}"
                )
            }
            Self::InvalidInput(msg) => write!(f, "invalid cursor operation: {msg}"),
        }
    }
}

impl std::error::Error for CursorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

impl From<StorageError> for CursorError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

/// Durable synchronization cursor coordinator.
#[derive(Debug, Clone)]
pub struct DurableSyncCursor<S> {
    storage: S,
}

impl<S> DurableSyncCursor<S>
where
    S: SyncStateStore,
{
    /// Creates a new [`DurableSyncCursor`] wrapping the sync state store.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying sync state storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Retrieves the current durable sync cursor from persistent storage.
    pub fn current_cursor(&self) -> Result<u64, CursorError> {
        let state = self.storage.get_sync_state()?;
        Ok(state.sync_cursor)
    }

    /// Retrieves the complete sync state (cursor, last_sync_at, device_id).
    pub fn get_sync_state(&self) -> Result<SyncState, CursorError> {
        let state = self.storage.get_sync_state()?;
        Ok(state)
    }

    /// Advances the durable cursor to a new server sequence.
    ///
    /// Validates monotonicity: `new_cursor` must be greater than or equal to current cursor.
    pub fn advance_to(&self, new_cursor: u64) -> Result<u64, CursorError> {
        let current = self.current_cursor()?;
        if new_cursor < current {
            return Err(CursorError::Regression {
                current,
                attempted: new_cursor,
            });
        }
        if new_cursor == current {
            return Ok(current);
        }

        self.storage.set_sync_cursor(new_cursor)?;
        Ok(new_cursor)
    }

    /// Applies a single remote change to local object storage and advances the cursor ONLY AFTER
    /// the local write has durably succeeded.
    ///
    /// In accordance with Scenario E:
    /// 1. Durably persists the remote change to `object_store`.
    /// 2. If step 1 fails, the cursor is NOT advanced and remains at the previous sequence.
    /// 3. If step 1 succeeds, updates the durable cursor to `change.server_seq`.
    pub fn apply_change<O: ObjectStore>(
        &self,
        object_store: &O,
        change: &ObjectChange,
    ) -> Result<u64, CursorError> {
        let current = self.current_cursor()?;
        if change.server_seq <= current {
            // Already processed or duplicate sequence; do not regress
            return Ok(current);
        }

        let stored = StoredEncryptedObject {
            object_id: change.object_id.clone(),
            object_kind: change.object_kind,
            revision: change.revision,
            server_seq: change.server_seq,
            is_deleted: change.is_deleted,
            envelope: change.envelope.clone(),
            updated_at: now_utc_rfc3339(),
        };

        // Step 1: Durably write remote object to local ObjectStore.
        // If this fails, the error propagates and set_sync_cursor is NEVER called.
        object_store.put_object(&stored)?;

        // Step 2: Advance cursor only after durable local storage write succeeded.
        self.storage.set_sync_cursor(change.server_seq)?;

        Ok(change.server_seq)
    }

    /// Applies a batch of remote changes sequentially.
    ///
    /// For each change, durably writes to `object_store` and immediately updates the cursor.
    /// If an error occurs on change `i`:
    /// - Changes prior to `i` remain committed with the cursor at change `i - 1`.
    /// - Change `i` and subsequent changes are not committed to the cursor.
    /// - On restart, pulling after `cursor` will re-fetch change `i`, preventing any data loss.
    pub fn apply_changes_sequential<O: ObjectStore>(
        &self,
        object_store: &O,
        changes: &[ObjectChange],
    ) -> Result<u64, CursorError> {
        let mut last_seq = self.current_cursor()?;

        for change in changes {
            if change.server_seq <= last_seq && last_seq > 0 {
                // If the stream contains non-monotonic sequence, check if duplicate or out of order
                if change.server_seq < last_seq {
                    return Err(CursorError::NonMonotonicSequence {
                        current: last_seq,
                        incoming: change.server_seq,
                    });
                }
                continue;
            }

            last_seq = self.apply_change(object_store, change)?;
        }

        Ok(last_seq)
    }

    /// Records the successful completion of a sync cycle with a UTC timestamp.
    pub fn record_sync_success(&self) -> Result<(), CursorError> {
        let mut state = self.storage.get_sync_state()?;
        state.last_sync_at = Some(now_utc_rfc3339());
        self.storage.set_sync_state(&state)?;
        Ok(())
    }

    /// Retrieves or lazily initializes a unique local device identifier.
    pub fn get_or_create_device_id(&self) -> Result<String, CursorError> {
        let mut state = self.storage.get_sync_state()?;
        if let Some(ref dev_id) = state.device_id {
            if !dev_id.is_empty() {
                return Ok(dev_id.clone());
            }
        }

        let new_id = Uuid::new_v4().to_string();
        state.device_id = Some(new_id.clone());
        self.storage.set_sync_state(&state)?;
        Ok(new_id)
    }

    /// Explicitly resets the sync cursor to 0 for full re-sync scenarios.
    pub fn reset_cursor_for_resync(&self) -> Result<(), CursorError> {
        self.storage.set_sync_cursor(0)?;
        Ok(())
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
    use zk_storage::memory::MemoryStorage;

    fn sample_change(seq: u64, id: &str) -> ObjectChange {
        ObjectChange {
            server_seq: seq,
            object_id: id.to_string(),
            revision: 1,
            object_kind: OBJECT_KIND_NOTE,
            envelope: EncryptedEnvelope {
                envelope_version: ENVELOPE_VERSION_V1,
                object_id: id.to_string(),
                object_kind: OBJECT_KIND_NOTE,
                wrapped_key: EncryptedKeyContainer {
                    nonce: "nonce".to_string(),
                    ciphertext: "cipher".to_string(),
                },
                payload: EncryptedPayloadContainer {
                    nonce: "nonce".to_string(),
                    ciphertext: "cipher".to_string(),
                },
            },
            is_deleted: false,
        }
    }

    #[test]
    fn test_initial_cursor_and_monotonic_advance() {
        let storage = MemoryStorage::new();
        let cursor = DurableSyncCursor::new(storage);

        assert_eq!(cursor.current_cursor().unwrap(), 0);

        cursor.advance_to(10).unwrap();
        assert_eq!(cursor.current_cursor().unwrap(), 10);

        // Same cursor is no-op
        cursor.advance_to(10).unwrap();
        assert_eq!(cursor.current_cursor().unwrap(), 10);

        // Regression is rejected
        let err = cursor.advance_to(5).unwrap_err();
        assert!(matches!(
            err,
            CursorError::Regression {
                current: 10,
                attempted: 5
            }
        ));
        assert_eq!(cursor.current_cursor().unwrap(), 10);
    }

    #[test]
    fn test_device_id_generation_and_sync_timestamp() {
        let storage = MemoryStorage::new();
        let cursor = DurableSyncCursor::new(storage);

        let dev_id1 = cursor.get_or_create_device_id().unwrap();
        assert!(!dev_id1.is_empty());
        let dev_id2 = cursor.get_or_create_device_id().unwrap();
        assert_eq!(dev_id1, dev_id2);

        cursor.record_sync_success().unwrap();
        let state = cursor.get_sync_state().unwrap();
        assert!(state.last_sync_at.is_some());
    }

    #[test]
    fn test_apply_change_advances_cursor_after_durable_write() {
        let storage = MemoryStorage::new();
        let cursor = DurableSyncCursor::new(storage.clone());

        let change1 = sample_change(1, "note-1");
        let seq = cursor.apply_change(&storage, &change1).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(cursor.current_cursor().unwrap(), 1);

        // Object exists in object store
        let obj = storage.get_object("note-1").unwrap().unwrap();
        assert_eq!(obj.server_seq, 1);
        assert_eq!(obj.revision, 1);
    }
}
