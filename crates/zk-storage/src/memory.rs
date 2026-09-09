//! In-memory thread-safe storage adapter serving as a test double and ephemeral storage.

use crate::error::StorageError;
use crate::models::{
    MutationStatus, ObjectFilter, PendingMutation, StoredEncryptedObject, SyncState,
};
use crate::traits::{BaseVersionStore, MutationStore, ObjectStore, SyncStateStore};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zk_protocol::envelope::EncryptedEnvelope;

/// In-memory thread-safe implementation of [`ObjectStore`], [`MutationStore`],
/// [`BaseVersionStore`], and [`SyncStateStore`].
///
/// Designed as a test double and ephemeral storage adapter for tests and local experiments.
#[derive(Debug, Default, Clone)]
pub struct MemoryStorage {
    objects: Arc<RwLock<HashMap<String, StoredEncryptedObject>>>,
    mutations: Arc<RwLock<Vec<PendingMutation>>>,
    base_versions: Arc<RwLock<HashMap<(String, u64), EncryptedEnvelope>>>,
    sync_state: Arc<RwLock<SyncState>>,
}

impl MemoryStorage {
    /// Creates a new empty in-memory storage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ObjectStore for MemoryStorage {
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError> {
        let guard = self
            .objects
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.get(object_id).cloned())
    }

    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError> {
        let mut guard = self
            .objects
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        guard.insert(object.object_id.clone(), object.clone());
        Ok(())
    }

    fn list_objects(
        &self,
        filter: &ObjectFilter,
    ) -> Result<Vec<StoredEncryptedObject>, StorageError> {
        let guard = self
            .objects
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;

        let mut results = Vec::new();
        for obj in guard.values() {
            if !filter.include_deleted && obj.is_deleted {
                continue;
            }
            if let Some(kind) = filter.kind {
                if obj.object_kind != kind {
                    continue;
                }
            }
            results.push(obj.clone());
        }

        // Deterministic sort by object_id
        results.sort_by(|a, b| a.object_id.cmp(&b.object_id));
        Ok(results)
    }

    fn mark_deleted(
        &self,
        object_id: &str,
        revision: u64,
        envelope: EncryptedEnvelope,
        updated_at: String,
    ) -> Result<(), StorageError> {
        let mut guard = self
            .objects
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;

        if let Some(existing) = guard.get_mut(object_id) {
            existing.revision = revision;
            existing.is_deleted = true;
            existing.envelope = envelope;
            existing.updated_at = updated_at;
            Ok(())
        } else {
            Err(StorageError::NotFound {
                entity: "object",
                id: object_id.to_string(),
            })
        }
    }

    fn purge_object(&self, object_id: &str) -> Result<bool, StorageError> {
        let mut guard = self
            .objects
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.remove(object_id).is_some())
    }
}

impl MutationStore for MemoryStorage {
    fn enqueue_mutation(&self, mutation: &PendingMutation) -> Result<(), StorageError> {
        let mut guard = self
            .mutations
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;

        // If duplicate mutation_id already exists, return AlreadyExists error
        if guard.iter().any(|m| m.mutation_id == mutation.mutation_id) {
            return Err(StorageError::AlreadyExists {
                entity: "pending_mutation",
                id: mutation.mutation_id.clone(),
            });
        }

        guard.push(mutation.clone());
        Ok(())
    }

    fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, StorageError> {
        let guard = self
            .mutations
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.iter().find(|m| m.mutation_id == mutation_id).cloned())
    }

    fn list_pending_mutations(&self) -> Result<Vec<PendingMutation>, StorageError> {
        let guard = self
            .mutations
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.clone())
    }

    fn list_mutations_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<PendingMutation>, StorageError> {
        let guard = self
            .mutations
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard
            .iter()
            .filter(|m| m.object_id == object_id)
            .cloned()
            .collect())
    }

    fn remove_mutation(&self, mutation_id: &str) -> Result<bool, StorageError> {
        let mut guard = self
            .mutations
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        if let Some(pos) = guard.iter().position(|m| m.mutation_id == mutation_id) {
            guard.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_mutation_status(
        &self,
        mutation_id: &str,
        status: MutationStatus,
        retry_count: u32,
    ) -> Result<(), StorageError> {
        let mut guard = self
            .mutations
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        if let Some(mutation) = guard.iter_mut().find(|m| m.mutation_id == mutation_id) {
            mutation.status = status;
            mutation.retry_count = retry_count;
            Ok(())
        } else {
            Err(StorageError::NotFound {
                entity: "pending_mutation",
                id: mutation_id.to_string(),
            })
        }
    }

    fn pending_mutation_count(&self) -> Result<usize, StorageError> {
        let guard = self
            .mutations
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.len())
    }
}

impl BaseVersionStore for MemoryStorage {
    fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, StorageError> {
        let guard = self
            .base_versions
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.get(&(object_id.to_string(), revision)).cloned())
    }

    fn put_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StorageError> {
        let mut guard = self
            .base_versions
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        guard.insert((object_id.to_string(), revision), envelope.clone());
        Ok(())
    }

    fn prune_base_versions(
        &self,
        object_id: &str,
        older_than_revision: u64,
    ) -> Result<usize, StorageError> {
        let mut guard = self
            .base_versions
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        let initial_len = guard.len();
        guard.retain(|(id, rev), _| !(id == object_id && *rev < older_than_revision));
        Ok(initial_len - guard.len())
    }

    fn clear_base_versions(&self, object_id: &str) -> Result<usize, StorageError> {
        let mut guard = self
            .base_versions
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        let initial_len = guard.len();
        guard.retain(|(id, _), _| id != object_id);
        Ok(initial_len - guard.len())
    }
}

impl SyncStateStore for MemoryStorage {
    fn get_sync_state(&self) -> Result<SyncState, StorageError> {
        let guard = self
            .sync_state
            .read()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        Ok(guard.clone())
    }

    fn set_sync_cursor(&self, cursor: u64) -> Result<(), StorageError> {
        let mut guard = self
            .sync_state
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        guard.sync_cursor = cursor;
        Ok(())
    }

    fn set_sync_state(&self, state: &SyncState) -> Result<(), StorageError> {
        let mut guard = self
            .sync_state
            .write()
            .map_err(|e| StorageError::Backend(format!("lock error: {e}")))?;
        *guard = state.clone();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::MutationType;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE, OBJECT_KIND_NOTEBOOK};
    use zk_protocol::envelope::{EncryptedKeyContainer, EncryptedPayloadContainer};

    fn dummy_envelope(object_id: &str, kind: u16) -> EncryptedEnvelope {
        EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: object_id.to_string(),
            object_kind: kind,
            wrapped_key: EncryptedKeyContainer {
                nonce: "AAAA".to_string(),
                ciphertext: "BBBB".to_string(),
            },
            payload: EncryptedPayloadContainer {
                nonce: "CCCC".to_string(),
                ciphertext: "DDDD".to_string(),
            },
        }
    }

    #[test]
    fn test_memory_object_store_crud() {
        let store = MemoryStorage::new();
        let id = "obj-1";
        let env = dummy_envelope(id, OBJECT_KIND_NOTE);

        let stored = StoredEncryptedObject {
            object_id: id.to_string(),
            object_kind: OBJECT_KIND_NOTE,
            revision: 1,
            server_seq: 10,
            is_deleted: false,
            envelope: env.clone(),
            updated_at: "2026-09-09T05:00:00Z".to_string(),
        };

        // Put and Get
        store.put_object(&stored).expect("put");
        let fetched = store.get_object(id).expect("get").expect("exists");
        assert_eq!(stored, fetched);

        // List active
        let active = store
            .list_objects(&ObjectFilter::active_only())
            .expect("list active");
        assert_eq!(active.len(), 1);

        // Mark deleted
        store
            .mark_deleted(id, 2, env, "2026-09-09T05:30:00Z".to_string())
            .expect("mark deleted");

        let active_after = store
            .list_objects(&ObjectFilter::active_only())
            .expect("list active");
        assert_eq!(active_after.len(), 0);

        let all_after = store.list_objects(&ObjectFilter::all()).expect("list all");
        assert_eq!(all_after.len(), 1);
        assert!(all_after[0].is_deleted);
        assert_eq!(all_after[0].revision, 2);

        // Purge
        assert!(store.purge_object(id).expect("purge"));
        assert_eq!(store.get_object(id).expect("get"), None);
    }

    #[test]
    fn test_memory_mutation_store_lifecycle() {
        let store = MemoryStorage::new();
        let mut_id = "mut-1";
        let obj_id = "obj-1";
        let env = dummy_envelope(obj_id, OBJECT_KIND_NOTE);

        let mutation = PendingMutation {
            mutation_id: mut_id.to_string(),
            object_id: obj_id.to_string(),
            expected_revision: 0,
            object_kind: OBJECT_KIND_NOTE,
            mutation_type: MutationType::Upsert,
            envelope: env,
            created_at: "2026-09-09T05:00:00Z".to_string(),
            retry_count: 0,
            status: MutationStatus::Pending,
        };

        // Enqueue
        store.enqueue_mutation(&mutation).expect("enqueue");
        assert_eq!(store.pending_mutation_count().expect("count"), 1);

        // Duplicate rejection
        let err = store.enqueue_mutation(&mutation).unwrap_err();
        assert_eq!(
            err,
            StorageError::AlreadyExists {
                entity: "pending_mutation",
                id: mut_id.to_string(),
            }
        );

        // Get
        let fetched = store.get_mutation(mut_id).expect("get").expect("found");
        assert_eq!(mutation, fetched);

        // Update status
        store
            .update_mutation_status(mut_id, MutationStatus::InFlight, 1)
            .expect("update status");
        let updated = store.get_mutation(mut_id).expect("get").expect("found");
        assert_eq!(updated.status, MutationStatus::InFlight);
        assert_eq!(updated.retry_count, 1);

        // List for object
        let list = store
            .list_mutations_for_object(obj_id)
            .expect("list for obj");
        assert_eq!(list.len(), 1);

        // Remove
        assert!(store.remove_mutation(mut_id).expect("remove"));
        assert_eq!(store.pending_mutation_count().expect("count"), 0);
    }

    #[test]
    fn test_memory_base_version_store() {
        let store = MemoryStorage::new();
        let obj_id = "obj-1";
        let env1 = dummy_envelope(obj_id, OBJECT_KIND_NOTE);
        let mut env2 = env1.clone();
        env2.wrapped_key.nonce = "REV2".to_string();

        store.put_base_version(obj_id, 1, &env1).expect("put rev 1");
        store.put_base_version(obj_id, 2, &env2).expect("put rev 2");

        let fetched1 = store
            .get_base_version(obj_id, 1)
            .expect("get rev 1")
            .expect("found");
        assert_eq!(env1, fetched1);

        // Prune older than revision 2
        let pruned = store.prune_base_versions(obj_id, 2).expect("prune");
        assert_eq!(pruned, 1);
        assert_eq!(store.get_base_version(obj_id, 1).expect("get rev 1"), None);
        assert!(store
            .get_base_version(obj_id, 2)
            .expect("get rev 2")
            .is_some());

        // Clear remaining
        let cleared = store.clear_base_versions(obj_id).expect("clear");
        assert_eq!(cleared, 1);
        assert_eq!(store.get_base_version(obj_id, 2).expect("get rev 2"), None);
    }

    #[test]
    fn test_memory_sync_state_store() {
        let store = MemoryStorage::new();

        // Default initial cursor is 0
        let state = store.get_sync_state().expect("get initial state");
        assert_eq!(state.sync_cursor, 0);
        assert_eq!(state.last_sync_at, None);

        // Set cursor
        store.set_sync_cursor(42).expect("set cursor");
        assert_eq!(store.get_sync_state().expect("get state").sync_cursor, 42);

        // Set full state
        let new_state = SyncState {
            sync_cursor: 100,
            last_sync_at: Some("2026-09-09T06:00:00Z".to_string()),
            device_id: Some("device-abc-123".to_string()),
        };
        store.set_sync_state(&new_state).expect("set state");
        assert_eq!(
            store.get_sync_state().expect("get updated state"),
            new_state
        );
    }

    #[test]
    fn test_filter_by_kind() {
        let store = MemoryStorage::new();
        let note_env = dummy_envelope("note-1", OBJECT_KIND_NOTE);
        let nb_env = dummy_envelope("nb-1", OBJECT_KIND_NOTEBOOK);

        store
            .put_object(&StoredEncryptedObject {
                object_id: "note-1".to_string(),
                object_kind: OBJECT_KIND_NOTE,
                revision: 1,
                server_seq: 1,
                is_deleted: false,
                envelope: note_env,
                updated_at: "2026-09-09T05:00:00Z".to_string(),
            })
            .expect("put note");

        store
            .put_object(&StoredEncryptedObject {
                object_id: "nb-1".to_string(),
                object_kind: OBJECT_KIND_NOTEBOOK,
                revision: 1,
                server_seq: 2,
                is_deleted: false,
                envelope: nb_env,
                updated_at: "2026-09-09T05:00:00Z".to_string(),
            })
            .expect("put notebook");

        let notes = store
            .list_objects(&ObjectFilter::for_kind(OBJECT_KIND_NOTE))
            .expect("list notes");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].object_id, "note-1");

        let notebooks = store
            .list_objects(&ObjectFilter::for_kind(OBJECT_KIND_NOTEBOOK))
            .expect("list notebooks");
        assert_eq!(notebooks.len(), 1);
        assert_eq!(notebooks[0].object_id, "nb-1");
    }
}
