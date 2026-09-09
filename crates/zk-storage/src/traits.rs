//! Storage traits defining abstract interfaces for persistence.

use crate::error::StorageError;
use crate::models::{ObjectFilter, PendingMutation, StoredEncryptedObject, SyncState};
use zk_protocol::envelope::EncryptedEnvelope;

/// Abstract store for persisting and querying encrypted objects.
pub trait ObjectStore: Send + Sync {
    /// Retrieves a stored encrypted object by its unique ID.
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError>;

    /// Inserts or updates a stored encrypted object.
    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError>;

    /// Lists stored encrypted objects matching the given query filter.
    fn list_objects(
        &self,
        filter: &ObjectFilter,
    ) -> Result<Vec<StoredEncryptedObject>, StorageError>;

    /// Marks an object as deleted by recording a tombstone envelope and revision.
    fn mark_deleted(
        &self,
        object_id: &str,
        revision: u64,
        envelope: EncryptedEnvelope,
        updated_at: String,
    ) -> Result<(), StorageError>;

    /// Permanently deletes an object from local storage (for cache purging or hard delete).
    fn purge_object(&self, object_id: &str) -> Result<bool, StorageError>;
}

/// Abstract queue and store for locally queued mutations awaiting synchronization.
pub trait MutationStore: Send + Sync {
    /// Enqueues a new pending mutation.
    fn enqueue_mutation(&self, mutation: &PendingMutation) -> Result<(), StorageError>;

    /// Retrieves a pending mutation by its unique mutation ID.
    fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, StorageError>;

    /// Lists all pending mutations in the order they should be pushed (typically by creation time).
    fn list_pending_mutations(&self) -> Result<Vec<PendingMutation>, StorageError>;

    /// Lists pending mutations for a specific target object.
    fn list_mutations_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<PendingMutation>, StorageError>;

    /// Removes an acknowledged mutation from the queue.
    fn remove_mutation(&self, mutation_id: &str) -> Result<bool, StorageError>;

    /// Updates the status and retry count of a pending mutation.
    fn update_mutation_status(
        &self,
        mutation_id: &str,
        status: crate::models::MutationStatus,
        retry_count: u32,
    ) -> Result<(), StorageError>;

    /// Returns the number of mutations currently awaiting sync.
    fn pending_mutation_count(&self) -> Result<usize, StorageError>;
}

/// Abstract store for retaining base encrypted envelopes needed for three-way conflict merge.
pub trait BaseVersionStore: Send + Sync {
    /// Retrieves the base encrypted envelope for an object at a specific revision.
    fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, StorageError>;

    /// Stores a base encrypted envelope for an object at a specific revision.
    fn put_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StorageError>;

    /// Prunes base versions older than the specified revision for an object.
    fn prune_base_versions(
        &self,
        object_id: &str,
        older_than_revision: u64,
    ) -> Result<usize, StorageError>;

    /// Clears all retained base versions for an object.
    fn clear_base_versions(&self, object_id: &str) -> Result<usize, StorageError>;

    /// Lists all retained base versions (revision and envelope) for an object, ordered by revision ascending.
    fn list_base_versions(
        &self,
        object_id: &str,
    ) -> Result<Vec<(u64, EncryptedEnvelope)>, StorageError>;
}

/// Abstract store for tracking synchronization cursors and device state.
pub trait SyncStateStore: Send + Sync {
    /// Retrieves the current synchronization state.
    fn get_sync_state(&self) -> Result<SyncState, StorageError>;

    /// Sets the synchronization cursor to a new server sequence.
    fn set_sync_cursor(&self, cursor: u64) -> Result<(), StorageError>;

    /// Updates the complete synchronization state.
    fn set_sync_state(&self, state: &SyncState) -> Result<(), StorageError>;
}

/// Unified local storage abstraction combining object, mutation, base version, and sync state stores.
pub trait LocalStorage:
    ObjectStore + MutationStore + BaseVersionStore + SyncStateStore + Send + Sync
{
}

impl<T> LocalStorage for T where
    T: ObjectStore + MutationStore + BaseVersionStore + SyncStateStore + Send + Sync
{
}

use std::sync::Arc;

impl<T: ObjectStore + ?Sized> ObjectStore for Arc<T> {
    fn get_object(&self, object_id: &str) -> Result<Option<StoredEncryptedObject>, StorageError> {
        (**self).get_object(object_id)
    }

    fn put_object(&self, object: &StoredEncryptedObject) -> Result<(), StorageError> {
        (**self).put_object(object)
    }

    fn list_objects(
        &self,
        filter: &ObjectFilter,
    ) -> Result<Vec<StoredEncryptedObject>, StorageError> {
        (**self).list_objects(filter)
    }

    fn mark_deleted(
        &self,
        object_id: &str,
        revision: u64,
        envelope: EncryptedEnvelope,
        updated_at: String,
    ) -> Result<(), StorageError> {
        (**self).mark_deleted(object_id, revision, envelope, updated_at)
    }

    fn purge_object(&self, object_id: &str) -> Result<bool, StorageError> {
        (**self).purge_object(object_id)
    }
}

impl<T: MutationStore + ?Sized> MutationStore for Arc<T> {
    fn enqueue_mutation(&self, mutation: &PendingMutation) -> Result<(), StorageError> {
        (**self).enqueue_mutation(mutation)
    }

    fn get_mutation(&self, mutation_id: &str) -> Result<Option<PendingMutation>, StorageError> {
        (**self).get_mutation(mutation_id)
    }

    fn list_pending_mutations(&self) -> Result<Vec<PendingMutation>, StorageError> {
        (**self).list_pending_mutations()
    }

    fn list_mutations_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<PendingMutation>, StorageError> {
        (**self).list_mutations_for_object(object_id)
    }

    fn remove_mutation(&self, mutation_id: &str) -> Result<bool, StorageError> {
        (**self).remove_mutation(mutation_id)
    }

    fn update_mutation_status(
        &self,
        mutation_id: &str,
        status: crate::models::MutationStatus,
        retry_count: u32,
    ) -> Result<(), StorageError> {
        (**self).update_mutation_status(mutation_id, status, retry_count)
    }

    fn pending_mutation_count(&self) -> Result<usize, StorageError> {
        (**self).pending_mutation_count()
    }
}

impl<T: BaseVersionStore + ?Sized> BaseVersionStore for Arc<T> {
    fn get_base_version(
        &self,
        object_id: &str,
        revision: u64,
    ) -> Result<Option<EncryptedEnvelope>, StorageError> {
        (**self).get_base_version(object_id, revision)
    }

    fn put_base_version(
        &self,
        object_id: &str,
        revision: u64,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StorageError> {
        (**self).put_base_version(object_id, revision, envelope)
    }

    fn prune_base_versions(
        &self,
        object_id: &str,
        older_than_revision: u64,
    ) -> Result<usize, StorageError> {
        (**self).prune_base_versions(object_id, older_than_revision)
    }

    fn clear_base_versions(&self, object_id: &str) -> Result<usize, StorageError> {
        (**self).clear_base_versions(object_id)
    }

    fn list_base_versions(
        &self,
        object_id: &str,
    ) -> Result<Vec<(u64, EncryptedEnvelope)>, StorageError> {
        (**self).list_base_versions(object_id)
    }
}

impl<T: SyncStateStore + ?Sized> SyncStateStore for Arc<T> {
    fn get_sync_state(&self) -> Result<SyncState, StorageError> {
        (**self).get_sync_state()
    }

    fn set_sync_cursor(&self, cursor: u64) -> Result<(), StorageError> {
        (**self).set_sync_cursor(cursor)
    }

    fn set_sync_state(&self, state: &SyncState) -> Result<(), StorageError> {
        (**self).set_sync_state(state)
    }
}
