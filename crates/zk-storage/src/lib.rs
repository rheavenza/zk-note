pub mod error;
pub mod memory;
pub mod models;
pub mod traits;

pub use error::StorageError;
pub use memory::MemoryStorage;
pub use models::{
    BaseVersion, MutationStatus, MutationType, ObjectFilter, PendingMutation,
    StoredEncryptedObject, SyncState,
};
pub use traits::{BaseVersionStore, LocalStorage, MutationStore, ObjectStore, SyncStateStore};

pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-storage"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_init() {
        assert_eq!(crate_name(), "zk-storage");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }
}
