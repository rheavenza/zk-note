//! Synchronization state machine, pull/push coordination,
//! conflict detection, and deterministic three-way merge logic.

pub mod adapter;
pub mod cursor;
pub mod error;
pub mod pull;
pub mod push;
pub mod queue;

pub use adapter::{
    validate_no_plaintext_secrets, MockSyncAdapter, NativeHttpSyncAdapter, SyncServerAdapter,
};
pub use cursor::{CursorError, DurableSyncCursor};
pub use error::SyncNetworkError;
pub use pull::{
    decrypt_stored_objects_on_unlock, pull_remote_changes, pull_with_session, DecryptedPullItem,
    LockedSyncBehavior, PullError, PullOptions, PullReport,
};
pub use push::{
    push_pending_changes, PushError, PushItemConflict, PushItemSuccess, PushOptions, PushReport,
};
pub use queue::{PendingMutationQueue, QueueError};
pub use zk_core as core;
pub use zk_crypto as crypto;
pub use zk_protocol as protocol;
pub use zk_storage as storage;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-sync"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_init() {
        assert_eq!(crate_name(), "zk-sync");
        assert_eq!(core::crate_name(), "zk-core");
        assert_eq!(crypto::crate_name(), "zk-crypto");
        assert_eq!(storage::crate_name(), "zk-storage");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }
}
