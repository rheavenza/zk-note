//! Synchronization state machine, pull/push coordination,
//! conflict detection, and deterministic three-way merge logic.

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
