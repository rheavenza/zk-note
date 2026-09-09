//! Note domain model, vault lifecycle management, and
//! encrypted object orchestration.

pub use zk_crypto as crypto;
pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_init() {
        assert_eq!(crate_name(), "zk-core");
        assert_eq!(crypto::crate_name(), "zk-crypto");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }
}
