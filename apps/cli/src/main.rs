//! Terminal/CLI client for zero-knowledge notes (`zk-note`).

fn main() {
    println!("zk-note: zero-knowledge note-taking client");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cli_init() {
        assert_eq!(zk_core::crate_name(), "zk-core");
        assert_eq!(zk_sync::crate_name(), "zk-sync");
        assert_eq!(zk_storage::crate_name(), "zk-storage");
        assert_eq!(zk_crypto::crate_name(), "zk-crypto");
        assert_eq!(zk_protocol::crate_name(), "zk-protocol");
    }
}
