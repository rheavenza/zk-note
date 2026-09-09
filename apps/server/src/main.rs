//! Zero-knowledge ciphertext storage and sync coordination server.
//!
//! In accordance with SEC-002, the server operates exclusively on opaque
//! ciphertext and protocol metadata and does not depend on crypto or core
//! plaintext models.

fn main() {
    println!("zk-server: zero-knowledge sync coordinator");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_server_init() {
        assert_eq!(zk_protocol::crate_name(), "zk-protocol");
    }
}
