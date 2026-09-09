//! Cryptographic primitives, key derivation (Argon2id), key wrapping,
//! and envelope encryption (XChaCha20-Poly1305) for zero-knowledge notes.

pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-crypto"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_init() {
        assert_eq!(crate_name(), "zk-crypto");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }
}
