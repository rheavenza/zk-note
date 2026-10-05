//! Versioned identity from the stable, encrypted recovery wrapper (not the password wrapper).
use base64ct::{Base64, Encoding};
use blake2::{Blake2s256, Digest};
use std::fmt;
use zk_protocol::vault::VaultBootstrap;

/// A malformed or unsupported bootstrap. Never reflects remote material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBootstrap;
impl fmt::Display for InvalidBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unsupported vault bootstrap")
    }
}
impl std::error::Error for InvalidBootstrap {}

/// Validate the v1 crypto suite and bounded Argon2id parameters before local allocation.
/// Bounds accept existing test/production bootstraps; never substitute weaker parameters.
pub fn validate_bootstrap(b: &VaultBootstrap) -> Result<(), InvalidBootstrap> {
    let k = &b.kdf;
    if b.crypto_version != 1
        || k.algorithm != "argon2id"
        || k.parallelism == 0
        || k.parallelism > 16
        || k.memory_kib < 8 * k.parallelism
        || k.memory_kib > 262_144
        || k.iterations == 0
        || k.iterations > 16
    {
        return Err(InvalidBootstrap);
    }
    let salt = Base64::decode_vec(&k.salt).map_err(|_| InvalidBootstrap)?;
    if !(8..=64).contains(&salt.len()) {
        return Err(InvalidBootstrap);
    }
    for w in [&b.wrapped_vault_key, &b.recovery_wrapped_vault_key] {
        if w.cipher_suite != "xchacha20poly1305"
            || Base64::decode_vec(&w.nonce)
                .map_err(|_| InvalidBootstrap)?
                .len()
                != 24
            || Base64::decode_vec(&w.ciphertext)
                .map_err(|_| InvalidBootstrap)?
                .len()
                != 48
        {
            return Err(InvalidBootstrap);
        }
    }
    Ok(())
}

/// BLAKE2s-256 over domain (19 bytes), u32 BE crypto version, then each
/// recovery-wrapper field framed by a u32 BE byte length. Nonce/ciphertext are
/// decoded bytes; cipher suite is ASCII. Lowercase hex is prefixed `blake2s-v1:`.
pub fn vault_fingerprint(b: &VaultBootstrap) -> Result<String, InvalidBootstrap> {
    validate_bootstrap(b)?;
    let w = &b.recovery_wrapped_vault_key;
    let nonce = Base64::decode_vec(&w.nonce).map_err(|_| InvalidBootstrap)?;
    let ciphertext = Base64::decode_vec(&w.ciphertext).map_err(|_| InvalidBootstrap)?;
    let mut h = Blake2s256::new();
    h.update(b"zk-note-vault-id-v1");
    h.update(b.crypto_version.to_be_bytes());
    for field in [w.cipher_suite.as_bytes(), &nonce, &ciphertext] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("blake2s-v1:{hex}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::vault::VaultManager;
    #[test]
    fn golden_canonical_fingerprint_and_serialization_stability() {
        let (mut b, _, _) =
            VaultManager::init_vault(b"pass", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
        b.recovery_wrapped_vault_key.nonce = Base64::encode_string(&[1; 24]);
        b.recovery_wrapped_vault_key.ciphertext = Base64::encode_string(&[2; 48]);
        assert_eq!(
            vault_fingerprint(&b).unwrap(),
            "blake2s-v1:0f1236f674f1ca0143e7fc9a8ce073df7f6dd4f6cb0d30e4c564c11652fd060d"
        );
        let round_trip = serde_json::from_str(&serde_json::to_string_pretty(&b).unwrap()).unwrap();
        assert_eq!(vault_fingerprint(&b), vault_fingerprint(&round_trip));
    }
    #[test]
    fn identity_is_stable_across_passphrase_rotation_but_changes_with_recovery_wrapper() {
        let (b, _, key) =
            VaultManager::init_vault(b"old", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
        let new = VaultManager::set_new_passphrase(
            &b,
            &key,
            b"new",
            &zk_crypto::kdf::KdfParams::new_test(),
        )
        .unwrap();
        assert_ne!(b.wrapped_vault_key, new.wrapped_vault_key);
        assert_eq!(vault_fingerprint(&b), vault_fingerprint(&new));
        let (other, _, _) =
            VaultManager::init_vault(b"old", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
        assert_ne!(vault_fingerprint(&b), vault_fingerprint(&other));
        let mut changed = b.clone();
        changed.recovery_wrapped_vault_key.nonce = Base64::encode_string(&[7; 24]);
        assert_ne!(vault_fingerprint(&b), vault_fingerprint(&changed));
    }
    #[test]
    fn malformed_crypto_and_excessive_kdf_parameters_fail_closed() {
        let (b, _, _) =
            VaultManager::init_vault(b"pass", &zk_crypto::kdf::KdfParams::new_test()).unwrap();
        for mutation in 0..9 {
            let mut bad = b.clone();
            match mutation {
                0 => bad.crypto_version = 2,
                1 => bad.kdf.algorithm = "bad".into(),
                2 => bad.kdf.memory_kib = u32::MAX,
                3 => bad.kdf.iterations = 0,
                4 => bad.kdf.parallelism = 0,
                5 => bad.kdf.salt = "invalid".into(),
                6 => bad.wrapped_vault_key.nonce = Base64::encode_string(&[0; 23]),
                7 => bad.recovery_wrapped_vault_key.ciphertext = Base64::encode_string(&[0; 47]),
                _ => bad.recovery_wrapped_vault_key.cipher_suite = "bad".into(),
            }
            assert_eq!(vault_fingerprint(&bad), Err(InvalidBootstrap));
        }
    }
}
