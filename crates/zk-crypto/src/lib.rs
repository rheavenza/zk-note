//! Cryptographic primitives, key derivation (Argon2id), key wrapping,
//! and envelope encryption (XChaCha20-Poly1305) for zero-knowledge notes.

pub mod attachment;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod object;
pub mod recovery;
pub mod vault;

pub use attachment::{
    build_chunk_aad, decrypt_chunk, decrypt_chunk_binary, encrypt_chunk, encrypt_chunk_binary,
    encrypt_chunk_with_rng, unwrap_attachment_key, wrap_attachment_key,
    wrap_attachment_key_with_rng,
};
pub use error::CryptoError;
pub use kdf::{derive_kek, KdfParams, ARGON2ID_ALGORITHM, SALT_LEN};
pub use keys::{AttachmentKey, KeyEncryptionKey, ObjectKey, RecoveryKey, VaultKey, KEY_LEN};
pub use object::{
    build_aad, decrypt_envelope, decrypt_object_payload, encrypt_envelope, encrypt_object_payload,
    unwrap_object_key, wrap_object_key,
};
pub use recovery::{format_recovery_key, parse_recovery_key, CHECKSUM_LEN, FORMATTED_RAW_LEN};
pub use vault::{
    rewrap_vault_key, unwrap_vault_key, unwrap_vault_key_recovery, wrap_vault_key,
    wrap_vault_key_recovery, WrappedVaultKey, NONCE_LEN, XCHACHA20_POLY1305_CIPHER_SUITE,
};
pub use zk_protocol as protocol;

/// Returns the crate name as a sanity check.
#[must_use]
pub fn crate_name() -> &'static str {
    "zk-crypto"
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;
    use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};

    #[test]
    fn test_crypto_init() {
        assert_eq!(crate_name(), "zk-crypto");
        assert_eq!(protocol::crate_name(), "zk-protocol");
    }

    #[test]
    fn test_invalid_key_lengths_rejected() {
        let invalid_lengths = [0, 1, 16, 31, 33, 48, 64, 128];

        for &len in &invalid_lengths {
            let buffer = vec![0xabu8; len];

            assert_eq!(
                VaultKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                ObjectKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                RecoveryKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );

            assert_eq!(
                KeyEncryptionKey::from_slice(&buffer),
                Err(CryptoError::InvalidKeyLength {
                    expected: KEY_LEN,
                    actual: len,
                })
            );
        }
    }

    #[test]
    fn test_valid_key_construction() {
        let bytes = [0x42u8; KEY_LEN];

        let vk = VaultKey::from_bytes(bytes);
        assert_eq!(vk.as_bytes(), &bytes);
        assert_eq!(vk.to_bytes(), bytes);
        assert_eq!(vk.as_ref(), &bytes);

        let vk_slice = VaultKey::from_slice(&bytes).expect("valid slice");
        assert_eq!(vk, vk_slice);
    }

    #[test]
    fn test_debug_formatting_redacts_secrets() {
        let raw = [0x5au8; KEY_LEN];

        let vk = VaultKey::from_bytes(raw);
        let ok = ObjectKey::from_bytes(raw);
        let rk = RecoveryKey::from_bytes(raw);
        let kek = KeyEncryptionKey::from_bytes(raw);

        let vk_debug = format!("{vk:?}");
        let ok_debug = format!("{ok:?}");
        let rk_debug = format!("{rk:?}");
        let kek_debug = format!("{kek:?}");

        assert_eq!(vk_debug, "VaultKey([REDACTED])");
        assert_eq!(ok_debug, "ObjectKey([REDACTED])");
        assert_eq!(rk_debug, "RecoveryKey([REDACTED])");
        assert_eq!(kek_debug, "KeyEncryptionKey([REDACTED])");

        // Verify secret byte pattern is not revealed in debug strings
        assert!(!vk_debug.contains("5a"));
    }

    #[test]
    fn test_os_csprng_random_generation() {
        let vk1 = VaultKey::generate();
        let vk2 = VaultKey::generate();

        assert_ne!(vk1, vk2);
        assert_ne!(vk1.as_bytes(), &[0u8; KEY_LEN]);
        assert_ne!(vk2.as_bytes(), &[0u8; KEY_LEN]);

        let ok1 = ObjectKey::generate();
        let ok2 = ObjectKey::generate();
        assert_ne!(ok1, ok2);

        let rk1 = RecoveryKey::generate();
        let rk2 = RecoveryKey::generate();
        assert_ne!(rk1, rk2);

        let kek1 = KeyEncryptionKey::generate();
        let kek2 = KeyEncryptionKey::generate();
        assert_ne!(kek1, kek2);
    }

    #[test]
    fn test_constant_time_equality() {
        let bytes_a = [0x11u8; KEY_LEN];
        let bytes_b = [0x22u8; KEY_LEN];

        let vk_a1 = VaultKey::from_bytes(bytes_a);
        let vk_a2 = VaultKey::from_bytes(bytes_a);
        let vk_b = VaultKey::from_bytes(bytes_b);

        assert!(bool::from(vk_a1.ct_eq(&vk_a2)));
        assert!(!bool::from(vk_a1.ct_eq(&vk_b)));
        assert_eq!(vk_a1, vk_a2);
        assert_ne!(vk_a1, vk_b);
    }

    #[test]
    fn test_zeroize_clears_memory() {
        let mut key = VaultKey::from_bytes([0xffu8; KEY_LEN]);
        assert_eq!(key.as_bytes(), &[0xffu8; KEY_LEN]);

        key.zeroize();
        assert_eq!(key.as_bytes(), &[0x00u8; KEY_LEN]);
    }

    // --- ZK-012: Vault Key creation and wrapping tests ---
    #[test]
    fn test_vault_key_wrapping_round_trip() {
        let vault_key = VaultKey::generate();
        let kek = KeyEncryptionKey::generate();

        let wrapped = wrap_vault_key(&vault_key, &kek).expect("wrap vault key");
        assert_eq!(wrapped.cipher_suite, XCHACHA20_POLY1305_CIPHER_SUITE);

        let unwrapped = unwrap_vault_key(&wrapped, &kek).expect("unwrap vault key");
        assert_eq!(vault_key, unwrapped);

        // Wrong KEK fails closed
        let wrong_kek = KeyEncryptionKey::generate();
        let err = unwrap_vault_key(&wrapped, &wrong_kek);
        assert_eq!(err, Err(CryptoError::DecryptionFailed));

        // Tampered ciphertext fails closed
        let mut tampered = wrapped.clone();
        let mut ct_bytes = base64ct::Base64::decode_vec(&tampered.ciphertext).expect("decode ct");
        ct_bytes[0] ^= 0x01; // flip 1 bit
        tampered.ciphertext = base64ct::Base64::encode_string(&ct_bytes);
        assert_eq!(
            unwrap_vault_key(&tampered, &kek),
            Err(CryptoError::DecryptionFailed)
        );

        // Tampered nonce fails closed
        let mut tampered_nonce = wrapped;
        let mut nonce_bytes =
            base64ct::Base64::decode_vec(&tampered_nonce.nonce).expect("decode nonce");
        nonce_bytes[0] ^= 0x01;
        tampered_nonce.nonce = base64ct::Base64::encode_string(&nonce_bytes);
        assert_eq!(
            unwrap_vault_key(&tampered_nonce, &kek),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // --- ZK-013: Recovery Key wrapping tests ---
    #[test]
    fn test_recovery_key_wrapping_and_formatting() {
        let vault_key = VaultKey::generate();
        let recovery_key = RecoveryKey::generate();

        // Wrap vault key under recovery key
        let wrapped_recovery =
            wrap_vault_key_recovery(&vault_key, &recovery_key).expect("wrap recovery");
        let restored =
            unwrap_vault_key_recovery(&wrapped_recovery, &recovery_key).expect("restore recovery");
        assert_eq!(vault_key, restored);

        // Wrong recovery key fails
        let wrong_recovery = RecoveryKey::generate();
        assert_eq!(
            unwrap_vault_key_recovery(&wrapped_recovery, &wrong_recovery),
            Err(CryptoError::DecryptionFailed)
        );

        // Test recovery key string formatting and checksum verification
        let formatted = format_recovery_key(&recovery_key);
        assert_eq!(formatted.len(), 72 + 8); // 72 hex digits + 8 hyphens = 80 chars
        let parsed = parse_recovery_key(&formatted).expect("parse recovery key");
        assert_eq!(recovery_key, parsed);

        // Test typo detection in recovery key string
        let mut typo_chars: Vec<char> = formatted.chars().collect();
        // Flip one character in the key portion
        typo_chars[0] = if typo_chars[0] == 'A' { 'B' } else { 'A' };
        let typo_str: String = typo_chars.into_iter().collect();
        assert_eq!(
            parse_recovery_key(&typo_str),
            Err(CryptoError::InvalidChecksum)
        );
    }

    // --- ZK-014: Object Key wrapping tests ---
    #[test]
    fn test_object_key_wrapping_and_aad_binding() {
        let vault_key = VaultKey::generate();
        let object_key = ObjectKey::generate();
        let object_id = "550e8400-e29b-41d4-a716-446655440000";
        let object_kind = OBJECT_KIND_NOTE;

        let wrapped = wrap_object_key(
            &object_key,
            &vault_key,
            ENVELOPE_VERSION_V1,
            object_id,
            object_kind,
        )
        .expect("wrap object key");

        let unwrapped = unwrap_object_key(
            &wrapped,
            &vault_key,
            ENVELOPE_VERSION_V1,
            object_id,
            object_kind,
        )
        .expect("unwrap object key");
        assert_eq!(object_key, unwrapped);

        // Tampered object_id in AAD fails
        let wrong_id_res = unwrap_object_key(
            &wrapped,
            &vault_key,
            ENVELOPE_VERSION_V1,
            "11111111-2222-3333-4444-555555555555",
            object_kind,
        );
        assert_eq!(wrong_id_res, Err(CryptoError::DecryptionFailed));

        // Tampered object_kind in AAD fails
        let wrong_kind_res =
            unwrap_object_key(&wrapped, &vault_key, ENVELOPE_VERSION_V1, object_id, 99);
        assert_eq!(wrong_kind_res, Err(CryptoError::DecryptionFailed));

        // Tampered envelope_version in AAD fails
        let wrong_ver_res = unwrap_object_key(&wrapped, &vault_key, 2, object_id, object_kind);
        assert_eq!(wrong_ver_res, Err(CryptoError::DecryptionFailed));
    }

    // --- ZK-015: Object payload encryption tests ---
    #[test]
    fn test_object_payload_encryption_round_trip() {
        let object_key = ObjectKey::generate();
        let object_id = "550e8400-e29b-41d4-a716-446655440000";
        let object_kind = OBJECT_KIND_NOTE;
        let plaintext = b"# Secret Note\n\nConfidential contents.";

        let enc = encrypt_object_payload(
            plaintext,
            &object_key,
            ENVELOPE_VERSION_V1,
            object_id,
            object_kind,
        )
        .expect("encrypt payload");

        let dec = decrypt_object_payload(
            &enc,
            &object_key,
            ENVELOPE_VERSION_V1,
            object_id,
            object_kind,
        )
        .expect("decrypt payload");
        assert_eq!(plaintext.as_slice(), dec.as_slice());

        // Wrong Object Key fails
        let wrong_key = ObjectKey::generate();
        assert_eq!(
            decrypt_object_payload(
                &enc,
                &wrong_key,
                ENVELOPE_VERSION_V1,
                object_id,
                object_kind
            ),
            Err(CryptoError::DecryptionFailed)
        );

        // Ciphertext tamper fails
        let mut tampered_enc = enc;
        let mut ct = base64ct::Base64::decode_vec(&tampered_enc.ciphertext).expect("decode ct");
        ct[0] ^= 0x01;
        tampered_enc.ciphertext = base64ct::Base64::encode_string(&ct);
        assert_eq!(
            decrypt_object_payload(
                &tampered_enc,
                &object_key,
                ENVELOPE_VERSION_V1,
                object_id,
                object_kind
            ),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // --- ZK-016: Complete encrypted envelope v1 tests ---
    #[test]
    fn test_complete_envelope_lifecycle() {
        let vault_key = VaultKey::generate();
        let object_id = "550e8400-e29b-41d4-a716-446655440000";
        let object_kind = OBJECT_KIND_NOTE;
        let plaintext = b"# Markdown Title\n\nZero-knowledge payload.";

        let envelope = encrypt_envelope(plaintext, &vault_key, object_id, object_kind)
            .expect("encrypt envelope");

        assert_eq!(envelope.envelope_version, ENVELOPE_VERSION_V1);
        assert_eq!(envelope.object_id, object_id);
        assert_eq!(envelope.object_kind, object_kind);

        // Decrypt envelope
        let decrypted = decrypt_envelope(&envelope, &vault_key).expect("decrypt envelope");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Serialization round trip
        let json = serde_json::to_string_pretty(&envelope).expect("json serialize");
        let parsed: zk_protocol::envelope::EncryptedEnvelope =
            serde_json::from_str(&json).expect("json deserialize");
        assert_eq!(envelope, parsed);

        // Unknown envelope version fails
        let mut invalid_ver = envelope.clone();
        invalid_ver.envelope_version = 2;
        assert_eq!(
            decrypt_envelope(&invalid_ver, &vault_key),
            Err(CryptoError::UnsupportedVersion(2))
        );

        // Wrong vault key fails
        let wrong_vk = VaultKey::generate();
        assert_eq!(
            decrypt_envelope(&envelope, &wrong_vk),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // --- ZK-017: Vault password rewrap tests ---
    #[test]
    fn test_vault_password_rewrap() {
        let old_passphrase = b"old-master-password";
        let old_params = KdfParams::new_test();
        let old_kek = derive_kek(old_passphrase, &old_params).expect("derive old kek");

        let vault_key = VaultKey::generate();
        let wrapped_key = wrap_vault_key(&vault_key, &old_kek).expect("wrap vault key");

        // Encrypt an object with the vault key
        let object_id = "test-object-123";
        let plaintext = b"Sensitive note encrypted before password change";
        let envelope = encrypt_envelope(plaintext, &vault_key, object_id, OBJECT_KIND_NOTE)
            .expect("encrypt object");

        // Now perform password rewrap
        let new_passphrase = b"new-super-secure-password";
        let new_params_template = KdfParams::new_test();

        let (new_params, new_wrapped_key, unmutated_vk) = rewrap_vault_key(
            old_passphrase,
            &old_params,
            &wrapped_key,
            new_passphrase,
            new_params_template,
        )
        .expect("rewrap vault key");

        // 1. Vault Key identity stays identical
        assert_eq!(vault_key, unmutated_vk);

        // 2. New passphrase derives new KEK that successfully unlocks the new wrapped key
        let new_kek = derive_kek(new_passphrase, &new_params).expect("derive new kek");
        let restored_vk =
            unwrap_vault_key(&new_wrapped_key, &new_kek).expect("unwrap with new kek");
        assert_eq!(vault_key, restored_vk);

        // 3. Old passphrase fails to unwrap new wrapped key
        assert_eq!(
            unwrap_vault_key(&new_wrapped_key, &old_kek),
            Err(CryptoError::DecryptionFailed)
        );

        // 4. Existing object ciphertext remains completely valid and decryptable using restored vault key
        let decrypted_after_rewrap =
            decrypt_envelope(&envelope, &restored_vk).expect("decrypt after rewrap");
        assert_eq!(plaintext.as_slice(), decrypted_after_rewrap.as_slice());
    }

    #[test]
    fn test_compatibility_test_vector_v1() {
        // Committed compatibility test vector for envelope v1:
        // Vault Key: [0x42; 32]
        // Plaintext: "Hello Zero-Knowledge World!"
        // Object ID: "550e8400-e29b-41d4-a716-446655440000"
        // Object Kind: 1 (Note)
        let vk_bytes = [0x42u8; KEY_LEN];
        let vault_key = VaultKey::from_bytes(vk_bytes);
        let expected_plaintext = b"Hello Zero-Knowledge World!";

        const COMMITTED_ENVELOPE_JSON: &str = r#"{"envelope_version":1,"object_id":"550e8400-e29b-41d4-a716-446655440000","object_kind":1,"wrapped_key":{"nonce":"lLxd8RQBi4n85jN61Q6ghaWhtCzK8ckb","ciphertext":"SoYpRSkMzujrTYawFLXTw6cN6Wv+RAfvFt2RNgWO0k/qxbXXbu9oXCzLafDBrqZ9"},"payload":{"nonce":"jTw5RahW+25wlf0T8R2IlAWIf6+RnNNT","ciphertext":"UWqjchGFnl2YkNiDrVTQsEgUsh1vkJ1eBAYpADavOn9wccYxKFTHyfTItw=="}}"#;

        let envelope: zk_protocol::envelope::EncryptedEnvelope =
            serde_json::from_str(COMMITTED_ENVELOPE_JSON).expect("parse committed vector");

        let decrypted =
            decrypt_envelope(&envelope, &vault_key).expect("decrypt committed test vector");
        assert_eq!(expected_plaintext.as_slice(), decrypted.as_slice());

        // Tampering with the committed test vector must fail closed
        let mut tampered = envelope;
        let mut ct = base64ct::Base64::decode_vec(&tampered.payload.ciphertext).expect("decode");
        ct[0] ^= 0x01;
        tampered.payload.ciphertext = base64ct::Base64::encode_string(&ct);
        assert_eq!(
            decrypt_envelope(&tampered, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }
}
