//! Negative and robustness test harness for cryptographic operations (ZK-018).
//!
//! Verifies:
//! - Malformed envelope corpus rejected safely;
//! - Truncated inputs fail closed;
//! - Unknown versions rejected cleanly;
//! - Modified nonce, ciphertext, or AAD fail closed;
//! - No panic under untrusted or fuzzed inputs.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64ct::{Base64, Encoding};
use zk_crypto::error::CryptoError;
use zk_crypto::keys::VaultKey;
use zk_crypto::object::{decrypt_envelope, encrypt_envelope};
use zk_crypto::recovery::parse_recovery_key;
use zk_protocol::constants::{ENVELOPE_VERSION_V1, OBJECT_KIND_NOTE};
use zk_protocol::envelope::{EncryptedEnvelope, EncryptedKeyContainer, EncryptedPayloadContainer};

const MALFORMED_CORPUS: &[&str] = &[
    "",
    " ",
    "\0",
    "{}",
    "[]",
    "null",
    "true",
    "12345",
    "\"a string\"",
    "{",
    "{\"envelope_version\": 1",
    "<!DOCTYPE html><html><body>Error</body></html>",
    r#"{"envelope_version": "one", "object_id": "test"}"#,
    r#"{"envelope_version": 1, "object_id": null}"#,
    r#"{"envelope_version": 1, "object_id": "test", "object_kind": "note"}"#,
    r#"{"envelope_version": 1, "object_id": "id", "object_kind": 1, "wrapped_key": {}}"#,
    r#"{"envelope_version": 1, "object_id": "id", "object_kind": 1, "wrapped_key": {"nonce": "", "ciphertext": ""}}"#,
    r#"{"envelope_version": 1, "object_id": "id", "object_kind": 1, "wrapped_key": {"nonce": "!!!bad-base64!!!", "ciphertext": "dGVzdA=="}, "payload": {"nonce": "dGVzdA==", "ciphertext": "dGVzdA=="}}"#,
    r#"{"envelope_version": 1, "object_id": "id", "object_kind": 1, "wrapped_key": {"nonce": "dGVzdA==", "ciphertext": "!!!bad-base64!!!"}, "payload": {"nonce": "dGVzdA==", "ciphertext": "dGVzdA=="}}"#,
];

#[test]
fn test_malformed_envelope_corpus() {
    let vault_key = VaultKey::generate();

    for &malformed in MALFORMED_CORPUS {
        let parse_res = serde_json::from_str::<EncryptedEnvelope>(malformed);
        if let Ok(env) = parse_res {
            // Even if it parses syntactically, decryption must fail closed without panic
            let dec_res = decrypt_envelope(&env, &vault_key);
            assert!(dec_res.is_err(), "malformed payload decrypted successfully");
        }
    }
}

#[test]
fn test_truncated_inputs_rejected() {
    let vault_key = VaultKey::generate();

    // 1. Truncated Nonce (< 24 bytes)
    for len in 0..24 {
        let short_nonce = Base64::encode_string(&vec![0x42u8; len]);
        let valid_ct = Base64::encode_string(&[0x42u8; 48]);

        let env = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: short_nonce.clone(),
                ciphertext: valid_ct.clone(),
            },
            payload: EncryptedPayloadContainer {
                nonce: short_nonce,
                ciphertext: valid_ct,
            },
        };

        let res = decrypt_envelope(&env, &vault_key);
        assert!(res.is_err());
    }

    // 2. Truncated Ciphertext (< 16 bytes Poly1305 auth tag)
    for len in 0..16 {
        let valid_nonce = Base64::encode_string(&[0x42u8; 24]);
        let short_ct = Base64::encode_string(&vec![0x42u8; len]);

        let env = EncryptedEnvelope {
            envelope_version: ENVELOPE_VERSION_V1,
            object_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            object_kind: OBJECT_KIND_NOTE,
            wrapped_key: EncryptedKeyContainer {
                nonce: valid_nonce.clone(),
                ciphertext: short_ct.clone(),
            },
            payload: EncryptedPayloadContainer {
                nonce: valid_nonce,
                ciphertext: short_ct,
            },
        };

        let res = decrypt_envelope(&env, &vault_key);
        assert!(res.is_err());
    }

    // 3. Truncated Recovery Key
    assert!(parse_recovery_key("").is_err());
    assert!(parse_recovery_key("1234").is_err());
    assert!(parse_recovery_key("1234-5678-90AB").is_err());
}

#[test]
fn test_unknown_envelope_versions_rejected() {
    let vault_key = VaultKey::generate();
    let valid_envelope = encrypt_envelope(
        b"Valid message",
        &vault_key,
        "550e8400-e29b-41d4-a716-446655440000",
        OBJECT_KIND_NOTE,
    )
    .expect("valid envelope");

    let unknown_versions = [0, 2, 3, 42, 999, u32::MAX];
    for &version in &unknown_versions {
        let mut bad_version_env = valid_envelope.clone();
        bad_version_env.envelope_version = version;

        let res = decrypt_envelope(&bad_version_env, &vault_key);
        assert_eq!(res, Err(CryptoError::UnsupportedVersion(version)));
    }
}

#[test]
fn test_modified_components_fail_closed() {
    let vault_key = VaultKey::generate();
    let original = encrypt_envelope(
        b"Strict integrity verification",
        &vault_key,
        "550e8400-e29b-41d4-a716-446655440000",
        OBJECT_KIND_NOTE,
    )
    .expect("valid envelope");

    // 1. Bit flip in payload ciphertext
    {
        let mut env = original.clone();
        let mut bytes = Base64::decode_vec(&env.payload.ciphertext).expect("decode");
        bytes[0] ^= 0x01;
        env.payload.ciphertext = Base64::encode_string(&bytes);
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // 2. Bit flip in payload nonce
    {
        let mut env = original.clone();
        let mut bytes = Base64::decode_vec(&env.payload.nonce).expect("decode");
        bytes[0] ^= 0x01;
        env.payload.nonce = Base64::encode_string(&bytes);
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // 3. Bit flip in wrapped_key ciphertext
    {
        let mut env = original.clone();
        let mut bytes = Base64::decode_vec(&env.wrapped_key.ciphertext).expect("decode");
        bytes[0] ^= 0x01;
        env.wrapped_key.ciphertext = Base64::encode_string(&bytes);
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // 4. Bit flip in wrapped_key nonce
    {
        let mut env = original.clone();
        let mut bytes = Base64::decode_vec(&env.wrapped_key.nonce).expect("decode");
        bytes[0] ^= 0x01;
        env.wrapped_key.nonce = Base64::encode_string(&bytes);
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // 5. Tampered AAD: object_id
    {
        let mut env = original.clone();
        env.object_id = "00000000-0000-0000-0000-000000000000".to_string();
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }

    // 6. Tampered AAD: object_kind
    {
        let mut env = original;
        env.object_kind = 2; // Notebook instead of Note
        assert_eq!(
            decrypt_envelope(&env, &vault_key),
            Err(CryptoError::DecryptionFailed)
        );
    }
}

#[test]
fn test_fuzz_mutations_no_panic() {
    let vault_key = VaultKey::generate();
    let valid = encrypt_envelope(
        b"Fuzz test seed message",
        &vault_key,
        "550e8400-e29b-41d4-a716-446655440000",
        OBJECT_KIND_NOTE,
    )
    .expect("valid envelope");

    let valid_json = serde_json::to_vec(&valid).expect("serialize");

    // Pseudo-random deterministic mutation loop (100 iterations)
    for seed in 0u8..100 {
        let mut mutated_bytes = valid_json.clone();

        // Mutate bytes based on seed
        let pos = (seed as usize * 7) % mutated_bytes.len();
        mutated_bytes[pos] ^= seed | 0x80;

        // Truncate or append
        if seed % 3 == 0 && mutated_bytes.len() > 10 {
            mutated_bytes.truncate(mutated_bytes.len() - (seed as usize % 10));
        }

        let panic_caught = std::panic::catch_unwind(|| {
            if let Ok(env) = serde_json::from_slice::<EncryptedEnvelope>(&mutated_bytes) {
                let _ = decrypt_envelope(&env, &vault_key);
            }
        });

        assert!(
            panic_caught.is_ok(),
            "fuzz mutation caused panic on seed {seed}"
        );
    }
}
