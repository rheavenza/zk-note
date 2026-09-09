//! Native/WASM cryptographic compatibility tests (ZK-061).
//!
//! Verifies that:
//! 1. Known deterministic test vectors (Argon2id KDF, Envelope v1) pass identically in WASM.
//! 2. Vault lifecycle (init, unlock, recovery unlock, passphrase rewrap) works in WASM.
//! 3. Failure vectors (wrong passphrase, tampered ciphertext, tampered AAD, invalid version) fail closed.
//!
//! Tests execute natively via `cargo test -p zk-wasm` and inside the WebAssembly VM
//! via `wasm-pack test --node crates/zk-wasm`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64ct::{Base64, Encoding};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
use zk_crypto::kdf::KdfParams;
use zk_crypto::keys::VaultKey;
use zk_protocol::envelope::EncryptedEnvelope;
use zk_wasm::{
    init_vault_impl, unlock_vault_impl, unlock_with_recovery_key_impl, wasm_decrypt_envelope,
    wasm_decrypt_raw, wasm_derive_kek, wasm_encrypt_envelope, wasm_encrypt_raw,
    wasm_unwrap_recovery, wasm_wrap_recovery,
};

const COMMITTED_ENVELOPE_JSON: &str = r#"{"envelope_version":1,"object_id":"550e8400-e29b-41d4-a716-446655440000","object_kind":1,"wrapped_key":{"nonce":"lLxd8RQBi4n85jN61Q6ghaWhtCzK8ckb","ciphertext":"SoYpRSkMzujrTYawFLXTw6cN6Wv+RAfvFt2RNgWO0k/qxbXXbu9oXCzLafDBrqZ9"},"payload":{"nonce":"jTw5RahW+25wlf0T8R2IlAWIf6+RnNNT","ciphertext":"UWqjchGFnl2YkNiDrVTQsEgUsh1vkJ1eBAYpADavOn9wccYxKFTHyfTItw=="}}"#;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_argon2id_deterministic_vector_in_wasm() {
    let salt = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let params = KdfParams::custom(1024, 2, 1, &salt).expect("valid custom params");
    let params_json = serde_json::to_string(&params).expect("serialize params");

    let kek_b64 = wasm_derive_kek("password", &params_json).expect("derive kek in wasm");
    let kek_bytes = Base64::decode_vec(&kek_b64).expect("decode kek b64");
    let kek_hex = kek_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    assert_eq!(
        kek_hex, "007f6b258779db1c07dda5ff432b9025b66d7ec395ed9acba7939210b3ed97b8",
        "Argon2id deterministic test vector mismatch in WASM"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_decrypt_committed_envelope_v1_in_wasm() {
    let vk_bytes = [0x42u8; 32];
    let vk_b64 = Base64::encode_string(&vk_bytes);

    let decrypted = wasm_decrypt_raw(&vk_b64, COMMITTED_ENVELOPE_JSON)
        .expect("decrypt committed vector in wasm");
    assert_eq!(decrypted.as_slice(), b"Hello Zero-Knowledge World!");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_committed_envelope_v1_tampering_fails_closed_in_wasm() {
    let vk_bytes = [0x42u8; 32];
    let vk_b64 = Base64::encode_string(&vk_bytes);

    let envelope: EncryptedEnvelope =
        serde_json::from_str(COMMITTED_ENVELOPE_JSON).expect("parse envelope");

    // 1. Bit flip in ciphertext
    let mut tampered = envelope.clone();
    let mut ct = Base64::decode_vec(&tampered.payload.ciphertext).expect("decode ct");
    ct[0] ^= 0x01;
    tampered.payload.ciphertext = Base64::encode_string(&ct);
    let tampered_json = serde_json::to_string(&tampered).expect("serialize tampered");
    assert!(
        wasm_decrypt_raw(&vk_b64, &tampered_json).is_err(),
        "tampered ciphertext must fail closed"
    );

    // 2. Tampered AAD (object_id)
    let mut tampered_aad = envelope.clone();
    tampered_aad.object_id = "550e8400-e29b-41d4-a716-446655440001".to_string();
    let tampered_aad_json = serde_json::to_string(&tampered_aad).expect("serialize");
    assert!(
        wasm_decrypt_raw(&vk_b64, &tampered_aad_json).is_err(),
        "tampered object_id must fail closed"
    );

    // 3. Tampered AAD (object_kind)
    let mut tampered_kind = envelope.clone();
    tampered_kind.object_kind = 2; // Attachment
    let tampered_kind_json = serde_json::to_string(&tampered_kind).expect("serialize");
    assert!(
        wasm_decrypt_raw(&vk_b64, &tampered_kind_json).is_err(),
        "tampered object_kind must fail closed"
    );

    // 4. Tampered AAD (envelope_version)
    let mut tampered_ver = envelope.clone();
    tampered_ver.envelope_version = 2;
    let tampered_ver_json = serde_json::to_string(&tampered_ver).expect("serialize");
    assert!(
        wasm_decrypt_raw(&vk_b64, &tampered_ver_json).is_err(),
        "unsupported envelope_version must fail closed"
    );

    // 5. Wrong vault key
    let wrong_vk = [0x99u8; 32];
    let wrong_vk_b64 = Base64::encode_string(&wrong_vk);
    assert!(
        wasm_decrypt_raw(&wrong_vk_b64, COMMITTED_ENVELOPE_JSON).is_err(),
        "wrong vault key must fail closed"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_note_envelope_round_trip_in_wasm() {
    let vault_key = VaultKey::generate();
    let vk_b64 = Base64::encode_string(vault_key.as_bytes());

    let note_id = "test-note-wasm-001";
    let title = "Cross-Runtime Note Title";
    let body = "# Header\n\nThis note is created and encrypted in WASM.\n\rLine with CRLF\r";
    let tags = vec!["Security".into(), "crypto".into(), "security".into()];

    let enc_json =
        wasm_encrypt_envelope(&vk_b64, note_id, title, body, tags).expect("encrypt in wasm");

    // Verify it is a valid EncryptedEnvelope
    let envelope: EncryptedEnvelope = serde_json::from_str(&enc_json).expect("parse envelope json");
    assert_eq!(envelope.envelope_version, 1);
    assert_eq!(envelope.object_id, note_id);
    assert_eq!(envelope.object_kind, 1);

    // Decrypt in WASM
    let dec_note = wasm_decrypt_envelope(&vk_b64, &enc_json).expect("decrypt in wasm");
    assert_eq!(dec_note.id(), note_id);
    assert_eq!(dec_note.title(), title);
    // Body newlines canonicalized to \n
    assert_eq!(
        dec_note.body(),
        "# Header\n\nThis note is created and encrypted in WASM.\n\nLine with CRLF\n"
    );
    // Tags canonicalized: lowercase, deduplicated, sorted
    assert_eq!(
        dec_note.tags(),
        vec!["crypto".to_string(), "security".to_string()]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_raw_payload_round_trip_in_wasm() {
    let vault_key = VaultKey::generate();
    let vk_b64 = Base64::encode_string(vault_key.as_bytes());

    let object_id = "binary-attachment-001";
    let object_kind = 2; // Attachment
    let mut raw_bytes = vec![0u8; 8192];
    for (i, b) in raw_bytes.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let enc_json =
        wasm_encrypt_raw(&vk_b64, object_id, object_kind, &raw_bytes).expect("encrypt raw in wasm");

    let dec_bytes = wasm_decrypt_raw(&vk_b64, &enc_json).expect("decrypt raw in wasm");
    assert_eq!(dec_bytes, raw_bytes);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_vault_lifecycle_round_trip_in_wasm() {
    let params = KdfParams::new_test();
    let passphrase = "initial-safe-passphrase-42";

    // 1. Init vault
    let mut init_res = init_vault_impl(passphrase, &params).expect("init vault");
    let wrapped_vk = init_res.wrapped_vault_key();
    let kdf_json = init_res.kdf_params_json();
    let wrapped_rec = init_res.wrapped_recovery_key();
    let rec_phrase = init_res.recovery_phrase();

    let mut session = init_res.take_session().expect("take session");
    let enc_note = session
        .encrypt_note(
            "note-init-01",
            "Lifecycle Note",
            "Content",
            vec!["test".into()],
        )
        .expect("encrypt note");

    // 2. Unlock via passphrase
    let session_pass =
        unlock_vault_impl(passphrase, &wrapped_vk, &kdf_json).expect("unlock via passphrase");
    let dec1 = session_pass
        .decrypt_note_impl(&enc_note)
        .expect("decrypt with pass session");
    assert_eq!(dec1.title(), "Lifecycle Note");

    // 3. Unlock via recovery key
    let session_rec = unlock_with_recovery_key_impl(&rec_phrase, &wrapped_rec)
        .expect("unlock via recovery phrase");
    let dec2 = session_rec
        .decrypt_note_impl(&enc_note)
        .expect("decrypt with rec session");
    assert_eq!(dec2.title(), "Lifecycle Note");

    // 4. Rewrap passphrase
    let new_passphrase = "updated-safe-passphrase-99";
    let rewrap_res = session
        .rewrap_passphrase_impl(new_passphrase, &params)
        .expect("rewrap passphrase");

    // 5. New passphrase unlocks successfully
    let session_new = unlock_vault_impl(
        new_passphrase,
        &rewrap_res.new_wrapped_vault_key(),
        &rewrap_res.new_kdf_params_json(),
    )
    .expect("unlock with new passphrase");
    let dec3 = session_new
        .decrypt_note_impl(&enc_note)
        .expect("decrypt with new pass session");
    assert_eq!(dec3.title(), "Lifecycle Note");

    // 6. Old passphrase fails closed
    let old_fail = unlock_vault_impl(
        passphrase,
        &rewrap_res.new_wrapped_vault_key(),
        &rewrap_res.new_kdf_params_json(),
    );
    assert!(
        old_fail.is_err(),
        "old passphrase must fail closed after rewrap"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_recovery_wrapping_standalone_round_trip() {
    let vault_key = VaultKey::generate();
    let vk_b64 = Base64::encode_string(vault_key.as_bytes());

    let recovery_key = zk_crypto::keys::RecoveryKey::generate();
    let rec_phrase = zk_crypto::recovery::format_recovery_key(&recovery_key);

    let wrapped_rec = wasm_wrap_recovery(&vk_b64, &rec_phrase).expect("wrap recovery in wasm");
    let unwrapped_vk_b64 =
        wasm_unwrap_recovery(&rec_phrase, &wrapped_rec).expect("unwrap recovery in wasm");

    assert_eq!(vk_b64, unwrapped_vk_b64);

    // Wrong recovery key must fail
    let wrong_rec = zk_crypto::keys::RecoveryKey::generate();
    let wrong_phrase = zk_crypto::recovery::format_recovery_key(&wrong_rec);
    assert!(
        wasm_unwrap_recovery(&wrong_phrase, &wrapped_rec).is_err(),
        "wrong recovery phrase must fail closed"
    );
}
