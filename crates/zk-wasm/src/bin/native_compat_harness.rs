//! Native cryptographic test harness for cross-runtime compatibility verification with WASM (ZK-061).
//!
//! Receives JSON commands or CLI arguments and performs native cryptographic operations,
//! outputting JSON results for Node.js test runner consumption.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use zk_core::note::PlaintextNote;
use zk_crypto::kdf::{derive_kek, KdfParams};
use zk_crypto::keys::{KeyEncryptionKey, RecoveryKey, VaultKey};
use zk_crypto::object::{decrypt_envelope, encrypt_envelope};
use zk_crypto::recovery::{format_recovery_key, parse_recovery_key};
use zk_crypto::vault::{
    unwrap_vault_key, unwrap_vault_key_recovery, wrap_vault_key, wrap_vault_key_recovery,
    WrappedVaultKey,
};
use zk_protocol::envelope::EncryptedEnvelope;

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    fn fail(err: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }
    }
}

fn print_response(resp: Response) {
    let s = serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".to_string());
    println!("{s}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_response(Response::fail("missing command argument"));
        return;
    }

    let cmd = &args[1];
    match cmd.as_str() {
        "derive-kek" => {
            if args.len() < 4 {
                print_response(Response::fail(
                    "derive-kek requires <passphrase> <params_json>",
                ));
                return;
            }
            let passphrase = &args[2];
            let params_res: Result<KdfParams, _> = serde_json::from_str(&args[3]);
            let params = match params_res {
                Ok(p) => p,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match derive_kek(passphrase.as_bytes(), &params) {
                Ok(kek) => {
                    let b64 = Base64::encode_string(kek.as_bytes());
                    print_response(Response::success(serde_json::json!({ "kek_b64": b64 })));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "wrap-key" => {
            if args.len() < 4 {
                print_response(Response::fail(
                    "wrap-key requires <vault_key_b64> <kek_b64>",
                ));
                return;
            }
            let vk_bytes = match Base64::decode_vec(&args[2]) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let kek_bytes = match Base64::decode_vec(&args[3]) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let kek = match KeyEncryptionKey::from_slice(&kek_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match wrap_vault_key(&vk, &kek) {
                Ok(wrapped) => {
                    let wrapped_json = serde_json::to_string(&wrapped).unwrap();
                    print_response(Response::success(
                        serde_json::json!({ "wrapped_json": wrapped_json }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "unwrap-key" => {
            if args.len() < 4 {
                print_response(Response::fail(
                    "unwrap-key requires <kek_b64> <wrapped_json>",
                ));
                return;
            }
            let kek_bytes = match Base64::decode_vec(&args[2]) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let kek = match KeyEncryptionKey::from_slice(&kek_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let wrapped: WrappedVaultKey = match serde_json::from_str(&args[3]) {
                Ok(w) => w,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match unwrap_vault_key(&wrapped, &kek) {
                Ok(vk) => {
                    let b64 = Base64::encode_string(vk.as_bytes());
                    print_response(Response::success(
                        serde_json::json!({ "vault_key_b64": b64 }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "init-vault" => {
            if args.len() < 4 {
                print_response(Response::fail(
                    "init-vault requires <passphrase> <params_json>",
                ));
                return;
            }
            let passphrase = &args[2];
            let params: KdfParams = match serde_json::from_str(&args[3]) {
                Ok(p) => p,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vault_key = VaultKey::generate();
            let recovery_key = RecoveryKey::generate();
            let recovery_phrase = format_recovery_key(&recovery_key);

            let kek = match derive_kek(passphrase.as_bytes(), &params) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let wrapped_vault = match wrap_vault_key(&vault_key, &kek) {
                Ok(w) => serde_json::to_string(&w).unwrap(),
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let wrapped_recovery = match wrap_vault_key_recovery(&vault_key, &recovery_key) {
                Ok(w) => serde_json::to_string(&w).unwrap(),
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let params_json = serde_json::to_string(&params).unwrap();
            let vk_b64 = Base64::encode_string(vault_key.as_bytes());

            print_response(Response::success(serde_json::json!({
                "wrapped_vault_key": wrapped_vault,
                "kdf_params_json": params_json,
                "wrapped_recovery_key": wrapped_recovery,
                "recovery_phrase": recovery_phrase,
                "vault_key_b64": vk_b64,
            })));
        }
        "unlock-vault" => {
            if args.len() < 5 {
                print_response(Response::fail(
                    "unlock-vault requires <passphrase> <wrapped_vk_json> <params_json>",
                ));
                return;
            }
            let passphrase = &args[2];
            let wrapped: WrappedVaultKey = match serde_json::from_str(&args[3]) {
                Ok(w) => w,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let params: KdfParams = match serde_json::from_str(&args[4]) {
                Ok(p) => p,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let kek = match derive_kek(passphrase.as_bytes(), &params) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match unwrap_vault_key(&wrapped, &kek) {
                Ok(vk) => {
                    let b64 = Base64::encode_string(vk.as_bytes());
                    print_response(Response::success(
                        serde_json::json!({ "vault_key_b64": b64 }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "unlock-recovery" => {
            if args.len() < 4 {
                print_response(Response::fail(
                    "unlock-recovery requires <recovery_phrase> <wrapped_rec_json>",
                ));
                return;
            }
            let phrase = &args[2];
            let recovery_key = match parse_recovery_key(phrase) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let wrapped: WrappedVaultKey = match serde_json::from_str(&args[3]) {
                Ok(w) => w,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match unwrap_vault_key_recovery(&wrapped, &recovery_key) {
                Ok(vk) => {
                    let b64 = Base64::encode_string(vk.as_bytes());
                    print_response(Response::success(
                        serde_json::json!({ "vault_key_b64": b64 }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "rewrap-passphrase" => {
            if args.len() < 5 {
                print_response(Response::fail(
                    "rewrap-passphrase requires <vault_key_b64> <new_passphrase> <params_json>",
                ));
                return;
            }
            let vk_bytes = match Base64::decode_vec(&args[2]) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let new_pass = &args[3];
            let params: KdfParams = match serde_json::from_str(&args[4]) {
                Ok(p) => p,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let new_kek = match derive_kek(new_pass.as_bytes(), &params) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match wrap_vault_key(&vk, &new_kek) {
                Ok(wrapped) => {
                    let wrapped_json = serde_json::to_string(&wrapped).unwrap();
                    let params_json = serde_json::to_string(&params).unwrap();
                    print_response(Response::success(serde_json::json!({
                        "new_wrapped_vault_key": wrapped_json,
                        "new_kdf_params_json": params_json,
                    })));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "encrypt-note" => {
            // Read JSON from stdin for large note payloads
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                print_response(Response::fail(e));
                return;
            }
            #[derive(Deserialize)]
            struct NoteReq {
                vault_key_b64: String,
                object_id: String,
                title: String,
                body: String,
                tags: Vec<String>,
            }
            let req: NoteReq = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk_bytes = match Base64::decode_vec(&req.vault_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let mut note = PlaintextNote::new(req.title, req.body);
            note.tags = req.tags;
            note.canonicalize();

            match note.encrypt(&vk, &req.object_id) {
                Ok(envelope) => {
                    let env_json = serde_json::to_string(&envelope).unwrap();
                    print_response(Response::success(
                        serde_json::json!({ "envelope_json": env_json }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "decrypt-note" => {
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                print_response(Response::fail(e));
                return;
            }
            #[derive(Deserialize)]
            struct DecReq {
                vault_key_b64: String,
                envelope_json: String,
            }
            let req: DecReq = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk_bytes = match Base64::decode_vec(&req.vault_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let envelope: EncryptedEnvelope = match serde_json::from_str(&req.envelope_json) {
                Ok(env) => env,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match PlaintextNote::decrypt(&envelope, &vk) {
                Ok(note) => {
                    print_response(Response::success(serde_json::json!({
                        "id": envelope.object_id,
                        "title": note.title,
                        "body": note.body,
                        "tags": note.tags,
                        "created_at": note.created_at,
                        "updated_at": note.updated_at,
                    })));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "encrypt-raw" => {
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                print_response(Response::fail(e));
                return;
            }
            #[derive(Deserialize)]
            struct RawReq {
                vault_key_b64: String,
                object_id: String,
                object_kind: u16,
                plaintext_b64: String,
            }
            let req: RawReq = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk_bytes = match Base64::decode_vec(&req.vault_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let pt_bytes = match Base64::decode_vec(&req.plaintext_b64) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match encrypt_envelope(&pt_bytes, &vk, &req.object_id, req.object_kind) {
                Ok(env) => {
                    let env_json = serde_json::to_string(&env).unwrap();
                    print_response(Response::success(
                        serde_json::json!({ "envelope_json": env_json }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        "decrypt-raw" => {
            let mut input = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut input) {
                print_response(Response::fail(e));
                return;
            }
            #[derive(Deserialize)]
            struct RawDecReq {
                vault_key_b64: String,
                envelope_json: String,
            }
            let req: RawDecReq = match serde_json::from_str(&input) {
                Ok(r) => r,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk_bytes = match Base64::decode_vec(&req.vault_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let vk = match VaultKey::from_slice(&vk_bytes) {
                Ok(k) => k,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            let envelope: EncryptedEnvelope = match serde_json::from_str(&req.envelope_json) {
                Ok(env) => env,
                Err(e) => {
                    print_response(Response::fail(e));
                    return;
                }
            };
            match decrypt_envelope(&envelope, &vk) {
                Ok(pt) => {
                    let pt_b64 = Base64::encode_string(&pt);
                    print_response(Response::success(
                        serde_json::json!({ "plaintext_b64": pt_b64 }),
                    ));
                }
                Err(e) => print_response(Response::fail(e)),
            }
        }
        other => {
            print_response(Response::fail(format!("unknown command '{other}'")));
        }
    }
}
