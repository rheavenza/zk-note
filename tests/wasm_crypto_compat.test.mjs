// Native/WASM cryptographic compatibility test suite (ZK-061).
//
// Verifies complete cross-runtime compatibility between native Rust and WebAssembly:
// 1. Native encrypt -> WASM decrypt
// 2. WASM encrypt -> Native decrypt
// 3. Vault wrapper compatibility (KEK derivation, key wrapping, recovery keys, rewrapping)
// 4. Failure vectors match (wrong passphrase, wrong recovery key, tampered ciphertext,
//    tampered AAD, invalid nonces, unsupported versions, corrupted payloads).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const HARNESS_BIN = path.join(ROOT_DIR, "target/debug/native_compat_harness");
const WASM_JS_PATH = path.join(ROOT_DIR, "crates/zk-wasm/pkg/zk_wasm.js");
const WASM_BG_PATH = path.join(ROOT_DIR, "crates/zk-wasm/pkg/zk_wasm_bg.wasm");

// Ensure native harness is built
if (!fs.existsSync(HARNESS_BIN)) {
    execFileSync("cargo", ["build", "--bin", "native_compat_harness"], { cwd: ROOT_DIR, stdio: "inherit" });
}

// Load WASM module
const zk = await import(WASM_JS_PATH);
const wasmBytes = fs.readFileSync(WASM_BG_PATH);
zk.initSync({ module: wasmBytes });

// Helper to call native harness
function callNative(args, inputJson = null) {
    const opts = { cwd: ROOT_DIR, encoding: "utf8" };
    if (inputJson) {
        opts.input = typeof inputJson === "string" ? inputJson : JSON.stringify(inputJson);
    }
    const proc = spawnSync(HARNESS_BIN, args, opts);
    if (proc.error) {
        throw proc.error;
    }
    try {
        return JSON.parse(proc.stdout.trim());
    } catch (e) {
        throw new Error(`Failed to parse native response: ${proc.stdout} (stderr: ${proc.stderr})`);
    }
}

// Fast test KDF parameters
const TEST_KDF_PARAMS = {
    algorithm: "argon2id",
    memory_kib: 1024,
    iterations: 1,
    parallelism: 1,
    salt: Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex").toString("base64"),
};
const TEST_KDF_PARAMS_JSON = JSON.stringify(TEST_KDF_PARAMS);

const COMMITTED_ENVELOPE_JSON = JSON.stringify({
    envelope_version: 1,
    object_id: "550e8400-e29b-41d4-a716-446655440000",
    object_kind: 1,
    wrapped_key: {
        nonce: "lLxd8RQBi4n85jN61Q6ghaWhtCzK8ckb",
        ciphertext: "SoYpRSkMzujrTYawFLXTw6cN6Wv+RAfvFt2RNgWO0k/qxbXXbu9oXCzLafDBrqZ9",
    },
    payload: {
        nonce: "jTw5RahW+25wlf0T8R2IlAWIf6+RnNNT",
        ciphertext: "UWqjchGFnl2YkNiDrVTQsEgUsh1vkJ1eBAYpADavOn9wccYxKFTHyfTItw==",
    },
});

// ============================================================================
// 1. Native Encrypt -> WASM Decrypt
// ============================================================================

test("Native encrypt -> WASM decrypt (short note)", () => {
    const vkBytes = Buffer.alloc(32, 0x5a);
    const vkB64 = vkBytes.toString("base64");

    const nativeEnc = callNative(["encrypt-note"], {
        vault_key_b64: vkB64,
        object_id: "note-cross-001",
        title: "Native Created Note",
        body: "Hello from native Rust core!",
        tags: ["rust", "wasm", "cross-runtime"],
    });
    assert.ok(nativeEnc.ok, nativeEnc.error);

    const wasmDec = zk.wasm_decrypt_envelope(vkB64, nativeEnc.data.envelope_json);
    assert.equal(wasmDec.id, "note-cross-001");
    assert.equal(wasmDec.title, "Native Created Note");
    assert.equal(wasmDec.body, "Hello from native Rust core!");
    assert.deepEqual(wasmDec.tags, ["cross-runtime", "rust", "wasm"]);
});

test("Native encrypt -> WASM decrypt (large body >64KB)", () => {
    const vkBytes = Buffer.alloc(32, 0x33);
    const vkB64 = vkBytes.toString("base64");
    const largeBody = "Markdown paragraph line.\n".repeat(3000); // ~75 KB

    const nativeEnc = callNative(["encrypt-note"], {
        vault_key_b64: vkB64,
        object_id: "note-large-001",
        title: "Large Note Title",
        body: largeBody,
        tags: ["large", "bulk"],
    });
    assert.ok(nativeEnc.ok, nativeEnc.error);

    const wasmDec = zk.wasm_decrypt_envelope(vkB64, nativeEnc.data.envelope_json);
    assert.equal(wasmDec.id, "note-large-001");
    assert.equal(wasmDec.title, "Large Note Title");
    assert.equal(wasmDec.body, largeBody);
    assert.deepEqual(wasmDec.tags, ["bulk", "large"]);
});

test("Native encrypt -> WASM decrypt (multibyte UTF-8, accents, emojis, Japanese)", () => {
    const vkBytes = Buffer.alloc(32, 0x77);
    const vkB64 = vkBytes.toString("base64");
    const utf8Title = "Notes & Secrets 🔐 — Résumé — 日本語";
    const utf8Body = "Contenu secret avec des caractères spéciaux: é, à, ç, œ, ⚡, 🚀, 🦀, 東京.";

    const nativeEnc = callNative(["encrypt-note"], {
        vault_key_b64: vkB64,
        object_id: "note-utf8-001",
        title: utf8Title,
        body: utf8Body,
        tags: ["sécurité", "日本語", "emoji-🦀"],
    });
    assert.ok(nativeEnc.ok, nativeEnc.error);

    const wasmDec = zk.wasm_decrypt_envelope(vkB64, nativeEnc.data.envelope_json);
    assert.equal(wasmDec.id, "note-utf8-001");
    assert.equal(wasmDec.title, utf8Title);
    assert.equal(wasmDec.body, utf8Body);
    assert.deepEqual(wasmDec.tags, ["emoji-🦀", "sécurité", "日本語"]);
});

test("Native encrypt raw attachment -> WASM decrypt raw", () => {
    const vkBytes = Buffer.alloc(32, 0x12);
    const vkB64 = vkBytes.toString("base64");
    const binaryData = Buffer.alloc(4096);
    for (let i = 0; i < binaryData.length; i++) binaryData[i] = i % 256;

    const nativeEnc = callNative(["encrypt-raw"], {
        vault_key_b64: vkB64,
        object_id: "att-001",
        object_kind: 2,
        plaintext_b64: binaryData.toString("base64"),
    });
    assert.ok(nativeEnc.ok, nativeEnc.error);

    const wasmDecBytes = zk.wasm_decrypt_raw(vkB64, nativeEnc.data.envelope_json);
    assert.deepEqual(Buffer.from(wasmDecBytes), binaryData);
});

test("Static committed envelope v1 vector -> WASM decrypt", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const wasmDecBytes = zk.wasm_decrypt_raw(vkB64, COMMITTED_ENVELOPE_JSON);
    assert.equal(Buffer.from(wasmDecBytes).toString("utf8"), "Hello Zero-Knowledge World!");
});

// ============================================================================
// 2. WASM Encrypt -> Native Decrypt
// ============================================================================

test("WASM encrypt -> Native decrypt (note)", () => {
    const vkBytes = Buffer.alloc(32, 0x88);
    const vkB64 = vkBytes.toString("base64");

    const wasmEnvJson = zk.wasm_encrypt_envelope(
        vkB64,
        "wasm-note-001",
        "WASM Authored Note",
        "Encrypted directly inside the browser WebAssembly core.",
        ["wasm", "zero-knowledge"]
    );

    const nativeDec = callNative(["decrypt-note"], {
        vault_key_b64: vkB64,
        envelope_json: wasmEnvJson,
    });
    assert.ok(nativeDec.ok, nativeDec.error);
    assert.equal(nativeDec.data.id, "wasm-note-001");
    assert.equal(nativeDec.data.title, "WASM Authored Note");
    assert.equal(nativeDec.data.body, "Encrypted directly inside the browser WebAssembly core.");
    assert.deepEqual(nativeDec.data.tags, ["wasm", "zero-knowledge"]);
});

test("WASM encrypt note with CRLF and duplicate tags -> Native decrypt verifies canonicalization", () => {
    const vkBytes = Buffer.alloc(32, 0x44);
    const vkB64 = vkBytes.toString("base64");

    const wasmEnvJson = zk.wasm_encrypt_envelope(
        vkB64,
        "canon-001",
        "Title",
        "Line 1\r\nLine 2\rLine 3\n",
        ["TagB", "taga", "tagb", "  TAGA  "]
    );

    const nativeDec = callNative(["decrypt-note"], {
        vault_key_b64: vkB64,
        envelope_json: wasmEnvJson,
    });
    assert.ok(nativeDec.ok, nativeDec.error);
    // Body newlines canonicalized to \n
    assert.equal(nativeDec.data.body, "Line 1\nLine 2\nLine 3\n");
    // Tags lowercase, deduplicated, sorted
    assert.deepEqual(nativeDec.data.tags, ["taga", "tagb"]);
});

test("WASM encrypt raw attachment -> Native decrypt raw", () => {
    const vkBytes = Buffer.alloc(32, 0x22);
    const vkB64 = vkBytes.toString("base64");
    const rawData = Buffer.from("Binary attachment payload content for testing! 1234567890");

    const wasmEnvJson = zk.wasm_encrypt_raw(vkB64, "raw-wasm-001", 2, rawData);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: wasmEnvJson,
    });
    assert.ok(nativeDec.ok, nativeDec.error);
    assert.equal(Buffer.from(nativeDec.data.plaintext_b64, "base64").toString(), rawData.toString());
});

// ============================================================================
// 3. Vault Wrapper Compatibility
// ============================================================================

test("Argon2id KEK derivation parity (RFC 9106 vector)", () => {
    const rfcSalt = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex").toString("base64");
    const rfcParams = JSON.stringify({
        algorithm: "argon2id",
        memory_kib: 1024,
        iterations: 2,
        parallelism: 1,
        salt: rfcSalt,
    });

    const nativeKek = callNative(["derive-kek", "password", rfcParams]);
    assert.ok(nativeKek.ok, nativeKek.error);

    const wasmKekB64 = zk.wasm_derive_kek("password", rfcParams);
    assert.equal(wasmKekB64, nativeKek.data.kek_b64);

    const kekHex = Buffer.from(wasmKekB64, "base64").toString("hex");
    assert.equal(kekHex, "007f6b258779db1c07dda5ff432b9025b66d7ec395ed9acba7939210b3ed97b8");
});

test("Argon2id KEK derivation parity with random salt", () => {
    const randomSalt = Buffer.from("9f8e7d6c5b4a39281706f5e4d3c2b1a0", "hex").toString("base64");
    const params = JSON.stringify({
        algorithm: "argon2id",
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
        salt: randomSalt,
    });

    const nativeKek = callNative(["derive-kek", "cross-platform-passphrase-77", params]);
    assert.ok(nativeKek.ok, nativeKek.error);

    const wasmKekB64 = zk.wasm_derive_kek("cross-platform-passphrase-77", params);
    assert.equal(wasmKekB64, nativeKek.data.kek_b64);
});

test("Native wrap vault key -> WASM unwrap vault key", () => {
    const vkB64 = Buffer.alloc(32, 0x1a).toString("base64");
    const kekB64 = Buffer.alloc(32, 0x2b).toString("base64");

    const nativeWrapped = callNative(["wrap-key", vkB64, kekB64]);
    assert.ok(nativeWrapped.ok, nativeWrapped.error);

    const wasmUnwrappedVk = zk.wasm_unwrap_key(kekB64, nativeWrapped.data.wrapped_json);
    assert.equal(wasmUnwrappedVk, vkB64);
});

test("WASM wrap vault key -> Native unwrap vault key", () => {
    const vkB64 = Buffer.alloc(32, 0x9c).toString("base64");
    const kekB64 = Buffer.alloc(32, 0x8d).toString("base64");

    const wasmWrappedJson = zk.wasm_wrap_key(kekB64, vkB64);

    const nativeUnwrap = callNative(["unwrap-key", kekB64, wasmWrappedJson]);
    assert.ok(nativeUnwrap.ok, nativeUnwrap.error);
    assert.equal(nativeUnwrap.data.vault_key_b64, vkB64);
});

test("Native init vault -> WASM unlock vault with passphrase and recovery phrase", () => {
    const pass = "native-master-passphrase-999";
    const nativeInit = callNative(["init-vault", pass, TEST_KDF_PARAMS_JSON]);
    assert.ok(nativeInit.ok, nativeInit.error);

    const { wrapped_vault_key, kdf_params_json, wrapped_recovery_key, recovery_phrase, vault_key_b64 } =
        nativeInit.data;

    // 1. WASM unlock via passphrase
    const sessionPass = zk.unlock_vault(pass, wrapped_vault_key, kdf_params_json);
    assert.ok(sessionPass.is_unlocked());

    // Decrypt a note encrypted with native vault key
    const envJson = zk.wasm_encrypt_envelope(vault_key_b64, "n1", "T", "B", ["tag"]);
    const decNotePass = sessionPass.decrypt_note(envJson);
    assert.equal(decNotePass.title, "T");

    // 2. WASM unlock via recovery phrase
    const sessionRec = zk.unlock_with_recovery_key(recovery_phrase, wrapped_recovery_key);
    assert.ok(sessionRec.is_unlocked());
    const decNoteRec = sessionRec.decrypt_note(envJson);
    assert.equal(decNoteRec.title, "T");
});

test("WASM init vault -> Native unlock vault with passphrase and recovery phrase", () => {
    const pass = "wasm-master-passphrase-777";
    const initRes = zk.init_vault_with_params(pass, TEST_KDF_PARAMS_JSON);

    const wrappedVk = initRes.wrapped_vault_key;
    const kdfParams = initRes.kdf_params_json;
    const wrappedRec = initRes.wrapped_recovery_key;
    const recPhrase = initRes.recovery_phrase;

    // 1. Native unlock via passphrase
    const nativePassUnlock = callNative(["unlock-vault", pass, wrappedVk, kdfParams]);
    assert.ok(nativePassUnlock.ok, nativePassUnlock.error);
    const nativeVkB64 = nativePassUnlock.data.vault_key_b64;

    // 2. Native unlock via recovery phrase
    const nativeRecUnlock = callNative(["unlock-recovery", recPhrase, wrappedRec]);
    assert.ok(nativeRecUnlock.ok, nativeRecUnlock.error);
    assert.equal(nativeRecUnlock.data.vault_key_b64, nativeVkB64);

    // Verify session can encrypt and native can decrypt
    const session = initRes.take_session();
    const encNote = session.encrypt_note("w-note-1", "From WASM", "Content", ["w1"]);
    const nativeDec = callNative(["decrypt-note"], {
        vault_key_b64: nativeVkB64,
        envelope_json: encNote,
    });
    assert.ok(nativeDec.ok, nativeDec.error);
    assert.equal(nativeDec.data.title, "From WASM");
});

test("Native init -> WASM rewrap passphrase -> Native unlock with new passphrase & fail old", () => {
    const oldPass = "initial-passphrase-alpha";
    const newPass = "updated-passphrase-beta";

    const nativeInit = callNative(["init-vault", oldPass, TEST_KDF_PARAMS_JSON]);
    assert.ok(nativeInit.ok, nativeInit.error);

    // Unlock in WASM
    const session = zk.unlock_vault(
        oldPass,
        nativeInit.data.wrapped_vault_key,
        nativeInit.data.kdf_params_json
    );

    // Rewrap in WASM
    const rewrapRes = session.rewrap_passphrase_with_params(newPass, TEST_KDF_PARAMS_JSON);
    const newWrappedVk = rewrapRes.new_wrapped_vault_key;
    const newKdfJson = rewrapRes.new_kdf_params_json;

    // Native unlock with new passphrase succeeds
    const nativeNewUnlock = callNative(["unlock-vault", newPass, newWrappedVk, newKdfJson]);
    assert.ok(nativeNewUnlock.ok, nativeNewUnlock.error);
    assert.equal(nativeNewUnlock.data.vault_key_b64, nativeInit.data.vault_key_b64);

    // Native unlock with old passphrase fails closed
    const nativeOldFail = callNative(["unlock-vault", oldPass, newWrappedVk, newKdfJson]);
    assert.equal(nativeOldFail.ok, false);
});

test("WASM init -> Native rewrap passphrase -> WASM unlock with new passphrase & fail old", () => {
    const oldPass = "wasm-init-alpha";
    const newPass = "native-rewrapped-beta";

    const initRes = zk.init_vault_with_params(oldPass, TEST_KDF_PARAMS_JSON);
    const session = initRes.take_session();

    // Unlock native to get VK
    const nativeUnlock = callNative([
        "unlock-vault",
        oldPass,
        initRes.wrapped_vault_key,
        initRes.kdf_params_json,
    ]);
    assert.ok(nativeUnlock.ok, nativeUnlock.error);

    // Native rewraps passphrase
    const nativeRewrap = callNative([
        "rewrap-passphrase",
        nativeUnlock.data.vault_key_b64,
        newPass,
        TEST_KDF_PARAMS_JSON,
    ]);
    assert.ok(nativeRewrap.ok, nativeRewrap.error);

    // WASM unlock with new passphrase succeeds
    const sessionNew = zk.unlock_vault(
        newPass,
        nativeRewrap.data.new_wrapped_vault_key,
        nativeRewrap.data.new_kdf_params_json
    );
    assert.ok(sessionNew.is_unlocked());

    // WASM unlock with old passphrase fails closed
    assert.throws(() => {
        zk.unlock_vault(
            oldPass,
            nativeRewrap.data.new_wrapped_vault_key,
            nativeRewrap.data.new_kdf_params_json
        );
    });
});

// ============================================================================
// 4. Failure Vectors Match (Parity Checks)
// ============================================================================

test("Wrong passphrase fails closed in both native and WASM", () => {
    const initRes = zk.init_vault_with_params("correct-pass", TEST_KDF_PARAMS_JSON);

    // Native fails closed
    const nativeFail = callNative([
        "unlock-vault",
        "wrong-pass",
        initRes.wrapped_vault_key,
        initRes.kdf_params_json,
    ]);
    assert.equal(nativeFail.ok, false);

    // WASM fails closed
    assert.throws(() => {
        zk.unlock_vault("wrong-pass", initRes.wrapped_vault_key, initRes.kdf_params_json);
    });
});

test("Wrong recovery key fails closed in both native and WASM", () => {
    const init1 = zk.init_vault_with_params("pass1", TEST_KDF_PARAMS_JSON);
    const init2 = zk.init_vault_with_params("pass2", TEST_KDF_PARAMS_JSON);

    // Use recovery phrase of vault 2 on wrapped recovery key of vault 1
    const nativeFail = callNative([
        "unlock-recovery",
        init2.recovery_phrase,
        init1.wrapped_recovery_key,
    ]);
    assert.equal(nativeFail.ok, false);

    assert.throws(() => {
        zk.unlock_with_recovery_key(init2.recovery_phrase, init1.wrapped_recovery_key);
    });
});

test("Corrupted recovery phrase checksum fails closed in both native and WASM", () => {
    const initRes = zk.init_vault_with_params("pass", TEST_KDF_PARAMS_JSON);
    const corruptedPhrase = initRes.recovery_phrase.slice(0, -2) + "00";

    const nativeFail = callNative([
        "unlock-recovery",
        corruptedPhrase,
        initRes.wrapped_recovery_key,
    ]);
    assert.equal(nativeFail.ok, false);

    assert.throws(() => {
        zk.unlock_with_recovery_key(corruptedPhrase, initRes.wrapped_recovery_key);
    });
});

test("Tampered ciphertext (single bit flip) fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    const ctBuf = Buffer.from(envelope.payload.ciphertext, "base64");
    ctBuf[0] ^= 0x01; // flip 1 bit
    envelope.payload.ciphertext = ctBuf.toString("base64");
    const tamperedJson = JSON.stringify(envelope);

    // Native fails closed
    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    // WASM fails closed
    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Tampered AAD (object_id altered) fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    envelope.object_id = "550e8400-e29b-41d4-a716-446655440999";
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Tampered AAD (object_kind altered) fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    envelope.object_kind = 2; // altered from NOTE(1) to ATTACHMENT(2)
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Tampered AAD (envelope_version altered to 2) fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    envelope.envelope_version = 2;
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Corrupted nonce fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    const nonceBuf = Buffer.from(envelope.payload.nonce, "base64");
    nonceBuf[0] ^= 0x01; // flip 1 bit in nonce
    envelope.payload.nonce = nonceBuf.toString("base64");
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Truncated nonce fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    envelope.payload.nonce = Buffer.alloc(12).toString("base64"); // 12 bytes instead of 24
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Corrupted base64 payload fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const envelope = JSON.parse(COMMITTED_ENVELOPE_JSON);
    envelope.payload.ciphertext = "!!!NotBase64!!!";
    const tamperedJson = JSON.stringify(envelope);

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: tamperedJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, tamperedJson);
    });
});

test("Malformed JSON payload fails closed in both native and WASM", () => {
    const vkBytes = Buffer.alloc(32, 0x42);
    const vkB64 = vkBytes.toString("base64");

    const brokenJson = "{ invalid json string ";

    const nativeDec = callNative(["decrypt-raw"], {
        vault_key_b64: vkB64,
        envelope_json: brokenJson,
    });
    assert.equal(nativeDec.ok, false);

    assert.throws(() => {
        zk.wasm_decrypt_raw(vkB64, brokenJson);
    });
});
