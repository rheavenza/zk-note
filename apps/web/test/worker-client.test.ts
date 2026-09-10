/**
 * Web Worker Client End-to-End Integration Tests (ZK-062).
 *
 * Verifies that:
 * 1. Heavy crypto (Argon2id, note encryption/decryption, search) runs in the worker thread.
 * 2. React/UI layer does not own persistent key state.
 * 3. Message protocol handles concurrent requests, broadcast events, and typed errors.
 */

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { VaultWorkerClient, WorkerError } from "../src/worker/client.js";
import { WorkerErrorCode } from "../src/worker/protocol.js";

import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = fs.existsSync(path.resolve(__dirname, "../src/worker/worker.js"))
  ? path.resolve(__dirname, "../src/worker/worker.js")
  : path.resolve(__dirname, "../dist/src/worker/worker.js");

// Fast test KDF parameters JSON
const TEST_KDF_PARAMS_JSON = JSON.stringify({
  algorithm: "argon2id",
  memory_kib: 1024,
  iterations: 1,
  parallelism: 1,
  salt: "AQIDBAUGBwgJCgsMDQ4PEA==",
});

function createTestClient(): { client: VaultWorkerClient; worker: Worker } {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  return { client, worker };
}

test("Vault initialization and status reporting in worker thread", async () => {
  const { client, worker } = createTestClient();
  try {
    const status1 = await client.getStatus();
    assert.equal(status1.isUnlocked, false);

    const initRes = await client.initVault("test-passphrase-alpha", TEST_KDF_PARAMS_JSON);
    assert.ok(initRes.wrappedVaultKey.length > 0);
    assert.ok(initRes.kdfParamsJson.length > 0);
    assert.ok(initRes.wrappedRecoveryKey.length > 0);
    assert.equal(initRes.recoveryPhrase.split("-").length, 9);

    const status2 = await client.getStatus();
    assert.equal(status2.isUnlocked, true);
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Note encryption, decryption, and batch decryption offloaded to worker", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("test-passphrase-notes", TEST_KDF_PARAMS_JSON);

    // 1. Single note encryption & decryption
    const enc = await client.encryptNote(
      "note-001",
      "Meeting Notes",
      "# Discussion\n\nKey cryptographic decisions made.",
      ["work", "crypto"]
    );
    assert.ok(enc.envelopeJson.includes("envelope_version"));

    const dec = await client.decryptNote(enc.envelopeJson);
    assert.equal(dec.id, "note-001");
    assert.equal(dec.title, "Meeting Notes");
    assert.equal(dec.body, "# Discussion\n\nKey cryptographic decisions made.");
    assert.deepEqual(dec.tags, ["crypto", "work"]);

    // 2. Batch decryption
    const enc2 = await client.encryptNote("note-002", "Second Note", "Body 2", ["test"]);
    const batchRes = await client.decryptNotesBatch([
      { id: "note-001", envelopeJson: enc.envelopeJson },
      { id: "note-002", envelopeJson: enc2.envelopeJson },
      { id: "invalid-003", envelopeJson: '{"bad":"json"}' },
    ]);

    assert.equal(batchRes.notes.length, 2);
    assert.equal(batchRes.notes[0]?.id, "note-001");
    assert.equal(batchRes.notes[1]?.id, "note-002");
    assert.equal(batchRes.failed.length, 1);
    assert.equal(batchRes.failed[0]?.id, "invalid-003");
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("In-memory search indexing and querying offloaded to worker", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("search-passphrase", TEST_KDF_PARAMS_JSON);

    await client.indexNote(
      "note-search-1",
      "Rust Architecture Guide",
      "Detailed notes on WebAssembly and Rust shared core components.",
      ["architecture", "rust"],
      "2026-09-10T10:00:00Z"
    );

    await client.indexNote(
      "note-search-2",
      "Database Optimization",
      "Techniques for SQLite indexing and durable cursor advancement.",
      ["sqlite", "perf"],
      "2026-09-10T10:05:00Z"
    );

    // Search query for "webassembly"
    const results1 = await client.search("webassembly");
    assert.equal(results1.length, 1);
    assert.equal(results1[0]?.noteId, "note-search-1");
    assert.ok(results1[0]?.snippet.toLowerCase().includes("webassembly"));

    // Search query for "sqlite"
    const results2 = await client.search("sqlite");
    assert.equal(results2.length, 1);
    assert.equal(results2[0]?.noteId, "note-search-2");

    // Remove from index
    await client.removeFromIndex("note-search-1");
    const resultsAfterRemove = await client.search("webassembly");
    assert.equal(resultsAfterRemove.length, 0);
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Passphrase rewrapping in worker preserves note access", async () => {
  const { client, worker } = createTestClient();
  try {
    const initRes = await client.initVault("old-password-123", TEST_KDF_PARAMS_JSON);
    const enc = await client.encryptNote("note-rewrap", "Secret", "Confidential text", ["safe"]);

    const rewrapRes = await client.rewrapPassphrase("new-password-456", TEST_KDF_PARAMS_JSON);
    assert.ok(rewrapRes.newWrappedVaultKey !== initRes.wrappedVaultKey);

    // Lock vault
    await client.lockVault();
    assert.equal((await client.getStatus()).isUnlocked, false);

    // Unlock with new passphrase succeeds
    await client.unlockVault(
      "new-password-456",
      rewrapRes.newWrappedVaultKey,
      rewrapRes.newKdfParamsJson
    );
    assert.equal((await client.getStatus()).isUnlocked, true);

    const dec = await client.decryptNote(enc.envelopeJson);
    assert.equal(dec.title, "Secret");
    assert.equal(dec.body, "Confidential text");
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Locking vault clears session, fires onLock listener, and fails subsequent crypto", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("lock-test-password", TEST_KDF_PARAMS_JSON);
    const enc = await client.encryptNote("n1", "T", "B", []);

    let lockNotified = false;
    client.onLock(() => {
      lockNotified = true;
    });

    await client.lockVault();
    assert.equal(lockNotified, true);
    assert.equal((await client.getStatus()).isUnlocked, false);

    // Attempting crypto on locked vault must fail closed with VAULT_LOCKED
    await assert.rejects(
      async () => {
        await client.decryptNote(enc.envelopeJson);
      },
      (err: any) => {
        assert.ok(err instanceof WorkerError);
        assert.equal(err.code, WorkerErrorCode.VAULT_LOCKED);
        return true;
      }
    );

    await assert.rejects(
      async () => {
        await client.encryptNote("n2", "T2", "B2", []);
      },
      (err: any) => {
        assert.ok(err instanceof WorkerError);
        assert.equal(err.code, WorkerErrorCode.VAULT_LOCKED);
        return true;
      }
    );
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Unlock with recovery key restores access", async () => {
  const { client, worker } = createTestClient();
  try {
    const initRes = await client.initVault("init-pw", TEST_KDF_PARAMS_JSON);
    const enc = await client.encryptNote("rec-note", "Recovery Test", "Safe text", []);

    await client.lockVault();
    assert.equal((await client.getStatus()).isUnlocked, false);

    await client.unlockWithRecoveryKey(initRes.recoveryPhrase, initRes.wrappedRecoveryKey);
    assert.equal((await client.getStatus()).isUnlocked, true);

    const dec = await client.decryptNote(enc.envelopeJson);
    assert.equal(dec.title, "Recovery Test");
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Wrong passphrase fails closed with DECRYPTION_FAILED", async () => {
  const { client, worker } = createTestClient();
  try {
    const initRes = await client.initVault("correct-pass", TEST_KDF_PARAMS_JSON);
    await client.lockVault();

    await assert.rejects(
      async () => {
        await client.unlockVault("wrong-pass", initRes.wrappedVaultKey, initRes.kdfParamsJson);
      },
      (err: any) => {
        assert.ok(err instanceof WorkerError);
        assert.equal(err.code, WorkerErrorCode.DECRYPTION_FAILED);
        return true;
      }
    );
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Concurrent requests across worker boundary resolve correctly by correlation ID", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("concurrency-pass", TEST_KDF_PARAMS_JSON);

    // Launch 10 simultaneous note encryption requests
    const promises = Array.from({ length: 10 }, (_, i) =>
      client.encryptNote(`c-note-${i}`, `Title ${i}`, `Body content ${i}`, [`tag-${i}`])
    );

    const results = await Promise.all(promises);
    assert.equal(results.length, 10);

    // Launch 10 simultaneous decryption requests
    const decPromises = results.map((res) => client.decryptNote(res.envelopeJson));
    const decResults = await Promise.all(decPromises);

    for (let i = 0; i < 10; i++) {
      assert.equal(decResults[i]?.id, `c-note-${i}`);
      assert.equal(decResults[i]?.title, `Title ${i}`);
      assert.equal(decResults[i]?.body, `Body content ${i}`);
    }
  } finally {
    client.dispose();
    await worker.terminate();
  }
});

test("Security verification: Client object does not expose raw keys or session", async () => {
  const { client, worker } = createTestClient();
  try {
    await client.initVault("security-audit-pass", TEST_KDF_PARAMS_JSON);

    // Inspect client instance properties
    const clientKeys = Object.keys(client);
    for (const key of clientKeys) {
      assert.ok(!key.toLowerCase().includes("vaultkey"));
      assert.ok(!key.toLowerCase().includes("session"));
      assert.ok(!key.toLowerCase().includes("secret"));
    }

    const clientString = JSON.stringify(client);
    assert.ok(!clientString.includes("vault_key"));
    assert.ok(!clientString.includes("WasmVaultSession"));
  } finally {
    client.dispose();
    await worker.terminate();
  }
});
