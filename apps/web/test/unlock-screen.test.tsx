/**
 * Unlock Screen and Vault Context Tests (ZK-064).
 *
 * Verifies:
 * 1. Passphrase remains client-side (no network transmission, masked inputs).
 * 2. Clear locked/unlocked state machine transitions (UNINITIALIZED, LOCKED, UNLOCKING, UNLOCKED).
 * 3. Failure does not reveal sensitive detail (sanitized generic errors, no key leaks).
 * 4. End-to-end integration with worker and encrypted storage.
 */

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import fs from "node:fs";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToString } from "react-dom/server";

import "fake-indexeddb/auto";
import {
  VaultProvider,
  useVault,
  VaultContextType,
  VaultBootstrapData,
  UnlockScreen,
  LockVaultButton,
  VaultStatusBadge,
  SecurityRecoveryModal,
} from "../src/index.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient, WorkerError } from "../src/worker/client.js";
import { WorkerErrorCode } from "../src/worker/protocol.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = fs.existsSync(path.resolve(__dirname, "../src/worker/worker.js"))
  ? path.resolve(__dirname, "../src/worker/worker.js")
  : path.resolve(__dirname, "../dist/src/worker/worker.js");

const TEST_KDF_PARAMS = JSON.stringify({
  algorithm: "argon2id",
  memory_kib: 1024,
  iterations: 1,
  parallelism: 1,
  salt: "AQIDBAUGBwgJCgsMDQ4PEA==",
});

function createMockClient(options: {
  isUnlocked?: boolean;
  shouldFailUnlock?: boolean;
  failErrorCode?: WorkerErrorCode;
} = {}) {
  let unlocked = options.isUnlocked ?? false;
  const lockListeners: Array<() => void> = [];

  const mock: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: unlocked, sessionInitialized: true }),
    initVault: async (_passphrase: string) => {
      unlocked = true;
      return {
        wrappedVaultKey: JSON.stringify({ v: 1, ct: "mock-wrapped-vault-key" }),
        kdfParamsJson: TEST_KDF_PARAMS,
        wrappedRecoveryKey: JSON.stringify({ v: 1, ct: "mock-wrapped-recovery-key" }),
        recoveryPhrase: "11111111-22222222-33333333-44444444-55555555-66666666-77777777-88888888-99999999",
      };
    },
    unlockVault: async (passphrase: string) => {
      if (options.shouldFailUnlock || passphrase !== "correct-passphrase") {
        throw new WorkerError(
          options.failErrorCode ?? WorkerErrorCode.DECRYPTION_FAILED,
          "AEAD decryption tag mismatch / invalid key"
        );
      }
      unlocked = true;
      return { success: true };
    },
    unlockWithRecoveryKey: async (recoveryPhrase: string) => {
      if (options.shouldFailUnlock || !recoveryPhrase.startsWith("11111111")) {
        throw new WorkerError(
          options.failErrorCode ?? WorkerErrorCode.INVALID_RECOVERY_KEY,
          "Recovery key checksum mismatch"
        );
      }
      unlocked = true;
      return { success: true };
    },
    rewrapPassphrase: async (_newPassphrase: string) => {
      return {
        newWrappedVaultKey: JSON.stringify({ v: 1, ct: "mock-rewrapped-key" }),
        newKdfParamsJson: TEST_KDF_PARAMS,
      };
    },
    lockVault: async () => {
      unlocked = false;
      for (const cb of lockListeners) cb();
      return { success: true };
    },
    onLock: (cb: () => void) => {
      lockListeners.push(cb);
      return () => {
        const idx = lockListeners.indexOf(cb);
        if (idx >= 0) lockListeners.splice(idx, 1);
      };
    },
    dispose: () => {},
  };

  return {
    client: mock as VaultWorkerClient,
    fireLockBroadcast: () => lockListeners.forEach((cb) => cb()),
    isUnlocked: () => unlocked,
  };
}

test("UnlockScreen renders uninitialized state when vault has no bootstrap data", async () => {
  const { client } = createMockClient({ isUnlocked: false });
  const storage = new IndexedDbStorage("test-db-uninit");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <UnlockScreen />
    </VaultProvider>
  );

  // Must render Create Vault form
  assert.ok(html.includes("Create Your Vault"));
  // Passphrase inputs must strictly be type="password"
  assert.ok(html.includes('type="password"'));
  assert.ok(html.includes('id="create-passphrase"'));
  assert.ok(html.includes('id="confirm-passphrase"'));
  assert.ok(html.includes("Create Vault"));
  // Plaintext secrets or keys must not be present
  assert.ok(!html.includes("mock-wrapped-vault-key"));
});

test("UnlockScreen renders locked state when bootstrap data exists", async () => {
  const { client } = createMockClient({ isUnlocked: false });
  const storage = new IndexedDbStorage("test-db-locked");
  const bootstrap: VaultBootstrapData = {
    wrappedVaultKey: "mock-key",
    kdfParamsJson: TEST_KDF_PARAMS,
    wrappedRecoveryKey: "mock-recovery",
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={bootstrap}>
      <UnlockScreen />
    </VaultProvider>
  );

  // Must render Unlock Vault form
  assert.ok(html.includes("Unlock Vault"));
  assert.ok(html.includes("Passphrase"));
  assert.ok(html.includes("Recovery Key"));
  assert.ok(html.includes('id="unlock-passphrase"'));
  assert.ok(html.includes('type="password"'));
});

test("UnlockScreen renders unlocked state or children when unlocked", async () => {
  const { client } = createMockClient({ isUnlocked: true });
  const storage = new IndexedDbStorage("test-db-unlocked");
  const bootstrap: VaultBootstrapData = {
    wrappedVaultKey: "mock-key",
    kdfParamsJson: TEST_KDF_PARAMS,
    wrappedRecoveryKey: "mock-recovery",
  };

  // 1. Without children -> renders default unlocked status and lock button
  const htmlDefault = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={bootstrap}>
      <UnlockScreen />
    </VaultProvider>
  );
  assert.ok(htmlDefault.length > 0);

  // Helper component to test children rendering in provider
  const UnlockedInspector: React.FC = () => {
    const { lock } = useVault();
    return (
      <div>
        <span className="unlocked-text">Notes Workspace Decrypted</span>
        <button onClick={lock} id="test-lock-btn">
          Lock
        </button>
      </div>
    );
  };

  const htmlWithChildren = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={bootstrap}>
      <UnlockedInspector />
    </VaultProvider>
  );
  assert.ok(htmlWithChildren.includes("Notes Workspace Decrypted"));
});

test("VaultStatusBadge and LockVaultButton reflect vault states", async () => {
  const { client } = createMockClient({ isUnlocked: false });
  const storage = new IndexedDbStorage("test-db-badge");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <VaultStatusBadge />
      <LockVaultButton />
    </VaultProvider>
  );

  assert.ok(html.includes("Setup Needed"));
  // Lock button must not render when locked or uninitialized
  assert.ok(!html.includes("Lock Vault"));
});

test("VaultContext state machine: initVault, unlock, lock, and error sanitization", async () => {
  const { client, fireLockBroadcast } = createMockClient({ isUnlocked: false });
  const storage = new IndexedDbStorage("test-db-context");

  let ctxRef: VaultContextType | null = null;
  const Consumer: React.FC = () => {
    ctxRef = useVault();
    return <div>Consumer</div>;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <Consumer />
    </VaultProvider>
  );

  assert.ok(ctxRef !== null);
  const ctx = ctxRef as VaultContextType;
  assert.equal(ctx.vaultState, "UNINITIALIZED");
  assert.equal(ctx.error, null);

  // 1. Initialize vault
  const initResult = await ctx.initVault("my-secure-passphrase");
  assert.equal(
    initResult.recoveryPhrase,
    "11111111-22222222-33333333-44444444-55555555-66666666-77777777-88888888-99999999"
  );
  assert.equal(ctx.vaultState, "UNLOCKED");
  assert.ok(ctx.bootstrap !== null);

  // 2. Lock vault
  await ctx.lock();
  assert.equal(ctx.vaultState, "LOCKED");

  // 3. Unlock with incorrect passphrase -> Sanitized error, no leak of AEAD tag mismatch
  await assert.rejects(
    async () => {
      await ctx.unlockWithPassphrase("wrong-passphrase");
    },
    (err: Error) => {
      // Must be sanitized generic error message
      assert.equal(err.message, "Incorrect passphrase or invalid recovery key.");
      // MUST NOT contain internal cipher error details
      assert.ok(!err.message.includes("AEAD"));
      assert.ok(!err.message.includes("tag mismatch"));
      return true;
    }
  );
  assert.equal(ctx.vaultState, "LOCKED");
  assert.equal(ctx.error, "Incorrect passphrase or invalid recovery key.");

  // Clear error
  ctx.clearError();
  assert.equal(ctx.error, null);

  // 4. Unlock with correct passphrase -> Transitions to UNLOCKED
  await ctx.unlockWithPassphrase("correct-passphrase");
  assert.equal(ctx.vaultState, "UNLOCKED");

  // 5. Worker lock broadcast event triggers lock in UI
  fireLockBroadcast();
  assert.equal(ctx.vaultState, "LOCKED");

  // 6. Unlock with recovery key
  await ctx.unlockWithRecoveryKey(
    "11111111-22222222-33333333-44444444-55555555-66666666-77777777-88888888-99999999"
  );
  assert.equal(ctx.vaultState, "UNLOCKED");
});

test("Security: Passphrase and recovery key inputs never contain plain text in attributes", () => {
  const { client } = createMockClient({ isUnlocked: false });
  const storage = new IndexedDbStorage("test-db-sec");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <UnlockScreen />
    </VaultProvider>
  );

  // Verify attributes
  assert.ok(html.includes('type="password"'));
  assert.ok(html.includes('autoComplete="new-password"'));
  assert.ok(html.includes('spellCheck="false"'));
  // Verify no default test credentials or sensitive data are embedded
  assert.ok(!html.includes("my-secure-passphrase"));
  assert.ok(!html.includes("correct-passphrase"));
});

test("End-to-end integration: VaultProvider with real Worker thread", async () => {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  const storage = new IndexedDbStorage("test-db-e2e");

  try {
    let ctxRef: VaultContextType | null = null;
    const Consumer: React.FC = () => {
      ctxRef = useVault();
      return <div>Consumer</div>;
    };

    renderToString(
      <VaultProvider client={client} storage={storage} initialBootstrap={null}>
        <Consumer />
      </VaultProvider>
    );

    assert.ok(ctxRef !== null);
    const ctx = ctxRef as VaultContextType;
    assert.equal(ctx.vaultState, "UNINITIALIZED");

    // Initialize vault via worker with real WASM
    const initRes = await ctx.initVault("master-passphrase-999", TEST_KDF_PARAMS);
    assert.ok(initRes.recoveryPhrase.split("-").length === 9);
    assert.equal(ctx.vaultState, "UNLOCKED");
    assert.ok(ctx.bootstrap !== null);

    // Lock vault
    await ctx.lock();
    assert.equal(ctx.vaultState, "LOCKED");

    // Attempt unlock with wrong passphrase -> fails closed with sanitized error
    await assert.rejects(
      async () => {
        await ctx.unlockWithPassphrase("wrong-passphrase");
      },
      (err: Error) => {
        assert.equal(err.message, "Incorrect passphrase or invalid recovery key.");
        return true;
      }
    );
    assert.equal(ctx.vaultState, "LOCKED");

    // Unlock with valid passphrase -> succeeds
    await ctx.unlockWithPassphrase("master-passphrase-999");
    assert.equal(ctx.vaultState, "UNLOCKED");

    // Lock again and unlock with valid recovery key -> succeeds
    await ctx.lock();
    assert.equal(ctx.vaultState, "LOCKED");

    await ctx.unlockWithRecoveryKey(initRes.recoveryPhrase);
    assert.equal(ctx.vaultState, "UNLOCKED");
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.close();
  }
});

test("Security & Recovery: Recovery warnings and passphrase rewrap lifecycle (ZK-073)", async () => {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  const storage = new IndexedDbStorage("test-db-recovery-ux");

  try {
    let ctxRef: VaultContextType | null = null;
    const Consumer: React.FC = () => {
      ctxRef = useVault();
      return <div>Consumer</div>;
    };

    renderToString(
      <VaultProvider client={client} storage={storage} initialBootstrap={null}>
        <Consumer />
      </VaultProvider>
    );

    const ctx = ctxRef! as VaultContextType;
    const initRes = await ctx.initVault("initial-passphrase-abc", TEST_KDF_PARAMS);
    const recoveryKey = initRes.recoveryPhrase;

    // Encrypt note under current VaultKey
    const encRes = await client.encryptNote(
      "note-recovery-1",
      "Confidential Note",
      "Top secret content that must survive recovery and rewrapping.",
      ["secret"]
    );

    // 1. Rewrap passphrase
    await ctx.rewrapPassphrase("new-passphrase-xyz", TEST_KDF_PARAMS);

    // 2. Lock vault
    await ctx.lock();
    assert.equal(ctx.vaultState, "LOCKED");

    // 3. Old passphrase fails closed
    await assert.rejects(
      async () => {
        await ctx.unlockWithPassphrase("initial-passphrase-abc");
      },
      (err: Error) => {
        assert.equal(err.message, "Incorrect passphrase or invalid recovery key.");
        return true;
      }
    );

    // 4. New passphrase unlocks successfully
    await ctx.unlockWithPassphrase("new-passphrase-xyz");
    assert.equal(ctx.vaultState, "UNLOCKED");

    // 5. Existing note remains decryptable (VaultKey unchanged)
    const decRes = await client.decryptNote(encRes.envelopeJson);
    assert.equal(decRes.title, "Confidential Note");
    assert.equal(decRes.body, "Top secret content that must survive recovery and rewrapping.");
    assert.deepEqual(decRes.tags, ["secret"]);

    // 6. Lock and verify recovery key still unlocks and decrypts
    await ctx.lock();
    await ctx.unlockWithRecoveryKey(recoveryKey);
    assert.equal(ctx.vaultState, "UNLOCKED");
    const decRes2 = await client.decryptNote(encRes.envelopeJson);
    assert.equal(decRes2.title, "Confidential Note");
    assert.equal(decRes2.body, "Top secret content that must survive recovery and rewrapping.");
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.close();
  }
});

test("SecurityRecoveryModal renders security guarantees, invariants, and warnings (ZK-073)", () => {
  const { client } = createMockClient({ isUnlocked: true });
  const storage = new IndexedDbStorage("test-db-modal");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SecurityRecoveryModal isOpen={true} onClose={() => {}} />
    </VaultProvider>
  );

  // Verifies zero-knowledge warning
  assert.ok(html.includes("Zero-Knowledge Architecture Warning"));
  assert.ok(html.includes("exclusively encrypted ciphertext"));
  assert.ok(html.includes("mathematically impossible"));

  // Verifies recovery invariants
  assert.ok(html.includes("Recovery Key Invariants"));
  assert.ok(html.includes("Single Vault Key"));
  assert.ok(html.includes("Passphrase Rotation"));

  // Verifies tabs
  assert.ok(html.includes("Security Guarantees"));
  assert.ok(html.includes("Change Passphrase"));
});

