import test from "node:test";
import assert from "node:assert/strict";
import { renderToString } from "react-dom/server";
import {
  VaultBootstrapDto,
  VaultBootstrapData,
  toVaultBootstrapDto,
  fromVaultBootstrapDto,
  areBootstrapsEqual,
  readVaultLink,
  writeVaultLink,
  clearVaultLink,
  linkLocalVaultToAccount,
  restoreVaultFromAccount,
  assertNoPlaintextSecrets,
  WrongAccountError,
  OriginMismatchError,
  CorruptedVaultLinkError,
  VaultLinkError,
  MismatchedVaultError,
  ExistingLocalVaultError,
  VAULT_LINK_STORAGE_KEY,
} from "../src/auth/vault-link.js";
import { AuthProvider } from "../src/context/AuthContext.js";
import { VaultProvider, VaultStore, persistBootstrap } from "../src/context/VaultContext.js";
import { AuthControls } from "../src/components/AuthControls.js";
import { UnlockScreen } from "../src/components/UnlockScreen.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient } from "../src/worker/client.js";
import "fake-indexeddb/auto";

// Sample fixture data
const sampleBootstrapDto: VaultBootstrapDto = {
  crypto_version: 1,
  kdf: {
    algorithm: "argon2id",
    salt: "cmFuZG9tLXNhbHQtMTZieXRlcw==",
    memory_kib: 65536,
    iterations: 3,
    parallelism: 1,
  },
  wrapped_vault_key: {
    cipher_suite: "xchacha20poly1305",
    nonce: "dGhpcyBpcyBhIDI0LWJ5dGUgbm9uY2U=",
    ciphertext: "d3JhcHBlZCB2YXVsdCBrZXkgY2lwaGVydGV4dA==",
  },
  recovery_wrapped_vault_key: {
    cipher_suite: "xchacha20poly1305",
    nonce: "cmVjb3ZlcnkgMjQtYnl0ZSBub25jZQ==",
    ciphertext: "cmVjb3Zlcnkgd3JhcHBlZCB2YXVsdCBrZXk=",
  },
};

const sampleBootstrapData: VaultBootstrapData = fromVaultBootstrapDto(sampleBootstrapDto);

const differingBootstrapDto: VaultBootstrapDto = {
  ...sampleBootstrapDto,
  wrapped_vault_key: {
    ...sampleBootstrapDto.wrapped_vault_key,
    ciphertext: "ZGlmZmVyZW50IHZhdWx0IGtleSBjaXBoZXJ0ZXh0",
  },
};

const differingBootstrapData: VaultBootstrapData = fromVaultBootstrapDto(differingBootstrapDto);

import path from "node:path";
import fs from "node:fs";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";

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

function createMockStorage(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => {
      map.set(k, v);
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
    clear: () => {
      map.clear();
    },
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    length: map.size,
  };
}

function createThrowingStorage(failingMethod: "getItem" | "setItem" | "removeItem" | "both" | "all" = "setItem"): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => {
      if (failingMethod === "getItem" || failingMethod === "all") {
        throw new Error("SecurityError: Access to localStorage is denied");
      }
      return map.get(k) ?? null;
    },
    setItem: (k: string, v: string) => {
      if (failingMethod === "setItem" || failingMethod === "both" || failingMethod === "all") {
        throw new Error("QuotaExceededError: LocalStorage quota exceeded");
      }
      map.set(k, v);
    },
    removeItem: (k: string) => {
      if (failingMethod === "removeItem" || failingMethod === "both" || failingMethod === "all") {
        throw new Error("StorageError: Failed to remove item");
      }
      map.delete(k);
    },
    clear: () => map.clear(),
    key: (_i: number) => null,
    length: 0,
  };
}

function createMockClient(): VaultWorkerClient {
  return {
    onLock: () => () => {},
    getStatus: async () => ({ isUnlocked: false }),
    dispose: () => {},
  } as any;
}

test("areBootstrapsEqual: field-by-field equality and detection of differences", () => {
  assert.equal(areBootstrapsEqual(sampleBootstrapData, sampleBootstrapData), true);
  assert.equal(areBootstrapsEqual(sampleBootstrapDto, sampleBootstrapData), true);
  assert.equal(areBootstrapsEqual(sampleBootstrapData, differingBootstrapData), false);

  const tamperedKdf: VaultBootstrapData = {
    ...sampleBootstrapData,
    kdfParamsJson: JSON.stringify({ ...sampleBootstrapDto.kdf, iterations: 4 }),
  };
  assert.equal(areBootstrapsEqual(sampleBootstrapData, tamperedKdf), false);
});

test("assertNoPlaintextSecrets: strictly blocks plaintext or passphrase fields (SEC-001/SEC-002)", () => {
  assert.doesNotThrow(() => assertNoPlaintextSecrets(sampleBootstrapDto));
  assert.doesNotThrow(() => assertNoPlaintextSecrets({ crypto_version: 1, safe_field: "value" }));

  assert.throws(
    () => assertNoPlaintextSecrets({ passphrase: "super-secret-password" }),
    /forbidden key 'passphrase'/
  );
  assert.throws(
    () => assertNoPlaintextSecrets({ nested: { vault_passphrase: "secret" } }),
    /forbidden key 'vault_passphrase'/
  );
  assert.throws(
    () => assertNoPlaintextSecrets({ master_key: "raw-bytes" }),
    /forbidden key 'master_key'/
  );
  assert.throws(
    () => assertNoPlaintextSecrets({ plaintext: "my secret note" }),
    /forbidden key 'plaintext'/
  );
  assert.throws(
    () => assertNoPlaintextSecrets({ recovery_phrase: "word-word-word" }),
    /forbidden key 'recovery_phrase'/
  );
});

test("toVaultBootstrapDto & fromVaultBootstrapDto round-trip cleanly", () => {
  const dto = toVaultBootstrapDto(sampleBootstrapData);
  assert.deepEqual(dto, sampleBootstrapDto);
  const data = fromVaultBootstrapDto(dto);
  assert.equal(areBootstrapsEqual(data, sampleBootstrapData), true);
});

test("readVaultLink, writeVaultLink, and clearVaultLink manage association without secret leaks", () => {
  const storage = createMockStorage();
  assert.equal(readVaultLink(storage), null);

  const link = {
    accountId: "acc-12345",
    serverOrigin: "https://notes.example.com",
    linkedAt: new Date().toISOString(),
  };

  writeVaultLink(storage, link);
  const loaded = readVaultLink(storage);
  assert.deepEqual(loaded, link);

  // SEC-001: Inspect raw storage string to ensure zero passwords or keys
  const rawStored = storage.getItem(VAULT_LINK_STORAGE_KEY)!;
  assert.match(rawStored, /acc-12345/);
  assert.doesNotMatch(rawStored, /passphrase|password|vault_key|secret/i);

  clearVaultLink(storage);
  assert.equal(readVaultLink(storage), null);
});

test("readVaultLink: fails closed when getItem throws with STORAGE_ERROR", () => {
  const throwingStorage = createThrowingStorage("getItem");

  assert.throws(
    () => readVaultLink(throwingStorage),
    (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
  );
});

test("readVaultLink: fails closed on corrupted/malformed stored link data", () => {
  const storage = createMockStorage();

  // Invalid JSON
  storage.setItem(VAULT_LINK_STORAGE_KEY, "{ not-valid-json");
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );

  // Not an object (e.g. array or primitive)
  storage.setItem(VAULT_LINK_STORAGE_KEY, "[\"account-1\", \"https://example.com\"]");
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );

  // Missing accountId
  storage.setItem(VAULT_LINK_STORAGE_KEY, JSON.stringify({ serverOrigin: "https://notes.example.com" }));
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );

  // Missing serverOrigin
  storage.setItem(VAULT_LINK_STORAGE_KEY, JSON.stringify({ accountId: "acc-1" }));
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );

  // Invalid serverOrigin URL (e.g. malformed URL or URL containing path)
  storage.setItem(VAULT_LINK_STORAGE_KEY, JSON.stringify({ accountId: "acc-1", serverOrigin: "not a valid url" }));
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );

  storage.setItem(VAULT_LINK_STORAGE_KEY, JSON.stringify({ accountId: "acc-1", serverOrigin: "https://notes.example.com/subpath" }));
  assert.throws(
    () => readVaultLink(storage),
    (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
  );
});

test("linkLocalVaultToAccount: fails closed before network activity when storage read throws or link is corrupted", async () => {
  const oldFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = (async () => {
    fetchCalled = true;
    throw new Error("Network must not be called when storage read fails");
  }) as unknown as typeof fetch;

  try {
    // 1. Storage read throws
    const throwingStorage = createThrowingStorage("getItem");
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: sampleBootstrapData,
        storage: throwingStorage,
      }),
      (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
    );
    assert.equal(fetchCalled, false, "Fetch must not be called when getItem throws");

    // 2. Storage has corrupted data
    const corruptStorage = createMockStorage();
    corruptStorage.setItem(VAULT_LINK_STORAGE_KEY, "{ malformed");
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: sampleBootstrapData,
        storage: corruptStorage,
      }),
      (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
    );
    assert.equal(fetchCalled, false, "Fetch must not be called when link is corrupted");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("restoreVaultFromAccount: fails closed before network activity when storage read throws or link is corrupted", async () => {
  const oldFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = (async () => {
    fetchCalled = true;
    throw new Error("Network must not be called when storage read fails");
  }) as unknown as typeof fetch;

  try {
    // 1. Storage read throws (both with localBootstrap and null)
    const throwingStorage = createThrowingStorage("getItem");
    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: sampleBootstrapData,
        storage: throwingStorage,
      }),
      (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
    );
    assert.equal(fetchCalled, false);

    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: null,
        storage: throwingStorage,
      }),
      (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
    );
    assert.equal(fetchCalled, false);

    // 2. Storage has corrupted data
    const corruptStorage = createMockStorage();
    corruptStorage.setItem(VAULT_LINK_STORAGE_KEY, "invalid-json");
    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: sampleBootstrapData,
        storage: corruptStorage,
      }),
      (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
    );
    assert.equal(fetchCalled, false);

    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-1",
        localBootstrap: null,
        storage: corruptStorage,
      }),
      (err: any) => err instanceof CorruptedVaultLinkError && err.code === "CORRUPT_VAULT_LINK"
    );
    assert.equal(fetchCalled, false);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("VaultStore: captures error when stored vault link read fails on init", () => {
  const corruptStorage = createMockStorage();
  corruptStorage.setItem(VAULT_LINK_STORAGE_KEY, "invalid-json");

  const client = createMockClient();
  const storage = new IndexedDbStorage("test_corrupt_link_db");

  const store = new VaultStore(client, storage, null, undefined, undefined, corruptStorage);

  assert.equal(store.getState().vaultLink, null);
  assert.match(store.getState().error || "", /Corrupted vault link association/);

  store.dispose();
});

test("linkLocalVaultToAccount: first upload uploads only encrypted bootstrap and allowed metadata", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;
  let getCalled = false;
  let postCalled = false;
  let postBody: any = null;
  let authHeader: string | null = null;

  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    authHeader = (init?.headers as any)?.Authorization || null;
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "GET") {
      getCalled = true;
      return { status: 404, ok: false, json: async () => ({ code: "OBJECT_NOT_FOUND" }) };
    }
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "POST") {
      postCalled = true;
      postBody = JSON.parse(init?.body as string);
      return { status: 201, ok: true, json: async () => postBody };
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  }) as unknown as typeof fetch;

  try {
    const result = await linkLocalVaultToAccount({
      serverOrigin: "https://notes.example.com",
      token: "valid-bearer-token",
      accountId: "acc-user-1",
      localBootstrap: sampleBootstrapData,
      storage,
    });

    assert.equal(result.status, "linked");
    assert.equal(getCalled, true);
    assert.equal(postCalled, true);
    assert.equal(authHeader, "Bearer valid-bearer-token");

    // SEC-001 / SEC-002: Inspect postBody
    assert.equal(postBody.crypto_version, 1);
    assert.ok(postBody.kdf);
    assert.ok(postBody.wrapped_vault_key);
    assert.ok(postBody.recovery_wrapped_vault_key);

    // Verify absence of plaintext secrets in payload
    assertNoPlaintextSecrets(postBody);
    const bodyStr = JSON.stringify(postBody);
    assert.doesNotMatch(bodyStr, /passphrase|password|plaintext|recoveryphrase|"vault_key"/i);

    // Verify storage has link record
    const savedLink = readVaultLink(storage);
    assert.equal(savedLink?.accountId, "acc-user-1");
    assert.equal(savedLink?.serverOrigin, "https://notes.example.com");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("linkLocalVaultToAccount: idempotent retry when server returns 409 and remote matches local", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;
  let postCount = 0;
  let getCount = 0;

  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "GET") {
      getCount++;
      if (getCount === 1) {
        // Initial check returns 404
        return { status: 404, ok: false, json: async () => ({ code: "OBJECT_NOT_FOUND" }) };
      }
      // Re-check after 409 returns matching bootstrap
      return { status: 200, ok: true, json: async () => sampleBootstrapDto };
    }
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "POST") {
      postCount++;
      // Simulate race condition / lost response
      return { status: 409, ok: false, json: async () => ({ code: "VAULT_ALREADY_EXISTS" }) };
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  }) as unknown as typeof fetch;

  try {
    const result = await linkLocalVaultToAccount({
      serverOrigin: "https://notes.example.com",
      token: "token-abc",
      accountId: "acc-user-1",
      localBootstrap: sampleBootstrapData,
      storage,
    });

    assert.equal(result.status, "linked");
    assert.equal(postCount, 1);
    assert.equal(getCount, 2);

    const savedLink = readVaultLink(storage);
    assert.equal(savedLink?.accountId, "acc-user-1");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("linkLocalVaultToAccount: mismatched remote bootstrap stops non-destructively", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "GET") {
      // Remote account already contains a DIFFERENT bootstrap
      return { status: 200, ok: true, json: async () => differingBootstrapDto };
    }
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "POST") {
      assert.fail("POST should not be called when remote mismatch is detected");
    }
    throw new Error(`Unexpected fetch URL: ${url}`);
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "token-abc",
        accountId: "acc-user-1",
        localBootstrap: sampleBootstrapData,
        storage,
      }),
      (err: any) => err instanceof MismatchedVaultError
    );

    // Link record must NOT be written
    assert.equal(readVaultLink(storage), null);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("linkLocalVaultToAccount: wrong account state stops non-destructively", async () => {
  const storage = createMockStorage();
  // Pre-existing link to account "acc-first"
  writeVaultLink(storage, {
    accountId: "acc-first",
    serverOrigin: "https://notes.example.com",
    linkedAt: new Date().toISOString(),
  });

  const oldFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    assert.fail("No network calls should occur when wrong account is detected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "token-second",
        accountId: "acc-second",
        localBootstrap: sampleBootstrapData,
        storage,
      }),
      (err: any) => err instanceof WrongAccountError && err.linkedAccountId === "acc-first"
    );

    // Existing link to acc-first preserved
    assert.equal(readVaultLink(storage)?.accountId, "acc-first");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("linkLocalVaultToAccount: network failure preserves unlinked local state", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "GET") {
      return { status: 404, ok: false, json: async () => ({ code: "OBJECT_NOT_FOUND" }) };
    }
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "POST") {
      throw new Error("Network connection lost");
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "token-net",
        accountId: "acc-net",
        localBootstrap: sampleBootstrapData,
        storage,
      }),
      /Network connection lost/
    );

    assert.equal(readVaultLink(storage), null);
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("restoreVaultFromAccount: second browser fetches remote bootstrap and associates link", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    if (url.endsWith("/v1/vault/bootstrap") && init?.method === "GET") {
      return { status: 200, ok: true, json: async () => sampleBootstrapDto };
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    const result = await restoreVaultFromAccount({
      serverOrigin: "https://notes.example.com",
      token: "token-browser2",
      accountId: "acc-browser2",
      localBootstrap: null,
      storage,
    });

    assert.equal(areBootstrapsEqual(result.bootstrap, sampleBootstrapData), true);
    assert.equal(result.link.accountId, "acc-browser2");
    assert.equal(readVaultLink(storage)?.accountId, "acc-browser2");
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("restoreVaultFromAccount: fails non-destructively if differing local vault exists", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string) => {
    if (url.endsWith("/v1/vault/bootstrap")) {
      return { status: 200, ok: true, json: async () => differingBootstrapDto };
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "token-browser1",
        accountId: "acc-user",
        localBootstrap: sampleBootstrapData,
        storage,
      }),
      (err: any) => err instanceof ExistingLocalVaultError
    );
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("restoreVaultFromAccount: fails if remote vault does not exist (404)", async () => {
  const storage = createMockStorage();
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string) => {
    if (url.endsWith("/v1/vault/bootstrap")) {
      return { status: 404, ok: false, json: async () => ({ code: "OBJECT_NOT_FOUND" }) };
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "token-browser2",
        accountId: "acc-novault",
        localBootstrap: null,
        storage,
      }),
      /No vault found/
    );
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("End-to-End: restore remote bootstrap into real Web Worker and unlock with passphrase & recovery key", async () => {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  const storage = new IndexedDbStorage("test_e2e_link_db");

  try {
    // 1. Initialize real vault in browser 1 with TEST_KDF_PARAMS to get valid crypto bootstrap
    const initRes = await client.initVault("my-master-passphrase", TEST_KDF_PARAMS);
    const browser1Bootstrap: VaultBootstrapData = {
      wrappedVaultKey: initRes.wrappedVaultKey,
      kdfParamsJson: initRes.kdfParamsJson,
      wrappedRecoveryKey: initRes.wrappedRecoveryKey,
    };
    const recoveryPhrase = initRes.recoveryPhrase;

    // 2. Lock browser 1
    await client.lockVault();

    // 3. Browser 2 simulates remote restore:
    // Browser 2 starts with null bootstrap (UNINITIALIZED)
    const store2 = new VaultStore(client, storage, null);
    assert.equal(store2.getState().vaultState, "UNINITIALIZED");

    // Restore remote bootstrap into store2
    store2.restoreFromRemote(browser1Bootstrap, {
      accountId: "account-alpha",
      serverOrigin: "https://notes.example.com",
      linkedAt: new Date().toISOString(),
    });

    assert.equal(store2.getState().vaultState, "LOCKED");
    assert.equal(store2.getState().vaultLink?.accountId, "account-alpha");

    // 4. Unlock with wrong passphrase -> fails closed
    await assert.rejects(
      store2.unlockWithPassphrase("wrong-passphrase"),
      /Current master passphrase is incorrect|Incorrect passphrase/
    );
    assert.equal(store2.getState().vaultState, "LOCKED");

    // 5. Unlock with correct passphrase -> UNLOCKED
    await store2.unlockWithPassphrase("my-master-passphrase");
    assert.equal(store2.getState().vaultState, "UNLOCKED");

    // Re-lock
    await store2.lock();
    assert.equal(store2.getState().vaultState, "LOCKED");

    // 6. Unlock with recovery key -> UNLOCKED
    await store2.unlockWithRecoveryKey(recoveryPhrase);
    assert.equal(store2.getState().vaultState, "UNLOCKED");

    store2.dispose();
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.close();
    await storage.deleteDatabase();
  }
});

test("UI rendering: AuthControls renders link button when unlinked and linked status when linked", () => {
  const client = createMockClient();
  const storage = new IndexedDbStorage("test_ui_link_db");

  try {
    // Unlinked vault
    const unlinkedHtml = renderToString(
      <AuthProvider
        serverUrl="https://notes.example.com"
        initialSession={{
          token: "tok",
          accountId: "acc-test",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider client={client} storage={storage} initialBootstrap={sampleBootstrapData} initialVaultLink={null}>
          <AuthControls initialOpen={true} />
        </VaultProvider>
      </AuthProvider>
    );
    assert.match(unlinkedHtml, /Signed in/);
    assert.match(unlinkedHtml, /Link vault to account/);

    // Linked vault
    const linkedHtml = renderToString(
      <AuthProvider
        serverUrl="https://notes.example.com"
        initialSession={{
          token: "tok",
          accountId: "acc-test",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider
          client={client}
          storage={storage}
          initialBootstrap={sampleBootstrapData}
          initialVaultLink={{
            accountId: "acc-test",
            serverOrigin: "https://notes.example.com",
            linkedAt: "2026-09-30T00:00:00Z",
          }}
        >
          <AuthControls initialOpen={true} />
        </VaultProvider>
      </AuthProvider>
    );
    assert.match(linkedHtml, /Signed in/);
    assert.match(linkedHtml, /Vault linked to this account/);
  } finally {
    storage.deleteDatabase().catch(() => {});
  }
});

test("UI rendering: UnlockScreen renders Restore option when uninitialized and authenticated", () => {
  const client = createMockClient();
  const storage = new IndexedDbStorage("test_ui_unlock_db");

  try {
    const uninitHtml = renderToString(
      <AuthProvider
        serverUrl="https://notes.example.com"
        initialSession={{
          token: "tok",
          accountId: "acc-restore-user",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider client={client} storage={storage} initialBootstrap={null}>
          <UnlockScreen />
        </VaultProvider>
      </AuthProvider>
    );

    assert.match(uninitHtml, /Restore Vault from Account/);
    assert.match(uninitHtml, /acc-restore-user/);
    assert.match(uninitHtml, /Create Your Vault/);
  } finally {
    storage.deleteDatabase().catch(() => {});
  }
});

test("linkLocalVaultToAccount: origin mismatch stops non-destructively", async () => {
  const storage = createMockStorage();
  writeVaultLink(storage, {
    accountId: "acc-user",
    serverOrigin: "https://server-a.com",
    linkedAt: "2026-09-30T00:00:00Z",
  });

  await assert.rejects(
    linkLocalVaultToAccount({
      serverOrigin: "https://server-b.com",
      token: "tok",
      accountId: "acc-user",
      localBootstrap: sampleBootstrapData,
      storage,
    }),
    (err: any) => err instanceof OriginMismatchError && err.code === "ORIGIN_MISMATCH"
  );

  // Link record remains untouched on server-a
  const link = readVaultLink(storage);
  assert.equal(link?.serverOrigin, "https://server-a.com");
  assert.equal(link?.accountId, "acc-user");
});

test("restoreVaultFromAccount: origin mismatch stops non-destructively (with localBootstrap)", async () => {
  const storage = createMockStorage();
  writeVaultLink(storage, {
    accountId: "acc-user",
    serverOrigin: "https://server-a.com",
    linkedAt: "2026-09-30T00:00:00Z",
  });

  await assert.rejects(
    restoreVaultFromAccount({
      serverOrigin: "https://server-b.com",
      token: "tok",
      accountId: "acc-user",
      localBootstrap: sampleBootstrapData,
      storage,
    }),
    (err: any) => err instanceof OriginMismatchError && err.code === "ORIGIN_MISMATCH"
  );

  // Existing link remains untouched
  const link = readVaultLink(storage);
  assert.equal(link?.serverOrigin, "https://server-a.com");
});

test("restoreVaultFromAccount: origin mismatch stops non-destructively when uninitialized (null localBootstrap)", async () => {
  const storage = createMockStorage();
  writeVaultLink(storage, {
    accountId: "acc-user",
    serverOrigin: "https://server-a.com",
    linkedAt: "2026-09-30T00:00:00Z",
  });

  // Even without a local bootstrap, the existing link to server-a protects against server-b restore
  await assert.rejects(
    restoreVaultFromAccount({
      serverOrigin: "https://server-b.com",
      token: "tok",
      accountId: "acc-user",
      localBootstrap: null,
      storage,
    }),
    (err: any) => err instanceof OriginMismatchError && err.code === "ORIGIN_MISMATCH"
  );

  const link = readVaultLink(storage);
  assert.equal(link?.serverOrigin, "https://server-a.com");
});

test("restoreVaultFromAccount: wrong account stops non-destructively (with localBootstrap)", async () => {
  const storage = createMockStorage();
  writeVaultLink(storage, {
    accountId: "acc-alpha",
    serverOrigin: "https://notes.example.com",
    linkedAt: "2026-09-30T00:00:00Z",
  });

  await assert.rejects(
    restoreVaultFromAccount({
      serverOrigin: "https://notes.example.com",
      token: "tok",
      accountId: "acc-beta",
      localBootstrap: sampleBootstrapData,
      storage,
    }),
    (err: any) => err instanceof WrongAccountError && err.code === "WRONG_ACCOUNT"
  );

  const link = readVaultLink(storage);
  assert.equal(link?.accountId, "acc-alpha");
});

test("restoreVaultFromAccount: wrong account stops non-destructively when uninitialized (null localBootstrap)", async () => {
  const storage = createMockStorage();
  writeVaultLink(storage, {
    accountId: "acc-alpha",
    serverOrigin: "https://notes.example.com",
    linkedAt: "2026-09-30T00:00:00Z",
  });

  await assert.rejects(
    restoreVaultFromAccount({
      serverOrigin: "https://notes.example.com",
      token: "tok",
      accountId: "acc-beta",
      localBootstrap: null,
      storage,
    }),
    (err: any) => err instanceof WrongAccountError && err.code === "WRONG_ACCOUNT"
  );

  const link = readVaultLink(storage);
  assert.equal(link?.accountId, "acc-alpha");
});

test("writeVaultLink and clearVaultLink fail closed on storage exception", () => {
  const throwingStorage = createThrowingStorage("both");

  assert.throws(
    () =>
      writeVaultLink(throwingStorage, {
        accountId: "acc-test",
        serverOrigin: "https://notes.example.com",
        linkedAt: "2026-09-30T00:00:00Z",
      }),
    (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
  );

  assert.throws(
    () => clearVaultLink(throwingStorage),
    (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
  );
});

test("persistBootstrap: throws observable error when storage write fails", () => {
  const throwingStorage = createThrowingStorage("setItem");

  assert.throws(
    () => persistBootstrap(sampleBootstrapData, throwingStorage),
    /Failed to persist vault bootstrap to storage/
  );
});

test("linkLocalVaultToAccount: fails closed when storage write throws", async () => {
  const throwingStorage = createThrowingStorage("setItem");
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string, init?: any) => {
    if (url.endsWith("/v1/vault/bootstrap")) {
      if (init?.method === "POST") {
        return { status: 201, ok: true, json: async () => sampleBootstrapDto };
      }
      return { status: 404, ok: false, json: async () => ({ code: "OBJECT_NOT_FOUND" }) };
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      linkLocalVaultToAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-test",
        localBootstrap: sampleBootstrapData,
        storage: throwingStorage,
      }),
      (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
    );
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("restoreVaultFromAccount: fails closed when storage write throws", async () => {
  const throwingStorage = createThrowingStorage("setItem");
  const oldFetch = globalThis.fetch;

  globalThis.fetch = (async (url: string) => {
    if (url.endsWith("/v1/vault/bootstrap")) {
      return { status: 200, ok: true, json: async () => sampleBootstrapDto };
    }
    throw new Error("Unexpected");
  }) as unknown as typeof fetch;

  try {
    await assert.rejects(
      restoreVaultFromAccount({
        serverOrigin: "https://notes.example.com",
        token: "tok",
        accountId: "acc-test",
        localBootstrap: null,
        storage: throwingStorage,
      }),
      (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
    );
  } finally {
    globalThis.fetch = oldFetch;
  }
});

test("VaultStore: restoreFromRemote and setVaultLink fail closed on storage write failure without transitioning state", () => {
  const throwingStorage = createThrowingStorage("setItem");
  const client = createMockClient();
  const storage = new IndexedDbStorage("test_fail_store_db");

  const store = new VaultStore(client, storage, null, undefined, null, throwingStorage);

  assert.equal(store.getState().vaultState, "UNINITIALIZED");
  assert.equal(store.getState().bootstrap, null);
  assert.equal(store.getState().vaultLink, null);

  // restoreFromRemote must throw because storage.setItem throws
  assert.throws(
    () =>
      store.restoreFromRemote(sampleBootstrapData, {
        accountId: "acc-test",
        serverOrigin: "https://notes.example.com",
        linkedAt: "2026-09-30T00:00:00Z",
      }),
    /Failed to persist vault bootstrap to storage/
  );

  // Crucial check: state must NOT transition to LOCKED! Must remain UNINITIALIZED.
  assert.equal(store.getState().vaultState, "UNINITIALIZED");
  assert.equal(store.getState().bootstrap, null);
  assert.equal(store.getState().vaultLink, null);

  // setVaultLink must throw because storage.setItem throws
  assert.throws(
    () =>
      store.setVaultLink({
        accountId: "acc-test",
        serverOrigin: "https://notes.example.com",
        linkedAt: "2026-09-30T00:00:00Z",
      }),
    (err: any) => err instanceof VaultLinkError && err.code === "STORAGE_ERROR"
  );

  // Crucial check: vaultLink must NOT be updated in snapshot
  assert.equal(store.getState().vaultLink, null);

  store.dispose();
});

test("UI rendering: AuthControls and UnlockScreen render origin mismatch warnings", () => {
  const client = createMockClient();
  const storage = new IndexedDbStorage("test_ui_mismatch_db");

  try {
    // AuthControls with server origin mismatch
    const htmlAuth = renderToString(
      <AuthProvider
        serverUrl="https://server-b.com"
        initialSession={{
          token: "tok",
          accountId: "acc-test",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider
          client={client}
          storage={storage}
          initialBootstrap={sampleBootstrapData}
          initialVaultLink={{
            accountId: "acc-test",
            serverOrigin: "https://server-a.com",
            linkedAt: "2026-09-30T00:00:00Z",
          }}
        >
          <AuthControls initialOpen={true} />
        </VaultProvider>
      </AuthProvider>
    );
    assert.match(htmlAuth, /Vault linked to different server/);

    // UnlockScreen with server origin mismatch in locked state
    const htmlUnlockLocked = renderToString(
      <AuthProvider
        serverUrl="https://server-b.com"
        initialSession={{
          token: "tok",
          accountId: "acc-test",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider
          client={client}
          storage={storage}
          initialBootstrap={sampleBootstrapData}
          initialVaultLink={{
            accountId: "acc-test",
            serverOrigin: "https://server-a.com",
            linkedAt: "2026-09-30T00:00:00Z",
          }}
        >
          <UnlockScreen />
        </VaultProvider>
      </AuthProvider>
    );
    assert.match(
      htmlUnlockLocked,
      /Connected to (?:'|&#x27;)https:\/\/server-b\.com(?:'|&#x27;), but this vault is linked to server (?:'|&#x27;)https:\/\/server-a\.com(?:'|&#x27;)/
    );

    // UnlockScreen with server origin mismatch in uninitialized state
    const htmlUnlockUninit = renderToString(
      <AuthProvider
        serverUrl="https://server-b.com"
        initialSession={{
          token: "tok",
          accountId: "acc-test",
          sessionId: "sess",
          expiresAt: "2099-01-01T00:00:00Z",
        }}
      >
        <VaultProvider
          client={client}
          storage={storage}
          initialBootstrap={null}
          initialVaultLink={{
            accountId: "acc-test",
            serverOrigin: "https://server-a.com",
            linkedAt: "2026-09-30T00:00:00Z",
          }}
        >
          <UnlockScreen />
        </VaultProvider>
      </AuthProvider>
    );
    assert.match(
      htmlUnlockUninit,
      /Connected to (?:'|&#x27;)https:\/\/server-b\.com(?:'|&#x27;), but this browser was linked to server (?:'|&#x27;)https:\/\/server-a\.com(?:'|&#x27;)/
    );
  } finally {
    storage.deleteDatabase().catch(() => {});
  }
});

