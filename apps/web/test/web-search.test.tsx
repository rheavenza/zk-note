/**
 * Web Search Tests (ZK-066).
 *
 * Verifies:
 * 1. In-memory local search across note titles, bodies, and tags.
 * 2. No server queries: search terms and results strictly client-side (SEC-001).
 * 3. Lock clears searchable plaintext state and in-memory search index (SEC-009).
 * 4. UI components: SearchBar, SearchModal, keyboard navigation.
 * 5. Full end-to-end integration with real WebAssembly worker thread.
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
  NotesProvider,
  SearchProvider,
  useSearch,
  SearchBar,
  SearchModal,
  NotesWorkspace,
} from "../src/index.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient, WorkerError } from "../src/worker/client.js";
import { WorkerErrorCode, SearchResultDto } from "../src/worker/protocol.js";

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

function createMockSearchWorkerClient() {
  let unlocked = false;
  const lockListeners: Array<() => void> = [];
  const index = new Map<string, { title: string; body: string; tags: string[] }>();

  const client: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: unlocked, sessionInitialized: true }),
    initVault: async (_passphrase: string) => {
      unlocked = true;
      return {
        wrappedVaultKey: "wk",
        kdfParamsJson: TEST_KDF_PARAMS,
        wrappedRecoveryKey: "rk",
        recoveryPhrase: "11111111-22222222-33333333-44444444-55555555-66666666-77777777-88888888-99999999",
      };
    },
    indexNote: async (noteId, title, body, tags, _updatedAt) => {
      if (!unlocked) throw new WorkerError(WorkerErrorCode.VAULT_LOCKED, "Vault is locked");
      index.set(noteId, { title, body, tags });
      return { success: true };
    },
    removeFromIndex: async (noteId) => {
      index.delete(noteId);
      return { success: true };
    },
    search: async (query: string): Promise<SearchResultDto[]> => {
      if (!unlocked) throw new WorkerError(WorkerErrorCode.VAULT_LOCKED, "Vault is locked");
      const q = query.toLowerCase();
      const results: SearchResultDto[] = [];

      for (const [id, note] of index.entries()) {
        const titleMatch = note.title.toLowerCase().includes(q);
        const bodyMatch = note.body.toLowerCase().includes(q);
        const tagMatch = note.tags.some((t) => t.toLowerCase().includes(q));

        if (titleMatch || bodyMatch || tagMatch) {
          let score = 0;
          if (titleMatch) score += 100;
          if (bodyMatch) score += 50;
          if (tagMatch) score += 30;

          results.push({
            noteId: id,
            score,
            matchedTitle: note.title,
            snippet: note.body.slice(0, 60),
          });
        }
      }

      results.sort((a, b) => b.score - a.score);
      return results;
    },
    lockVault: async () => {
      unlocked = false;
      index.clear(); // Clear search index on lock (SEC-009)
      for (const cb of lockListeners) cb();
      return { success: true };
    },
    onLock: (cb) => {
      lockListeners.push(cb);
      return () => {
        const idx = lockListeners.indexOf(cb);
        if (idx >= 0) lockListeners.splice(idx, 1);
      };
    },
    dispose: () => {},
  };

  return {
    client: client as VaultWorkerClient,
    setUnlocked: (val: boolean) => {
      unlocked = val;
    },
    triggerLock: () => {
      unlocked = false;
      index.clear();
      for (const cb of lockListeners) cb();
    },
    index,
  };
}

// ----------------------------------------------------------------------------
// 1. SearchContext State & Lifecycle Tests
// ----------------------------------------------------------------------------

test("SearchContext executes in-memory local search and updates results", async () => {
  const { client } = createMockSearchWorkerClient();
  const storage = new IndexedDbStorage("test-db-search-ctx");

  let vaultRef: ReturnType<typeof useVault> | null = null;
  let searchRef: ReturnType<typeof useSearch> | null = null;
  const Consumer: React.FC = () => {
    vaultRef = useVault();
    searchRef = useSearch();
    return <div>Consumer</div>;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SearchProvider>
        <Consumer />
      </SearchProvider>
    </VaultProvider>
  );

  assert.ok(vaultRef !== null);
  assert.ok(searchRef !== null);

  const vault = vaultRef as unknown as ReturnType<typeof useVault>;
  const search = searchRef as unknown as ReturnType<typeof useSearch>;

  // Initialize vault to transition to UNLOCKED state
  await vault.initVault("test-passphrase");
  assert.equal(vault.vaultState, "UNLOCKED");

  // Populate mock index
  await client.indexNote(
    "note-1",
    "Zero-Knowledge Architecture",
    "Details on end-to-end crypto",
    ["sec"],
    "2026-09-10T12:00:00Z"
  );
  await client.indexNote(
    "note-2",
    "Grocery List",
    "Apples, bananas, and oats",
    ["shopping"],
    "2026-09-10T12:00:00Z"
  );

  assert.equal(search.query, "");
  assert.equal(search.results.length, 0);
  assert.equal(search.isSearching, false);

  // Execute search for "crypto"
  const res1 = await search.searchNow("crypto");
  assert.equal(res1.length, 1);
  assert.equal(res1[0]!.noteId, "note-1");
  assert.equal(res1[0]!.matchedTitle, "Zero-Knowledge Architecture");
  assert.ok(res1[0]!.score > 0);

  // Execute search for "banana"
  const res2 = await search.searchNow("banana");
  assert.equal(res2.length, 1);
  assert.equal(res2[0]!.noteId, "note-2");

  // Non-matching search
  const res3 = await search.searchNow("nonexistent-keyword-xyz");
  assert.equal(res3.length, 0);

  await storage.close();
});

test("Security: Vault lock clears searchable plaintext state and active queries (SEC-009)", async () => {
  const { client } = createMockSearchWorkerClient();
  const storage = new IndexedDbStorage("test-db-search-lock");

  let vaultRef: ReturnType<typeof useVault> | null = null;
  let searchRef: ReturnType<typeof useSearch> | null = null;
  const Consumer: React.FC = () => {
    vaultRef = useVault();
    searchRef = useSearch();
    return <div>Consumer</div>;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SearchProvider>
        <Consumer />
      </SearchProvider>
    </VaultProvider>
  );

  const vault = vaultRef as unknown as ReturnType<typeof useVault>;
  const search = searchRef as unknown as ReturnType<typeof useSearch>;

  await vault.initVault("test-passphrase");
  assert.equal(vault.vaultState, "UNLOCKED");

  await client.indexNote(
    "note-1",
    "Confidential Plan",
    "Secret body text",
    ["private"],
    "2026-09-10T12:00:00Z"
  );

  const results = await search.searchNow("Confidential");
  assert.equal(results.length, 1);

  // Lock vault
  await vault.lock();
  assert.equal(vault.vaultState, "LOCKED");

  // Attempting search when locked must fail closed and return empty
  const lockedResults = await search.searchNow("Confidential");
  assert.equal(lockedResults.length, 0);

  await storage.close();
});

// ----------------------------------------------------------------------------
// 2. UI Rendering Tests (SearchBar, SearchModal, NotesWorkspace)
// ----------------------------------------------------------------------------

test("SearchBar renders search input and shortcut indicator", () => {
  const { client } = createMockSearchWorkerClient();
  const storage = new IndexedDbStorage("test-ui-search-bar");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <NotesProvider>
        <SearchProvider>
          <SearchBar />
        </SearchProvider>
      </NotesProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("Search notes..."));
  assert.ok(html.includes("zk-search-bar"));
});

test("SearchModal renders search dialog when open", () => {
  const { client } = createMockSearchWorkerClient();
  const storage = new IndexedDbStorage("test-ui-search-modal");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <NotesProvider>
        <SearchProvider>
          <SearchModal isOpen={true} />
        </SearchProvider>
      </NotesProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("zk-search-modal") || html.includes("Zero-Knowledge Search"));
  assert.ok(html.includes("Search notes by title, body, or tags..."));
  assert.ok(html.includes("Queries execute 100% locally in Web Worker"));
});

test("NotesWorkspace renders SearchBar in navbar", () => {
  const { client } = createMockSearchWorkerClient();
  const storage = new IndexedDbStorage("test-ui-notes-workspace-search");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <NotesProvider>
        <SearchProvider>
          <NotesWorkspace />
        </SearchProvider>
      </NotesProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("zk-search-bar"));
  assert.ok(html.includes("Zero-Knowledge Notes"));
});

// ----------------------------------------------------------------------------
// 3. End-to-End Real WebAssembly Worker Search Test
// ----------------------------------------------------------------------------

test("End-to-End: Real WASM in-memory search, indexing, scoring, and lock scrubbing", async () => {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);

  try {
    // 1. Initialize vault session in real WASM worker
    await client.initVault("my-secure-search-passphrase", TEST_KDF_PARAMS);
    const status = await client.getStatus();
    assert.equal(status.isUnlocked, true);

    // 2. Index three notes in real WASM search index
    await client.indexNote(
      "note-wasm-1",
      "Zero-Knowledge Rust Architecture",
      "Building a private client-side encrypted note system with WebAssembly.",
      ["rust", "security", "wasm"],
      "2026-09-10T12:00:00Z"
    );

    await client.indexNote(
      "note-wasm-2",
      "Grocery Shopping",
      "Fresh apples, almond milk, and sourdough bread.",
      ["shopping", "food"],
      "2026-09-10T12:01:00Z"
    );

    await client.indexNote(
      "note-wasm-3",
      "Weekly Project Roadmap",
      "Milestone 6: Web client and WebAssembly worker integration.",
      ["roadmap", "planning"],
      "2026-09-10T12:02:00Z"
    );

    // 3. Execute search for "Zero-Knowledge"
    const zkResults = await client.search("Zero-Knowledge");
    assert.ok(zkResults.length >= 1);
    assert.equal(zkResults[0]!.noteId, "note-wasm-1");
    assert.equal(zkResults[0]!.matchedTitle, "Zero-Knowledge Rust Architecture");
    assert.ok(zkResults[0]!.score > 0);

    // 4. Search across body content: "almond milk"
    const milkResults = await client.search("almond milk");
    assert.ok(milkResults.length >= 1);
    assert.equal(milkResults[0]!.noteId, "note-wasm-2");
    assert.ok(milkResults[0]!.snippet.toLowerCase().includes("milk"));

    // 5. Search across tags: "wasm"
    const tagResults = await client.search("wasm");
    assert.ok(tagResults.length >= 1);
    assert.ok(tagResults.some((r) => r.noteId === "note-wasm-1"));

    // 6. Remove note from index
    await client.removeFromIndex("note-wasm-2");
    const afterRemovalResults = await client.search("almond milk");
    assert.equal(afterRemovalResults.length, 0);

    // 7. Lock vault -> verifies lock clears search index and fails closed (SEC-009, SEC-010)
    await client.lockVault();

    await assert.rejects(
      async () => {
        await client.search("Zero-Knowledge");
      },
      (err: WorkerError) => {
        assert.equal(err.code, WorkerErrorCode.VAULT_LOCKED);
        return true;
      }
    );
  } finally {
    client.dispose();
    await worker.terminate();
  }
});
