/**
 * Web Sync Status Tests (ZK-067).
 *
 * Verifies:
 * 1. Accurate display and transitions of all 6 required states:
 *    - "offline"
 *    - "syncing"
 *    - "synced"
 *    - "pending changes"
 *    - "conflict"
 *    - "error"
 * 2. Zero-Knowledge security audit: Sync status and error messages never leak note content (SEC-001, SEC-003).
 * 3. Popover metrics, manual sync triggers, and offline mode toggling.
 */

import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";

import "fake-indexeddb/auto";
import {
  VaultProvider,
  SyncProvider,
  useSync,
  SyncStatusIndicator,
  sanitizeSyncErrorMessage,
} from "../src/index.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient } from "../src/worker/client.js";
import {
  MutationType,
  MutationStatus,
  EncryptedEnvelopeDto,
  ConflictRecord,
} from "../src/storage/models.js";

const DUMMY_ENVELOPE: EncryptedEnvelopeDto = {
  envelope_version: 1,
  object_id: "obj-dummy-1",
  object_kind: 1,
  wrapped_key: { nonce: "nonce-k", ciphertext: "ct-k" },
  payload: { nonce: "nonce-p", ciphertext: "ct-p" },
};

function createMockSyncWorkerClient() {
  const client: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: true, sessionInitialized: true }),
    onLock: () => () => {},
    dispose: () => {},
  };
  return client as VaultWorkerClient;
}

// ----------------------------------------------------------------------------
// 1. All 6 Sync States Verification
// ----------------------------------------------------------------------------

test("Sync status displays 'synced' when online with 0 pending changes and 0 conflicts", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-synced");

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  assert.ok(syncRef !== null);
  const sync = syncRef as unknown as ReturnType<typeof useSync>;

  assert.equal(sync.status, "synced");
  assert.equal(sync.pendingCount, 0);
  assert.equal(sync.conflictCount, 0);

  // HTML must contain exact status label "synced" and checkmark icon
  assert.ok(html.includes("synced"));
  assert.ok(html.includes("✓"));

  await storage.close();
});

test("Sync status displays 'pending changes' when queued mutations exist", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-pending");

  // Enqueue pending mutation
  await storage.enqueueMutation({
    mutation_id: "mut-1",
    object_id: "note-1",
    expected_revision: 0,
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    envelope: DUMMY_ENVELOPE,
    created_at: new Date().toISOString(),
    retry_count: 0,
    status: MutationStatus.Pending,
  });

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  const sync = syncRef as unknown as ReturnType<typeof useSync>;
  await sync.refreshStatus();

  assert.equal(sync.status, "pending changes");
  assert.equal(sync.pendingCount, 1);

  // Render component again with updated context
  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider store={sync.store}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("pending changes"));
  assert.ok(html.includes("(1)"));
  assert.ok(html.includes("⏳"));

  await storage.close();
});

test("Sync status displays 'conflict' when unresolved conflicts exist", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-conflict");

  // Put an active unresolved conflict
  const conflict: ConflictRecord = {
    conflict_id: "conflict-1",
    object_id: "note-conflict-1",
    object_kind: 1,
    base_revision: 1,
    remote_revision: 2,
    base_envelope: DUMMY_ENVELOPE,
    local_envelope: DUMMY_ENVELOPE,
    remote_envelope: DUMMY_ENVELOPE,
    candidate_envelope: null,
    resolved: false,
    created_at: new Date().toISOString(),
    resolved_at: null,
  };
  await storage.putConflict(conflict);

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  const sync = syncRef as unknown as ReturnType<typeof useSync>;
  await sync.refreshStatus();

  assert.equal(sync.status, "conflict");
  assert.equal(sync.conflictCount, 1);

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider store={sync.store}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("conflict"));
  assert.ok(html.includes("(1)"));
  assert.ok(html.includes("⚠️"));

  await storage.close();
});

test("Sync status displays 'offline' when offline mode is active", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-offline");

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  const sync = syncRef as unknown as ReturnType<typeof useSync>;
  sync.setOfflineMode(true);

  assert.equal(sync.status, "offline");
  assert.equal(sync.isOnline, false);

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider store={sync.store}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("offline"));
  assert.ok(html.includes("☁️"));

  await storage.close();
});

test("Sync status displays 'syncing' during active synchronization", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-syncing");

  let resolveSync: (() => void) | null = null;
  const serverAdapter = {
    pushMutations: async () => {
      await new Promise<void>((res) => {
        resolveSync = res;
      });
    },
  };

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider serverAdapter={serverAdapter}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  const sync = syncRef as unknown as ReturnType<typeof useSync>;

  // Trigger syncNow in background
  const syncPromise = sync.syncNow();
  assert.equal(sync.status, "syncing");
  assert.equal(sync.isSyncing, true);

  // Complete sync
  if (resolveSync) (resolveSync as () => void)();
  await syncPromise;

  assert.equal(sync.status, "synced");
  assert.equal(sync.isSyncing, false);

  await storage.close();
});

test("Sync status displays 'error' when synchronization fails", async () => {
  const client = createMockSyncWorkerClient();
  const storage = new IndexedDbStorage("test-sync-state-error");

  const serverAdapter = {
    pushMutations: async () => {
      throw new Error("HTTP 503 Server Unavailable");
    },
  };

  let syncRef: ReturnType<typeof useSync> | null = null;
  const Consumer: React.FC = () => {
    syncRef = useSync();
    return <SyncStatusIndicator />;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider serverAdapter={serverAdapter}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  const sync = syncRef as unknown as ReturnType<typeof useSync>;

  // Attempt sync
  await sync.syncNow();

  assert.equal(sync.status, "error");
  assert.ok(sync.error !== null);
  // Error message must be sanitized
  assert.equal(sync.error, "Server unavailable. Retrying later.");

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <SyncProvider store={sync.store} serverAdapter={serverAdapter}>
        <Consumer />
      </SyncProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("error"));
  assert.ok(html.includes("❌"));

  // Dismiss error
  sync.clearError();
  assert.equal(sync.error, null);

  await storage.close();
});

// ----------------------------------------------------------------------------
// 2. Zero-Knowledge Plaintext Leak Audit (SEC-001, SEC-003)
// ----------------------------------------------------------------------------

test("Security Audit: Sync status and error messages never leak note content (SEC-001, SEC-003)", () => {
  const secretTitle = "SUPER SENSITIVE NOTE TITLE";
  const secretBody = "SECRET NOTE CONTENT THAT MUST NEVER BE IN LOGS OR UI SYNC";

  // Simulate raw error with accidental leak of sensitive string
  const rawError = `Failed to push note "${secretTitle}" with body "${secretBody}": network fetch failed`;
  const sanitized = sanitizeSyncErrorMessage(rawError);

  assert.ok(!sanitized.includes(secretTitle));
  assert.ok(!sanitized.includes(secretBody));
  assert.equal(sanitized, "Network connection failed. Changes queued locally.");

  // Test other error sanitizations
  assert.equal(
    sanitizeSyncErrorMessage("401 Unauthorized token expired"),
    "Authentication required to synchronize."
  );
  assert.equal(
    sanitizeSyncErrorMessage("409 Conflict revision mismatch"),
    "Conflicting remote changes detected."
  );
  assert.equal(
    sanitizeSyncErrorMessage("429 Too Many Requests rate limit"),
    "Sync rate limit reached. Retrying shortly."
  );
});
