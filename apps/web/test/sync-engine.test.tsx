/**
 * Comprehensive Sync Engine & Browser Sync Adapter Tests (ZK-106).
 *
 * Covers all required acceptance criteria and security invariants:
 * 1. Clean create -> push -> pull round trip
 * 2. Edit sync
 * 3. Delete / tombstone sync
 * 4. Offline edit then reconnect
 * 5. Duplicate mutation replay (idempotent 200)
 * 6. Lost response after server accepted mutation
 * 7. Stale edit CAS conflict
 * 8. Delete-vs-edit conflict
 * 9. Pull pagination / sequence ordering
 * 10. Cursor persistence
 * 11. Crash between ciphertext persistence and cursor advancement
 * 12. Browser restart with pending mutations (resetInFlightMutations)
 * 13. Locked-vault pull (zero plaintext, ciphertext stored only)
 * 14. Unauthorized / expired session (401 fails closed, preserves local notes)
 * 15. Server switch isolation (OriginMismatchError)
 * 16. Account switch isolation (WrongAccountError)
 * 17. Two-browser offline conflict
 * 18. Zero plaintext leakage in network payloads (SEC-001, SEC-002)
 * 19. Zero secrets in logs (SEC-003)
 * 20. Truthful sync UI: "Server synchronization is not configured" disappears once linked
 */

import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import { createRoot } from "react-dom/client";
import "fake-indexeddb/auto";

import {
  BrowserSyncAdapter,
  SyncError,
  UnauthorizedSyncError,
  validateNoPlaintextSecrets,
} from "../src/sync/adapter.js";
import {
  writeVaultLink,
  VaultLinkRecord,
  WrongAccountError,
  OriginMismatchError,
} from "../src/auth/vault-link.js";
import {
  IndexedDbStorage,
  getScopedDatabaseName,
  DEFAULT_DB_NAME,
} from "../src/storage/indexeddb.js";
import {
  MutationType,
  MutationStatus,
  EncryptedEnvelopeDto,
  StoredEncryptedObject,
} from "../src/storage/models.js";
import {
  SyncProvider,
  useSync,
} from "../src/context/SyncContext.js";
import { SyncStatusIndicator } from "../src/components/SyncStatusIndicator.js";
import { AuthProvider } from "../src/context/AuthContext.js";
import { VaultProvider, VaultStore } from "../src/context/VaultContext.js";
import { VaultWorkerClient } from "../src/worker/client.js";
import { App } from "../src/App.js";

// ============================================================================
// Mock Server & Helpers
// ============================================================================

const SERVER_ORIGIN = "https://sync.example.com";
const ACCOUNT_ID = "acc-alice-1";
const AUTH_TOKEN = "jwt-valid-token-alice";

function createMockStorage(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => map.set(key, value),
    removeItem: (key: string) => map.delete(key),
    clear: () => map.clear(),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    get length() {
      return map.size;
    },
  };
}

function createEnvelope(objectId: string, tag = "v1"): EncryptedEnvelopeDto {
  return {
    envelope_version: 1,
    object_id: objectId,
    object_kind: 1,
    wrapped_key: {
      nonce: `nonce-key-${objectId}-${tag}`,
      ciphertext: `ct-key-${objectId}-${tag}`,
    },
    payload: {
      nonce: `nonce-payload-${objectId}-${tag}`,
      ciphertext: `ct-payload-${objectId}-${tag}`,
    },
  };
}

interface StoredServerObject {
  revision: number;
  server_seq: number;
  is_deleted: boolean;
  envelope: EncryptedEnvelopeDto;
  object_kind: number;
}

class MockSyncServer {
  public objects = new Map<string, StoredServerObject>();
  public history: Array<{
    server_seq: number;
    object_id: string;
    revision: number;
    object_kind: number;
    is_deleted: boolean;
    envelope: EncryptedEnvelopeDto;
  }> = [];
  public acceptedMutations = new Map<string, { object_id: string; revision: number; server_seq: number }>();
  public currentSeq = 0;
  public networkCalls: Array<{ url: string; method: string; body?: any; headers?: any }> = [];
  public shouldSimulateLostResponse = false;
  public forceHttpError: number | null = null;

  public handleFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method || "GET";
    const headers = (init?.headers || {}) as Record<string, string>;
    const bodyText = init?.body ? String(init.body) : undefined;
    const body = bodyText ? JSON.parse(bodyText) : undefined;

    this.networkCalls.push({ url, method, body, headers });

    // Enforce SEC-001 / SEC-002 check on every incoming payload
    if (body) {
      validateNoPlaintextSecrets(body);
    }

    if (this.forceHttpError) {
      return new Response(JSON.stringify({ error: `HTTP ${this.forceHttpError}` }), {
        status: this.forceHttpError,
        headers: { "Content-Type": "application/json" },
      });
    }

    const authHeader = headers["authorization"] || headers["Authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ") || !authHeader.includes(AUTH_TOKEN)) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (url.endsWith("/v1/sync/push") && method === "POST") {
      const { mutation_id, object_id, expected_revision, object_kind, envelope, is_deleted } = body;

      // Check idempotency replay
      if (this.acceptedMutations.has(mutation_id)) {
        const replay = this.acceptedMutations.get(mutation_id)!;
        return new Response(JSON.stringify(replay), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Check CAS revision
      const existing = this.objects.get(object_id);
      const currentRev = existing ? existing.revision : 0;
      if (currentRev !== expected_revision) {
        return new Response(
          JSON.stringify({
            error: "revision_conflict",
            object_id,
            expected_revision,
            current_revision: currentRev,
            current_server_seq: existing ? existing.server_seq : 0,
            current_envelope: existing ? existing.envelope : envelope,
            is_deleted: existing ? existing.is_deleted : false,
          }),
          { status: 409, headers: { "Content-Type": "application/json" } }
        );
      }

      // If simulating a lost response, server accepts and writes, but response drops
      const nextRev = currentRev + 1;
      const nextSeq = ++this.currentSeq;
      const storedObj: StoredServerObject = {
        revision: nextRev,
        server_seq: nextSeq,
        is_deleted: Boolean(is_deleted),
        envelope,
        object_kind,
      };
      this.objects.set(object_id, storedObj);
      this.history.push({
        server_seq: nextSeq,
        object_id,
        revision: nextRev,
        object_kind,
        is_deleted: Boolean(is_deleted),
        envelope,
      });

      const responsePayload = {
        object_id,
        revision: nextRev,
        server_seq: nextSeq,
      };
      this.acceptedMutations.set(mutation_id, responsePayload);

      if (this.shouldSimulateLostResponse) {
        this.shouldSimulateLostResponse = false;
        throw new TypeError("Failed to fetch: network response lost after server write");
      }

      return new Response(JSON.stringify(responsePayload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (url.includes("/v1/sync/pull")) {
      let cursor = 0;
      let limit = 100;

      if (method === "POST" && body) {
        cursor = Number(body.cursor ?? 0);
        limit = Number(body.limit ?? 100);
      } else {
        const u = new URL(url);
        cursor = Number(u.searchParams.get("after") ?? u.searchParams.get("cursor") ?? u.searchParams.get("since") ?? 0);
        limit = Number(u.searchParams.get("limit") ?? 100);
      }

      const filtered = this.history.filter((h) => h.server_seq > cursor);
      const changes = filtered.slice(0, limit);
      const has_more = filtered.length > limit;
      const next_cursor = changes.length > 0 ? changes[changes.length - 1]!.server_seq : cursor;

      return new Response(
        JSON.stringify({
          changes,
          next_cursor,
          has_more,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  };
}

function createMockSyncWorkerClient(): VaultWorkerClient {
  const client: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: true, sessionInitialized: true }),
    lockVault: async () => ({ success: true as const }),
    onLock: () => () => {},
    dispose: () => {},
  };
  return client as VaultWorkerClient;
}

// ============================================================================
// Test Suite
// ============================================================================

test("clean create -> push -> pull round trip", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storageA = new IndexedDbStorage(`test-e2e-create-a-${Date.now()}`);
  const storageB = new IndexedDbStorage(`test-e2e-create-b-${Date.now()}`);
  const mockStore = createMockStorage();

  const linkRecord: VaultLinkRecord = {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  };
  writeVaultLink(mockStore, linkRecord);

  try {
    const adapterA = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });
    const adapterB = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    // 1. Client A creates a note and enqueues a mutation
    const noteId = "note-roundtrip-1";
    const envelope = createEnvelope(noteId, "rev1");
    const storedObject: StoredEncryptedObject = {
      object_id: noteId,
      revision: 1,
      server_seq: 0,
      object_kind: 1,
      envelope,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    };
    await storageA.putObject(storedObject);
    await storageA.enqueueMutation({
      mutation_id: "mut-create-1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Verify client A has 1 pending mutation
    let pendingA = await storageA.listPendingMutations();
    assert.equal(pendingA.length, 1);

    // 2. Client A pushes via sync()
    const syncReportA = await adapterA.sync(storageA);
    assert.equal(syncReportA.push.accepted.length, 1);
    assert.equal(syncReportA.push.conflicts.length, 0);

    // Pending mutation is cleared from client A
    pendingA = await storageA.listPendingMutations();
    assert.equal(pendingA.length, 0);

    // Stored object in Client A now has server_seq = 1
    const objA = await storageA.getObject(noteId);
    assert.ok(objA);
    assert.equal(objA?.server_seq, 1);

    // 3. Client B syncs (pulls)
    const syncReportB = await adapterB.sync(storageB);
    assert.equal(syncReportB.initialPull.appliedChanges, 1);
    assert.equal(syncReportB.finalCursor, 1);

    // Client B now has the encrypted object persisted
    const objB = await storageB.getObject(noteId);
    assert.ok(objB);
    assert.equal(objB?.revision, 1);
    assert.equal(objB?.server_seq, 1);
    assert.deepEqual(objB?.envelope, envelope);
  } finally {
    globalThis.fetch = oldFetch;
    await storageA.close();
    await storageB.close();
  }
});

test("edit sync", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storageA = new IndexedDbStorage(`test-e2e-edit-a-${Date.now()}`);
  const storageB = new IndexedDbStorage(`test-e2e-edit-b-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapterA = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });
    const adapterB = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    // Client A creates note (rev 1)
    const noteId = "note-edit-1";
    const env1 = createEnvelope(noteId, "rev1");
    await storageA.putObject({
      object_id: noteId,
      revision: 1,
      server_seq: 0,
      object_kind: 1,
      envelope: env1,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageA.enqueueMutation({
      mutation_id: "mut-edit-c1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env1,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);

    // Client B pulls rev 1
    await adapterB.sync(storageB);
    const objBRev1 = await storageB.getObject(noteId);
    assert.equal(objBRev1?.revision, 1);

    // Client A edits note (rev 1 -> 2)
    const env2 = createEnvelope(noteId, "rev2");
    await storageA.putObject({
      object_id: noteId,
      revision: 2,
      server_seq: 1,
      object_kind: 1,
      envelope: env2,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageA.enqueueMutation({
      mutation_id: "mut-edit-u1",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env2,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);

    // Client B pulls edit
    await adapterB.sync(storageB);
    const objBRev2 = await storageB.getObject(noteId);
    assert.equal(objBRev2?.revision, 2);
    assert.deepEqual(objBRev2?.envelope, env2);
  } finally {
    globalThis.fetch = oldFetch;
    await storageA.close();
    await storageB.close();
  }
});

test("delete/tombstone sync", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storageA = new IndexedDbStorage(`test-e2e-del-a-${Date.now()}`);
  const storageB = new IndexedDbStorage(`test-e2e-del-b-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapterA = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });
    const adapterB = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-del-1";
    const env1 = createEnvelope(noteId, "rev1");
    await storageA.putObject({
      object_id: noteId,
      revision: 1,
      server_seq: 0,
      object_kind: 1,
      envelope: env1,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageA.enqueueMutation({
      mutation_id: "mut-del-c1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env1,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);
    await adapterB.sync(storageB);

    // Client A deletes note (tombstone)
    await storageA.markDeleted(noteId, 2, env1, new Date().toISOString());
    await storageA.enqueueMutation({
      mutation_id: "mut-del-d1",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Delete,
      envelope: env1,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);

    // Client B pulls deletion
    await adapterB.sync(storageB);
    const objB = await storageB.getObject(noteId);
    assert.ok(objB);
    assert.equal(objB?.is_deleted, true);
    assert.equal(objB?.revision, 2);
  } finally {
    globalThis.fetch = oldFetch;
    await storageA.close();
    await storageB.close();
  }
});

test("offline edit then reconnect", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-offline-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    // Server is down / offline
    server.forceHttpError = 503;

    const env = createEnvelope("note-offline-1", "rev1");
    await storage.enqueueMutation({
      mutation_id: "mut-offline-1",
      object_id: "note-offline-1",
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Push fails
    await assert.rejects(
      adapter.sync(storage),
      (err: any) => err instanceof SyncError
    );

    // Mutation remains intact in pending queue
    let pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.status, MutationStatus.Pending);

    // Server comes back online
    server.forceHttpError = null;

    // Retry sync
    const report = await adapter.sync(storage);
    assert.equal(report.push.accepted.length, 1);

    // Mutation is cleared
    pending = await storage.listPendingMutations();
    assert.equal(pending.length, 0);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("duplicate mutation replay is idempotent", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-replay-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-replay-1";
    const env = createEnvelope(noteId, "rev1");
    const mutation = {
      mutation_id: "mut-stable-id-1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      envelope: env,
      is_deleted: false,
    };

    // First push
    const res1 = await adapter.pushMutation(mutation);
    assert.equal(res1.revision, 1);
    assert.equal(res1.server_seq, 1);

    // Replay exact same mutation
    const res2 = await adapter.pushMutation(mutation);
    assert.equal(res2.revision, 1);
    assert.equal(res2.server_seq, 1);

    // Server still only has 1 sequence and 1 object revision
    assert.equal(server.currentSeq, 1);
    assert.equal(server.objects.get(noteId)?.revision, 1);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("lost response after server accepted mutation", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-lost-resp-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-lost-1";
    const env = createEnvelope(noteId, "rev1");
    await storage.enqueueMutation({
      mutation_id: "mut-lost-resp-1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Simulate lost response: server accepts mutation, but network drops before response reaches client
    server.shouldSimulateLostResponse = true;

    await assert.rejects(
      adapter.sync(storage),
      (err: any) => err instanceof SyncError && err.message.includes("network response lost")
    );

    // Mutation remains pending in storage (was reset from in-flight on failure)
    let pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);

    // On next sync cycle, client retries exact same mutation
    const report = await adapter.sync(storage);
    assert.equal(report.push.accepted.length, 1);
    assert.equal(report.push.conflicts.length, 0);

    // Mutation successfully cleared without creating a duplicate revision
    pending = await storage.listPendingMutations();
    assert.equal(pending.length, 0);
    assert.equal(server.objects.get(noteId)?.revision, 1);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("stale edit CAS conflict creates actionable conflict record", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-stale-cas-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-cas-1";
    // Remote is already at revision 2
    server.objects.set(noteId, {
      revision: 2,
      server_seq: 2,
      is_deleted: false,
      envelope: createEnvelope(noteId, "remote-rev2"),
      object_kind: 1,
    });
    server.currentSeq = 2;

    // Client attempts to push with stale expected_revision 1
    const localEnvelope = createEnvelope(noteId, "local-stale-rev2");
    await storage.putObject({
      object_id: noteId,
      revision: 2,
      server_seq: 1,
      object_kind: 1,
      envelope: localEnvelope,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storage.enqueueMutation({
      mutation_id: "mut-stale-1",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: localEnvelope,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    const report = await adapter.pushMutations(storage);
    assert.equal(report.conflicts.length, 1);
    assert.equal(report.accepted.length, 0);

    // Conflict record preserved in storage
    const conflicts = await storage.listConflicts(false);
    assert.equal(conflicts.length, 1);
    assert.equal(conflicts[0]?.object_id, noteId);
    assert.equal(conflicts[0]?.base_revision, 1);
    assert.equal(conflicts[0]?.remote_revision, 2);
    // Pending mutation is retained for recovery (matching Rust push_pending_changes)
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.mutation_id, "mut-stale-1");
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("delete-vs-edit conflict", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-del-vs-edit-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-dve-1";
    // Remote was edited to revision 2
    server.objects.set(noteId, {
      revision: 2,
      server_seq: 5,
      is_deleted: false,
      envelope: createEnvelope(noteId, "remote-edited-rev2"),
      object_kind: 1,
    });
    server.currentSeq = 5;

    // Client had deleted with expected_revision 1
    const tombstoneEnv = createEnvelope(noteId, "local-tombstone");
    await storage.enqueueMutation({
      mutation_id: "mut-dve-del-1",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Delete,
      envelope: tombstoneEnv,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    const report = await adapter.pushMutations(storage);
    assert.equal(report.conflicts.length, 1);

    const conflicts = await storage.listConflicts(false);
    assert.equal(conflicts.length, 1);
    assert.equal(conflicts[0]?.object_id, noteId);
    assert.equal(conflicts[0]?.remote_revision, 2);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("pull pagination / sequence ordering", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-pagination-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    // Populate 5 history entries on server
    for (let i = 1; i <= 5; i++) {
      const noteId = `note-page-${i}`;
      server.history.push({
        server_seq: i,
        object_id: noteId,
        revision: 1,
        object_kind: 1,
        is_deleted: false,
        envelope: createEnvelope(noteId, "rev1"),
      });
    }

    // Pull with page size limit = 2
    const report = await adapter.pullChangesToStorage(storage, undefined, 2);
    assert.equal(report.pagesFetched, 3);
    assert.equal(report.totalChanges, 5);
    assert.equal(report.appliedChanges, 5);
    assert.equal(report.initialCursor, 0);
    assert.equal(report.finalCursor, 5);

    // All 5 objects are persisted
    for (let i = 1; i <= 5; i++) {
      const obj = await storage.getObject(`note-page-${i}`);
      assert.ok(obj);
      assert.equal(obj?.server_seq, i);
    }
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("cursor persistence and resumption", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-cursor-persist-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    server.history.push({
      server_seq: 1,
      object_id: "note-cp-1",
      revision: 1,
      object_kind: 1,
      is_deleted: false,
      envelope: createEnvelope("note-cp-1"),
    });

    await adapter.sync(storage);

    // Cursor is persisted in storage
    const state = await storage.getSyncState(adapter.identity);
    assert.equal(state?.sync_cursor, 1);
    assert.ok(state?.last_sync_at);

    // Add another item
    server.history.push({
      server_seq: 2,
      object_id: "note-cp-2",
      revision: 1,
      object_kind: 1,
      is_deleted: false,
      envelope: createEnvelope("note-cp-2"),
    });

    // Next sync resumes from cursor 1 and fetches only item 2
    server.networkCalls = [];
    await adapter.sync(storage);

    const pullCalls = server.networkCalls.filter((c) => c.url.includes("/v1/sync/pull"));
    assert.ok(pullCalls.length > 0);
    const pullUrl = new URL(pullCalls[0]!.url);
    assert.equal(pullUrl.searchParams.get("after"), "1");

    const updatedState = await storage.getSyncState(adapter.identity);
    assert.equal(updatedState?.sync_cursor, 2);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("crash between ciphertext persistence and cursor advancement does not skip changes", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-crash-recovery-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    server.history.push({
      server_seq: 1,
      object_id: "note-crash-1",
      revision: 1,
      object_kind: 1,
      is_deleted: false,
      envelope: createEnvelope("note-crash-1"),
    });

    // Monkey-patch setSyncCursor to simulate crash right after object persistence
    let crashTriggered = false;
    const originalSetSyncCursor = storage.setSyncCursor.bind(storage);
    storage.setSyncCursor = async (cursor, identity) => {
      if (!crashTriggered) {
        crashTriggered = true;
        throw new Error("Simulated storage crash during cursor commit");
      }
      return originalSetSyncCursor(cursor, identity);
    };

    await assert.rejects(
      adapter.pullChangesToStorage(storage),
      (err: any) => err.message.includes("Simulated storage crash")
    );

    // Object 1 was stored, but cursor was NOT advanced (still 0)
    const storedObj = await storage.getObject("note-crash-1");
    assert.ok(storedObj);
    const syncState = await storage.getSyncState(adapter.identity);
    assert.equal(syncState?.sync_cursor ?? 0, 0);

    // On restart / subsequent pull, resumes from cursor 0 cleanly without skipping
    const recoveryReport = await adapter.pullChangesToStorage(storage);
    assert.equal(recoveryReport.finalCursor, 1);
    const finalState = await storage.getSyncState(adapter.identity);
    assert.equal(finalState?.sync_cursor, 1);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("browser restart with pending mutations resets in-flight status", async () => {
  const storage = new IndexedDbStorage(`test-e2e-restart-${Date.now()}`);

  try {
    // Simulate mutation left in "in-flight" status due to browser crash/close
    await storage.enqueueMutation({
      mutation_id: "mut-crash-inflight",
      object_id: "note-crash-inflight",
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: createEnvelope("note-crash-inflight"),
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.InFlight,
    });

    let pending = await storage.listPendingMutations();
    assert.equal(pending.length, 0); // InFlight is not in pending list

    // On browser startup / storage init:
    const resetCount = await storage.resetInFlightMutations();
    assert.equal(resetCount, 1);

    // Mutation is now Pending again and ready for sync
    pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.status, MutationStatus.Pending);
  } finally {
    await storage.close();
  }
});

test("locked-vault pull: fetches and persists ciphertext only, zero plaintext, zero decryption", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-locked-pull-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    server.history.push({
      server_seq: 1,
      object_id: "note-locked-1",
      revision: 1,
      object_kind: 1,
      is_deleted: false,
      envelope: createEnvelope("note-locked-1", "secret-payload"),
    });

    // Vault is LOCKED (no vault worker, no keys in memory). Pull executes.
    const report = await adapter.pullChangesToStorage(storage);
    assert.equal(report.appliedChanges, 1);
    assert.equal(report.finalCursor, 1);

    // Verify stored object contains ONLY the encrypted envelope, no plaintext fields
    const stored = await storage.getObject("note-locked-1");
    assert.ok(stored);
    assert.equal((stored as any).title, undefined);
    assert.equal((stored as any).body, undefined);
    assert.equal((stored as any).tags, undefined);
    assert.ok(stored?.envelope.payload.ciphertext.includes("ct-payload-note-locked-1"));
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("unauthorized / expired session: fails closed with UnauthorizedSyncError, preserves local notes", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-unauthorized-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    // Use invalid/expired token
    const adapter = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: "expired-token",
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    const env = createEnvelope("note-unauth-1");
    await storage.putObject({
      object_id: "note-unauth-1",
      revision: 1,
      server_seq: 0,
      object_kind: 1,
      envelope: env,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storage.enqueueMutation({
      mutation_id: "mut-unauth-1",
      object_id: "note-unauth-1",
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    await assert.rejects(
      adapter.sync(storage),
      (err: any) => err instanceof UnauthorizedSyncError
    );

    // Local encrypted notes and pending mutation queue remain fully intact!
    const obj = await storage.getObject("note-unauth-1");
    assert.ok(obj);
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("server switch isolation: OriginMismatchError stops sync before network", async () => {
  const storage = new IndexedDbStorage(`test-e2e-server-switch-${Date.now()}`);
  const mockStore = createMockStorage();

  try {
    // Vault is linked to server A
    writeVaultLink(mockStore, {
      serverOrigin: "https://server-a.com",
      accountId: ACCOUNT_ID,
      linkedAt: new Date().toISOString(),
    });

    // Adapter configured for server B
    const adapterB = new BrowserSyncAdapter({
      serverOrigin: "https://server-b.com",
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    assert.throws(
      () => adapterB.assertLinkedStorage(storage),
      (err: any) => err instanceof OriginMismatchError
    );
  } finally {
    await storage.close();
  }
});

test("account switch isolation: WrongAccountError stops sync before network", async () => {
  const storage = new IndexedDbStorage(`test-e2e-account-switch-${Date.now()}`);
  const mockStore = createMockStorage();

  try {
    // Vault is linked to account A
    writeVaultLink(mockStore, {
      serverOrigin: SERVER_ORIGIN,
      accountId: "acc-alice-1",
      linkedAt: new Date().toISOString(),
    });

    // Adapter configured for account B
    const adapterB = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: "acc-bob-2",
      linkStorage: mockStore,
    });

    assert.throws(
      () => adapterB.assertLinkedStorage(storage),
      (err: any) => err instanceof WrongAccountError
    );
  } finally {
    await storage.close();
  }
});

test("two-browser offline conflict produces conflict record", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storageA = new IndexedDbStorage(`test-e2e-2b-a-${Date.now()}`);
  const storageB = new IndexedDbStorage(`test-e2e-2b-b-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapterA = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });
    const adapterB = new BrowserSyncAdapter({ serverOrigin: SERVER_ORIGIN, token: AUTH_TOKEN, accountId: ACCOUNT_ID, linkStorage: mockStore });

    const noteId = "note-2b-1";
    const envRev1 = createEnvelope(noteId, "rev1");

    // Both start at rev 1
    await storageA.putObject({
      object_id: noteId,
      revision: 1,
      server_seq: 0,
      object_kind: 1,
      envelope: envRev1,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageA.enqueueMutation({
      mutation_id: "mut-2b-c1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: envRev1,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);
    await adapterB.sync(storageB);

    // Browser A edits offline (rev 2) and syncs
    const envA2 = createEnvelope(noteId, "rev2-browserA");
    await storageA.putObject({
      object_id: noteId,
      revision: 2,
      server_seq: 1,
      object_kind: 1,
      envelope: envA2,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageA.enqueueMutation({
      mutation_id: "mut-2b-uA2",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: envA2,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });
    await adapterA.sync(storageA);
    assert.equal(server.objects.get(noteId)?.revision, 2);

    // Browser B also edited offline (rev 2 with expected_revision 1) and syncs
    const envB2 = createEnvelope(noteId, "rev2-browserB");
    await storageB.putObject({
      object_id: noteId,
      revision: 2,
      server_seq: 1,
      object_kind: 1,
      envelope: envB2,
      is_deleted: false,
      updated_at: new Date().toISOString(),
    });
    await storageB.enqueueMutation({
      mutation_id: "mut-2b-uB2",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: envB2,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Browser B sync detects CAS conflict
    const reportB = await adapterB.sync(storageB);
    assert.equal(reportB.push.conflicts.length, 1);

    // Browser B has conflict record
    const conflictsB = await storageB.listConflicts(false);
    assert.equal(conflictsB.length, 1);
    assert.equal(conflictsB[0]?.object_id, noteId);
    assert.equal(conflictsB[0]?.base_revision, 1);
    assert.equal(conflictsB[0]?.remote_revision, 2);
  } finally {
    globalThis.fetch = oldFetch;
    await storageA.close();
    await storageB.close();
  }
});

test("Zero plaintext in request fixtures (SEC-001/SEC-002)", () => {
  // Push request with forbidden field must throw immediately
  const badPayloads = [
    { mutation_id: "m1", object_id: "n1", expected_revision: 0, title: "Secret Note" },
    { mutation_id: "m1", object_id: "n1", expected_revision: 0, body: "My plain note text" },
    { mutation_id: "m1", object_id: "n1", expected_revision: 0, tags: ["private"] },
    { mutation_id: "m1", object_id: "n1", expected_revision: 0, passphrase: "password123" },
    { mutation_id: "m1", object_id: "n1", expected_revision: 0, vault_key: "raw-key-bytes" },
  ];

  for (const payload of badPayloads) {
    assert.throws(
      () => validateNoPlaintextSecrets(payload),
      (err: any) => err.message.includes("SEC-001/SEC-002 violation")
    );
  }

  // Valid opaque envelope payload passes
  const validPayload = {
    mutation_id: "m1",
    object_id: "n1",
    expected_revision: 0,
    object_kind: 1,
    envelope: createEnvelope("n1"),
    is_deleted: false,
  };
  assert.doesNotThrow(() => validateNoPlaintextSecrets(validPayload));
});

test("Zero secrets in logs (SEC-003)", async () => {
  const loggedMessages: string[] = [];
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;

  console.log = (...args) => loggedMessages.push(args.join(" "));
  console.warn = (...args) => loggedMessages.push(args.join(" "));
  console.error = (...args) => loggedMessages.push(args.join(" "));

  const storage = new IndexedDbStorage(`test-e2e-logs-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, { serverOrigin: SERVER_ORIGIN, accountId: ACCOUNT_ID, linkedAt: new Date().toISOString() });

  try {
    const adapter = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    try {
      await adapter.sync(storage);
    } catch {
      // Ignore network errors
    }

    const allLogs = loggedMessages.join("\n");
    assert.doesNotMatch(allLogs, new RegExp(AUTH_TOKEN));
    assert.doesNotMatch(allLogs, /passphrase|vault_key|private_key/i);
  } finally {
    console.log = originalLog;
    console.warn = originalWarn;
    console.error = originalError;
    await storage.close();
  }
});

test("Sync Now no longer reports 'server synchronization is not configured' once authenticated & linked", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-syncnow-linked-${Date.now()}`);
  const client = createMockSyncWorkerClient();
  const mockStore = createMockStorage();

  try {
    // 1. Unlinked state: syncNow reports "Server synchronization is not configured"
    let syncRef: ReturnType<typeof useSync> | null = null;
    const Consumer: React.FC = () => {
      syncRef = useSync();
      return <SyncStatusIndicator />;
    };

    renderToString(
      <AuthProvider serverUrl={SERVER_ORIGIN} initialSession={null}>
        <VaultProvider client={client} storage={storage} initialBootstrap={null} localStore={mockStore}>
          <SyncProvider>
            <Consumer />
          </SyncProvider>
        </VaultProvider>
      </AuthProvider>
    );

    let sync = syncRef as unknown as ReturnType<typeof useSync>;
    await sync.syncNow();
    assert.equal(sync.error, "Server synchronization is not configured. Notes remain local.");

    // 2. Link vault to account
    const linkRecord: VaultLinkRecord = {
      serverOrigin: SERVER_ORIGIN,
      accountId: ACCOUNT_ID,
      linkedAt: new Date().toISOString(),
    };
    writeVaultLink(mockStore, linkRecord);

    renderToString(
      <AuthProvider
        serverUrl={SERVER_ORIGIN}
        initialSession={{
          sessionId: "sess-alice-1",
          token: AUTH_TOKEN,
          accountId: ACCOUNT_ID,
          deviceId: "dev-1",
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }}
      >
        <VaultProvider
          client={client}
          storage={storage}
          initialBootstrap={null}
          initialVaultLink={linkRecord}
          localStore={mockStore}
        >
          <SyncProvider>
            <Consumer />
          </SyncProvider>
        </VaultProvider>
      </AuthProvider>
    );

    sync = syncRef as unknown as ReturnType<typeof useSync>;
    sync.clearError();
    await sync.syncNow();

    // The error "Server synchronization is not configured" MUST NOT appear
    assert.notEqual(sync.error, "Server synchronization is not configured. Notes remain local.");
    assert.equal(sync.status, "synced");
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("HTTP 409 replay mismatch fails closed, preserves mutation, does not record revision conflict", async () => {
  const oldFetch = globalThis.fetch;
  const storage = new IndexedDbStorage(`test-e2e-409-mismatch-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  });

  try {
    globalThis.fetch = async (input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/sync/push")) {
        return new Response(
          JSON.stringify({
            code: "MUTATION_REPLAY_MISMATCH",
            message: "Mutation replay mismatch: mutation_id already accepted with different payload",
          }),
          { status: 409, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response(JSON.stringify({}), { status: 200 });
    };

    const adapter = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    const noteId = "note-mismatch-1";
    const env = createEnvelope(noteId, "v1");
    await storage.enqueueMutation({
      mutation_id: "mut-mismatch-1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Push must fail closed with MUTATION_REPLAY_MISMATCH
    await assert.rejects(
      adapter.pushMutations(storage),
      (err: any) =>
        err instanceof SyncError &&
        err.code === "MUTATION_REPLAY_MISMATCH" &&
        err.message.includes("replay mismatch")
    );

    // Mutation MUST remain intact in storage for recovery/audit
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.mutation_id, "mut-mismatch-1");
    assert.equal(pending[0]?.status, MutationStatus.Pending);

    // No bogus conflict record was created
    const conflicts = await storage.listConflicts(false);
    assert.equal(conflicts.length, 0);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("multi-edit offline scenario: two sequential local edits encounter newer remote revision", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-multiedit-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  });

  try {
    const adapter = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    const noteId = "note-multiedit-1";
    // Remote is already at revision 3
    server.objects.set(noteId, {
      revision: 3,
      server_seq: 7,
      is_deleted: false,
      envelope: createEnvelope(noteId, "remote-rev3"),
      object_kind: 1,
    });
    server.currentSeq = 7;

    // Client made 2 offline edits in sequence:
    // Edit 1: expected_revision 1 -> 2
    // Edit 2: expected_revision 2 -> 3
    const env1 = createEnvelope(noteId, "local-offline-edit1");
    const env2 = createEnvelope(noteId, "local-offline-edit2");

    await storage.enqueueMutation({
      mutation_id: "mut-edit-1",
      object_id: noteId,
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env1,
      created_at: new Date(Date.now() - 5000).toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    await storage.enqueueMutation({
      mutation_id: "mut-edit-2",
      object_id: noteId,
      expected_revision: 2,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env2,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Push pending mutations
    const report = await adapter.pushMutations(storage);

    // First mutation conflicted with server revision 3
    assert.equal(report.conflicts.length, 1);
    assert.equal(report.accepted.length, 0);

    // Crucially: subsequent mutation mut-edit-2 was NOT pushed against stale state
    assert.equal(server.objects.get(noteId)?.revision, 3);
    assert.deepEqual(server.objects.get(noteId)?.envelope, createEnvelope(noteId, "remote-rev3"));

    // Conflict record accurately reflects the conflict on edit 1 vs remote revision 3
    const conflicts = await storage.listConflicts(false);
    assert.equal(conflicts.length, 1);
    assert.equal(conflicts[0]?.object_id, noteId);
    assert.equal(conflicts[0]?.base_revision, 1);
    assert.equal(conflicts[0]?.remote_revision, 3);

    // Both mutations remain intact in local storage queue (none prematurely deleted)
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 2);
    assert.equal(pending[0]?.mutation_id, "mut-edit-1");
    assert.equal(pending[1]?.mutation_id, "mut-edit-2");
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("multi-identity physical isolation: two identities in same browser do not leak objects, mutations, or conflicts", async () => {
  const origin = "https://sync.example.com";
  const aliceAccount = "acc-alice";
  const bobAccount = "acc-bob";

  const aliceDbName = getScopedDatabaseName(DEFAULT_DB_NAME, origin, aliceAccount);
  const bobDbName = getScopedDatabaseName(DEFAULT_DB_NAME, origin, bobAccount);

  assert.notEqual(aliceDbName, bobDbName);

  const storageAlice = new IndexedDbStorage(aliceDbName);
  const storageBob = new IndexedDbStorage(bobDbName);

  try {
    // 1. Populate Alice's isolated storage
    const aliceNoteId = "note-alice-secret";
    const aliceEnv = createEnvelope(aliceNoteId, "alice-v1");

    await storageAlice.putObject({
      object_id: aliceNoteId,
      object_kind: 1,
      revision: 1,
      server_seq: 1,
      is_deleted: false,
      envelope: aliceEnv,
      updated_at: new Date().toISOString(),
    });

    await storageAlice.enqueueMutation({
      mutation_id: "mut-alice-1",
      object_id: aliceNoteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: aliceEnv,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    await storageAlice.putConflict({
      conflict_id: "conf-alice-1",
      object_id: aliceNoteId,
      object_kind: 1,
      base_revision: 0,
      remote_revision: 1,
      base_envelope: null,
      local_envelope: aliceEnv,
      remote_envelope: aliceEnv,
      candidate_envelope: null,
      resolved: false,
      remote_is_deleted: false,
      local_is_deleted: false,
      created_at: new Date().toISOString(),
      resolved_at: null,
    });

    await storageAlice.setSyncState(
      { sync_cursor: 42, last_sync_at: "2026-10-02T10:00:00Z", device_id: "dev-alice" },
      `${origin}::${aliceAccount}`
    );

    // 2. Verify Bob's storage is completely pristine and isolated
    const bobObjects = await storageBob.listObjects();
    assert.equal(bobObjects.length, 0);

    const bobMutations = await storageBob.listPendingMutations();
    assert.equal(bobMutations.length, 0);

    const bobConflicts = await storageBob.listConflicts(false);
    assert.equal(bobConflicts.length, 0);

    const bobSyncState = await storageBob.getSyncState(`${origin}::${bobAccount}`);
    assert.equal(bobSyncState?.sync_cursor, 0);
    assert.equal(bobSyncState?.last_sync_at, null);

    // 3. Populate Bob's storage and verify Alice does not see Bob's data
    const bobNoteId = "note-bob-private";
    const bobEnv = createEnvelope(bobNoteId, "bob-v1");

    await storageBob.putObject({
      object_id: bobNoteId,
      object_kind: 1,
      revision: 1,
      server_seq: 2,
      is_deleted: false,
      envelope: bobEnv,
      updated_at: new Date().toISOString(),
    });

    const aliceObjects = await storageAlice.listObjects();
    assert.equal(aliceObjects.length, 1);
    assert.equal(aliceObjects[0]?.object_id, aliceNoteId);
  } finally {
    await storageAlice.close();
    await storageBob.close();
  }
});

test("conflict handling data-loss window: mutation is never removed before conflict record commits", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-dataloss-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  });

  try {
    const adapter = new BrowserSyncAdapter({
      serverOrigin: SERVER_ORIGIN,
      token: AUTH_TOKEN,
      accountId: ACCOUNT_ID,
      linkStorage: mockStore,
    });

    const noteId = "note-dataloss-1";
    server.objects.set(noteId, {
      revision: 2,
      server_seq: 1,
      is_deleted: false,
      envelope: createEnvelope(noteId, "remote-rev2"),
      object_kind: 1,
    });
    server.currentSeq = 1;

    const localEnv = createEnvelope(noteId, "local-rev1");
    await storage.enqueueMutation({
      mutation_id: "mut-dataloss-1",
      object_id: noteId,
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: localEnv,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // Simulate storage failure on putConflict
    const originalPutConflict = storage.putConflict.bind(storage);
    storage.putConflict = async () => {
      throw new Error("Simulated IndexedDB disk failure on putConflict");
    };

    // Push should fail because conflict record could not be written
    await assert.rejects(
      adapter.pushMutations(storage),
      (err: any) => err.message.includes("Simulated IndexedDB disk failure")
    );

    // Crucially: mutation MUST STILL BE IN QUEUE (no data loss!)
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.mutation_id, "mut-dataloss-1");

    // Restore putConflict
    storage.putConflict = originalPutConflict;
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("scoped database name is collision-resistant across punctuated and distinct origins", () => {
  const base = DEFAULT_DB_NAME;
  const name1 = getScopedDatabaseName(base, "https://a-b.example.com", "user1");
  const name2 = getScopedDatabaseName(base, "https://a.b-example.com", "user1");
  assert.notEqual(name1, name2, "distinct origins with hyphen vs dot must not collide");

  const name3 = getScopedDatabaseName(base, "https://example.com/api", "user1");
  const name4 = getScopedDatabaseName(base, "https://example.com/api2", "user1");
  assert.notEqual(name3, name4);

  const name5 = getScopedDatabaseName(base, "https://example.com", "user_1");
  const name6 = getScopedDatabaseName(base, "https://example.com", "user-1");
  assert.notEqual(name5, name6, "accounts with underscore vs hyphen must not collide");

  const name7 = getScopedDatabaseName(base, "https://example.com", "user:1");
  const name8 = getScopedDatabaseName(base, "https://example.com", "user1");
  assert.notEqual(name7, name8);
});

test("lifecycle: pre-auth notes in default DB migrate durably to scoped DB on login/link", async () => {
  const defaultStorage = new IndexedDbStorage(DEFAULT_DB_NAME);
  const noteId = "note-preauth-1";
  const env = createEnvelope(noteId, "preauth-v1");

  await defaultStorage.putObject({
    object_id: noteId,
    object_kind: 1,
    revision: 0,
    server_seq: 0,
    is_deleted: false,
    envelope: env,
    updated_at: new Date().toISOString(),
  });

  await defaultStorage.enqueueMutation({
    mutation_id: "mut-preauth-1",
    object_id: noteId,
    expected_revision: 0,
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    envelope: env,
    created_at: new Date().toISOString(),
    retry_count: 0,
    status: MutationStatus.Pending,
  });

  await defaultStorage.putBaseVersion(noteId, 0, env);

  // Now user links/authenticates with (SERVER_ORIGIN, "acc-migrated-user")
  const scopedDbName = getScopedDatabaseName(DEFAULT_DB_NAME, SERVER_ORIGIN, "acc-migrated-user");
  const scopedStorage = new IndexedDbStorage(scopedDbName);
  // User links/authenticates: explicitly migrate pre-auth data to scoped storage
  await scopedStorage.migrateFromDefault();

  // Verify records are now in scoped storage
  const migratedObj = await scopedStorage.getObject(noteId);
  assert.ok(migratedObj, "object must be migrated to scoped storage");
  assert.equal(migratedObj.object_id, noteId);

  const migratedMutations = await scopedStorage.listPendingMutations();
  assert.equal(migratedMutations.length, 1);
  assert.equal(migratedMutations[0]?.mutation_id, "mut-preauth-1");

  const migratedBase = await scopedStorage.getBaseVersion(noteId, 0);
  assert.ok(migratedBase, "base version must be migrated");

  // Verify default storage was cleared so second account does not inherit same unlinked data
  const remainingDefaultObjs = await defaultStorage.listObjects();
  assert.equal(remainingDefaultObjs.length, 0, "default storage must be cleared after migration");
  const remainingDefaultMuts = await defaultStorage.listPendingMutations();
  assert.equal(remainingDefaultMuts.length, 0);

  // Clean up
  await scopedStorage.close();
  await defaultStorage.close();
});

test("lifecycle: account switch while vault is unlocked locks worker and prevents key contamination", async () => {
  let isUnlocked = true;
  let lockCalls = 0;

  const messageListeners: any[] = [];
  const mockWorker = {
    postMessage: (msg: any) => {
      if (msg.type === "LOCK_VAULT" || msg.type === "LOCK") {
        isUnlocked = false;
        lockCalls++;
        for (const l of messageListeners) {
          l({ data: { id: msg.id, ok: true, data: null } });
        }
      } else if (msg.type === "GET_STATUS") {
        for (const l of messageListeners) {
          l({ data: { id: msg.id, ok: true, data: { isUnlocked } } });
        }
      }
    },
    addEventListener: (_type: string, listener: any) => {
      messageListeners.push(listener);
    },
    removeEventListener: () => {},
  };
  const client = new VaultWorkerClient(mockWorker as any);

  const storage1 = new IndexedDbStorage("test-identity-1");
  const store1 = new VaultStore(client, storage1);

  // Store 1 is active with unlocked worker
  assert.equal(isUnlocked, true);

  // Account switch occurs: store1 is disposed
  store1.dispose();
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(isUnlocked, false, "disposing store on identity switch must lock worker");
  assert.ok(lockCalls >= 1);

  // New store mounted for identity 2
  const storage2 = new IndexedDbStorage("test-identity-2");
  const store2 = new VaultStore(client, storage2);
  assert.notEqual(store2.getState().vaultState, "UNLOCKED", "new store must not be UNLOCKED");

  store2.dispose();
  await storage1.close();
  await storage2.close();
});

test("worker/WASM conflict-generation failure fails closed without silent fallback or data loss", async () => {
  const server = new MockSyncServer();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = server.handleFetch as unknown as typeof fetch;

  const storage = new IndexedDbStorage(`test-e2e-failclosed-conflict-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  });

  // Mock worker client whose recordConflict throws an error (e.g. cryptographic failure / tampering)
  const failingWorkerClient = {
    recordConflict: async () => {
      throw new Error("Cryptographic verification failed: tampered ciphertext during merge candidate generation (SEC-010)");
    },
  } as unknown as VaultWorkerClient;

  const adapter = new BrowserSyncAdapter({
    serverOrigin: SERVER_ORIGIN,
    token: AUTH_TOKEN,
    accountId: ACCOUNT_ID,
    linkStorage: mockStore,
    workerClient: failingWorkerClient,
  });

  const noteId = "note-failclosed-1";
  server.objects.set(noteId, {
    revision: 2,
    server_seq: 1,
    is_deleted: false,
    envelope: createEnvelope(noteId, "remote-rev2"),
    object_kind: 1,
  });
  server.currentSeq = 1;

  const localEnv = createEnvelope(noteId, "local-rev1");
  await storage.enqueueMutation({
    mutation_id: "mut-failclosed-1",
    object_id: noteId,
    expected_revision: 0,
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    envelope: localEnv,
    created_at: new Date().toISOString(),
    retry_count: 0,
    status: MutationStatus.Pending,
  });

  try {
    // Push encounters 409 conflict, calls recordConflict, which throws.
    // MUST fail closed: no silent fallback to JS constructed record!
    await assert.rejects(
      adapter.pushMutations(storage),
      (err: any) => err.message.includes("Cryptographic verification failed")
    );

    // Crucially: mutation MUST remain intact in queue marked Pending
    const pending = await storage.listPendingMutations();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.mutation_id, "mut-failclosed-1");

    // No bogus conflict record should have been written
    const conflicts = await storage.listConflicts(false);
    assert.equal(conflicts.length, 0);
  } finally {
    globalThis.fetch = oldFetch;
    await storage.close();
  }
});

test("migration: fails closed on target-write failure without clearing source storage", async () => {
  const defaultStorage = new IndexedDbStorage(`test-def-targetfail-${Date.now()}`);
  const noteId = "note-preauth-fail";
  const env = createEnvelope(noteId, "preauth-v1");
  await defaultStorage.putObject({
    object_id: noteId,
    revision: 1,
    server_seq: 0,
    object_kind: 1,
    envelope: env,
    is_deleted: false,
    updated_at: new Date().toISOString(),
  });

  const scopedStorage = new IndexedDbStorage(`test-scoped-targetfail-${Date.now()}`);

  // Monkey patch getRawDb on scopedStorage so that target transaction rejects on readwrite
  const origGetRawDb = scopedStorage.getRawDb.bind(scopedStorage);
  scopedStorage.getRawDb = async () => {
    const db = await origGetRawDb();
    const origTx = db.transaction.bind(db);
    db.transaction = (storeNames: any, mode: any) => {
      if (mode === "readwrite") {
        throw new Error("Simulated target write failure");
      }
      return origTx(storeNames, mode);
    };
    return db;
  };

  await assert.rejects(
    scopedStorage.migrateFrom(defaultStorage),
    (err: any) => String(err).includes("Simulated target write failure")
  );

  // Source storage data MUST remain intact (fail-closed!)
  const defaultObjs = await defaultStorage.listObjects();
  assert.equal(defaultObjs.length, 1);
  assert.equal(defaultObjs[0]?.object_id, noteId);

  await defaultStorage.close();
  await scopedStorage.close();
});

test("migration: fails closed on source-clear failure", async () => {
  const defaultStorage = new IndexedDbStorage(`test-def-clearfail-${Date.now()}`);
  const noteId = "note-clearfail";
  const env = createEnvelope(noteId, "clearfail-v1");
  await defaultStorage.putObject({
    object_id: noteId,
    revision: 1,
    server_seq: 0,
    object_kind: 1,
    envelope: env,
    is_deleted: false,
    updated_at: new Date().toISOString(),
  });

  const scopedStorage = new IndexedDbStorage(`test-scoped-clearfail-${Date.now()}`);

  // Simulate source clear failure
  defaultStorage.clearAllData = async () => {
    throw new Error("Simulated source clear failure");
  };

  await assert.rejects(
    scopedStorage.migrateFrom(defaultStorage),
    (err: any) => err.message.includes("Simulated source clear failure")
  );

  await defaultStorage.close();
  await scopedStorage.close();
});

function setupDomEnvironment(customStorage?: Storage) {
  (globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

  const storageMap = new Map<string, string>();
  const mockStorage: Storage = customStorage || {
    getItem: (k: string) => storageMap.get(k) ?? null,
    setItem: (k: string, v: string) => storageMap.set(k, String(v)),
    removeItem: (k: string) => storageMap.delete(k),
    clear: () => storageMap.clear(),
    key: (i: number) => Array.from(storageMap.keys())[i] ?? null,
    length: 0,
  };

  const windowListeners = new Map<string, Function[]>();

  function createMockElement(tagName = "DIV"): any {
    const listeners = new Map<string, Function[]>();
    const children: any[] = [];
    const attributes = new Map<string, string>();
    const target: any = {
      nodeType: 1,
      tagName: tagName.toUpperCase(),
      childNodes: children,
      firstChild: null,
      style: {},
      className: "",
      _textContent: "",
      get textContent(): string {
        if (target._textContent) return target._textContent;
        return children.map((c) => (c ? c.textContent || "" : "")).join("");
      },
      set textContent(v: string) {
        target._textContent = v;
      },
      innerHTML: "",
      value: "",
      removeChild(c: any) {
        const idx = children.indexOf(c);
        if (idx !== -1) children.splice(idx, 1);
        target.firstChild = children[0] || null;
        return c;
      },
      appendChild(c: any) {
        children.push(c);
        target.firstChild = children[0];
        return c;
      },
      insertBefore(c: any, ref: any) {
        const idx = children.indexOf(ref);
        if (idx === -1) children.push(c);
        else children.splice(idx, 0, c);
        target.firstChild = children[0];
        return c;
      },
      addEventListener(name: string, fn: Function) {
        if (!listeners.has(name)) listeners.set(name, []);
        listeners.get(name)!.push(fn);
      },
      removeEventListener(name: string, fn: Function) {
        const arr = listeners.get(name);
        if (arr) {
          const idx = arr.indexOf(fn);
          if (idx !== -1) arr.splice(idx, 1);
        }
      },
      setAttribute(name: string, val: any) {
        attributes.set(name, String(val));
      },
      getAttribute(name: string) {
        return attributes.get(name) ?? null;
      },
      removeAttribute(name: string) {
        attributes.delete(name);
      },
      contains(other: any) {
        if (other === target) return true;
        return children.some((c) => c && typeof c.contains === "function" && c.contains(other));
      },
      ownerDocument: null,
    };
    return target;
  }

  const container = createMockElement("DIV");
  const doc: any = {
    nodeType: 9,
    documentElement: container,
    createElement(tag: string) {
      const el = createMockElement(tag);
      el.ownerDocument = doc;
      return el;
    },
    createElementNS(_ns: string, tag: string) {
      const el = createMockElement(tag);
      el.ownerDocument = doc;
      return el;
    },
    createTextNode(text: string) {
      return { nodeType: 3, textContent: text, setAttribute() {}, removeAttribute() {} };
    },
    createComment(data: string) {
      return { nodeType: 8, data };
    },
    addEventListener() {},
    removeEventListener() {},
    activeElement: container,
  };
  container.ownerDocument = doc;

  const originalDoc = (globalThis as any).document;
  const originalWindow = (globalThis as any).window;
  const originalIframe = (globalThis as any).HTMLIFrameElement;

  (globalThis as any).HTMLIFrameElement = class HTMLIFrameElement {};
  (globalThis as any).document = doc;
  (globalThis as any).window = {
    document: doc,
    location: {
      origin: SERVER_ORIGIN,
      href: `${SERVER_ORIGIN}/`,
      protocol: SERVER_ORIGIN.startsWith("https") ? "https:" : "http:",
    },
    HTMLIFrameElement: (globalThis as any).HTMLIFrameElement,
    addEventListener(name: string, fn: Function) {
      if (!windowListeners.has(name)) windowListeners.set(name, []);
      windowListeners.get(name)!.push(fn);
    },
    removeEventListener(name: string, fn: Function) {
      const arr = windowListeners.get(name);
      if (arr) {
        const idx = arr.indexOf(fn);
        if (idx !== -1) arr.splice(idx, 1);
      }
    },
    dispatchEvent(event: any) {
      const arr = windowListeners.get(event.type);
      if (arr) {
        for (const fn of [...arr]) fn(event);
      }
      return true;
    },
    localStorage: mockStorage,
    setTimeout: (fn: any, ms?: number, ...args: any[]) => {
      const t = setTimeout(fn, ms, ...args);
      if (typeof (t as any)?.unref === "function") (t as any).unref();
      return t;
    },
    clearTimeout: (id: any) => clearTimeout(id),
    setInterval: (fn: any, ms?: number, ...args: any[]) => {
      const t = setInterval(fn, ms, ...args);
      if (typeof (t as any)?.unref === "function") (t as any).unref();
      return t;
    },
    clearInterval: (id: any) => clearInterval(id),
  };

  return {
    container,
    localStorage: mockStorage,
    cleanup() {
      (globalThis as any).document = originalDoc;
      (globalThis as any).window = originalWindow;
      (globalThis as any).HTMLIFrameElement = originalIframe;
    },
  };
}

function createMockVaultWorker(options?: {
  isUnlocked?: boolean;
  lockDelayMs?: number;
  onGetStatus?: (isUnlocked: boolean) => void;
}) {
  let isUnlocked = options?.isUnlocked ?? false;
  const messageListeners: any[] = [];
  const lockDelayMs = options?.lockDelayMs ?? 0;

  const worker = {
    postMessage: (msg: any) => {
      if (msg.type === "LOCK_VAULT" || msg.type === "LOCK") {
        if (lockDelayMs > 0) {
          setTimeout(() => {
            isUnlocked = false;
            for (const l of messageListeners) {
              l({ data: { id: msg.id, ok: true, data: null } });
            }
          }, lockDelayMs);
        } else {
          isUnlocked = false;
          for (const l of messageListeners) {
            l({ data: { id: msg.id, ok: true, data: null } });
          }
        }
      } else if (msg.type === "GET_STATUS") {
        options?.onGetStatus?.(isUnlocked);
        for (const l of messageListeners) {
          l({ data: { id: msg.id, ok: true, data: { isUnlocked } } });
        }
      } else {
        for (const l of messageListeners) {
          l({ data: { id: msg.id, ok: true, data: null } });
        }
      }
    },
    addEventListener: (_type: string, listener: any) => {
      messageListeners.push(listener);
    },
    removeEventListener: () => {},
    getIsUnlocked: () => isUnlocked,
    setIsUnlocked: (val: boolean) => {
      isUnlocked = val;
    },
  };

  return worker;
}

async function mountTestApp(
  element: React.ReactElement,
  options?: { localStorage?: Storage }
) {
  const env = setupDomEnvironment(options?.localStorage);
  const root = createRoot(env.container);
  await (React as any).act(async () => {
    root.render(element);
  });

  return {
    root,
    container: env.container,
    localStorage: env.localStorage,
    async act(fn: () => Promise<void> | void) {
      await (React as any).act(async () => {
        await fn();
      });
    },
    async update(newElement: React.ReactElement) {
      await (React as any).act(async () => {
        root.render(newElement);
      });
    },
    async settle(ms = 50) {
      await (React as any).act(async () => {
        await new Promise((r) => setTimeout(r, ms));
      });
    },
    async unmount() {
      await (React as any).act(async () => {
        root.unmount();
      });
      env.cleanup();
    },
  };
}

test("identity lifecycle: authenticating as unlinked/wrong account does not adopt scoped DB or drain default DB", async () => {
  const defaultStorage = new IndexedDbStorage(DEFAULT_DB_NAME);
  const noteId = "note-unlinked-safe";
  const env = createEnvelope(noteId, "v1");
  await defaultStorage.putObject({
    object_id: noteId,
    revision: 1,
    server_seq: 0,
    object_kind: 1,
    envelope: env,
    is_deleted: false,
    updated_at: new Date().toISOString(),
  });
  await defaultStorage.enqueueMutation({
    mutation_id: "mut-unlinked-safe",
    object_id: noteId,
    expected_revision: 0,
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    envelope: env,
    created_at: new Date().toISOString(),
    retry_count: 0,
    status: MutationStatus.Pending,
  });

  const mockWorker = createMockVaultWorker({ isUnlocked: false });
  const client = new VaultWorkerClient(mockWorker as any);

  // Scoped DB for unlinked-user-1
  const unlinkedScopedDb = getScopedDatabaseName(DEFAULT_DB_NAME, SERVER_ORIGIN, "unlinked-user-1");
  const unlinkedStorage = new IndexedDbStorage(unlinkedScopedDb);
  const linkedScopedDb = getScopedDatabaseName(DEFAULT_DB_NAME, SERVER_ORIGIN, "linked-user-1");
  const linkedStorage = new IndexedDbStorage(linkedScopedDb);

  let activeMountedDb = "";
  const harness = await mountTestApp(
    <App
      serverUrl={SERVER_ORIGIN}
      initialSession={{
        sessionId: "sess-unlinked",
        token: "tok-unlinked",
        accountId: "unlinked-user-1",
        deviceId: "dev-unlinked",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }}
      client={client}
      onMountedStateChange={(state) => {
        activeMountedDb = state.dbName;
      }}
    >
      <div id="test-observer">unlinked</div>
    </App>
  );

  try {
    // Wait for all React mount and identity effects to settle
    await harness.settle();

    // App must remain on DEFAULT_DB_NAME because vault is not linked to unlinked-user-1
    assert.equal(activeMountedDb, DEFAULT_DB_NAME);

    // Crucially: default storage remains untouched!
    const remainingDefaultObjs = await defaultStorage.listObjects();
    assert.equal(remainingDefaultObjs.length, 1);
    assert.equal(remainingDefaultObjs[0]?.object_id, noteId);
    const remainingDefaultMuts = await defaultStorage.listPendingMutations();
    assert.equal(remainingDefaultMuts.length, 1);

    // And unlinked account storage was NOT created or populated with default notes
    const unlinkedObjsAfter = await unlinkedStorage.listObjects();
    assert.equal(unlinkedObjsAfter.length, 0);

    // Now, link the vault to a linked account 'linked-user-1'
    await harness.act(() => {
      writeVaultLink(harness.localStorage, {
        serverOrigin: SERVER_ORIGIN,
        accountId: "linked-user-1",
        linkedAt: new Date().toISOString(),
      });
    });

    // Re-render App with initialSession matching the link
    await harness.update(
      <App
        serverUrl={SERVER_ORIGIN}
        initialSession={{
          sessionId: "sess-linked",
          token: "tok-linked",
          accountId: "linked-user-1",
          deviceId: "dev-linked",
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }}
        client={client}
        onMountedStateChange={(state) => {
          activeMountedDb = state.dbName;
        }}
      >
        <div id="test-observer">linked</div>
      </App>
    );

    // Settle migration and transition effects
    await harness.settle(80);

    assert.equal(activeMountedDb, linkedScopedDb, "App must adopt scoped DB when vault link matches session");

    // Verify pre-auth notes migrated to scoped storage and drained from default storage
    const migratedObj = await linkedStorage.getObject(noteId);
    assert.ok(migratedObj, "notes must be migrated into scoped storage");
    assert.equal(migratedObj.object_id, noteId);

    const drainedDefault = await defaultStorage.listObjects();
    assert.equal(drainedDefault.length, 0, "default storage must be cleared after successful migration");
  } finally {
    await harness.unmount();
    await defaultStorage.close();
    await unlinkedStorage.close();
    await linkedStorage.close();
  }
});

test("worker isolation: delayed LOCK_VAULT response prevents GET_STATUS race during identity switch", async () => {
  let statusObservedWhileUnlocked = false;
  let isTransitioning = false;

  const mockWorker = createMockVaultWorker({
    isUnlocked: true,
    lockDelayMs: 40,
    onGetStatus: (unlocked) => {
      if (isTransitioning && unlocked) {
        statusObservedWhileUnlocked = true;
      }
    },
  });

  const client = new VaultWorkerClient(mockWorker as any);

  let activeMountedDb = "";
  const handleMountedStateChange = (state: { dbName: string }) => {
    activeMountedDb = state.dbName;
    if (state.dbName !== DEFAULT_DB_NAME && mockWorker.getIsUnlocked()) {
      statusObservedWhileUnlocked = true;
    }
  };

  // Mount App initially in unlinked state (DEFAULT_DB_NAME) with unlocked client
  const harness = await mountTestApp(
    <App
      serverUrl={SERVER_ORIGIN}
      client={client}
      onMountedStateChange={handleMountedStateChange}
    >
      <div id="test-observer">test-2</div>
    </App>
  );

  try {
    await harness.settle();
    assert.equal(activeMountedDb, DEFAULT_DB_NAME);
    assert.equal(mockWorker.getIsUnlocked(), true);

    // Now initiate an actual React App transition to linked account 'linked-user-target'
    isTransitioning = true;
    statusObservedWhileUnlocked = false;

    // Pre-associate vault link in localStorage and dispatch change event
    await harness.act(() => {
      writeVaultLink(harness.localStorage, {
        serverOrigin: SERVER_ORIGIN,
        accountId: "linked-user-target",
        linkedAt: new Date().toISOString(),
      });
    });

    // Update App with authenticated session matching the link
    await harness.update(
      <App
        serverUrl={SERVER_ORIGIN}
        initialSession={{
          sessionId: "sess-target",
          token: "tok-target",
          accountId: "linked-user-target",
          deviceId: "dev-target",
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }}
        client={client}
        onMountedStateChange={handleMountedStateChange}
      >
        <div id="test-observer">test-2-target</div>
      </App>
    );

    // During the delayed LOCK_VAULT transition (e.g. 10ms into the 40ms delay),
    // App must NOT have mounted the new VaultProvider yet!
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(
      activeMountedDb,
      DEFAULT_DB_NAME,
      "App must gate mounting new VaultProvider until lockVault finishes"
    );

    // Let the 40ms delay resolve and the transition effect settle
    await harness.settle(80);

    const expectedScopedDb = getScopedDatabaseName(DEFAULT_DB_NAME, SERVER_ORIGIN, "linked-user-target");
    assert.equal(activeMountedDb, expectedScopedDb, "App must transition to target scoped DB once locked");
    assert.equal(mockWorker.getIsUnlocked(), false, "Worker must be locked after transition");
    assert.equal(statusObservedWhileUnlocked, false, "New identity must never observe unlocked status during identity switch");
  } finally {
    await harness.unmount();
  }
});

test("corrupted vault link blocks App with error screen and prevents selecting DEFAULT_DB_NAME or scoped DB", async () => {
  const mockStorageMap = new Map<string, string>();
  mockStorageMap.set("zk_vault_link", "not-valid-json{");

  const customStorage: Storage = {
    getItem: (k: string) => mockStorageMap.get(k) ?? null,
    setItem: (k: string, v: string) => mockStorageMap.set(k, String(v)),
    removeItem: (k: string) => mockStorageMap.delete(k),
    clear: () => mockStorageMap.clear(),
    key: (i: number) => Array.from(mockStorageMap.keys())[i] ?? null,
    length: mockStorageMap.size,
  };

  let activeMountedDb = "";
  const harness = await mountTestApp(
    <App
      serverUrl={SERVER_ORIGIN}
      initialSession={{
        sessionId: "sess-corrupt",
        token: "tok-corrupt",
        accountId: "user-corrupt",
        deviceId: "dev-corrupt",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }}
      onMountedStateChange={(state) => {
        activeMountedDb = state.dbName;
      }}
    >
      <div id="test-observer">should-not-mount</div>
    </App>,
    { localStorage: customStorage }
  );

  try {
    await harness.settle();

    // App MUST NOT have mounted VaultProvider or selected any DB (activeMountedDb is empty)
    assert.equal(activeMountedDb, "", "Corrupted link must not mount VaultProvider or select DB");

    // Harness container must display blocking error screen
    assert.ok(
      harness.container.textContent.includes("Vault Link Error") ||
      harness.container.innerHTML.includes("Vault Link Error"),
      "App must display blocking Vault Link Error screen"
    );
  } finally {
    await harness.unmount();
  }
});

test("push failure on 401/403, 429, and 5xx resets mutation to Pending and does not mark Failed", async () => {
  const originalFetch = globalThis.fetch;
  const storage = new IndexedDbStorage(`test-push-retryability-${Date.now()}`);
  const mockStore = createMockStorage();
  writeVaultLink(mockStore, {
    serverOrigin: SERVER_ORIGIN,
    accountId: ACCOUNT_ID,
    linkedAt: new Date().toISOString(),
  });

  const noteId = "note-retryable-1";
  const env = createEnvelope(noteId, "v1");

  const adapter = new BrowserSyncAdapter({
    serverOrigin: SERVER_ORIGIN,
    token: AUTH_TOKEN,
    accountId: ACCOUNT_ID,
    linkStorage: mockStore,
  });

  try {
    for (const statusCode of [401, 403, 429, 500, 503]) {
      // Enqueue fresh pending mutation
      const mutId = `mut-status-${statusCode}`;
      await storage.enqueueMutation({
        mutation_id: mutId,
        object_id: noteId,
        expected_revision: 0,
        object_kind: 1,
        mutation_type: MutationType.Upsert,
        envelope: env,
        created_at: new Date().toISOString(),
        retry_count: 0,
        status: MutationStatus.Pending,
      });

      // Mock fetch returning the given HTTP status
      globalThis.fetch = (async () => {
        return new Response(JSON.stringify({ error: `Simulated HTTP ${statusCode}` }), {
          status: statusCode,
          headers: { "Content-Type": "application/json" },
        });
      }) as any;

      // pushMutations must reject with error
      await assert.rejects(adapter.pushMutations(storage));

      // CRITICAL: The mutation MUST be reset to Pending (never marked Failed!)
      const pending = await storage.listPendingMutations();
      const mut = pending.find((m) => m.mutation_id === mutId);
      assert.ok(mut, `Mutation ${mutId} must remain in pending queue after HTTP ${statusCode}`);
      assert.equal(mut.status, MutationStatus.Pending, `Mutation status must be Pending after HTTP ${statusCode}`);

      // Clean up for next iteration
      await storage.removeMutation(mutId);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await storage.close();
  }
});

test("persisted vault link selects scoped DB regardless of session; logout/expiry/wrong account preserves local vault", async () => {
  const scopedDbName = getScopedDatabaseName(DEFAULT_DB_NAME, SERVER_ORIGIN, "alice-linked");
  const scopedStorage = new IndexedDbStorage(scopedDbName);
  const noteId = "note-alice-preservation";
  const env = createEnvelope(noteId, "v1");

  // Pre-populate Alice's scoped storage with a note
  await scopedStorage.putObject({
    object_id: noteId,
    revision: 1,
    server_seq: 1,
    object_kind: 1,
    envelope: env,
    is_deleted: false,
    updated_at: new Date().toISOString(),
  });

  const mockStorageMap = new Map<string, string>();
  const linkRecord = {
    serverOrigin: SERVER_ORIGIN,
    accountId: "alice-linked",
    linkedAt: new Date().toISOString(),
  };
  mockStorageMap.set("zk_vault_link", JSON.stringify(linkRecord));

  const customStorage: Storage = {
    getItem: (k: string) => mockStorageMap.get(k) ?? null,
    setItem: (k: string, v: string) => mockStorageMap.set(k, String(v)),
    removeItem: (k: string) => mockStorageMap.delete(k),
    clear: () => mockStorageMap.clear(),
    key: (i: number) => Array.from(mockStorageMap.keys())[i] ?? null,
    length: mockStorageMap.size,
  };

  let activeMountedDb = "";
  // 1. Initial mount with NO session (logged out)
  const harness = await mountTestApp(
    <App
      serverUrl={SERVER_ORIGIN}
      initialSession={null}
      onMountedStateChange={(state) => {
        activeMountedDb = state.dbName;
      }}
    >
      <div id="test-observer">logged-out</div>
    </App>,
    { localStorage: customStorage }
  );

  try {
    await harness.settle();

    // App MUST select scoped DB even when completely logged out!
    assert.equal(
      activeMountedDb,
      scopedDbName,
      "Persisted vault link must select scoped DB even when logged out"
    );

    // Alice's note is present and visible
    const objsLoggedOut = await scopedStorage.listObjects();
    assert.equal(objsLoggedOut.length, 1);
    assert.equal(objsLoggedOut[0]?.object_id, noteId);

    // 2. User logs in with matching account
    await harness.update(
      <App
        serverUrl={SERVER_ORIGIN}
        initialSession={{
          sessionId: "sess-alice",
          token: "tok-alice",
          accountId: "alice-linked",
          deviceId: "dev-alice",
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }}
        onMountedStateChange={(state) => {
          activeMountedDb = state.dbName;
        }}
      >
        <div id="test-observer">logged-in-alice</div>
      </App>
    );
    await harness.settle();
    assert.equal(activeMountedDb, scopedDbName);

    // 3. User logs out (session becomes null / expired)
    await harness.update(
      <App
        serverUrl={SERVER_ORIGIN}
        initialSession={null}
        onMountedStateChange={(state) => {
          activeMountedDb = state.dbName;
        }}
      >
        <div id="test-observer">logged-out-again</div>
      </App>
    );
    await harness.settle();
    assert.equal(
      activeMountedDb,
      scopedDbName,
      "Logging out must not switch away to default DB"
    );

    // 4. Logging into another account (e.g. bob)
    await harness.update(
      <App
        serverUrl={SERVER_ORIGIN}
        initialSession={{
          sessionId: "sess-bob",
          token: "tok-bob",
          accountId: "bob-different",
          deviceId: "dev-bob",
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        }}
        onMountedStateChange={(state) => {
          activeMountedDb = state.dbName;
        }}
      >
        <div id="test-observer">logged-in-bob</div>
      </App>
    );
    await harness.settle();
    assert.equal(
      activeMountedDb,
      scopedDbName,
      "Logging into another account must not switch local vault away from linked scoped DB"
    );

    // Encrypted local notes remain completely intact in scoped storage throughout all auth transitions
    const finalObjs = await scopedStorage.listObjects();
    assert.equal(finalObjs.length, 1);
    assert.equal(finalObjs[0]?.object_id, noteId);
  } finally {
    await harness.unmount();
    await scopedStorage.close();
  }
});
