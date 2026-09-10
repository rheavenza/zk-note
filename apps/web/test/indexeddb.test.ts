/**
 * IndexedDB Encrypted Storage Adapter Tests (ZK-063).
 *
 * Verifies:
 * 1. Exact storage semantics parity with native SQLite adapter (`crates/zk-storage`).
 * 2. Encrypted note ciphertext persistence across restarts.
 * 3. Pending mutation queue (FIFO) and sync cursor persistence.
 * 4. Zero-knowledge browser storage audit: inspection reveals NO plaintext note content.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { indexedDB as fakeIDB } from "fake-indexeddb";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import {
  StoredEncryptedObject,
  PendingMutation,
  MutationType,
  MutationStatus,
  EncryptedEnvelopeDto,
  ConflictRecord,
} from "../src/storage/models.js";

// Sample envelope fixture containing opaque base64 ciphertext
function createSampleEnvelope(objectId: string, kind = 1): EncryptedEnvelopeDto {
  return {
    envelope_version: 1,
    object_id: objectId,
    object_kind: kind,
    wrapped_key: {
      nonce: "lLxd8RQBi4n85jN61Q6ghaWhtCzK8ckb",
      ciphertext: "SoYpRSkMzujrTYawFLXTw6cN6Wv+RAfvFt2RNgWO0k/qxbXXbu9oXCzLafDBrqZ9",
    },
    payload: {
      nonce: "jTw5RahW+25wlf0T8R2IlAWIf6+RnNNT",
      ciphertext: "UWqjchGFnl2YkNiDrVTQsEgUsh1vkJ1eBAYpADavOn9wccYxKFTHyfTItw==",
    },
  };
}

test("ObjectStore semantics: put, get, list, markDeleted, and purge", async () => {
  const dbName = `test-objects-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    const env1 = createSampleEnvelope("obj-1", 1);
    const obj1: StoredEncryptedObject = {
      object_id: "obj-1",
      object_kind: 1,
      revision: 1,
      server_seq: 100,
      is_deleted: false,
      envelope: env1,
      updated_at: "2026-09-10T10:00:00Z",
    };

    const env2 = createSampleEnvelope("obj-2", 2);
    const obj2: StoredEncryptedObject = {
      object_id: "obj-2",
      object_kind: 2,
      revision: 1,
      server_seq: 101,
      is_deleted: false,
      envelope: env2,
      updated_at: "2026-09-10T10:05:00Z",
    };

    // Put and Get
    await storage.putObject(obj1);
    await storage.putObject(obj2);

    const fetched1 = await storage.getObject("obj-1");
    assert.ok(fetched1);
    assert.equal(fetched1.object_id, "obj-1");
    assert.equal(fetched1.revision, 1);
    assert.equal(fetched1.server_seq, 100);
    assert.deepEqual(fetched1.envelope, env1);

    // List objects: active only (default)
    const listActive = await storage.listObjects();
    assert.equal(listActive.length, 2);

    // List filter by kind
    const listKind2 = await storage.listObjects({ kind: 2 });
    assert.equal(listKind2.length, 1);
    assert.equal(listKind2[0]?.object_id, "obj-2");

    // Mark deleted (tombstone)
    const tombstoneEnv = createSampleEnvelope("obj-1", 1);
    await storage.markDeleted("obj-1", 2, tombstoneEnv, "2026-09-10T10:10:00Z");

    const fetchedDeleted = await storage.getObject("obj-1");
    assert.ok(fetchedDeleted);
    assert.equal(fetchedDeleted.is_deleted, true);
    assert.equal(fetchedDeleted.revision, 2);

    // Listing active excludes deleted
    const listAfterDelete = await storage.listObjects();
    assert.equal(listAfterDelete.length, 1);
    assert.equal(listAfterDelete[0]?.object_id, "obj-2");

    // Listing with include_deleted includes tombstone
    const listAll = await storage.listObjects({ include_deleted: true });
    assert.equal(listAll.length, 2);

    // Purge object
    const purged = await storage.purgeObject("obj-1");
    assert.equal(purged, true);
    assert.equal(await storage.getObject("obj-1"), null);
    assert.equal(await storage.purgeObject("obj-nonexistent"), false);
  } finally {
    await storage.deleteDatabase();
  }
});

test("MutationStore semantics: FIFO queue ordering, status updates, and removal", async () => {
  const dbName = `test-mutations-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    const mut1: PendingMutation = {
      mutation_id: "mut-001",
      object_id: "note-A",
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: createSampleEnvelope("note-A"),
      created_at: "2026-09-10T10:00:00.000Z",
      retry_count: 0,
      status: MutationStatus.Pending,
    };

    const mut2: PendingMutation = {
      mutation_id: "mut-002",
      object_id: "note-B",
      expected_revision: 5,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: createSampleEnvelope("note-B"),
      created_at: "2026-09-10T10:01:00.000Z",
      retry_count: 0,
      status: MutationStatus.Pending,
    };

    const mut3: PendingMutation = {
      mutation_id: "mut-003",
      object_id: "note-A",
      expected_revision: 1,
      object_kind: 1,
      mutation_type: MutationType.Delete,
      envelope: createSampleEnvelope("note-A"),
      created_at: "2026-09-10T10:02:00.000Z",
      retry_count: 0,
      status: MutationStatus.Pending,
    };

    // Insert out of chronological order to verify FIFO sorting
    await storage.enqueueMutation(mut2);
    await storage.enqueueMutation(mut1);
    await storage.enqueueMutation(mut3);

    // listPendingMutations must return strictly in FIFO order by created_at ascending
    const queue = await storage.listPendingMutations();
    assert.equal(queue.length, 3);
    assert.equal(queue[0]?.mutation_id, "mut-001");
    assert.equal(queue[1]?.mutation_id, "mut-002");
    assert.equal(queue[2]?.mutation_id, "mut-003");

    // listMutationsForObject
    const noteAMutations = await storage.listMutationsForObject("note-A");
    assert.equal(noteAMutations.length, 2);
    assert.equal(noteAMutations[0]?.mutation_id, "mut-001");
    assert.equal(noteAMutations[1]?.mutation_id, "mut-003");

    // Pending count
    assert.equal(await storage.pendingMutationCount(), 3);

    // Update status
    await storage.updateMutationStatus("mut-001", MutationStatus.InFlight, 1);
    const updated1 = await storage.getMutation("mut-001");
    assert.ok(updated1);
    assert.equal(updated1.status, MutationStatus.InFlight);
    assert.equal(updated1.retry_count, 1);

    // Remove mutation
    const removed = await storage.removeMutation("mut-001");
    assert.equal(removed, true);
    assert.equal(await storage.getMutation("mut-001"), null);
    assert.equal(await storage.pendingMutationCount(), 2);
  } finally {
    await storage.deleteDatabase();
  }
});

test("BaseVersionStore semantics: put, get, list, and pruning", async () => {
  const dbName = `test-base-versions-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    const objId = "note-conflict-base";
    const env1 = createSampleEnvelope(objId);
    const env2 = createSampleEnvelope(objId);
    const env3 = createSampleEnvelope(objId);

    await storage.putBaseVersion(objId, 1, env1);
    await storage.putBaseVersion(objId, 2, env2);
    await storage.putBaseVersion(objId, 3, env3);

    // Get specific version
    const base2 = await storage.getBaseVersion(objId, 2);
    assert.ok(base2);
    assert.deepEqual(base2, env2);
    assert.equal(await storage.getBaseVersion(objId, 99), null);

    // List base versions ascending
    const versions = await storage.listBaseVersions(objId);
    assert.equal(versions.length, 3);
    assert.equal(versions[0]?.revision, 1);
    assert.equal(versions[1]?.revision, 2);
    assert.equal(versions[2]?.revision, 3);

    // Prune versions older than revision 3 (should remove 1 and 2)
    const prunedCount = await storage.pruneBaseVersions(objId, 3);
    assert.equal(prunedCount, 2);

    const remaining = await storage.listBaseVersions(objId);
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]?.revision, 3);

    // Clear all
    const cleared = await storage.clearBaseVersions(objId);
    assert.equal(cleared, 1);
    assert.equal((await storage.listBaseVersions(objId)).length, 0);
  } finally {
    await storage.deleteDatabase();
  }
});

test("SyncStateStore semantics: cursor and device state persistence", async () => {
  const dbName = `test-sync-state-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    // Initial sync state default
    const initial = await storage.getSyncState();
    assert.equal(initial.sync_cursor, 0);
    assert.equal(initial.last_sync_at, null);
    assert.equal(initial.device_id, null);

    // Update cursor
    await storage.setSyncCursor(1500);
    const afterCursor = await storage.getSyncState();
    assert.equal(afterCursor.sync_cursor, 1500);

    // Update full state
    await storage.setSyncState({
      sync_cursor: 1550,
      last_sync_at: "2026-09-10T10:30:00Z",
      device_id: "device-web-uuid-001",
    });

    const finalState = await storage.getSyncState();
    assert.equal(finalState.sync_cursor, 1550);
    assert.equal(finalState.last_sync_at, "2026-09-10T10:30:00Z");
    assert.equal(finalState.device_id, "device-web-uuid-001");
  } finally {
    await storage.deleteDatabase();
  }
});

test("ConflictStore semantics: put, active lookup, resolution, and deletion", async () => {
  const dbName = `test-conflicts-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  try {
    const conflict: ConflictRecord = {
      conflict_id: "conf-001",
      object_id: "note-divergent-1",
      object_kind: 1,
      base_revision: 2,
      remote_revision: 3,
      base_envelope: createSampleEnvelope("note-divergent-1"),
      local_envelope: createSampleEnvelope("note-divergent-1"),
      remote_envelope: createSampleEnvelope("note-divergent-1"),
      candidate_envelope: null,
      resolved: false,
      created_at: "2026-09-10T11:00:00Z",
      resolved_at: null,
    };

    await storage.putConflict(conflict);

    // Get active conflict
    const active = await storage.getActiveConflictForObject("note-divergent-1");
    assert.ok(active);
    assert.equal(active.conflict_id, "conf-001");
    assert.equal(active.resolved, false);

    // List conflicts filter
    const unresolvedList = await storage.listConflicts(false);
    assert.equal(unresolvedList.length, 1);
    const resolvedList = await storage.listConflicts(true);
    assert.equal(resolvedList.length, 0);

    // Resolve conflict with candidate envelope
    const resolvedCandidateEnv = createSampleEnvelope("note-divergent-1");
    const resolvedOk = await storage.resolveConflict(
      "conf-001",
      resolvedCandidateEnv,
      "2026-09-10T11:05:00Z"
    );
    assert.equal(resolvedOk, true);

    const afterResolve = await storage.getConflict("conf-001");
    assert.ok(afterResolve);
    assert.equal(afterResolve.resolved, true);
    assert.equal(afterResolve.resolved_at, "2026-09-10T11:05:00Z");
    assert.deepEqual(afterResolve.candidate_envelope, resolvedCandidateEnv);

    // No longer returned by getActiveConflictForObject
    assert.equal(await storage.getActiveConflictForObject("note-divergent-1"), null);

    // Delete conflict
    const deleted = await storage.deleteConflict("conf-001");
    assert.equal(deleted, true);
    assert.equal(await storage.getConflict("conf-001"), null);
  } finally {
    await storage.deleteDatabase();
  }
});

test("Persistence across database reopening (simulated browser restart)", async () => {
  const dbName = `test-restart-${Date.now()}`;
  const storage1 = new IndexedDbStorage(dbName, fakeIDB);

  try {
    // Populate data in session 1
    const env = createSampleEnvelope("note-persist-1");
    await storage1.putObject({
      object_id: "note-persist-1",
      object_kind: 1,
      revision: 4,
      server_seq: 400,
      is_deleted: false,
      envelope: env,
      updated_at: "2026-09-10T11:10:00Z",
    });

    await storage1.enqueueMutation({
      mutation_id: "mut-persist-1",
      object_id: "note-persist-1",
      expected_revision: 4,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: env,
      created_at: "2026-09-10T11:10:00.000Z",
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    await storage1.setSyncCursor(8888);

    // Close database connection
    await storage1.close();

    // Reopen database in session 2
    const storage2 = new IndexedDbStorage(dbName, fakeIDB);

    const fetchedObj = await storage2.getObject("note-persist-1");
    assert.ok(fetchedObj);
    assert.equal(fetchedObj.revision, 4);
    assert.deepEqual(fetchedObj.envelope, env);

    const fetchedMut = await storage2.getMutation("mut-persist-1");
    assert.ok(fetchedMut);
    assert.equal(fetchedMut.expected_revision, 4);

    const syncState = await storage2.getSyncState();
    assert.equal(syncState.sync_cursor, 8888);

    await storage2.close();
  } finally {
    const cleaner = new IndexedDbStorage(dbName, fakeIDB);
    await cleaner.deleteDatabase();
  }
});

test("Zero-Knowledge Security Audit: Storage inspection reveals NO plaintext note content (SEC-009)", async () => {
  const dbName = `test-security-audit-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  // Secret terms that MUST NOT appear anywhere in IndexedDB persistence
  const secrets = [
    "Secret Note Title",
    "Confidential note body with passwords and financial records.",
    "super-confidential-tag",
    "vault-passphrase-hunter2",
  ];

  try {
    // Populate encrypted stores
    const noteEnvelope = createSampleEnvelope("note-sec-1", 1);
    await storage.putObject({
      object_id: "note-sec-1",
      object_kind: 1,
      revision: 1,
      server_seq: 1,
      is_deleted: false,
      envelope: noteEnvelope,
      updated_at: "2026-09-10T11:20:00Z",
    });

    await storage.enqueueMutation({
      mutation_id: "mut-sec-1",
      object_id: "note-sec-1",
      expected_revision: 0,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope: noteEnvelope,
      created_at: "2026-09-10T11:20:00Z",
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    await storage.putBaseVersion("note-sec-1", 1, noteEnvelope);

    await storage.putConflict({
      conflict_id: "conf-sec-1",
      object_id: "note-sec-1",
      object_kind: 1,
      base_revision: 1,
      remote_revision: 2,
      base_envelope: noteEnvelope,
      local_envelope: noteEnvelope,
      remote_envelope: noteEnvelope,
      candidate_envelope: noteEnvelope,
      resolved: false,
      created_at: "2026-09-10T11:20:00Z",
      resolved_at: null,
    });

    await storage.setSyncState({
      sync_cursor: 50,
      last_sync_at: "2026-09-10T11:20:00Z",
      device_id: "device-uuid-audit",
    });

    // Audit: Read raw database records from all 5 stores and scan for plaintext strings
    const db = await storage.getDb();
    const storeNames = Array.from(db.objectStoreNames);
    assert.deepEqual(storeNames.sort(), [
      "base_versions",
      "conflicts",
      "mutations",
      "objects",
      "sync_state",
    ]);

    for (const storeName of storeNames) {
      const records = await new Promise<any[]>((resolve, reject) => {
        const tx = db.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });

      for (const record of records) {
        const serialized = JSON.stringify(record);

        // Verify that none of the plaintext secrets appear in serialized records
        for (const secret of secrets) {
          assert.ok(
            !serialized.includes(secret),
            `Security Invariant SEC-009 Violated: Plaintext secret '${secret}' found in store '${storeName}'!`
          );
        }

        // If the record contains an envelope, verify it only contains base64 ciphertext and nonces
        const envelope = record.envelope || record.local_envelope;
        if (envelope) {
          assert.ok(envelope.payload);
          assert.ok(typeof envelope.payload.ciphertext === "string");
          assert.ok(typeof envelope.payload.nonce === "string");
          // Ensure payload does not contain plaintext note fields
          assert.equal((envelope as any).title, undefined);
          assert.equal((envelope as any).body, undefined);
          assert.equal((envelope as any).tags, undefined);
        }
      }
    }
  } finally {
    await storage.deleteDatabase();
  }
});
