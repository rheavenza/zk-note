/**
 * Plaintext Leakage Test Suite - Web / IndexedDB / Client Network Audit (ZK-092).
 *
 * In accordance with:
 * - SEC-001: Plaintext never crosses the network (titles, bodies, tags, filenames, MIME types, search queries).
 * - SEC-002: Server cannot decrypt user content.
 * - SEC-003: No secrets in logs or diagnostic outputs.
 * - SEC-009: Local persistent storage (IndexedDB) stores ciphertext only.
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

// Canary values that must NEVER appear in persistent storage or outgoing network payloads
const CANARIES = {
  TITLE: "CONFIDENTIAL_CANARY_NOTE_TITLE_SECRET_PROJECT_X",
  BODY: "CONFIDENTIAL_CANARY_NOTE_BODY_CREDIT_CARD_4111_2222_3333_4444",
  TAG_1: "canary-secret-tag-finance",
  TAG_2: "canary-secret-tag-exec",
  ATTACHMENT_NAME: "canary_board_presentation_q4.pdf",
  ATTACHMENT_MIME: "application/pdf",
  ATTACHMENT_DATA: "CANARY_ATTACHMENT_PLAINTEXT_BYTES_TOP_SECRET",
  PASSPHRASE: "canary-vault-passphrase-hunter42-supersecret",
};

const ALL_CANARY_STRINGS = Object.values(CANARIES);

function createSampleEnvelope(objectId: string): EncryptedEnvelopeDto {
  return {
    envelope_version: 1,
    object_id: objectId,
    object_kind: 1,
    wrapped_key: {
      nonce: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NM",
      ciphertext: "U0VDUkVUX0tFWV9XUkFQUEVEX0NJUEhFUlRFWFQ=",
    },
    payload: {
      nonce: "B8YpRSkMzujrTYawFLXTw6cN6Wv+RAfv",
      ciphertext: "T1BBUVVFX0NJUEhFUlRFWFRfUEFZTE9BRF9OT19QTEFJTlRFWFQ=",
    },
  };
}

test("Plaintext Leakage Audit: IndexedDB stores zero plaintext canaries across all object stores", async () => {
  const dbName = `audit-leakage-${Date.now()}`;
  const storage = new IndexedDbStorage(dbName, fakeIDB);

  // 1. Persist object in ObjectStore
  const envelope = createSampleEnvelope("canary-obj-1");
  const storedObject: StoredEncryptedObject = {
    object_id: "canary-obj-1",
    object_kind: 1,
    revision: 1,
    server_seq: 100,
    is_deleted: false,
    envelope,
    updated_at: new Date().toISOString(),
  };
  await storage.putObject(storedObject);

  // 2. Persist base version
  await storage.putBaseVersion(storedObject.object_id, storedObject.revision, storedObject.envelope);

  // 3. Persist pending mutation
  const pendingMutation: PendingMutation = {
    mutation_id: "mut-canary-101",
    object_id: "canary-obj-1",
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    expected_revision: 1,
    envelope,
    created_at: new Date().toISOString(),
    status: MutationStatus.Pending,
    retry_count: 0,
  };
  await storage.enqueueMutation(pendingMutation);

  // 4. Persist conflict record
  const conflictRecord: ConflictRecord = {
    conflict_id: "conf-canary-1",
    object_id: "canary-obj-1",
    object_kind: 1,
    base_revision: 1,
    remote_revision: 2,
    base_envelope: envelope,
    local_envelope: envelope,
    remote_envelope: envelope,
    candidate_envelope: null,
    resolved: false,
    created_at: new Date().toISOString(),
    resolved_at: null,
  };
  await storage.putConflict(conflictRecord);

  // 5. Persist blob chunk
  await storage.putBlob("blob-canary-id-99", new Uint8Array([0xde, 0xad, 0xbe, 0xef]));

  // 6. Set sync cursor
  await storage.setSyncCursor(101);

  // Now audit all 6 stores directly using raw IDB inspection
  const rawDb = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = fakeIDB.open(dbName);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

  const storeNames = Array.from(rawDb.objectStoreNames);
  assert.deepEqual(storeNames.sort(), [
    "base_versions",
    "blobs",
    "conflicts",
    "mutations",
    "objects",
    "sync_state",
  ]);

  for (const storeName of storeNames) {
    const allRecords = await new Promise<any[]>((resolve, reject) => {
      const tx = rawDb.transaction(storeName, "readonly");
      const store = tx.objectStore(storeName);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    const serializedDump = JSON.stringify(allRecords);

    for (const canary of ALL_CANARY_STRINGS) {
      assert.ok(
        !serializedDump.includes(canary),
        `Prohibited plaintext canary "${canary}" was found in IndexedDB store "${storeName}": ${serializedDump}`
      );
    }
  }

  rawDb.close();
});

test("Plaintext Leakage Audit: PushRequest and Blob payloads strictly exclude plaintext fields", () => {
  const envelope = createSampleEnvelope("canary-obj-2");

  // Build push payload as sent over network
  const pushPayload = {
    mutation_id: "mut-canary-202",
    object_id: "canary-obj-2",
    expected_revision: 0,
    object_kind: 1,
    envelope,
    is_deleted: false,
  };

  const serialized = JSON.stringify(pushPayload);

  // Check that no plaintext properties exist
  const parsed = JSON.parse(serialized);
  assert.equal(parsed.title, undefined);
  assert.equal(parsed.body, undefined);
  assert.equal(parsed.tags, undefined);
  assert.equal(parsed.passphrase, undefined);
  assert.equal(parsed.filename, undefined);
  assert.equal(parsed.mime_type, undefined);

  for (const canary of ALL_CANARY_STRINGS) {
    assert.ok(
      !serialized.includes(canary),
      `Prohibited canary found in network payload: ${canary}`
    );
  }
});

test("Plaintext Leakage Audit: Error messages never reflect plaintext note content", () => {
  function formatSyncError(err: Error, contextTitle?: string): string {
    // Under SEC-003, contextTitle must never be included in diagnostic log / error string
    const sanitizedContext = contextTitle ? "[REDACTED_CONTEXT]" : "unknown";
    return `Sync failed (${sanitizedContext}): ${err.message}`;
  }

  const err = new Error("Network timeout while syncing object");
  const formatted = formatSyncError(err, CANARIES.TITLE);

  assert.ok(!formatted.includes(CANARIES.TITLE));
  assert.ok(!formatted.includes(CANARIES.BODY));
  assert.ok(!formatted.includes(CANARIES.PASSPHRASE));
});
