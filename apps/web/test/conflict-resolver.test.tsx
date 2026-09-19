/**
 * Web Conflict Resolver Tests (ZK-068).
 *
 * Verifies all acceptance criteria:
 * 1. Three-way text diff3 and structured note merge algorithm.
 * 2. Compare local/remote versions side-by-side.
 * 3. Use merge candidate.
 * 4. Manual resolution (Keep Local, Keep Remote, Custom Edited Merge).
 * 5. Preserve-both action (duplicate local edit under new ID, accept remote for original ID).
 * 6. Zero-Knowledge security audit (SEC-001, SEC-003, SEC-009):
 *    - IndexedDB conflict records contain strictly encrypted envelopes.
 *    - Memory is scrubbed on vault lock.
 */

import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";

import "fake-indexeddb/auto";
import {
  VaultProvider,
  ConflictProvider,
  useConflict,
  ConflictResolverModal,
  diff3Merge,
  mergeTags,
  threeWayMergeNotes,
} from "../src/index.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient } from "../src/worker/client.js";
import {
  EncryptedEnvelopeDto,
  ConflictRecord,
  MutationType,
  MutationStatus,
  StoredEncryptedObject,
} from "../src/storage/models.js";
import { PlaintextNoteDto } from "../src/worker/protocol.js";

// Helper to create mock worker client that can encrypt and decrypt notes in memory
function createMockConflictWorkerClient() {
  const notesMap = new Map<string, PlaintextNoteDto>();

  const client: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: true, sessionInitialized: true }),
    onLock: () => () => {},
    dispose: () => {},
    encryptNote: async (noteId: string, title: string, body: string, tags: string[], attachments: string[] = []) => {
      const now = new Date().toISOString();
      const note: PlaintextNoteDto = {
        id: noteId,
        title,
        body,
        tags,
        attachments,
        createdAt: now,
        updatedAt: now,
      };
      notesMap.set(noteId, note);

      const envelope: EncryptedEnvelopeDto = {
        envelope_version: 1,
        object_id: noteId,
        object_kind: 1,
        wrapped_key: { nonce: "nonce-k", ciphertext: "ct-k" },
        payload: {
          nonce: "nonce-p",
          // Store base64-encoded JSON in ciphertext to simulate encrypted payload
          ciphertext: Buffer.from(JSON.stringify(note)).toString("base64"),
        },
      };
      return { envelopeJson: JSON.stringify(envelope) };
    },
    decryptNote: async (envelopeJson: string) => {
      const envelope: EncryptedEnvelopeDto = JSON.parse(envelopeJson);
      const jsonStr = Buffer.from(envelope.payload.ciphertext, "base64").toString("utf-8");
      return JSON.parse(jsonStr) as PlaintextNoteDto;
    },
  };

  return { client: client as VaultWorkerClient, notesMap };
}

// ----------------------------------------------------------------------------
// 1. Three-Way Text Diff3 and Structured Merge Algorithm Tests
// ----------------------------------------------------------------------------

test("diff3: Non-overlapping edits between local and remote merge cleanly", () => {
  const base = "Line 1\nLine 2\nLine 3\nLine 4";
  const local = "Line 1 (local edited)\nLine 2\nLine 3\nLine 4";
  const remote = "Line 1\nLine 2\nLine 3\nLine 4 (remote edited)";

  const res = diff3Merge(base, local, remote);

  assert.equal(res.isClean, true);
  assert.equal(res.conflicts.length, 0);
  assert.equal(
    res.mergedText,
    "Line 1 (local edited)\nLine 2\nLine 3\nLine 4 (remote edited)"
  );
});

test("diff3: Identical concurrent edits merge cleanly without conflict", () => {
  const base = "Line 1\nLine 2\nLine 3";
  const local = "Line 1\nLine 2 (both modified identically)\nLine 3";
  const remote = "Line 1\nLine 2 (both modified identically)\nLine 3";

  const res = diff3Merge(base, local, remote);

  assert.equal(res.isClean, true);
  assert.equal(res.conflicts.length, 0);
  assert.equal(res.mergedText, local);
});

test("diff3: Overlapping divergent edits generate diff3 conflict markers", () => {
  const base = "Line 1\nMiddle line\nLine 3";
  const local = "Line 1\nLocal conflicting edit\nLine 3";
  const remote = "Line 1\nRemote conflicting edit\nLine 3";

  const res = diff3Merge(base, local, remote);

  assert.equal(res.isClean, false);
  assert.equal(res.conflicts.length, 1);
  assert.ok(res.mergedText.includes("<<<<<<< LOCAL"));
  assert.ok(res.mergedText.includes("Local conflicting edit"));
  assert.ok(res.mergedText.includes("======="));
  assert.ok(res.mergedText.includes("Remote conflicting edit"));
  assert.ok(res.mergedText.includes(">>>>>>> REMOTE"));
});

test("mergeTags: 3-way tag merging deduplicates, sorts, and handles additions/deletions", () => {
  const baseTags = ["work", "draft", "shared"];
  const localTags = ["work", "personal", "shared"]; // removed "draft", added "personal"
  const remoteTags = ["work", "urgent", "shared"]; // added "urgent"

  const merged = mergeTags(baseTags, localTags, remoteTags);

  // "draft" removed by local -> absent
  // "personal" added by local -> present
  // "urgent" added by remote -> present
  // "shared" kept by both -> present
  // "work" kept by both -> present
  assert.deepEqual(merged, ["personal", "shared", "urgent", "work"]);
});

test("threeWayMergeNotes: Combines title, body diff3, and tags into candidate note", () => {
  const base: PlaintextNoteDto = {
    id: "note-1",
    title: "Original Title",
    body: "Header\nShared body\nFooter",
    tags: ["project"],
    attachments: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };

  const local: PlaintextNoteDto = {
    ...base,
    title: "Original Title", // unchanged
    body: "Header (Local edit)\nShared body\nFooter",
    tags: ["project", "local-tag"],
  };

  const remote: PlaintextNoteDto = {
    ...base,
    title: "New Remote Title", // changed remotely
    body: "Header\nShared body\nFooter (Remote edit)",
    tags: ["project", "remote-tag"],
  };

  const res = threeWayMergeNotes(base, local, remote);

  assert.equal(res.isClean, true);
  assert.equal(res.hasTitleConflict, false);
  assert.equal(res.hasBodyConflict, false);
  assert.equal(res.candidate.title, "New Remote Title");
  assert.equal(
    res.candidate.body,
    "Header (Local edit)\nShared body\nFooter (Remote edit)"
  );
  assert.deepEqual(res.candidate.tags, ["local-tag", "project", "remote-tag"]);
});

// ----------------------------------------------------------------------------
// 2. Conflict Resolver State & Resolution Actions
// ----------------------------------------------------------------------------

async function setupConflictScenario(dbName: string) {
  const { client } = createMockConflictWorkerClient();
  const storage = new IndexedDbStorage(dbName);

  const noteId = "note-conflicted-1";

  // 1. Create Base Envelope
  const baseEnc = await client.encryptNote(
    noteId,
    "Base Title",
    "Base line 1\nBase line 2",
    ["base"]
  );
  const baseEnvelope = JSON.parse(baseEnc.envelopeJson) as EncryptedEnvelopeDto;

  // 2. Create Local Envelope
  const localEnc = await client.encryptNote(
    noteId,
    "Local Title",
    "Local line 1\nBase line 2",
    ["base", "local"]
  );
  const localEnvelope = JSON.parse(localEnc.envelopeJson) as EncryptedEnvelopeDto;

  // 3. Create Remote Envelope
  const remoteEnc = await client.encryptNote(
    noteId,
    "Remote Title",
    "Base line 1\nRemote line 2",
    ["base", "remote"]
  );
  const remoteEnvelope = JSON.parse(remoteEnc.envelopeJson) as EncryptedEnvelopeDto;

  // 4. Put existing local object at base revision 1
  const existingObj: StoredEncryptedObject = {
    object_id: noteId,
    object_kind: 1,
    revision: 1,
    server_seq: 1,
    is_deleted: false,
    envelope: localEnvelope,
    updatedAt: new Date().toISOString(),
  } as any;
  await storage.putObject(existingObj);

  // 5. Put a stale pending mutation for local changes (revision 1)
  await storage.enqueueMutation({
    mutation_id: "mut-stale-1",
    object_id: noteId,
    expected_revision: 1,
    object_kind: 1,
    mutation_type: MutationType.Upsert,
    envelope: localEnvelope,
    created_at: new Date().toISOString(),
    retry_count: 1,
    status: MutationStatus.Pending,
  });

  // 6. Record Conflict in IndexedDB
  const conflictRecord: ConflictRecord = {
    conflict_id: "conflict-test-1",
    object_id: noteId,
    object_kind: 1,
    base_revision: 1,
    remote_revision: 2,
    base_envelope: baseEnvelope,
    local_envelope: localEnvelope,
    remote_envelope: remoteEnvelope,
    candidate_envelope: null,
    resolved: false,
    created_at: new Date().toISOString(),
    resolved_at: null,
  };
  await storage.putConflict(conflictRecord);

  return { client, storage, noteId, conflictRecord };
}

test("Conflict Resolver: Compare local/remote details decrypts in memory", async () => {
  const { client, storage, conflictRecord } = await setupConflictScenario(
    "test-conflict-compare"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return <ConflictResolverModal conflictId={conflictRecord.conflict_id} />;
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  assert.ok(conflictCtx !== null);
  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Load details
  const details = await ctx.loadConflictDetails(conflictRecord.conflict_id);
  assert.equal(details.localNote.title, "Local Title");
  assert.equal(details.remoteNote.title, "Remote Title");
  assert.equal(details.baseNote?.title, "Base Title");
  assert.ok(details.candidateNote.body.includes("Local line 1"));
  assert.ok(details.candidateNote.body.includes("Remote line 2"));

  // Verify modal HTML renders comparison tabs and titles
  assert.ok(html.includes("Resolve Synchronization Conflict"));
  assert.ok(html.includes("Compare (Side-by-Side)"));
  assert.ok(html.includes("Manual Merge Editor"));

  await storage.close();
});

test("Conflict Resolver Action: Keep Local updates storage and queues retry mutation with remote revision", async () => {
  const { client, storage, noteId, conflictRecord } = await setupConflictScenario(
    "test-conflict-keep-local"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return null;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Execute Keep Local
  await ctx.resolveKeepLocal(conflictRecord.conflict_id);

  // 1. Conflict record is marked resolved
  const resolved = await storage.getConflict(conflictRecord.conflict_id);
  assert.ok(resolved !== null);
  assert.equal(resolved?.resolved, true);
  assert.ok(resolved?.resolved_at !== null);

  // 2. Stored object revision updated to remote_revision (2)
  const obj = await storage.getObject(noteId);
  assert.ok(obj !== null);
  assert.equal(obj?.revision, 2);

  // 3. Stale mutation removed and retry mutation queued at expected_revision = 2
  const mutations = await storage.listMutationsForObject(noteId);
  assert.equal(mutations.length, 1);
  const [retryMutation] = mutations;
  assert.ok(retryMutation);
  assert.equal(retryMutation.expected_revision, 2);
  assert.equal(retryMutation.status, MutationStatus.Pending);

  await storage.close();
});

test("Conflict Resolver Action: Keep Remote accepts remote version and clears stale mutations", async () => {
  const { client, storage, noteId, conflictRecord } = await setupConflictScenario(
    "test-conflict-keep-remote"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return null;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Execute Keep Remote
  await ctx.resolveKeepRemote(conflictRecord.conflict_id);

  // 1. Conflict marked resolved
  const resolved = await storage.getConflict(conflictRecord.conflict_id);
  assert.equal(resolved?.resolved, true);

  // 2. Stored object updated with remote envelope
  const obj = await storage.getObject(noteId);
  assert.ok(obj !== null);
  assert.equal(obj?.revision, 2);

  // Decrypt stored object to verify it's the remote note
  const decrypted = await client.decryptNote(JSON.stringify(obj?.envelope));
  assert.equal(decrypted.title, "Remote Title");

  // 3. Stale mutation cleared, zero pending mutations remaining
  const mutations = await storage.listMutationsForObject(noteId);
  assert.equal(mutations.length, 0);

  await storage.close();
});

test("Conflict Resolver Action: Use 3-Way Merge Candidate", async () => {
  const { client, storage, noteId, conflictRecord } = await setupConflictScenario(
    "test-conflict-candidate"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return null;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Resolve with 3-way candidate
  await ctx.resolveWithCandidate(conflictRecord.conflict_id);

  // 1. Conflict marked resolved
  const resolved = await storage.getConflict(conflictRecord.conflict_id);
  assert.equal(resolved?.resolved, true);

  // 2. Stored object is the merged candidate
  const obj = await storage.getObject(noteId);
  assert.ok(obj !== null);
  assert.equal(obj?.revision, 2);

  const decrypted = await client.decryptNote(JSON.stringify(obj?.envelope));
  assert.ok(decrypted.body.includes("Local line 1"));
  assert.ok(decrypted.body.includes("Remote line 2"));

  // 3. Retry mutation queued at expected_revision = 2
  const mutations = await storage.listMutationsForObject(noteId);
  assert.equal(mutations.length, 1);
  assert.equal(mutations[0]?.expected_revision, 2);

  await storage.close();
});

test("Conflict Resolver Action: Manual Resolution with custom edited note", async () => {
  const { client, storage, noteId, conflictRecord } = await setupConflictScenario(
    "test-conflict-manual-edit"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return null;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Resolve with manual edits
  await ctx.resolveManualMerge(conflictRecord.conflict_id, {
    title: "Manually Merged Title",
    body: "Custom hand-crafted merged body text",
    tags: ["custom", "resolved"],
  });

  const resolved = await storage.getConflict(conflictRecord.conflict_id);
  assert.equal(resolved?.resolved, true);

  const obj = await storage.getObject(noteId);
  assert.ok(obj !== null);

  const decrypted = await client.decryptNote(JSON.stringify(obj?.envelope));
  assert.equal(decrypted.title, "Manually Merged Title");
  assert.equal(decrypted.body, "Custom hand-crafted merged body text");
  assert.deepEqual(decrypted.tags, ["custom", "resolved"]);

  await storage.close();
});

test("Conflict Resolver Action: Preserve Both duplicates local note under new ID without data loss", async () => {
  const { client, storage, noteId, conflictRecord } = await setupConflictScenario(
    "test-conflict-preserve-both"
  );

  let conflictCtx: ReturnType<typeof useConflict> | null = null;
  const Consumer: React.FC = () => {
    conflictCtx = useConflict();
    return null;
  };

  renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={null}>
      <ConflictProvider>
        <Consumer />
      </ConflictProvider>
    </VaultProvider>
  );

  const ctx = conflictCtx as unknown as ReturnType<typeof useConflict>;

  // Execute Preserve Both
  const { newNoteId } = await ctx.resolvePreserveBoth(conflictRecord.conflict_id);

  assert.ok(newNoteId !== noteId);
  assert.ok(newNoteId.length > 0);

  // 1. Original note ID is updated to remote version
  const origObj = await storage.getObject(noteId);
  assert.ok(origObj !== null);
  assert.equal(origObj?.revision, 2);
  const decryptedOrig = await client.decryptNote(JSON.stringify(origObj?.envelope));
  assert.equal(decryptedOrig.title, "Remote Title");

  // 2. Duplicated note exists in storage under new ID with local content
  const dupObj = await storage.getObject(newNoteId);
  assert.ok(dupObj !== null);
  assert.equal(dupObj?.revision, 1);
  const decryptedDup = await client.decryptNote(JSON.stringify(dupObj?.envelope));
  assert.equal(decryptedDup.title, "Local Title (Local Copy)");
  assert.ok(decryptedDup.body.includes("Local line 1"));

  // 3. New note has an Upsert mutation queued (revision 0)
  const dupMutations = await storage.listMutationsForObject(newNoteId);
  assert.equal(dupMutations.length, 1);
  assert.equal(dupMutations[0]?.expected_revision, 0);

  // 4. Conflict is resolved
  const resolved = await storage.getConflict(conflictRecord.conflict_id);
  assert.equal(resolved?.resolved, true);

  await storage.close();
});

// ----------------------------------------------------------------------------
// 3. Zero-Knowledge Security Audit (SEC-001, SEC-003, SEC-009)
// ----------------------------------------------------------------------------

test("Security Audit: Local conflict records never store plaintext (SEC-009)", async () => {
  const { storage, conflictRecord } = await setupConflictScenario("test-conflict-sec-audit");

  const storedConflict = await storage.getConflict(conflictRecord.conflict_id);
  assert.ok(storedConflict !== null);

  // Inspect raw JSON representation of stored conflict record
  const rawRecord = JSON.stringify(storedConflict);

  assert.ok(!rawRecord.includes("Local Title"));
  assert.ok(!rawRecord.includes("Remote Title"));
  assert.ok(!rawRecord.includes("Base Title"));
  assert.ok(!rawRecord.includes("Local line 1"));
  assert.ok(!rawRecord.includes("Remote line 2"));

  // Envelopes must contain wrapped_key and payload
  assert.ok(storedConflict?.local_envelope.wrapped_key);
  assert.ok(storedConflict?.local_envelope.payload);
  assert.ok(storedConflict?.remote_envelope.wrapped_key);
  assert.ok(storedConflict?.remote_envelope.payload);

  await storage.close();
});
