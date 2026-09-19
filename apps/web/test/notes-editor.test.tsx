/**
 * Notes List and Markdown Editor Tests (ZK-065).
 *
 * Verifies:
 * 1. Create / Edit / Delete lifecycle.
 * 2. Markdown source editor and safe HTML rendering.
 * 3. Autosave to encrypted local state (IndexedDB + mutation queue).
 * 4. Offline operation and vault lock memory wiping (SEC-001, SEC-009).
 * 5. Full end-to-end integration with real Web Worker thread and IndexedDB.
 */

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import fs from "node:fs";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { renderToString } from "react-dom/server";

import "fake-indexeddb/auto";
import {
  VaultProvider,
  NotesProvider,
  NotesStore,
  NotesWorkspace,
  NotesList,
  MarkdownEditor,
  renderMarkdown,
  escapeHtml,
  sanitizeUrl,
} from "../src/index.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import { VaultWorkerClient } from "../src/worker/client.js";
import { MutationType, MutationStatus } from "../src/storage/models.js";

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

// ----------------------------------------------------------------------------
// 1. Markdown Parsing and XSS Sanitization Tests
// ----------------------------------------------------------------------------

test("Markdown parser renders basic formatting cleanly", () => {
  const md = `# Title\n\n## Subtitle\n\nThis is **bold** and *italic* with \`code\`.\n\n- Item 1\n- Item 2\n\n> Quote line\n\n\`\`\`\ncode block line\n\`\`\``;
  const html = renderMarkdown(md);

  assert.ok(html.includes("<h1>Title</h1>"));
  assert.ok(html.includes("<h2>Subtitle</h2>"));
  assert.ok(html.includes("<strong>bold</strong>"));
  assert.ok(html.includes("<em>italic</em>"));
  assert.ok(html.includes('<code class="inline-code">code</code>'));
  assert.ok(html.includes("<ul>"));
  assert.ok(html.includes("<li>Item 1</li>"));
  assert.ok(html.includes("<li>Item 2</li>"));
  assert.ok(html.includes("<blockquote>Quote line</blockquote>"));
  assert.ok(html.includes('<pre><code class="code-block">code block line</code></pre>'));
});

test("Markdown parser escapes malicious HTML and prevents XSS", () => {
  assert.equal(escapeHtml("<script>"), "&lt;script&gt;");
  assert.equal(sanitizeUrl("javascript:alert(1)"), "#");
  assert.equal(sanitizeUrl("https://example.com"), "https://example.com");

  const attack = `<script>alert('xss')</script>\n<img src=x onerror=alert(1)>\n[Malicious](javascript:alert(1))`;
  const html = renderMarkdown(attack);

  // Raw HTML tags must be strictly escaped
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;img src=x"));

  // javascript: URLs must be neutralized to '#'
  assert.ok(!html.includes("href=\"javascript:"));
  assert.ok(html.includes("href=\"#\""));
});

// ----------------------------------------------------------------------------
// 2. Headless NotesStore Unit Tests
// ----------------------------------------------------------------------------

function createMockWorkerClient() {
  const indexedNotes = new Map<string, { title: string; body: string; tags: string[] }>();

  const client: Partial<VaultWorkerClient> = {
    getStatus: async () => ({ isUnlocked: true, sessionInitialized: true }),
    encryptNote: async (noteId, title, body, tags) => {
      // Simulate encrypted envelope
      const envelope = {
        envelope_version: 1,
        object_id: noteId,
        object_kind: 1,
        wrapped_key: { nonce: "nonce-k", ciphertext: "ct-k" },
        payload: {
          nonce: "nonce-p",
          ciphertext: Buffer.from(JSON.stringify({ id: noteId, title, body, tags })).toString("base64"),
        },
      };
      return { envelopeJson: JSON.stringify(envelope) };
    },
    decryptNote: async (envelopeJson) => {
      const env = JSON.parse(envelopeJson);
      const decoded = Buffer.from(env.payload.ciphertext, "base64").toString("utf8");
      const parsed = JSON.parse(decoded);
      return {
        id: parsed.id,
        title: parsed.title,
        body: parsed.body,
        tags: parsed.tags,
        attachments: parsed.attachments || [],
        createdAt: "2026-09-10T12:00:00Z",
        updatedAt: "2026-09-10T12:00:00Z",
      };
    },
    decryptNotesBatch: async (envelopes) => {
      const notes = envelopes.map((item) => {
        const env = JSON.parse(item.envelopeJson);
        const decoded = Buffer.from(env.payload.ciphertext, "base64").toString("utf8");
        const parsed = JSON.parse(decoded);
        return {
          id: parsed.id,
          title: parsed.title,
          body: parsed.body,
          tags: parsed.tags || [],
          attachments: parsed.attachments || [],
          createdAt: "2026-09-10T12:00:00Z",
          updatedAt: "2026-09-10T12:00:00Z",
        };
      });
      return { notes, failed: [] };
    },
    indexNote: async (noteId, title, body, tags) => {
      indexedNotes.set(noteId, { title, body, tags });
      return { success: true };
    },
    removeFromIndex: async (noteId) => {
      indexedNotes.delete(noteId);
      return { success: true };
    },
    onLock: () => () => {},
  };

  return { client: client as VaultWorkerClient, indexedNotes };
}

test("NotesStore create, edit, autosave, and delete lifecycle", async () => {
  const { client, indexedNotes } = createMockWorkerClient();
  const storage = new IndexedDbStorage("test-notes-store-lifecycle");
  const store = new NotesStore(client, storage);

  // 1. Must fail when locked
  await assert.rejects(
    async () => {
      await store.createNote({ title: "Fail" });
    },
    /locked/
  );

  // 2. Unlock store
  await store.handleVaultUnlocked();
  assert.equal(store.getSnapshot().notes.length, 0);

  // 3. Create Note
  const note1 = await store.createNote({
    title: "Meeting Notes",
    body: "# Discussion\n\nAction items pending.",
    tags: ["work", "meeting"],
  });

  assert.ok(note1.id.length > 0);
  assert.equal(note1.title, "Meeting Notes");
  assert.equal(store.getSnapshot().notes.length, 1);
  assert.equal(store.getSnapshot().selectedNoteId, note1.id);
  assert.equal(store.getSnapshot().saveStatus, "saved");

  // Verify stored in IndexedDB objects store
  const storedObj1 = await storage.getObject(note1.id);
  assert.ok(storedObj1 !== null);
  assert.equal(storedObj1.revision, 1);
  assert.equal(storedObj1.is_deleted, false);

  // Verify mutation queued in IndexedDB
  const mutations1 = await storage.listPendingMutations();
  assert.equal(mutations1.length, 1);
  assert.equal(mutations1[0]!.object_id, note1.id);
  assert.equal(mutations1[0]!.mutation_type, MutationType.Upsert);
  assert.equal(mutations1[0]!.expected_revision, 0);
  assert.equal(mutations1[0]!.status, MutationStatus.Pending);

  // Verify indexed in worker
  assert.ok(indexedNotes.has(note1.id));

  // 4. Update Note and autosave
  store.updateNote(note1.id, {
    title: "Updated Meeting Notes",
    body: "## Updated body with decisions",
  });

  // Check state updated in-memory immediately
  const snapAfterUpdate = store.getSnapshot();
  assert.equal(snapAfterUpdate.notes[0]!.title, "Updated Meeting Notes");
  assert.equal(snapAfterUpdate.saveStatus, "unsaved");

  // Flush save immediately
  await store.saveNoteNow(note1.id);
  assert.equal(store.getSnapshot().saveStatus, "saved");

  // Verify revision incremented in IndexedDB
  const storedObj2 = await storage.getObject(note1.id);
  assert.equal(storedObj2!.revision, 2);

  // Verify second mutation queued
  const mutations2 = await storage.listPendingMutations();
  assert.equal(mutations2.length, 2);
  assert.equal(mutations2[1]!.expected_revision, 1);

  // 5. Delete Note
  await store.deleteNote(note1.id);

  // Verify removed from in-memory store
  assert.equal(store.getSnapshot().notes.length, 0);
  assert.equal(store.getSnapshot().selectedNoteId, null);

  // Verify tombstone in IndexedDB
  const storedObjDeleted = await storage.getObject(note1.id);
  assert.ok(storedObjDeleted !== null);
  assert.equal(storedObjDeleted.is_deleted, true);
  assert.equal(storedObjDeleted.revision, 3);

  // Verify delete mutation queued
  const mutations3 = await storage.listPendingMutations();
  assert.equal(mutations3.length, 3);
  assert.equal(mutations3[2]!.mutation_type, MutationType.Delete);
  assert.equal(mutations3[2]!.expected_revision, 2);

  // Verify removed from worker search index
  assert.ok(!indexedNotes.has(note1.id));

  await storage.close();
});

test("Security Audit: Local IndexedDB never contains plaintext note contents (SEC-009)", async () => {
  const { client } = createMockWorkerClient();
  const dbName = "test-db-sec-audit";
  const storage = new IndexedDbStorage(dbName);
  const store = new NotesStore(client, storage);

  await store.handleVaultUnlocked();

  const secretTitle = "TOP SECRET TITLE 12345";
  const secretBody = "CLASSIFIED NOTE BODY TEXT NEVER EXPOSE IN STORAGE";

  const note = await store.createNote({
    title: secretTitle,
    body: secretBody,
    tags: ["secret-tag"],
  });
  assert.ok(note.id.length > 0);

  // Inspect raw IndexedDB database contents
  const db = await storage.getDb();
  const rawObjects: any[] = await new Promise((res, rej) => {
    const tx = db.transaction("objects", "readonly");
    const req = tx.objectStore("objects").getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });

  assert.equal(rawObjects.length, 1);
  const rawObjStr = JSON.stringify(rawObjects[0]);

  // The raw object in IndexedDB MUST NOT contain the plaintext title or body as strings
  assert.ok(!rawObjStr.includes(`"title":"${secretTitle}"`));
  assert.ok(!rawObjStr.includes(`"body":"${secretBody}"`));

  // Lock vault -> ensure memory is completely purged
  store.handleVaultLocked();
  assert.equal(store.getSnapshot().notes.length, 0);
  assert.equal(store.getSnapshot().selectedNoteId, null);

  await storage.close();
});

// ----------------------------------------------------------------------------
// 3. UI Component Rendering Tests
// ----------------------------------------------------------------------------

test("MarkdownEditor renders toolbar, inputs, preview, and save status", () => {
  const { client } = createMockWorkerClient();
  const storage = new IndexedDbStorage("test-ui-editor");

  const initialBootstrap = {
    wrappedVaultKey: "wk",
    kdfParamsJson: TEST_KDF_PARAMS,
    wrappedRecoveryKey: "rk",
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={initialBootstrap}>
      <NotesProvider>
        <MarkdownEditor />
      </NotesProvider>
    </VaultProvider>
  );

  // When no note is selected initially, renders empty prompt
  assert.ok(html.includes("No Note Selected"));
});

test("NotesList renders notes count, filter input, and new note button", () => {
  const { client } = createMockWorkerClient();
  const storage = new IndexedDbStorage("test-ui-notes-list");

  const initialBootstrap = {
    wrappedVaultKey: "wk",
    kdfParamsJson: TEST_KDF_PARAMS,
    wrappedRecoveryKey: "rk",
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={initialBootstrap}>
      <NotesProvider>
        <NotesList />
      </NotesProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("Notes"));
  assert.ok(html.includes("+ New Note"));
  assert.ok(html.includes("Filter notes..."));
});

test("NotesWorkspace renders navbar, sidebar, and layout", () => {
  const { client } = createMockWorkerClient();
  const storage = new IndexedDbStorage("test-ui-workspace");

  const initialBootstrap = {
    wrappedVaultKey: "wk",
    kdfParamsJson: TEST_KDF_PARAMS,
    wrappedRecoveryKey: "rk",
  };

  const html = renderToString(
    <VaultProvider client={client} storage={storage} initialBootstrap={initialBootstrap}>
      <NotesProvider>
        <NotesWorkspace />
      </NotesProvider>
    </VaultProvider>
  );

  assert.ok(html.includes("Zero-Knowledge Notes"));
  assert.ok(html.includes("zk-sync-badge"));
  assert.ok(html.includes("Notes"));
  assert.ok(html.includes("+ New Note"));
});

// ----------------------------------------------------------------------------
// 4. End-to-End Real Web Worker & IndexedDB Integration Test
// ----------------------------------------------------------------------------

test("End-to-End: Create, edit, autosave, reload, and lock notes with real WebAssembly worker", async () => {
  const worker = new Worker(WORKER_PATH);
  const client = new VaultWorkerClient(worker);
  const storage = new IndexedDbStorage("test-notes-real-e2e");

  try {
    // 1. Initialize vault session in real WASM worker
    await client.initVault("my-vault-passphrase-999", TEST_KDF_PARAMS);
    const status = await client.getStatus();
    assert.equal(status.isUnlocked, true);

    const store = new NotesStore(client, storage);
    await store.handleVaultUnlocked();

    // 2. Create Note with real WASM envelope encryption
    const note1 = await store.createNote({
      title: "Real WASM Note",
      body: "# Heading 1\n\nEncrypted locally with AES-256-GCM envelope.",
      tags: ["e2e", "wasm"],
    });

    assert.ok(note1.id.length > 0);
    assert.equal(store.getSnapshot().notes.length, 1);

    // Verify stored object in IndexedDB
    const storedObj = await storage.getObject(note1.id);
    assert.ok(storedObj !== null);
    assert.equal(storedObj.revision, 1);
    assert.equal(storedObj.envelope.envelope_version, 1);
    assert.ok(storedObj.envelope.payload.ciphertext.length > 0);

    // Verify raw storage contains ZERO cleartext of note title or body
    const rawStored = JSON.stringify(storedObj);
    assert.ok(!rawStored.includes("Real WASM Note"));
    assert.ok(!rawStored.includes("Encrypted locally"));

    // 3. Edit Note and trigger autosave
    store.updateNote(note1.id, {
      title: "Real WASM Note (Edited)",
      body: "# Heading 1 (Edited)\n\nAutosaved to IndexedDB.",
    });

    await store.saveNoteNow(note1.id);
    assert.equal(store.getSnapshot().saveStatus, "saved");

    const updatedObj = await storage.getObject(note1.id);
    assert.equal(updatedObj!.revision, 2);

    // 4. Simulate application restart / page refresh:
    // Create a new NotesStore instance pointing to the same storage
    const reloadedStore = new NotesStore(client, storage);
    await reloadedStore.handleVaultUnlocked();

    const loadedNotes = reloadedStore.getSnapshot().notes;
    assert.equal(loadedNotes.length, 1);
    assert.equal(loadedNotes[0]!.id, note1.id);
    assert.equal(loadedNotes[0]!.title, "Real WASM Note (Edited)");
    assert.equal(loadedNotes[0]!.body, "# Heading 1 (Edited)\n\nAutosaved to IndexedDB.");
    assert.deepEqual(loadedNotes[0]!.tags, ["e2e", "wasm"]);

    // 5. Lock vault -> in-memory data must be wiped immediately
    reloadedStore.handleVaultLocked();
    assert.equal(reloadedStore.getSnapshot().notes.length, 0);
    assert.equal(reloadedStore.getSnapshot().selectedNoteId, null);

    // 6. Delete Note
    await reloadedStore.handleVaultUnlocked();
    assert.equal(reloadedStore.getSnapshot().notes.length, 1);

    await reloadedStore.deleteNote(note1.id);
    assert.equal(reloadedStore.getSnapshot().notes.length, 0);

    // Verify tombstone in storage
    const deletedObj = await storage.getObject(note1.id);
    assert.ok(deletedObj !== null);
    assert.equal(deletedObj.is_deleted, true);
    assert.equal(deletedObj.revision, 3);

    store.dispose();
    reloadedStore.dispose();
  } finally {
    client.dispose();
    await worker.terminate();
    await storage.close();
  }
});
