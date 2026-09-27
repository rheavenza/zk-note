import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";
import { VaultStore } from "../src/context/VaultContext.js";
import { SyncStore } from "../src/context/SyncContext.js";
import { NotesStore } from "../src/context/NotesContext.js";
import { ConflictStore } from "../src/context/ConflictContext.js";
import { IndexedDbStorage } from "../src/storage/indexeddb.js";
import type { VaultWorkerClient } from "../src/worker/client.js";

test("external-store snapshots remain stable until a state change", async () => {
  const storage = new IndexedDbStorage("snapshot-stability");
  const client = { onLock: () => () => {} } as unknown as VaultWorkerClient;
  const vault = new VaultStore(client, storage, null);
  const sync = new SyncStore(storage);
  const notes = new NotesStore(client, storage);
  const conflicts = new ConflictStore(client, storage);

  for (const store of [vault, sync, notes, conflicts]) {
    assert.strictEqual(store.getSnapshot(), store.getSnapshot());
  }
  const previous = sync.getSnapshot();
  sync.setOfflineMode(true);
  assert.notStrictEqual(sync.getSnapshot(), previous);
  assert.strictEqual(sync.getSnapshot(), sync.getSnapshot());

  vault.dispose();
  sync.dispose();
  await storage.close();
});
