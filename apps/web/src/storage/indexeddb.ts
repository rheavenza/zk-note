/**
 * IndexedDB Encrypted Storage Adapter (ZK-063).
 *
 * Implements the browser encrypted persistent cache with exact semantic parity
 * to the native SQLite storage adapter (`crates/zk-storage`).
 *
 * Security Invariants:
 * - SEC-001 / SEC-002: Stores ciphertext and encrypted envelopes only.
 * - SEC-009: Persistent local cache never stores plaintext note contents.
 * - Monotonic sync cursor and FIFO mutation queue.
 * - Tombstones prevent stale resurrection.
 */

import {
  StoredEncryptedObject,
  ObjectFilter,
  PendingMutation,
  MutationStatus,
  SyncState,
  ConflictRecord,
  EncryptedEnvelopeDto,
} from "./models.js";

export const DB_SCHEMA_VERSION = 1;
export const DEFAULT_DB_NAME = "zk_notes_db";

export class IndexedDbStorage {
  private dbName: string;
  private idbFactory: IDBFactory;
  private dbPromise: Promise<IDBDatabase> | null = null;

  constructor(dbName = DEFAULT_DB_NAME, idbFactory?: IDBFactory) {
    this.dbName = dbName;
    this.idbFactory =
      idbFactory ||
      (typeof indexedDB !== "undefined"
        ? indexedDB
        : (typeof globalThis !== "undefined" && (globalThis as any).indexedDB) ||
          null);

    if (!this.idbFactory) {
      throw new Error("IndexedDB is not available in the current environment.");
    }
  }

  /**
   * Opens or initializes the IndexedDB database.
   */
  public async getDb(): Promise<IDBDatabase> {
    if (this.dbPromise) {
      return this.dbPromise;
    }

    this.dbPromise = new Promise((resolve, reject) => {
      const request = this.idbFactory.open(this.dbName, DB_SCHEMA_VERSION);

      request.onupgradeneeded = (event) => {
        const db = request.result;
        this.initializeSchema(db, event.oldVersion);
      };

      request.onsuccess = () => {
        resolve(request.result);
      };

      request.onerror = () => {
        reject(request.error || new Error("Failed to open IndexedDB database"));
      };
    });

    return this.dbPromise;
  }

  private initializeSchema(db: IDBDatabase, _oldVersion: number): void {
    // 1. Objects Store (encrypted envelopes)
    if (!db.objectStoreNames.contains("objects")) {
      const objectsStore = db.createObjectStore("objects", { keyPath: "object_id" });
      objectsStore.createIndex("by_kind", "object_kind", { unique: false });
      objectsStore.createIndex("by_is_deleted", "is_deleted", { unique: false });
      objectsStore.createIndex("by_updated_at", "updated_at", { unique: false });
    }

    // 2. Pending Mutations Store (FIFO queue)
    if (!db.objectStoreNames.contains("mutations")) {
      const mutationsStore = db.createObjectStore("mutations", { keyPath: "mutation_id" });
      mutationsStore.createIndex("by_object_id", "object_id", { unique: false });
      mutationsStore.createIndex("by_created_at", "created_at", { unique: false });
      mutationsStore.createIndex("by_status", "status", { unique: false });
    }

    // 3. Base Versions Store (for 3-way conflict merge)
    if (!db.objectStoreNames.contains("base_versions")) {
      const baseStore = db.createObjectStore("base_versions", {
        keyPath: ["object_id", "revision"],
      });
      baseStore.createIndex("by_object_id", "object_id", { unique: false });
    }

    // 4. Sync State Store (singleton)
    if (!db.objectStoreNames.contains("sync_state")) {
      db.createObjectStore("sync_state", { keyPath: "key" });
    }

    // 5. Conflicts Store (persistent conflict records)
    if (!db.objectStoreNames.contains("conflicts")) {
      const conflictsStore = db.createObjectStore("conflicts", { keyPath: "conflict_id" });
      conflictsStore.createIndex("by_object_id", "object_id", { unique: false });
      conflictsStore.createIndex("by_resolved", "resolved", { unique: false });
    }
  }

  // ==========================================================================
  // ObjectStore Implementation
  // ==========================================================================

  public async getObject(objectId: string): Promise<StoredEncryptedObject | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("objects", "readonly");
      const store = tx.objectStore("objects");
      const req = store.get(objectId);

      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  public async putObject(object: StoredEncryptedObject): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("objects", "readwrite");
      const store = tx.objectStore("objects");
      const req = store.put(object);

      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async listObjects(filter?: ObjectFilter): Promise<StoredEncryptedObject[]> {
    const db = await this.getDb();
    const includeDeleted = filter?.include_deleted ?? false;
    const kindFilter = filter?.kind;

    return new Promise((resolve, reject) => {
      const tx = db.transaction("objects", "readonly");
      const store = tx.objectStore("objects");
      const req = store.getAll();

      req.onsuccess = () => {
        let results: StoredEncryptedObject[] = req.result || [];
        if (!includeDeleted) {
          results = results.filter((o) => !o.is_deleted);
        }
        if (kindFilter !== undefined) {
          results = results.filter((o) => o.object_kind === kindFilter);
        }
        resolve(results);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async markDeleted(
    objectId: string,
    revision: number,
    envelope: EncryptedEnvelopeDto,
    updatedAt: string
  ): Promise<void> {
    const existing = await this.getObject(objectId);
    const tombstone: StoredEncryptedObject = {
      object_id: objectId,
      object_kind: existing ? existing.object_kind : envelope.object_kind,
      revision,
      server_seq: existing ? existing.server_seq : 0,
      is_deleted: true,
      envelope,
      updated_at: updatedAt,
    };
    await this.putObject(tombstone);
  }

  public async purgeObject(objectId: string): Promise<boolean> {
    const existing = await this.getObject(objectId);
    if (!existing) {
      return false;
    }
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("objects", "readwrite");
      const store = tx.objectStore("objects");
      const req = store.delete(objectId);

      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  // ==========================================================================
  // MutationStore Implementation
  // ==========================================================================

  public async enqueueMutation(mutation: PendingMutation): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readwrite");
      const store = tx.objectStore("mutations");
      const req = store.put(mutation);

      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async getMutation(mutationId: string): Promise<PendingMutation | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readonly");
      const store = tx.objectStore("mutations");
      const req = store.get(mutationId);

      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  public async listPendingMutations(): Promise<PendingMutation[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readonly");
      const store = tx.objectStore("mutations");
      const req = store.getAll();

      req.onsuccess = () => {
        const mutations: PendingMutation[] = req.result || [];
        // FIFO order: sort by created_at ascending, breaking ties with expected_revision
        mutations.sort((a, b) => {
          const cmp = a.created_at.localeCompare(b.created_at);
          if (cmp !== 0) return cmp;
          return a.expected_revision - b.expected_revision;
        });
        resolve(mutations);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async listMutationsForObject(objectId: string): Promise<PendingMutation[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readonly");
      const store = tx.objectStore("mutations");
      const index = store.index("by_object_id");
      const req = index.getAll(objectId);

      req.onsuccess = () => {
        const mutations: PendingMutation[] = req.result || [];
        mutations.sort((a, b) => {
          const cmp = a.created_at.localeCompare(b.created_at);
          if (cmp !== 0) return cmp;
          return a.expected_revision - b.expected_revision;
        });
        resolve(mutations);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async removeMutation(mutationId: string): Promise<boolean> {
    const existing = await this.getMutation(mutationId);
    if (!existing) {
      return false;
    }
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readwrite");
      const store = tx.objectStore("mutations");
      const req = store.delete(mutationId);

      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  public async updateMutationStatus(
    mutationId: string,
    status: MutationStatus,
    retryCount: number
  ): Promise<void> {
    const mutation = await this.getMutation(mutationId);
    if (!mutation) {
      throw new Error(`Mutation ${mutationId} not found`);
    }
    mutation.status = status;
    mutation.retry_count = retryCount;
    await this.enqueueMutation(mutation);
  }

  public async pendingMutationCount(): Promise<number> {
    const mutations = await this.listPendingMutations();
    return mutations.filter(
      (m) => m.status === MutationStatus.Pending || m.status === MutationStatus.InFlight
    ).length;
  }

  // ==========================================================================
  // BaseVersionStore Implementation
  // ==========================================================================

  public async putBaseVersion(
    objectId: string,
    revision: number,
    envelope: EncryptedEnvelopeDto
  ): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("base_versions", "readwrite");
      const store = tx.objectStore("base_versions");
      const req = store.put({
        object_id: objectId,
        revision,
        envelope,
      });

      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async getBaseVersion(
    objectId: string,
    revision: number
  ): Promise<EncryptedEnvelopeDto | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("base_versions", "readonly");
      const store = tx.objectStore("base_versions");
      const req = store.get([objectId, revision]);

      req.onsuccess = () => {
        if (req.result && req.result.envelope) {
          resolve(req.result.envelope);
        } else {
          resolve(null);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async listBaseVersions(
    objectId: string
  ): Promise<Array<{ revision: number; envelope: EncryptedEnvelopeDto }>> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("base_versions", "readonly");
      const store = tx.objectStore("base_versions");
      const index = store.index("by_object_id");
      const req = index.getAll(objectId);

      req.onsuccess = () => {
        const list: Array<{ revision: number; envelope: EncryptedEnvelopeDto }> = (
          req.result || []
        ).map((r: any) => ({
          revision: r.revision,
          envelope: r.envelope,
        }));
        list.sort((a, b) => a.revision - b.revision);
        resolve(list);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async pruneBaseVersions(objectId: string, olderThanRevision: number): Promise<number> {
    const db = await this.getDb();
    const versions = await this.listBaseVersions(objectId);
    const toPrune = versions.filter((v) => v.revision < olderThanRevision);

    if (toPrune.length === 0) {
      return 0;
    }

    return new Promise((resolve, reject) => {
      const tx = db.transaction("base_versions", "readwrite");
      const store = tx.objectStore("base_versions");

      for (const item of toPrune) {
        store.delete([objectId, item.revision]);
      }

      tx.oncomplete = () => resolve(toPrune.length);
      tx.onerror = () => reject(tx.error);
    });
  }

  public async clearBaseVersions(objectId: string): Promise<number> {
    const versions = await this.listBaseVersions(objectId);
    if (versions.length === 0) {
      return 0;
    }

    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("base_versions", "readwrite");
      const store = tx.objectStore("base_versions");

      for (const item of versions) {
        store.delete([objectId, item.revision]);
      }

      tx.oncomplete = () => resolve(versions.length);
      tx.onerror = () => reject(tx.error);
    });
  }

  // ==========================================================================
  // SyncStateStore Implementation
  // ==========================================================================

  public async getSyncState(): Promise<SyncState> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sync_state", "readonly");
      const store = tx.objectStore("sync_state");
      const req = store.get("singleton");

      req.onsuccess = () => {
        if (req.result && req.result.state) {
          resolve(req.result.state);
        } else {
          resolve({
            sync_cursor: 0,
            last_sync_at: null,
            device_id: null,
          });
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async setSyncCursor(cursor: number): Promise<void> {
    const current = await this.getSyncState();
    current.sync_cursor = cursor;
    await this.setSyncState(current);
  }

  public async setSyncState(state: SyncState): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sync_state", "readwrite");
      const store = tx.objectStore("sync_state");
      const req = store.put({
        key: "singleton",
        state,
      });

      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // ==========================================================================
  // ConflictStore Implementation
  // ==========================================================================

  public async putConflict(conflict: ConflictRecord): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("conflicts", "readwrite");
      const store = tx.objectStore("conflicts");
      const req = store.put(conflict);

      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async getConflict(conflictId: string): Promise<ConflictRecord | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("conflicts", "readonly");
      const store = tx.objectStore("conflicts");
      const req = store.get(conflictId);

      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  public async getActiveConflictForObject(objectId: string): Promise<ConflictRecord | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("conflicts", "readonly");
      const store = tx.objectStore("conflicts");
      const index = store.index("by_object_id");
      const req = index.getAll(objectId);

      req.onsuccess = () => {
        const records: ConflictRecord[] = req.result || [];
        const active = records.find((c) => !c.resolved);
        resolve(active || null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async listConflicts(resolved?: boolean): Promise<ConflictRecord[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("conflicts", "readonly");
      const store = tx.objectStore("conflicts");
      const req = store.getAll();

      req.onsuccess = () => {
        let records: ConflictRecord[] = req.result || [];
        if (resolved !== undefined) {
          records = records.filter((c) => c.resolved === resolved);
        }
        resolve(records);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async resolveConflict(
    conflictId: string,
    resolvedEnvelope: EncryptedEnvelopeDto | null = null,
    resolvedAt: string
  ): Promise<boolean> {
    const conflict = await this.getConflict(conflictId);
    if (!conflict) {
      return false;
    }
    conflict.resolved = true;
    conflict.resolved_at = resolvedAt;
    if (resolvedEnvelope) {
      conflict.candidate_envelope = resolvedEnvelope;
    }
    await this.putConflict(conflict);
    return true;
  }

  public async deleteConflict(conflictId: string): Promise<boolean> {
    const existing = await this.getConflict(conflictId);
    if (!existing) {
      return false;
    }
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("conflicts", "readwrite");
      const store = tx.objectStore("conflicts");
      const req = store.delete(conflictId);

      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * Closes the database connection.
   */
  public async close(): Promise<void> {
    if (this.dbPromise) {
      const db = await this.dbPromise;
      db.close();
      this.dbPromise = null;
    }
  }

  /**
   * Deletes the entire IndexedDB database (used for tests or vault resets).
   */
  public async deleteDatabase(): Promise<void> {
    await this.close();
    return new Promise((resolve, reject) => {
      const req = this.idbFactory.deleteDatabase(this.dbName);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
      req.onblocked = () => resolve();
    });
  }
}
