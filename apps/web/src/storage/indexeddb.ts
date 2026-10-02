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

import { normalizeServerOrigin } from "../auth/session.js";

export const DB_SCHEMA_VERSION = 2;
export const DEFAULT_DB_NAME = "zk_notes_db";

function stringToHex(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Returns a deterministic, collision-safe database name scoped to (serverOrigin, accountId)
 * using bijective byte-level hex encoding to prevent origin collisions (ZK-106).
 */
export function getScopedDatabaseName(
  baseName: string = DEFAULT_DB_NAME,
  serverOrigin?: string | null,
  accountId?: string | null
): string {
  if (!serverOrigin || !accountId) return baseName;
  try {
    const originPart = stringToHex(normalizeServerOrigin(serverOrigin));
    const accountPart = stringToHex(accountId.trim());
    return `${baseName}_${originPart}_${accountPart}`;
  } catch {
    const originPart = stringToHex(serverOrigin.trim());
    const accountPart = stringToHex(accountId.trim());
    return `${baseName}_${originPart}_${accountPart}`;
  }
}

export class IndexedDbStorage {
  private dbName: string;
  private idbFactory: IDBFactory;
  private dbPromise: Promise<IDBDatabase> | null = null;
  private migrationPromise: Promise<boolean> | null = null;

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
   * Returns the database name for this storage instance.
   */
  public getDatabaseName(): string {
    return this.dbName;
  }

  /**
   * Opens or initializes the IndexedDB database.
   */
  public async getDb(): Promise<IDBDatabase> {
    return this.getRawDb();
  }

  /**
   * Opens or returns the raw IDBDatabase instance without running migration hooks.
   */
  public async getRawDb(): Promise<IDBDatabase> {
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

  /**
   * Durably migrates pre-auth notes from DEFAULT_DB_NAME to this account-scoped database.
   * Gated explicitly on vault linking, fails closed on errors, and allows retrying.
   */
  public async migrateFromDefault(): Promise<boolean> {
    if (this.dbName === DEFAULT_DB_NAME) {
      return false;
    }
    if (!this.migrationPromise) {
      this.migrationPromise = (async () => {
        const defaultStorage = new IndexedDbStorage(DEFAULT_DB_NAME, this.idbFactory);
        return await this.migrateFrom(defaultStorage);
      })().catch((err) => {
        this.migrationPromise = null;
        throw err;
      });
    }
    return this.migrationPromise;
  }

  /**
   * Durably copies all encrypted objects, mutations, base versions, conflicts, and blobs
   * from sourceStorage to this storage, then clears the source storage.
   */
  public async migrateFrom(sourceStorage: IndexedDbStorage): Promise<boolean> {
    if (sourceStorage.getDatabaseName() === this.dbName) {
      return false;
    }

    const sourceDb = await sourceStorage.getRawDb();
    const targetDb = await this.getRawDb();

    // Check if source has any data to migrate
    const sourceHasData = await new Promise<boolean>((resolve, reject) => {
      const tx = sourceDb.transaction(
        ["objects", "mutations", "conflicts"],
        "readonly"
      );
      let count = 0;
      tx.objectStore("objects").count().onsuccess = (e: any) => {
        count += e.target.result || 0;
      };
      tx.objectStore("mutations").count().onsuccess = (e: any) => {
        count += e.target.result || 0;
      };
      tx.objectStore("conflicts").count().onsuccess = (e: any) => {
        count += e.target.result || 0;
      };
      tx.oncomplete = () => resolve(count > 0);
      tx.onerror = () => reject(tx.error);
    });

    if (!sourceHasData) {
      return false;
    }

    // Read all records from source
    const readStore = async (storeName: string): Promise<any[]> => {
      return new Promise((resolve, reject) => {
        const tx = sourceDb.transaction(storeName, "readonly");
        const store = tx.objectStore(storeName);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });
    };

    const objects = await readStore("objects");
    const mutations = await readStore("mutations");
    const baseVersions = await readStore("base_versions");
    const conflicts = await readStore("conflicts");
    const blobs = sourceDb.objectStoreNames.contains("blobs")
      ? await readStore("blobs")
      : [];

    // Write all records to target
    await new Promise<void>((resolve, reject) => {
      const storeNames = ["objects", "mutations", "base_versions", "conflicts"];
      if (targetDb.objectStoreNames.contains("blobs")) {
        storeNames.push("blobs");
      }
      const tx = targetDb.transaction(storeNames, "readwrite");

      const objStore = tx.objectStore("objects");
      for (const obj of objects) {
        objStore.put(obj);
      }
      const mutStore = tx.objectStore("mutations");
      for (const m of mutations) {
        mutStore.put(m);
      }
      const bvStore = tx.objectStore("base_versions");
      for (const bv of baseVersions) {
        bvStore.put(bv);
      }
      const confStore = tx.objectStore("conflicts");
      for (const c of conflicts) {
        confStore.put(c);
      }
      if (targetDb.objectStoreNames.contains("blobs")) {
        const blobStore = tx.objectStore("blobs");
        for (const b of blobs) {
          blobStore.put(b);
        }
      }

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    // Clear migrated data from source storage
    await sourceStorage.clearAllData();
    return true;
  }

  /**
   * Clears objects, mutations, base_versions, conflicts, and blobs in this storage.
   */
  public async clearAllData(): Promise<void> {
    const db = await this.getRawDb();
    await new Promise<void>((resolve, reject) => {
      const storeNames = ["objects", "mutations", "base_versions", "conflicts"];
      if (db.objectStoreNames.contains("blobs")) {
        storeNames.push("blobs");
      }
      const tx = db.transaction(storeNames, "readwrite");
      for (const name of storeNames) {
        tx.objectStore(name).clear();
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
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

    // 6. Ciphertext Blobs Store (ZK-084)
    if (!db.objectStoreNames.contains("blobs")) {
      db.createObjectStore("blobs", { keyPath: "blob_id" });
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
        const pending = mutations.filter((m) => m.status === MutationStatus.Pending);
        // FIFO order: sort by created_at ascending, breaking ties with expected_revision
        pending.sort((a, b) => {
          const cmp = a.created_at.localeCompare(b.created_at);
          if (cmp !== 0) return cmp;
          return a.expected_revision - b.expected_revision;
        });
        resolve(pending);
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
    retryCount?: number
  ): Promise<void> {
    const mutation = await this.getMutation(mutationId);
    if (!mutation) {
      throw new Error(`Mutation ${mutationId} not found`);
    }
    mutation.status = status;
    if (retryCount !== undefined) {
      mutation.retry_count = retryCount;
    }
    await this.enqueueMutation(mutation);
  }

  public async pendingMutationCount(): Promise<number> {
    const mutations = await this.listPendingMutations();
    return mutations.filter(
      (m) => m.status === MutationStatus.Pending || m.status === MutationStatus.InFlight
    ).length;
  }

  /**
   * Resets all mutations currently stuck in InFlight status back to Pending (ZK-041/ZK-106).
   * Ensures interrupted push operations from crashes/restarts can be safely retried.
   */
  public async resetInFlightMutations(): Promise<number> {
    const db = await this.getDb();
    const allMutations: PendingMutation[] = await new Promise((resolve, reject) => {
      const tx = db.transaction("mutations", "readonly");
      const store = tx.objectStore("mutations");
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });

    let resetCount = 0;
    for (const m of allMutations) {
      if (m.status === MutationStatus.InFlight) {
        await this.updateMutationStatus(m.mutation_id, MutationStatus.Pending, m.retry_count);
        resetCount++;
      }
    }
    return resetCount;
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

  public async getSyncState(identity = "singleton"): Promise<SyncState> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sync_state", "readonly");
      const store = tx.objectStore("sync_state");
      const req = store.get(identity);

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

  public async setSyncCursor(cursor: number, identity = "singleton"): Promise<void> {
    const current = await this.getSyncState(identity);
    current.sync_cursor = cursor;
    await this.setSyncState(current, identity);
  }

  public async setSyncState(state: SyncState, identity = "singleton"): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("sync_state", "readwrite");
      const store = tx.objectStore("sync_state");
      const req = store.put({
        key: identity,
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

  // ==========================================================================
  // Ciphertext Blob Storage (ZK-084)
  // SEC-001/SEC-009: Persists only opaque blob IDs and ciphertext bytes
  // ==========================================================================

  public async putBlob(blobId: string, data: Uint8Array): Promise<void> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("blobs", "readwrite");
      const store = tx.objectStore("blobs");
      const req = store.put({
        blob_id: blobId,
        data,
        size: data.length,
        created_at: new Date().toISOString(),
      });
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async getBlob(blobId: string): Promise<Uint8Array | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("blobs", "readonly");
      const store = tx.objectStore("blobs");
      const req = store.get(blobId);
      req.onsuccess = () => {
        if (!req.result) {
          resolve(null);
        } else {
          resolve(req.result.data as Uint8Array);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async deleteBlob(blobId: string): Promise<boolean> {
    const existing = await this.getBlob(blobId);
    if (!existing) {
      return false;
    }
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("blobs", "readwrite");
      const store = tx.objectStore("blobs");
      const req = store.delete(blobId);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  public async listBlobIds(): Promise<string[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("blobs", "readonly");
      const store = tx.objectStore("blobs");
      const req = store.getAllKeys();
      req.onsuccess = () => {
        resolve((req.result as string[]) || []);
      };
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
