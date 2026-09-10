/**
 * Notes Context, Store, and Autosave State Machine (ZK-065).
 *
 * Requirements:
 * - Create / Edit / Delete notes.
 * - Autosave to encrypted local state (IndexedDB objects + mutations queue).
 * - Offline operation (100% local, zero network requests).
 * - SEC-001 / SEC-009: In-memory plaintext is completely wiped when vault locks.
 */

import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useVault } from "./VaultContext.js";
import { VaultWorkerClient } from "../worker/client.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import { PlaintextNoteDto, DecryptBatchItem } from "../worker/protocol.js";
import {
  EncryptedEnvelopeDto,
  MutationType,
  MutationStatus,
  StoredEncryptedObject,
} from "../storage/models.js";

export type SaveStatus = "saved" | "saving" | "unsaved" | "error";

export interface NotesSnapshot {
  notes: PlaintextNoteDto[];
  selectedNoteId: string | null;
  isLoading: boolean;
  saveStatus: SaveStatus;
  lastSavedAt: Date | null;
  error: string | null;
}

export interface NotesContextType extends NotesSnapshot {
  selectedNote: PlaintextNoteDto | null;
  selectNote: (id: string | null) => void;
  createNote: (initial?: { title?: string; body?: string; tags?: string[] }) => Promise<PlaintextNoteDto>;
  updateNote: (id: string, updates: { title?: string; body?: string; tags?: string[] }) => void;
  saveNoteNow: (id: string) => Promise<void>;
  deleteNote: (id: string) => Promise<void>;
  reloadNotes: () => Promise<void>;
  clearError: () => void;
  store: NotesStore;
}

const DEBOUNCE_DELAY_MS = 600;

/**
 * Headless Notes Store managing the in-memory decrypted note cache,
 * debounced autosaving, mutation queueing, and IndexedDB persistence.
 */
export class NotesStore {
  private notes: PlaintextNoteDto[] = [];
  private selectedNoteId: string | null = null;
  private isLoading = false;
  private saveStatus: SaveStatus = "saved";
  private lastSavedAt: Date | null = null;
  private error: string | null = null;

  private listeners = new Set<() => void>();
  private saveTimers = new Map<string, NodeJS.Timeout | number>();
  private isUnlocked = false;

  constructor(
    public readonly client: VaultWorkerClient,
    public readonly storage: IndexedDbStorage
  ) {}

  public getSnapshot = (): NotesSnapshot => {
    return {
      notes: this.notes,
      selectedNoteId: this.selectedNoteId,
      isLoading: this.isLoading,
      saveStatus: this.saveStatus,
      lastSavedAt: this.lastSavedAt,
      error: this.error,
    };
  };

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private notify(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }

  public clearError(): void {
    this.error = null;
    this.notify();
  }

  /**
   * Called when vault unlocks: loads encrypted notes from storage and decrypts them.
   */
  public async handleVaultUnlocked(): Promise<void> {
    this.isUnlocked = true;
    await this.reloadNotes();
  }

  /**
   * SEC-009 / SEC-001: Called when vault locks: immediately purges all plaintext notes from memory.
   */
  public handleVaultLocked(): void {
    this.isUnlocked = false;
    // Clear any pending autosave timers
    for (const timer of this.saveTimers.values()) {
      clearTimeout(timer);
    }
    this.saveTimers.clear();

    // Wipe decrypted data from memory
    this.notes = [];
    this.selectedNoteId = null;
    this.saveStatus = "saved";
    this.error = null;
    this.notify();
  }

  /**
   * Loads all encrypted note objects from IndexedDB, batch decrypts via Web Worker,
   * and populates the in-memory store and worker search index.
   */
  public async reloadNotes(): Promise<void> {
    if (!this.isUnlocked) return;

    this.isLoading = true;
    this.error = null;
    this.notify();

    try {
      const storedObjects = await this.storage.listObjects({ kind: 1, include_deleted: false });

      if (storedObjects.length === 0) {
        this.notes = [];
        this.selectedNoteId = null;
        this.isLoading = false;
        this.notify();
        return;
      }

      // Prepare envelopes for worker batch decryption
      const batchItems: DecryptBatchItem[] = storedObjects.map((obj) => ({
        id: obj.object_id,
        envelopeJson: JSON.stringify(obj.envelope),
      }));

      const batchResult = await this.client.decryptNotesBatch(batchItems);

      // Sort notes by updatedAt desc
      const decryptedNotes = batchResult.notes.sort((a, b) => {
        return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
      });

      this.notes = decryptedNotes;

      // Select first note if nothing is selected or previously selected note no longer exists
      if (!this.selectedNoteId && decryptedNotes.length > 0) {
        this.selectedNoteId = decryptedNotes[0]?.id ?? null;
      } else if (this.selectedNoteId && !decryptedNotes.some((n) => n.id === this.selectedNoteId)) {
        this.selectedNoteId = decryptedNotes[0]?.id ?? null;
      }

      // Populate worker search index in parallel
      for (const note of decryptedNotes) {
        this.client
          .indexNote(note.id, note.title, note.body, note.tags, note.updatedAt)
          .catch(() => {});
      }
    } catch (err) {
      this.error = "Failed to decrypt local notes.";
    } finally {
      this.isLoading = false;
      this.notify();
    }
  }

  public selectNote(id: string | null): void {
    if (this.selectedNoteId !== id) {
      // Flush any pending save for current note before switching
      if (this.selectedNoteId && this.saveTimers.has(this.selectedNoteId)) {
        this.saveNoteNow(this.selectedNoteId).catch(() => {});
      }
      this.selectedNoteId = id;
      this.notify();
    }
  }

  /**
   * Creates a new note, writes encrypted state, records mutation, and updates index.
   */
  public async createNote(initial?: {
    title?: string;
    body?: string;
    tags?: string[];
  }): Promise<PlaintextNoteDto> {
    if (!this.isUnlocked) {
      throw new Error("Cannot create note while vault is locked.");
    }

    const id = (typeof crypto !== "undefined" && crypto.randomUUID)
      ? crypto.randomUUID()
      : `note-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    const now = new Date().toISOString();
    const newNote: PlaintextNoteDto = {
      id,
      title: initial?.title || "",
      body: initial?.body || "",
      tags: initial?.tags || [],
      createdAt: now,
      updatedAt: now,
    };

    // Prepend to memory
    this.notes = [newNote, ...this.notes];
    this.selectedNoteId = id;
    this.saveStatus = "saving";
    this.notify();

    try {
      await this.persistNoteToStorage(newNote);
      this.saveStatus = "saved";
      this.lastSavedAt = new Date();
      this.notify();
      return newNote;
    } catch (err) {
      this.saveStatus = "error";
      this.error = "Failed to save new note.";
      this.notify();
      throw err;
    }
  }

  /**
   * Updates note fields in memory immediately, and schedules a debounced autosave.
   */
  public updateNote(
    id: string,
    updates: { title?: string; body?: string; tags?: string[] }
  ): void {
    const idx = this.notes.findIndex((n) => n.id === id);
    if (idx < 0) return;

    const existing = this.notes[idx]!;
    const updatedNote: PlaintextNoteDto = {
      ...existing,
      title: updates.title !== undefined ? updates.title : existing.title,
      body: updates.body !== undefined ? updates.body : existing.body,
      tags: updates.tags !== undefined ? updates.tags : existing.tags,
      updatedAt: new Date().toISOString(),
    };

    // Replace in memory
    const nextNotes = [...this.notes];
    nextNotes[idx] = updatedNote;
    this.notes = nextNotes;
    this.saveStatus = "unsaved";
    this.notify();

    // Reset debounce timer
    const existingTimer = this.saveTimers.get(id);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timer = setTimeout(() => {
      this.saveTimers.delete(id);
      this.saveNoteNow(id).catch(() => {});
    }, DEBOUNCE_DELAY_MS);

    this.saveTimers.set(id, timer);
  }

  /**
   * Immediately flushes any pending save to encrypted local storage.
   */
  public async saveNoteNow(id: string): Promise<void> {
    const timer = this.saveTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.saveTimers.delete(id);
    }

    const note = this.notes.find((n) => n.id === id);
    if (!note) return;

    this.saveStatus = "saving";
    this.notify();

    try {
      await this.persistNoteToStorage(note);
      this.saveStatus = "saved";
      this.lastSavedAt = new Date();
      this.notify();
    } catch (err) {
      this.saveStatus = "error";
      this.error = "Autosave failed.";
      this.notify();
      throw err;
    }
  }

  /**
   * Deletes a note by recording a revisioned tombstone in IndexedDB,
   * queuing a deletion mutation, and removing from search index & memory.
   */
  public async deleteNote(id: string): Promise<void> {
    const timer = this.saveTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.saveTimers.delete(id);
    }

    const existingObject = await this.storage.getObject(id);
    const expectedRevision = existingObject ? existingObject.revision : 0;
    const nextRevision = expectedRevision + 1;
    const now = new Date().toISOString();

    // If existing envelope exists, use it for tombstone; otherwise create a placeholder
    let tombstoneEnvelope: EncryptedEnvelopeDto;
    if (existingObject) {
      tombstoneEnvelope = existingObject.envelope;
    } else {
      const encRes = await this.client.encryptNote(id, "", "", []);
      tombstoneEnvelope = JSON.parse(encRes.envelopeJson);
    }

    // 1. Record tombstone in local object store
    await this.storage.markDeleted(id, nextRevision, tombstoneEnvelope, now);

    // 2. Queue pending mutation for sync
    const mutationId = (typeof crypto !== "undefined" && crypto.randomUUID)
      ? crypto.randomUUID()
      : `mut-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    await this.storage.enqueueMutation({
      mutation_id: mutationId,
      object_id: id,
      expected_revision: expectedRevision,
      object_kind: 1,
      mutation_type: MutationType.Delete,
      envelope: tombstoneEnvelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // 3. Remove from worker search index
    await this.client.removeFromIndex(id).catch(() => {});

    // 4. Update in-memory notes list
    const remaining = this.notes.filter((n) => n.id !== id);
    this.notes = remaining;

    if (this.selectedNoteId === id) {
      this.selectedNoteId = remaining.length > 0 ? remaining[0]?.id ?? null : null;
    }

    this.saveStatus = "saved";
    this.notify();
  }

  /**
   * Internal helper: encrypts note via Web Worker, writes StoredEncryptedObject,
   * queues PendingMutation, and updates search index.
   */
  private async persistNoteToStorage(note: PlaintextNoteDto): Promise<void> {
    // 1. Encrypt note through Web Worker (never encrypt in UI thread)
    const encRes = await this.client.encryptNote(
      note.id,
      note.title,
      note.body,
      note.tags
    );
    const envelope: EncryptedEnvelopeDto = JSON.parse(encRes.envelopeJson);

    // 2. Check current stored revision to compute CAS expected revision
    const existing = await this.storage.getObject(note.id);
    const expectedRevision = existing ? existing.revision : 0;
    const nextRevision = expectedRevision + 1;

    const storedObject: StoredEncryptedObject = {
      object_id: note.id,
      object_kind: 1, // OBJECT_KIND_NOTE
      revision: nextRevision,
      server_seq: existing ? existing.server_seq : 0,
      is_deleted: false,
      envelope,
      updated_at: note.updatedAt,
    };

    // 3. Write encrypted envelope to local objects store
    await this.storage.putObject(storedObject);

    // 4. Queue pending mutation for offline-first sync
    const mutationId = (typeof crypto !== "undefined" && crypto.randomUUID)
      ? crypto.randomUUID()
      : `mut-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    await this.storage.enqueueMutation({
      mutation_id: mutationId,
      object_id: note.id,
      expected_revision: expectedRevision,
      object_kind: 1,
      mutation_type: MutationType.Upsert,
      envelope,
      created_at: new Date().toISOString(),
      retry_count: 0,
      status: MutationStatus.Pending,
    });

    // 5. Update worker search index
    await this.client.indexNote(
      note.id,
      note.title,
      note.body,
      note.tags,
      note.updatedAt
    );
  }

  public dispose(): void {
    for (const timer of this.saveTimers.values()) {
      clearTimeout(timer);
    }
    this.saveTimers.clear();
    this.listeners.clear();
  }
}

const NotesContext = createContext<NotesContextType | null>(null);

export interface NotesProviderProps {
  children: React.ReactNode;
}

export const NotesProvider: React.FC<NotesProviderProps> = ({ children }) => {
  const { client, storage, vaultState } = useVault();

  const store = useMemo(() => new NotesStore(client, storage), [client, storage]);

  useEffect(() => {
    return () => {
      store.dispose();
    };
  }, [store]);

  // Sync vault state changes with notes store
  useEffect(() => {
    if (vaultState === "UNLOCKED") {
      store.handleVaultUnlocked();
    } else {
      store.handleVaultLocked();
    }
  }, [vaultState, store]);

  useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);

  const snapshot = store.getSnapshot();

  const selectedNote = useMemo(() => {
    if (!snapshot.selectedNoteId) return null;
    return snapshot.notes.find((n) => n.id === snapshot.selectedNoteId) || null;
  }, [snapshot.notes, snapshot.selectedNoteId]);

  const value: NotesContextType = useMemo(
    () => ({
      ...snapshot,
      selectedNote,
      selectNote: (id: string | null) => store.selectNote(id),
      createNote: (initial) => store.createNote(initial),
      updateNote: (id, updates) => store.updateNote(id, updates),
      saveNoteNow: (id) => store.saveNoteNow(id),
      deleteNote: (id) => store.deleteNote(id),
      reloadNotes: () => store.reloadNotes(),
      clearError: () => store.clearError(),
      store,
    }),
    [snapshot, selectedNote, store]
  );

  return <NotesContext.Provider value={value}>{children}</NotesContext.Provider>;
};

export function useNotes(): NotesContextType {
  const ctx = useContext(NotesContext);
  if (!ctx) {
    throw new Error("useNotes must be used within a NotesProvider");
  }
  return ctx;
}
