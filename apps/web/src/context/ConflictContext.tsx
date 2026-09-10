/**
 * Conflict Context, Store, and Resolution Engine (ZK-068).
 *
 * Requirements:
 * - Compare local and remote note versions.
 * - Three-way merge candidate usage.
 * - Manual resolution (keep local, keep remote, edit merged).
 * - Preserve-both action (duplicate local note, keep remote).
 * - Zero-knowledge security (SEC-001, SEC-003, SEC-009):
 *   - Plaintext is only decrypted in memory when vault is unlocked.
 *   - All persisted objects and retry mutations are authenticated encrypted envelopes.
 *   - Vault locking scrubs decrypted conflict views.
 */

import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useVault } from "./VaultContext.js";
import { useNotes } from "./NotesContext.js";
import { useSync } from "./SyncContext.js";
import { VaultWorkerClient } from "../worker/client.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import { PlaintextNoteDto } from "../worker/protocol.js";
import {
  ConflictRecord,
  EncryptedEnvelopeDto,
  MutationType,
  MutationStatus,
  StoredEncryptedObject,
  PendingMutation,
} from "../storage/models.js";
import { threeWayMergeNotes } from "../utils/diff3.js";
import { generateUuid } from "../utils/uuid.js";

export interface ConflictDetails {
  record: ConflictRecord;
  baseNote: PlaintextNoteDto | null;
  localNote: PlaintextNoteDto;
  remoteNote: PlaintextNoteDto;
  candidateNote: PlaintextNoteDto;
  hasTitleConflict: boolean;
  hasBodyConflict: boolean;
}

export interface ConflictSnapshot {
  activeConflicts: ConflictRecord[];
  activeConflictCount: number;
  selectedConflictId: string | null;
  isModalOpen: boolean;
  isLoadingDetails: boolean;
  error: string | null;
}

export interface ConflictContextType extends ConflictSnapshot {
  openModal: (conflictId: string) => void;
  closeModal: () => void;
  refreshConflicts: () => Promise<void>;
  loadConflictDetails: (conflictId: string) => Promise<ConflictDetails>;
  resolveKeepLocal: (conflictId: string) => Promise<void>;
  resolveKeepRemote: (conflictId: string) => Promise<void>;
  resolveWithCandidate: (conflictId: string) => Promise<void>;
  resolveManualMerge: (
    conflictId: string,
    merged: { title: string; body: string; tags: string[] }
  ) => Promise<void>;
  resolvePreserveBoth: (
    conflictId: string,
    customDuplicateTitle?: string
  ) => Promise<{ newNoteId: string }>;
  clearError: () => void;
  store: ConflictStore;
}

/**
 * Headless Conflict Store managing active conflicts, modal state,
 * and cryptographic resolution execution.
 */
export class ConflictStore {
  private activeConflicts: ConflictRecord[] = [];
  private selectedConflictId: string | null = null;
  private isModalOpen = false;
  private isLoadingDetails = false;
  private error: string | null = null;
  private listeners = new Set<() => void>();

  constructor(
    public readonly client: VaultWorkerClient,
    public readonly storage: IndexedDbStorage,
    public readonly onConflictResolved?: () => Promise<void>
  ) {}

  public getSnapshot = (): ConflictSnapshot => {
    return {
      activeConflicts: this.activeConflicts,
      activeConflictCount: this.activeConflicts.length,
      selectedConflictId: this.selectedConflictId,
      isModalOpen: this.isModalOpen,
      isLoadingDetails: this.isLoadingDetails,
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

  public openModal(conflictId: string): void {
    this.selectedConflictId = conflictId;
    this.isModalOpen = true;
    this.error = null;
    this.notify();
  }

  public closeModal(): void {
    this.isModalOpen = false;
    this.selectedConflictId = null;
    this.notify();
  }

  public async refreshConflicts(): Promise<void> {
    try {
      const records = await this.storage.listConflicts(false);
      this.activeConflicts = records;
      this.notify();
    } catch {
      // Ignore polling errors
    }
  }

  /**
   * Decrypts the BASE (if available), LOCAL, and REMOTE envelopes for comparison
   * and computes or returns the 3-way merge candidate.
   */
  public async loadConflictDetails(conflictId: string): Promise<ConflictDetails> {
    this.isLoadingDetails = true;
    this.error = null;
    this.notify();

    try {
      const record = await this.storage.getConflict(conflictId);
      if (!record) {
        throw new Error(`Conflict record not found: ${conflictId}`);
      }

      // Decrypt Local Note
      const localNote = await this.client.decryptNote(
        JSON.stringify(record.local_envelope)
      );

      // Decrypt Remote Note
      const remoteNote = await this.client.decryptNote(
        JSON.stringify(record.remote_envelope)
      );

      // Decrypt Base Note (if present)
      let baseNote: PlaintextNoteDto | null = null;
      if (record.base_envelope) {
        try {
          baseNote = await this.client.decryptNote(
            JSON.stringify(record.base_envelope)
          );
        } catch {
          baseNote = null;
        }
      }

      // Candidate Note: If candidate_envelope exists, decrypt it; otherwise compute 3-way merge
      let candidateNote: PlaintextNoteDto;
      let hasTitleConflict = false;
      let hasBodyConflict = false;

      if (record.candidate_envelope) {
        try {
          candidateNote = await this.client.decryptNote(
            JSON.stringify(record.candidate_envelope)
          );
        } catch {
          const merge = threeWayMergeNotes(baseNote, localNote, remoteNote);
          candidateNote = merge.candidate;
          hasTitleConflict = merge.hasTitleConflict;
          hasBodyConflict = merge.hasBodyConflict;
        }
      } else {
        const merge = threeWayMergeNotes(baseNote, localNote, remoteNote);
        candidateNote = merge.candidate;
        hasTitleConflict = merge.hasTitleConflict;
        hasBodyConflict = merge.hasBodyConflict;
      }

      this.isLoadingDetails = false;
      this.notify();

      return {
        record,
        baseNote,
        localNote,
        remoteNote,
        candidateNote,
        hasTitleConflict,
        hasBodyConflict,
      };
    } catch (err: any) {
      this.isLoadingDetails = false;
      this.error = err instanceof Error ? err.message : String(err);
      this.notify();
      throw err;
    }
  }

  /**
   * Action 1: Keep Local.
   * Keeps local version and enqueues a retry mutation with expected_revision = remote_revision.
   */
  public async resolveKeepLocal(conflictId: string): Promise<void> {
    const conflict = await this.storage.getConflict(conflictId);
    if (!conflict) throw new Error(`Conflict record not found: ${conflictId}`);
    if (conflict.resolved) throw new Error(`Conflict ${conflictId} is already resolved.`);

    const now = new Date().toISOString();

    // 1. Remove stale pending mutations for this note
    const staleMutations = await this.storage.listMutationsForObject(conflict.object_id);
    for (const m of staleMutations) {
      await this.storage.removeMutation(m.mutation_id);
    }

    // 2. Update local stored object to reflect local edits at remote revision
    const isDel = !!conflict.local_is_deleted;
    const localObj: StoredEncryptedObject = {
      object_id: conflict.object_id,
      object_kind: conflict.object_kind,
      revision: conflict.remote_revision,
      server_seq: 0,
      is_deleted: isDel,
      envelope: conflict.local_envelope,
      updated_at: now,
    };
    await this.storage.putObject(localObj);

    // 3. Enqueue retry mutation so CAS push will succeed against remote_revision
    const retryMutation: PendingMutation = {
      mutation_id: generateUuid(),
      object_id: conflict.object_id,
      expected_revision: conflict.remote_revision,
      object_kind: conflict.object_kind,
      mutation_type: isDel ? MutationType.Delete : MutationType.Upsert,
      envelope: conflict.local_envelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    };
    await this.storage.enqueueMutation(retryMutation);

    // 4. Mark conflict record resolved
    await this.storage.resolveConflict(conflictId, conflict.local_envelope, now);

    await this.refreshConflicts();
    this.closeModal();

    if (this.onConflictResolved) {
      await this.onConflictResolved();
    }
  }

  /**
   * Action 2: Keep Remote.
   * Discards local edit and accepts remote version as canonical.
   */
  public async resolveKeepRemote(conflictId: string): Promise<void> {
    const conflict = await this.storage.getConflict(conflictId);
    if (!conflict) throw new Error(`Conflict record not found: ${conflictId}`);
    if (conflict.resolved) throw new Error(`Conflict ${conflictId} is already resolved.`);

    const now = new Date().toISOString();

    // 1. Remove stale pending mutations for this note
    const staleMutations = await this.storage.listMutationsForObject(conflict.object_id);
    for (const m of staleMutations) {
      await this.storage.removeMutation(m.mutation_id);
    }

    // 2. Update local stored object with remote envelope at remote revision
    const remoteObj: StoredEncryptedObject = {
      object_id: conflict.object_id,
      object_kind: conflict.object_kind,
      revision: conflict.remote_revision,
      server_seq: 0,
      is_deleted: !!conflict.remote_is_deleted,
      envelope: conflict.remote_envelope,
      updated_at: now,
    };
    await this.storage.putObject(remoteObj);

    // 3. Mark conflict record resolved (no retry mutation needed because remote is already server state)
    await this.storage.resolveConflict(conflictId, conflict.remote_envelope, now);

    await this.refreshConflicts();
    this.closeModal();

    if (this.onConflictResolved) {
      await this.onConflictResolved();
    }
  }

  /**
   * Action 3: Manual Merge / Candidate Merge.
   * Encrypts the merged note, updates local object, and enqueues a retry mutation at remote_revision.
   */
  public async resolveManualMerge(
    conflictId: string,
    merged: { title: string; body: string; tags: string[] }
  ): Promise<void> {
    const conflict = await this.storage.getConflict(conflictId);
    if (!conflict) throw new Error(`Conflict record not found: ${conflictId}`);
    if (conflict.resolved) throw new Error(`Conflict ${conflictId} is already resolved.`);

    const now = new Date().toISOString();

    // 1. Encrypt merged note via Web Worker
    const { envelopeJson } = await this.client.encryptNote(
      conflict.object_id,
      merged.title,
      merged.body,
      merged.tags
    );
    const mergedEnvelope = JSON.parse(envelopeJson) as EncryptedEnvelopeDto;

    // 2. Remove stale pending mutations
    const staleMutations = await this.storage.listMutationsForObject(conflict.object_id);
    for (const m of staleMutations) {
      await this.storage.removeMutation(m.mutation_id);
    }

    // 3. Update local stored object
    const mergedObj: StoredEncryptedObject = {
      object_id: conflict.object_id,
      object_kind: conflict.object_kind,
      revision: conflict.remote_revision,
      server_seq: 0,
      is_deleted: false,
      envelope: mergedEnvelope,
      updated_at: now,
    };
    await this.storage.putObject(mergedObj);

    // 4. Enqueue retry mutation at remote_revision
    const retryMutation: PendingMutation = {
      mutation_id: generateUuid(),
      object_id: conflict.object_id,
      expected_revision: conflict.remote_revision,
      object_kind: conflict.object_kind,
      mutation_type: MutationType.Upsert,
      envelope: mergedEnvelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    };
    await this.storage.enqueueMutation(retryMutation);

    // 5. Mark conflict resolved
    await this.storage.resolveConflict(conflictId, mergedEnvelope, now);

    await this.refreshConflicts();
    this.closeModal();

    if (this.onConflictResolved) {
      await this.onConflictResolved();
    }
  }

  /**
   * Helper: Resolve with the 3-way merge candidate directly.
   */
  public async resolveWithCandidate(conflictId: string): Promise<void> {
    const details = await this.loadConflictDetails(conflictId);
    await this.resolveManualMerge(conflictId, {
      title: details.candidateNote.title,
      body: details.candidateNote.body,
      tags: details.candidateNote.tags,
    });
  }

  /**
   * Action 4: Preserve Both.
   * Keeps the remote version for the original note ID, and creates a brand-new
   * note containing the local edits under a new UUID.
   */
  public async resolvePreserveBoth(
    conflictId: string,
    customDuplicateTitle?: string
  ): Promise<{ newNoteId: string }> {
    const conflict = await this.storage.getConflict(conflictId);
    if (!conflict) throw new Error(`Conflict record not found: ${conflictId}`);
    if (conflict.resolved) throw new Error(`Conflict ${conflictId} is already resolved.`);

    const now = new Date().toISOString();

    // 1. Accept remote version for the original object
    const staleMutations = await this.storage.listMutationsForObject(conflict.object_id);
    for (const m of staleMutations) {
      await this.storage.removeMutation(m.mutation_id);
    }

    const remoteObj: StoredEncryptedObject = {
      object_id: conflict.object_id,
      object_kind: conflict.object_kind,
      revision: conflict.remote_revision,
      server_seq: 0,
      is_deleted: !!conflict.remote_is_deleted,
      envelope: conflict.remote_envelope,
      updated_at: now,
    };
    await this.storage.putObject(remoteObj);

    // 2. Decrypt local note to duplicate it under new UUID
    const localNote = await this.client.decryptNote(
      JSON.stringify(conflict.local_envelope)
    );

    const newNoteId = generateUuid();
    const dupTitle =
      customDuplicateTitle !== undefined && customDuplicateTitle.trim().length > 0
        ? customDuplicateTitle.trim()
        : localNote.title
        ? `${localNote.title} (Local Copy)`
        : "Untitled (Local Copy)";

    // 3. Encrypt new duplicated note
    const { envelopeJson } = await this.client.encryptNote(
      newNoteId,
      dupTitle,
      localNote.body,
      localNote.tags
    );
    const dupEnvelope = JSON.parse(envelopeJson) as EncryptedEnvelopeDto;

    // 4. Save duplicated note to storage
    const dupObj: StoredEncryptedObject = {
      object_id: newNoteId,
      object_kind: conflict.object_kind,
      revision: 1,
      server_seq: 0,
      is_deleted: false,
      envelope: dupEnvelope,
      updated_at: now,
    };
    await this.storage.putObject(dupObj);

    // 5. Enqueue creation mutation for the new duplicated note
    const dupMutation: PendingMutation = {
      mutation_id: generateUuid(),
      object_id: newNoteId,
      expected_revision: 0,
      object_kind: conflict.object_kind,
      mutation_type: MutationType.Upsert,
      envelope: dupEnvelope,
      created_at: now,
      retry_count: 0,
      status: MutationStatus.Pending,
    };
    await this.storage.enqueueMutation(dupMutation);

    // 6. Mark original conflict record resolved
    await this.storage.resolveConflict(conflictId, conflict.remote_envelope, now);

    await this.refreshConflicts();
    this.closeModal();

    if (this.onConflictResolved) {
      await this.onConflictResolved();
    }

    return { newNoteId };
  }

  public dispose(): void {
    this.listeners.clear();
  }
}

const ConflictContext = createContext<ConflictContextType | null>(null);

export interface ConflictProviderProps {
  store?: ConflictStore;
  children: React.ReactNode;
}

export const ConflictProvider: React.FC<ConflictProviderProps> = ({
  store: propStore,
  children,
}) => {
  const { client, storage, vaultState } = useVault();
  const notes = useNotes();
  const sync = useSync();

  const handleResolved = useMemo(() => {
    return async () => {
      try {
        if (notes && typeof notes.reloadNotes === "function") {
          await notes.reloadNotes();
        }
        if (sync && typeof sync.refreshStatus === "function") {
          await sync.refreshStatus();
        }
      } catch {
        // Ignore background refresh errors
      }
    };
  }, [notes, sync]);

  const store = useMemo(
    () => propStore || new ConflictStore(client, storage, handleResolved),
    [propStore, client, storage, handleResolved]
  );

  useEffect(() => {
    return () => {
      store.dispose();
    };
  }, [store]);

  // Lock listener: close modal and scrub state on lock (SEC-009)
  useEffect(() => {
    if (!client) return undefined;
    const unsub = client.onLock(() => {
      store.closeModal();
    });
    return unsub;
  }, [client, store]);

  // Poll active conflicts whenever unlocked
  useEffect(() => {
    if (vaultState === "UNLOCKED") {
      store.refreshConflicts();
      const interval = setInterval(() => store.refreshConflicts(), 3000);
      return () => clearInterval(interval);
    }
    return undefined;
  }, [vaultState, store]);

  useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);

  const snapshot = store.getSnapshot();

  const value: ConflictContextType = useMemo(
    () => ({
      ...snapshot,
      openModal: (id: string) => store.openModal(id),
      closeModal: () => store.closeModal(),
      refreshConflicts: () => store.refreshConflicts(),
      loadConflictDetails: (id: string) => store.loadConflictDetails(id),
      resolveKeepLocal: (id: string) => store.resolveKeepLocal(id),
      resolveKeepRemote: (id: string) => store.resolveKeepRemote(id),
      resolveWithCandidate: (id: string) => store.resolveWithCandidate(id),
      resolveManualMerge: (id: string, m) => store.resolveManualMerge(id, m),
      resolvePreserveBoth: (id: string, t) => store.resolvePreserveBoth(id, t),
      clearError: () => store.clearError(),
      store,
    }),
    [snapshot, store]
  );

  return (
    <ConflictContext.Provider value={value}>{children}</ConflictContext.Provider>
  );
};

export function useConflict(): ConflictContextType {
  const ctx = useContext(ConflictContext);
  if (!ctx) {
    return {
      activeConflicts: [],
      activeConflictCount: 0,
      selectedConflictId: null,
      isModalOpen: false,
      isLoadingDetails: false,
      error: null,
      openModal: () => {},
      closeModal: () => {},
      refreshConflicts: async () => {},
      loadConflictDetails: async () => {
        throw new Error("ConflictContext not found");
      },
      resolveKeepLocal: async () => {},
      resolveKeepRemote: async () => {},
      resolveWithCandidate: async () => {},
      resolveManualMerge: async () => {},
      resolvePreserveBoth: async () => ({ newNoteId: "" }),
      clearError: () => {},
      store: null as any,
    };
  }
  return ctx;
}
