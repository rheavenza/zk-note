/**
 * Sync Context, Store, and Sync State Machine (ZK-067).
 *
 * Requirements:
 * - Display states: 'offline' | 'syncing' | 'synced' | 'pending changes' | 'conflict' | 'error'.
 * - Must NOT leak note content or titles in sync status (SEC-001, SEC-003).
 * - Tracks pending mutations, active conflicts, and network state.
 */

import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
} from "react";
import { useVault } from "./VaultContext.js";
import { useAuth } from "./AuthContext.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import {
  BrowserSyncAdapter,
  type SyncServerAdapter,
} from "../sync/adapter.js";

export type SyncStatus =
  | "local only"
  | "offline"
  | "syncing"
  | "synced"
  | "pending changes"
  | "conflict"
  | "error";

export interface SyncStateSnapshot {
  status: SyncStatus;
  isOnline: boolean;
  isSyncing: boolean;
  pendingCount: number;
  conflictCount: number;
  lastSyncAt: Date | null;
  error: string | null;
}

export interface SyncContextType extends SyncStateSnapshot {
  syncNow: () => Promise<void>;
  setOfflineMode: (offline: boolean) => void;
  clearError: () => void;
  refreshStatus: () => Promise<void>;
  store: SyncStore;
}

/**
 * Sanitizes sync error messages to ensure zero sensitive note details or tokens leak (SEC-001, SEC-003).
 */
export function sanitizeSyncErrorMessage(raw: string): string {
  const lower = raw.toLowerCase();
  if (lower.includes("network") || lower.includes("fetch") || lower.includes("offline")) {
    return "Network connection failed. Changes queued locally.";
  }
  if (lower.includes("wrong_account") || lower.includes("linked to account") || lower.includes("different account")) {
    return "This vault is linked to a different account. Sign in to the linked account to synchronize.";
  }
  if (lower.includes("origin_mismatch") || lower.includes("linked to server") || lower.includes("different server")) {
    return "This vault is linked to a different server. Switch to the linked server to synchronize.";
  }
  if (lower.includes("not_linked") || lower.includes("not linked")) {
    return "Vault must be linked to an account to synchronize.";
  }
  if (lower.includes("auth") || lower.includes("unauthorized") || lower.includes("401") || lower.includes("403")) {
    return "Authentication required to synchronize.";
  }
  if (lower.includes("conflict") || lower.includes("409")) {
    return "Conflicting remote changes detected.";
  }
  if (lower.includes("rate limit") || lower.includes("429")) {
    return "Sync rate limit reached. Retrying shortly.";
  }
  if (lower.includes("server") || lower.includes("500") || lower.includes("503")) {
    return "Server unavailable. Retrying later.";
  }
  return "Synchronization failed. Safe to work offline.";
}

/**
 * Headless Sync Store managing sync state, pending mutation counts,
 * active conflicts, and network state outside React.
 */
export class SyncStore {
  private isManualOffline = false;
  private isNetworkOnline = true;
  private isSyncing = false;
  private pendingCount = 0;
  private conflictCount = 0;
  private lastSyncAt: Date | null = null;
  private error: string | null = null;
  private listeners = new Set<() => void>();
  private snapshot: SyncStateSnapshot;

  constructor(
    public readonly storage: IndexedDbStorage,
    public readonly serverAdapter?: SyncServerAdapter
  ) {
    if (typeof navigator !== "undefined" && typeof navigator.onLine === "boolean") {
      this.isNetworkOnline = navigator.onLine;
    }

    this.snapshot = {
      status: this.getStatus(),
      isOnline: this.getIsOnline(),
      isSyncing: this.isSyncing,
      pendingCount: this.pendingCount,
      conflictCount: this.conflictCount,
      lastSyncAt: this.lastSyncAt,
      error: this.error,
    };
  }

  private updateSnapshot(): void {
    this.snapshot = {
      status: this.getStatus(),
      isOnline: this.getIsOnline(),
      isSyncing: this.isSyncing,
      pendingCount: this.pendingCount,
      conflictCount: this.conflictCount,
      lastSyncAt: this.lastSyncAt,
      error: this.error,
    };
  }

  public getState(): SyncStateSnapshot {
    return this.snapshot;
  }

  public getSnapshot = (): SyncStateSnapshot => {
    return this.snapshot;
  };

  public subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  private notify(): void {
    this.updateSnapshot();
    for (const listener of this.listeners) {
      listener();
    }
  }

  public getIsOnline(): boolean {
    return this.isNetworkOnline && !this.isManualOffline;
  }

  public getStatus(): SyncStatus {
    if (this.conflictCount > 0) return "conflict";
    if (this.error !== null) return "error";
    if (!this.getIsOnline()) return "offline";
    if (this.isSyncing) return "syncing";
    if (this.pendingCount > 0) return "pending changes";
    if (!this.serverAdapter?.pushMutations || !this.serverAdapter?.pullChanges) return "local only";
    return "synced";
  }

  public getPendingCount(): number {
    return this.pendingCount;
  }

  public getConflictCount(): number {
    return this.conflictCount;
  }

  public getLastSyncAt(): Date | null {
    return this.lastSyncAt;
  }

  public getError(): string | null {
    return this.error;
  }

  public clearError(): void {
    this.error = null;
    this.notify();
  }

  public setServerAdapter(serverAdapter?: SyncServerAdapter): void {
    (this as any).serverAdapter = serverAdapter;
    this.notify();
  }

  public setOfflineMode(offline: boolean): void {
    this.isManualOffline = offline;
    this.notify();
  }

  public setNetworkOnline(online: boolean): void {
    this.isNetworkOnline = online;
    this.notify();
  }

  public async refreshStatus(): Promise<void> {
    try {
      // 1. Check pending mutations count
      const mutations = await this.storage.listPendingMutations();
      this.pendingCount = mutations.length;

      // 2. Check active unresolved conflicts count
      const conflicts = await this.storage.listConflicts(false);
      this.conflictCount = conflicts.length;

      // 3. Check last sync time from sync state store
      const identity = (this.serverAdapter as any)?.identity;
      const syncState = await this.storage.getSyncState(identity);
      if (syncState && syncState.last_sync_at) {
        this.lastSyncAt = new Date(syncState.last_sync_at);
      } else {
        this.lastSyncAt = null;
      }
      this.notify();
    } catch {
      // Ignore storage polling errors
    }
  }

  public async syncNow(): Promise<void> {
    if (!this.serverAdapter?.pushMutations && !this.serverAdapter?.sync) {
      this.error = "Server synchronization is not configured. Notes remain local.";
      this.notify();
      return;
    }
    if (!this.getIsOnline()) {
      this.error = "Cannot sync while offline.";
      this.notify();
      return;
    }

    if (this.isSyncing) return;

    this.error = null;
    this.isSyncing = true;
    this.notify();

    try {
      if (this.serverAdapter.sync) {
        await this.serverAdapter.sync(this.storage);
      } else {
        if (this.serverAdapter.pushMutations) {
          await this.serverAdapter.pushMutations(this.storage);
        }
        if (this.serverAdapter.pullChanges) {
          await this.serverAdapter.pullChanges(this.storage);
        }

        const now = new Date();
        const identity = (this.serverAdapter as any)?.identity;
        const existingState = await this.storage.getSyncState(identity);
        await this.storage.setSyncState(
          {
            sync_cursor: existingState ? existingState.sync_cursor : 0,
            last_sync_at: now.toISOString(),
            device_id: existingState ? existingState.device_id : null,
          },
          identity
        );
      }

      await this.refreshStatus();
    } catch (err: any) {
      const rawMessage = err instanceof Error ? err.message : String(err);
      this.error = sanitizeSyncErrorMessage(rawMessage);
    } finally {
      this.isSyncing = false;
      this.notify();
    }
  }

  public dispose(): void {
    this.listeners.clear();
  }
}

const SyncContext = createContext<SyncContextType | null>(null);

export interface SyncProviderProps {
  store?: SyncStore;
  serverAdapter?: SyncServerAdapter;
  children: React.ReactNode;
}

export const SyncProvider: React.FC<SyncProviderProps> = ({
  store: propStore,
  serverAdapter: propServerAdapter,
  children,
}) => {
  const { storage, vaultState, vaultLink } = useVault();
  const { session, serverOrigin, isAuthenticated } = useAuth();

  const activeAdapter = useMemo(() => {
    if (propServerAdapter) return propServerAdapter;
    if (
      isAuthenticated &&
      session?.token &&
      session.accountId &&
      vaultLink &&
      vaultLink.accountId === session.accountId &&
      vaultLink.serverOrigin === serverOrigin
    ) {
      return new BrowserSyncAdapter({
        serverOrigin,
        token: session.token,
        accountId: session.accountId,
      });
    }
    return undefined;
  }, [
    propServerAdapter,
    isAuthenticated,
    session?.token,
    session?.accountId,
    vaultLink,
    serverOrigin,
  ]);

  const store = useMemo(
    () => propStore || new SyncStore(storage, activeAdapter),
    [propStore, storage]
  );

  useEffect(() => {
    if (!propStore) {
      store.setServerAdapter(activeAdapter);
      store.refreshStatus();
    }
  }, [store, activeAdapter, propStore]);

  useEffect(() => {
    return () => {
      store.dispose();
    };
  }, [store]);

  // Hook into browser online/offline events
  useEffect(() => {
    const handleOnline = () => store.setNetworkOnline(true);
    const handleOffline = () => store.setNetworkOnline(false);

    if (typeof window !== "undefined") {
      window.addEventListener("online", handleOnline);
      window.addEventListener("offline", handleOffline);
      return () => {
        window.removeEventListener("online", handleOnline);
        window.removeEventListener("offline", handleOffline);
      };
    }
    return undefined;
  }, [store]);

  // Periodic status refresh
  useEffect(() => {
    store.refreshStatus();
    const interval = setInterval(() => store.refreshStatus(), 3000);
    return () => clearInterval(interval);
  }, [store, vaultState]);

  const snapshot = useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);

  const value: SyncContextType = useMemo(
    () => ({
      get status() {
        return store.getStatus();
      },
      get isOnline() {
        return store.getIsOnline();
      },
      get isSyncing() {
        return store.getState().isSyncing;
      },
      get pendingCount() {
        return store.getPendingCount();
      },
      get conflictCount() {
        return store.getConflictCount();
      },
      get lastSyncAt() {
        return store.getLastSyncAt();
      },
      get error() {
        return store.getError();
      },
      syncNow: () => store.syncNow(),
      setOfflineMode: (off: boolean) => store.setOfflineMode(off),
      clearError: () => store.clearError(),
      refreshStatus: () => store.refreshStatus(),
      store,
    }),
    [store, snapshot]
  );

  return <SyncContext.Provider value={value}>{children}</SyncContext.Provider>;
};

export function useSync(): SyncContextType {
  const ctx = useContext(SyncContext);
  if (!ctx) {
    return {
      status: "synced",
      isOnline: true,
      isSyncing: false,
      pendingCount: 0,
      conflictCount: 0,
      lastSyncAt: null,
      error: null,
      syncNow: async () => {},
      setOfflineMode: () => {},
      clearError: () => {},
      refreshStatus: async () => {},
      store: null as any,
    };
  }
  return ctx;
}
