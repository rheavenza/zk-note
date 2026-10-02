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
import { normalizeServerOrigin } from "../auth/session.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import {
  BrowserSyncAdapter,
  type SyncServerAdapter,
} from "../sync/adapter.js";

/**
 * Truthful synchronization states (ZK-107).
 *
 * - "local only":        the vault is not linked to any account; nothing leaves this device.
 * - "sign in to sync":   the vault is linked, but no authenticated session matches the link.
 * - "not synced yet":    linked and authenticated, but no server round trip has completed yet.
 * - "offline":           the browser or the user reports no connectivity.
 * - "pending changes":   encrypted local changes are queued and have not been uploaded.
 * - "syncing":           a server round trip is in flight.
 * - "synced":            ONLY set after a server round trip completes successfully.
 * - "error":             the last synchronization attempt failed.
 * - "conflict":          one or more conflicts require an explicit decision.
 *
 * "synced" must never be reached from local persistence alone (ZK-107 acceptance A).
 */
export type SyncStatus =
  | "local only"
  | "sign in to sync"
  | "not synced yet"
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
  /** True when a persisted vault link ties this browser to an account. */
  linked: boolean;
  /** True when an authenticated, link-matching server adapter is wired up. */
  syncConfigured: boolean;
  /** True only when at least one full server round trip has completed for this identity. */
  hasCompletedSync: boolean;
}

export interface SyncContextType extends SyncStateSnapshot {
  syncNow: () => Promise<void>;
  setOfflineMode: (offline: boolean) => void;
  clearError: () => void;
  refreshStatus: () => Promise<void>;
  store: SyncStore;
}

/**
 * Link context describing whether this browser's vault is associated with an account.
 * The identity is used to read the durable sync cursor/timestamp for the correct
 * account-scoped database, even while no authenticated adapter is active.
 */
export interface SyncLinkContext {
  linked: boolean;
  identity?: string;
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
  private linked = false;
  private syncIdentity?: string;
  private listeners = new Set<() => void>();
  private snapshot: SyncStateSnapshot;

  constructor(
    public readonly storage: IndexedDbStorage,
    public readonly serverAdapter?: SyncServerAdapter
  ) {
    if (typeof navigator !== "undefined" && typeof navigator.onLine === "boolean") {
      this.isNetworkOnline = navigator.onLine;
    }

    this.snapshot = this.buildSnapshot();
  }

  private buildSnapshot(): SyncStateSnapshot {
    return {
      status: this.getStatus(),
      isOnline: this.getIsOnline(),
      isSyncing: this.isSyncing,
      pendingCount: this.pendingCount,
      conflictCount: this.conflictCount,
      lastSyncAt: this.lastSyncAt,
      error: this.error,
      linked: this.linked,
      syncConfigured: this.isSyncConfigured(),
      hasCompletedSync: this.lastSyncAt !== null,
    };
  }

  private updateSnapshot(): void {
    this.snapshot = this.buildSnapshot();
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

  /** True when a usable authenticated server adapter is wired up (ZK-107 acceptance A4). */
  public isSyncConfigured(): boolean {
    const adapter = this.serverAdapter;
    if (!adapter) return false;
    return Boolean(adapter.sync || adapter.pushMutations || adapter.pullChanges);
  }

  public isLinked(): boolean {
    return this.linked;
  }

  /**
   * Derives the truthful display status.
   *
   * Precedence is deliberate: conflicts and connectivity are facts that outrank a
   * stale success/failure banner, and "synced" is reachable only when a full server
   * round trip has recorded `last_sync_at` for the active identity.
   */
  public getStatus(): SyncStatus {
    if (this.conflictCount > 0) return "conflict";
    if (!this.getIsOnline()) return "offline";
    if (this.error !== null) return "error";
    if (this.isSyncing) return "syncing";
    if (this.isSyncConfigured()) {
      // Only a vault with a real upload target can have "pending" changes.
      if (this.pendingCount > 0) return "pending changes";
      return this.lastSyncAt !== null ? "synced" : "not synced yet";
    }
    // No usable adapter: local work is not "pending" against any server.
    return this.linked ? "sign in to sync" : "local only";
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

  /**
   * Records whether this browser's vault is linked to an account, and under which
   * identity its durable sync state (cursor + `last_sync_at`) is stored.
   */
  public setLinkContext(context?: SyncLinkContext): void {
    this.linked = context?.linked ?? false;
    this.syncIdentity = context?.identity;
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

      // 3. Read the durable sync timestamp for the linked identity. When no identity is
      //    known the default ("singleton") record of the selected database is used; the
      //    "synced" status additionally requires a configured adapter, so a stale value
      //    can never by itself present local-only state as server-synchronized.
      const identity = (this.serverAdapter as any)?.identity || this.syncIdentity;
      const syncState = await this.storage.getSyncState(identity);
      this.lastSyncAt =
        syncState && syncState.last_sync_at ? new Date(syncState.last_sync_at) : null;
      this.notify();
    } catch {
      // Ignore storage polling errors
    }
  }

  public async syncNow(): Promise<void> {
    if (!this.isSyncConfigured()) {
      // No authenticated adapter that matches the vault link: never claim success.
      this.error = this.linked
        ? "Sign in to the account this vault is linked to before synchronizing."
        : "This vault is not linked to an account. Notes remain on this device.";
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

    // Guarded by isSyncConfigured() above.
    const adapter = this.serverAdapter!;

    try {
      if (adapter.sync) {
        await adapter.sync(this.storage);
      } else {
        if (adapter.pushMutations) {
          await adapter.pushMutations(this.storage);
        }
        if (adapter.pullChanges) {
          await adapter.pullChanges(this.storage);
        }

        const now = new Date();
        const identity = (adapter as { identity?: string }).identity;
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
  const { storage, vaultState, vaultLink, client } = useVault();
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
        workerClient: client,
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
    client,
  ]);

  // The identity that owns this browser's durable sync state. It is derived from the
  // persisted vault link (not the transient session), so cursor and last-sync timestamp
  // survive logout, expiry, and wrong-account sign-in.
  const linkedIdentity = useMemo(() => {
    if (!vaultLink) return undefined;
    return `${normalizeServerOrigin(vaultLink.serverOrigin)}::${vaultLink.accountId}`;
  }, [vaultLink]);

  const activeAdapterIdentity = (activeAdapter as { identity?: string } | undefined)?.identity;

  const linkContext = useMemo<SyncLinkContext>(
    () => ({
      linked: Boolean(vaultLink),
      identity: activeAdapterIdentity || linkedIdentity,
    }),
    [vaultLink, activeAdapterIdentity, linkedIdentity]
  );

  const store = useMemo(
    () => propStore || new SyncStore(storage, activeAdapter),
    [propStore, storage]
  );

  useEffect(() => {
    if (!propStore) {
      store.setServerAdapter(activeAdapter);
      store.setLinkContext(linkContext);
      store.refreshStatus();
    }
  }, [store, activeAdapter, linkContext, propStore]);

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
      get linked() {
        return store.isLinked();
      },
      get syncConfigured() {
        return store.isSyncConfigured();
      },
      get hasCompletedSync() {
        return store.getState().hasCompletedSync;
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

/**
 * Without a provider there is no evidence of any server synchronization, so the
 * only truthful state is local-only (never "synced"). Kept as a module-level
 * constant so consumers do not see a new object identity on every render.
 */
const NO_SYNC_CONTEXT: SyncContextType = {
  status: "local only",
  isOnline: true,
  isSyncing: false,
  pendingCount: 0,
  conflictCount: 0,
  lastSyncAt: null,
  error: null,
  linked: false,
  syncConfigured: false,
  hasCompletedSync: false,
  syncNow: async () => {},
  setOfflineMode: () => {},
  clearError: () => {},
  refreshStatus: async () => {},
  store: null as any,
};

export function useSync(): SyncContextType {
  const ctx = useContext(SyncContext);
  return ctx || NO_SYNC_CONTEXT;
}
