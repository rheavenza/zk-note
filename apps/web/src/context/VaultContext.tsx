/**
 * Vault React Context, State Store, and State Machine (ZK-064).
 *
 * Enforces:
 * - SEC-001 / SEC-002: VaultKey is NEVER held in React component state.
 * - Clear state machine: UNINITIALIZED -> LOCKED <-> UNLOCKED.
 * - Sanitized, non-revealing error reporting.
 */

import React, {
  createContext,
  useContext,
  useMemo,
  useEffect,
  useSyncExternalStore,
} from "react";
import { VaultWorkerClient, WorkerError } from "../worker/client.js";
import { IndexedDbStorage } from "../storage/indexeddb.js";
import { WorkerErrorCode } from "../worker/protocol.js";

export type VaultState = "UNINITIALIZED" | "LOCKED" | "UNLOCKING" | "UNLOCKED";

export interface VaultBootstrapData {
  wrappedVaultKey: string;
  kdfParamsJson: string;
  wrappedRecoveryKey: string;
}

export interface VaultSnapshot {
  vaultState: VaultState;
  bootstrap: VaultBootstrapData | null;
  error: string | null;
  autoLockTimeoutMinutes: number;
}

export interface VaultContextType {
  vaultState: VaultState;
  bootstrap: VaultBootstrapData | null;
  error: string | null;
  autoLockTimeoutMinutes: number;
  clearError: () => void;
  initVault: (passphrase: string, kdfParamsJson?: string) => Promise<{ recoveryPhrase: string }>;
  unlockWithPassphrase: (passphrase: string) => Promise<void>;
  unlockWithRecoveryKey: (recoveryPhrase: string) => Promise<void>;
  rewrapPassphrase: (
    newPassphrase: string,
    kdfParamsJson?: string,
    oldPassphrase?: string
  ) => Promise<void>;
  lock: () => Promise<void>;
  setAutoLockTimeout: (minutes: number) => void;
  recordActivity: () => void;
  checkIdleLock: () => Promise<void>;
  client: VaultWorkerClient;
  storage: IndexedDbStorage;
  store: VaultStore;
}

const BOOTSTRAP_STORAGE_KEY = "zk_vault_bootstrap";
export const DEFAULT_AUTO_LOCK_MINUTES = 15;
export const AUTO_LOCK_STORAGE_KEY = "zk_autolock_minutes";

function getStoredBootstrap(): VaultBootstrapData | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const raw = window.localStorage.getItem(BOOTSTRAP_STORAGE_KEY);
      if (raw) return JSON.parse(raw);
    }
  } catch {
    // Ignore storage errors
  }
  return null;
}

function persistBootstrap(data: VaultBootstrapData): void {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(BOOTSTRAP_STORAGE_KEY, JSON.stringify(data));
    }
  } catch {
    // Ignore storage errors
  }
}

function getStoredAutoLockTimeout(): number {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const raw = window.localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
      if (raw !== null) {
        const parsed = parseInt(raw, 10);
        if (!isNaN(parsed) && parsed >= 0) {
          return parsed;
        }
      }
    }
  } catch {
    // Ignore storage errors
  }
  return DEFAULT_AUTO_LOCK_MINUTES;
}

function persistAutoLockTimeout(minutes: number): void {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(AUTO_LOCK_STORAGE_KEY, minutes.toString());
    }
  } catch {
    // Ignore storage errors
  }
}

/**
 * Headless Vault State Store.
 * Encapsulates the state machine and worker communication outside React,
 * ensuring clean separation and deterministic testing.
 */
export class VaultStore {
  private state: VaultState;
  private bootstrap: VaultBootstrapData | null;
  private error: string | null = null;
  private autoLockTimeoutMinutes: number;
  private lastActivityTime: number = Date.now();
  private idleCheckInterval: any = null;
  private listeners = new Set<() => void>();
  private unsubscribeLock: () => void;
  private isDisposed = false;

  constructor(
    public readonly client: VaultWorkerClient,
    public readonly storage: IndexedDbStorage,
    initialBootstrap: VaultBootstrapData | null = null,
    initialAutoLockMinutes?: number
  ) {
    this.autoLockTimeoutMinutes =
      initialAutoLockMinutes !== undefined
        ? initialAutoLockMinutes
        : getStoredAutoLockTimeout();

    if (initialBootstrap !== undefined && initialBootstrap !== null) {
      this.bootstrap = initialBootstrap;
      this.state = "LOCKED";
    } else if (initialBootstrap === null) {
      const stored = getStoredBootstrap();
      if (stored) {
        this.bootstrap = stored;
        this.state = "LOCKED";
      } else {
        this.bootstrap = null;
        this.state = "UNINITIALIZED";
      }
    } else {
      this.bootstrap = null;
      this.state = "UNINITIALIZED";
    }

    // Subscribe to worker lock broadcasts
    this.unsubscribeLock = this.client.onLock(() => {
      this.state = "LOCKED";
      this.notify();
    });

    // Start background idle lock checker interval (every 2s)
    if (typeof setInterval !== "undefined") {
      this.idleCheckInterval = setInterval(() => {
        this.checkIdleLock();
      }, 2000);
      if (
        this.idleCheckInterval &&
        typeof (this.idleCheckInterval as any).unref === "function"
      ) {
        (this.idleCheckInterval as any).unref();
      }
    }

    // Check actual worker session status if available
    this.checkWorkerStatus();
  }

  private async checkWorkerStatus(): Promise<void> {
    try {
      const status = await this.client.getStatus();
      if (!this.isDisposed && status.isUnlocked) {
        this.state = "UNLOCKED";
        this.recordActivity();
        this.notify();
      }
    } catch {
      // Ignore initial status check errors
    }
  }

  public getState(): VaultSnapshot {
    return {
      vaultState: this.state,
      bootstrap: this.bootstrap,
      error: this.error,
      autoLockTimeoutMinutes: this.autoLockTimeoutMinutes,
    };
  }

  public getSnapshot = (): VaultSnapshot => {
    return this.getState();
  };

  public setAutoLockTimeout(minutes: number): void {
    this.autoLockTimeoutMinutes = Math.max(0, minutes);
    persistAutoLockTimeout(this.autoLockTimeoutMinutes);
    this.recordActivity();
    this.notify();
  }

  public getAutoLockTimeout(): number {
    return this.autoLockTimeoutMinutes;
  }

  public recordActivity(): void {
    this.lastActivityTime = Date.now();
  }

  public checkIdleLock = async (): Promise<void> => {
    if (this.isDisposed) return;
    if (this.state === "UNLOCKED" && this.autoLockTimeoutMinutes > 0) {
      const elapsedMs = Date.now() - this.lastActivityTime;
      const timeoutMs = this.autoLockTimeoutMinutes * 60 * 1000;
      if (elapsedMs >= timeoutMs) {
        await this.lock();
      }
    }
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

  public sanitizeError(err: unknown): string {
    if (err instanceof WorkerError) {
      switch (err.code) {
        case WorkerErrorCode.DECRYPTION_FAILED:
          if (
            (err as any)?.message &&
            String((err as any).message).includes("Current master passphrase is incorrect")
          ) {
            return "Current master passphrase is incorrect.";
          }
          return "Incorrect passphrase or invalid recovery key.";
        case WorkerErrorCode.INVALID_RECOVERY_KEY:
          return "Invalid recovery phrase format or checksum.";
        case WorkerErrorCode.VAULT_LOCKED:
          return "Vault is locked.";
        default:
          return "Cryptographic operation failed.";
      }
    }
    return "An unexpected error occurred.";
  }

  public async initVault(
    passphrase: string,
    kdfParamsJson?: string
  ): Promise<{ recoveryPhrase: string }> {
    this.error = null;
    this.state = "UNLOCKING";
    this.notify();

    try {
      const res = await this.client.initVault(passphrase, kdfParamsJson);
      const newBootstrap: VaultBootstrapData = {
        wrappedVaultKey: res.wrappedVaultKey,
        kdfParamsJson: res.kdfParamsJson,
        wrappedRecoveryKey: res.wrappedRecoveryKey,
      };

      persistBootstrap(newBootstrap);

      this.bootstrap = newBootstrap;
      this.state = "UNLOCKED";
      this.recordActivity();
      this.notify();

      return { recoveryPhrase: res.recoveryPhrase };
    } catch (err) {
      const msg = this.sanitizeError(err);
      this.error = msg;
      this.state = "UNINITIALIZED";
      this.notify();
      throw new Error(msg);
    }
  }

  public async unlockWithPassphrase(passphrase: string): Promise<void> {
    if (!this.bootstrap) {
      this.error = "Vault is not initialized.";
      this.notify();
      return;
    }

    this.error = null;
    this.state = "UNLOCKING";
    this.notify();

    try {
      await this.client.unlockVault(
        passphrase,
        this.bootstrap.wrappedVaultKey,
        this.bootstrap.kdfParamsJson
      );
      this.state = "UNLOCKED";
      this.recordActivity();
      this.notify();
    } catch (err) {
      const msg = this.sanitizeError(err);
      this.error = msg;
      this.state = "LOCKED";
      this.notify();
      throw new Error(msg);
    }
  }

  public async unlockWithRecoveryKey(recoveryPhrase: string): Promise<void> {
    if (!this.bootstrap) {
      this.error = "Vault is not initialized.";
      this.notify();
      return;
    }

    this.error = null;
    this.state = "UNLOCKING";
    this.notify();

    try {
      await this.client.unlockWithRecoveryKey(
        recoveryPhrase.trim(),
        this.bootstrap.wrappedRecoveryKey
      );
      this.state = "UNLOCKED";
      this.recordActivity();
      this.notify();
    } catch (err) {
      const msg = this.sanitizeError(err);
      this.error = msg;
      this.state = "LOCKED";
      this.notify();
      throw new Error(msg);
    }
  }

  public async rewrapPassphrase(
    newPassphrase: string,
    kdfParamsJson?: string,
    oldPassphrase?: string
  ): Promise<void> {
    if (!this.bootstrap) {
      this.error = "Vault is not initialized.";
      this.notify();
      return;
    }

    this.error = null;
    try {
      const res = await this.client.rewrapPassphrase(
        newPassphrase,
        kdfParamsJson,
        oldPassphrase,
        this.bootstrap.wrappedVaultKey,
        this.bootstrap.kdfParamsJson
      );
      const newBootstrap: VaultBootstrapData = {
        wrappedVaultKey: res.newWrappedVaultKey,
        kdfParamsJson: res.newKdfParamsJson,
        wrappedRecoveryKey: this.bootstrap.wrappedRecoveryKey,
      };

      persistBootstrap(newBootstrap);
      this.bootstrap = newBootstrap;
      this.notify();
    } catch (err) {
      const msg = this.sanitizeError(err);
      this.error = msg;
      this.notify();
      throw new Error(msg);
    }
  }

  public async lock(): Promise<void> {
    try {
      await this.client.lockVault();
    } finally {
      this.state = "LOCKED";
      this.error = null;
      this.notify();
    }
  }

  public dispose(): void {
    this.isDisposed = true;
    if (this.idleCheckInterval) {
      clearInterval(this.idleCheckInterval);
      this.idleCheckInterval = null;
    }
    this.unsubscribeLock();
    this.listeners.clear();
  }
}

const VaultContext = createContext<VaultContextType | null>(null);

export interface VaultProviderProps {
  client: VaultWorkerClient;
  storage: IndexedDbStorage;
  initialBootstrap?: VaultBootstrapData | null;
  initialAutoLockMinutes?: number;
  children: React.ReactNode;
}

export const VaultProvider: React.FC<VaultProviderProps> = ({
  client,
  storage,
  initialBootstrap = null,
  initialAutoLockMinutes,
  children,
}) => {
  const store = useMemo(
    () => new VaultStore(client, storage, initialBootstrap, initialAutoLockMinutes),
    [client, storage, initialBootstrap, initialAutoLockMinutes]
  );

  useEffect(() => {
    return () => {
      store.dispose();
    };
  }, [store]);

  // Window/document user activity listeners to touch idle timeout
  useEffect(() => {
    if (typeof window === "undefined") return;

    let lastThrottledTime = 0;
    const handleActivity = () => {
      const now = Date.now();
      if (now - lastThrottledTime > 1000) {
        lastThrottledTime = now;
        store.recordActivity();
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        store.checkIdleLock();
      }
    };

    const events = ["mousedown", "keydown", "touchstart", "scroll", "mousemove"];
    for (const event of events) {
      window.addEventListener(event, handleActivity, { passive: true });
    }
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      for (const event of events) {
        window.removeEventListener(event, handleActivity);
      }
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [store]);

  // Hook into React external store lifecycle to re-render consumers
  useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);

  const value: VaultContextType = useMemo(
    () => ({
      get vaultState() {
        return store.getState().vaultState;
      },
      get bootstrap() {
        return store.getState().bootstrap;
      },
      get error() {
        return store.getState().error;
      },
      get autoLockTimeoutMinutes() {
        return store.getState().autoLockTimeoutMinutes;
      },
      clearError: () => store.clearError(),
      initVault: (p: string, k?: string) => store.initVault(p, k),
      unlockWithPassphrase: (p: string) => store.unlockWithPassphrase(p),
      unlockWithRecoveryKey: (r: string) => store.unlockWithRecoveryKey(r),
      rewrapPassphrase: (p: string, k?: string, old?: string) =>
        store.rewrapPassphrase(p, k, old),
      lock: () => store.lock(),
      setAutoLockTimeout: (minutes: number) => store.setAutoLockTimeout(minutes),
      recordActivity: () => store.recordActivity(),
      checkIdleLock: () => store.checkIdleLock(),
      client: store.client,
      storage: store.storage,
      store,
    }),
    [store]
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
};

export function useVault(): VaultContextType {
  const ctx = useContext(VaultContext);
  if (!ctx) {
    throw new Error("useVault must be used within a VaultProvider");
  }
  return ctx;
}
