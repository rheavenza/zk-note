/**
 * Root Application Component (Zero-Knowledge Notes).
 *
 * Wires the complete context provider hierarchy:
 * 1. VaultProvider (vault lifecycle, key derivation, worker orchestration)
 * 2. SyncProvider (offline/online synchronization state machine)
 * 3. ConflictProvider (side-by-side conflict resolution)
 * 4. SearchProvider (in-memory search indexing and query)
 * 5. NotesProvider (note state, autosave, markdown editing)
 * 6. UnlockScreen (guards workspace until vault is unlocked)
 * 7. NotesWorkspace (split pane layout, toolbar, editor)
 */

import React from "react";
import { VaultWorkerClient } from "./worker/client.js";
import {
  IndexedDbStorage,
  getScopedDatabaseName,
  DEFAULT_DB_NAME,
} from "./storage/indexeddb.js";
import { VaultProvider } from "./context/VaultContext.js";
import { AuthProvider } from "./context/AuthContext.js";
import { SyncProvider } from "./context/SyncContext.js";
import { ConflictProvider } from "./context/ConflictContext.js";
import { SearchProvider } from "./context/SearchContext.js";
import { NotesProvider } from "./context/NotesContext.js";
import { ErrorBoundary } from "./components/ErrorBoundary.js";
import { UnlockScreen } from "./components/UnlockScreen.js";
import { NotesWorkspace } from "./components/NotesWorkspace.js";
import { readVaultLink, VaultLinkRecord } from "./auth/vault-link.js";
import { WebAuthnSession } from "./auth/webauthn.js";

export interface AppInnerProps {
  client?: VaultWorkerClient;
  storage?: IndexedDbStorage;
  onMountedStateChange?: (state: {
    dbName: string;
    storage: IndexedDbStorage;
    client: VaultWorkerClient;
  }) => void;
  children?: React.ReactNode;
}

export interface AppProps {
  client?: VaultWorkerClient;
  storage?: IndexedDbStorage;
  serverUrl?: string;
  initialSession?: WebAuthnSession | null;
  onMountedStateChange?: (state: {
    dbName: string;
    storage: IndexedDbStorage;
    client: VaultWorkerClient;
  }) => void;
  children?: React.ReactNode;
}

function createDefaultWorkerClient(): VaultWorkerClient {
  if (typeof window !== "undefined" && typeof Worker !== "undefined") {
    const worker = new Worker(new URL("./worker/worker.js", import.meta.url), {
      type: "module",
    });
    return new VaultWorkerClient(worker);
  }
  const dummyWorker = {
    postMessage: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
  };
  return new VaultWorkerClient(dummyWorker);
}

export const AppInner: React.FC<AppInnerProps> = ({
  client,
  storage: propStorage,
  onMountedStateChange,
  children,
}) => {
  const [linkState, setLinkState] = React.useState<{
    link: VaultLinkRecord | null;
    error: string | null;
  }>(() => {
    if (typeof window === "undefined" || !window.localStorage) {
      return { link: null, error: null };
    }
    try {
      return { link: readVaultLink(window.localStorage), error: null };
    } catch (err: any) {
      return {
        link: null,
        error: err?.message || "Failed to read vault link association from storage.",
      };
    }
  });

  React.useEffect(() => {
    const handler = (e: any) => {
      try {
        if (typeof window !== "undefined" && window.localStorage) {
          const l = readVaultLink(window.localStorage);
          setLinkState({ link: l, error: null });
        } else {
          setLinkState({ link: e.detail || null, error: null });
        }
      } catch (err: any) {
        setLinkState({
          link: null,
          error: err?.message || "Failed to read vault link association from storage.",
        });
      }
    };
    if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      window.addEventListener("zk:vault-link-changed", handler);
      return () => window.removeEventListener("zk:vault-link-changed", handler);
    }
    return undefined;
  }, []);

  const targetDbName = React.useMemo(() => {
    if (linkState.error) return null;
    if (propStorage) return propStorage.getDatabaseName();
    return linkState.link
      ? getScopedDatabaseName(DEFAULT_DB_NAME, linkState.link.serverOrigin, linkState.link.accountId)
      : DEFAULT_DB_NAME;
  }, [propStorage, linkState.error, linkState.link]);

  const [migrationError, setMigrationError] = React.useState<string | null>(null);
  const [retryNonce, setRetryNonce] = React.useState(0);

  // Track the active mounted state (dbName, storage, and worker client)
  const [mountedState, setMountedState] = React.useState<{
    dbName: string;
    storage: IndexedDbStorage;
    client: VaultWorkerClient;
  } | null>(() => {
    if (propStorage) {
      const cl = client || createDefaultWorkerClient();
      return { dbName: propStorage.getDatabaseName(), storage: propStorage, client: cl };
    }
    if (linkState.error) {
      return null;
    }
    const initialDbName = linkState.link
      ? getScopedDatabaseName(DEFAULT_DB_NAME, linkState.link.serverOrigin, linkState.link.accountId)
      : DEFAULT_DB_NAME;
    const st = new IndexedDbStorage(initialDbName);
    const cl = client || createDefaultWorkerClient();
    return { dbName: initialDbName, storage: st, client: cl };
  });

  // When targetDbName changes or retry is triggered, gate mounting/switching until worker lock completes
  React.useEffect(() => {
    if (!targetDbName) return undefined;
    if (targetDbName === mountedState?.dbName && !migrationError) {
      return undefined;
    }

    let isCancelled = false;
    const switchIdentity = async () => {
      setMigrationError(null);
      try {
        if (mountedState?.client && typeof mountedState.client.lockVault === "function") {
          await mountedState.client.lockVault();
        }
      } catch {
        // Proceed with clean client
      }
      if (isCancelled) return;

      const newStorage = propStorage || new IndexedDbStorage(targetDbName);

      if (targetDbName !== DEFAULT_DB_NAME) {
        try {
          await newStorage.migrateFromDefault();
        } catch (err: any) {
          if (!isCancelled) {
            setMigrationError(err?.message || "Failed to migrate vault data");
          }
          return;
        }
      }
      if (isCancelled) return;

      const newClient = client || createDefaultWorkerClient();

      setMountedState({
        dbName: targetDbName,
        storage: newStorage,
        client: newClient,
      });
    };

    void switchIdentity();

    return () => {
      isCancelled = true;
    };
  }, [targetDbName, mountedState?.dbName, mountedState?.client, propStorage, client, retryNonce]);

  React.useEffect(() => {
    if (mountedState) {
      onMountedStateChange?.(mountedState);
    }
  }, [mountedState, onMountedStateChange]);

  if (linkState.error) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900 p-6">
        <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 text-center space-y-4">
          <h2 className="text-lg font-semibold text-red-600 dark:text-red-400">Vault Link Error</h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {linkState.error}
          </p>
          <button
            type="button"
            onClick={() => {
              try {
                if (typeof window !== "undefined" && window.localStorage) {
                  const l = readVaultLink(window.localStorage);
                  setLinkState({ link: l, error: null });
                }
              } catch (err: any) {
                setLinkState({
                  link: null,
                  error: err?.message || "Failed to read vault link association from storage.",
                });
              }
            }}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (migrationError) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900 p-6">
        <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 text-center space-y-4">
          <h2 className="text-lg font-semibold text-red-600 dark:text-red-400">Vault Migration Failed</h2>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            {migrationError}
          </p>
          <button
            type="button"
            onClick={() => {
              setMigrationError(null);
              setRetryNonce((n) => n + 1);
            }}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium"
          >
            Retry Migration
          </button>
        </div>
      </div>
    );
  }

  // If transition is pending, do not render old or new VaultProvider to prevent async race
  if (!mountedState || targetDbName !== mountedState.dbName) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="text-sm text-gray-500">Switching vault identity...</div>
      </div>
    );
  }

  if (children) {
    return (
      <VaultProvider
        key={mountedState.dbName}
        client={mountedState.client}
        storage={mountedState.storage}
      >
        {children}
      </VaultProvider>
    );
  }

  return (
    <VaultProvider
      key={mountedState.dbName}
      client={mountedState.client}
      storage={mountedState.storage}
    >
      <SyncProvider>
        <ConflictProvider>
          <SearchProvider>
            <NotesProvider>
              <UnlockScreen>
                <NotesWorkspace />
              </UnlockScreen>
            </NotesProvider>
          </SearchProvider>
        </ConflictProvider>
      </SyncProvider>
    </VaultProvider>
  );
};

export const App: React.FC<AppProps> = ({
  client,
  storage,
  serverUrl,
  initialSession,
  onMountedStateChange,
  children,
}) => {
  return (
    <ErrorBoundary>
      <AuthProvider serverUrl={serverUrl} initialSession={initialSession}>
        <AppInner
          client={client}
          storage={storage}
          onMountedStateChange={onMountedStateChange}
        >
          {children}
        </AppInner>
      </AuthProvider>
    </ErrorBoundary>
  );
};

export default App;
