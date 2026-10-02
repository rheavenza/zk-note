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

import React, { useMemo } from "react";
import { VaultWorkerClient } from "./worker/client.js";
import {
  IndexedDbStorage,
  getScopedDatabaseName,
  DEFAULT_DB_NAME,
} from "./storage/indexeddb.js";
import { VaultProvider } from "./context/VaultContext.js";
import { AuthProvider, useAuth } from "./context/AuthContext.js";
import { SyncProvider } from "./context/SyncContext.js";
import { ConflictProvider } from "./context/ConflictContext.js";
import { SearchProvider } from "./context/SearchContext.js";
import { NotesProvider } from "./context/NotesContext.js";
import { ErrorBoundary } from "./components/ErrorBoundary.js";
import { UnlockScreen } from "./components/UnlockScreen.js";
import { NotesWorkspace } from "./components/NotesWorkspace.js";

export interface AppProps {
  client?: VaultWorkerClient;
  storage?: IndexedDbStorage;
  serverUrl?: string;
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

const AppInner: React.FC<{
  client?: VaultWorkerClient;
  storage?: IndexedDbStorage;
}> = ({ client, storage: propStorage }) => {
  const { serverOrigin, session } = useAuth();
  const activeClient = useMemo(
    () => client || createDefaultWorkerClient(),
    [client]
  );

  const activeStorage = useMemo(() => {
    if (propStorage) return propStorage;
    const dbName = getScopedDatabaseName(
      DEFAULT_DB_NAME,
      serverOrigin,
      session?.accountId
    );
    return new IndexedDbStorage(dbName);
  }, [propStorage, serverOrigin, session?.accountId]);

  const storageKey = activeStorage.getDatabaseName();

  const lastStorageKeyRef = React.useRef<string>(storageKey);
  if (lastStorageKeyRef.current !== storageKey) {
    lastStorageKeyRef.current = storageKey;
    activeClient.lockVault().catch(() => {});
  }

  React.useEffect(() => {
    activeClient.lockVault().catch(() => {});
  }, [storageKey, activeClient]);

  return (
    <VaultProvider key={storageKey} client={activeClient} storage={activeStorage}>
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

export const App: React.FC<AppProps> = ({ client, storage, serverUrl }) => {
  return (
    <ErrorBoundary>
      <AuthProvider serverUrl={serverUrl}>
        <AppInner client={client} storage={storage} />
      </AuthProvider>
    </ErrorBoundary>
  );
};

export default App;
