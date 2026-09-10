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
import { IndexedDbStorage } from "./storage/indexeddb.js";
import { VaultProvider } from "./context/VaultContext.js";
import { SyncProvider } from "./context/SyncContext.js";
import { ConflictProvider } from "./context/ConflictContext.js";
import { SearchProvider } from "./context/SearchContext.js";
import { NotesProvider } from "./context/NotesContext.js";
import { UnlockScreen } from "./components/UnlockScreen.js";
import { NotesWorkspace } from "./components/NotesWorkspace.js";

export interface AppProps {
  client?: VaultWorkerClient;
  storage?: IndexedDbStorage;
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

export const App: React.FC<AppProps> = ({ client, storage }) => {
  const activeClient = useMemo(() => client || createDefaultWorkerClient(), [client]);
  const activeStorage = useMemo(() => storage || new IndexedDbStorage(), [storage]);

  return (
    <VaultProvider client={activeClient} storage={activeStorage}>
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

export default App;
