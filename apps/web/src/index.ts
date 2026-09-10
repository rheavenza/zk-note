/**
 * Web Application Core Exports (ZK-062).
 */

export * from "./worker/protocol.js";
export * from "./worker/vault-handler.js";
export * from "./worker/client.js";
export * from "./storage/models.js";
export * from "./storage/indexeddb.js";
export * from "./context/VaultContext.js";
export * from "./context/NotesContext.js";
export * from "./context/SearchContext.js";
export * from "./context/SyncContext.js";
export * from "./context/AuthContext.js";
export * from "./auth/webauthn.js";
export * from "./components/UnlockScreen.js";
export * from "./components/MarkdownEditor.js";
export * from "./components/NotesList.js";
export * from "./components/SearchBar.js";
export * from "./components/SearchModal.js";
export * from "./components/SyncStatusIndicator.js";
export * from "./components/NotesWorkspace.js";
export * from "./components/ConflictResolverModal.js";
export * from "./components/SecurityRecoveryModal.js";
export * from "./context/ConflictContext.js";
export * from "./utils/markdown.js";
export * from "./utils/diff3.js";
export * from "./utils/uuid.js";
export * from "./App.js";

import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.js";

// Mount root if running in a browser DOM environment with a #root container
if (typeof document !== "undefined") {
  const rootElement = document.getElementById("root");
  if (rootElement) {
    const root = createRoot(rootElement);
    root.render(React.createElement(App));
  }
}
