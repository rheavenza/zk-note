/**
 * Notes Workspace Component (ZK-065).
 *
 * Integrates:
 * - Left pane: NotesList (sidebar with creation, filter, and selection).
 * - Right pane: MarkdownEditor (Markdown source, live preview, tags, autosave).
 * - Top navbar: App brand, offline indicator, vault status, and lock button.
 */

import React from "react";
import { NotesList } from "./NotesList.js";
import { MarkdownEditor } from "./MarkdownEditor.js";
import { LockVaultButton, VaultStatusBadge } from "./UnlockScreen.js";
import { SearchBar } from "./SearchBar.js";
import { SearchModal } from "./SearchModal.js";

export interface NotesWorkspaceProps {
  className?: string;
}

export const NotesWorkspace: React.FC<NotesWorkspaceProps> = ({ className }) => {
  return (
    <div
      className={className || "zk-notes-workspace"}
      style={workspaceContainerStyle}
      data-testid="notes-workspace"
    >
      {/* Top Navbar */}
      <header style={navbarStyle}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "20px" }}>🔒</span>
          <h1 style={{ margin: 0, fontSize: "16px", fontWeight: 700, color: "#111827" }}>
            Zero-Knowledge Notes
          </h1>
          <span style={offlineBadgeStyle}>
            ● Offline Ready (Encrypted Locally)
          </span>
        </div>

        {/* Local in-memory search bar */}
        <SearchBar />

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <VaultStatusBadge />
          <LockVaultButton />
        </div>
      </header>

      {/* Main Two-Pane Split Layout */}
      <div style={mainSplitStyle}>
        <aside style={{ height: "100%", display: "flex" }}>
          <NotesList />
        </aside>

        <main style={{ flex: 1, height: "100%", overflow: "hidden" }}>
          <MarkdownEditor />
        </main>
      </div>

      {/* Quick Search Modal / Command Palette */}
      <SearchModal />
    </div>
  );
};

// Styles
const workspaceContainerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  height: "100vh",
  width: "100%",
  backgroundColor: "#ffffff",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  overflow: "hidden",
};

const navbarStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "10px 20px",
  backgroundColor: "#ffffff",
  borderBottom: "1px solid #e5e7eb",
  boxSizing: "border-box",
};

const offlineBadgeStyle: React.CSSProperties = {
  fontSize: "11px",
  fontWeight: 600,
  color: "#059669",
  backgroundColor: "#ecfdf5",
  padding: "2px 8px",
  borderRadius: "12px",
  border: "1px solid #a7f3d0",
};

const mainSplitStyle: React.CSSProperties = {
  flex: 1,
  display: "flex",
  overflow: "hidden",
};
