/**
 * Notes Workspace Component (ZK-065).
 *
 * Integrates:
 * - Left pane: NotesList (sidebar with creation, filter, and selection).
 * - Right pane: MarkdownEditor (Markdown source, live preview, tags, autosave).
 * - Top navbar: App brand, offline indicator, vault status, and lock button.
 */

import React, { useState } from "react";
import { NotesList } from "./NotesList.js";
import { MarkdownEditor } from "./MarkdownEditor.js";
import { LockVaultButton, VaultStatusBadge } from "./UnlockScreen.js";
import { SearchBar } from "./SearchBar.js";
import { SearchModal } from "./SearchModal.js";
import { SyncStatusIndicator } from "./SyncStatusIndicator.js";
import { ConflictResolverModal } from "./ConflictResolverModal.js";
import { SecurityRecoveryModal } from "./SecurityRecoveryModal.js";

export interface NotesWorkspaceProps {
  className?: string;
}

export const NotesWorkspace: React.FC<NotesWorkspaceProps> = ({ className }) => {
  const [isSecurityModalOpen, setIsSecurityModalOpen] = useState(false);

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
          <SyncStatusIndicator />
        </div>

        {/* Local in-memory search bar */}
        <SearchBar />

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <VaultStatusBadge />
          <button
            type="button"
            onClick={() => setIsSecurityModalOpen(true)}
            title="Security & Recovery"
            style={securityButtonStyle}
            aria-label="Security and recovery settings"
            className="zk-security-recovery-btn"
          >
            🛡️ Security
          </button>
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

      {/* Sync Conflict Resolver Modal */}
      <ConflictResolverModal />

      {/* Security & Recovery Invariants Modal (ZK-073) */}
      <SecurityRecoveryModal
        isOpen={isSecurityModalOpen}
        onClose={() => setIsSecurityModalOpen(false)}
      />
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


const mainSplitStyle: React.CSSProperties = {
  flex: 1,
  display: "flex",
  overflow: "hidden",
};

const securityButtonStyle: React.CSSProperties = {
  padding: "6px 12px",
  borderRadius: "6px",
  border: "1px solid #d1d5db",
  backgroundColor: "#ffffff",
  color: "#374151",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: 500,
  display: "inline-flex",
  alignItems: "center",
  gap: "6px",
};
