/**
 * Sync Status Indicator Component (ZK-067, ZK-107).
 *
 * Requirements:
 * - Accurately and truthfully displays every sync state:
 *   - "local only"       (vault not linked to any account)
 *   - "sign in to sync"  (linked, but no matching authenticated session)
 *   - "not synced yet"   (linked + signed in, no server round trip completed)
 *   - "offline"
 *   - "syncing"
 *   - "synced"           (only after a real server round trip)
 *   - "pending changes"
 *   - "conflict"
 *   - "error"
 * - Must NOT leak note content, titles, or secrets (SEC-001, SEC-003).
 * - Interactive popover showing counts, timestamps, and manual sync / offline controls.
 */

import React, { useState } from "react";
import { useSync, SyncStatus } from "../context/SyncContext.js";
import { useConflict } from "../context/ConflictContext.js";

export interface SyncStatusIndicatorProps {
  className?: string;
  style?: React.CSSProperties;
  showPopoverOnClick?: boolean;
  status?: SyncStatus;
  pendingCount?: number;
  conflictCount?: number;
}

export const SyncStatusIndicator: React.FC<SyncStatusIndicatorProps> = ({
  className,
  style,
  showPopoverOnClick = true,
  status: propStatus,
  pendingCount: propPendingCount,
  conflictCount: propConflictCount,
}) => {
  const sync = useSync();
  const { activeConflicts, openModal } = useConflict();

  const status = propStatus || sync.status;
  const pendingCount = propPendingCount !== undefined ? propPendingCount : sync.pendingCount;
  const conflictCount = propConflictCount !== undefined ? propConflictCount : sync.conflictCount;
  const {
    isOnline,
    isSyncing,
    lastSyncAt,
    error,
    syncNow,
    setOfflineMode,
    clearError,
  } = sync;

  const [isPopoverOpen, setIsPopoverOpen] = useState(false);

  const getStatusConfig = (s: SyncStatus) => {
    switch (s) {
      case "local only":
        return {
          icon: "◯", label: "local only", bg: "#f3f4f6", text: "#4b5563", border: "#d1d5db",
        };
      case "sign in to sync":
        return {
          icon: "🔑", label: "sign in to sync", bg: "#eef2ff", text: "#4338ca", border: "#c7d2fe",
        };
      case "not synced yet":
        return {
          icon: "⬆", label: "not synced yet", bg: "#eff6ff", text: "#1d4ed8", border: "#bfdbfe",
        };
      case "offline":
        return {
          icon: "☁️",
          label: "offline",
          bg: "#f3f4f6",
          text: "#4b5563",
          border: "#d1d5db",
        };
      case "syncing":
        return {
          icon: "🔄",
          label: "syncing",
          bg: "#eff6ff",
          text: "#1d4ed8",
          border: "#bfdbfe",
        };
      case "synced":
        return {
          icon: "✓",
          label: "synced",
          bg: "#f0fdf4",
          text: "#15803d",
          border: "#bbf7d0",
        };
      case "pending changes":
        return {
          icon: "⏳",
          label: "pending changes",
          bg: "#fefce8",
          text: "#a16207",
          border: "#fef08a",
        };
      case "conflict":
        return {
          icon: "⚠️",
          label: "conflict",
          bg: "#fff7ed",
          text: "#c2410c",
          border: "#fed7aa",
        };
      case "error":
        return {
          icon: "❌",
          label: "error",
          bg: "#fef2f2",
          text: "#b91c1c",
          border: "#fecaca",
        };
    }
  };

  const config = getStatusConfig(status);

  /**
   * Truthful, zero-knowledge explanation of what the current state means for the
   * user's data. Never claims server synchronization that has not happened.
   */
  const getStatusExplanation = (s: SyncStatus): string => {
    switch (s) {
      case "local only":
        return pendingCount > 0
          ? `This vault is not linked to an account. ${pendingCount} encrypted local change${pendingCount === 1 ? "" : "s"} are stored on this device only, with no server copy.`
          : "This vault is not linked to an account. Notes are encrypted and stored on this device only.";
      case "sign in to sync":
        return pendingCount > 0
          ? `This vault is linked to an account and ${pendingCount} local change${pendingCount === 1 ? "" : "s"} are waiting to upload. Sign in to the linked account to synchronize them.`
          : "This vault is linked to an account, but no matching signed-in session is active. Notes stay available locally and sync is disabled until you sign in to the linked account.";
      case "not synced yet":
        return "Linked and signed in, but no server synchronization has completed yet. Run Sync Now to upload this vault.";
      case "offline":
        return pendingCount > 0
          ? `Offline. ${pendingCount} change${pendingCount === 1 ? "" : "s"} are saved on this device and will upload when the connection returns.`
          : "Offline. Notes are saved on this device only and are not being synchronized.";
      case "syncing":
        return "Uploading and downloading encrypted changes with the server.";
      case "synced":
        return "The last server round trip completed successfully. Local changes made offline will return to pending until they are uploaded.";
      case "pending changes":
        return `${pendingCount} encrypted change${pendingCount === 1 ? "" : "s"} are saved on this device and waiting to upload. They are not yet on the server.`;
      case "conflict":
        return "A remote change conflicts with a local edit. Your local edit is preserved until you resolve the conflict.";
      case "error":
        return "The last synchronization attempt failed. Your notes remain safe on this device.";
    }
  };

  const handleTogglePopover = () => {
    if (showPopoverOnClick) {
      setIsPopoverOpen((prev) => !prev);
    }
  };

  return (
    <div
      style={{ position: "relative", display: "inline-block", ...style }}
      className={className || "zk-sync-status-container"}
      data-testid="sync-status-container"
    >
      {/* Badge Button */}
      <button
        type="button"
        onClick={handleTogglePopover}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "6px",
          padding: "3px 10px",
          borderRadius: "9999px",
          fontSize: "12px",
          fontWeight: 600,
          backgroundColor: config.bg,
          color: config.text,
          border: `1px solid ${config.border}`,
          cursor: "pointer",
          outline: "none",
          transition: "background-color 0.15s ease",
        }}
        className={`zk-sync-badge zk-sync-status-${status.replace(/\s+/g, "-")}`}
        aria-label={`Sync status: ${status}`}
        data-testid="sync-status-badge"
      >
        <span style={{ fontSize: "11px" }}>{config.icon}</span>
        <span className="zk-sync-label">{config.label}</span>
        {(status === "pending changes" || status === "offline") && pendingCount > 0 && (
          <span style={badgeCountStyle}>{`(${pendingCount})`}</span>
        )}
        {status === "conflict" && conflictCount > 0 && (
          <span style={badgeCountStyle}>{`(${conflictCount})`}</span>
        )}
      </button>

      {/* Popover Details Modal */}
      {isPopoverOpen && (
        <>
          <div
            style={backdropOverlayStyle}
            onClick={() => setIsPopoverOpen(false)}
            data-testid="sync-popover-backdrop"
          />
          <div
            style={popoverCardStyle}
            className="zk-sync-popover"
            data-testid="sync-popover"
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h4 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "#111827" }}>
                Synchronization Status
              </h4>
              <button
                type="button"
                onClick={() => setIsPopoverOpen(false)}
                style={closeButtonStyle}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            {/* Current State Detail */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: 12 }}>
              <span
                style={{
                  display: "inline-block",
                  padding: "3px 8px",
                  borderRadius: "6px",
                  backgroundColor: config.bg,
                  color: config.text,
                  fontSize: "12px",
                  fontWeight: 600,
                }}
              >
                {config.icon} {config.label}
              </span>
            </div>

            {/* Truthful state explanation (zero note content, SEC-001/SEC-003) */}
            <p
              style={{ margin: "0 0 12px 0", fontSize: "12px", lineHeight: 1.5, color: "#4b5563" }}
              data-testid="sync-status-explanation"
            >
              {getStatusExplanation(status)}
            </p>

            {/* Sanitized Metrics (Zero note content) */}
            <div style={metricsContainerStyle}>
              <div style={metricRowStyle}>
                <span style={metricLabelStyle}>Pending Mutations:</span>
                <span style={metricValueStyle}>{pendingCount}</span>
              </div>
              <div style={metricRowStyle}>
                <span style={metricLabelStyle}>Active Conflicts:</span>
                <span style={conflictCount > 0 ? { ...metricValueStyle, color: "#c2410c" } : metricValueStyle}>
                  {conflictCount}
                </span>
              </div>
              <div style={metricRowStyle}>
                <span style={metricLabelStyle}>Last Synchronized:</span>
                <span style={metricValueStyle}>
                  {lastSyncAt ? lastSyncAt.toLocaleTimeString() : "Never"}
                </span>
              </div>
            </div>

            {/* Sanitized Error Banner (if error state) */}
            {error && (
              <div style={errorBannerStyle} role="alert">
                <p style={{ margin: "0 0 6px 0", fontSize: "12px", color: "#991b1b" }}>
                  {error}
                </p>
                <button
                  type="button"
                  onClick={clearError}
                  style={dismissErrorButtonStyle}
                >
                  Dismiss error
                </button>
              </div>
            )}

            {/* Actions */}
            <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: 12 }}>
              {conflictCount > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    setIsPopoverOpen(false);
                    const firstConflict = activeConflicts[0];
                    if (firstConflict) {
                      openModal(firstConflict.conflict_id);
                    }
                  }}
                  style={resolveConflictPopoverButtonStyle}
                  className="zk-resolve-conflicts-button"
                  data-testid="resolve-conflicts-popover-button"
                >
                  Resolve Conflicts {`(${conflictCount})`}
                </button>
              )}

              <button
                type="button"
                onClick={() => syncNow().catch(() => {})}
                disabled={isSyncing || !isOnline}
                style={{
                  ...primaryActionButtonStyle,
                  opacity: isSyncing || !isOnline ? 0.6 : 1,
                  cursor: isSyncing || !isOnline ? "not-allowed" : "pointer",
                }}
                className="zk-sync-now-button"
              >
                {isSyncing ? "Syncing changes..." : "Sync Now"}
              </button>

              <button
                type="button"
                onClick={() => setOfflineMode(isOnline)}
                style={secondaryActionButtonStyle}
                className="zk-toggle-offline-button"
              >
                {isOnline ? "Switch to Offline Mode" : "Switch to Online Mode"}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

// Styles
const badgeCountStyle: React.CSSProperties = {
  fontSize: "11px",
  opacity: 0.85,
};

const backdropOverlayStyle: React.CSSProperties = {
  position: "fixed",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  zIndex: 40,
};

const popoverCardStyle: React.CSSProperties = {
  position: "absolute",
  top: "calc(100% + 6px)",
  right: 0,
  width: "280px",
  backgroundColor: "#ffffff",
  borderRadius: "8px",
  boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)",
  border: "1px solid #e5e7eb",
  padding: "16px",
  zIndex: 50,
  boxSizing: "border-box",
};

const closeButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#9ca3af",
  fontSize: "16px",
  cursor: "pointer",
  padding: 0,
};

const metricsContainerStyle: React.CSSProperties = {
  backgroundColor: "#f9fafb",
  borderRadius: "6px",
  padding: "10px",
  marginBottom: "12px",
  border: "1px solid #f3f4f6",
};

const metricRowStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  fontSize: "12px",
  lineHeight: 1.6,
};

const metricLabelStyle: React.CSSProperties = {
  color: "#6b7280",
};

const metricValueStyle: React.CSSProperties = {
  fontWeight: 600,
  color: "#111827",
};

const errorBannerStyle: React.CSSProperties = {
  backgroundColor: "#fef2f2",
  border: "1px solid #fecaca",
  borderRadius: "6px",
  padding: "8px 10px",
  marginBottom: "12px",
};

const dismissErrorButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#b91c1c",
  fontSize: "11px",
  cursor: "pointer",
  textDecoration: "underline",
  padding: 0,
};

const primaryActionButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px",
  backgroundColor: "#2563eb",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
};

const secondaryActionButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "6px",
  backgroundColor: "#f3f4f6",
  color: "#4b5563",
  border: "1px solid #d1d5db",
  borderRadius: "6px",
  fontSize: "12px",
  cursor: "pointer",
};

const resolveConflictPopoverButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "7px",
  backgroundColor: "#fff7ed",
  color: "#c2410c",
  border: "1px solid #fed7aa",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};
