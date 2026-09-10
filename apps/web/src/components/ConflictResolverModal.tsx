/**
 * Conflict Resolver Modal Component (ZK-068).
 *
 * Requirements:
 * - Compare local and remote note versions side-by-side.
 * - Use merge candidate (one-click 3-way merge).
 * - Manual resolution (interactive editor for merged title, body, tags).
 * - Preserve-both action (keeps remote and creates a duplicate local note).
 * - Zero-knowledge security (SEC-001, SEC-003, SEC-009):
 *   - Plaintext is never sent to the server.
 *   - Closes and scrubs view when vault locks.
 */

import React, { useState, useEffect } from "react";
import { useConflict, ConflictDetails } from "../context/ConflictContext.js";

export interface ConflictResolverModalProps {
  className?: string;
  conflictId?: string;
  onClose?: () => void;
}

export const ConflictResolverModal: React.FC<ConflictResolverModalProps> = ({
  className,
  conflictId: propConflictId,
  onClose,
}) => {
  const {
    isModalOpen,
    selectedConflictId,
    closeModal,
    loadConflictDetails,
    resolveKeepLocal,
    resolveKeepRemote,
    resolveWithCandidate,
    resolveManualMerge,
    resolvePreserveBoth,
  } = useConflict();

  const activeId = propConflictId || selectedConflictId;
  const isOpen = propConflictId ? true : isModalOpen && activeId !== null;

  const [details, setDetails] = useState<ConflictDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"compare" | "editor">("compare");

  // Manual editor state
  const [mergedTitle, setMergedTitle] = useState("");
  const [mergedBody, setMergedBody] = useState("");
  const [mergedTagsText, setMergedTagsText] = useState("");
  const [isResolving, setIsResolving] = useState(false);

  useEffect(() => {
    if (isOpen && activeId) {
      setLoading(true);
      setErrorMessage(null);
      loadConflictDetails(activeId)
        .then((d) => {
          setDetails(d);
          setMergedTitle(d.candidateNote.title);
          setMergedBody(d.candidateNote.body);
          setMergedTagsText(d.candidateNote.tags.join(", "));
          setLoading(false);
        })
        .catch((err) => {
          setErrorMessage(err instanceof Error ? err.message : String(err));
          setLoading(false);
        });
    } else {
      setDetails(null);
      setActiveTab("compare");
    }
  }, [isOpen, activeId]);

  if (!isOpen || !activeId) {
    return null;
  }

  const handleClose = () => {
    closeModal();
    onClose?.();
  };

  const handleKeepLocal = async () => {
    if (!activeId || isResolving) return;
    setIsResolving(true);
    try {
      await resolveKeepLocal(activeId);
      handleClose();
    } catch (err: any) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsResolving(false);
    }
  };

  const handleKeepRemote = async () => {
    if (!activeId || isResolving) return;
    setIsResolving(true);
    try {
      await resolveKeepRemote(activeId);
      handleClose();
    } catch (err: any) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsResolving(false);
    }
  };

  const handleUseCandidate = async () => {
    if (!activeId || isResolving) return;
    setIsResolving(true);
    try {
      await resolveWithCandidate(activeId);
      handleClose();
    } catch (err: any) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsResolving(false);
    }
  };

  const handlePreserveBoth = async () => {
    if (!activeId || isResolving) return;
    setIsResolving(true);
    try {
      await resolvePreserveBoth(activeId);
      handleClose();
    } catch (err: any) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsResolving(false);
    }
  };

  const handleSaveManualMerge = async () => {
    if (!activeId || isResolving) return;
    setIsResolving(true);
    try {
      const tags = mergedTagsText
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);

      await resolveManualMerge(activeId, {
        title: mergedTitle,
        body: mergedBody,
        tags,
      });
      handleClose();
    } catch (err: any) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsResolving(false);
    }
  };

  return (
    <div
      style={overlayStyle}
      className={className || "zk-conflict-modal-overlay"}
      data-testid="conflict-modal-overlay"
    >
      <div
        style={modalCardStyle}
        className="zk-conflict-modal-card"
        data-testid="conflict-modal"
      >
        {/* Header */}
        <div style={headerStyle}>
          <div>
            <h3 style={{ margin: 0, fontSize: "18px", fontWeight: 700, color: "#111827" }}>
              ⚠️ Resolve Synchronization Conflict
            </h3>
            <span style={{ fontSize: "12px", color: "#6b7280" }}>
              Object ID: <code>{details?.record.object_id || activeId}</code>
            </span>
          </div>
          <button
            type="button"
            onClick={handleClose}
            style={closeButtonStyle}
            aria-label="Close conflict resolver"
            data-testid="conflict-close-button"
          >
            ×
          </button>
        </div>

        {/* Error Banner */}
        {errorMessage && (
          <div style={errorBannerStyle} role="alert" data-testid="conflict-error-banner">
            <span style={{ fontSize: "13px", color: "#991b1b" }}>{errorMessage}</span>
          </div>
        )}

        {/* Tab Navigation */}
        <div style={tabBarStyle}>
          <button
            type="button"
            onClick={() => setActiveTab("compare")}
            style={activeTab === "compare" ? activeTabButtonStyle : tabButtonStyle}
            data-testid="tab-compare"
          >
            Compare (Side-by-Side)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("editor")}
            style={activeTab === "editor" ? activeTabButtonStyle : tabButtonStyle}
            data-testid="tab-editor"
          >
            Manual Merge Editor
          </button>
        </div>

        {/* Content Body */}
        <div style={contentBodyStyle}>
          {loading && (
            <div style={loadingContainerStyle}>
              <span>Decrypting conflicting envelopes locally...</span>
            </div>
          )}

          {!loading && details && activeTab === "compare" && (
            <div style={comparisonContainerStyle} data-testid="conflict-comparison-view">
              {/* Local Column */}
              <div style={columnStyle}>
                <div style={columnHeaderLocalStyle}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <h4 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "#15803d" }}>
                      Local Version (Your edits)
                    </h4>
                    <span style={revisionBadgeStyle}>Rev {details.record.base_revision}</span>
                  </div>
                </div>
                <div style={columnBodyStyle}>
                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Title:</label>
                    <div style={fieldValueStyle} data-testid="local-title">
                      {details.localNote.title || "(Untitled)"}
                    </div>
                  </div>

                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Tags:</label>
                    <div style={tagsContainerStyle} data-testid="local-tags">
                      {details.localNote.tags.length > 0 ? (
                        details.localNote.tags.map((t) => (
                          <span key={t} style={tagPillStyle}>
                            #{t}
                          </span>
                        ))
                      ) : (
                        <span style={{ fontSize: "12px", color: "#9ca3af" }}>None</span>
                      )}
                    </div>
                  </div>

                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Body:</label>
                    <pre style={preBodyStyle} data-testid="local-body">
                      {details.localNote.body || "(Empty)"}
                    </pre>
                  </div>
                </div>
                <div style={columnFooterStyle}>
                  <button
                    type="button"
                    onClick={handleKeepLocal}
                    disabled={isResolving}
                    style={primaryGreenButtonStyle}
                    data-testid="resolve-keep-local"
                  >
                    Keep Local Version
                  </button>
                </div>
              </div>

              {/* Remote Column */}
              <div style={columnStyle}>
                <div style={columnHeaderRemoteStyle}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <h4 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "#1d4ed8" }}>
                      Remote Version (Server)
                    </h4>
                    <span style={revisionBadgeStyle}>Rev {details.record.remote_revision}</span>
                  </div>
                </div>
                <div style={columnBodyStyle}>
                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Title:</label>
                    <div style={fieldValueStyle} data-testid="remote-title">
                      {details.remoteNote.title || "(Untitled)"}
                    </div>
                  </div>

                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Tags:</label>
                    <div style={tagsContainerStyle} data-testid="remote-tags">
                      {details.remoteNote.tags.length > 0 ? (
                        details.remoteNote.tags.map((t) => (
                          <span key={t} style={tagPillStyle}>
                            #{t}
                          </span>
                        ))
                      ) : (
                        <span style={{ fontSize: "12px", color: "#9ca3af" }}>None</span>
                      )}
                    </div>
                  </div>

                  <div style={fieldGroupStyle}>
                    <label style={fieldLabelStyle}>Body:</label>
                    <pre style={preBodyStyle} data-testid="remote-body">
                      {details.remoteNote.body || "(Empty)"}
                    </pre>
                  </div>
                </div>
                <div style={columnFooterStyle}>
                  <button
                    type="button"
                    onClick={handleKeepRemote}
                    disabled={isResolving}
                    style={primaryBlueButtonStyle}
                    data-testid="resolve-keep-remote"
                  >
                    Keep Remote Version
                  </button>
                </div>
              </div>
            </div>
          )}

          {!loading && details && activeTab === "editor" && (
            <div style={editorContainerStyle} data-testid="conflict-editor-view">
              {details.hasBodyConflict && (
                <div style={conflictNoticeStyle}>
                  <strong>⚠️ Overlapping body edits detected.</strong> Standard diff3 markers (
                  <code>&lt;&lt;&lt;&lt;&lt;&lt;&lt; LOCAL</code>, <code>=======</code>,{" "}
                  <code>&gt;&gt;&gt;&gt;&gt;&gt;&gt; REMOTE</code>) are included in the editor
                  below for manual resolution.
                </div>
              )}

              <div style={{ marginBottom: 12 }}>
                <label style={fieldLabelStyle}>Merged Title:</label>
                <input
                  type="text"
                  value={mergedTitle}
                  onChange={(e) => setMergedTitle(e.target.value)}
                  style={textInputStyle}
                  data-testid="manual-merged-title"
                />
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={fieldLabelStyle}>Merged Tags (comma-separated):</label>
                <input
                  type="text"
                  value={mergedTagsText}
                  onChange={(e) => setMergedTagsText(e.target.value)}
                  style={textInputStyle}
                  data-testid="manual-merged-tags"
                />
              </div>

              <div style={{ marginBottom: 16, flex: 1, display: "flex", flexDirection: "column" }}>
                <label style={fieldLabelStyle}>Merged Body (Markdown):</label>
                <textarea
                  value={mergedBody}
                  onChange={(e) => setMergedBody(e.target.value)}
                  style={textAreaStyle}
                  data-testid="manual-merged-body"
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 12 }}>
                <button
                  type="button"
                  onClick={() => {
                    setMergedTitle(details.candidateNote.title);
                    setMergedBody(details.candidateNote.body);
                    setMergedTagsText(details.candidateNote.tags.join(", "));
                  }}
                  style={secondaryButtonStyle}
                  data-testid="reset-candidate-button"
                >
                  Reset to 3-Way Candidate
                </button>
                <button
                  type="button"
                  onClick={handleSaveManualMerge}
                  disabled={isResolving}
                  style={primaryActionButtonStyle}
                  data-testid="resolve-save-merge"
                >
                  {isResolving ? "Encrypting & Resolving..." : "Save Merged Note"}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Global Action Footer */}
        <div style={footerStyle}>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}>
            <button
              type="button"
              onClick={handleUseCandidate}
              disabled={isResolving || loading}
              style={candidateActionButtonStyle}
              data-testid="resolve-candidate"
              title="Accepts clean automated 3-way merge candidate"
            >
              Use Merge Candidate
            </button>
            <button
              type="button"
              onClick={handlePreserveBoth}
              disabled={isResolving || loading}
              style={preserveBothButtonStyle}
              data-testid="resolve-preserve-both"
              title="Keeps remote version and duplicates local note as a separate copy"
            >
              Preserve Both (Duplicate Local)
            </button>
          </div>

          <button
            type="button"
            onClick={handleClose}
            style={secondaryButtonStyle}
            data-testid="conflict-cancel-button"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

// Styles
const overlayStyle: React.CSSProperties = {
  position: "fixed",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: "rgba(0, 0, 0, 0.5)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 60,
  padding: "20px",
  boxSizing: "border-box",
};

const modalCardStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  borderRadius: "10px",
  width: "100%",
  maxWidth: "960px",
  maxHeight: "90vh",
  display: "flex",
  flexDirection: "column",
  boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
  overflow: "hidden",
};

const headerStyle: React.CSSProperties = {
  padding: "16px 20px",
  borderBottom: "1px solid #e5e7eb",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
};

const closeButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  fontSize: "24px",
  color: "#9ca3af",
  cursor: "pointer",
  lineHeight: 1,
};

const tabBarStyle: React.CSSProperties = {
  display: "flex",
  borderBottom: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
  padding: "0 20px",
};

const tabButtonStyle: React.CSSProperties = {
  padding: "10px 16px",
  border: "none",
  background: "none",
  fontSize: "13px",
  fontWeight: 600,
  color: "#6b7280",
  cursor: "pointer",
  borderBottom: "2px solid transparent",
};

const activeTabButtonStyle: React.CSSProperties = {
  ...tabButtonStyle,
  color: "#2563eb",
  borderBottom: "2px solid #2563eb",
};

const contentBodyStyle: React.CSSProperties = {
  flex: 1,
  overflowY: "auto",
  padding: "20px",
  minHeight: "360px",
};

const comparisonContainerStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: "20px",
  height: "100%",
};

const columnStyle: React.CSSProperties = {
  border: "1px solid #e5e7eb",
  borderRadius: "8px",
  display: "flex",
  flexDirection: "column",
  backgroundColor: "#ffffff",
  overflow: "hidden",
};

const columnHeaderLocalStyle: React.CSSProperties = {
  backgroundColor: "#f0fdf4",
  borderBottom: "1px solid #bbf7d0",
  padding: "10px 14px",
};

const columnHeaderRemoteStyle: React.CSSProperties = {
  backgroundColor: "#eff6ff",
  borderBottom: "1px solid #bfdbfe",
  padding: "10px 14px",
};

const revisionBadgeStyle: React.CSSProperties = {
  fontSize: "11px",
  fontWeight: 600,
  padding: "2px 6px",
  borderRadius: "4px",
  backgroundColor: "rgba(0, 0, 0, 0.06)",
  color: "#4b5563",
};

const columnBodyStyle: React.CSSProperties = {
  flex: 1,
  padding: "14px",
  overflowY: "auto",
};

const columnFooterStyle: React.CSSProperties = {
  padding: "12px 14px",
  borderTop: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
};

const fieldGroupStyle: React.CSSProperties = {
  marginBottom: "12px",
};

const fieldLabelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "12px",
  fontWeight: 600,
  color: "#4b5563",
  marginBottom: "4px",
};

const fieldValueStyle: React.CSSProperties = {
  fontSize: "14px",
  fontWeight: 600,
  color: "#111827",
};

const tagsContainerStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: "6px",
};

const tagPillStyle: React.CSSProperties = {
  fontSize: "11px",
  fontWeight: 600,
  padding: "2px 6px",
  borderRadius: "4px",
  backgroundColor: "#f3f4f6",
  color: "#374151",
};

const preBodyStyle: React.CSSProperties = {
  fontSize: "12px",
  fontFamily: "monospace",
  backgroundColor: "#f9fafb",
  border: "1px solid #f3f4f6",
  borderRadius: "6px",
  padding: "8px",
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  maxHeight: "220px",
  overflowY: "auto",
  margin: 0,
};

const primaryGreenButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  backgroundColor: "#15803d",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

const primaryBlueButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  backgroundColor: "#2563eb",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

const editorContainerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  height: "100%",
};

const conflictNoticeStyle: React.CSSProperties = {
  backgroundColor: "#fff7ed",
  border: "1px solid #fed7aa",
  borderRadius: "6px",
  padding: "10px 14px",
  fontSize: "12px",
  color: "#9a3412",
  marginBottom: "14px",
};

const textInputStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  borderRadius: "6px",
  border: "1px solid #d1d5db",
  fontSize: "13px",
  boxSizing: "border-box",
};

const textAreaStyle: React.CSSProperties = {
  width: "100%",
  minHeight: "200px",
  padding: "10px",
  borderRadius: "6px",
  border: "1px solid #d1d5db",
  fontFamily: "monospace",
  fontSize: "12px",
  lineHeight: 1.5,
  boxSizing: "border-box",
  resize: "vertical",
};

const footerStyle: React.CSSProperties = {
  padding: "14px 20px",
  borderTop: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
};

const candidateActionButtonStyle: React.CSSProperties = {
  padding: "8px 14px",
  backgroundColor: "#059669",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

const preserveBothButtonStyle: React.CSSProperties = {
  padding: "8px 14px",
  backgroundColor: "#4f46e5",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: "8px 14px",
  backgroundColor: "#ffffff",
  color: "#4b5563",
  border: "1px solid #d1d5db",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 500,
  cursor: "pointer",
};

const primaryActionButtonStyle: React.CSSProperties = {
  padding: "8px 16px",
  backgroundColor: "#2563eb",
  color: "#ffffff",
  border: "none",
  borderRadius: "6px",
  fontSize: "12px",
  fontWeight: 600,
  cursor: "pointer",
};

const errorBannerStyle: React.CSSProperties = {
  backgroundColor: "#fef2f2",
  borderBottom: "1px solid #fecaca",
  padding: "8px 20px",
};

const loadingContainerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  height: "200px",
  color: "#6b7280",
  fontSize: "14px",
};
