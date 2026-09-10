/**
 * Security & Recovery Modal Component (ZK-073).
 *
 * Implements:
 * - Safe presentation of zero-knowledge recovery invariants.
 * - Prominent warning that the server cannot recover lost keys.
 * - In-vault passphrase change / rotation via rewrapPassphrase without touching note ciphertext.
 * - Offline security and recovery key storage recommendations.
 */

import React, { useState } from "react";
import { useVault } from "../context/VaultContext.js";

export interface SecurityRecoveryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SecurityRecoveryModal: React.FC<SecurityRecoveryModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { vaultState, rewrapPassphrase } = useVault();

  const [activeTab, setActiveTab] = useState<"overview" | "changePassphrase">("overview");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(
    null
  );

  if (!isOpen) return null;

  const handleChangePassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);

    if (newPassphrase.length < 8) {
      setFeedback({
        type: "error",
        message: "New passphrase must be at least 8 characters long.",
      });
      return;
    }

    if (newPassphrase !== confirmPassphrase) {
      setFeedback({
        type: "error",
        message: "Passphrases do not match.",
      });
      return;
    }

    const pass = newPassphrase;
    setNewPassphrase("");
    setConfirmPassphrase("");
    setIsSubmitting(true);

    try {
      await rewrapPassphrase(pass);
      setFeedback({
        type: "success",
        message: "Master passphrase successfully updated! Your existing recovery key remains valid.",
      });
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to update passphrase.",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      style={overlayStyle}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      data-testid="security-recovery-modal"
    >
      <div style={modalStyle} role="dialog" aria-modal="true" aria-labelledby="sec-modal-title">
        {/* Header */}
        <div style={headerStyle}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 20 }}>🛡️</span>
            <h2 id="sec-modal-title" style={{ margin: 0, fontSize: 18, fontWeight: 600, color: "#111827" }}>
              Security & Recovery
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={closeButtonStyle}
            aria-label="Close modal"
          >
            ×
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={tabContainerStyle}>
          <button
            type="button"
            onClick={() => {
              setActiveTab("overview");
              setFeedback(null);
            }}
            style={activeTab === "overview" ? activeTabStyle : tabStyle}
          >
            Security Guarantees
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab("changePassphrase");
              setFeedback(null);
            }}
            style={activeTab === "changePassphrase" ? activeTabStyle : tabStyle}
            disabled={vaultState !== "UNLOCKED"}
          >
            Change Passphrase
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: "16px 20px" }}>
          {feedback && (
            <div
              style={{
                ...feedbackAlertStyle,
                backgroundColor: feedback.type === "success" ? "#e6f4ea" : "#fce8e6",
                borderColor: feedback.type === "success" ? "#34a853" : "#ea4335",
                color: feedback.type === "success" ? "#137333" : "#c5221f",
              }}
            >
              {feedback.message}
            </div>
          )}

          {activeTab === "overview" ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {/* Critical Warning Alert */}
              <div style={warningBoxStyle}>
                <strong>⚠️ Zero-Knowledge Architecture Warning:</strong>
                <p style={{ margin: "4px 0 0 0", fontSize: 13, lineHeight: 1.4 }}>
                  The application server stores exclusively encrypted ciphertext envelopes. The
                  server DOES NOT have your passphrase, Vault Key, Note Keys, or plaintext note
                  contents. If you lose both your master passphrase and recovery key, data recovery is
                  <strong> mathematically impossible</strong>.
                </p>
              </div>

              <div style={sectionStyle}>
                <h3 style={sectionHeadingStyle}>🔑 Recovery Key Invariants</h3>
                <ul style={listStyle}>
                  <li>
                    <strong>Single Vault Key:</strong> Both your passphrase and Recovery Key unwrap
                    the identical master Vault Key.
                  </li>
                  <li>
                    <strong>Passphrase Rotation:</strong> Changing your passphrase re-wraps the
                    Vault Key under a new Key Encryption Key. Your existing recovery key remains
                    100% valid.
                  </li>
                  <li>
                    <strong>Tamper Proofing:</strong> Recovery keys include an embedded BLAKE2b
                    checksum to prevent typos and fail closed on corruption.
                  </li>
                </ul>
              </div>

              <div style={sectionStyle}>
                <h3 style={sectionHeadingStyle}>🔒 Safe Storage Recommendations</h3>
                <ul style={listStyle}>
                  <li>Store your recovery key in an offline password manager or safe deposit box.</li>
                  <li>Do not store recovery keys in unencrypted cloud documents or chat messages.</li>
                  <li>Never disclose your recovery key or master passphrase to anyone.</li>
                </ul>
              </div>
            </div>
          ) : (
            <form onSubmit={handleChangePassphrase} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <p style={{ fontSize: 13, color: "#4b5563", margin: 0 }}>
                Enter a new master passphrase to re-wrap your vault. Your note ciphertexts are
                preserved and your recovery key remains valid.
              </p>

              <div>
                <label htmlFor="modal-new-passphrase" style={labelStyle}>
                  New Master Passphrase
                </label>
                <input
                  id="modal-new-passphrase"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  value={newPassphrase}
                  onChange={(e) => setNewPassphrase(e.target.value)}
                  disabled={isSubmitting}
                  placeholder="Minimum 8 characters"
                  style={inputStyle}
                  required
                />
              </div>

              <div>
                <label htmlFor="modal-confirm-passphrase" style={labelStyle}>
                  Confirm New Passphrase
                </label>
                <input
                  id="modal-confirm-passphrase"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  value={confirmPassphrase}
                  onChange={(e) => setConfirmPassphrase(e.target.value)}
                  disabled={isSubmitting}
                  placeholder="Re-enter new passphrase"
                  style={inputStyle}
                  required
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 8 }}>
                <button
                  type="button"
                  onClick={onClose}
                  style={secondaryButtonStyle}
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={primaryButtonStyle}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? "Updating..." : "Update Passphrase"}
                </button>
              </div>
            </form>
          )}
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
  backgroundColor: "rgba(0, 0, 0, 0.45)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 1000,
  backdropFilter: "blur(2px)",
};

const modalStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  borderRadius: 8,
  width: "100%",
  maxWidth: 520,
  boxShadow: "0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04)",
  overflow: "hidden",
  fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
};

const headerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "16px 20px",
  borderBottom: "1px solid #e5e7eb",
};

const closeButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  fontSize: 22,
  cursor: "pointer",
  color: "#9ca3af",
  padding: 0,
  lineHeight: 1,
};

const tabContainerStyle: React.CSSProperties = {
  display: "flex",
  borderBottom: "1px solid #e5e7eb",
  backgroundColor: "#f9fafb",
};

const tabStyle: React.CSSProperties = {
  flex: 1,
  padding: "10px 16px",
  background: "none",
  border: "none",
  borderBottom: "2px solid transparent",
  color: "#6b7280",
  fontSize: 13,
  fontWeight: 500,
  cursor: "pointer",
};

const activeTabStyle: React.CSSProperties = {
  ...tabStyle,
  color: "#1d4ed8",
  borderBottom: "2px solid #1d4ed8",
  backgroundColor: "#ffffff",
};

const warningBoxStyle: React.CSSProperties = {
  backgroundColor: "#fef3c7",
  border: "1px solid #f59e0b",
  borderRadius: 6,
  padding: "10px 14px",
  fontSize: 13,
  color: "#92400e",
};

const sectionStyle: React.CSSProperties = {
  backgroundColor: "#f9fafb",
  borderRadius: 6,
  padding: "10px 14px",
  border: "1px solid #e5e7eb",
};

const sectionHeadingStyle: React.CSSProperties = {
  margin: "0 0 6px 0",
  fontSize: 13,
  fontWeight: 600,
  color: "#111827",
};

const listStyle: React.CSSProperties = {
  margin: 0,
  paddingLeft: 18,
  fontSize: 12,
  color: "#4b5563",
  display: "flex",
  flexDirection: "column",
  gap: 4,
};

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: 13,
  fontWeight: 500,
  color: "#374151",
  marginBottom: 4,
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "8px 12px",
  fontSize: 14,
  border: "1px solid #d1d5db",
  borderRadius: 6,
  boxSizing: "border-box",
  outline: "none",
};

const primaryButtonStyle: React.CSSProperties = {
  backgroundColor: "#1a73e8",
  color: "#ffffff",
  padding: "8px 16px",
  fontSize: 13,
  fontWeight: 500,
  borderRadius: 6,
  border: "none",
  cursor: "pointer",
};

const secondaryButtonStyle: React.CSSProperties = {
  backgroundColor: "#f3f4f6",
  color: "#374151",
  padding: "8px 16px",
  fontSize: 13,
  fontWeight: 500,
  borderRadius: 6,
  border: "1px solid #d1d5db",
  cursor: "pointer",
};

const feedbackAlertStyle: React.CSSProperties = {
  padding: "8px 12px",
  borderRadius: 6,
  border: "1px solid",
  fontSize: 13,
  marginBottom: 12,
};
