/**
 * Unlock Screen Component (ZK-064).
 *
 * Requirements:
 * - Passphrase remains strictly client-side (no network transmission, masked inputs).
 * - Component state is wiped of sensitive passphrases immediately after submission.
 * - Clear visual states: UNINITIALIZED, LOCKED, UNLOCKING, UNLOCKED.
 * - Failures are sanitized and safe (no key leaks or cipher details).
 */

import React, { useState, useCallback } from "react";
import { useVault } from "../context/VaultContext.js";

export interface UnlockScreenProps {
  children?: React.ReactNode;
  onUnlocked?: () => void;
  title?: string;
}

export const UnlockScreen: React.FC<UnlockScreenProps> = ({
  children,
  onUnlocked,
  title,
}) => {
  const {
    vaultState,
    bootstrap,
    error: contextError,
    clearError,
    initVault,
    unlockWithPassphrase,
    unlockWithRecoveryKey,
    lock,
  } = useVault();

  const [mode, setMode] = useState<"passphrase" | "recoveryKey">("passphrase");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  // Post-initialization recovery key presentation state
  const [pendingRecoveryPhrase, setPendingRecoveryPhrase] = useState<string | null>(null);
  const [acknowledgedSaved, setAcknowledgedSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  // Active error (prefer local validation error, then sanitized context error)
  const activeError = validationError || contextError;

  const handleClearError = useCallback(() => {
    setValidationError(null);
    clearError();
  }, [clearError]);

  // Handler for creating a new vault
  const handleCreateVault = async (e: React.FormEvent) => {
    e.preventDefault();
    handleClearError();

    if (passphrase.length < 8) {
      setValidationError("Passphrase must be at least 8 characters long.");
      return;
    }

    if (passphrase !== confirmPassphrase) {
      setValidationError("Passphrases do not match.");
      return;
    }

    const enteredPassphrase = passphrase;
    // Clear input state immediately to avoid lingering in React memory
    setPassphrase("");
    setConfirmPassphrase("");

    try {
      const res = await initVault(enteredPassphrase);
      // Prompt user to save the recovery key
      setPendingRecoveryPhrase(res.recoveryPhrase);
      setAcknowledgedSaved(false);
      setCopied(false);
    } catch {
      // Error is sanitized and stored in context
    }
  };

  // Handler for unlocking with passphrase
  const handleUnlockPassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    handleClearError();

    if (!passphrase) {
      setValidationError("Please enter your passphrase.");
      return;
    }

    const enteredPassphrase = passphrase;
    // Wipe local input
    setPassphrase("");

    try {
      await unlockWithPassphrase(enteredPassphrase);
      onUnlocked?.();
    } catch {
      // Error handled by context
    }
  };

  // Handler for unlocking with recovery key
  const handleUnlockRecoveryKey = async (e: React.FormEvent) => {
    e.preventDefault();
    handleClearError();

    const trimmed = recoveryKeyInput.trim();
    if (!trimmed) {
      setValidationError("Please enter your recovery key.");
      return;
    }

    // Wipe local input
    setRecoveryKeyInput("");

    try {
      await unlockWithRecoveryKey(trimmed);
      onUnlocked?.();
    } catch {
      // Error handled by context
    }
  };

  // Handler when user confirms they've stored their recovery key
  const handleAcknowledgeRecovery = () => {
    setPendingRecoveryPhrase(null);
    setAcknowledgedSaved(false);
    setCopied(false);
    onUnlocked?.();
  };

  const handleCopyRecoveryPhrase = async () => {
    if (!pendingRecoveryPhrase) return;
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(pendingRecoveryPhrase);
        setCopied(true);
        setTimeout(() => setCopied(false), 3000);
      }
    } catch {
      // Clipboard write failed; user can still copy manually from text
    }
  };

  // 1. Post-initialization Recovery Key Screen
  if (pendingRecoveryPhrase) {
    return (
      <div className="zk-unlock-container" style={containerStyle}>
        <div className="zk-unlock-card" style={cardStyle}>
          <div style={{ textAlign: "center", marginBottom: 20 }}>
            <span style={iconBadgeStyle}>🔑</span>
            <h2 style={headingStyle}>Save Your Recovery Key</h2>
            <p style={subheadingStyle}>
              Your vault has been created. If you lose your passphrase, this recovery key is the
              <strong> ONLY</strong> way to recover your notes. Store it securely offline.
            </p>
          </div>

          <div
            className="zk-recovery-key-display"
            style={recoveryBoxStyle}
            aria-label="Recovery Key"
          >
            <code style={codeStyle}>{pendingRecoveryPhrase}</code>
          </div>

          <div style={{ display: "flex", justifyContent: "center", margin: "16px 0" }}>
            <button
              type="button"
              onClick={handleCopyRecoveryPhrase}
              style={secondaryButtonStyle}
              className="zk-copy-button"
            >
              {copied ? "✓ Copied to clipboard" : "Copy Recovery Key"}
            </button>
          </div>

          <label style={checkboxLabelStyle}>
            <input
              type="checkbox"
              checked={acknowledgedSaved}
              onChange={(e) => setAcknowledgedSaved(e.target.checked)}
              style={{ marginRight: 8, cursor: "pointer" }}
            />
            I have written down or safely saved this recovery key.
          </label>

          <button
            type="button"
            disabled={!acknowledgedSaved}
            onClick={handleAcknowledgeRecovery}
            style={{
              ...primaryButtonStyle,
              opacity: acknowledgedSaved ? 1 : 0.5,
              cursor: acknowledgedSaved ? "pointer" : "not-allowed",
            }}
            className="zk-continue-button"
          >
            Enter Vault
          </button>
        </div>
      </div>
    );
  }

  // 2. Unlocked state
  if (vaultState === "UNLOCKED") {
    if (children) {
      return <>{children}</>;
    }

    return (
      <div className="zk-unlock-container" style={containerStyle}>
        <div className="zk-unlock-card" style={cardStyle}>
          <div style={{ textAlign: "center" }}>
            <span style={{ ...iconBadgeStyle, background: "#e6f4ea", color: "#137333" }}>🔓</span>
            <h2 style={headingStyle}>Vault Unlocked</h2>
            <p style={subheadingStyle}>
              Your zero-knowledge notes are decrypted and held securely in memory.
            </p>
            <button
              type="button"
              onClick={lock}
              style={{ ...secondaryButtonStyle, marginTop: 24 }}
              className="zk-lock-button"
            >
              Lock Vault
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 3. Uninitialized state (Create Vault)
  if (vaultState === "UNINITIALIZED" || (vaultState === "UNLOCKING" && !bootstrap)) {
    const isBusy = vaultState === "UNLOCKING";
    return (
      <div className="zk-unlock-container" style={containerStyle}>
        <div className="zk-unlock-card" style={cardStyle}>
          <div style={{ textAlign: "center", marginBottom: 24 }}>
            <span style={iconBadgeStyle}>🔒</span>
            <h2 style={headingStyle}>{title || "Create Your Vault"}</h2>
            <p style={subheadingStyle}>
              Zero-knowledge end-to-end encryption. Your passphrase derives your keys locally;
              it is never transmitted to the server.
            </p>
          </div>

          {activeError && (
            <div role="alert" style={errorAlertStyle} className="zk-error-alert">
              <span>{activeError}</span>
              <button
                type="button"
                onClick={handleClearError}
                style={closeErrorButtonStyle}
                aria-label="Dismiss error"
              >
                ×
              </button>
            </div>
          )}

          <form onSubmit={handleCreateVault} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label htmlFor="create-passphrase" style={labelStyle}>
                Master Passphrase
              </label>
              <input
                id="create-passphrase"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
                value={passphrase}
                onChange={(e) => {
                  setPassphrase(e.target.value);
                  if (activeError) handleClearError();
                }}
                disabled={isBusy}
                placeholder="At least 8 characters"
                style={inputStyle}
                required
              />
            </div>

            <div>
              <label htmlFor="confirm-passphrase" style={labelStyle}>
                Confirm Passphrase
              </label>
              <input
                id="confirm-passphrase"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
                value={confirmPassphrase}
                onChange={(e) => {
                  setConfirmPassphrase(e.target.value);
                  if (activeError) handleClearError();
                }}
                disabled={isBusy}
                placeholder="Re-enter master passphrase"
                style={inputStyle}
                required
              />
            </div>

            <button
              type="submit"
              disabled={isBusy}
              style={{
                ...primaryButtonStyle,
                opacity: isBusy ? 0.6 : 1,
                cursor: isBusy ? "not-allowed" : "pointer",
              }}
              className="zk-submit-button"
            >
              {isBusy ? "Initializing Vault..." : "Create Vault"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // 4. Locked / Unlocking state (Unlock Vault)
  const isBusy = vaultState === "UNLOCKING";

  return (
    <div className="zk-unlock-container" style={containerStyle}>
      <div className="zk-unlock-card" style={cardStyle}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <span style={iconBadgeStyle}>🔒</span>
          <h2 style={headingStyle}>{title || "Unlock Vault"}</h2>
          <p style={subheadingStyle}>
            Enter your credentials to decrypt and access your zero-knowledge notes.
          </p>
        </div>

        {/* Tab switchers */}
        <div style={tabContainerStyle}>
          <button
            type="button"
            onClick={() => {
              setMode("passphrase");
              handleClearError();
            }}
            style={mode === "passphrase" ? activeTabStyle : tabStyle}
            disabled={isBusy}
          >
            Passphrase
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("recoveryKey");
              handleClearError();
            }}
            style={mode === "recoveryKey" ? activeTabStyle : tabStyle}
            disabled={isBusy}
          >
            Recovery Key
          </button>
        </div>

        {activeError && (
          <div role="alert" style={errorAlertStyle} className="zk-error-alert">
            <span>{activeError}</span>
            <button
              type="button"
              onClick={handleClearError}
              style={closeErrorButtonStyle}
              aria-label="Dismiss error"
            >
              ×
            </button>
          </div>
        )}

        {mode === "passphrase" ? (
          <form onSubmit={handleUnlockPassphrase} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label htmlFor="unlock-passphrase" style={labelStyle}>
                Master Passphrase
              </label>
              <input
                id="unlock-passphrase"
                type="password"
                autoComplete="current-password"
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
                value={passphrase}
                onChange={(e) => {
                  setPassphrase(e.target.value);
                  if (activeError) handleClearError();
                }}
                disabled={isBusy}
                placeholder="Enter your passphrase"
                style={inputStyle}
                required
              />
            </div>

            <button
              type="submit"
              disabled={isBusy}
              style={{
                ...primaryButtonStyle,
                opacity: isBusy ? 0.6 : 1,
                cursor: isBusy ? "not-allowed" : "pointer",
              }}
              className="zk-submit-button"
            >
              {isBusy ? "Unlocking Vault..." : "Unlock Vault"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleUnlockRecoveryKey} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label htmlFor="unlock-recovery-key" style={labelStyle}>
                Recovery Key
              </label>
              <input
                id="unlock-recovery-key"
                type="text"
                autoComplete="off"
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
                value={recoveryKeyInput}
                onChange={(e) => {
                  setRecoveryKeyInput(e.target.value);
                  if (activeError) handleClearError();
                }}
                disabled={isBusy}
                placeholder="XXXXXXXX-XXXXXXXX-..."
                style={{ ...inputStyle, fontFamily: "monospace", letterSpacing: "0.05em" }}
                required
              />
            </div>

            <button
              type="submit"
              disabled={isBusy}
              style={{
                ...primaryButtonStyle,
                opacity: isBusy ? 0.6 : 1,
                cursor: isBusy ? "not-allowed" : "pointer",
              }}
              className="zk-submit-button"
            >
              {isBusy ? "Verifying Recovery Key..." : "Unlock with Recovery Key"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

export interface LockVaultButtonProps {
  className?: string;
  style?: React.CSSProperties;
}

export const LockVaultButton: React.FC<LockVaultButtonProps> = ({ className, style }) => {
  const { vaultState, lock } = useVault();
  if (vaultState !== "UNLOCKED") return null;

  return (
    <button
      type="button"
      onClick={lock}
      className={className || "zk-lock-button"}
      style={{
        padding: "6px 14px",
        borderRadius: "6px",
        border: "1px solid #d1d5db",
        backgroundColor: "#ffffff",
        cursor: "pointer",
        fontSize: "14px",
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        ...style,
      }}
    >
      <span>🔒</span> Lock Vault
    </button>
  );
};

export interface VaultStatusBadgeProps {
  className?: string;
  style?: React.CSSProperties;
}

export const VaultStatusBadge: React.FC<VaultStatusBadgeProps> = ({ className, style }) => {
  const { vaultState } = useVault();

  let bg = "#f3f4f6";
  let text = "#4b5563";
  let label = "Checking...";

  switch (vaultState) {
    case "UNLOCKED":
      bg = "#dcfce7";
      text = "#166534";
      label = "Unlocked";
      break;
    case "LOCKED":
      bg = "#fee2e2";
      text = "#991b1b";
      label = "Locked";
      break;
    case "UNLOCKING":
      bg = "#fef3c7";
      text = "#92400e";
      label = "Unlocking...";
      break;
    case "UNINITIALIZED":
      bg = "#e0e7ff";
      text = "#3730a3";
      label = "Setup Needed";
      break;
  }

  return (
    <span
      className={className || "zk-status-badge"}
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: "9999px",
        fontSize: "12px",
        fontWeight: 600,
        backgroundColor: bg,
        color: text,
        ...style,
      }}
    >
      {label}
    </span>
  );
};

// Styles
const containerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: "100vh",
  padding: "16px",
  boxSizing: "border-box",
  backgroundColor: "#f9fafb",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
};

const cardStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: "440px",
  backgroundColor: "#ffffff",
  borderRadius: "12px",
  boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)",
  padding: "32px",
  boxSizing: "border-box",
};

const iconBadgeStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: "48px",
  height: "48px",
  borderRadius: "50%",
  backgroundColor: "#f3f4f6",
  fontSize: "24px",
  marginBottom: "12px",
};

const headingStyle: React.CSSProperties = {
  margin: "0 0 8px 0",
  fontSize: "22px",
  fontWeight: 700,
  color: "#111827",
};

const subheadingStyle: React.CSSProperties = {
  margin: 0,
  fontSize: "14px",
  color: "#6b7280",
  lineHeight: 1.5,
};

const tabContainerStyle: React.CSSProperties = {
  display: "flex",
  borderBottom: "1px solid #e5e7eb",
  marginBottom: "20px",
};

const tabStyle: React.CSSProperties = {
  flex: 1,
  padding: "10px",
  background: "none",
  border: "none",
  borderBottom: "2px solid transparent",
  color: "#6b7280",
  fontWeight: 500,
  fontSize: "14px",
  cursor: "pointer",
};

const activeTabStyle: React.CSSProperties = {
  ...tabStyle,
  color: "#2563eb",
  borderBottom: "2px solid #2563eb",
  fontWeight: 600,
};

const labelStyle: React.CSSProperties = {
  display: "block",
  marginBottom: "6px",
  fontSize: "13px",
  fontWeight: 600,
  color: "#374151",
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  border: "1px solid #d1d5db",
  borderRadius: "8px",
  fontSize: "14px",
  color: "#111827",
  outline: "none",
  boxSizing: "border-box",
};

const primaryButtonStyle: React.CSSProperties = {
  width: "100%",
  padding: "12px",
  backgroundColor: "#2563eb",
  color: "#ffffff",
  border: "none",
  borderRadius: "8px",
  fontSize: "15px",
  fontWeight: 600,
  cursor: "pointer",
  transition: "background-color 0.2s",
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: "10px 18px",
  backgroundColor: "#f3f4f6",
  color: "#374151",
  border: "1px solid #d1d5db",
  borderRadius: "8px",
  fontSize: "14px",
  fontWeight: 500,
  cursor: "pointer",
};

const errorAlertStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "10px 14px",
  backgroundColor: "#fef2f2",
  border: "1px solid #fecaca",
  borderRadius: "8px",
  color: "#b91c1c",
  fontSize: "13px",
  marginBottom: "16px",
};

const closeErrorButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#b91c1c",
  fontSize: "16px",
  cursor: "pointer",
  padding: "0 4px",
};

const recoveryBoxStyle: React.CSSProperties = {
  backgroundColor: "#f8fafc",
  border: "1px solid #cbd5e1",
  borderRadius: "8px",
  padding: "16px",
  textAlign: "center",
  wordBreak: "break-all",
  margin: "16px 0",
};

const codeStyle: React.CSSProperties = {
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  fontSize: "14px",
  color: "#0f172a",
  fontWeight: 600,
  lineHeight: 1.6,
};

const checkboxLabelStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  fontSize: "13px",
  color: "#4b5563",
  marginBottom: "20px",
  cursor: "pointer",
};
