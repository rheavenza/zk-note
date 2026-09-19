/**
 * Device Management Modal Component (ZK-075).
 *
 * Requirements & Security Invariants:
 * - Lists authorized devices and active sessions for the account.
 * - Allows revoking specific devices and terminating their active sessions.
 * - Current device is clearly badged.
 * - Revoking current device terminates local session.
 * - SEC-001 / SEC-002: Completely decoupled from vault keys and note ciphertext.
 */

import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext.js";
import { DeviceInfo } from "../auth/webauthn.js";

export interface DeviceManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DeviceManagementModal: React.FC<DeviceManagementModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { session, listDevices, revokeDevice } = useAuth();

  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [confirmDeviceId, setConfirmDeviceId] = useState<string | null>(null);

  const fetchDevices = useCallback(async () => {
    if (!session?.token) return;
    setIsLoading(true);
    setActionError(null);
    try {
      const list = await listDevices();
      setDevices(list);
    } catch (err: any) {
      setActionError(err?.message || "Failed to load device list.");
    } finally {
      setIsLoading(false);
    }
  }, [session?.token, listDevices]);

  useEffect(() => {
    if (isOpen) {
      setSuccessMessage(null);
      setActionError(null);
      setConfirmDeviceId(null);
      fetchDevices();
    }
  }, [isOpen, fetchDevices]);

  if (!isOpen) return null;

  const handleRevoke = async (deviceId: string) => {
    setRevokingId(deviceId);
    setActionError(null);
    setSuccessMessage(null);
    try {
      const res = await revokeDevice(deviceId);
      setSuccessMessage(`Device successfully revoked (${res.revokedSessionsCount} session(s) invalidated).`);
      setConfirmDeviceId(null);
      // Refresh list
      await fetchDevices();
    } catch (err: any) {
      setActionError(err?.message || "Failed to revoke device.");
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div
      style={overlayStyle}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="device-modal-title"
      data-testid="device-management-modal"
    >
      <div style={modalContainerStyle}>
        {/* Header */}
        <div style={headerStyle}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "22px" }}>📱</span>
            <h2 id="device-modal-title" style={{ margin: 0, fontSize: "18px", fontWeight: 700, color: "#111827" }}>
              Authorized Devices & Sessions
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={closeButtonStyle}
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Security Notice */}
        <div style={noticeStyle}>
          <p style={{ margin: 0, fontSize: "13px", color: "#374151", lineHeight: 1.5 }}>
            <strong>Zero-Knowledge Device Management:</strong> Devices registered to your account can
            synchronize encrypted note objects. Revoking a device immediately invalidates its active sessions.
            Stored note ciphertext remains protected by your client-side Vault Key.
          </p>
        </div>

        {/* Feedback Banners */}
        {actionError && (
          <div style={errorBannerStyle} role="alert">
            <span>⚠️ {actionError}</span>
            <button
              type="button"
              onClick={fetchDevices}
              style={retryButtonStyle}
            >
              Retry
            </button>
          </div>
        )}

        {successMessage && (
          <div style={successBannerStyle} role="status">
            <span>✅ {successMessage}</span>
          </div>
        )}

        {/* Device List Body */}
        <div style={contentBodyStyle}>
          {!session?.token ? (
            <div style={{ padding: "24px", textAlign: "center", color: "#6b7280" }}>
              You must be logged in to view and manage registered devices.
            </div>
          ) : isLoading && devices.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", color: "#6b7280" }}>
              Loading authorized devices...
            </div>
          ) : devices.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", color: "#6b7280" }}>
              No registered devices found.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {devices.map((device) => {
                const isCurrent = device.deviceId === session.deviceId;
                const isRevoked = device.isRevoked;
                const isConfirming = confirmDeviceId === device.deviceId;
                const isProcessing = revokingId === device.deviceId;

                return (
                  <div
                    key={device.deviceId}
                    style={{
                      ...deviceCardStyle,
                      borderColor: isRevoked ? "#e5e7eb" : isCurrent ? "#3b82f6" : "#d1d5db",
                      backgroundColor: isRevoked ? "#f9fafb" : "#ffffff",
                    }}
                    data-testid={`device-card-${device.deviceId}`}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                        <span style={{ fontWeight: 600, fontSize: "14px", color: isRevoked ? "#6b7280" : "#111827" }}>
                          {device.displayName || "Unnamed Device"}
                        </span>
                        {isCurrent && (
                          <span style={currentBadgeStyle} data-testid="current-device-badge">
                            This Device
                          </span>
                        )}
                        <span
                          style={{
                            ...statusBadgeStyle,
                            backgroundColor: isRevoked ? "#fee2e2" : "#dcfce7",
                            color: isRevoked ? "#991b1b" : "#166534",
                          }}
                        >
                          {isRevoked ? "Revoked" : "Active"}
                        </span>
                      </div>

                      <div style={{ marginTop: "4px", fontSize: "12px", fontFamily: "monospace", color: "#4b5563" }}>
                        ID: {device.deviceId}
                      </div>

                      <div style={{ marginTop: "6px", fontSize: "12px", color: "#6b7280", display: "flex", gap: "16px", flexWrap: "wrap" }}>
                        <span>Registered: {formatTimestamp(device.createdAt)}</span>
                        {device.lastSeen && <span>Last seen: {formatTimestamp(device.lastSeen)}</span>}
                        {device.revokedAt && <span style={{ color: "#dc2626" }}>Revoked at: {formatTimestamp(device.revokedAt)}</span>}
                      </div>
                    </div>

                    {/* Action button */}
                    {!isRevoked && (
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        {isConfirming ? (
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <button
                              type="button"
                              onClick={() => handleRevoke(device.deviceId)}
                              disabled={isProcessing}
                              style={confirmRevokeButtonStyle}
                              data-testid={`confirm-revoke-${device.deviceId}`}
                            >
                              {isProcessing ? "Revoking..." : "Confirm Revoke"}
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDeviceId(null)}
                              disabled={isProcessing}
                              style={cancelButtonStyle}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setConfirmDeviceId(device.deviceId)}
                            disabled={isProcessing}
                            style={revokeButtonStyle}
                            data-testid={`revoke-btn-${device.deviceId}`}
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={footerStyle}>
          <button
            type="button"
            onClick={fetchDevices}
            disabled={isLoading || !session?.token}
            style={refreshButtonStyle}
          >
            🔄 Refresh List
          </button>
          <button
            type="button"
            onClick={onClose}
            style={doneButtonStyle}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  } catch {
    return ts;
  }
}

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
  zIndex: 1000,
  padding: "16px",
};

const modalContainerStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  borderRadius: "10px",
  width: "100%",
  maxWidth: "680px",
  maxHeight: "85vh",
  display: "flex",
  flexDirection: "column",
  boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
  overflow: "hidden",
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
  fontSize: "18px",
  cursor: "pointer",
  color: "#6b7280",
  padding: "4px 8px",
  borderRadius: "4px",
};

const noticeStyle: React.CSSProperties = {
  backgroundColor: "#f3f4f6",
  padding: "12px 20px",
  borderBottom: "1px solid #e5e7eb",
};

const errorBannerStyle: React.CSSProperties = {
  backgroundColor: "#fee2e2",
  color: "#991b1b",
  padding: "10px 20px",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  fontSize: "13px",
  borderBottom: "1px solid #fca5a5",
};

const retryButtonStyle: React.CSSProperties = {
  padding: "3px 8px",
  fontSize: "12px",
  backgroundColor: "#ffffff",
  border: "1px solid #dc2626",
  borderRadius: "4px",
  color: "#dc2626",
  cursor: "pointer",
};

const successBannerStyle: React.CSSProperties = {
  backgroundColor: "#ecfdf5",
  color: "#065f46",
  padding: "10px 20px",
  fontSize: "13px",
  borderBottom: "1px solid #a7f3d0",
};

const contentBodyStyle: React.CSSProperties = {
  padding: "20px",
  overflowY: "auto",
  flex: 1,
};

const deviceCardStyle: React.CSSProperties = {
  border: "1px solid #d1d5db",
  borderRadius: "8px",
  padding: "14px 16px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "16px",
};

const currentBadgeStyle: React.CSSProperties = {
  fontSize: "11px",
  fontWeight: 600,
  backgroundColor: "#dbeafe",
  color: "#1e40af",
  padding: "2px 6px",
  borderRadius: "4px",
};

const statusBadgeStyle: React.CSSProperties = {
  fontSize: "11px",
  fontWeight: 600,
  padding: "2px 6px",
  borderRadius: "4px",
};

const revokeButtonStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  border: "1px solid #dc2626",
  color: "#dc2626",
  padding: "6px 12px",
  borderRadius: "6px",
  fontSize: "13px",
  fontWeight: 500,
  cursor: "pointer",
};

const confirmRevokeButtonStyle: React.CSSProperties = {
  backgroundColor: "#dc2626",
  border: "none",
  color: "#ffffff",
  padding: "6px 12px",
  borderRadius: "6px",
  fontSize: "13px",
  fontWeight: 600,
  cursor: "pointer",
};

const cancelButtonStyle: React.CSSProperties = {
  backgroundColor: "#f3f4f6",
  border: "1px solid #d1d5db",
  color: "#374151",
  padding: "6px 10px",
  borderRadius: "6px",
  fontSize: "13px",
  cursor: "pointer",
};

const footerStyle: React.CSSProperties = {
  padding: "12px 20px",
  borderTop: "1px solid #e5e7eb",
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  backgroundColor: "#fafafa",
};

const refreshButtonStyle: React.CSSProperties = {
  backgroundColor: "#ffffff",
  border: "1px solid #d1d5db",
  color: "#374151",
  padding: "6px 12px",
  borderRadius: "6px",
  fontSize: "13px",
  cursor: "pointer",
};

const doneButtonStyle: React.CSSProperties = {
  backgroundColor: "#2563eb",
  border: "none",
  color: "#ffffff",
  padding: "6px 16px",
  borderRadius: "6px",
  fontSize: "13px",
  fontWeight: 600,
  cursor: "pointer",
};
