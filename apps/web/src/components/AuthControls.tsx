import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext.js";
import { useVaultOptional } from "../context/VaultContext.js";
import { linkLocalVaultToAccount, restoreVaultFromAccount } from "../auth/vault-link.js";
import { normalizeServerOrigin } from "../auth/session.js";

export interface AuthControlsProps {
  initialOpen?: boolean;
}

export const AuthControls: React.FC<AuthControlsProps> = ({ initialOpen = false }) => {
  const auth = useAuth();
  const vault = useVaultOptional();
  const bootstrap = vault?.bootstrap ?? null;
  const vaultLink = vault?.vaultLink ?? null;

  const [username, setUsername] = useState("");
  const [open, setOpen] = useState(initialOpen);
  const [serverInput, setServerInput] = useState(auth.serverOrigin);
  const [serverError, setServerError] = useState<string | null>(null);
  const [isLinking, setIsLinking] = useState(false);
  const [isRestoring, setIsRestoring] = useState(false);
  const [linkError, setLinkError] = useState<string | null>(null);
  const [linkMessage, setLinkMessage] = useState<string | null>(null);

  const pageOrigin = typeof window !== "undefined" ? window.location.origin : auth.serverOrigin;
  const sameOrigin = pageOrigin === auth.serverOrigin;

  useEffect(() => { setServerInput(auth.serverOrigin); }, [auth.serverOrigin]);

  const state = auth.isOffline ? "Offline — local vault available" :
    auth.isAuthenticated ? `Signed in (${auth.session?.accountId})` :
      auth.isExpired ? "Session expired — sign in again" : "Local vault only — not signed in";

  const handleLinkVault = async () => {
    if (!auth.session || !bootstrap || !vault) return;
    setIsLinking(true);
    setLinkError(null);
    setLinkMessage(null);
    try {
      const res = await linkLocalVaultToAccount({
        serverOrigin: auth.serverOrigin,
        token: auth.session.token,
        accountId: auth.session.accountId,
        localBootstrap: bootstrap,
      });
      vault.setVaultLink(res.link);
      setLinkMessage("Vault successfully linked to this account.");
    } catch (err: any) {
      setLinkError(err.message || "Failed to link vault.");
    } finally {
      setIsLinking(false);
    }
  };

  const handleRestoreVault = async () => {
    if (!auth.session || !vault) return;
    setIsRestoring(true);
    setLinkError(null);
    setLinkMessage(null);
    try {
      const res = await restoreVaultFromAccount({
        serverOrigin: auth.serverOrigin,
        token: auth.session.token,
        accountId: auth.session.accountId,
        localBootstrap: bootstrap,
      });
      vault.restoreFromRemote(res.bootstrap, res.link);
      setLinkMessage("Vault successfully restored. Enter your passphrase to unlock.");
    } catch (err: any) {
      setLinkError(err.message || "Failed to restore vault.");
    } finally {
      setIsRestoring(false);
    }
  };

  return <div style={{ position: "relative", fontSize: 12 }}>
    <button type="button" onClick={() => setOpen(!open)} aria-label="Account and server authentication" aria-expanded={open}>
      {state}
    </button>
    {open && <div role="group" aria-label="Account authentication" style={{ position: "absolute", right: 0, top: "100%", zIndex: 20, width: 280, padding: 12, background: "white", border: "1px solid #d1d5db", boxShadow: "0 4px 12px #0002" }}>
      <form onSubmit={event => {
        event.preventDefault();
        try { auth.setServerOrigin(serverInput); setServerError(null); }
        catch (error) { setServerError(error instanceof Error ? error.message : "Invalid server address."); }
      }}>
        <label>Server address
          <input type="text" inputMode="url" value={serverInput} onChange={event => setServerInput(event.target.value)} placeholder="https://notes.example.com" style={{ width: "100%", boxSizing: "border-box" }} />
        </label>
        <button type="submit" disabled={auth.isLoading}>Use server</button>
      </form>
      {serverError && <p role="alert">{serverError}</p>}
      {!sameOrigin && <p role="note">
        Account creation and passkey sign-in are unavailable with this server address. The web page and API must share the server’s HTTPS origin. An HTTP LAN address is for API access and cannot be used for passkeys. Open the web app on the server’s HTTPS hostname, then use that page’s address as the server address.
      </p>}
      {!sameOrigin && <button type="button" onClick={() => {
        auth.setServerOrigin(pageOrigin);
        setServerInput(pageOrigin);
        setServerError(null);
      }}>Use this page’s server</button>}
      {auth.isAuthenticated ? <div>
        <button type="button" disabled={auth.isLoading} onClick={() => void auth.logout().catch(() => {})}>Sign out</button>
        {vault && (bootstrap ? (
          <div style={{ marginTop: 10, padding: 8, background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 4 }}>
            {vaultLink ? (
              normalizeServerOrigin(vaultLink.serverOrigin) !== normalizeServerOrigin(auth.serverOrigin) ? (
                <p role="alert" style={{ margin: 0, color: "#b91c1c", fontWeight: 600 }}>
                  ⚠️ Vault linked to different server: {vaultLink.serverOrigin}
                </p>
              ) : vaultLink.accountId === auth.session?.accountId ? (
                <p style={{ margin: 0, color: "#166534", fontWeight: 600 }}>✓ Vault linked to this account</p>
              ) : (
                <p role="alert" style={{ margin: 0, color: "#b91c1c", fontWeight: 600 }}>
                  ⚠️ Vault linked to different account: {vaultLink.accountId}
                </p>
              )
            ) : (
              <div>
                <p style={{ margin: "0 0 6px 0", color: "#4b5563" }}>Vault is local-only (unlinked).</p>
                <button
                  type="button"
                  disabled={isLinking || auth.isOffline}
                  onClick={handleLinkVault}
                  className="zk-link-vault-button"
                >
                  {isLinking ? "Linking..." : "Link vault to account"}
                </button>
              </div>
            )}
          </div>
        ) : (
          <div style={{ marginTop: 10, padding: 8, background: "#f9fafb", border: "1px solid #e5e7eb", borderRadius: 4 }}>
            {vaultLink && (
              normalizeServerOrigin(vaultLink.serverOrigin) !== normalizeServerOrigin(auth.serverOrigin) ? (
                <p role="alert" style={{ margin: "0 0 6px 0", color: "#b91c1c", fontWeight: 600 }}>
                  ⚠️ Browser linked to different server: {vaultLink.serverOrigin}
                </p>
              ) : vaultLink.accountId !== auth.session?.accountId ? (
                <p role="alert" style={{ margin: "0 0 6px 0", color: "#b91c1c", fontWeight: 600 }}>
                  ⚠️ Browser linked to different account: {vaultLink.accountId}
                </p>
              ) : null
            )}
            <p style={{ margin: "0 0 6px 0", color: "#4b5563" }}>No local vault on this browser.</p>
            <button
              type="button"
              disabled={isRestoring || auth.isOffline}
              onClick={handleRestoreVault}
              className="zk-restore-vault-button"
            >
              {isRestoring ? "Restoring..." : "Restore vault from account"}
            </button>
          </div>
        ))}
        {linkMessage && <p style={{ color: "#166534", margin: "6px 0 0 0" }}>{linkMessage}</p>}
        {linkError && <p role="alert" style={{ color: "#b91c1c", margin: "6px 0 0 0" }}>{linkError}</p>}
      </div> : <>
        <label>Account name <input value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" /></label>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <button type="button" disabled={auth.isLoading || auth.isOffline || !sameOrigin || !username.trim()} onClick={() => void auth.register({ username: username.trim(), displayName: username.trim() }).catch(() => {})}>Create account</button>
          <button type="button" disabled={auth.isLoading || auth.isOffline || !sameOrigin} onClick={() => void auth.signIn().catch(() => {})}>Sign in with passkey</button>
        </div>
      </>}
      {auth.error && <p role="alert">{auth.error}</p>}
      <p style={{ marginTop: 8, color: "#6b7280" }}>Signing in does not upload this vault. Vault linking is a separate step.</p>
    </div>}
  </div>;
};
