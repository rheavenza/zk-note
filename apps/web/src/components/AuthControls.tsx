import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext.js";

export const AuthControls: React.FC = () => {
  const auth = useAuth();
  const [username, setUsername] = useState("");
  const [open, setOpen] = useState(false);
  const [serverInput, setServerInput] = useState(auth.serverOrigin);
  const [serverError, setServerError] = useState<string | null>(null);
  const pageOrigin = typeof window !== "undefined" ? window.location.origin : auth.serverOrigin;
  const sameOrigin = pageOrigin === auth.serverOrigin;

  useEffect(() => { setServerInput(auth.serverOrigin); }, [auth.serverOrigin]);

  const state = auth.isOffline ? "Offline — local vault available" :
    auth.isAuthenticated ? `Signed in (${auth.session?.accountId})` : "Local vault only — not signed in";

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
      {auth.isAuthenticated ? <button type="button" disabled={auth.isLoading} onClick={() => void auth.logout()}>Sign out</button> : <>
        <label>Account name <input value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" /></label>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <button type="button" disabled={auth.isLoading || auth.isOffline || !sameOrigin || !username.trim()} onClick={() => void auth.register({ username: username.trim(), displayName: username.trim() }).catch(() => {})}>Create account</button>
          <button type="button" disabled={auth.isLoading || auth.isOffline || !sameOrigin} onClick={() => void auth.signIn().catch(() => {})}>Sign in with passkey</button>
        </div>
      </>}
      {auth.error && <p role="alert">{auth.error}</p>}
      <p>Signing in does not upload this vault. Vault linking is a separate step.</p>
    </div>}
  </div>;
};
