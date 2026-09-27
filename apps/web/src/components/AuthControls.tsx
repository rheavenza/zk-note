import React, { useState } from "react";
import { useAuth } from "../context/AuthContext.js";

export const AuthControls: React.FC = () => {
  const auth = useAuth();
  const [username, setUsername] = useState("");
  const [open, setOpen] = useState(false);

  const state = auth.isOffline ? "Offline — local vault available" :
    auth.isAuthenticated ? `Signed in (${auth.session?.accountId})` : "Local vault only — not signed in";

  return <div style={{ position: "relative", fontSize: 12 }}>
    <button type="button" onClick={() => setOpen(!open)} aria-label="Account and server authentication" aria-expanded={open}>
      {state}
    </button>
    {open && <div role="group" aria-label="Account authentication" style={{ position: "absolute", right: 0, top: "100%", zIndex: 20, width: 280, padding: 12, background: "white", border: "1px solid #d1d5db", boxShadow: "0 4px 12px #0002" }}>
      <p>Server: {auth.serverOrigin}</p>
      {auth.isAuthenticated ? <button type="button" disabled={auth.isLoading} onClick={() => void auth.logout()}>Sign out</button> : <>
        <label>Account name <input value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" /></label>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <button type="button" disabled={auth.isLoading || auth.isOffline || !username.trim()} onClick={() => void auth.register({ username: username.trim(), displayName: username.trim() }).catch(() => {})}>Create account</button>
          <button type="button" disabled={auth.isLoading || auth.isOffline} onClick={() => void auth.signIn().catch(() => {})}>Sign in with passkey</button>
        </div>
      </>}
      {auth.error && <p role="alert">{auth.error}</p>}
      <p>Signing in does not upload this vault. Vault linking is a separate step.</p>
    </div>}
  </div>;
};
