import type { WebAuthnSession } from "./webauthn.js";

export const SESSION_STORAGE_KEY = "zk_auth_session_v2";
export const SERVER_ORIGIN_STORAGE_KEY = "zk_server_origin";

export function normalizeServerOrigin(serverUrl: string): string {
  const input = serverUrl.trim();
  const bareHost = /^[a-zA-Z0-9.-]+(?::\d+)?$/.test(input);
  const localHost = /^(localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/i.test(input);
  const url = new URL(bareHost ? `${localHost ? "http" : "https"}://${input}` : input);
  if (!(["https:", "http:"].includes(url.protocol))) throw new Error("Unsupported server URL");
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("Server URL must be an origin without credentials or a path");
  }
  return url.origin;
}

export function readServerOrigin(storage: Pick<Storage, "getItem">, fallback: string): string {
  try {
    const saved = storage.getItem(SERVER_ORIGIN_STORAGE_KEY);
    return saved ? normalizeServerOrigin(saved) : normalizeServerOrigin(fallback);
  } catch {
    return normalizeServerOrigin(fallback);
  }
}

export function writeServerOrigin(storage: Pick<Storage, "setItem">, origin: string): void {
  storage.setItem(SERVER_ORIGIN_STORAGE_KEY, normalizeServerOrigin(origin));
}

export function isSessionCurrent(session: WebAuthnSession, now = Date.now()): boolean {
  return Boolean(session.token && session.accountId && session.sessionId) &&
    (!session.expiresAt || (Number.isFinite(Date.parse(session.expiresAt)) && Date.parse(session.expiresAt) > now));
}

export function readSession(storage: Pick<Storage, "getItem" | "removeItem">, origin: string): WebAuthnSession | null {
  try {
    const raw = storage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const saved: unknown = JSON.parse(raw);
    if (!saved || typeof saved !== "object") return null;
    const record = saved as { origin?: unknown; session?: WebAuthnSession };
    if (record.origin === origin && record.session && isSessionCurrent(record.session)) return record.session;
    storage.removeItem(SESSION_STORAGE_KEY);
  } catch { /* Invalid or inaccessible session storage is treated as signed out. */ }
  return null;
}

export function writeSession(storage: Pick<Storage, "setItem" | "removeItem">, origin: string, session: WebAuthnSession | null): void {
  if (session) storage.setItem(SESSION_STORAGE_KEY, JSON.stringify({ origin, session }));
  else storage.removeItem(SESSION_STORAGE_KEY);
}

export function assertRpCompatible(rpId: string, browserUrl: string): void {
  const browser = new URL(browserUrl);
  const host = browser.hostname.toLowerCase();
  const rp = rpId.toLowerCase();
  if (!rp || (host !== rp && !host.endsWith(`.${rp}`))) {
    throw new Error(`This browser origin cannot use the server's passkey domain (${rpId}). Open the web app on an HTTPS origin within that domain, or configure the server for this origin.`);
  }
  if (browser.protocol !== "https:" && host !== "localhost") {
    throw new Error("Passkeys require HTTPS, except on localhost. Open the web app over HTTPS.");
  }
}
