/**
 * WebAuthn / Authentication React Context (ZK-071).
 *
 * Requirements & Security Invariants:
 * - Decouples server authentication from vault encryption (SEC-001, SEC-002).
 * - Vault passphrases are NEVER handled by this context.
 * - Manages passkey registration, sign-in, and session revocation.
 */

import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from "react";
import { isSessionCurrent, normalizeServerOrigin, readServerOrigin, readSessionState, revokeBeforeSignOut, writeServerOrigin, writeSession } from "../auth/session.js";
import {
  WebAuthnSession,
  DeviceInfo,
  RevokeDeviceResponse,
  registerPasskey,
  signInWithPasskey,
  revokeSession,
  listDevices,
  revokeDevice,
} from "../auth/webauthn.js";

export interface AuthContextType {
  session: WebAuthnSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isOffline: boolean;
  isExpired: boolean;
  serverOrigin: string;
  setServerOrigin: (serverUrl: string) => void;
  error: string | null;
  register: (options?: {
    username?: string;
    displayName?: string;
    accountId?: string;
    deviceId?: string;
  }) => Promise<WebAuthnSession>;
  signIn: (options?: { accountId?: string; deviceId?: string }) => Promise<WebAuthnSession>;
  logout: () => Promise<void>;
  listDevices: () => Promise<DeviceInfo[]>;
  revokeDevice: (deviceId: string) => Promise<RevokeDeviceResponse>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

function persistSession(origin: string, session: WebAuthnSession | null): void {
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      writeSession(window.sessionStorage, origin, session);
    }
  } catch {
    // Ignore storage write errors
  }
}

export interface AuthProviderProps {
  children: React.ReactNode;
  serverUrl?: string;
  initialSession?: WebAuthnSession | null;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({
  children,
  serverUrl,
  initialSession,
}) => {
  const [serverOrigin, updateServerOrigin] = useState(() => {
    const fallback = serverUrl ?? (typeof window !== "undefined" && window.location?.origin ? window.location.origin : "http://localhost:8080");
    return typeof window !== "undefined" && !serverUrl ? readServerOrigin(window.localStorage, fallback) : normalizeServerOrigin(fallback);
  });
  const currentOrigin = useRef(serverOrigin);
  currentOrigin.current = serverOrigin;
  const [initialAuth] = useState(() => initialSession !== undefined
    ? { session: initialSession && isSessionCurrent(initialSession) ? initialSession : null, expired: Boolean(initialSession && !isSessionCurrent(initialSession)) }
    : typeof window !== "undefined" ? readSessionState(window.sessionStorage, serverOrigin) : { session: null, expired: false });
  const [session, setSession] = useState<WebAuthnSession | null>(initialAuth.session);
  const [isExpired, setIsExpired] = useState(initialAuth.expired);
  const [sessionOrigin, setSessionOrigin] = useState(serverOrigin);
  const activeSession = sessionOrigin === serverOrigin && session && isSessionCurrent(session) ? session : null;
  const [isOffline, setIsOffline] = useState(() => typeof navigator !== "undefined" && navigator.onLine === false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setServerOrigin = useCallback((input: string): void => {
    const origin = normalizeServerOrigin(input.trim());
    if (typeof window !== "undefined" && window.location.protocol === "https:" && origin.startsWith("http:")) {
      throw new Error("An HTTPS web app requires an HTTPS server address.");
    }
    if (origin === serverOrigin) return;
    currentOrigin.current = origin;
    setSession(null);
    setIsExpired(false);
    persistSession(serverOrigin, null);
    setError(null);
    updateServerOrigin(origin);
    try {
      if (typeof window !== "undefined") writeServerOrigin(window.localStorage, origin);
    } catch { /* The selected origin remains active for this tab. */ }
  }, [serverOrigin]);

  useEffect(() => {
    if (!serverUrl) return;
    const origin = normalizeServerOrigin(serverUrl);
    if (origin !== serverOrigin) setServerOrigin(origin);
  }, [serverUrl]);

  useEffect(() => {
    if (sessionOrigin === serverOrigin) return;
    setSession(null);
    setIsExpired(false);
    setSessionOrigin(serverOrigin);
    persistSession(serverOrigin, null);
    setError(null);
  }, [serverOrigin, sessionOrigin]);

  useEffect(() => {
    const update = () => setIsOffline(navigator.onLine === false);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => { window.removeEventListener("online", update); window.removeEventListener("offline", update); };
  }, []);

  useEffect(() => {
    if (!session?.expiresAt || sessionOrigin !== serverOrigin) return;
    const delay = Date.parse(session.expiresAt) - Date.now();
    if (delay <= 0) { setSession(null); setIsExpired(true); persistSession(serverOrigin, null); return; }
    const timer = window.setTimeout(() => { setSession(null); setIsExpired(true); persistSession(serverOrigin, null); }, delay);
    return () => window.clearTimeout(timer);
  }, [session, sessionOrigin, serverOrigin]);

  useEffect(() => {
    if (initialSession !== undefined) {
      const isCurrent = Boolean(initialSession && isSessionCurrent(initialSession));
      setSession(isCurrent ? initialSession : null);
      setIsExpired(Boolean(initialSession && !isCurrent));
      setSessionOrigin(serverOrigin);
    }
  }, [initialSession, serverOrigin]);

  const clearError = useCallback(() => setError(null), []);

  const register = useCallback(
    async (options?: {
      username?: string;
      displayName?: string;
      accountId?: string;
      deviceId?: string;
    }): Promise<WebAuthnSession> => {
      setIsLoading(true);
      setError(null);
      try {
        if (isOffline) throw new Error("Connect to the server before registering a passkey.");
        const newSession = await registerPasskey(serverOrigin, { ...options, token: activeSession?.token });
        if (currentOrigin.current !== serverOrigin) throw new Error("Server origin changed during registration. Sign in again.");
        setSession(newSession);
        setIsExpired(false);
        setSessionOrigin(serverOrigin);
        persistSession(serverOrigin, newSession);
        return newSession;
      } catch (err: any) {
        const msg = err?.message || "Failed to register passkey";
        setError(msg);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [serverOrigin, activeSession?.token, isOffline]
  );

  const signIn = useCallback(
    async (options?: { accountId?: string; deviceId?: string }): Promise<WebAuthnSession> => {
      setIsLoading(true);
      setError(null);
      try {
        if (isOffline) throw new Error("Connect to the server before signing in.");
        const newSession = await signInWithPasskey(serverOrigin, options);
        if (currentOrigin.current !== serverOrigin) throw new Error("Server origin changed during sign-in. Sign in again.");
        setSession(newSession);
        setIsExpired(false);
        setSessionOrigin(serverOrigin);
        persistSession(serverOrigin, newSession);
        return newSession;
      } catch (err: any) {
        const msg = err?.message || "Failed to sign in with passkey";
        setError(msg);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [serverOrigin, isOffline]
  );

  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      await revokeBeforeSignOut(activeSession, isOffline, current => revokeSession(serverOrigin, current.token, current.sessionId));
      setSession(null);
      setIsExpired(false);
      persistSession(serverOrigin, null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke the server session. Please retry sign-out.");
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [serverOrigin, activeSession, isOffline]);

  const listDevicesCallback = useCallback(async (): Promise<DeviceInfo[]> => {
    if (!activeSession?.token) {
      throw new Error("Cannot list devices: not authenticated");
    }
    setError(null);
    try {
      return await listDevices(serverOrigin, activeSession.token);
    } catch (err: any) {
      const msg = err?.message || "Failed to list devices";
      setError(msg);
      throw err;
    }
  }, [serverOrigin, activeSession?.token]);

  const revokeDeviceCallback = useCallback(
    async (deviceId: string): Promise<RevokeDeviceResponse> => {
      if (!activeSession?.token) {
        throw new Error("Cannot revoke device: not authenticated");
      }
      setError(null);
      try {
        const res = await revokeDevice(serverOrigin, activeSession.token, deviceId);
        if (activeSession.deviceId === deviceId) {
          setSession(null);
          persistSession(serverOrigin, null);
        }
        return res;
      } catch (err: any) {
        const msg = err?.message || "Failed to revoke device";
        setError(msg);
        throw err;
      }
    },
    [serverOrigin, activeSession?.token, activeSession?.deviceId]
  );

  const value: AuthContextType = {
    session: activeSession,
    isAuthenticated: Boolean(activeSession),
    isLoading,
    isOffline,
    isExpired,
    serverOrigin,
    setServerOrigin,
    error,
    register,
    signIn,
    logout,
    listDevices: listDevicesCallback,
    revokeDevice: revokeDeviceCallback,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    return {
      session: null,
      isAuthenticated: false,
      isLoading: false,
      isOffline: true,
      isExpired: false,
      serverOrigin: "",
      setServerOrigin: () => {},
      error: null,
      register: async () => {
        throw new Error("useAuth must be used within an AuthProvider");
      },
      signIn: async () => {
        throw new Error("useAuth must be used within an AuthProvider");
      },
      logout: async () => {},
      listDevices: async () => [],
      revokeDevice: async () => ({
        status: "revoked",
        deviceId: "",
        revokedSessionsCount: 0,
      }),
      clearError: () => {},
    };
  }
  return context;
}
