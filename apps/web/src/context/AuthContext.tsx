/**
 * WebAuthn / Authentication React Context (ZK-071).
 *
 * Requirements & Security Invariants:
 * - Decouples server authentication from vault encryption (SEC-001, SEC-002).
 * - Vault passphrases are NEVER handled by this context.
 * - Manages passkey registration, sign-in, and session revocation.
 */

import React, { createContext, useContext, useState, useCallback } from "react";
import {
  WebAuthnSession,
  registerPasskey,
  signInWithPasskey,
  revokeSession,
} from "../auth/webauthn.js";

export interface AuthContextType {
  session: WebAuthnSession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  register: (options?: {
    username?: string;
    displayName?: string;
    accountId?: string;
    deviceId?: string;
  }) => Promise<WebAuthnSession>;
  signIn: (options?: { accountId?: string; deviceId?: string }) => Promise<WebAuthnSession>;
  logout: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const SESSION_STORAGE_KEY = "zk_auth_session";

function getStoredSession(): WebAuthnSession | null {
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      const raw = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (raw) return JSON.parse(raw);
    }
  } catch {
    // Ignore storage parse errors
  }
  return null;
}

function persistSession(session: WebAuthnSession | null): void {
  try {
    if (typeof window !== "undefined" && window.sessionStorage) {
      if (session) {
        window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
      } else {
        window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
      }
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
  serverUrl = "http://localhost:8080",
  initialSession,
}) => {
  const [session, setSession] = useState<WebAuthnSession | null>(
    () => initialSession !== undefined ? initialSession : getStoredSession()
  );
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
        const newSession = await registerPasskey(serverUrl, options);
        setSession(newSession);
        persistSession(newSession);
        return newSession;
      } catch (err: any) {
        const msg = err?.message || "Failed to register passkey";
        setError(msg);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [serverUrl]
  );

  const signIn = useCallback(
    async (options?: { accountId?: string; deviceId?: string }): Promise<WebAuthnSession> => {
      setIsLoading(true);
      setError(null);
      try {
        const newSession = await signInWithPasskey(serverUrl, options);
        setSession(newSession);
        persistSession(newSession);
        return newSession;
      } catch (err: any) {
        const msg = err?.message || "Failed to sign in with passkey";
        setError(msg);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [serverUrl]
  );

  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      if (session?.token) {
        await revokeSession(serverUrl, session.token, session.sessionId).catch(() => {});
      }
    } finally {
      setSession(null);
      persistSession(null);
      setIsLoading(false);
    }
  }, [serverUrl, session]);

  const value: AuthContextType = {
    session,
    isAuthenticated: Boolean(session?.token),
    isLoading,
    error,
    register,
    signIn,
    logout,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
