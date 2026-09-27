import test from "node:test";
import assert from "node:assert/strict";
import { renderToString } from "react-dom/server";
import { assertRpCompatible, isSessionCurrent, normalizeServerOrigin, readServerOrigin, readSession, SERVER_ORIGIN_STORAGE_KEY, SESSION_STORAGE_KEY, writeServerOrigin, writeSession } from "../src/auth/session.js";
import { registerPasskey, signInWithPasskey, type WebAuthnSession } from "../src/auth/webauthn.js";
import { AuthProvider } from "../src/context/AuthContext.js";
import { AuthControls } from "../src/components/AuthControls.js";

const session: WebAuthnSession = { token: "secret-token", accountId: "account", sessionId: "session", expiresAt: "2099-01-01T00:00:00Z" };

test("session survives only on its configured server origin", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
  writeSession(storage, "https://one.example", session);
  assert.deepEqual(readSession(storage, "https://one.example"), session);
  assert.equal(readSession(storage, "https://two.example"), null);
  assert.equal(values.has(SESSION_STORAGE_KEY), false);
  writeSession(storage, "https://one.example", session);
  writeSession(storage, "https://one.example", null);
  assert.equal(readSession(storage, "https://one.example"), null);
});

test("expired and malformed sessions fail closed", () => {
  assert.equal(isSessionCurrent({ ...session, expiresAt: "2020-01-01T00:00:00Z" }), false);
  assert.equal(isSessionCurrent({ ...session, expiresAt: "invalid" }), false);
  const storage = { getItem: () => "{invalid", removeItem: () => {} };
  assert.equal(readSession(storage, "https://one.example"), null);
});

test("server URL accepts only a plain origin", () => {
  assert.equal(normalizeServerOrigin("https://one.example/"), "https://one.example");
  assert.equal(normalizeServerOrigin("192.0.2.10:8090"), "http://192.0.2.10:8090");
  assert.equal(normalizeServerOrigin("notes.example.com"), "https://notes.example.com");
  assert.throws(() => normalizeServerOrigin("https://one.example/path"));
  assert.throws(() => normalizeServerOrigin("https://user:pass@one.example"));
});

test("server address can be entered and restored without persisting credentials", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
  };
  assert.equal(readServerOrigin(storage, "https://default.example"), "https://default.example");
  writeServerOrigin(storage, "http://192.0.2.10:8090/");
  assert.equal(readServerOrigin(storage, "https://default.example"), "http://192.0.2.10:8090");
  assert.equal(values.get(SERVER_ORIGIN_STORAGE_KEY), "http://192.0.2.10:8090");
  values.set(SERVER_ORIGIN_STORAGE_KEY, "javascript:alert(1)");
  assert.equal(readServerOrigin(storage, "https://default.example"), "https://default.example");
});

test("passkey RP must match browser domain and use a secure context", () => {
  assert.doesNotThrow(() => assertRpCompatible("example.com", "https://notes.example.com/"));
  assert.doesNotThrow(() => assertRpCompatible("localhost", "http://localhost:5173/"));
  assert.throws(() => assertRpCompatible("example.com", "http://localhost:5173/"), /cannot use/);
  assert.throws(() => assertRpCompatible("example.com", "https://notexample.com/"), /cannot use/);
  assert.throws(() => assertRpCompatible("example.com", "http://notes.example.com/"), /HTTPS/);
});

test("auth controls expose local-only and authenticated states without vault data", () => {
  const local = renderToString(<AuthProvider serverUrl="https://notes.example.com"><AuthControls /></AuthProvider>);
  assert.match(local, /Local vault only/);
  const signedIn = renderToString(<AuthProvider serverUrl="https://notes.example.com" initialSession={session}><AuthControls /></AuthProvider>);
  assert.match(signedIn, /Signed in/);
  assert.doesNotMatch(signedIn, /secret-token/);
});

test("registration and login reject an incompatible RP before invoking credentials", async () => {
  const oldWindow = globalThis.window;
  const oldFetch = globalThis.fetch;
  let credentialCalls = 0;
  Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { href: "http://localhost:5173/" } } });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials: { create: () => { credentialCalls++; }, get: () => { credentialCalls++; } } } });
  globalThis.fetch = (async () => ({ ok: true, json: async () => ({
    challenge_b64: "AA", rp: { id: "remote.example", name: "Notes" }, rp_id: "remote.example",
  }) })) as unknown as typeof fetch;
  try {
    await assert.rejects(registerPasskey("https://remote.example"), /cannot use/);
    await assert.rejects(signInWithPasskey("https://remote.example"), /cannot use/);
    assert.equal(credentialCalls, 0);
  } finally {
    globalThis.fetch = oldFetch;
    Object.defineProperty(globalThis, "window", { configurable: true, value: oldWindow });
    Reflect.deleteProperty(globalThis, "navigator");
  }
});
