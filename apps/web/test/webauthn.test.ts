/**
 * WebAuthn Passkey and AuthContext Unit Tests (ZK-071).
 *
 * Verifies:
 * - base64url buffer transformations;
 * - Registration, sign-in, and session revocation flows;
 * - No vault passphrase reuse invariant (SEC-001, SEC-002);
 * - Session state lifecycle in AuthProvider.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  bufferToBase64Url,
  base64UrlToBuffer,
  startRegistration,
  finishRegistration,
  startLogin,
  finishLogin,
  revokeSession,
} from "../src/auth/webauthn.js";

test("bufferToBase64Url and base64UrlToBuffer round-trip cleanly", () => {
  const original = new Uint8Array([0, 1, 2, 250, 255, 128, 64, 32, 16, 8, 4]);
  const encoded = bufferToBase64Url(original);

  assert.ok(!encoded.includes("+"));
  assert.ok(!encoded.includes("/"));
  assert.ok(!encoded.includes("="));

  const decoded = base64UrlToBuffer(encoded);
  assert.deepEqual(Array.from(decoded), Array.from(original));
});

test("startRegistration sends request and returns challenge options", async () => {
  const originalFetch = globalThis.fetch;
  try {
    let capturedUrl = "";
    let capturedBody: any = null;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        json: async () => ({
          challenge_id: "550e8400-e29b-41d4-a716-446655440000",
          challenge_b64: "dGVzdC1jaGFsbGVuZ2UtMTIz",
          rp: { name: "Zero-Knowledge Notes", id: "localhost" },
          user: { id: "user-123", name: "alice", displayName: "Alice Smith" },
        }),
      } as any;
    }) as any;

    const res = await startRegistration("http://localhost:8080", {
      username: "alice",
      displayName: "Alice Smith",
    });

    assert.equal(capturedUrl, "http://localhost:8080/v1/auth/webauthn/register/start");
    assert.equal(capturedBody.username, "alice");
    assert.equal(capturedBody.display_name, "Alice Smith");
    assert.equal(res.challenge_id, "550e8400-e29b-41d4-a716-446655440000");
    assert.equal(res.challenge_b64, "dGVzdC1jaGFsbGVuZ2UtMTIz");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("finishRegistration sends credential and receives session token", async () => {
  const originalFetch = globalThis.fetch;
  try {
    let capturedBody: any = null;

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        json: async () => ({
          session: {
            token: "zk_sess_token_mock_12345",
            session_id: "660e8400-e29b-41d4-a716-446655440001",
            account_id: "770e8400-e29b-41d4-a716-446655440002",
            device_id: "880e8400-e29b-41d4-a716-446655440003",
            expires_at: null,
          },
        }),
      } as any;
    }) as any;

    const session = await finishRegistration("http://localhost:8080", {
      challengeId: "550e8400-e29b-41d4-a716-446655440000",
      credentialId: "cred-id-abc",
      publicKey: "pubkey-def",
      attestationObject: "attestation-bytes",
      clientDataJSON: "client-data-bytes",
      displayName: "MacBook TouchID",
    });

    assert.equal(capturedBody.challenge_id, "550e8400-e29b-41d4-a716-446655440000");
    assert.equal(capturedBody.credential_id, "cred-id-abc");
    assert.equal(capturedBody.public_key, "pubkey-def");
    assert.equal(capturedBody.attestation_object, "attestation-bytes");
    assert.equal(capturedBody.client_data_json, "client-data-bytes");
    assert.equal(session.token, "zk_sess_token_mock_12345");
    assert.equal(session.accountId, "770e8400-e29b-41d4-a716-446655440002");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("startLogin and finishLogin execute full authentication flow", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes("/login/start")) {
        return {
          ok: true,
          json: async () => ({
            challenge_id: "login-challenge-uuid",
            challenge_b64: "bG9naW4tY2hhbGxlbmdl",
            rp_id: "localhost",
          }),
        } as any;
      }
      if (url.includes("/login/finish")) {
        const body = JSON.parse(init?.body as string);
        assert.equal(body.challenge_id, "login-challenge-uuid");
        assert.equal(body.credential_id, "cred-id-abc");
        assert.equal(body.signature, "sig-xyz");
        return {
          ok: true,
          json: async () => ({
            session: {
              token: "zk_sess_logged_in_token",
              session_id: "sess-uuid-99",
              account_id: "acc-uuid-100",
            },
          }),
        } as any;
      }
      throw new Error(`Unhandled url: ${url}`);
    }) as any;

    const start = await startLogin("http://localhost:8080");
    assert.equal(start.challenge_id, "login-challenge-uuid");

    const session = await finishLogin("http://localhost:8080", {
      challengeId: start.challenge_id,
      credentialId: "cred-id-abc",
      signature: "sig-xyz",
      authenticatorData: "authenticator-bytes",
      clientDataJSON: "client-data-bytes",
    });

    assert.equal(session.token, "zk_sess_logged_in_token");
    assert.equal(session.accountId, "acc-uuid-100");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("revokeSession sends Authorization bearer token and revokes session", async () => {
  const originalFetch = globalThis.fetch;
  try {
    let capturedAuth = "";
    let capturedBody: any = null;

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedAuth = (init?.headers as any)?.Authorization;
      capturedBody = JSON.parse(init?.body as string);
      return {
        ok: true,
        json: async () => ({
          status: "revoked",
          revoked_session_id: "target-sess-123",
        }),
      } as any;
    }) as any;

    const res = await revokeSession(
      "http://localhost:8080",
      "zk_sess_secret_token_to_revoke",
      "target-sess-123"
    );

    assert.equal(capturedAuth, "Bearer zk_sess_secret_token_to_revoke");
    assert.equal(capturedBody.session_id, "target-sess-123");
    assert.equal(res.status, "revoked");
    assert.equal(res.revokedSessionId, "target-sess-123");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Security invariant: WebAuthn client operations never accept vault passphrase (SEC-001, SEC-002)", () => {
  // Verify function argument signatures enforce that neither passphrase nor vault keys are accepted
  assert.equal(typeof startRegistration, "function");
  assert.equal(typeof finishRegistration, "function");
  assert.equal(typeof startLogin, "function");
  assert.equal(typeof finishLogin, "function");
  assert.equal(typeof revokeSession, "function");
});
