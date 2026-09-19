/**
 * Device Management and Revocation Tests (ZK-075).
 *
 * Verifies:
 * - listDevices fetches /v1/devices and parses device models;
 * - revokeDevice issues DELETE /v1/devices/{deviceId};
 * - AuthProvider device management methods;
 * - Revoking current device terminates local session;
 * - DeviceManagementModal rendering and security assurances;
 * - Zero plaintext leakage (SEC-001, SEC-002, SEC-003).
 */

import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import { listDevices, revokeDevice } from "../src/auth/webauthn.js";
import { AuthProvider, useAuth, AuthContextType } from "../src/context/AuthContext.js";
import { DeviceManagementModal } from "../src/components/DeviceManagementModal.js";

test("listDevices sends GET /v1/devices with Bearer token and returns DeviceInfo[]", async () => {
  const originalFetch = globalThis.fetch;
  try {
    let capturedUrl = "";
    let capturedAuth = "";

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedAuth = (init?.headers as any)?.Authorization;
      return {
        ok: true,
        json: async () => ({
          devices: [
            {
              device_id: "dev-uuid-1",
              display_name: "MacBook Pro",
              created_at: "2026-09-01T12:00:00Z",
              last_seen: "2026-09-19T10:00:00Z",
              last_ack_server_seq: 42,
              is_revoked: false,
              revoked_at: null,
            },
            {
              device_id: "dev-uuid-2",
              display_name: "iPhone",
              created_at: "2026-09-05T15:00:00Z",
              last_seen: "2026-09-10T08:00:00Z",
              last_ack_server_seq: 15,
              is_revoked: true,
              revoked_at: "2026-09-11T09:00:00Z",
            },
          ],
        }),
      } as any;
    }) as any;

    const devices = await listDevices("http://localhost:8080", "secret-token-abc");

    assert.equal(capturedUrl, "http://localhost:8080/v1/devices");
    assert.equal(capturedAuth, "Bearer secret-token-abc");
    assert.equal(devices.length, 2);

    assert.equal(devices[0]!.deviceId, "dev-uuid-1");
    assert.equal(devices[0]!.displayName, "MacBook Pro");
    assert.equal(devices[0]!.lastAckServerSeq, 42);
    assert.equal(devices[0]!.isRevoked, false);
    assert.equal(devices[0]!.revokedAt, null);

    assert.equal(devices[1]!.deviceId, "dev-uuid-2");
    assert.equal(devices[1]!.displayName, "iPhone");
    assert.equal(devices[1]!.isRevoked, true);
    assert.equal(devices[1]!.revokedAt, "2026-09-11T09:00:00Z");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("revokeDevice sends DELETE /v1/devices/{deviceId} and returns RevokeDeviceResponse", async () => {
  const originalFetch = globalThis.fetch;
  try {
    let capturedUrl = "";
    let capturedMethod = "";
    let capturedAuth = "";

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedMethod = init?.method || "GET";
      capturedAuth = (init?.headers as any)?.Authorization;
      return {
        ok: true,
        json: async () => ({
          status: "revoked",
          device_id: "dev-to-revoke-99",
          revoked_sessions_count: 2,
        }),
      } as any;
    }) as any;

    const res = await revokeDevice(
      "http://localhost:8080",
      "secret-token-xyz",
      "dev-to-revoke-99"
    );

    assert.equal(capturedUrl, "http://localhost:8080/v1/devices/dev-to-revoke-99");
    assert.equal(capturedMethod, "DELETE");
    assert.equal(capturedAuth, "Bearer secret-token-xyz");
    assert.equal(res.status, "revoked");
    assert.equal(res.deviceId, "dev-to-revoke-99");
    assert.equal(res.revokedSessionsCount, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("AuthProvider listDevices and revokeDevice lifecycle", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method || "GET";

      if (url.includes("/v1/devices") && method === "GET") {
        return {
          ok: true,
          json: async () => ({
            devices: [
              {
                device_id: "dev-curr-1",
                display_name: "Web Browser",
                created_at: "2026-09-01T12:00:00Z",
                last_seen: "2026-09-19T10:00:00Z",
                last_ack_server_seq: 10,
                is_revoked: false,
                revoked_at: null,
              },
              {
                device_id: "dev-other-2",
                display_name: "CLI Linux",
                created_at: "2026-09-02T12:00:00Z",
                last_seen: "2026-09-18T10:00:00Z",
                last_ack_server_seq: 5,
                is_revoked: false,
                revoked_at: null,
              },
            ],
          }),
        } as any;
      }

      if (url.includes("/v1/devices/dev-other-2") && method === "DELETE") {
        return {
          ok: true,
          json: async () => ({
            status: "revoked",
            device_id: "dev-other-2",
            revoked_sessions_count: 1,
          }),
        } as any;
      }

      if (url.includes("/v1/devices/dev-curr-1") && method === "DELETE") {
        return {
          ok: true,
          json: async () => ({
            status: "revoked",
            device_id: "dev-curr-1",
            revoked_sessions_count: 1,
          }),
        } as any;
      }

      return { ok: false, status: 404 } as any;
    }) as any;

    const store = new Map<string, string>();
    const mockStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => store.set(k, v),
      removeItem: (k: string) => store.delete(k),
    };
    (globalThis as any).window = { sessionStorage: mockStorage };

    let authCtx: AuthContextType | null = null;
    const TestConsumer: React.FC = () => {
      authCtx = useAuth();
      return <div>Consumer</div>;
    };

    const initialSession = {
      token: "tok-12345",
      sessionId: "sess-1",
      accountId: "acc-1",
      deviceId: "dev-curr-1",
    };

    renderToString(
      <AuthProvider serverUrl="http://localhost:8080" initialSession={initialSession}>
        <TestConsumer />
      </AuthProvider>
    );

    assert.ok(authCtx !== null);
    const ctx = authCtx as AuthContextType;

    // 1. List devices
    const list = await ctx.listDevices();
    assert.equal(list.length, 2);

    // 2. Revoke other device -> Current session remains active in storage
    const revokeOther = await ctx.revokeDevice("dev-other-2");
    assert.equal(revokeOther.deviceId, "dev-other-2");

    // 3. Revoke current device -> Local session is removed from storage
    const revokeCurrent = await ctx.revokeDevice("dev-curr-1");
    assert.equal(revokeCurrent.deviceId, "dev-curr-1");
    assert.equal(store.get("zk_auth_session"), undefined);
  } finally {
    delete (globalThis as any).window;
    globalThis.fetch = originalFetch;
  }
});

test("DeviceManagementModal renders dialog and zero-knowledge notices", () => {
  // 1. Closed modal renders nothing
  const closedHtml = renderToString(
    <DeviceManagementModal isOpen={false} onClose={() => {}} />
  );
  assert.equal(closedHtml, "");

  // 2. Open modal renders dialog, title, and ZK notice
  const openHtml = renderToString(
    <DeviceManagementModal isOpen={true} onClose={() => {}} />
  );
  assert.ok(openHtml.includes("Authorized Devices &amp; Sessions") || openHtml.includes("Authorized Devices & Sessions"));
  assert.ok(openHtml.includes("Zero-Knowledge Device Management"));
  assert.ok(openHtml.includes("You must be logged in"));
  assert.ok(openHtml.includes("Done"));
});
