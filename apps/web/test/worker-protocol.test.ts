/**
 * Web Worker Protocol Unit Tests (ZK-062).
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  WorkerErrorCode,
  isWorkerBroadcastEvent,
  WorkerRequest,
  WorkerResponseSuccess,
  WorkerResponseError,
  WorkerOutgoingMessage,
} from "../src/worker/protocol.js";

test("WorkerErrorCode enum values are distinct and expected", () => {
  assert.equal(WorkerErrorCode.VAULT_LOCKED, "VAULT_LOCKED");
  assert.equal(WorkerErrorCode.DECRYPTION_FAILED, "DECRYPTION_FAILED");
  assert.equal(WorkerErrorCode.ENCRYPTION_FAILED, "ENCRYPTION_FAILED");
  assert.equal(WorkerErrorCode.INVALID_PAYLOAD, "INVALID_PAYLOAD");
  assert.equal(WorkerErrorCode.INVALID_RECOVERY_KEY, "INVALID_RECOVERY_KEY");
  assert.equal(WorkerErrorCode.INTERNAL_ERROR, "INTERNAL_ERROR");
});

test("isWorkerBroadcastEvent identifies broadcast vs response messages", () => {
  const broadcast: WorkerOutgoingMessage = { event: "VAULT_LOCKED" };
  assert.equal(isWorkerBroadcastEvent(broadcast), true);

  const responseSuccess: WorkerOutgoingMessage = {
    id: "req-1",
    ok: true,
    data: { isUnlocked: true },
  };
  assert.equal(isWorkerBroadcastEvent(responseSuccess), false);

  const responseError: WorkerOutgoingMessage = {
    id: "req-2",
    ok: false,
    error: {
      code: WorkerErrorCode.VAULT_LOCKED,
      message: "Vault is locked",
    },
  };
  assert.equal(isWorkerBroadcastEvent(responseError), false);

  assert.equal(isWorkerBroadcastEvent(null), false);
  assert.equal(isWorkerBroadcastEvent(undefined), false);
  assert.equal(isWorkerBroadcastEvent("string"), false);
  assert.equal(isWorkerBroadcastEvent(42), false);
});

test("WorkerRequest and WorkerResponse types serialize cleanly as JSON", () => {
  const req: WorkerRequest = {
    id: "corr-123",
    type: "ENCRYPT_NOTE",
    payload: {
      noteId: "note-1",
      title: "Title",
      body: "Body",
      tags: ["tag1"],
    },
  };

  const serialized = JSON.stringify(req);
  const parsed = JSON.parse(serialized);
  assert.deepEqual(parsed, req);

  const res: WorkerResponseSuccess = {
    id: "corr-123",
    ok: true,
    data: { envelopeJson: '{"envelope_version":1}' },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(res)), res);

  const errRes: WorkerResponseError = {
    id: "corr-123",
    ok: false,
    error: {
      code: WorkerErrorCode.DECRYPTION_FAILED,
      message: "bad key",
    },
  };
  assert.deepEqual(JSON.parse(JSON.stringify(errRes)), errRes);
});
