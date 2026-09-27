import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { VaultHandler } from "../src/worker/vault-handler.js";
import { VaultInitResultDto, WorkerRequest, WorkerResponse } from "../src/worker/protocol.js";

const TEST_KDF_PARAMS = JSON.stringify({
  algorithm: "argon2id",
  memory_kib: 1024,
  iterations: 1,
  parallelism: 1,
  salt: "AQIDBAUGBwgJCgsMDQ4PEA==",
});

test("browser-style worker initialization loads WASM before vault creation", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input instanceof URL ? input : new URL(String(input));
    if (url.protocol === "file:") {
      const bytes = await readFile(fileURLToPath(url));
      return new Response(bytes, {
        headers: { "Content-Type": "application/wasm" },
      });
    }
    return originalFetch(input, init);
  };

  const handler = new VaultHandler();
  try {
    await handler.initWasm();

    const request: WorkerRequest = {
      id: "browser-init-1",
      type: "INIT_VAULT",
      payload: {
        passphrase: "test-passphrase",
        kdfParamsJson: TEST_KDF_PARAMS,
      },
    };
    let response: WorkerResponse | undefined;
    handler.handleMessage(request, (message) => {
      response = message;
    });

    assert.equal(response?.ok, true);
    if (response?.ok) {
      const data = response.data as VaultInitResultDto;
      assert.ok(data.recoveryPhrase);
      assert.ok(data.wrappedVaultKey);

      handler.handleMessage(
        { id: "browser-init-lock", type: "LOCK_VAULT", payload: undefined },
        () => {}
      );
      let unlockResponse: WorkerResponse | undefined;
      handler.handleMessage(
        {
          id: "browser-init-unlock",
          type: "UNLOCK_VAULT",
          payload: {
            passphrase: "test-passphrase",
            wrappedVaultKeyJson: data.wrappedVaultKey,
            kdfParamsJson: data.kdfParamsJson,
          },
        },
        (message) => {
          unlockResponse = message;
        }
      );
      assert.equal(unlockResponse?.ok, true);
    }
  } finally {
    handler.handleMessage(
      { id: "browser-init-lock", type: "LOCK_VAULT", payload: undefined },
      () => {}
    );
    globalThis.fetch = originalFetch;
  }
});
