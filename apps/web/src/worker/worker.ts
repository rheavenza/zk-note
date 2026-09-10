/**
 * Web Worker Entrypoint (ZK-062).
 *
 * Runs in a dedicated Web Worker thread (or Node.js worker_thread in tests).
 * Initializes the WASM core, sets up error hooks, and processes incoming RPC messages.
 */

import { VaultHandler } from "./vault-handler.js";
import { WorkerRequest, WorkerOutgoingMessage } from "./protocol.js";

const handler = new VaultHandler();

// Setup listener for browser Web Worker environment
if (typeof self !== "undefined" && typeof window === "undefined") {
  // Initialize WASM automatically if running in browser worker
  handler.initWasm().catch((err) => {
    console.error("Failed to initialize WASM in Web Worker:", err);
  });

  self.onmessage = (event: MessageEvent<WorkerRequest>) => {
    handler.handleMessage(
      event.data,
      (res: WorkerOutgoingMessage) => self.postMessage(res),
      (broadcast: WorkerOutgoingMessage) => self.postMessage(broadcast)
    );
  };
}

// Setup listener for Node.js worker_threads environment (used for tests)
async function setupNodeWorker(): Promise<void> {
  try {
    const workerThreads = await import("node:worker_threads");
    if (workerThreads.parentPort) {
      const port = workerThreads.parentPort;

      // Initialize WASM in Node.js worker thread
      if (workerThreads.workerData?.wasmBytes) {
        await handler.initWasm(workerThreads.workerData.wasmBytes);
      } else {
        try {
          const { createRequire } = await import("node:module");
          const fs = await import("node:fs");
          const path = await import("node:path");
          const require = createRequire(import.meta.url);
          const pkgJs = require.resolve("zk-wasm");
          const wasmPath = path.join(path.dirname(pkgJs), "zk_wasm_bg.wasm");
          if (fs.existsSync(wasmPath)) {
            const bytes = fs.readFileSync(wasmPath);
            await handler.initWasm(bytes);
          }
        } catch (err) {
          console.error("Failed to load WASM binary in Node worker:", err);
        }
      }

      port.on("message", (req: WorkerRequest) => {
        handler.handleMessage(
          req,
          (res: WorkerOutgoingMessage) => port.postMessage(res),
          (broadcast: WorkerOutgoingMessage) => port.postMessage(broadcast)
        );
      });
    }
  } catch {
    // Not running under Node worker_threads
  }
}

setupNodeWorker().catch(() => {});

export { handler };
