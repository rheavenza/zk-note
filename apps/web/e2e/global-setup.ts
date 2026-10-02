/**
 * ZK-107 browser acceptance stack.
 *
 * Boots a disposable, deterministic stack:
 *   - the real Rust `zk-server` on 127.0.0.1:18080 with a fresh temp SQLite DB,
 *   - the real production web bundle via `vite preview` on http://localhost:5173,
 *     which same-origin proxies `/v1` to the API.
 *
 * Both processes are torn down (and the temp DB removed) after the run. No live
 * or staging origin, credential, or operator hostname is referenced here.
 */

import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const WEB_DIR = path.resolve(HERE, "..");
export const REPO_ROOT = path.resolve(WEB_DIR, "../..");

export const API_PORT = 18080;
export const WEB_PORT = 5173;
export const API_ORIGIN = `http://127.0.0.1:${API_PORT}`;
export const WEB_SCHEME = process.env.ZK_E2E_HTTPS === "1" ? "https" : "http";
export const WEB_ORIGIN = `${WEB_SCHEME}://localhost:${WEB_PORT}`;

const STARTUP_TIMEOUT_MS = 60_000;

async function waitForHttp(url: string, timeoutMs = STARTUP_TIMEOUT_MS): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok || res.status < 500) return;
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${url}: ${String(lastError)}`);
}

function ensureWasmPackage(): void {
  const wasmPkg = path.join(REPO_ROOT, "crates/zk-wasm/pkg/zk_wasm.js");
  if (!fs.existsSync(wasmPkg)) {
    throw new Error(
      `Missing WASM package at ${wasmPkg}. Build it first:\n` +
        "  wasm-pack build --target web crates/zk-wasm --out-dir pkg"
    );
  }
}

function ensureServerBinary(): string {
  const bin = path.join(REPO_ROOT, "target/debug/zk-server");
  if (!fs.existsSync(bin)) {
    execFileSync("cargo", ["build", "-p", "zk-server"], {
      cwd: REPO_ROOT,
      stdio: "inherit",
    });
  }
  return bin;
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  ensureWasmPackage();
  const serverBin = ensureServerBinary();

  // Build the production bundle that `vite preview` will serve.
  execFileSync("npm", ["run", "build"], { cwd: WEB_DIR, stdio: "inherit" });

  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "zk107-e2e-"));
  const dbPath = path.join(stateDir, "server.db");

  // Optional HTTPS mode (ZK_E2E_HTTPS=1): mirrors the deployment requirement that
  // the app and API share one TLS origin, using a throwaway self-signed cert.
  const previewEnv: NodeJS.ProcessEnv = { ...process.env, VITE_API_URL: API_ORIGIN };
  if (WEB_SCHEME === "https") {
    // The setup process health-checks the throwaway self-signed origin; the
    // browser is configured with `ignoreHTTPSErrors` instead.
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const certPath = path.join(stateDir, "cert.pem");
    const keyPath = path.join(stateDir, "key.pem");
    execFileSync(
      "openssl",
      [
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", keyPath, "-out", certPath,
        "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost",
      ],
      { stdio: "ignore" }
    );
    previewEnv.ZK_E2E_HTTPS_CERT = certPath;
    previewEnv.ZK_E2E_HTTPS_KEY = keyPath;
  }

  const children: ChildProcess[] = [];
  const shutdown = async () => {
    for (const child of children.reverse()) {
      if (!child.pid || child.killed) continue;
      child.kill("SIGTERM");
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
    for (const child of children) {
      if (child.pid && !child.killed) {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }
    }
    fs.rmSync(stateDir, { recursive: true, force: true });
  };

  const server = spawn(serverBin, [], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      ZK_SERVER_HOST: "127.0.0.1",
      ZK_SERVER_PORT: String(API_PORT),
      ZK_SERVER_DB_PATH: dbPath,
      ZK_SERVER_LOG_LEVEL: "warn",
      ZK_SERVER_LOG_FORMAT: "text",
      // The browser page is the same origin that hosts the API proxy.
      ZK_WEBAUTHN_RP_ID: "localhost",
      ZK_WEBAUTHN_ORIGIN: WEB_ORIGIN,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(server);
  server.stderr?.on("data", (chunk) => process.stderr.write(`[zk-server] ${chunk}`));

  const preview = spawn(path.join(WEB_DIR, "node_modules/.bin/vite"), ["preview", "--port", String(WEB_PORT), "--strictPort"], {
    cwd: WEB_DIR,
    env: previewEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(preview);
  preview.stderr?.on("data", (chunk) => process.stderr.write(`[vite] ${chunk}`));

  try {
    await waitForHttp(`${API_ORIGIN}/health`);
    await waitForHttp(`${WEB_ORIGIN}/`);
    // Confirm the same-origin proxy actually reaches the API.
    await waitForHttp(`${WEB_ORIGIN}/v1/health`);
  } catch (err) {
    await shutdown();
    throw err;
  }

  return shutdown;
}
