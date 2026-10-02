import { defineConfig, devices } from "@playwright/test";

const HTTPS_MODE = process.env.ZK_E2E_HTTPS === "1";

/**
 * Browser-level acceptance configuration for ZK-107.
 *
 * The suite drives the real production bundle (`vite preview` serving `dist/`)
 * against the real Rust `zk-server` over a real HTTP origin, with a Chromium
 * virtual WebAuthn authenticator standing in for a platform passkey. Nothing is
 * mocked: IndexedDB, the Web Worker, the WASM crypto core, the authenticated
 * session, and the `/v1` sync protocol are all exercised end to end.
 *
 * `e2e/global-setup.ts` owns the server/preview lifecycle so the two browsers
 * share one deterministic, disposable account database.
 */
export default defineConfig({
  testDir: "./e2e",
  // Real crypto (Argon2id) plus multi-browser convergence needs generous time.
  timeout: 120_000,
  expect: { timeout: 20_000 },
  // One worker: every spec shares a single server process and origin.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : [["list"]],
  outputDir: "e2e-results",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: `${HTTPS_MODE ? "https" : "http"}://localhost:5173`,
    // Only relevant in ZK_E2E_HTTPS=1 mode, where the origin uses a throwaway cert.
    ignoreHTTPSErrors: HTTPS_MODE,
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
