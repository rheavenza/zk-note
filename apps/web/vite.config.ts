import fs from "node:fs";
import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Dev-mode CSP transform plugin.
 * In development, Vite injects an inline script for React Refresh and connects
 * to a local WebSocket for HMR. This plugin permits inline scripts and ws: in
 * dev mode only, preserving strict CSP headers in production builds.
 */
function devCspPlugin(): Plugin {
  return {
    name: "dev-csp",
    apply: "serve",
    transformIndexHtml(html) {
      return html
        .replace(
          /script-src 'self' 'wasm-unsafe-eval';/g,
          "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval';"
        )
        .replace(
          /connect-src 'self';/g,
          "connect-src 'self' ws://localhost:5173;"
        );
    },
  };
}

export default defineConfig({
  plugins: [react(), devCspPlugin()],
  server: {
    port: 5173,
    strictPort: true,
    host: "localhost",
    fs: {
      allow: ["../.."],
    },
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    proxy: {
      "/v1": {
        target: process.env.VITE_API_URL || "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 5173,
    host: "localhost",
    // Browser-acceptance HTTPS mode (ZK-107): serve the same-origin app over TLS
    // with a throwaway certificate so the deployment HTTPS assumption is exercised.
    https:
      process.env.ZK_E2E_HTTPS_CERT && process.env.ZK_E2E_HTTPS_KEY
        ? {
            cert: fs.readFileSync(process.env.ZK_E2E_HTTPS_CERT),
            key: fs.readFileSync(process.env.ZK_E2E_HTTPS_KEY),
          }
        : undefined,
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
  build: {
    emptyOutDir: false,
  },
  worker: {
    format: "es",
  },
});
