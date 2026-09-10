/**
 * Browser Security Headers & CSP Verification Tests (ZK-069).
 *
 * Verifies all acceptance criteria:
 * 1. Restrictive Content Security Policy (CSP).
 * 2. No third-party runtime script requirements.
 * 3. No inline unsafe script requirements.
 * 4. Clickjacking and MIME-type hardening (X-Frame-Options, nosniff, no-referrer).
 * 5. Production deployment configurations and documentation exist.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webRootDir = fs.existsSync(path.resolve(__dirname, "package.json"))
  ? __dirname
  : fs.existsSync(path.resolve(__dirname, "../package.json"))
  ? path.resolve(__dirname, "..")
  : path.resolve(__dirname, "../..");
const repoRootDir = path.resolve(webRootDir, "../..");

test("CSP: index.html contains strict Content-Security-Policy meta tag", () => {
  const indexHtmlPath = path.join(webRootDir, "index.html");
  assert.ok(fs.existsSync(indexHtmlPath), "apps/web/index.html must exist");

  const html = fs.readFileSync(indexHtmlPath, "utf-8");

  // Extract CSP content
  const cspMatch = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  assert.ok(cspMatch, "index.html must contain a Content-Security-Policy meta tag");

  const csp = cspMatch[1]!;

  // Must include default-src 'none'
  assert.ok(csp.includes("default-src 'none'"), "CSP must include default-src 'none'");

  // Must include script-src 'self' 'wasm-unsafe-eval'
  assert.ok(csp.includes("script-src 'self' 'wasm-unsafe-eval'"), "CSP must permit self and wasm-unsafe-eval");

  // Must NOT permit unsafe-inline for scripts
  const scriptSrcPart = csp.split(";").find((part) => part.trim().startsWith("script-src")) || "";
  assert.ok(!scriptSrcPart.includes("'unsafe-inline'"), "script-src must NOT permit unsafe-inline");

  // Must restrict connect-src to 'self' (zero plaintext exfiltration)
  assert.ok(csp.includes("connect-src 'self'"), "connect-src must be restricted to 'self'");

  // Must disable object plugins
  assert.ok(csp.includes("object-src 'none'"), "object-src must be 'none'");

  // Must include frame-ancestors 'none' (clickjacking defense)
  assert.ok(csp.includes("frame-ancestors 'none'"), "frame-ancestors must be 'none'");

  // Must include base-uri 'self'
  assert.ok(csp.includes("base-uri 'self'"), "base-uri must be 'self'");
});

test("Hardening: index.html contains nosniff and no-referrer meta tags", () => {
  const indexHtmlPath = path.join(webRootDir, "index.html");
  const html = fs.readFileSync(indexHtmlPath, "utf-8");

  assert.ok(
    html.includes('http-equiv="X-Content-Type-Options" content="nosniff"'),
    "index.html must contain nosniff meta tag"
  );
  assert.ok(
    html.includes('name="referrer" content="no-referrer"'),
    "index.html must contain no-referrer meta tag"
  );
});

test("Zero Third-Party Runtime Scripts: index.html contains no external script tags", () => {
  const indexHtmlPath = path.join(webRootDir, "index.html");
  const html = fs.readFileSync(indexHtmlPath, "utf-8");

  // Regex for any <script ... src="http..." or https://
  const externalScriptRegex = /<script[^>]+src=["'](https?:|\/\/)[^"']+["']/gi;
  const matches = html.match(externalScriptRegex);
  assert.equal(matches, null, "index.html must not include any external script tags");

  // Verify no inline executable script tags
  const inlineScriptRegex = /<script(?![^>]*type=["']module["'][^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
  const inlineMatches = html.match(inlineScriptRegex);
  assert.equal(inlineMatches, null, "index.html must not contain inline JavaScript code");
});

test("Zero Third-Party Runtime Dependencies: package.json has no tracker, analytics, or CDN libraries", () => {
  const packageJsonPath = path.join(webRootDir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));

  const runtimeDeps = Object.keys(pkg.dependencies || {});

  // Only react, react-dom, and local zk-wasm are permitted runtime dependencies
  const allowedRuntimeDeps = new Set(["react", "react-dom", "zk-wasm"]);

  for (const dep of runtimeDeps) {
    assert.ok(
      allowedRuntimeDeps.has(dep),
      `Dependency ${dep} is not in the allowed runtime dependencies list`
    );
  }
});

test("Deployment configurations exist for Nginx and Caddy with strict security headers", () => {
  const nginxConfPath = path.join(repoRootDir, "deploy/nginx/security-headers.conf");
  assert.ok(fs.existsSync(nginxConfPath), "deploy/nginx/security-headers.conf must exist");
  const nginxContent = fs.readFileSync(nginxConfPath, "utf-8");
  assert.ok(nginxContent.includes("Content-Security-Policy"));
  assert.ok(nginxContent.includes("X-Frame-Options \"DENY\""));
  assert.ok(nginxContent.includes("X-Content-Type-Options \"nosniff\""));
  assert.ok(nginxContent.includes("Cross-Origin-Opener-Policy \"same-origin\""));
  assert.ok(nginxContent.includes("Cross-Origin-Embedder-Policy \"require-corp\""));

  const caddyPath = path.join(repoRootDir, "deploy/caddy/Caddyfile");
  assert.ok(fs.existsSync(caddyPath), "deploy/caddy/Caddyfile must exist");
  const caddyContent = fs.readFileSync(caddyPath, "utf-8");
  assert.ok(caddyContent.includes("Content-Security-Policy"));
  assert.ok(caddyContent.includes("X-Frame-Options \"DENY\""));

  const docPath = path.join(repoRootDir, "docs/deployment/web-security.md");
  assert.ok(fs.existsSync(docPath), "docs/deployment/web-security.md must exist");
});
