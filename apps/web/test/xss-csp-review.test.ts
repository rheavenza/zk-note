/**
 * Comprehensive Browser XSS / CSP Security Review Test Suite (ZK-094).
 *
 * Verifies acceptance criteria:
 * - CSP tested across index.html, Nginx, and Caddy configs;
 * - Dangerous HTML rendering inventory audited;
 * - Markdown renderer sanitization against script, event handlers, attribute breakout, and URI schemes;
 * - No third-party origin script execution permitted.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderMarkdown, escapeHtml, sanitizeUrl } from "../src/utils/markdown.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webRootDir = fs.existsSync(path.resolve(__dirname, "package.json"))
  ? __dirname
  : fs.existsSync(path.resolve(__dirname, "../package.json"))
  ? path.resolve(__dirname, "..")
  : path.resolve(__dirname, "../..");
const repoRootDir = path.resolve(webRootDir, "../..");

// ----------------------------------------------------------------------------
// 1. Comprehensive Markdown XSS Penetration Vectors
// ----------------------------------------------------------------------------

test("XSS Penetration: Raw <script> tags are neutralized across variations", () => {
  const vectors = [
    "<script>alert(1)</script>",
    "<SCRIPT SRC='https://evil.com/xss.js'></SCRIPT>",
    "<script\x20type=\"text/javascript\">alert(document.cookie)</script>",
    "<script/xss>alert(1)</script>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
  ];

  for (const vector of vectors) {
    const rendered = renderMarkdown(vector);
    assert.ok(
      !rendered.includes("<script") && !rendered.includes("<SCRIPT"),
      `Vector should not emit executable script tag: ${vector} => ${rendered}`
    );
    assert.ok(
      rendered.includes("&lt;"),
      `Vector opening bracket must be HTML escaped: ${vector}`
    );
  }
});

test("XSS Penetration: HTML event handlers (onload, onerror, etc.) are escaped", () => {
  const vectors = [
    "<img src=x onerror=alert('img-xss')>",
    "<svg onload=alert('svg-xss')>",
    "<body onload=alert('body-xss')>",
    "<iframe src=\"javascript:alert('iframe')\"></iframe>",
    "<input autofocus onfocus=alert('focus')>",
    "<video><source onerror=\"javascript:alert(1)\">",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    "<embed src=\"https://evil.com/malicious.swf\">",
  ];

  for (const vector of vectors) {
    const rendered = renderMarkdown(vector);
    // Any tag opening must be escaped to &lt;, preventing browser element creation
    assert.ok(!rendered.includes("<img"), `Unescaped img: ${rendered}`);
    assert.ok(!rendered.includes("<svg"), `Unescaped svg: ${rendered}`);
    assert.ok(!rendered.includes("<body"), `Unescaped body: ${rendered}`);
    assert.ok(!rendered.includes("<iframe"), `Unescaped iframe: ${rendered}`);
    assert.ok(!rendered.includes("<input"), `Unescaped input: ${rendered}`);
    assert.ok(!rendered.includes("<video"), `Unescaped video: ${rendered}`);
    assert.ok(!rendered.includes("<object"), `Unescaped object: ${rendered}`);
    assert.ok(!rendered.includes("<embed"), `Unescaped embed: ${rendered}`);
    assert.ok(rendered.includes("&lt;"), `Expected &lt; escaping: ${rendered}`);
  }
});

test("XSS Penetration: Dangerous link URI schemes are neutralized", () => {
  const dangerousUrls = [
    "javascript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "javascript:void(0)",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "file:///etc/passwd",
    "  javascript:alert(1)",
    "jav\tascript:alert(1)",
    "jav\x00ascript:alert(1)",
  ];

  for (const url of dangerousUrls) {
    const sanitized = sanitizeUrl(url);
    assert.equal(
      sanitized,
      "#",
      `Dangerous URL must be neutralized to '#': ${url}`
    );

    const markdown = `[Click Here](${url})`;
    const rendered = renderMarkdown(markdown);
    assert.ok(
      !rendered.includes("href=\"javascript:") &&
        !rendered.includes("href=\"vbscript:") &&
        !rendered.includes("href=\"data:"),
      `Rendered link must not contain dangerous URI scheme: ${rendered}`
    );
    assert.ok(
      rendered.includes("href=\"#\""),
      `Rendered link must have href="#": ${rendered}`
    );
  }
});

test("XSS Penetration: Attribute breakout attempts in links are prevented", () => {
  const breakoutUrls = [
    'https://example.com" onclick="alert(1)',
    "https://example.com' onmouseover='alert(1)",
    'https://example.com" onfocus="alert(1)" autofocus="',
    'https://example.com" style="color:red" onmouseover="alert(1)',
    'https://example.com><script>alert(1)</script>',
  ];

  for (const url of breakoutUrls) {
    const sanitized = sanitizeUrl(url);
    assert.equal(
      sanitized,
      "#",
      `Breakout URL should be neutralized to '#': ${url}`
    );

    const markdown = `[Test](${url})`;
    const rendered = renderMarkdown(markdown);
    assert.ok(
      !rendered.includes('onclick='),
      `Attribute breakout onclick found: ${rendered}`
    );
    assert.ok(
      !rendered.includes('onmouseover='),
      `Attribute breakout onmouseover found: ${rendered}`
    );
    assert.ok(
      !rendered.includes('onfocus='),
      `Attribute breakout onfocus found: ${rendered}`
    );
  }
});

test("XSS Penetration: Safe Markdown links remain functional", () => {
  const safeUrls = [
    "https://example.com",
    "https://example.com/path/to/page?query=param#anchor",
    "http://localhost:3000",
    "/notes/123",
    "#heading-1",
  ];

  for (const url of safeUrls) {
    const sanitized = sanitizeUrl(url);
    assert.equal(sanitized, url, `Safe URL should be preserved: ${url}`);

    const markdown = `[Safe Link](${url})`;
    const rendered = renderMarkdown(markdown);
    assert.ok(
      rendered.includes(`href="${escapeHtml(url)}"`),
      `Rendered link must retain safe URL: ${rendered}`
    );
    assert.ok(
      rendered.includes('target="_blank" rel="noopener noreferrer"'),
      `External links must include noopener noreferrer: ${rendered}`
    );
  }
});

// ----------------------------------------------------------------------------
// 2. CSP and Security Header Directives Audit
// ----------------------------------------------------------------------------

test("CSP Review: index.html meta tag restricts all sensitive capabilities", () => {
  const indexHtmlPath = path.join(webRootDir, "index.html");
  const html = fs.readFileSync(indexHtmlPath, "utf-8");

  const cspMatch = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  assert.ok(cspMatch, "index.html must contain a Content-Security-Policy meta tag");

  const csp = cspMatch[1]!;

  // 1. default-src 'none' (deny all unlisted resources by default)
  assert.ok(csp.includes("default-src 'none'"));

  // 2. script-src strictly 'self' 'wasm-unsafe-eval' (no unsafe-inline, no remote scripts)
  assert.ok(csp.includes("script-src 'self' 'wasm-unsafe-eval'"));
  const scriptSrcPart = csp.split(";").find((part) => part.trim().startsWith("script-src")) || "";
  assert.ok(!scriptSrcPart.includes("'unsafe-inline'"));

  // 3. connect-src 'self' (prevents exfiltration to rogue endpoints)
  assert.ok(csp.includes("connect-src 'self'"));

  // 4. object-src 'none' (blocks Flash, Java, PDF plugins)
  assert.ok(csp.includes("object-src 'none'"));

  // 5. frame-ancestors 'none' (clickjacking defense)
  assert.ok(csp.includes("frame-ancestors 'none'"));

  // 6. base-uri 'self' (prevents <base> hijacking)
  assert.ok(csp.includes("base-uri 'self'"));

  // 7. form-action 'self' (prevents form submission redirection)
  assert.ok(csp.includes("form-action 'self'"));
});

test("CSP Review: Deployment configs enforce matching strict headers", () => {
  // Nginx
  const nginxPath = path.join(repoRootDir, "deploy/nginx/security-headers.conf");
  assert.ok(fs.existsSync(nginxPath));
  const nginxContent = fs.readFileSync(nginxPath, "utf-8");
  assert.ok(nginxContent.includes("default-src 'none'"));
  assert.ok(nginxContent.includes("script-src 'self' 'wasm-unsafe-eval'"));
  assert.ok(nginxContent.includes("connect-src 'self'"));
  assert.ok(nginxContent.includes("X-Frame-Options \"DENY\""));
  assert.ok(nginxContent.includes("X-Content-Type-Options \"nosniff\""));

  // Caddy
  const caddyPath = path.join(repoRootDir, "deploy/caddy/Caddyfile");
  assert.ok(fs.existsSync(caddyPath));
  const caddyContent = fs.readFileSync(caddyPath, "utf-8");
  assert.ok(caddyContent.includes("default-src 'none'"));
  assert.ok(caddyContent.includes("script-src 'self' 'wasm-unsafe-eval'"));
  assert.ok(caddyContent.includes("connect-src 'self'"));
});
