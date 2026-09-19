# Browser XSS & Content Security Policy (CSP) Security Review (ZK-094)

## 1. Executive Summary

This document provides the security review of the browser client for the Zero-Knowledge Note-Taking application, evaluating Cross-Site Scripting (XSS) defenses, Content Security Policy (CSP) enforcement, dangerous HTML rendering sinks, and third-party script isolation under **SEC-001**, **SEC-002**, **SEC-003**, and **SEC-009**.

The client web application is designed with defense-in-depth:
1. **Zero-Knowledge Core**: Decryption keys and plaintext notes exist only in memory; keys reside strictly within a dedicated Web Worker.
2. **Strict CSP**: Completely disables external script loading, disallows inline scripts, and restricts network endpoints strictly to `'self'`.
3. **Safe Rendering Engine**: Zero dangerous `dangerouslySetInnerHTML` sinks outside of the audited, escaping markdown parser.
4. **Supply-Chain Lockdown**: Zero third-party CDN scripts, zero trackers, and zero external font or stylesheet dependencies.

---

## 2. Content Security Policy (CSP) Specification & Analysis

The application enforces a strict Content Security Policy defined in `apps/web/index.html` (for offline/standalone usage) and injected via HTTP response headers in production deployment configs (`deploy/nginx/security-headers.conf`, `deploy/caddy/Caddyfile`).

```http
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;
```

### Directive Security Justifications:

| Directive | Value | Security Impact / Threat Mitigated |
| :--- | :--- | :--- |
| `default-src` | `'none'` | **Default Deny**: Blocks any unlisted resource types from loading. |
| `script-src` | `'self' 'wasm-unsafe-eval'` | **No Remote / No Inline Scripts**: Blocks external script injection. Permits WebAssembly compilation (`'wasm-unsafe-eval'`) while prohibiting dynamic JavaScript `eval()` or inline `<script>` tags. |
| `style-src` | `'self' 'unsafe-inline'` | Allows application styles and React inline style attributes. No external stylesheets. |
| `connect-src` | `'self'` | **Exfiltration Defense**: Strictly prevents `fetch`, `XMLHttpRequest`, or `WebSocket` connections to external origins, mitigating data exfiltration even under hypothetical DOM injection. |
| `img-src` | `'self' data: blob:` | Allows local UI icons, decrypted attachment image previews (`blob:`), and inline SVG icons (`data:`). |
| `font-src` | `'self'` | Prohibits external fonts (e.g. Google Fonts) to prevent user tracking. |
| `object-src` | `'none'` | Completely disables legacy browser plugins (Flash, Java, ActiveX, NPAPI). |
| `base-uri` | `'self'` | Prevents `<base>` tag injection attacks that rewrite relative URLs. |
| `form-action` | `'self'` | Prevents form submission redirection to attacker servers. |
| `frame-ancestors` | `'none'` | **Clickjacking Defense**: Prevents embedding the application in `<iframe>`, `<frame>`, `<embed>`, or `<object>` on any other origin (equivalent to `X-Frame-Options: DENY`). |
| `upgrade-insecure-requests` | *present* | Forces browser to upgrade any accidental HTTP requests to HTTPS. |

---

## 3. Dangerous HTML Rendering Sink Inventory

All DOM sinks in `apps/web` were audited for unsafe string-to-DOM conversion:

| Component / File | Sink | Input Source | Sanitization & Mitigations | Status |
| :--- | :--- | :--- | :--- | :--- |
| `MarkdownEditor.tsx` | `dangerouslySetInnerHTML` | Note body (user Markdown) | Passed through `renderMarkdown(selectedNote.body)`. `escapeHtml` escapes `&`, `<`, `>`, `"`, `'` across all block elements before tag rendering. `sanitizeUrl` disallows quotes, whitespace, control characters, and non-http(s)/local schemes. Link href attributes are additionally escaped with `escapeHtml`. | **AUDITED & SAFE** |
| `NotesList.tsx` | Standard JSX `{note.title}` | Note title | Native React text node rendering (automatic character entity escaping). | **SAFE** |
| `DeviceManagementModal.tsx` | Standard JSX | Device metadata | Native React text node rendering. | **SAFE** |
| `UnlockScreen.tsx` | Standard JSX `<input>` | Passphrase, Recovery Key | Passphrase never reflected in DOM attributes; type is `password`. | **SAFE** |
| `ConflictResolverModal.tsx` | Standard JSX | Conflict versions | Plaintext comparisons rendered via text nodes. | **SAFE** |

---

## 4. Markdown Sanitization Deep-Dive & Test Coverage

The safe markdown renderer in `apps/web/src/utils/markdown.ts` was tested against standard and advanced XSS payloads in `apps/web/test/xss-csp-review.test.ts`:

1. **Script Tag Neutralization**:
   - Tested: `<script>alert(1)</script>`, `<SCRIPT SRC='evil.com'></SCRIPT>`, `<script/xss>`, malformed nested `<SCRIPT>` tags.
   - Result: All tags escaped to `&lt;script...&gt;`, neutralizing browser execution.
2. **Event Handler Neutralization**:
   - Tested: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<body onload=alert(1)>`, `<input autofocus onfocus=alert(1)>`.
   - Result: Bracket escaping prevents browser DOM parser from instantiating elements or binding event handlers.
3. **Dangerous URI Schemes**:
   - Tested: `javascript:`, `JAVASCRIPT:`, `vbscript:`, `data:text/html`, `file:`, and obfuscated URI schemes with whitespace/null-byte control chars.
   - Result: All neutralized to `href="#"`.
4. **Attribute Breakouts**:
   - Tested: `[Click](https://example.com" onclick="alert(1))`, `[Click](https://example.com' onmouseover='alert(1))`.
   - Result: URLs containing quotes, backslashes, spaces, or control characters are rejected to `#`, and all `href` values are wrapped with `escapeHtml`.

---

## 5. Additional Browser Hardening Headers

Production web servers (Nginx / Caddy) must send the following hardening headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- **Nosniff**: Prevents MIME confusion attacks where text or HTML payloads are interpreted as scripts or stylesheets.
- **COOP / COEP**: Enables cross-origin isolation, unlocking high-resolution timers and protecting process memory against Spectre-style browser side-channel leaks.
- **No-Referrer**: Prevents the browser from leaking document URLs, query strings, or paths to external sites during outbound navigation.

---

## 6. Verification

Continuous integration enforces this security baseline via:
- `apps/web/test/security-headers.test.ts`
- `apps/web/test/xss-csp-review.test.ts`
- Automated checks in `./scripts/ci.sh` gate 8.
