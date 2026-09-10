# Web Client Security Headers & Content Security Policy (CSP)

This document specifies the browser hardening, Content Security Policy (CSP), and HTTP security headers enforced by the Zero-Knowledge note-taking web client, in accordance with **MASTER_SPEC.md § 18**, **SEC-001**, **SEC-002**, **SEC-003**, and **SEC-009**.

---

## 1. Zero-Knowledge Threat Model & Browser Invariants

Because user notes are encrypted client-side and plaintext is only held in browser process memory when the vault is unlocked, the web browser environment is the most critical trust boundary.

The browser security headers serve five primary objectives:
1. **Prevent Code Injection (XSS)**: Guarantee that attacker-controlled content cannot execute arbitrary JavaScript in the application origin.
2. **Prevent Network Exfiltration**: Prevent compromised libraries or rogue network calls from transmitting decrypted note plaintext or keys (SEC-001).
3. **Prevent Clickjacking & UI Redressing**: Ensure the vault unlock screen and note editor cannot be embedded within external frames or iframes.
4. **Isolate Cryptographic Memory**: Protect Web Worker linear memory and cryptographic sessions from cross-origin Spectre and side-channel timing attacks.
5. **Zero Third-Party Dependency**: Enforce an absolute ban on external CDNs, analytics, tracking beacons, tag managers, and ad networks.

---

## 2. Enforced Security Headers

Every HTTP response serving the web application and its API endpoints MUST include the following headers:

| Header | Production Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;` | Comprehensive capability restriction |
| `X-Frame-Options` | `DENY` | Anti-clickjacking (legacy browser defense) |
| `X-Content-Type-Options` | `nosniff` | Disables MIME type sniffing |
| `Referrer-Policy` | `no-referrer` | Zero URL/path leakage on outbound requests |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates browsing context group |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Enables cross-origin isolation for WASM threads/memory |
| `Cross-Origin-Resource-Policy` | `same-origin` | Forbids other origins from loading application assets |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` | Disables unused sensor & hardware browser APIs |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | 2-year HSTS enforcement |

---

## 3. Detailed CSP Directive Rationale

### `default-src 'none'`
Default-deny posture. Any resource type not explicitly whitelisted is rejected by default.

### `script-src 'self' 'wasm-unsafe-eval'`
- `'self'`: Allows scripts only from the exact origin of the application.
- `'wasm-unsafe-eval'`: Required under CSP Level 3 to compile and instantiate WebAssembly modules (`WebAssembly.compile`, `WebAssembly.instantiate`) for the cryptographic core.
- **Banned**: `'unsafe-inline'` for JavaScript is strictly forbidden. All application scripts are loaded from external modules or workers. Third-party script CDNs are prohibited.

### `style-src 'self' 'unsafe-inline'`
- `'self'`: Allows local stylesheets.
- `'unsafe-inline'`: Permitted strictly for React dynamic component inline style attributes (`style={{ ... }}`).

### `connect-src 'self'`
Limits all `fetch()`, `XMLHttpRequest`, and WebSocket sync calls to the application's origin API server. Even if a script injection were attempted, outbound network traffic to third-party endpoints is blocked at the browser network layer, guaranteeing note plaintext cannot leave the device unencrypted (SEC-001).

### `img-src 'self' data: blob:`
- `'self'`: Application icons and images.
- `data:`: Base64-encoded SVG icons.
- `blob:`: Decrypted attachment image previews created via `URL.createObjectURL(blob)`.

### `font-src 'self'`
Disallows external font CDNs (e.g. Google Fonts) to prevent user IP tracking and external dependency failures.

### `object-src 'none'`
Completely disables legacy plugins (Flash, Java applets, Silverlight).

### `base-uri 'self'`
Prevents malicious manipulation of `<base href="...">`, which could redirect relative script or worker URLs.

### `form-action 'self'`
Restricts form submission actions to the application origin.

### `frame-ancestors 'none'`
Modern CSP anti-clickjacking defense. Explicitly forbids embedding this application within an `<iframe>`, `<frame>`, `<embed>`, or `<object>` on any origin.

### `upgrade-insecure-requests`
Instructs the browser to upgrade all HTTP requests to HTTPS before transmission.

---

## 4. Cross-Origin Isolation (COOP, COEP, CORP)

The combination of:
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: same-origin`

activates **cross-origin isolation** in modern browsers (`window.crossOriginIsolated === true`).

Benefits:
1. **Side-Channel Mitigation**: Protects linear memory containing the active 32-byte `VaultKey` against Spectre-style microarchitectural attacks.
2. **High-Precision Timers**: Allows safe usage of high-resolution performance timers without exposure to timing side-channels.
3. **Web Worker Isolation**: Ensures Web Workers cannot share unapproved cross-origin buffers or memory.

---

## 5. Deployment Configurations

### 5.1 Native Axum Server
The Rust backend server (`apps/server`) automatically injects all security headers on every response (both API and error responses) via `security_headers_middleware`.

### 5.2 Nginx Reverse Proxy
When deploying behind Nginx, include the configuration snippet from `deploy/nginx/security-headers.conf`:

```nginx
# Include in server block
include /etc/nginx/snippets/security-headers.conf;
```

Full configuration example is available at `deploy/nginx/notes.conf`.

### 5.3 Caddy Server
When deploying behind Caddy, configure headers in the `Caddyfile`:

```caddy
header {
    Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "no-referrer"
    Cross-Origin-Opener-Policy "same-origin"
    Cross-Origin-Embedder-Policy "require-corp"
    Cross-Origin-Resource-Policy "same-origin"
    Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
}
```

Full Caddy configuration is available at `deploy/caddy/Caddyfile`.

### 5.4 Static Hosting (S3 / CloudFront / GitHub Pages)
When serving `apps/web/index.html` statically without a reverse proxy, the `<meta http-equiv="Content-Security-Policy">` tag inside `apps/web/index.html` provides origin-level enforcement for CSP, `nosniff`, and `no-referrer`.

---

## 6. Verification and Auditing

To verify security headers on a deployed instance:

```bash
curl -I https://notes.example.com/
```

Verify that all headers are present with `HTTP/2 200` or `HTTP/1.1 200`.

To inspect with security tools:
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- Chrome DevTools -> Application -> Security Panel
