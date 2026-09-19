# `@zk-notes/web` — Zero-Knowledge Web Client

The official browser application for the Zero-Knowledge note-taking system. Built with [React 18](https://react.dev/), [TypeScript](https://www.typescriptlang.org/), and client-side [WebAssembly](https://webassembly.org/) compiled from the shared Rust core (`zk-wasm`).

---

## 1. Architecture & Security Isolation

The web client is designed around strict process isolation and browser security standards:

```text
┌────────────────────────────────────────────────────────┐
│ Modern Web Browser                                     │
│                                                        │
│  ┌─────────────────────────┐   Commands / Views       │
│  │ Main Thread (DOM / UI)  │◄───────────────────────┐  │
│  │ - React 18 Components   │                        │  │
│  │ - Markdown Live Preview │                        │  │
│  │ - Conflict Visualizer   │                        │  │
│  └────────────┬────────────┘                        ▼  │
│               │ postMessage (RPC)       ┌──────────────┴─────────────┐
│               ▼                         │ Web Worker (zk-wasm)       │
│  ┌─────────────────────────┐            │ - Argon2id KDF             │
│  │ Encrypted IndexedDB     │            │ - XChaCha20-Poly1305 AEAD  │
│  │ - objects (ciphertext)  │            │ - Memory Scrubbing         │
│  │ - mutations (CAS queue) │            │ - In-Memory Search Index   │
│  │ - conflict records      │            └──────────────┬─────────────┘
│  └─────────────────────────┘                           │
│                                                        │
└────────────────────────┼───────────────────────────────┘
                         │ TLS 1.3 (Ciphertext Only)
                         ▼
               ┌───────────────────┐
               │ zk-server (Cloud) │
               └───────────────────┘
```

### Key Security Invariants
- **Web Worker RPC Boundary**: All cryptographic primitives and linear memory holding the decrypted `VaultKey` reside in an isolated Web Worker thread. Key material is never stored in React component state.
- **Cross-Origin Isolation**: Protected by `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` to mitigate Spectre side-channel attacks against cryptographic memory.
- **Zero-Knowledge IndexedDB (`SEC-009`)**: Local browser storage (`zk_notes_db`) stores exclusively encrypted envelopes.
- **Zero Third-Party Dependencies**: Absolute ban on external CDN scripts, tracking beacons, tag managers, Google Fonts, and analytics SDKs.

---

## 2. Development Setup

### Prerequisites
- Node.js v20.x or v22.x LTS and npm
- Rust toolchain with `wasm32-unknown-unknown` target
- `wasm-pack` 0.12+ (`cargo install wasm-pack`)

### Step 1: Compile WebAssembly Core Package
From the repository root:
```bash
wasm-pack build --target web crates/zk-wasm --out-dir pkg
```
This generates the WebAssembly binary and JavaScript bindings in `crates/zk-wasm/pkg/`.

### Step 2: Install Node Dependencies
```bash
cd apps/web
npm install
```

### Step 3: Run Tests & Typecheck
```bash
npm run typecheck
npm test
```

### Step 4: Start Local Development Server
```bash
npm run dev
```
Open your browser to `http://localhost:5173/`.

---

## 3. Web Application Features

### 3.1 Vault Setup & Authentication
- **First-Time Setup**: Prompts for master passphrase, derives KEK with Argon2id, and displays a formatted 288-bit recovery key with typo-detection checksum.
- **Biometric WebAuthn Passkeys**: Register platform authenticators (Touch ID, Windows Hello, YubiKeys) for seamless hardware-backed device authorization.
- **Auto-Lock Policy**: Configurable idle timeout automatically purges decrypted keys and in-memory search indices from RAM when inactive.

### 3.2 Live Markdown Editor & Autosave
- Side-by-side or tabbed live Markdown editor.
- Automatic draft persistence and re-encryption.
- Safe HTML escaping neutralizing raw `<script>` tags, event handlers (`onload`, `onerror`), and dangerous URI schemes (`javascript:`, `vbscript:`).

### 3.3 Fast In-Memory Full-Text Search (`Cmd+K` / `Ctrl+K`)
- Ephemeral search across note titles, Markdown bodies, and tags.
- Instant contextual snippet extraction around matched search terms.
- Zero plaintext index persistence on disk; completely cleared on vault lock.

### 3.4 4-Way Visual Conflict Resolver
When offline edits conflict with changes made on another device, the UI surfaces an intuitive conflict resolution workspace:
1. **Automatic 3-Way Merge (`diff3`)**: View candidate note cleanly merging non-overlapping lines.
2. **Keep Local**: Accept local device edits and schedule a push to overwrite remote.
3. **Keep Remote**: Discard local changes and accept remote revision.
4. **Preserve Both**: Accept remote revision and duplicate local edits into a separate note to prevent accidental data loss.

### 3.5 Streaming Encrypted Attachments
- Drag-and-drop file upload.
- Client-side 256 KiB chunking and subkey derivation.
- Streaming client decryption and inline image preview via safe `blob:` URLs.

---

## 4. Production Build & Deployment

### Step 1: Compile Production Web Bundle
```bash
cd apps/web
npm run build
```
The optimized static bundle is output to `apps/web/dist/`.

### Step 2: Deploy Static Bundle with Strict CSP Headers

Deploy the contents of `dist/` behind Nginx or Caddy. Ensure all mandatory security headers and Content Security Policy directives are injected.

#### Nginx Configuration Snippet:
```nginx
server {
    listen 443 ssl http2;
    server_name notes.example.com;

    root /var/www/zk-notes-web/dist;
    index index.html;

    # Security Headers
    add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Single Page Application routing
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy to zk-server
    location /v1/ {
        proxy_pass http://127.0.0.1:8080/v1/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Caddy Configuration Snippet:
```caddy
notes.example.com {
    root * /var/www/zk-notes-web/dist
    file_server

    header {
        Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Embedder-Policy "require-corp"
        Cross-Origin-Resource-Policy "same-origin"
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    }

    # Reverse proxy API traffic to zk-server
    handle /v1/* {
        reverse_proxy 127.0.0.1:8080
    }

    # SPA routing fallback
    try_files {path} /index.html
}
```

---

## 5. Security & Threat Considerations

Because browser clients depend on code delivered over HTTP, review [`docs/threat-model/threat-model-review.md`](../../docs/threat-model/threat-model-review.md) regarding the **Web-Origin Trust Limitation** (the web crypto delivery paradox) and ensure that production web hosting origins enforce DNSSEC, Subresource Integrity, and TLS 1.3.
