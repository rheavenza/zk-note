# Comprehensive Human Smoke Testing Guide

**Zero-Knowledge, Offline-First Note-Taking Application**  
*Document Version:* 1.0.0  
*Target Release:* Milestone 7 (M7)  
*Applicable Binaries & Packages:* `zk-note` (CLI), `zk-server` (Sync Server), `@zk-notes/web` (Web UI), `zk-wasm` (Core Worker)

---

## 1. Overview & Verification Objectives

This document provides a systematic, manual smoke testing procedure for human testers, QA engineers, and security auditors. The goal is to verify that the entire system—from low-level cryptographic primitives up to the browser WebAssembly worker and terminal user interfaces—functions correctly, reliably, and strictly adheres to the core zero-knowledge security invariants.

### Non-Negotiable Security Invariants Under Test

| Invariant | Title | What the Human Tester Must Verify |
| :--- | :--- | :--- |
| **SEC-001** | Plaintext Never Crosses Network | Note titles, bodies, tags, filenames, and search terms are NEVER sent to the server in plaintext. |
| **SEC-002** | Server Cannot Decrypt Content | The server possesses only opaque ciphertext envelopes (`wrapped_key`, `payload`), KDF salts, and sync sequences. |
| **SEC-003** | No Secrets in Logs | Master passphrases, recovery phrases, decrypted keys, and authorization tokens are NEVER logged or displayed in logs (must show `[REDACTED]`). |
| **SEC-004** | Authenticated Encryption | Every note is encrypted with ChaCha20-Poly1305 and unique nonces using wrapped Note Keys. |
| **SEC-006** | Conflict Safety (CAS) | The server rejects stale writes when `expected_revision` differs from the current revision (`409 Conflict`). |
| **SEC-007** | Retry Safety (Idempotency) | Replaying the exact same accepted mutation with identical `mutation_id` does NOT increment revisions or sequences. |
| **SEC-008** | Deletion Safety (Tombstones) | Deletions generate revisioned tombstones. Stale clients cannot resurrect deleted notes without explicit resolution. |
| **SEC-009** | Local Persistence is Encrypted | Persistent SQLite databases (`notes.db`) and browser IndexedDB (`zk_notes_db`) store ONLY encrypted envelopes. Zero plaintext on disk. |
| **SEC-010** | Errors Fail Closed | Corrupted ciphertext, tampered tags, invalid nonces, or wrong passphrases abort immediately with errors; no partial plaintext is ever returned. |

---

## 2. Prerequisites & Environment Setup

Before starting the smoke test, ensure the testing host has the following toolchains installed:

### Toolchain Checklist

- [ ] **Rust**: `rustc` 1.80.0 or higher, with `cargo` (`rustup update stable`).
- [ ] **WebAssembly Target**: `rustup target add wasm32-unknown-unknown`.
- [ ] **wasm-pack**: `wasm-pack` 0.12+ (`cargo install wasm-pack` or via package manager).
- [ ] **Node.js**: v20.x or v22.x LTS, with `npm` (`node -v && npm -v`).
- [ ] **SQLite CLI**: `sqlite3` CLI utility installed for database inspection (`sqlite3 --version`).
- [ ] **cURL & jq**: For interacting with the HTTP sync server (`curl --version && jq --version`).
- [ ] **Modern Web Browser**: Google Chrome, Mozilla Firefox, Apple Safari, or Microsoft Edge.

### Verification Commands

Run these commands in your terminal to verify your toolchains:

```bash
rustc --version
cargo --version
node --version
npm --version
wasm-pack --version
sqlite3 --version
curl --version
jq --version
```

---

## 3. Phase 0: Clean Build from Scratch

Build all native binaries, WebAssembly modules, and web client bundles from clean repository state.

### Step 0.1: Build Rust Workspace (Native Binaries & Crates)

In the repository root:

```bash
cargo build --workspace --all-targets
```

*Expected Result:*
- All crates (`zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync`, `zk-wasm`) compile without errors or warnings.
- Binaries generated:
  - `target/debug/zk-note` (CLI client)
  - `target/debug/zk-server` (Sync coordination server)
  - `target/debug/native_compat_harness` (Compatibility test harness)

### Step 0.2: Compile WebAssembly Core Package

Build the shared cryptographic core for WebAssembly:

```bash
wasm-pack build --target web crates/zk-wasm --out-dir pkg
```

*Expected Result:*
- WebAssembly binary and JavaScript bindings generated in `crates/zk-wasm/pkg/`:
  - `zk_wasm_bg.wasm`
  - `zk_wasm.js`
  - `zk_wasm.d.ts`

### Step 0.3: Build Web Application Bundle

Install web dependencies and build the TypeScript application:

```bash
cd apps/web
npm install
npm run build
cd ../..
```

*Expected Result:*
- TypeScript compiles cleanly into `apps/web/dist/`.
- No missing module or type errors.

### Step 0.4: Run Sanity Test Suite

Execute the repository automated test gate to ensure the baseline is completely clean:

```bash
./scripts/ci.sh
```

*Expected Result:*
- All 8 CI gates pass (Formatting, Clippy, Check, Workspace Tests, WASM compilation, WASM tests, Cross-runtime compat suite, Web unit & worker tests).

---

## 4. Phase 1: Terminal / CLI Client Smoke Test (`zk-note`)

We will configure an isolated test profile directory so the smoke test does not interfere with existing notes.

```bash
export ZK_NOTE_DIR="/tmp/zk-cli-smoke"
rm -rf "$ZK_NOTE_DIR"
mkdir -p "$ZK_NOTE_DIR"
```

### Test 1.1: Verify Initial Vault Status

Run:
```bash
cargo run -p zk-cli -- status
```

- **Expected Output:**
  ```text
  Vault status: UNINITIALIZED
  Path: /tmp/zk-cli-smoke
  Run 'zk-note init' to create a new vault.
  ```
- **Invariant Verified:** System detects an uninitialized vault state gracefully.

---

### Test 1.2: Initialize New Vault & Record Recovery Key

Run interactive initialization:
```bash
cargo run -p zk-cli -- init
```

1. When prompted for `Enter master passphrase:`, enter `Passphrase!SmokeTest2026`.
2. When prompted for `Confirm passphrase:`, enter `Passphrase!SmokeTest2026`.

- **Expected Output:**
  ```text
  Initializing vault with Argon2id key derivation...

  === VAULT CREATED SUCCESSFULLY ===
  Data directory: /tmp/zk-cli-smoke

  RECOVERY KEY:
    <HEX-FORMATTED-24-BYTE-RECOVERY-KEY>

  IMPORTANT:
    - Store this recovery key in a secure, offline location.
    - If you lose your passphrase, this recovery key is the ONLY way to recover notes.
    - The server CANNOT decrypt your notes or reset your passphrase.
    - Vault is currently unlocked for this session.
  ```
- **Action for Tester:** Copy the displayed `RECOVERY KEY` and save it to a scratchpad. You will need it in Test 1.10.

---

### Test 1.3: Zero-Knowledge Local Disk Audit (SEC-009)

Verify that the initialization files created on disk contain NO plaintext passphrases or unencrypted keys.

1. Inspect `vault.json`:
   ```bash
   cat "$ZK_NOTE_DIR/vault.json" | jq .
   ```
   *Expected Result:*
   - Contains `crypto_version: 1`
   - Contains `kdf_algorithm: "argon2id"` with `memory_kib: 65536`, `iterations: 3`, `parallelism: 4`
   - Contains `kdf_salt` (base64)
   - Contains `wrapped_vault_key` (nonce + ciphertext)
   - Contains `recovery_wrapped_vault_key` (nonce + ciphertext)
   - **CRITICAL:** Passphrase string `Passphrase!SmokeTest2026` DOES NOT appear anywhere.

2. Inspect `notes.db` schema:
   ```bash
   sqlite3 "$ZK_NOTE_DIR/notes.db" ".schema local_objects"
   ```
   *Expected Result:*
   ```sql
   CREATE TABLE local_objects (
       object_id TEXT PRIMARY KEY NOT NULL,
       object_kind INTEGER NOT NULL,
       revision INTEGER NOT NULL,
       server_seq INTEGER NOT NULL DEFAULT 0,
       is_deleted INTEGER NOT NULL DEFAULT 0,
       envelope TEXT NOT NULL,
       updated_at TEXT NOT NULL
   );
   ```
   - **CRITICAL:** Columns named `title`, `body`, or `tags` DO NOT EXIST. All note data is stored exclusively in `envelope`.

---

### Test 1.4: Create a Note

Run:
```bash
cargo run -p zk-cli -- new -t "Mission Briefing" -b "Operation Zero Knowledge is active. Meet at Sector 7." -g "intel,confidential"
```

- **Expected Output:**
  ```text
  Created note: <NOTE-UUID>
  Title: Mission Briefing
  Tags: intel, confidential
  ```
- **Action for Tester:** Note down the `<NOTE-UUID>` (e.g. `e1a2b3c4-...`).

---

### Test 1.5: List & Show Note

1. List notes:
   ```bash
   cargo run -p zk-cli -- list
   ```
   *Expected Result:* Displays a formatted table with columns `ID`, `UPDATED`, `TAGS`, `TITLE`. The note "Mission Briefing" is displayed.

2. Show note using its UUID (or first 8 characters):
   ```bash
   cargo run -p zk-cli -- show <NOTE-UUID-PREFIX>
   ```
   *Expected Result:*
   ```text
   ================================================================================
   ID:       <NOTE-UUID>
   Title:    Mission Briefing
   Tags:     intel, confidential
   Updated:  <ISO8601-TIMESTAMP>
   Created:  <ISO8601-TIMESTAMP>
   Revision: 1
   ================================================================================

   Operation Zero Knowledge is active. Meet at Sector 7.
   ```

---

### Test 1.6: Zero-Knowledge Database Ciphertext Inspection (SEC-009)

Confirm that the SQLite database file contains ONLY ciphertext and no plaintext notes.

1. Query `local_objects`:
   ```bash
   sqlite3 "$ZK_NOTE_DIR/notes.db" "SELECT object_id, revision, is_deleted, envelope FROM local_objects;"
   ```
   *Expected Result:*
   - Output shows JSON string in `envelope` containing:
     `{"envelope_version":1,"object_id":"...","object_kind":1,"wrapped_key":{"nonce":"...","ciphertext":"..."},"payload":{"nonce":"...","ciphertext":"..."}}`
   - Notice both `wrapped_key` and `payload` are opaque base64-encoded strings.

2. Binary Grep on the SQLite database:
   ```bash
   grep -i "Mission Briefing" "$ZK_NOTE_DIR/notes.db" || echo "PASS: No plaintext title in SQLite database file."
   grep -i "Sector 7" "$ZK_NOTE_DIR/notes.db" || echo "PASS: No plaintext body in SQLite database file."
   ```
   *Expected Result:* Both checks must output `PASS: No plaintext...`.

---

### Test 1.7: Edit Note and Inspect Revision History

1. Update the note:
   ```bash
   cargo run -p zk-cli -- edit <NOTE-UUID-PREFIX> -t "Mission Briefing (Updated)" -b "Operation Zero Knowledge updated. Rendezvous moved to Sector 9." -g "intel,urgent"
   ```
   *Expected Result:* Note updated, revision incremented to 2.

2. View revision history:
   ```bash
   cargo run -p zk-cli -- history <NOTE-UUID-PREFIX>
   ```
   *Expected Result:* Shows revisions `1` and `2` with respective timestamps.

3. View historical revision 1:
   ```bash
   cargo run -p zk-cli -- history <NOTE-UUID-PREFIX> -r 1
   ```
   *Expected Result:* Displays original title "Mission Briefing" and body "Meet at Sector 7."

---

### Test 1.8: Local Full-Text In-Memory Search

Test searching across decrypted fields (SEC-001: search is computed purely client-side):

1. Search body text:
   ```bash
   cargo run -p zk-cli -- search "Sector 9"
   ```
   *Expected Result:* Matches "Mission Briefing (Updated)".

2. Search tags:
   ```bash
   cargo run -p zk-cli -- search "urgent"
   ```
   *Expected Result:* Matches "Mission Briefing (Updated)".

3. Search nonexistent query:
   ```bash
   cargo run -p zk-cli -- search "NonExistentTerm123"
   ```
   *Expected Result:* Reports 0 matches found.

---

### Test 1.9: Tombstone Deletion Semantics (SEC-008)

1. Delete the note:
   ```bash
   cargo run -p zk-cli -- delete <NOTE-UUID-PREFIX>
   ```
   *Expected Result:* `Deleted note: <NOTE-UUID> (revision: 3)`

2. Regular list:
   ```bash
   cargo run -p zk-cli -- list
   ```
   *Expected Result:* Empty list (note is deleted).

3. List including deleted tombstones:
   ```bash
   cargo run -p zk-cli -- list --include-deleted
   ```
   *Expected Result:* Note appears marked with `[DELETED]` tag/status and `Revision: 3`.

4. SQLite check:
   ```bash
   sqlite3 "$ZK_NOTE_DIR/notes.db" "SELECT object_id, revision, is_deleted FROM local_objects;"
   ```
   *Expected Result:* `is_deleted` column value is `1`.

---

### Test 1.10: Lock Vault & Verify Fail-Closed State (SEC-010)

1. Lock vault:
   ```bash
   cargo run -p zk-cli -- lock
   ```
   *Expected Result:* `Vault locked.`

2. Check status:
   ```bash
   cargo run -p zk-cli -- status
   ```
   *Expected Result:* `Vault status: LOCKED`

3. Attempt to list notes while locked:
   ```bash
   cargo run -p zk-cli -- list
   ```
   *Expected Result:* Fails closed with `Error: vault is locked; run 'zk-note unlock' first`.

4. Attempt to unlock with WRONG passphrase:
   ```bash
   cargo run -p zk-cli -- unlock --passphrase "IncorrectPassword!"
   ```
   *Expected Result:* Fails closed with `Error: authentication failed: incorrect passphrase or corrupted vault`.

---

### Test 1.11: Unlock via 24-Word Recovery Key

Use the recovery key saved from Step 1.2:
```bash
cargo run -p zk-cli -- unlock --recovery-key "<SAVED-RECOVERY-KEY>"
```

- **Expected Output:**
  ```text
  Unlocking vault with recovery key...
  Vault unlocked successfully.
  ```
- **Verify:** Run `cargo run -p zk-cli -- status` -> `Vault status: UNLOCKED`.

---

## 5. Phase 2: Zero-Knowledge Sync Server Smoke Test (`zk-server`)

The sync server coordinates encrypted sync mutations, revisions, and tombstones. In accordance with SEC-002, it has zero cryptographic keys and cannot decrypt user content.

### Test 2.1: Start the Sync Server

In a separate terminal window:
```bash
PORT=8080 ZK_SERVER_LOG_FORMAT=text RUST_LOG=info cargo run -p zk-server
```

- **Expected Output:**
  ```text
  INFO zk_server: initializing zero-knowledge server host="127.0.0.1" port=8080 log_level="info"
  INFO zk_server::server: binding TCP listener host="127.0.0.1" port=8080 log_level="info"
  INFO zk_server::server: server listening and ready for requests addr=127.0.0.1:8080
  ```

---

### Test 2.2: Health Check & Strict Security Headers Audit (ZK-069)

In your main terminal, test the `/health` endpoint:
```bash
curl -i http://127.0.0.1:8080/health
```

- **Expected Status:** `HTTP/1.1 200 OK`
- **Expected Payload:** `{"status":"ok","version":"0.1.0","protocol_version":1}`
- **Security Headers Verification:**
  - [ ] `Content-Security-Policy`: Must specify `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; ...`
  - [ ] `X-Frame-Options`: Must be `DENY`
  - [ ] `X-Content-Type-Options`: Must be `nosniff`
  - [ ] `Referrer-Policy`: Must be `no-referrer`
  - [ ] `Cross-Origin-Opener-Policy`: Must be `same-origin`
  - [ ] `Cross-Origin-Embedder-Policy`: Must be `require-corp`
  - [ ] `Cross-Origin-Resource-Policy`: Must be `same-origin`
  - [ ] `Strict-Transport-Security`: Must include `max-age=63072000; includeSubDomains; preload`

---

### Test 2.3: Authentication Enforcement (ZK-070, SEC-001)

Attempt to access protected sync endpoints without authentication:

1. Without Authorization header:
   ```bash
   curl -i http://127.0.0.1:8080/v1/sync/changes
   ```
   *Expected Status:* `HTTP/1.1 401 Unauthorized`  
   *Expected JSON:* `{"code":"AUTH_REQUIRED","message":"Authorization header is required"}`

2. With invalid / malformed token:
   ```bash
   curl -i -H "Authorization: Bearer bad-token-xyz" http://127.0.0.1:8080/v1/sync/changes
   ```
   *Expected Status:* `HTTP/1.1 401 Unauthorized`  
   *Expected JSON:* `{"code":"AUTH_REQUIRED","message":"Invalid or malformed authorization token"}`

---

### Test 2.4: Log Redaction Verification (SEC-003)

Examine the server console output from Test 2.3:
- Verify that `bad-token-xyz` DOES NOT appear anywhere in the server logs.
- The request logger logs only `method`, `path`, `status: 401`, and `request_id`.
- Sensitive authentication headers are unconditionally redacted.

---

## 6. Phase 3: Web Application Smoke Test (`apps/web`)

The web client runs React with the shared Rust cryptographic core running in a dedicated Web Worker via WebAssembly.

### Test 3.1: Launch Web Application Preview Server

In a new terminal window:
```bash
cd apps/web
npx serve -l 3000 .
```
*(Alternatively: `python3 -m http.server 3000 --directory .`)*

Open your browser and navigate to:
```text
http://localhost:3000
```

---

### Test 3.2: Browser Console & Security Audit (ZK-069)

1. Open Browser DevTools (`F12` or right-click -> "Inspect").
2. Switch to the **Console** tab:
   - Ensure there are no CSP violation errors or script loading errors.
3. Switch to the **Network** tab and refresh the page (`Ctrl+R` or `Cmd+R`):
   - Verify that **100% of network requests originate from `localhost:3000`**.
   - Confirm: **Zero calls** to third-party CDNs (Google Fonts, unpkg, cdnjs, analytics, etc.).
   - Confirm: `index.html` loads with `Content-Security-Policy` enforcing `default-src 'none'`.

---

### Test 3.3: First-Time Vault Initialization in Browser

When loaded for the first time, the UI detects an uninitialized vault state:

1. Verify the screen displays:
   - Header: "Initialize Encrypted Vault"
   - Information notice: "Zero-Knowledge Encryption: Your notes are encrypted client-side using Argon2id and ChaCha20-Poly1305. We never see your password or keys."
   - Input: "Master Passphrase"
   - Input: "Confirm Passphrase"
   - Button: "Initialize Vault"
2. Enter Master Passphrase: `WebPassphrase!2026`
3. Enter Confirm Passphrase: `WebPassphrase!2026`
4. Click **"Initialize Vault"**.

**Expected Result:**
- A high-visibility modal opens titled **"Save Your Recovery Phrase"**.
- Displays a 24-word formatted recovery phrase (e.g. `word1 word2 word3 ... word24`).
- Prompts with a warning: "If you lose your passphrase, this recovery phrase is the ONLY way to access your notes."
- **Action for Tester:** Copy the 24 words to your scratchpad.
- Click **"I have safely stored my recovery phrase"**.
- The modal dismisses and the main **Notes Workspace** renders.

---

### Test 3.4: Markdown Note Creation, Live Preview & Autosave

1. In the left sidebar (`NotesList`), click the **"+ New Note"** button.
2. In the right pane editor:
   - Title input: Type `Quarterly Cryptography Audit`.
   - Tags input: Type `security, zero-knowledge, release`.
   - Body editor: Type the following Markdown text:
     ```markdown
     # Security Audit Overview

     All cryptographic invariants have been verified:
     - **ChaCha20-Poly1305** for payload encryption
     - **Argon2id** for key derivation
     - **Memory scrubbing** via `zeroize`

     ```rust
     fn verify_zero_knowledge() -> bool {
         true
     }
     ```
     ```
3. Observe the top-right save status badge:
   - Shows **"Saving..."** during typing debouncing.
   - Transitions to **"Saved"** (green indicator) when encrypted to IndexedDB.
4. Click the **"Preview"** tab button on the editor toolbar:
   - Verify Markdown renders as formatted HTML (Header 1, bold text, bullet points, syntax code block).
   - Click the **"Write"** tab to switch back to Markdown editing mode.

---

### Test 3.5: Fast In-Memory Full-Text Search (`Cmd+K` / `Ctrl+K`)

1. Press `Cmd+K` (macOS) or `Ctrl+K` (Linux/Windows), or click the Search Bar in the top navbar.
2. The Search Modal opens.
3. Type: `Audit`.
   - The note "Quarterly Cryptography Audit" appears in the live results list.
4. Type: `zero-knowledge`.
   - Matches by tag and highlights the result.
5. Hit `Enter` or click the result:
   - Modal closes and the matching note is active in the editor.

---

### Test 3.6: Browser Storage Zero-Knowledge Audit (SEC-009)

Confirm that the browser's persistent storage contains NO plaintext content.

1. In DevTools, open the **Application** tab (or **Storage** tab in Firefox).
2. Expand **IndexedDB** -> **`zk_notes_db`** -> **`objects`**:
   - Click the row corresponding to your note.
   - Expand the record in the value inspector:
     - `object_id`: UUID
     - `envelope_version`: `1`
     - `wrapped_key`: Object with `nonce` (base64) and `ciphertext` (base64)
     - `payload`: Object with `nonce` (base64) and `ciphertext` (base64)
   - **CONFIRM:** There are **NO** properties for `title`, `body`, or `tags`.
3. Expand **Local Storage** -> `http://localhost:3000`:
   - Inspect `zk_vault_bootstrap`:
     - Contains only `wrappedVaultKey`, `kdfParamsJson`, `wrappedRecoveryKey`.
     - **CONFIRM:** Raw VaultKey and plaintext passphrases are NEVER stored in localStorage.

---

### Test 3.7: Vault Locking & Memory Scrubbing

1. In the top navbar, click the **"Lock Vault"** button.
2. **Expected Result:**
   - The main workspace immediately unmounts.
   - The view transitions back to the **Unlock Screen**.
   - Vault status badge displays "Vault Locked".
   - The Web Worker client immediately scrubs the in-memory VaultKey.

---

### Test 3.8: Unlock via Passphrase and Recovery Phrase

1. On the Unlock Screen:
   - Enter wrong passphrase: `WrongPassword123` -> Click **"Unlock Vault"**.
   - **Expected Result:** Error banner displays: "Decryption failed. Please verify your passphrase." (Fail closed - SEC-010).
   - Enter correct passphrase: `WebPassphrase!2026` -> Click **"Unlock Vault"**.
   - **Expected Result:** Workspace reopens with your note "Quarterly Cryptography Audit" intact.
2. Lock vault again (click "Lock Vault").
3. Click the **"Use Recovery Phrase"** tab:
   - Enter the 24-word recovery phrase copied in Step 3.3.
   - Click **"Unlock with Recovery Key"**.
   - **Expected Result:** Successfully unlocks vault and restores full note access.

---

## 7. Phase 4: Multi-Device Sync & Conflict Resolution Smoke Test

This phase tests how the system behaves when two devices make concurrent offline edits to the same note, verifying Compare-And-Swap (CAS) rejection and visual 4-way conflict resolution.

### Test Setup: Two Simulated Devices

- **Device A**: CLI Client (Profile `/tmp/zk-device-a`)
- **Device B**: Web Client (or second CLI Profile `/tmp/zk-device-b`)

---

### Test 4.1: Clean Sync Push & Pull (Happy Path)

1. Device A creates Note 1 (`Revision 1`) and pushes to the sync server.
2. Device B connects and pulls sync changes from the sync server.
3. Device B successfully decrypts Note 1 and displays it in the UI.
- **Expected Result:** Both devices have identical Note 1 content at `Revision 1`.

---

### Test 4.2: Concurrent Offline Edits & 409 Conflict Generation (SEC-006)

1. Disconnect both devices from sync (or simulate offline state).
2. **Device A Edit:**
   - Title: `Project Roadmap - Mobile First`
   - Body: `Phase 1: iOS and Android clients.`
   - Device A saves locally (`expected_revision = 1`, local revision = 2A).
3. **Device B Edit (Concurrent):**
   - Title: `Project Roadmap - Desktop First`
   - Body: `Phase 1: Linux, macOS, and Windows clients.`
   - Device B saves locally (`expected_revision = 1`, local revision = 2B).
4. **Device A Reconnects & Syncs:**
   - Device A pushes its mutation (`expected_revision = 1`).
   - Server checks CAS: Server current revision is 1 == `expected_revision`. Push accepted!
   - Server revision becomes `2A`.
5. **Device B Reconnects & Syncs:**
   - Device B attempts to push its mutation (`expected_revision = 1`).
   - Server checks CAS: Server current revision is `2A` != `1`.
   - **Expected Result:** Server **REJECTS** Device B's push with `409 Conflict`.
   - **Invariant SEC-006 Verified:** Server DOES NOT silently overwrite Device A's changes.

---

### Test 4.3: Visual 4-Way Conflict Resolution (ZK-068)

When Device B receives the `409 Conflict`, the Web UI displays a conflict badge in the navbar and automatically opens (or provides a button to open) the **Conflict Resolver Modal**.

Verify all 4 resolution options in the modal:

1. **Compare Local vs Remote View:**
   - Left side shows Local Draft (`Project Roadmap - Desktop First`).
   - Right side shows Remote Server Version (`Project Roadmap - Mobile First`).
2. **Option 1: "Keep Local Version"**:
   - Overwrites remote on next sync push with updated `expected_revision = 2`.
3. **Option 2: "Keep Remote Version"**:
   - Discards local offline changes and accepts server version.
4. **Option 3: "Preserve Both (Duplicate)"**:
   - Accepts remote as the authoritative note.
   - Duplicates local version as a new independent note titled `Project Roadmap - Desktop First (Conflict Copy)`.
   - Zero data loss!
5. **Option 4: "3-Way Merge & Edit"**:
   - Displays a diff editor combining non-overlapping changes.
   - Allows user to manually edit the merged note body.
   - Click "Save Merged Version": Bumps revision cleanly, enqueues mutation, and marks conflict as RESOLVED.

---

### Test 4.4: Deletion vs Edit Conflict (SEC-008)

1. Device A deletes Note 2 while online (creates revisioned tombstone `is_deleted = true`, revision 2).
2. Device B was offline and concurrently edited Note 2.
3. Device B attempts to sync.
- **Expected Result:** Sync produces a delete-vs-edit conflict. The deleted tombstone is **NOT** silently overwritten or resurrected.
- UI prompts user: Discard local edit OR explicitly resurrect the note with a new revision.

---

## 8. Phase 5: Adversarial & Fail-Closed Security Audit

Verify that malicious tampering or data corruption fails closed without data leakage (SEC-010).

### Test 5.1: Tampered Ciphertext in Database (SEC-010)

Corrupt one byte of note ciphertext in the SQLite database:

```bash
# Pick an existing record and corrupt its payload
sqlite3 "$ZK_NOTE_DIR/notes.db" "UPDATE local_objects SET envelope = replace(envelope, '\"ciphertext\":\"', '\"ciphertext\":\"TAMPERED_');"
```

Now attempt to read the note:
```bash
cargo run -p zk-cli -- show <NOTE-UUID-PREFIX>
```

- **Expected Result:** Command terminates with an explicit cryptographic failure:
  `Error: cryptographic failure: Poly1305 tag verification failed` (or `DECRYPTION_FAILED`).
- **CRITICAL:** NO partial, corrupt, or guessed plaintext is ever printed to terminal.

---

### Test 5.2: Tampered AAD (Associated Authenticated Data)

The envelope uses the `object_id` and `envelope_version` as Associated Authenticated Data (AAD) in the AEAD cipher:

```bash
# Tamper with the object_id inside the envelope while keeping the database key
sqlite3 "$ZK_NOTE_DIR/notes.db" "UPDATE local_objects SET envelope = replace(envelope, '\"envelope_version\":1', '\"envelope_version\":2');"
```

Attempt to read the note:
```bash
cargo run -p zk-cli -- show <NOTE-UUID-PREFIX>
```

- **Expected Result:** Command fails closed. Modifying authenticated metadata without recomputing the MAC tag causes immediate rejection.

---

### Test 5.3: Mutation Idempotency Verification (SEC-007)

Send the same push mutation twice with identical `mutation_id` to the server:

- **Expected Result:**
  - The first request returns HTTP 200 with the resulting revision and sequence.
  - The second duplicate request returns HTTP 200 with the EXACT same response payload from the idempotency cache.
  - The server sequence number and revision DO NOT increment a second time.

---

## 9. Human Tester Verification Checklist Table

Complete this table during testing and include it in your release sign-off report:

| Test ID | Area | Scenario | Step-by-Step Action | Expected Result | Pass / Fail | Notes |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **SMK-001** | Build | Clean workspace build | `cargo build --workspace` | All crates build cleanly | [ ] | |
| **SMK-002** | Build | WASM compilation | `wasm-pack build --target web crates/zk-wasm` | Output in `crates/zk-wasm/pkg` | [ ] | |
| **SMK-003** | Build | Web TypeScript build | `npm --prefix apps/web run build` | Zero type/build errors | [ ] | |
| **SMK-004** | Build | CI Quality Gates | `./scripts/ci.sh` | All 8 CI gates PASS | [ ] | |
| **SMK-010** | CLI | Initial Status | `zk-note status` (fresh dir) | Status: UNINITIALIZED | [ ] | |
| **SMK-011** | CLI | Vault Init | `zk-note init` with passphrase | Generates 24-word recovery key | [ ] | |
| **SMK-012** | CLI / Sec | Disk Audit (vault.json) | Inspect `vault.json` with `jq` | Argon2id params; NO plaintext pass | [ ] | |
| **SMK-013** | CLI / Sec | Disk Audit (notes.db) | `sqlite3 .schema local_objects` | NO title/body columns | [ ] | |
| **SMK-014** | CLI | Note Creation | `zk-note new -t ... -b ...` | Note created with UUID | [ ] | |
| **SMK-015** | CLI | Note Decryption | `zk-note show <id>` | Decrypts and prints title/body | [ ] | |
| **SMK-016** | CLI / Sec | Zero-Plaintext Audit | `grep -i "title" notes.db` | ZERO plaintext matches in DB file | [ ] | |
| **SMK-017** | CLI | Note Edit & History | `zk-note edit` & `history` | Revision bumps; history viewable | [ ] | |
| **SMK-018** | CLI | Client-Side Search | `zk-note search "query"` | Decrypted in memory; finds note | [ ] | |
| **SMK-019** | CLI | Tombstone Deletion | `zk-note delete <id>` | Hidden in list; tombstone in DB | [ ] | |
| **SMK-020** | CLI | Lock Vault | `zk-note lock` | Vault status: LOCKED | [ ] | |
| **SMK-021** | CLI / Sec | Fail-Closed Locked | `zk-note list` while locked | Denies access with error | [ ] | |
| **SMK-022** | CLI / Sec | Wrong Passphrase | `zk-note unlock --passphrase bad` | Denies access; fails closed | [ ] | |
| **SMK-023** | CLI | Recovery Key Unlock | `zk-note unlock --recovery-key ...` | Unlocks vault successfully | [ ] | |
| **SMK-030** | Server | Health Check | `curl /health` | HTTP 200 `{"status":"ok"}` | [ ] | |
| **SMK-031** | Server / Sec | Security Headers | Inspect `curl -i /health` | CSP, nosniff, DENY, HSTS present | [ ] | |
| **SMK-032** | Server / Sec | Auth Enforcement | `curl /v1/sync/changes` without token | HTTP 401 Unauthorized | [ ] | |
| **SMK-033** | Server / Sec | Log Redaction | Inspect server logs for auth tokens | Auth token logged as `[REDACTED]` | [ ] | |
| **SMK-040** | Web | Web Preview Launch | Open `http://localhost:3000` | UI loads cleanly | [ ] | |
| **SMK-041** | Web / Sec | Zero 3rd Party Scripts | DevTools Network Tab | Zero external CDN or script calls | [ ] | |
| **SMK-042** | Web | Web Vault Init | Enter pass -> Initialize Vault | 24-word recovery modal displays | [ ] | |
| **SMK-043** | Web | Markdown Edit & Preview | Edit note -> Click "Preview" | Cleanly rendered safe HTML | [ ] | |
| **SMK-044** | Web | Autosave | Observe save badge while editing | Transitions "Saving..." -> "Saved" | [ ] | |
| **SMK-045** | Web | Quick Search (Cmd+K) | Press `Cmd+K` -> Search note | Instant in-memory search results | [ ] | |
| **SMK-046** | Web / Sec | IndexedDB Audit | DevTools -> IndexedDB -> `objects` | ONLY ciphertext envelopes stored | [ ] | |
| **SMK-047** | Web | Lock Vault & Scrub | Click "Lock Vault" button | UI resets to Unlock Screen | [ ] | |
| **SMK-048** | Web | Web Unlock (Passphrase) | Unlock with password | Workspace restores notes | [ ] | |
| **SMK-049** | Web | Web Unlock (Recovery) | Unlock with 24-word phrase | Workspace restores notes | [ ] | |
| **SMK-050** | Sync | CAS 409 Conflict | Concurrent offline edits | Server rejects stale write (409) | [ ] | |
| **SMK-051** | Sync | 4-Way Conflict Resolver | Open Conflict Resolver Modal | 4 options: Keep Local/Remote/Dup/Merge | [ ] | |
| **SMK-052** | Sync / Sec | Deletion Conflict | Concurrent delete vs edit | Prevents silent resurrection | [ ] | |
| **SMK-060** | Adversarial | Tampered Ciphertext | Flip byte in SQLite payload | Fails closed with crypto error | [ ] | |
| **SMK-061** | Adversarial | Tampered AAD | Modify version in envelope | Poly1305 MAC failure | [ ] | |
| **SMK-062** | Adversarial | Idempotent Retry | Send duplicate mutation_id | Returns identical cached response | [ ] | |

---

## 10. Smoke Test Completion Sign-Off

**Date Tested:** ____________________  
**Tester Name:** ____________________  
**Tester Signature:** ____________________  
**Overall Status:** `[ ] PASS` / `[ ] FAIL`  

**Summary of Observations & Deviations:**
```text
(Record any UX observations, timing notes, or deviations here)
```
