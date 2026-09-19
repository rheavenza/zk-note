# Application Threat Model Review & Residual Risk Assessment (ZK-097)

## 1. Executive Summary & Security Objectives

Zero-Knowledge Notes is designed to guarantee privacy, authenticity, and data durability for personal and organizational notes.

The primary security guarantees are:
1. **Zero Knowledge on Server (SEC-001, SEC-002)**: Note titles, bodies, tags, attachment filenames, MIME types, search queries, and cryptographic keys are encrypted client-side and never exist in plaintext on the server or in transit.
2. **Authenticated Encryption (SEC-004, SEC-005, SEC-010)**: All user data is encrypted with XChaCha20-Poly1305 using 192-bit random nonces and authenticated additional data (AAD), failing closed on any modification, tampering, or truncation.
3. **Collision & Conflict Safety (SEC-006, SEC-007, SEC-008)**: Revisioned objects use atomic compare-and-swap (CAS) mutation logic, unique idempotency keys, and explicit tombstone deletions.
4. **Encrypted Persistence (SEC-009)**: Local client caches (native SQLite and browser IndexedDB) store ciphertext envelopes only.

---

## 2. Threat Boundaries & Adversary Profiles

| Adversary Profile | Capabilities & Attack Surface | Assumed Protections |
| :--- | :--- | :--- |
| **Passive Network Eavesdropper** | Captures all network traffic between client and server (public Wi-Fi, ISP, upstream transit). | TLS 1.3 encryption in transit; application-layer XChaCha20-Poly1305 encryption prevents plaintext leakage even under TLS termination/compromise. |
| **Compromised Application Server / Rogue Cloud Operator** | Has full read/write access to the server database, logs, file storage, and OS memory. | Cannot decrypt notes or attachment blobs; does not possess Vault Keys, Note Keys, or user passphrases. Cannot forge accepted mutations without passing CAS or client decryption validation. |
| **Malicious Peer Account (Multi-tenant IDOR)** | Authenticated user attempting to access, enumerate, mutate, or delete other accounts' objects. | Server authorization middleware and tenant-isolated SQL queries reject cross-account queries with HTTP 404/401; blob and sync streams are strictly isolated (tested in `authorization_penetration_tests.rs`). |
| **Local Multi-User Adversary** | Unprivileged local user on a shared workstation or server. | SQLite database files and CLI temporary edit files enforce `0600`/`0700` POSIX permissions; temporary edit files are placed in RAM disks (`/dev/shm`) and zeroized on drop. |
| **Physical Device Thief (Device at Rest)** | Obtains physical possession of a powered-off laptop or storage drive. | Local persistent storage contains only ciphertext envelopes; VaultKey is encrypted at rest using Argon2id-derived KEK. |

---

## 3. Web-Origin Trust Limitations & The Web Crypto Paradox

### 3.1 The Web Delivery Vulnerability
In a standard web browser application, the security boundary differs fundamentally from native compiled software:

> **The Web Delivery Dilemma**: Every time a browser loads a web application, it fetches HTML, JavaScript, and WebAssembly binaries from the server origin. A malicious server operator, a compromised CDN, a rogue DNS provider, or a state-level adversary capable of modifying HTTP responses can replace the client code with a modified version that harvests passphrases or keys upon entry.

### 3.2 Defensive Mitigations Implemented
To maximize web client resilience, the application implements:
1. **Strict Content Security Policy**:
   - `default-src 'none'`: Prevents unlisted resources.
   - `script-src 'self' 'wasm-unsafe-eval'`: Prohibits inline scripts (`'unsafe-inline'` disabled for scripts) and blocks all third-party script CDNs.
   - `connect-src 'self'`: Prevents exfiltration of sensitive data to rogue third-party endpoints, even in the event of partial script injection.
2. **MIME & Frame Hardening**:
   - `X-Content-Type-Options: nosniff` prevents MIME confusion attacks.
   - `frame-ancestors 'none'` / `X-Frame-Options: DENY` prevents clickjacking and UI redressing.
3. **Web Worker Key Isolation**:
   - Decryption keys (`VaultKey`, `AttachmentKey`) reside exclusively in a dedicated Web Worker thread and are never exposed to the DOM rendering thread or React component state.
4. **Supply-Chain Minimization**:
   - Zero external tracking scripts, advertising SDKs, analytics pixels, or remote fonts.

### 3.3 Recommendation for High-Assurance Environments
For users facing high-threat adversary models (e.g. state surveillance, targeted corporate espionage):
- **Use the Native CLI Client (`zk-note`)**: Native binaries are compiled from source, cryptographically signed, and executed locally without fetching code over the network on each session.
- **Self-Hosting**: Host the web application and sync server on hardware and domain origins under your exclusive operational control.

---

## 4. Comprehensive Residual Risk Inventory

Despite rigorous controls, certain residual risks are inherent to the operational environment:

### 4.1 Traffic Analysis and Metadata Leakage
- **Residual Risk**: While note bodies, titles, and tags are encrypted, the server naturally observes:
  - Account ID and authenticated device IDs;
  - Timestamps of synchronization requests;
  - Size of ciphertext envelopes and blob chunks;
  - Number of mutations and revision count.
- **Risk Assessment**: An observer can infer note edit activity patterns or approximate document sizes.
- **Mitigation**: Future protocol iterations may implement fixed-size envelope padding and delayed batch syncing.

### 4.2 Volatile RAM Remanence
- **Residual Risk**: When a vault is unlocked, note plaintext and keys are decrypted into volatile system memory. While keys are zeroized on drop (`zeroize::Zeroize`), modern garbage-collected runtimes (JavaScript engines, V8, SpiderMonkey) and WebAssembly linear memory allocations may retain transient copies in memory until reclaimed or overwritten.
- **Mitigation**: Auto-lock timeouts (`ZK-076`) proactively scrub session state and trigger browser memory cleanups.

### 4.3 Browser Extensions and Compromised Workstations
- **Residual Risk**: Browser extensions with elevated permissions (`<all_urls>`, DOM access) execute with the same privileges as the user and can inspect input fields or DOM elements. Similarly, kernel keyloggers, rootkits, or screen-recording software bypass client-side encryption.
- **Mitigation**: Users must exercise discretion regarding browser extensions and maintain workstation endpoint security.

### 4.4 Weak Passphrase & Offline Exhaustion
- **Residual Risk**: An adversary with access to the server database can extract the `WrappedVaultKey` and `KdfParams`. While the server cannot decrypt the key, the attacker can attempt an offline dictionary brute-force attack.
- **Mitigation**: The system configures Argon2id with 64 MiB memory hardness, 3 iterations, and 1 parallelism lane, significantly raising the compute and memory cost of GPU/ASIC cluster cracking. Users are educated to use high-entropy passphrases or passphrases generated from diceware wordlists.

---

## 5. Security Invariants Verification Matrix

| Invariant | Description | Verification Test Suites | Status |
| :--- | :--- | :--- | :--- |
| **SEC-001** | Plaintext never crosses the network | `plaintext_leakage_tests.rs`, `plaintext-leakage.test.ts`, `server_blob_tests.rs` | **VERIFIED** |
| **SEC-002** | Server cannot decrypt user content | `plaintext_leakage_tests.rs`, `backup_restore_tests.rs` | **VERIFIED** |
| **SEC-003** | No secrets in application logs | `server_skeleton_tests.rs`, `plaintext_leakage_tests.rs` | **VERIFIED** |
| **SEC-004** | Authenticated encryption only | `zk_crypto_tests`, `protocol_property_tests.rs` | **VERIFIED** |
| **SEC-005** | Nonce uniqueness (192-bit random) | `zk-crypto/src/attachment.rs`, `zk-crypto/src/object.rs` | **VERIFIED** |
| **SEC-006** | CAS conflict safety | `server_cas_push_tests.rs`, `concurrency_stress_tests.rs` | **VERIFIED** |
| **SEC-007** | Retry and mutation idempotency | `server_mutation_idempotency_tests.rs`, `protocol_property_tests.rs` | **VERIFIED** |
| **SEC-008** | Tombstone deletion safety | `server_tombstone_tests.rs`, `backup_restore_tests.rs` | **VERIFIED** |
| **SEC-009** | Local persistence is encrypted | `plaintext_leakage_tests.rs`, `plaintext-leakage.test.ts` | **VERIFIED** |
| **SEC-010** | Cryptographic errors fail closed | `wasm_crypto_compat.test.mjs`, `xss-csp-review.test.ts` | **VERIFIED** |
