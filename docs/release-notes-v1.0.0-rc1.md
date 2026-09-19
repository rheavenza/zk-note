# Release Notes — Zero-Knowledge Notes v1.0.0-RC1

**Version:** `1.0.0-rc1`  
**Date:** September 2026  
**Status:** Release Candidate  
**Quality Gate:** Passed (Milestone 9 Gate, ZK-099)

---

## 1. Executive Summary

We are pleased to announce **v1.0.0-RC1** of the **Zero-Knowledge, Offline-First Note-Taking Application**. 

This release candidate delivers a production-grade, mathematically audited, zero-knowledge note-taking system designed for high-security, privacy-critical environments. User notes, titles, tags, full-text search indexes, attachment payloads, and filenames are encrypted client-side before touching the network or disk. The coordination server operates as an untrusted ciphertext repository and sequence allocator with **zero ability** to decrypt, inspect, or tamper with user content.

---

## 2. Core Architecture & Features

### 2.1 Cryptographic Core & Key Hierarchy
- **Authenticated Encryption**: `XChaCha20-Poly1305` (256-bit keys, 192-bit random nonces) protecting all note payloads, metadata envelopes, and attachment chunks.
- **Key Derivation Function (KDF)**: `Argon2id v13` (64 MiB memory hardness, 3 iterations, 1 parallelism lane, 16-byte random salt) deriving 256-bit Key Encryption Keys (`KeyEncryptionKey`) from master passphrases.
- **Subkey & PRF Derivation**: `BLAKE2b` and `BLAKE2s` keyed hashing for subkey derivation and attachment chunk integrity.
- **Typo-Detecting Recovery Key**: 288-bit recovery key with embedded BLAKE2b checksum formatted as a 9-group hyphenated token (`XXXX-XXXX-...`) allowing full vault recovery and zero-loss passphrase rotation.
- **Memory Scrubbing**: Ephemeral cryptographic keys and search buffers implement `zeroize::ZeroizeOnDrop` to scrub memory when locked.

### 2.2 Client-Side Shared Rust Engine & WebAssembly
- **Single Source of Truth**: Unified Rust workspace (`zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync`) shared across the native terminal CLI (`zk-note`) and browser web client (`@zk-notes/web` via `zk-wasm`).
- **Web Worker Process Isolation**: Cryptographic operations and SQLite/IndexedDB operations execute within an isolated Web Worker, ensuring main-thread UI responsiveness and guarding key buffers against DOM-level interference.
- **Ephemeral In-Memory Search**: Full-text search operates exclusively on decrypted in-memory structures while unlocked. Locking the vault immediately scrubs all search indices. No plaintext indices are ever persisted to disk.

### 2.3 Synchronization & Conflict Safety
- **Compare-And-Swap (CAS)**: Strict `expected_revision` enforcement rejects stale concurrent edits with HTTP 409 Conflict, preventing silent data loss (`SEC-006`).
- **Mutation Idempotency**: Cryptographic `mutation_id` deduplication guarantees retry safety across unreliable networks (`SEC-007`).
- **Structured 3-Way Merge**: Native `diff3` line-based text merge for note bodies combined with scalar field conflict resolution and set union for tags.
- **Conflict Preservation**: Conflicted revisions automatically create durable local `ConflictRecord`s retaining base, local, and remote envelopes for visual resolution.
- **Tombstone Deletions**: Revisioned tombstones prevent resurrection of deleted items by stale clients (`SEC-008`).

### 2.4 Streaming Encrypted Attachments
- **Chunked Storage**: Attachments are split into 256 KiB chunks, encrypted with individual derived `AttachmentKey`s, and addressed by content digest (`BLAKE2b`).
- **Opaque Server Storage**: Server stores encrypted chunks without knowledge of file names, extensions, MIME types, or sizes.

---

## 3. Verification & Security Quality Gates

The v1.0.0-RC1 release candidate has passed all 9 repository-wide CI gates and specialized security audit suites:

1. **Full Workspace Quality Gate (`./scripts/ci.sh`)**:
   - `cargo fmt --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo check --workspace --locked`
   - `cargo test --workspace --all-targets --all-features`
   - `cargo check --target wasm32-unknown-unknown`
   - `wasm-pack test --node crates/zk-wasm`
   - Cross-runtime test suite (`tests/wasm_crypto_compat.test.mjs`)
   - Web application test suite (`npm run typecheck && npm test`)
   - Supply-chain dependency audit (`cargo-audit` & `npm audit`: 0 vulnerabilities)

2. **Specialized Security & Hardening Suites**:
   - **Protocol Property Fuzzing (`protocol_property_tests.rs`)**: 500-step randomized state machine simulation validating CAS invariants and sequence monotonicity.
   - **Concurrency Stress Suite (`concurrency_stress_tests.rs`)**: 50 concurrent client workers racing against identical note objects; zero race conditions or database deadlocks.
   - **Plaintext Leakage Audit (`plaintext_leakage_tests.rs`, `plaintext-leakage.test.ts`)**: Scans server SQLite databases, server audit logs, network traces, client SQLite files, and IndexedDB object stores for secret canaries; verified 0 leaks.
   - **Multi-Tenant Penetration Suite (`authorization_penetration_tests.rs`)**: Verified complete cross-tenant isolation, IDOR prevention, revoked token invalidation, and blob access control.
   - **Backup & Restore Lifecycle (`backup_restore_tests.rs`)**: Live snapshot verification proving zero plaintext leakage in backup files and 100% data recovery on a restored server.
   - **Two-Client Offline Conflict & Recovery Demos (`scripts/demo_rc.sh`, `release_candidate_tests.rs`)**: Automated end-to-end demonstration of concurrent offline edits, CAS rejection, 3-way merge resolution, recovery key unwrap, and passphrase rotation with zero data loss.

---

## 4. Known Limitations & Residual Risks

While the zero-knowledge security architecture guarantees confidentiality against server compromises and network eavesdropping, the following inherent threat model limitations and residual risks must be understood:

### 4.1 Web-Origin Trust Limitation (Web Crypto Delivery Paradox)
- **Description**: Browser applications inherently trust the web server from which their JavaScript and WebAssembly bundles are fetched on every session. A compromised web hosting origin or malicious reverse proxy could theoretically serve a modified JavaScript bundle designed to exfiltrate keys at the browser level.
- **Mitigation & Advice**: Production web deployments MUST enforce strict Content Security Policy (`CSP`) headers, HTTP Strict Transport Security (`HSTS`), Subresource Integrity (`SRI`), and DNSSEC. Users requiring absolute origin immutability should utilize the native terminal client (`zk-note`) compiled from source.

### 4.2 Endpoint Compromise & Browser Extension Risks
- **Description**: Client-side encryption operates inside process memory while the vault is unlocked. Malicious browser extensions with broad permissions (`<all_urls>`, DOM access), keyloggers, or kernel rootkits can capture keystrokes or dump process RAM.
- **Mitigation & Advice**: Inactivity auto-lock timers proactively purge decrypted keys from memory. Users should run the application in clean browser profiles without untrusted third-party extensions.

### 4.3 Traffic Analysis & Metadata Side-Channels
- **Description**: While note contents, titles, tags, and attachment payloads are fully encrypted, a network adversary observing TLS traffic can observe ciphertext envelope sizes, sync update frequencies, and IP addresses.
- **Mitigation**: Future releases will explore client-side padding schemes and traffic shaping.

### 4.4 Weak Passphrases & Offline Dictionary Attacks
- **Description**: An attacker who obtains a full dump of the server database possesses the encrypted `WrappedVaultKey` and `KdfParams`. Although the server cannot decrypt the key, the attacker could attempt offline dictionary attacks.
- **Mitigation**: Argon2id with 64 MiB RAM and 3 iterations significantly raises the cost of GPU cluster cracking. Users must select high-entropy passphrases (16+ characters or 4+ Diceware words).

### 4.5 Absence of Per-Note Forward Secrecy
- **Description**: Note keys are wrapped under the master `VaultKey`. If an adversary compromises the user's active `VaultKey` in memory, all historical notes wrapped by that key become decryptable.
- **Mitigation**: Master passphrase rotation with recovery re-keying is supported. Future major revisions may introduce ratcheted per-note key evolution.

---

## 5. Deployment & Quick Start

### 5.1 Run Automated Release Candidate Demonstrations
```bash
./scripts/demo_rc.sh
```

### 5.2 Native CLI Quick Start
```bash
# Build binary
cargo build --release --bin zk-note

# Initialize vault
./target/release/zk-note init

# Create and sync notes
./target/release/zk-note new --title "My Note" --body "Encrypted content"
./target/release/zk-note list
```

### 5.3 Sync Server Quick Start
```bash
# Run server
cargo run --release --bin zk-server
```

---

## 6. Milestone Completion Matrix

| Task ID | Task Description | Status | Priority |
| :--- | :--- | :--- | :--- |
| **ZK-090** | Protocol property tests (fuzzing & invariants) | **DONE** | P1 |
| **ZK-091** | Concurrency stress suite (50 workers, CAS race) | **DONE** | P1 |
| **ZK-092** | Plaintext leakage test suite (Server, Client, Logs) | **DONE** | P0 |
| **ZK-093** | Dependency and supply-chain audit (`cargo-audit`, `npm`) | **DONE** | P1 |
| **ZK-094** | Browser XSS / CSP security review | **DONE** | P1 |
| **ZK-095** | Authorization penetration tests (Multi-tenant IDOR) | **DONE** | P0 |
| **ZK-096** | Backup & restore decryption lifecycle test | **DONE** | P1 |
| **ZK-097** | Threat model review & residual risk documentation | **DONE** | P0 |
| **ZK-098** | External security review preparation package | **DONE** | P1 |
| **ZK-099** | Release candidate gate & verification suite | **DONE** | P0 |

**Result:** All Milestone 9 tasks complete. v1.0.0-RC1 ready for external security audit and deployment.
