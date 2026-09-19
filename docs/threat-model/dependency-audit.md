# Dependency and Supply-Chain Security Audit (ZK-093)

## 1. Overview and Threat Model

This document establishes the supply-chain security baseline, dependency audit methodology, and vulnerability remediation policies for the Zero-Knowledge Note-Taking application across the Rust core, server, CLI, WebAssembly, and web frontend.

Under **SEC-001** through **SEC-010** and the Repository Operating Rules (`AGENTS.md` § 10):
- Plaintext note contents and encryption keys must never be exposed or exfiltrated;
- Third-party dependencies must be minimized, reproducible, strictly audited, and pinned via lockfiles;
- No third-party runtime scripts, tracking pixels, telemetry, or remote CDN dependencies are permitted.

---

## 2. Cryptographic Dependencies Manual Review

All cryptographic operations are encapsulated in `crates/zk-crypto` and built upon vetted primitives maintained by the **RustCrypto** project.

| Dependency | Version | Purpose | Cryptographic Justification & Security Properties |
| :--- | :--- | :--- | :--- |
| `chacha20poly1305` | `0.10` | Authenticated Encryption (AEAD) | Uses **XChaCha20-Poly1305** with 192-bit (24-byte) random nonces. Eliminates birthday-bound collision risk ($2^{-96}$) under random nonce generation. Constant-time software implementation resistant to side-channel cache-timing attacks. Audited by NCC Group. |
| `argon2` | `0.5` | Key Derivation Function (KDF) | Implements **Argon2id v13**. Configured with 64 MiB memory (`memory_kib = 65536`), 3 iterations (`iterations = 3`), 1 lane (`parallelism = 1`), and 16-byte random salt. Provides high memory-hardness to defend against GPU/FPGA/ASIC brute-force attacks while resisting cache-timing attacks via hybrid 2id passes. |
| `blake2` | `0.10` | Keyed PRF / Hash Function | Implements **BLAKE2b** and **BLAKE2s**. Used for deterministic subkey derivation, chunk content hashing, and domain separation. Immune to length-extension attacks (unlike SHA-2). Extremely fast and cryptographically secure. |
| `zeroize` | `1.8` | Secret Memory Scrubbing | Implements memory clearing using volatile memory writes and compiler memory fences on `Drop`. Enforced on all key material (`VaultKey`, `NoteKey`, `AttachmentKey`, derived KEKs). |
| `rand_core` / `getrandom` | `0.6` / `0.2` | Cryptographic RNG | Cryptographically secure random number generation. Pulls entropy directly from OS CSPRNG (`getrandom` / `/dev/urandom` on Unix, `crypto.getRandomValues` on WebAssembly via `js` feature). |
| `subtle` | `2.6` | Constant-Time Operations | Provides constant-time conditional selection, equality, and tag verification (`ConstantTimeEq`). Prevents timing leaks during authentication and MAC verification. |
| `base64ct` | `1.8` | Constant-Time Base64 | Base64 encoder/decoder written specifically to prevent timing side-channels during envelope serialization/deserialization across network and storage boundaries. |

---

## 3. Dependency Inventory and Attack Surface Analysis

### 3.1 Rust Workspace Crates (`Cargo.lock`)

- **Root & Crates**: `zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync`, `zk-wasm`.
  - Dependency direction is strictly acyclic: `zk-protocol` $\leftarrow$ `zk-crypto` $\leftarrow$ `zk-core` $\leftarrow$ `zk-storage` $\leftarrow$ `zk-sync`.
  - `apps/server` depends ONLY on `zk-protocol` (and not `zk-crypto` or `zk-core`), guaranteeing structural impossibility of server possessing note decryption keys or plaintext models (SEC-002).
- **SQLite Engine**: `rusqlite 0.32` configured with `bundled` feature. Compiles SQLite directly from verified amalgamation source, removing host system library dependencies.
- **Server HTTP Stack**: `axum 0.8`, `tokio 1.43`, `tower 0.5`, `tower-http 0.6`. Standard, robust, high-performance async Rust networking stack.

### 3.2 Web Frontend (`apps/web/package-lock.json`)

- **Runtime Dependencies**:
  - `react 19.3.0`
  - `react-dom 19.3.0`
  - `zk-wasm` (`file:../../crates/zk-wasm/pkg`)
- **Zero Third-Party Trackers or CDNs**:
  - No external fonts (local system font stacks used).
  - No analytics SDKs, tag managers, or crash reporting telemetry services.
  - Zero external JavaScript tags loaded at runtime (enforced via CSP and CI tests).

---

## 4. Supply-Chain Policies & Remediation SLA

1. **Lockfile Enforcement**:
   - `Cargo.lock` and `package-lock.json` must always be checked into version control.
   - CI builds run with `--locked` / `npm ci` ensuring zero unreviewed dependency drift.
2. **Vulnerability Severity SLA**:
   - **Critical (CVSS 9.0–10.0)**: Remediate and patch within 24 hours. If an upstream patch is not yet released, pin a fork or disable the affected feature path.
   - **High (CVSS 7.0–8.9)**: Remediate within 72 hours.
   - **Medium / Low (CVSS 0.1–6.9)**: Remediate in next scheduled release cycle (< 14 days).
3. **Rust `unsafe` Policy**:
   - Root `Cargo.toml` enforces `#![forbid(unsafe_code)]` workspace-wide.
   - No `unsafe` code blocks are permitted in any crate without a formal Architectural Decision Record (ADR) and explicit approval.
4. **Supply Chain Defense Mechanisms**:
   - Typosquatting protection: dependencies are explicitly specified in workspace `Cargo.toml` with pinned minor/patch versions.
   - Source repository verification: all primary crypto dependencies originate from the official `RustCrypto` organization.

---

## 5. Audit Execution Verification

The automated audit script `scripts/audit.sh` verifies:
- `cargo audit` against the RustSec Advisory Database;
- `npm audit --prefix apps/web` against the npm security advisory database;
- Integrity of `Cargo.lock` and `apps/web/package-lock.json`.
