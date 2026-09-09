# ADR-0001: Lint, Error Handling, and Safety Conventions

## Status

Accepted

## Context

The zero-knowledge notes system requires strict guarantees around data integrity, memory safety, secret handling, and error handling:
- Decryption or verification failures must fail closed (**SEC-010**);
- Unhandled errors, unwrap panics, or partial operations must never corrupt state or compromise confidentiality;
- Production code must never crash or panic on untrusted inputs or network messages;
- Plaintext, passphrases, or decrypted keys must never leak via debug logs or error formatting (**SEC-003**).

Establishing consistent, toolchain-enforced conventions from the project inception prevents regressions and ensures consistent semantics across all crates.

## Decision

### 1. Compiler and Clippy Lint Policy

All crates in the workspace inherit centralized workspace lints configured in the root `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
```

In CI and local check scripts (`scripts/ci.sh`), lints are enforced with `-D warnings`, causing any warning to fail the build.

### 2. Prohibition of `unsafe` Code

- `unsafe_code = "forbid"` is enforced across all crates.
- If an exceptional case requires `unsafe` (e.g., low-level platform interaction or specific SIMD routines), it must be justified and approved via a dedicated Architecture Decision Record (ADR).

### 3. Prohibition of Production `unwrap()`, `expect()`, and `panic!`

- Production execution paths—especially those parsing network packets, deserializing envelopes, accessing local storage, or reading user inputs—**MUST NOT** call `.unwrap()`, `.expect()`, or `panic!()`.
- All operations that can fail must return a typed `Result<T, E>`.
- The `?` operator must be used for explicit and traceable error propagation.
- Test modules (`#[cfg(test)]`) may selectively allow `clippy::unwrap_used` or `clippy::expect_used` where assertions on expected test outcomes are appropriate.

### 4. Shared Policy for Typed Errors

- **No Stringly Typed Errors**: Functions in libraries (`zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync`) must never return `Result<T, String>` or unstructured `Box<dyn Error>`.
- **Domain-Specific Typed Enums**: Each crate defines strongly typed, domain-specific error enums implementing `std::error::Error` and `core::fmt::Display` (e.g. `ProtocolError`, `CryptoError`, `StorageError`, `CoreError`, `SyncError`).
- **Secret Redaction in Errors**: Error display and debug formatting must never interpolate or expose secret material, plaintext note contents, or decrypted keys (**SEC-003**).
- **Error Taxonomy Alignment**: Errors surfaced across crate boundaries or over the network must map cleanly to the canonical protocol error categories defined in `MASTER_SPEC.md` §20:
  - `AUTH_REQUIRED`
  - `AUTH_FORBIDDEN`
  - `VAULT_LOCKED`
  - `CRYPTO_UNSUPPORTED_VERSION`
  - `CRYPTO_AUTH_FAILED`
  - `INVALID_ENVELOPE`
  - `REVISION_CONFLICT`
  - `MUTATION_REPLAY_MISMATCH`
  - `OBJECT_NOT_FOUND`
  - `OBJECT_DELETED`
  - `SYNC_CURSOR_INVALID`
  - `RATE_LIMITED`
  - `NETWORK_UNAVAILABLE`
  - `LOCAL_STORAGE_FAILURE`
  - `SERVER_FAILURE`
- **Fail Closed**: Cryptographic authentication, decryption, or signature verification errors must immediately abort the operation and return an error; they must never substitute empty content or proceed partially (**SEC-010**).

## Consequences

- Compile-time and lint-time guarantees prevent unchecked `unwrap()` and `unsafe` code from entering production code paths.
- Error reporting is predictable, debuggable, and safe from secret leakage.
- Clear error mapping aligns protocol responses and client diagnostics without violating zero-knowledge boundaries.
