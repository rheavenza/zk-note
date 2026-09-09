# Zero-Knowledge Notes (`zk-notes`)

A zero-knowledge, offline-first note-taking application with end-to-end client-side encryption, revision-guarded synchronization, and multi-device conflict resolution.

## Architectural Boundaries & Dependency Direction

The codebase is organized as a Cargo workspace with strict layer boundaries preventing cyclic dependencies and enforcing zero-knowledge invariants (e.g. the server crate has no access to client-side cryptography or plaintext models).

```text
       zk-protocol
      (wire models, version constants, error codes)
         ▲          ▲
         │          │
         │     zk-storage
         │    (storage traits)
         │          ▲
         │          │
     zk-crypto      │
  (KDF, AEAD, keys) │
         ▲          │
         │          │
      zk-core ──────┤
   (note domain,    │
  vault lifecycle)  │
         ▲          │
         │          │
      zk-sync ──────┘
  (sync engine, CAS,
   reconciliation)
         ▲
         │
   ┌─────┴────────────────┐
   │                      │
apps/cli              apps/server
(terminal client)     (sync coordinator & ciphertext store)
                      * depends ONLY on zk-protocol
```

### Crate Roles

| Crate / App | Purpose | Dependencies |
| :--- | :--- | :--- |
| `crates/zk-protocol` | Protocol types, constants, error codes, and serialization models. | *(none)* |
| `crates/zk-crypto` | Cryptographic primitives (Argon2id, XChaCha20-Poly1305), key wrapping, and envelope encryption. | `zk-protocol` |
| `crates/zk-storage` | Abstract storage traits for encrypted objects, pending mutations, base versions, and sync cursors. | `zk-protocol` |
| `crates/zk-core` | Plaintext note domain model, vault lifecycle management, and encrypted object orchestration. | `zk-protocol`, `zk-crypto` |
| `crates/zk-sync` | Synchronization engine, pending mutation queue, conflict detection, and 3-way merge logic. | `zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage` |
| `apps/cli` | Terminal/CLI client binary (`zk-note`). | `zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync` |
| `apps/server` | Zero-knowledge ciphertext store and sync coordination server binary (`zk-server`). | `zk-protocol` |

### Security Invariants

- **SEC-001**: Plaintext never crosses the network.
- **SEC-002**: Server cannot decrypt user content; `apps/server` does not depend on `zk-crypto` or `zk-core`.
- **SEC-006**: Compare-and-swap (CAS) mutation handling prevents silent overwrite.

## Building and Testing

```bash
# Build all workspace crates and binaries
cargo build --workspace

# Run all workspace tests
cargo test --workspace

# Format and lint checks
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
