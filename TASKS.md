# TASKS.md

# Zero-Knowledge Notes — AI Agent Build Plan

This backlog is intentionally optimized for AI coding agents.

It uses:

- small task IDs;
- explicit dependencies;
- acceptance criteria;
- milestone quality gates;
- one-task-at-a-time execution.

Do not treat this like calendar Scrum. Treat milestones as shippable increments and tasks as reviewable tickets.

Status values:

```text
TODO
IN_PROGRESS
BLOCKED
DONE
```

Priority:

```text
P0 = correctness/security blocker
P1 = required for milestone
P2 = useful but deferrable
```

---

# Global Definition of Done

Every task must satisfy:

- code builds;
- relevant tests pass;
- no known security invariant violation;
- no plaintext server logging/network addition;
- task acceptance criteria satisfied;
- implementation notes recorded;
- docs updated if protocol/behavior changed.

---

# M0 — Repository and architecture foundation

## ZK-100 — Parallel Cloudflare deployment backend
Status: DONE
Priority: P0
Dependencies: authentication compatibility decision approved by user

Acceptance criteria (user-requested deployment):
- Preserve native `apps/server`; add a protocol-only Rust workers-rs backend.
- Preserve `/v1/*` sync, bootstrap, authentication, devices, sessions, and WebAuthn contracts and security invariants.
- Store server metadata in independently migrated D1; store private account-scoped ciphertext blobs in R2 behind authenticated routes.
- Prove atomic CAS, payload-bound idempotency, monotonic account sequences, history, tombstones, indexed cursor reads, and account isolation through integration/concurrency tests.
- Reconcile D1/R2 partial failures without permanently corrupting quota accounting.
- Provide local Wrangler configuration, pinned dependencies, migrations, smoke tests, and shared native/Worker contract fixtures.
- Pass applicable repository gates and local D1/R2 tests before remote staging deployment.
- If authenticated, create D1/private R2 resources, migrate, deploy to workers.dev, and smoke-test staging; do not change production DNS/client configuration.
- Document setup, rollback, backup/export, troubleshooting, limits and Free-tier CPU/D1 costs in `docs/deployment-cloudflare.md`; link from README and retain VPS/systemd documentation.

Completion notes:
- Added `apps/cloudflare-worker`, a parallel workers-rs backend that depends only on `zk-protocol`, `zk-server-auth`, and server-safe utility crates. The native Axum/SQLite server remains available and covered by its existing tests.
- Added append-only D1 migrations for accounts, vault bootstrap data, encrypted objects and history, mutation idempotency, account sequences, devices, sessions, WebAuthn state, and blob quota metadata. D1 constraints, triggers, and batched statements preserve CAS, replay, sequence, history, tombstone, and account-isolation semantics.
- Added private, account-scoped R2 blob storage behind authenticated API routes. Reservation, publication, garbage, and scheduled reconciliation state prevents failed R2 operations from permanently consuming or releasing quota incorrectly.
- Hardened both servers with verified ES256 WebAuthn ceremonies, single-use challenges, authenticated existing-account enrollment/device authorization, and rejection of UUID bearer tokens. Updated the CLI and browser adapters for the verified ceremony and recorded the decision in ADR 0006.
- Added a shared HTTP contract suite for the native server and Worker, including authentication, account/session isolation, sync CAS and concurrent replay, cursors, tombstones, and blob lifecycle. Added Miniflare/D1/R2 fault tests for storage compensation and query plans, plus an isolated Wrangler local smoke runner.
- Added pinned Wrangler/Miniflare tooling, local bindings and scripts, CI checks, ignore rules, and `docs/deployment-cloudflare.md`. Local D1 and R2 are simulated by default.
- Created remote D1 database `zk-note-staging-db` (`c1c16c84-bb64-474b-8ef7-a0c2d645d6f8`) in APAC and applied migration `0001_server.sql`. Created private R2 bucket `zk-note-ciphertext-staging` and deployed staging Worker version `efbde019-8572-44e2-b7a8-d60f9e2bee2e` at `https://zk-note-staging.trustymountainyak.workers.dev`.

Remote staging note:
- After account-level R2 activation, the remote migration state was confirmed current and the shared contract passed against staging with 84 protocol checks plus CAS/replay concurrency. Error-level log tailing during a repeated contract run produced no exceptions or D1/R2/reconciliation errors. No production DNS or client endpoint was changed.

Validation:
- Shared native/Worker contract: 84 protocol checks plus CAS/replay concurrency passed for each backend.
- Local Worker D1/R2 fault and reconciliation suite passed.
- The complete `scripts/ci.sh` gate passed, including formatting, Clippy with warnings denied, locked workspace checks/tests, native/WASM compatibility, browser tests, npm audit, cargo audit, and forbidden-dependency checks. The local Wrangler smoke and Worker D1/R2 failure suite also passed.

---

Goal: establish a stable workspace before security-sensitive implementation.

## ZK-001 — Initialize Rust workspace
Status: DONE  
Priority: P0  
Dependencies: none

Create:

```text
crates/zk-protocol
crates/zk-crypto
crates/zk-core
crates/zk-storage
crates/zk-sync
apps/cli
apps/server
```

Acceptance criteria:

- root Cargo workspace exists;
- all crates compile;
- minimal dependency direction documented;
- `cargo test --workspace` succeeds.

Completion notes:
- Created root `Cargo.toml` configuring 7-member workspace (`zk-protocol`, `zk-crypto`, `zk-core`, `zk-storage`, `zk-sync`, `apps/cli` (`zk-cli`), `apps/server` (`zk-server`)).
- Configured dependencies to enforce zero-knowledge architecture (server depends only on `zk-protocol`; no server access to crypto keys or plaintext note models).
- Documented dependency hierarchy in root `Cargo.toml` and `README.md`.
- Added baseline unit tests validating crate linkage across all workspace members.
- Verified with `cargo test --workspace`, `cargo fmt --check`, and `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

---

## ZK-002 — Add baseline CI
Status: DONE  
Priority: P0  
Dependencies: ZK-001

Acceptance criteria:

- formatter check;
- clippy;
- workspace tests;
- dependency lockfile committed;
- CI fails on test/build failure.

Completion notes:
- Added GitHub Actions workflow `.github/workflows/ci.yml` running format checks (`cargo fmt --check`), clippy (`cargo clippy --workspace --all-targets --all-features -- -D warnings`), locked dependency verification (`cargo check --workspace --locked`), workspace build, and test suite.
- Added executable local script `scripts/ci.sh` for running the exact CI gates locally.
- Verified that `Cargo.lock` is tracked and committed.
- Confirmed that build/test/lint failures produce non-zero exit codes that fail CI.

---

## ZK-003 — Define repository lint/error conventions
Status: DONE  
Priority: P1  
Dependencies: ZK-001

Acceptance criteria:

- shared policy for typed errors;
- no production `unwrap()` on external input;
- clippy policy configured;
- conventions documented in README/ADR.

Completion notes:
- Configured workspace-level compiler and clippy lints in root `Cargo.toml` (`unsafe_code = "forbid"`, `clippy::unwrap_used = "warn"`, `clippy::expect_used = "warn"`, `clippy::panic = "warn"`, `missing_debug_implementations = "warn"`).
- Enabled `[lints] workspace = true` across all 7 workspace crates and application binaries.
- Established ADR-0001 (`docs/adr/0001-lint-and-error-conventions.md`) defining the typed error hierarchy, alignment with `MASTER_SPEC.md` §20 error taxonomy, fail-closed principles (SEC-010), and prohibition of production panics and stringly typed errors.
- Updated `README.md` summarizing lint and error conventions with link to ADR-0001.
- Validated via `./scripts/ci.sh`.

---

## ZK-004 — Create protocol ADR
Status: DONE  
Priority: P0  
Dependencies: ZK-001

Document:

- protocol versioning;
- object IDs;
- object kinds;
- revision;
- server sequence;
- mutation IDs;
- cursor semantics.

Acceptance criteria:

- ADR exists;
- protocol v1 constants defined in `zk-protocol`.

Completion notes:
- Created ADR-0002 (`docs/adr/0002-protocol-v1-foundation.md`) documenting protocol and envelope versioning, object IDs, object kinds, compare-and-swap revisions, server sequence monotonicity, mutation idempotency, cursor durable advance semantics, and tombstone deletion.
- Defined protocol V1 constants in `crates/zk-protocol/src/constants.rs` (`PROTOCOL_VERSION_V1`, `ENVELOPE_VERSION_V1`, `INITIAL_EXPECTED_REVISION`, `INITIAL_OBJECT_REVISION`, `INITIAL_SERVER_SEQ`, `INITIAL_SYNC_CURSOR`, object kinds, and standard error strings).
- Implemented `ObjectKind` enum with conversions in `crates/zk-protocol/src/kind.rs`.
- Added unit tests in `crates/zk-protocol` covering constant values, round-trip kind conversions, unknown kind rejection, and error constants.
- Verified via `./scripts/ci.sh`.

---

## ZK-005 — Create crypto ADR
Status: DONE  
Priority: P0  
Dependencies: ZK-001

Record:

```text
Argon2id
XChaCha20-Poly1305
256-bit keys
192-bit nonces
CSPRNG
```

Acceptance criteria:

- crypto choices documented;
- no application crypto implementation yet;
- dependency shortlist documented.

Completion notes:
- Created ADR-0003 (`docs/adr/0003-cryptographic-architecture.md`) documenting Argon2id KDF (RFC 9106), XChaCha20-Poly1305 AEAD, 256-bit symmetric keys, 192-bit nonces with CSPRNG, key wrapping hierarchy, zeroization, and secret redaction.
- Documented dependency shortlist (`chacha20poly1305`, `argon2`, `zeroize`, `subtle`, `getrandom`, `rand_core`) for upcoming Milestone M1 implementation.
- Confirmed zero application crypto code implemented in this step.
- Verified workspace passes all checks via `./scripts/ci.sh`.

---

## ZK-006 — Define binary/serialization conventions
Status: DONE  
Priority: P0  
Dependencies: ZK-004, ZK-005

Decide and document:

- UUID encoding;
- byte encoding for JSON APIs;
- envelope serialization;
- timestamp policy;
- version fields;
- canonical plaintext serialization expectations.

Acceptance criteria:

- `docs/protocol/v1.md` exists;
- example payloads included;
- round-trip serialization unit tests.

Completion notes:
- Authored `docs/protocol/v1.md` defining RFC 4122 lowercase UUID encoding, RFC 4648 §4 Standard Base64 byte encoding with padding, RFC 3339 UTC timestamps (`YYYY-MM-DDTHH:MM:SS.sssZ`), protocol/envelope/crypto/schema version fields, and canonical plaintext note expectations (UTF-8, no BOM, Unix newlines, sorted unique lowercase tags).
- Documented full example payloads for `EncryptedEnvelope`, `VaultBootstrap`, CAS push request, push response, revision conflict response, pull changes response, and plaintext note schema.
- Added serde serialization models in `crates/zk-protocol` (`envelope.rs`, `vault.rs`, `sync.rs`, `note.rs`).
- Implemented comprehensive unit tests verifying round-trip JSON serialization/deserialization across all protocol models and rejecting malformed inputs.
- Validated via `./scripts/ci.sh` (M0 gate passed).

---

### M0 Gate

Run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Do not begin M1 until the protocol/crypto ADRs are present.

---

# M1 — Cryptographic core

Goal: implement independently testable vault and object encryption.

## ZK-010 — Secure key types
Status: DONE  
Priority: P0  
Dependencies: M0

Implement strongly typed:

```text
VaultKey
ObjectKey
RecoveryKey
KeyEncryptionKey
```

Acceptance criteria:

- key lengths enforced;
- debug formatting redacts secrets;
- secret zeroization used where practical;
- random generation uses OS CSPRNG;
- tests cover invalid sizes.

Completion notes:
- Implemented strongly typed 256-bit (32-byte) key wrappers: `VaultKey`, `ObjectKey`, `RecoveryKey`, and `KeyEncryptionKey` in `crates/zk-crypto/src/keys.rs`.
- Enforced strict 32-byte length checks in `from_slice` returning typed `CryptoError::InvalidKeyLength`.
- Implemented `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` to safely scrub secret key buffers from memory on drop.
- Implemented custom `fmt::Debug` redacting secret material to prevent secret leakage in logs (SEC-003).
- Implemented constant-time equality comparisons using `subtle::ConstantTimeEq`.
- Integrated OS CSPRNG random generation via `rand_core::OsRng`.
- Added unit tests covering invalid sizes (0, 1, 16, 31, 33, 48, 64, 128 bytes), valid construction, debug redaction, CSPRNG generation, constant-time equality, and memory zeroization.
- Verified via `./scripts/ci.sh`.

---

## ZK-011 — Argon2id KEK derivation
Status: DONE  
Priority: P0  
Dependencies: ZK-010

Acceptance criteria:

- passphrase + stored params derive KEK;
- params serialize/deserialize;
- production defaults separate from test parameters;
- known deterministic test vector exists;
- passphrase is not retained unnecessarily.

Completion notes:
- Implemented Argon2id key derivation in `crates/zk-crypto/src/kdf.rs` deriving 256-bit `KeyEncryptionKey` from passphrase and `KdfParams`.
- Defined `KdfParams` supporting serde JSON serialization and round-trip conversions to/from `zk_protocol::vault::KdfParams`.
- Established separate production parameters (`64 MiB`, 3 iterations, 1 parallelism) and fast test parameters (`1 MiB`, 1 iteration, 1 parallelism).
- Established known deterministic test vector in unit tests verifying exact byte output `007f6b258779db1c07dda5ff432b9025b66d7ec395ed9acba7939210b3ed97b8`.
- Passphrase is taken as a borrowed slice `&[u8]` and processed directly by Argon2 without retention.
- Validated via `./scripts/ci.sh`.

---

## ZK-012 — Vault Key creation and wrapping
Status: DONE  
Priority: P0  
Dependencies: ZK-010, ZK-011

Acceptance criteria:

- random Vault Key generated;
- Vault Key wrapped by KEK using AEAD;
- unwrap returns identical key;
- wrong KEK fails closed;
- tampered wrapper fails closed.

Completion notes:
- Implemented `wrap_vault_key` and `unwrap_vault_key` in `crates/zk-crypto/src/vault.rs` using XChaCha20-Poly1305 AEAD with 192-bit CSPRNG nonces (`OsRng`).
- Verified round-trip wrap and unwrap restores identical Vault Key.
- Verified wrong KEK fails closed (`CryptoError::DecryptionFailed`).
- Verified tampering with ciphertext or nonce fails closed.
- Implemented bidirectional conversions between `zk_crypto::vault::WrappedVaultKey` and `zk_protocol::vault::WrappedVaultKey`.
- Validated via `./scripts/ci.sh`.

---

## ZK-013 — Recovery Key wrapping
Status: DONE  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- random Recovery Key generated;
- same Vault Key independently wrapped;
- Recovery Key can restore Vault Key;
- wrong Recovery Key fails;
- recovery representation has checksum or typo-detection strategy documented.

Completion notes:
- Implemented `wrap_vault_key_recovery` and `unwrap_vault_key_recovery` in `crates/zk-crypto/src/vault.rs` independently wrapping the Vault Key using a 256-bit `RecoveryKey`.
- Implemented `format_recovery_key` and `parse_recovery_key` in `crates/zk-crypto/src/recovery.rs` appending a 4-byte cryptographic BLAKE2b checksum to the 32-byte key (36 bytes total = 72 hex digits), formatted into 9 groups of 8 hex digits separated by hyphens (80 characters total).
- Implemented constant-time checksum comparison (`subtle::ConstantTimeEq`) detecting typos before attempting cryptographic operations.
- Added tests covering recovery key wrapping round-trip, wrong recovery key rejection, formatted string parsing, and typo detection.
- Validated via `./scripts/ci.sh`.

---

## ZK-014 — Object Key wrapping
Status: DONE  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- per-object random key;
- wrapped using Vault Key;
- object ID/kind bound via AAD according to protocol;
- tampered AAD fails.

Completion notes:
- Implemented `wrap_object_key` and `unwrap_object_key` in `crates/zk-crypto/src/object.rs` wrapping a per-object random `ObjectKey` under the `VaultKey` with XChaCha20-Poly1305.
- Implemented canonical AAD builder `build_aad` binding envelope version, object ID string, and object kind (`zk-envelope-aad:<version>:<object_id>:<kind>`).
- Added tests verifying round-trip unwrapping and fail-closed rejection when object ID, object kind, or envelope version is modified in the AAD.
- Validated via `./scripts/ci.sh`.

---

## ZK-015 — Object payload encryption
Status: DONE  
Priority: P0  
Dependencies: ZK-014

Acceptance criteria:

- XChaCha20-Poly1305 encrypt/decrypt;
- random unique nonce per encryption;
- wrong Object Key fails;
- ciphertext tamper fails;
- unknown envelope version fails.

Completion notes:
- Implemented `encrypt_object_payload` and `decrypt_object_payload` in `crates/zk-crypto/src/object.rs` using XChaCha20-Poly1305 with unique 192-bit CSPRNG nonces and canonical AAD metadata binding.
- Added unit tests verifying payload encryption/decryption round-trip, wrong Object Key rejection, ciphertext tamper rejection, and nonce tamper rejection.
- Validated via `./scripts/ci.sh`.

---

## ZK-016 — Encrypted envelope v1
Status: DONE  
Priority: P0  
Dependencies: ZK-014, ZK-015

Acceptance criteria:

- complete envelope type implemented;
- serialization round-trip;
- malformed input rejected;
- no secret values exposed through Debug/Display;
- compatibility test vector committed.

Completion notes:
- Implemented `encrypt_envelope` and `decrypt_envelope` in `crates/zk-crypto/src/object.rs` assembling complete versioned `EncryptedEnvelope` (V1) holding wrapped key and encrypted payload containers.
- Validated serialization and deserialization round-trip with `zk_protocol::envelope::EncryptedEnvelope`.
- Enforced `[REDACTED]` debug representation for all key types (`VaultKey`, `ObjectKey`, `RecoveryKey`, `KeyEncryptionKey`).
- Committed static compatibility test vector in `test_compatibility_test_vector_v1` verifying deterministic decryption and fail-closed tamper detection.
- Validated via `./scripts/ci.sh`.

---

## ZK-017 — Vault password rewrap
Status: DONE  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- old passphrase unwraps Vault Key;
- new passphrase derives new KEK;
- Vault Key identity stays unchanged;
- existing object ciphertext remains unchanged.

Completion notes:
- Implemented `rewrap_vault_key` in `crates/zk-crypto/src/vault.rs` enabling vault password changes without re-encrypting object content.
- Unwraps existing `VaultKey` using old passphrase and old KDF params, derives new KEK using new passphrase and new KDF params, and wraps the unchanged `VaultKey` under the new KEK.
- Added tests verifying Vault Key identity preservation, successful unlock with new passphrase, rejection with old passphrase, and continued decryptability of existing object ciphertexts.
- Validated via `./scripts/ci.sh`.

---

## ZK-018 — Crypto negative/fuzz test harness
Status: DONE  
Priority: P1  
Dependencies: ZK-016

Acceptance criteria:

- malformed envelope corpus;
- truncated inputs;
- unknown versions;
- modified nonce/ciphertext/AAD;
- no panic on untrusted envelope bytes.

Completion notes:
- Created negative and robustness test harness in `crates/zk-crypto/tests/crypto_negative_tests.rs`.
- Tested malformed envelope corpus (`MALFORMED_CORPUS` covering empty strings, invalid JSON, missing fields, corrupted Base64).
- Tested truncated inputs (truncated nonces < 24 bytes, truncated ciphertexts < 16 bytes auth tag, truncated recovery keys).
- Tested unknown envelope versions (versions 0, 2, 3, 42, 999, u32::MAX) returning `CryptoError::UnsupportedVersion`.
- Tested bit flips across payload ciphertext, payload nonce, wrapped key ciphertext, wrapped key nonce, and AAD fields (object ID and kind), verifying all fail closed without panics.
- Tested pseudo-random fuzzed envelope mutations over 100 iterations with `std::panic::catch_unwind` demonstrating panic-free fail-closed handling.
- Validated via `./scripts/ci.sh`.

---

### M1 Gate

Required tests:

```text
vault create/unlock
wrong password
recovery unlock
password change
object round trip
tamper rejection
AAD rejection
version rejection
```

Gate verification:
- `vault create/unlock`: covered in `test_vault_key_wrapping_round_trip`
- `wrong password`: covered in `test_vault_key_wrapping_round_trip`
- `recovery unlock`: covered in `test_recovery_key_wrapping_and_formatting`
- `password change`: covered in `test_vault_password_rewrap`
- `object round trip`: covered in `test_complete_envelope_lifecycle`
- `tamper rejection`: covered in `test_modified_components_fail_closed`
- `AAD rejection`: covered in `test_object_key_wrapping_and_aad_binding`
- `version rejection`: covered in `test_unknown_envelope_versions_rejected`

All required tests passing. M1 gate passed!

Do not implement server persistence before M1 is green.

---

# M2 — Local-only encrypted CLI

Goal: prove the note model and encrypted persistence without networking.

## ZK-020 — Plaintext note model
Status: DONE  
Priority: P0  
Dependencies: M1

Implement:

```text
schema_version
title
body
tags
created_at
updated_at
attachments placeholder
```

Acceptance criteria:

- serialization deterministic enough for application requirements;
- schema version present;
- validation limits documented.

Completion notes:
- Implemented `PlaintextNote` domain model (aliased as `Note`) and `NoteBuilder` in `crates/zk-core/src/note.rs` with `schema_version = 1`, `title`, `body`, `tags`, `created_at`, `updated_at`, and `attachments` placeholder.
- Implemented canonicalization: BOM stripping (`\u{feff}`), Markdown newline normalization (`\r\n` and `\r` -> `\n`), tag whitespace trimming, lowercase conversion, deduplication, and ascending lexicographical sorting.
- Implemented deterministic canonical JSON serialization (`to_canonical_json`, `to_canonical_bytes`) ensuring identical logical note state produces byte-identical canonical JSON.
- Implemented strict RFC 3339 timestamp parsing and validation in `crates/zk-core/src/time.rs` covering year, month, day-of-month, leap year, hour/minute/second, and timezone offsets without heavy external dependencies.
- Enforced and documented validation limits in `crates/zk-core/src/note.rs`, `crates/zk-core/README.md`, and `docs/protocol/v1.md` §3.4 (`MAX_TITLE_LEN = 1024` bytes, `MAX_BODY_LEN = 10 MiB`, `MAX_TAGS_COUNT = 100`, `MAX_TAG_LEN = 128` bytes, `MAX_ATTACHMENTS_COUNT = 100`, `MAX_ATTACHMENT_ID_LEN = 128` bytes, `NOTE_SCHEMA_VERSION_V1 = 1`).
- Implemented `encrypt(&vault_key, object_id)` and `decrypt(&envelope, &vault_key)` integrating domain notes directly with `zk-crypto` encrypted envelopes.
- Implemented typed `NoteValidationError` and `CoreError` in `crates/zk-core/src/error.rs`.
- Added unit tests covering default construction, builder pattern, BOM stripping, newline normalization, tag canonicalization, deterministic serialization, all validation limit failures, and envelope encryption/decryption round trips.
- Validated via `./scripts/ci.sh`.

---

## ZK-021 — Local storage traits
Status: DONE  
Priority: P0  
Dependencies: ZK-020

Define storage traits for:

- encrypted objects;
- pending mutations;
- base versions;
- sync state.

Acceptance criteria:

- core has no SQLite dependency;
- storage interface test doubles available.

Completion notes:
- Defined storage abstraction traits in `crates/zk-storage/src/traits.rs`:
  - `ObjectStore`: CRUD, kind filtering, and tombstone tracking for `StoredEncryptedObject`.
  - `MutationStore`: FIFO enqueue, retrieval, object lookup, status/retry updates, and dequeue for `PendingMutation`.
  - `BaseVersionStore`: storage, retrieval, and pruning of `BaseVersion` envelopes for three-way conflict merge.
  - `SyncStateStore`: tracking and advancing `SyncState` (sync cursor and device state).
  - `LocalStorage`: composite blanket trait combining all four storage interfaces.
- Defined storage domain models in `crates/zk-storage/src/models.rs`: `StoredEncryptedObject`, `ObjectFilter`, `PendingMutation`, `MutationType`, `MutationStatus`, `BaseVersion`, and `SyncState`.
- Defined typed error enum `StorageError` in `crates/zk-storage/src/error.rs`.
- Implemented `MemoryStorage` in `crates/zk-storage/src/memory.rs` providing a thread-safe in-memory test double implementing all storage traits.
- Confirmed zero SQLite dependencies in `zk-core` and `zk-storage`.
- Documented architecture and traits in `crates/zk-storage/README.md`.
- Added unit tests covering all four storage trait implementations in `MemoryStorage`.
- Validated via `./scripts/ci.sh`.

---

## ZK-022 — SQLite encrypted cache
Status: DONE  
Priority: P0  
Dependencies: ZK-021

Acceptance criteria:

- migrations exist;
- encrypted envelopes persisted;
- no plaintext title/body/tag columns;
- reopen preserves encrypted objects;
- tests inspect DB schema/content for plaintext leakage.

Completion notes:
- Created initial SQLite migration in `migrations/001_initial_local_storage.sql` establishing tables for `local_objects`, `pending_mutations`, `encrypted_base_versions`, and `sync_state` with index coverage and idempotent migration tracking via `_schema_migrations`.
- Implemented `SqliteStorage` in `crates/zk-storage/src/sqlite.rs` backing all storage traits (`ObjectStore`, `MutationStore`, `BaseVersionStore`, `SyncStateStore`, and `LocalStorage`).
- Confirmed zero-knowledge local persistence (SEC-009): tables store strictly opaque encrypted envelopes without plaintext columns for title, body, or tags.
- Added tests verifying:
  - Database schema inspection (`PRAGMA table_info`) verifying complete absence of plaintext column names across all tables.
  - Raw binary disk inspection confirming no plaintext canary strings leak into SQLite database files.
  - Full CRUD operations and kind filtering.
  - Persistence across database close and reopen from disk.
- Validated via `./scripts/ci.sh`.

---

## ZK-023 — Vault init/unlock/lock CLI
Status: DONE  
Priority: P0  
Dependencies: ZK-013, ZK-022

Commands:

```text
zk-note init
zk-note unlock
zk-note lock
```

Acceptance criteria:

- passphrase input not echoed;
- vault metadata persists;
- unlock required for plaintext operations;
- lock clears in-memory vault state.

Completion notes:
- Implemented `VaultManager` and `VaultSession` in `crates/zk-core/src/vault.rs` providing `init_vault`, `unlock_with_passphrase`, and `unlock_with_recovery_key`.
- Implemented CLI entrypoint and commands (`zk-note init`, `zk-note unlock`, `zk-note lock`, `zk-note status`) in `apps/cli` using `clap` and `rpassword`.
- Passphrase input uses `rpassword::prompt_password` with terminal echo disabled; confirmation prompt enforced during `init`.
- Vault metadata is deterministically persisted to `vault.json` (`VaultBootstrap`), holding wrapped master keys and Argon2id KDF parameters with zero plaintext.
- SQLite encrypted cache (`notes.db`) is initialized during `zk-note init` using `SqliteStorage`.
- Active session keys are stored in a restricted session file (`session.key`, permissions `0600` on Unix) and zeroized in-memory with `zeroize::Zeroize` and on-disk with zero-byte overwrite before removal upon `zk-note lock`.
- Added unit tests in `apps/cli/src/main.rs` covering the full init -> unlock -> lock lifecycle, recovery key unlocks, and session permission/clearing guarantees. Validated via `./scripts/ci.sh`.

---

## ZK-024 — Create/show/list local notes
Status: DONE  
Priority: P0  
Dependencies: ZK-020, ZK-023

Acceptance criteria:

- create encrypted note;
- show decrypts only while unlocked;
- list works using locally decrypted state while unlocked;
- database contains ciphertext only.

Completion notes:
- Implemented `zk-note new` (with alias `create`), `zk-note show <note-id>`, and `zk-note list` subcommands in `apps/cli` (`commands.rs`, `main.rs`).
- `zk-note new` validates input, serializes to canonical plaintext JSON, encrypts with a fresh Object Key wrapped under the session `VaultKey`, saves the encrypted envelope to SQLite `local_objects`, and enqueues a `PendingMutation` in `pending_mutations`. Supports piped stdin or command arguments.
- `zk-note show` requires an active unlocked session (`VaultKey`), resolves full UUIDs or unique prefix matches (>= 4 chars), decrypts the envelope in-memory, and outputs formatted markdown or JSON. Fails closed with `VaultLocked` when locked.
- `zk-note list` requires an active unlocked session, decrypts stored envelopes in-memory to present titles, update timestamps, and tags, with support for tag filtering (`--tag`) and JSON output (`--json`). Fails closed with `VaultLocked` when locked.
- Verified that SQLite database `notes.db` contains ciphertext only, with zero plaintext leakage in database columns or raw disk bytes.
- Added comprehensive unit and integration tests in `apps/cli/src/main.rs`. Validated via `./scripts/ci.sh`.

---

## ZK-025 — `$EDITOR` edit flow
Status: DONE  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- temporary edit handling documented;
- plaintext temp-file risk explicitly mitigated or clearly surfaced;
- updated note re-encrypted;
- editor failure does not corrupt prior note.

Security note:

Prefer secure temporary-file behavior. If plaintext temp files cannot be eliminated, document the native-client threat boundary and cleanup behavior.

Completion notes:
- Documented native client temporary edit threat boundaries, RAM-backed tmpfs vs physical disk lifecycles, and residual risks in `docs/threat-model/cli-editor-security.md`.
- Authored `docs/adr/0004-cli-editor-workflow.md` documenting frontmatter format, permission enforcement, base version retention, and error handling.
- Implemented `TempFileGuard` in `apps/cli/src/edit.rs` prioritizing RAM-backed tmpfs (`/dev/shm`, `$XDG_RUNTIME_DIR`), enforcing `0600` file permissions on Unix, and guaranteeing in-memory and on-disk zeroization with `sync_all()` prior to file unlinking via an RAII drop guard.
- Implemented Markdown frontmatter serialization and parsing (`note_to_edit_buffer`, `parse_edit_buffer`) in `apps/cli/src/edit.rs` allowing simultaneous editing of title, tags, and body with fallback handling.
- Implemented `zk-note edit <note-id>` with `$EDITOR`/`$VISUAL` integration, shell execution, and programmatic overrides (`--title`, `--body`, `--tag`, `--editor`) in `apps/cli/src/commands.rs` and `apps/cli/src/main.rs`.
- Ensured atomic re-encryption: validates note schema, archives prior revision envelope into `BaseVersionStore` (`encrypted_base_versions`) for three-way conflict merge, increments object revision, saves re-encrypted envelope, and enqueues upsert into `pending_mutations`.
- Guaranteed editor failure atomicity: non-zero editor exit status or validation errors drop the temp guard (zeroing and deleting the file) without writing to SQLite, keeping prior revisions intact and uncorrupted.
- Added comprehensive unit tests in `apps/cli/src/edit.rs` and `apps/cli/src/main.rs`. Validated via `./scripts/ci.sh`.

---

## ZK-026 — Local delete/tombstone model
Status: DONE  
Priority: P0  
Dependencies: ZK-024

Acceptance criteria:

- delete becomes local tombstone state;
- deletion revision intent represented;
- history/base state remains available.

Completion notes:
- Extended `BaseVersionStore` trait with `list_base_versions` and implemented in `MemoryStorage` and `SqliteStorage` to query historical base envelopes ordered by revision ascending.
- Implemented `cmd_delete` in `apps/cli/src/commands.rs`:
  - When deleting a note, archives pre-deletion version via `storage.put_base_version`, increments monotonic revision counter (`R + 1`), sets `is_deleted = true` in SQLite while preserving the ciphertext envelope (tombstone), and records UTC timestamp.
  - Enqueues `PendingMutation` with `mutation_type = MutationType::Delete`, `expected_revision = prior_revision` (representing deletion revision intent for conflict-safe CAS sync), and preserved envelope.
  - Supports `--purge` flag to permanently remove the object and all historical base versions.
- Updated `find_note_object` in `apps/cli/src/commands.rs` to take `include_deleted: bool` and fail closed with typed `CliError::NoteAlreadyDeleted` when an active note is expected.
- Updated `cmd_list` and `NoteSummary` with `is_deleted` field and `--include-deleted` CLI flag.
- Implemented `cmd_history` in `apps/cli/src/commands.rs` and CLI subcommand `zk-note history <note_id> [--revision <rev>] [--json]` to inspect complete revision history or retrieve specific historical revisions while unlocked.
- Added comprehensive unit tests in `apps/cli/src/main.rs` covering delete tombstone state transitions, deletion revision intent verification, base version retention, history retrieval, locked-vault fail-closed behavior, and raw SQLite file ciphertext-only inspection (zero plaintext leakage). Validated via `./scripts/ci.sh`.

---

## ZK-027 — Local search
Status: DONE  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- title/body/tag search;
- search operates only while unlocked;
- persistent DB has no plaintext index;
- lock clears in-memory index.

Completion notes:
- Implemented `InMemorySearchIndex` in `crates/zk-core/src/search.rs` supporting:
  - Multi-field search over note titles, tags, and bodies with relevance scoring and tie-breaking by `updated_at` descending.
  - Multi-term queries with AND semantics across fields.
  - Case-insensitive matching and explicit `#tag` syntax for targeted tag filtering.
  - Contextual snippet extraction around matched terms in note bodies with clean boundary trimming.
  - Volatile memory scrubbing via `Zeroize` and `ZeroizeOnDrop` on `IndexedNote` and `InMemorySearchIndex::clear`.
- Integrated `search_index` into `VaultSession` in `crates/zk-core/src/vault.rs`:
  - `session.search_index()` and `session.search_index_mut()` provide index access while unlocked, returning `Err(CoreError::VaultLocked)` when locked.
  - `session.lock()` automatically clears and zeroes the in-memory search index.
- Implemented `cmd_search` in `apps/cli/src/commands.rs` and added `zk-note search <query> [--json]` subcommand in `apps/cli/src/main.rs`.
- Added comprehensive unit tests in `crates/zk-core/src/search.rs`, `crates/zk-core/src/vault.rs`, and `apps/cli/src/main.rs` covering:
  - Title, body, tag, `#tag`, multi-term AND matching, case-insensitivity, and empty queries.
  - Fail-closed behavior (`CliError::VaultLocked`) when search is attempted while vault is locked.
  - Tombstone exclusion (deleted notes are excluded from search results).
  - Memory scrubbing on index clear and vault lock.
  - Persistent SQLite inspection verifying no plaintext tokens or search tables (`fts%`, `index`, `search`) exist in the database file.
- Validated via `./scripts/ci.sh`.

---

## ZK-028 — Local history
Status: DONE  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- encrypted previous versions retained locally;
- history command can display selected revision while unlocked.

Completion notes:
- Defined `NoteHistoryItem` in `crates/zk-core/src/note.rs` and exported via `zk-core` for unified note revision history models across client adapters.
- Implemented encrypted local base version retention in `crates/zk-storage`:
  - `encrypted_base_versions` stores historical revision envelopes `(object_id, revision, envelope, stored_at)` in SQLite with zero plaintext leakage (SEC-001, SEC-002, SEC-009).
  - Every note edit and tombstone deletion archives the pre-mutation revision into `encrypted_base_versions` via `storage.put_base_version`.
- Added typed `CliError::RevisionNotFound { note_id, revision }` error in `apps/cli/src/error.rs`.
- Implemented `cmd_history` in `apps/cli/src/commands.rs`:
  - Lists complete historical progression across all revisions (revisions 1..N) with revision numbers, UTC timestamps, Active/Deleted status, and titles.
  - With `--revision <rev>`, decrypts and displays the selected historical revision's full title, tags, and body content while unlocked.
  - Supports `--json` flag for machine-readable JSON output.
  - Fails closed with `CliError::VaultLocked` when vault is locked.
- Added comprehensive unit tests in `apps/cli/src/main.rs`:
  - `test_cli_history_multi_revision_retention_and_selection`: tests multi-revision retention across edits, full history listing, selected revision display, typed `RevisionNotFound` error, and locked-vault fail-closed protection.
  - `test_m2_gate_full_lifecycle_demo`: automated reproduction of the full M2 gate manual demo script (`init` -> `new` -> `lock` -> inspect SQLite ciphertext -> `reopen` -> `unlock` -> `search` -> `edit` -> `delete` -> `history` -> `lock`).
- Validated via `./scripts/ci.sh` (all 86 tests passed; M2 gate passed).

---

### M2 Gate

Manual demo:

```text
init vault
create notes
close process
inspect SQLite → no note plaintext
reopen
unlock
search
edit
delete
history
lock
```

---

# M3 — Zero-knowledge sync server

Goal: server stores ciphertext and coordinates safe revisions without note semantics.

## ZK-030 — Server skeleton
Status: DONE  
Priority: P0  
Dependencies: M0

Acceptance criteria:

- Axum server starts;
- configuration loading;
- health endpoint;
- structured logs with redaction policy.

Implementation notes:
- Implemented `zk-server` in `apps/server` using Axum 0.8 and Tokio, with zero dependencies on `zk-crypto` or `zk-core` (SEC-002).
- Added `ServerConfig` with environment variable loading (`ZK_SERVER_HOST`/`HOST`, `ZK_SERVER_PORT`/`PORT`, `ZK_SERVER_LOG_LEVEL`/`RUST_LOG`, `ZK_SERVER_LOG_FORMAT`/`LOG_FORMAT`), parsing validation, and fallback defaults.
- Implemented structured JSON and text logging via `tracing-subscriber` with SEC-003 compliant redaction policy:
  - `is_sensitive_header`: classifies `authorization`, `cookie`, `x-auth-token`, `x-session-token`, `x-api-key`, `x-recovery-key`, etc. as sensitive;
  - `redact_header_value` / `sanitize_headers` / `sanitize_header_map`: redacts token credentials (preserving scheme such as `Bearer [REDACTED]`);
  - `redacted_trace_middleware`: logs method, path, response status, duration (ms) without query parameters or plaintext/secret headers.
- Implemented `request_id_middleware` injecting/propagating `x-request-id` correlation IDs.
- Implemented `health_handler` responding to `GET /health` and `GET /v1/health` with HTTP 200 OK, service status, package version, and `protocol_version: 1`.
- Added graceful shutdown signal handling for `SIGINT` (Ctrl+C) and `SIGTERM`.
- Added unit and integration tests covering configuration loading, live TCP socket lifecycle, health endpoint JSON payloads, and strict redaction rules.

---


## ZK-031 — PostgreSQL schema/migrations
Status: DONE  
Priority: P0  
Dependencies: ZK-030

Implement initial:

```text
accounts
vaults
encrypted_objects
object_history
processed_mutations
devices
```

Acceptance criteria:

- migrations reproducible;
- account/object uniqueness enforced;
- indexes support sync sequence reads.

Implementation notes:
- Authored initial PostgreSQL / server schema migration in `migrations/002_initial_server_schema.sql` based on MASTER_SPEC.md §8.
- Defined all 6 core tables (`accounts`, `vaults`, `encrypted_objects`, `object_history`, `processed_mutations`, `devices`) along with `schema_migrations` tracking table:
  - Strict zero-knowledge layout: stores only opaque envelopes (`wrapped_key`, `payload`), KDF params, salts, and revision metadata; zero plaintext note columns (titles, bodies, tags, passphrases).
  - Uniqueness and primary keys: `accounts(id)`, `vaults(account_id)`, `encrypted_objects(account_id, object_id)`, `object_history(account_id, object_id, revision)`, `processed_mutations(account_id, mutation_id)`, `devices(account_id, device_id)`.
  - Foreign key constraints with cascading deletion from `accounts`.
  - Unique index `encrypted_objects_account_seq_idx` on `(account_id, server_seq)` ensuring monotonic sequence allocation per account.
  - Secondary indexes: `idx_object_history_account_seq`, `idx_processed_mutations_account_object`, `idx_devices_account_last_ack`.
- Implemented `apps/server/src/db/`:
  - `schema.rs`: strongly typed row structs (`AccountRow`, `VaultRow`, `EncryptedObjectRow`, `ObjectHistoryRow`, `ProcessedMutationRow`, `DeviceRow`, `SchemaMigrationRow`), table/index constants, and `verify_database_schema` integrity checker.
  - `migrations.rs`: embedded `002_initial_server_schema.sql`, transactional `run_server_migrations` runner with idempotent tracking, and `create_in_memory_db` test database factory.
- Added integration test suite `apps/server/tests/server_db_migration_tests.rs`:
  - Verified reproducible, idempotent migration execution from clean state;
  - Verified rejection of duplicate accounts, duplicate vaults, and foreign key violations;
  - Verified rejection of duplicate `(account_id, object_id)` and duplicate `(account_id, server_seq)`;
  - Verified query plan uses `encrypted_objects_account_seq_idx` for sync sequence pull queries (`account_id = ? AND server_seq > ? ORDER BY server_seq ASC`);
  - Verified zero plaintext columns exist in database schema.

---


## ZK-032 — Vault bootstrap API
Status: DONE  
Priority: P0  
Dependencies: ZK-031

Acceptance criteria:

- server stores only KDF params + wrapped keys;
- no passphrase API field;
- get/bootstrap round-trip;
- cross-account access denied.

Implementation notes:
- Implemented `POST /v1/vault/bootstrap` and `GET /v1/vault/bootstrap` in `apps/server/src/routes/vault.rs`.
- Enforced zero-knowledge invariants (SEC-001/SEC-002):
  - Stored strictly KDF parameters (`algorithm`, `salt`, `memory_kib`, `iterations`, `parallelism`) and wrapped key envelopes (`wrapped_vault_key`, `recovery_wrapped_vault_key`) in the `vaults` database table;
  - Verified no passphrase/password/key field exists in the `VaultBootstrap` API model, with recursive request payload inspection to strictly reject any forbidden credentials (`passphrase`, `password`, `secret`, etc.) with HTTP 400 (`INVALID_VAULT_BOOTSTRAP`).
- Implemented `AuthenticatedAccount` extractor in `apps/server/src/auth.rs` enforcing `Bearer <uuid>` authentication:
  - Missing or malformed headers return HTTP 401 (`AUTH_REQUIRED`);
  - Scopes all queries strictly to the caller's authenticated `account_id`;
  - Explicitly rejects mismatched cross-account headers (`x-account-id`) with HTTP 403 (`AUTH_FORBIDDEN`).
- Implemented `ServerDb` vault persistence operations (`create_vault_bootstrap` and `get_vault_bootstrap`) in `apps/server/src/db/store.rs`:
  - Enforces single-vault-per-account lifecycle, returning HTTP 409 (`VAULT_ALREADY_EXISTS`) on duplicate bootstrap calls;
  - Decodes/encodes Base64 salts and JSON wrapped keys with full lossless fidelity.
- Added integration test suite in `apps/server/tests/server_vault_bootstrap_tests.rs`:
  - Verified POST/GET round-trip preserving all cryptographic fields;
  - Verified rejection of forbidden passphrase fields;
  - Verified cross-account access rejection and account isolation;
  - Verified authentication enforcement (SEC-003).

---


## ZK-033 — Server sequence allocator
Status: DONE  
Priority: P0  
Dependencies: ZK-031

Acceptance criteria:

- monotonic per account;
- transactional;
- concurrency test proves uniqueness/order.

Implementation notes:
- Created migration `migrations/003_account_sequences.sql` defining `account_sequences` table (`account_id`, `current_seq`, `updated_at`) with backfilling from `encrypted_objects (MAX(server_seq))` for existing accounts.
- Added `TABLE_ACCOUNT_SEQUENCES` and `AccountSequenceRow` schema definitions to `apps/server/src/db/schema.rs` and registered migration 003 into `SERVER_MIGRATIONS` in `apps/server/src/db/migrations.rs`.
- Implemented sequence allocator in `apps/server/src/db/store.rs`:
  - `ServerDb::allocate_sequence_in_tx(&tx, account_id)`: atomic transactional upsert allocating next sequence (`INSERT ... ON CONFLICT (account_id) DO UPDATE SET current_seq = account_sequences.current_seq + 1 ... RETURNING current_seq`);
  - `ServerDb::allocate_next_sequence(&self, account_id)`: atomic single-sequence transaction helper;
  - `ServerDb::current_sequence_on_conn(&conn, account_id)` and `ServerDb::current_sequence(&self, account_id)`: inspection helper returning highest sequence (or 0 if unallocated);
  - `ServerDb::current_sequence_in_tx(&tx, account_id)`: transaction-scoped sequence inspection;
  - `ServerDb::connection(&self)`: thread-safe connection mutex accessor for multi-operation transactions.
- Verified acceptance criteria with unit and integration tests:
  - Monotonic per account: sequence begins at 1 and increments strictly monotonically; distinct accounts have completely independent sequence spaces.
  - Transactional: sequence increments execute inside database transactions; transaction rollback cleanly rolls back sequence increments without gaps or orphan state; dropped transactions roll back automatically.
  - Concurrency: 50 concurrent tokio tasks simultaneously allocating sequences for a single account produce strictly unique, contiguous numbers `1..=50` with no duplicates and no gaps; multi-account concurrent allocations (90 tasks across 3 accounts) maintain full per-account isolation.
  - Backfill verification: migration 003 correctly initializes sequence counter from `MAX(server_seq)` of existing objects.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency check, workspace tests).

---

## ZK-034 — CAS mutation endpoint
Status: DONE  
Priority: P0  
Dependencies: ZK-031, ZK-033

Implement:

```text
POST /v1/sync/push
```

Acceptance criteria:

- create expected revision 0;
- update requires exact current revision;
- stale update rejected;
- successful update increments revision exactly once;
- previous revision stored in history.

Implementation notes:
- Implemented `POST /v1/sync/push` endpoint handler in `apps/server/src/routes/sync.rs` mounted on the Axum router.
- Implemented CAS push transactional logic in `apps/server/src/db/store.rs`:
  - `ServerDb::push_mutation_in_tx(&tx, account_id, &request)`: implements MASTER_SPEC.md §9.3 11-step transactional compare-and-swap state machine:
    1. Checks `processed_mutations` for idempotency and returns cached result on replay (or detects mismatch);
    2. Reads current object row from `encrypted_objects`;
    3. If `expected_revision == 0` and object does not exist: creates object at revision 1 and allocates next server sequence;
    4. If `expected_revision == 0` and object already exists: rejects as conflict returning HTTP 409 `ConflictResponse` with latest `current_envelope`;
    5. If `expected_revision != current_revision`: rejects as conflict returning HTTP 409 `ConflictResponse`;
    6. If `expected_revision == current_revision`: archives prior revision into `object_history` table, allocates next monotonic server sequence, increments revision by exactly 1 (`current_revision + 1`), and updates `encrypted_objects`;
    7. Persists successful mutation result into `processed_mutations` and commits transaction.
  - `ServerDb::push_mutation(&self, account_id, &request)`: transactional wrapper returning `PushOutcome` (`Success`, `Conflict`, `ObjectNotFound`, `ReplayMismatch`).
  - `ServerDb::get_encrypted_object` and `ServerDb::get_object_history`: state and history inspection methods.
- Enforced zero-knowledge invariants (SEC-001/SEC-002) and security rules:
  - Scans JSON payloads with `contains_forbidden_keys` to strictly reject plaintext notes or credentials with HTTP 400 (`INVALID_ENVELOPE`);
  - Enforces `AuthenticatedAccount` bearer token authentication with cross-account access isolation;
  - Validates UUIDs, envelope versions (`ENVELOPE_VERSION_V1`), object ID consistency, and standard Base64 nonce/ciphertext formatting;
  - Diagnostic logs strictly avoid logging ciphertexts or payload keys (SEC-003).
- Added comprehensive unit tests in `apps/server/src/db/store.rs` and integration tests in `apps/server/tests/server_cas_push_tests.rs`:
  - Verified creation at revision 1 and server sequence 1 for `expected_revision = 0`;
  - Verified duplicate create rejection with HTTP 409 `ConflictResponse`;
  - Verified exact revision requirement and increment by 1 on update (`1 -> 2 -> 3`);
  - Verified rejection of stale updates with HTTP 409 `ConflictResponse`;
  - Verified prior revisions are faithfully preserved in `object_history`;
  - Verified cross-account isolation and rejection of unauthenticated requests and forbidden plaintext keys.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency checks, and 144 workspace tests).

---

## ZK-035 — Mutation idempotency
Status: DONE  
Priority: P0  
Dependencies: ZK-034

Acceptance criteria:

- same mutation ID/same request returns original result;
- no additional revision/server sequence;
- same mutation ID with incompatible payload returns explicit replay mismatch error;
- concurrency test for duplicate simultaneous retries.

Completion notes:
- Added migration `migrations/004_mutation_idempotency.sql` adding `request_hash BYTEA` to `processed_mutations` table.
- Implemented `compute_mutation_request_hash` in `apps/server/src/db/store.rs` computing deterministic 32-byte Blake2s-256 digest of semantic request payload fields (`object_id`, `expected_revision`, `object_kind`, `is_deleted`, and envelope ciphertext/nonce components) preserving zero-knowledge invariants (SEC-001/SEC-002).
- Enhanced CAS push mutation state machine in `apps/server/src/db/store.rs`:
  - When replaying an identical mutation (matching `account_id`, `mutation_id`, and `request_hash`): returns the original cached `PushResponse` without incrementing revision or allocating a new server sequence.
  - When replaying with an incompatible payload (mismatched `object_id`, `expected_revision`, `is_deleted`, or envelope ciphertexts/nonces): returns `PushOutcome::ReplayMismatch`, mapped by `apps/server/src/routes/sync.rs` to HTTP 409 Conflict with error code `MUTATION_REPLAY_MISMATCH`.
  - Persists `request_hash` alongside response body and resulting revision/sequence on both create and update operations.
- Added comprehensive unit tests in `apps/server/src/db/store.rs` and integration tests in `apps/server/tests/server_mutation_idempotency_tests.rs`:
  - Verified exact create and update replay return original `PushResponse` with HTTP 200 OK;
  - Verified revision and sequence counters do not advance on replay, and object history is not duplicated;
  - Verified explicit replay mismatch errors for differing `object_id`, `expected_revision`, payload ciphertext, and `is_deleted` flag (HTTP 409 `MUTATION_REPLAY_MISMATCH`);
  - Concurrency tests: 50 concurrent tokio tasks simultaneously retrying create and 50 concurrent tokio tasks simultaneously retrying update all succeed with HTTP 200 OK and identical responses without race conditions or duplicated allocations.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency check, and all 158 workspace tests).

---

## ZK-036 — Pull changes endpoint
Status: DONE  
Priority: P0  
Dependencies: ZK-033, ZK-034

Acceptance criteria:

- ordered `server_seq`;
- pagination;
- cursor semantics documented;
- tombstones included;
- no missed rows under concurrent writes.

Completion notes:
- Added `PullChangesQuery` model in `crates/zk-protocol/src/sync.rs` and re-exported it in `zk-protocol`.
- Implemented `ServerDb::pull_changes(&self, account_id: Uuid, after: u64, limit: usize) -> Result<PullChangesResponse, DbError>` in `apps/server/src/db/store.rs`:
  - Queries `encrypted_objects` with `account_id = ?1 AND server_seq > ?2 ORDER BY server_seq ASC LIMIT ?3` accelerated by `encrypted_objects_account_seq_idx`;
  - Fetches `limit + 1` rows to accurately evaluate `has_more` and calculates `next_cursor`;
  - Deserializes encrypted envelopes into `ObjectChange` maintaining zero-knowledge invariants (SEC-001/SEC-002);
  - Includes deletion tombstones (`is_deleted: true`).
- Implemented `pull_changes_handler` in `apps/server/src/routes/sync.rs` mounted on both `GET /v1/sync/changes` and `GET /v1/sync/pull` in `apps/server/src/app.rs`:
  - Enforces `AuthenticatedAccount` bearer token authentication with cross-account access isolation;
  - Parses and validates `after` (default 0) and `limit` (default 50, clamped to 1..=500);
  - Returns HTTP 400 Bad Request with `SYNC_CURSOR_INVALID` on malformed query parameters;
  - Emits redacted diagnostic logs without secrets (SEC-003).
- Documented cursor and pagination semantics in `docs/protocol/v1.md` §3.3.4 (monotonic cursor definition, pagination advancement, empty page behavior, tombstone visibility, and client durability invariant before cursor update).
- Added unit tests in `apps/server/src/db/store.rs` and 9 integration tests in `apps/server/tests/server_pull_changes_tests.rs`:
  - Verified empty account behavior (`changes: []`, `next_cursor == 0`, `has_more == false`);
  - Verified changes are returned in strictly ascending `server_seq` order;
  - Verified multi-page pagination flow with `has_more` and `next_cursor` advancing contiguously;
  - Verified tombstone (`is_deleted: true`) presence and ordering;
  - Verified `/v1/sync/changes` and `/v1/sync/pull` endpoint aliases;
  - Verified cross-account isolation and unauthenticated access rejection;
  - Verified query parameter validation and error handling (`SYNC_CURSOR_INVALID`);
  - Concurrency test: 30 concurrent writes and 5 concurrent readers reading concurrently observed all 30 objects across contiguous sequences `1..=30` with zero missed rows.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency check, and all 172 workspace tests).

---

## ZK-037 — Tombstone persistence server-side
Status: DONE  
Priority: P0  
Dependencies: ZK-034

Acceptance criteria:

- delete mutation is revisioned;
- stale edit against tombstone conflicts;
- deleted object remains sync-visible.

Completion notes:
- Verified and enforced delete mutation revisioning in `apps/server/src/db/store.rs`:
  - `POST /v1/sync/push` mutations with `is_deleted = true` require exact matching `expected_revision`;
  - Accepted deletion increments object revision by exactly 1 (`current_revision + 1`), allocates the next monotonic account `server_seq`, archives previous active state into `object_history`, and updates `encrypted_objects` with `is_deleted: true` and the tombstone envelope;
  - Delete mutations are fully idempotent under re-submission.
- Verified and enforced conflict safety on tombstones (SEC-008):
  - Stale edits based on prior revisions are rejected with HTTP 409 Conflict (`REVISION_CONFLICT`) containing current tombstone revision and envelope;
  - Resurrection via duplicate create (`expected_revision = 0`) is rejected with HTTP 409 Conflict, preventing stale clients from silently resurrecting deleted objects;
  - Explicit resurrection (un-delete with `expected_revision == tombstone_revision` and `is_deleted = false`) succeeds, incrementing revision and preserving the tombstone in `object_history`.
- Verified sync visibility:
  - Tombstones remain persisted in `encrypted_objects` with `is_deleted: true` and their allocated `server_seq`;
  - `GET /v1/sync/changes` returns tombstones to syncing peer clients so peers observe and apply deletions.
- Added integration test suite `apps/server/tests/server_tombstone_tests.rs`:
  - Verified delete mutation revisioning, sequence allocation, and prior state archiving;
  - Verified stale edits and duplicate creates conflict against tombstones;
  - Verified tombstones are returned in `GET /v1/sync/changes` for full and incremental pulls;
  - Verified explicit resurrection lifecycle and multi-revision history audit trail.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency check, and all 176 workspace tests).

---

## ZK-038 — Authorization isolation tests
Status: DONE  
Priority: P0  
Dependencies: ZK-032, ZK-036

Acceptance criteria:

- account A cannot fetch/mutate B objects;
- guessed object IDs do not bypass ownership;
- history access isolated.

Completion notes:
- Implemented integration test suite `apps/server/tests/server_authorization_isolation_tests.rs` rigorously verifying zero-knowledge cross-account authorization and data boundaries (SEC-001, SEC-002, SEC-003):
  - Verified Account A cannot mutate or delete Account B objects: attempting update or delete on an object ID owned by Account B returns HTTP 404 `OBJECT_NOT_FOUND` without leaking object existence, current revision, or ciphertext;
  - Verified guessed object IDs do not bypass ownership: probing with arbitrary expected revisions returns 404 NOT FOUND without conflict metadata leakage; creating with `expected_revision = 0` creates an isolated record scoped to `(account_a, object_id)` while Account B's record `(account_b, object_id)` remains completely untouched;
  - Verified history access is strictly isolated: Account A querying history for Account B's object ID returns an empty list with zero visibility into B's historical revisions;
  - Verified sync pull stream isolation: concurrent pulls across multiple accounts return strictly account-scoped objects with independent monotonic sequence counters;
  - Verified vault bootstrap isolation: Account A cannot read Account B's bootstrap metadata (returns 404 NOT FOUND);
  - Verified unauthenticated requests fail closed with HTTP 401 `AUTH_REQUIRED`.
- Satisfied M3 Gate requirements: CAS compare-and-swap, mutation idempotency, monotonic server sequences, cross-account authorization isolation, tombstone behavior, and history preservation are all proven by integration tests.
- All quality gates passed via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency check, and all 183 workspace tests).

---

### M3 Gate

Integration suite must prove:

```text
CAS
idempotency
monotonic sequence
cross-account isolation
tombstone behavior
history preservation
```

---

# M4 — Offline multi-device sync

Goal: connect CLI to server without silent overwrite.

## ZK-040 — Native HTTP sync adapter
Status: DONE  
Priority: P0  
Dependencies: M3

Acceptance criteria:

- protocol models shared from `zk-protocol`;
- authenticated requests abstracted;
- network errors typed;
- no plaintext payload fields.

Completion notes:
- Implemented strongly typed network and sync error representation in `crates/zk-sync/src/error.rs` (`SyncNetworkError`), capturing `Unauthorized`, `Forbidden`, `NotFound`, `Conflict(Box<ConflictResponse>)`, `ReplayMismatch`, `InvalidCursor`, `InvalidPayload`, `ServerError`, `ConnectionFailed`, `Serialization`, and `ForbiddenPlaintext`.
- Implemented `SyncServerAdapter` trait and `NativeHttpSyncAdapter` in `crates/zk-sync/src/adapter.rs`, abstracting authentication token state and headers, URL normalization, request dispatch, and response status mapping into typed errors.
- Implemented `validate_no_plaintext_secrets` enforcing SEC-001/SEC-002 client-side before any payload packet is sent across the network.
- Provided `MockSyncAdapter` for deterministic local sync testing.
- Added comprehensive integration tests in `apps/server/tests/server_sync_adapter_tests.rs` verifying live HTTP interaction with Axum server: vault bootstrap round trip, CAS push, revision conflicts, mutation replay mismatch, paginated pull with tombstones, and token lifecycle.
- Validated via `./scripts/ci.sh` (cargo fmt, clippy with `-D warnings`, cargo test --workspace).

---

## ZK-041 — Pending mutation queue
Status: DONE  
Priority: P0  
Dependencies: ZK-021, ZK-040

Acceptance criteria:

- local edits generate mutation IDs;
- mutations survive process restart;
- base revision recorded;
- mutation removed only after durable accepted result.

Completion notes:
- Implemented `PendingMutationQueue` in `crates/zk-sync/src/queue.rs` wrapping local storage implementing `MutationStore`, `ObjectStore`, and `BaseVersionStore`.
- Implemented automatic UUID v4 mutation ID generation and base revision recording on local creates, edits, and deletes (`enqueue_local_note_upsert`, `enqueue_local_note_delete`, `enqueue_upsert`, `enqueue_delete`).
- Stored base versions in `BaseVersionStore` at edit time for downstream three-way conflict merge.
- Enforced durable write sequencing in `acknowledge_accepted`: the mutation is deleted from `pending_mutations` ONLY AFTER `put_object` durably persists the accepted object state. If the durable storage write fails, the mutation remains safely queued.
- Added `reset_in_flight` to recover interrupted in-flight mutations upon process restart, preserving the original mutation ID for SEC-007 idempotent retry.
- Added comprehensive unit tests and integration tests in `crates/zk-sync/tests/pending_mutation_queue_tests.rs` verifying process restart persistence with disk-backed `SqliteStorage`, fault injection failure recovery, FIFO ordering, and tombstone recording.
- Validated via `./scripts/ci.sh` (cargo fmt, clippy with `-D warnings`, cargo test --workspace).

---

## ZK-042 — Durable sync cursor
Status: DONE  
Priority: P0  
Dependencies: ZK-021, ZK-036

Acceptance criteria:

- cursor advances only after local durable application;
- crash simulation does not skip remote changes.

Completion notes:
- Implemented `DurableSyncCursor` in `crates/zk-sync/src/cursor.rs` wrapping persistent storage implementing `SyncStateStore`.
- Implemented strict monotonic cursor advancement and regression rejection (`CursorError::Regression`).
- Implemented `apply_change` and `apply_changes_sequential` enforcing that the persistent `sync_cursor` advances ONLY AFTER the remote encrypted object is durably written to `ObjectStore`. If a local write fails, the cursor remains at the last committed sequence.
- Added blanket implementations for `Arc<T>` across all storage traits in `crates/zk-storage/src/traits.rs` to allow safe multi-component sharing.
- Added comprehensive unit tests and integration tests in `crates/zk-sync/tests/durable_sync_cursor_tests.rs` verifying:
  - Cursor advances only after durable write;
  - Mid-stream failure stops cursor advancement without corrupting earlier writes;
  - Scenario E crash simulation with real SQLite disk storage: process crash during pull leaves cursor at last durable sequence (97), restart re-fetches uncommitted changes (98..100) without skipping remote changes;
  - Monotonicity checks and explicit resync reset.
- Validated via `./scripts/ci.sh` (cargo fmt, clippy with `-D warnings`, cargo test --workspace).

---

## ZK-043 — Pull remote changes
Status: DONE  
Priority: P0  
Dependencies: ZK-040, ZK-042

Acceptance criteria:

- paginated pull;
- encrypted changes stored first;
- unlocked client can decrypt/apply;
- locked sync behavior explicitly defined.

Recommended V1 locked behavior:

Store remote ciphertext durably and defer plaintext reconciliation until unlock.

Completion notes:
- Implemented `pull_remote_changes`, `pull_with_session`, and `decrypt_stored_objects_on_unlock` in `crates/zk-sync/src/pull.rs`.
- Implemented paginated pull requests looping through `SyncServerAdapter::pull_changes` until `has_more == false`.
- Enforced storing encrypted changes first into `ObjectStore` and updating the durable cursor via `DurableSyncCursor` before any decryption is attempted.
- Defined locked sync behavior (`LockedSyncBehavior::StoreCiphertextDeferDecryption`): pulls persist remote ciphertext and advance cursor while locked, deferring plaintext decryption and search index updates until user unlock (`decrypt_stored_objects_on_unlock`).
- Unlocked clients decrypt remote notes into memory, handle deletion tombstones, and update the session's in-memory search index.
- Enforced SEC-010 fail-closed semantics: corrupted or tampered envelopes fail closed without partial returns.
- Added comprehensive unit tests and integration tests in `crates/zk-sync/tests/pull_remote_changes_tests.rs` covering multi-page pulls, locked sync deferral, tombstone handling, and fail-closed crypto verification.
- Validated via `./scripts/ci.sh` (cargo fmt, clippy with `-D warnings`, cargo test --workspace).

---

## ZK-044 — Push pending changes
Status: DONE  
Priority: P0  
Dependencies: ZK-041, ZK-043

Acceptance criteria:

- expected revision supplied;
- accepted writes clear queue;
- lost-response retry uses same mutation ID;
- conflict leaves local mutation recoverable.

Completion notes:
- Implemented `push_pending_changes`, `PushOptions`, `PushReport`, and `PushError` in `crates/zk-sync/src/push.rs`.
- Enforced CAS revision checks: `expected_revision` is transmitted with each mutation and checked by server/adapter.
- Implemented queue cleanup and durable object store updates upon server acceptance.
- Implemented idempotent retry: identical `mutation_id` is retransmitted during retries and replayed cleanly without duplicating revisions.
- Conflicting mutations (revision mismatch) are preserved in the pending queue with base revision and envelopes intact for three-way merge resolution.
- Added comprehensive unit tests in `push.rs` and integration tests in `crates/zk-sync/tests/push_pending_changes_tests.rs`.
- Verified via `./scripts/ci.sh`.

---

## ZK-045 — Pull-before-push orchestration
Status: DONE  
Priority: P0  
Dependencies: ZK-043, ZK-044

Acceptance criteria:

- deterministic sync cycle;
- retryable network failure;
- final cursor consistent;
- no mutation silently dropped.

Completion notes:
- Implemented `run_sync_cycle`, `run_sync_cycle_with_session`, `SyncEngine`, `SyncCycleOptions`, `SyncCycleReport`, and `SyncCycleError` in `crates/zk-sync/src/orchestrator.rs`.
- Enforced MASTER_SPEC.md § 9.6 pull-before-push execution order:
  1. Reset stuck in-flight mutations from interrupted runs;
  2. Initial pull fetches remote changes after cursor and stores encrypted objects durably;
  3. Push phase transmits pending mutations with CAS revision verification;
  4. Follow-up pull fetches server-allocated sequences and updates final cursor;
  5. Decrypted search index updated when unlocked session is provided.
- Added `is_retryable()` to `SyncNetworkError` and `SyncCycleError` to cleanly distinguish retryable transport/server errors from fatal errors without dropping mutations or corrupting cursors.
- Added unit tests in `orchestrator.rs` and integration tests in `crates/zk-sync/tests/orchestrator_tests.rs`.
- Verified via `./scripts/ci.sh`.

---

## ZK-046 — Two-client integration harness
Status: DONE  
Priority: P0  
Dependencies: ZK-045

Acceptance criteria:

Automated scenario spins up:

```text
server
client A local DB
client B local DB
```

and proves clean multi-device sync.

Completion notes:
- Implemented comprehensive two-client integration test harness in `apps/server/tests/two_client_sync_tests.rs`.
- Spun up real HTTP server over TCP (`127.0.0.1:0`), client A with local SQLite storage, and client B with local SQLite storage.
- Executed the full M4 Gate scenario:
  1. Device A creates note offline;
  2. Device A syncs to server;
  3. Device B syncs from server, stores encrypted object in its local DB, decrypts note and updates search index;
  4. Device B edits note offline;
  5. Device B syncs edit to server;
  6. Device A syncs from server;
  7. Device A sees decrypted update and updated search index.
- Performed rigorous zero-knowledge database audit directly on server SQLite database: confirmed 0 forbidden plaintext strings appear anywhere in `encrypted_objects`, `object_history`, `processed_mutations`, `vaults`, or `accounts`.
- Added 10 sequential alternating multi-device edits test.
- Added tombstone deletion propagation test between devices.
- Added killed sync resumption test from durable cursor without skipped revisions.
- Verified via `./scripts/ci.sh`.

---

### M4 Gate: PASSED

Required scenario:

```text
A creates offline
A syncs
B syncs
B edits offline
B syncs
A syncs
A sees update
```

No plaintext is present in server DB. All M4 acceptance criteria and gates verified.

---

# M5 — Conflict resolution and guarded LWW

Goal: make multi-device offline conflicts safe and usable.

## ZK-050 — Persist encrypted BASE versions
Status: DONE  
Priority: P0  
Dependencies: ZK-041

Acceptance criteria:

- pending edit stores reference/base ciphertext;
- restart preserves merge capability;
- plaintext BASE is not persisted.

Completion notes:
- Enforced atomic persistence of encrypted base versions in `PendingMutationQueue::enqueue_upsert`, `enqueue_delete`, and `enqueue_local_note_upsert` in `crates/zk-sync/src/queue.rs`.
- Added public helper methods on `PendingMutationQueue`: `get_base_version`, `get_base_version_for_mutation`, and `store_base_version`.
- Propagated durable base version persistence errors fail-closed so merge capability is never lost silently.
- Added comprehensive integration tests in `crates/zk-sync/tests/base_version_persistence_tests.rs`:
  - Verified pending edits store reference `expected_revision` and base encrypted envelope in `BaseVersionStore`;
  - Verified process restart across SQLite connections reloads both pending mutation and base envelope, preserving full decryptability of BASE, LOCAL, and conflicting REMOTE notes for 3-way merge;
  - Verified zero-knowledge audit: confirmed zero plaintext note titles, bodies, tags, or keys are persisted in the database file (SEC-009).
- Verified via `./scripts/ci.sh`.

---

## ZK-051 — Structured three-way merge engine
Status: DONE  
Priority: P0  
Dependencies: ZK-020, ZK-050

Acceptance criteria:

- unchanged/local-only/remote-only field cases;
- identical concurrent changes;
- divergent scalar changes reported as conflict;
- deterministic tag merge.

Completion notes:
- Implemented structured three-way merge engine in `crates/zk-sync/src/merge.rs` conforming to MASTER_SPEC.md § 10.2:
  - `merge_scalar_field` handles unchanged, local-only, remote-only, identical concurrent, and divergent conflict cases for scalar fields;
  - `merge_tags` implements deterministic set-based three-way merge (canonicalizing, deduplicating, and sorting lexicographically);
  - `merge_attachments` implements stable ID three-way merge;
  - `three_way_merge_note` coordinates complete note merge producing `NoteMergeOutcome`, containing merged candidate and explicit `FieldConflict`s (`Title`, `Body`, `Attachments`).
- Re-exported merge types in `crates/zk-sync/src/lib.rs`.
- Added unit tests in `merge.rs` and comprehensive integration test suite in `crates/zk-sync/tests/structured_three_way_merge_tests.rs`.
- Verified via `./scripts/ci.sh`.

---

## ZK-052 — Markdown body diff3
Status: DONE  
Priority: P0  
Dependencies: ZK-051

Acceptance criteria:

- non-overlapping edits auto-merge;
- overlapping edits become explicit conflict;
- no side silently discarded;
- deterministic tests.

Completion notes:
- Implemented line-based Longest Common Subsequence (LCS) three-way merge (`diff3_merge`) in `crates/zk-sync/src/diff3.rs`:
  - Trims common line prefix and suffix before LCS dynamic programming for high performance;
  - Includes allocation guard preventing runaway dynamic programming allocations on pathological inputs;
  - Identifies common anchors across BASE, LOCAL, and REMOTE;
  - Cleanly auto-merges non-overlapping edits, additions at boundaries, and deletions;
  - Cleanly resolves identical concurrent modifications without conflict;
  - Detects overlapping divergent line edits and converts them into explicit `BodyConflict` records;
  - Never discards either side silently: formats conflicting chunks with standard diff3 conflict markers (`<<<<<<< LOCAL`, `||||||| BASE`, `=======`, `>>>>>>> REMOTE`);
  - Normalizes `\r\n` and `\r` to `\n` to guarantee deterministic line behavior across platforms.
- Integrated `diff3_merge` directly into `three_way_merge_note` in `crates/zk-sync/src/merge.rs`:
  - Added `FieldMergeStatus::Merged(T)` variant for fields resolved cleanly via automatic 3-way line merge;
  - Injected `body_diff: Option<Diff3Result>` into `NoteMergeOutcome` for rich diagnostics and structured conflict introspection;
  - Merged candidate body receives clean merged text on non-overlapping edits, or formatted conflict markers preserving BASE, LOCAL, and REMOTE on overlapping edits.
- Added comprehensive unit and integration test suites:
  - Unit tests in `crates/zk-sync/src/diff3.rs` and `crates/zk-sync/src/merge.rs`;
  - Integration tests in `crates/zk-sync/tests/markdown_body_diff3_tests.rs` covering non-overlapping section auto-merging, boundary additions, edit-vs-delete conflicts, overlapping edits, mixed clean/conflict documents, CRLF normalization, 100-run determinism, and full `PlaintextNote` 3-way merge integration.
- Passed all quality gates via `./scripts/ci.sh` (formatting, clippy `-D warnings`, dependency audit, workspace tests).

---

## ZK-053 — Conflict record model
Status: DONE  
Priority: P0  
Dependencies: ZK-051, ZK-052

Persist encrypted/local metadata for:

```text
BASE
LOCAL
REMOTE
merge candidate
```

Acceptance criteria:

- survives restart;
- contains enough information to retry after resolution;
- no plaintext durable conflict body.

Completion notes:
- Created SQLite migration `migrations/005_local_conflict_records.sql` creating the `conflict_records` table, indexed by `object_id` and `resolved`, holding strictly encrypted envelopes (`base_envelope`, `local_envelope`, `remote_envelope`, `candidate_envelope`) and metadata (`conflict_id`, `object_id`, `object_kind`, `base_revision`, `remote_revision`, `created_at`, `resolved_at`). Zero plaintext columns for title, body, or tags.
- Defined `ConflictRecord` domain model in `crates/zk-storage/src/models.rs`.
- Defined `ConflictStore` trait in `crates/zk-storage/src/traits.rs` (`put_conflict`, `get_conflict`, `get_active_conflict_for_object`, `list_conflicts`, `resolve_conflict`, `delete_conflict`), composed it into the `LocalStorage` trait, and implemented `Arc<T>` delegation.
- Implemented `ConflictStore` in both `MemoryStorage` (`crates/zk-storage/src/memory.rs`) and `SqliteStorage` (`crates/zk-storage/src/sqlite.rs`).
- Created conflict engine in `crates/zk-sync/src/conflict.rs` (`generate_merge_candidate`, `record_conflict`, `resolve_conflict`) supporting `KeepLocal`, `KeepRemote`, `Merge`, and `DuplicateAsSeparate` strategies, packaging retry mutations with correct target expected revisions.
- Integrated automatic conflict record creation on push CAS conflict in `crates/zk-sync/src/push.rs` and `crates/zk-sync/src/orchestrator.rs`.
- Added unit and integration tests in `crates/zk-storage` and `crates/zk-sync/tests/conflict_record_persistence_tests.rs`:
  - Verified conflict records survive process restarts and SQLite database close/reopen;
  - Verified all resolution paths retain sufficient metadata (`remote_revision`, envelopes) for immediate CAS retry mutations;
  - Performed raw binary disk inspection proving zero plaintext leakage into SQLite disk files (SEC-009).
- Passed all quality gates via `./scripts/ci.sh`.

---

## ZK-054 — CLI conflict commands
Status: DONE  
Priority: P1  
Dependencies: ZK-053

Commands:

```text
zk-note conflicts
zk-note resolve <id>
```

Acceptance criteria:

- user can choose local;
- user can choose remote;
- user can save manual merge;
- user can preserve both as separate notes where safe.

Completion notes:
- Implemented `zk-note conflicts` subcommand in `apps/cli/src/commands.rs` and `apps/cli/src/main.rs`:
  - Lists active/unresolved conflict records by default, with `--all` flag to include resolved records.
  - Supports `--json` for machine-readable output.
  - Safe when vault is locked (displays sync metadata with `[locked]` title, preserving SEC-009 zero-knowledge on disk).
  - Decrypts and shows note titles in list when vault is unlocked.
- Implemented `zk-note resolve <conflict_id>` subcommand in `apps/cli/src/commands.rs` and `apps/cli/src/main.rs`:
  - Supports resolving by full UUID or unique >=4-char prefix.
  - Four resolution strategies supported:
    - User can choose local: `--local` (`-l`) or interactive option `1` (queues retry mutation based on remote revision, updates local object).
    - User can choose remote: `--remote` (`-r`) or interactive option `2` (updates local object with remote envelope, clears stale mutation).
    - User can save manual merge: `--merge` (`-m`) or interactive option `3`, supporting `$EDITOR` with diff3 conflict markers or programmatic overrides (`--title`, `--body`, `--tag`).
    - User can preserve both as separate notes where safe: `--duplicate` (`-d`) or interactive option `4`, creating a new note with local content while updating the original note to the remote version.
  - Validates mutex constraints, fails closed if conflict not found or already resolved, and requires unlocked vault.
- Added comprehensive unit and integration test suite covering:
  - `test_cli_conflicts_listing_and_filtering` (empty, active-only, all, json, locked mask).
  - `test_cli_resolve_keep_local` (mutation retry, storage update, already-resolved guard).
  - `test_cli_resolve_keep_remote` (remote update, show output).
  - `test_cli_resolve_manual_merge` (overrides, decrypted object verification).
  - `test_cli_resolve_duplicate_as_separate` (both notes preserved and showable).
  - `test_cli_resolve_prefix_matching_and_validations` (prefix matching, mutually exclusive flag validation, not-found validation).
- Passed all quality gates via `./scripts/ci.sh`.

---

## ZK-055 — Guarded LWW policy option
Status: DONE  
Priority: P2  
Dependencies: ZK-053, ZK-028

Acceptance criteria:

- optional policy documented;
- selected visible head may use LWW;
- losing revision always recoverable;
- CAS remains enforced.

Do not enable by default in V1 without explicit product decision.

Completion notes:
- Authored ADR 0005 (`docs/adr/0005-guarded-lww-policy.md`) documenting Guarded Last-Write-Wins (LWW) policy context, invariants, non-default opt-in model, and zero-knowledge preservation.
- Implemented `ConflictPolicy` enum (`Manual` [default], `GuardedLww`), `LwwWinner`, `GuardedLwwOutcome`, and `evaluate_guarded_lww` in `crates/zk-sync/src/conflict.rs`.
- Enforced `ConflictPolicy::Manual` as the default in `PushOptions` and `ConflictPolicy::default()`, guaranteeing Guarded LWW is not enabled by default in V1 without an explicit opt-in product decision.
- Implemented visible head update and lossless recovery:
  - When Local wins: local version becomes visible head in `ObjectStore`, losing remote version is archived in `BaseVersionStore` at `remote_revision`, and a retry mutation is enqueued with `expected_revision = remote_revision` to satisfy server CAS.
  - When Remote wins: remote version becomes visible head in `ObjectStore`, losing local version is archived in `BaseVersionStore`, and stale local mutation is removed from the queue.
  - Resolved `ConflictRecord` is persisted in `ConflictStore` for auditability in both cases.
- Integrated `ConflictPolicy` and `vault_key` into `PushOptions`, `push_pending_changes`, and orchestrator sync cycles (`run_sync_cycle`, `run_sync_cycle_with_session`).
- Added comprehensive integration test suite in `crates/zk-sync/tests/guarded_lww_tests.rs`:
  - `test_default_conflict_policy_is_manual_v1_safe`: verifies default policy is `Manual`;
  - `test_guarded_lww_local_wins_updates_visible_head_preserves_remote_enforces_cas`: verifies visible head selection, losing revision recovery, and subsequent CAS retry acceptance;
  - `test_guarded_lww_remote_wins_updates_visible_head_preserves_local_clears_stale_mutation`: verifies remote winner visible head, local backup in `BaseVersionStore`, and stale mutation dequeuing;
  - `test_guarded_lww_with_sqlite_backend_restart_and_audit`: verifies persistence across SQLite reopen and raw binary disk inspection proving zero plaintext leakage (SEC-009);
  - `test_guarded_lww_opaque_mode_without_vault_key`: verifies locked/opaque clients resolve deterministically without panic.
- Passed all quality gates via `./scripts/ci.sh`.

---

## ZK-056 — Delete-vs-edit conflict
Status: DONE  
Priority: P0  
Dependencies: ZK-053, ZK-037

Acceptance criteria:

- stale edit cannot resurrect deleted note;
- conflict UX distinguishes deletion;
- user can explicitly restore as new/current revision.

Completion notes:
- Enforced tombstone resurrection prevention (SEC-008, MASTER_SPEC.md § 11):
  - Updated `zk-protocol` and `zk-server` to return `is_deleted: bool` in `ConflictResponse` whenever a CAS revision conflict occurs on push.
  - Guarded LWW (`evaluate_guarded_lww`) strictly refuses automatic resolution when either the local mutation or the remote state is a tombstone (`is_del_conflict`), preserving the conflict record for explicit user action.
- Distinguishable Delete-vs-Edit conflict UX:
  - Added migration `migrations/006_conflict_records_deletion_flags.sql` adding `remote_is_deleted` and `local_is_deleted` flags to `conflict_records`.
  - Added deletion flags to `ConflictRecord` in `crates/zk-storage/src/models.rs` with helper methods (`is_deletion_conflict`, `is_delete_vs_edit`, `conflict_type_str`).
  - Updated `zk-storage` SQLite backend to persist and query deletion flags across restarts.
  - Enhanced CLI `zk-note conflicts list` (`apps/cli/src/commands.rs`) to display `Unresolved (Delete-vs-Edit)` / `Unresolved (Edit-vs-Delete)` and decrypt note titles from the active version when remote is deleted.
  - Enhanced CLI `zk-note conflicts resolve` with dedicated interactive prompt for delete-vs-edit conflicts, clearly explaining tombstone state and offering tailored choices:
    - [1] Restore at current revision (resurrect note on server with local changes);
    - [2] Accept remote deletion (discard local changes and delete note locally);
    - [3] Restore as new note (preserve remote deletion, create new note with local content).
  - Added `--restore` flag to CLI `zk-note conflicts resolve --note-id <ID> --restore` and disallowed `--merge` on deletion conflicts with descriptive fail-closed errors.
- Explicit restore and resurrection semantics:
  - Added `ConflictResolutionStrategy::RestoreResurrect` in `crates/zk-sync/src/conflict.rs`.
  - In `resolve_conflict`:
    - `RestoreResurrect` / `KeepLocal`: enqueues an `Upsert` mutation targeting the current remote revision (`expected_revision = remote_revision`), ensuring CAS compliance and explicit resurrection on the server;
    - `KeepRemote`: applies remote tombstone locally (`is_deleted = true`);
    - `DuplicateAsSeparate`: preserves remote tombstone on original note, creating a brand new note at `expected_revision = 0`.
- Verified with comprehensive test suites:
  - Unit tests in `apps/cli/src/main.rs` (`test_cli_delete_vs_edit_conflict_lifecycle`, `test_cli_delete_vs_edit_keep_remote_accepts_deletion`);
  - Unit test in `crates/zk-storage/src/sqlite.rs` (`test_sqlite_delete_vs_edit_conflict_flags_survive_restart`);
  - Integration tests in `crates/zk-sync/tests/delete_vs_edit_conflict_tests.rs` (7 tests covering stale edit rejection, Guarded LWW tombstone safety, explicit restore, keep remote, duplicate separate, merge fail-closed, and SQLite persistence & zero-knowledge plaintext audit);
  - Server tests in `apps/server/tests/server_tombstone_tests.rs`.
- All quality gates passed via `./scripts/ci.sh`.

---

## ZK-057 — Conflict integration matrix
Status: DONE  
Priority: P0  
Dependencies: ZK-054, ZK-056

Automate:

```text
body vs body
title vs body
tag vs body
same edit vs same edit
delete vs edit
lost response
repeated conflict retry
```

Completion notes:
- Automated the entire conflict integration matrix and M5 Gate in `apps/server/tests/conflict_integration_matrix_tests.rs` running multi-device clients with isolated SQLite storage and active vault sessions against a real HTTP server:
  1. `body vs body` (`test_matrix_body_vs_body`):
     - Non-overlapping body edits: diff3 auto-merges cleanly without conflict markers; candidate resolved and pushed with revision 3;
     - Overlapping divergent body edits: diff3 detects conflict and inserts `<<<<<<< LOCAL ... >>>>>>> REMOTE` markers into candidate envelope; both local and remote contents remain recoverable in conflict records; manual resolution accepted at revision 5.
  2. `title vs body` (`test_matrix_title_vs_body`):
     - Client A edits title, Client B edits body; structured three-way merge automatically resolves title from remote and body from local (`is_clean() == true`); candidate pushed and accepted at revision 3; both clients converge with both updates.
  3. `tag vs body` (`test_matrix_tag_vs_body`):
     - Client A modifies tags, Client B edits body; structured three-way merge combines tag set changes with body edit (`is_clean() == true`); candidate pushed and accepted at revision 3.
  4. `same edit vs same edit` (`test_matrix_same_edit_vs_same_edit`):
     - Concurrent identical changes across title, body, and tags detected by three-way merge as identical (`is_clean() == true`), converging without divergence.
  5. `delete vs edit` (`test_matrix_delete_vs_edit`):
     - Client A deletes note, Client B edits offline; server strictly rejects push with 409 Conflict (`is_deleted = true`), preventing accidental resurrection (SEC-008);
     - Tested all three resolution strategies:
       - Accept deletion (`KeepRemote`): applies tombstone locally;
       - Explicit resurrection (`RestoreResurrect`): enqueues retry upsert at `expected_revision = remote_revision`, accepted by server at revision 3;
       - Duplicate as separate (`DuplicateAsSeparate`): preserves original tombstone at revision 2 and creates duplicate note at revision 1.
  6. `lost response` (`test_matrix_lost_response`):
     - Dropped HTTP response simulation: client resends exact same `mutation_id` (SEC-007); server idempotency handler detects existing mutation, returning original revision 1 and server sequence 1 without duplicate revision or conflict.
  7. `repeated conflict retry` (`test_matrix_repeated_conflict_retry`):
     - Three clients: Client B conflicts against Client A's revision 2 and prepares retry mutation; Client C preempts with revision 3; Client B retries against revision 2 and receives another 409 conflict; Client B's active conflict record updates to revision 3, preserving the local mutation; Client B re-resolves against revision 3 and successfully pushes revision 4.
- Integrated automated M5 Gate test (`test_m5_gate_offline_concurrent_edits_full_lifecycle`):
  - Two clients edit the same revision offline;
  - Verified server does not overwrite silently (CAS mismatch HTTP 409);
  - Verified both contents remain recoverable locally and in conflict records;
  - Verified client resolves and server accepts new revision;
  - Zero-Knowledge security audit: verified raw SQLite database bytes on server disk contains zero note plaintext titles, bodies, tags, or keys (SEC-001, SEC-002, SEC-003, SEC-009).
- Enhanced `crates/zk-sync/src/push.rs`:
  - Wired `record_conflict` directly into `push_pending_changes`, automatically evaluating and storing the 3-way merge candidate envelope in `ConflictRecord` during push conflict handling whenever the vault key is available in `PushOptions`.
- Quality gates: all tests passed via `./scripts/ci.sh`.

---

### M5 Gate

Status: PASSED  
Automated verification in `apps/server/tests/conflict_integration_matrix_tests.rs::test_m5_gate_offline_concurrent_edits_full_lifecycle`.

Two clients edit the same revision offline.

After synchronization:

- server does not overwrite silently;
- both contents remain recoverable;
- client resolves and produces a new accepted revision.

---

# M6 — Web/WASM client

Goal: reuse the proven core in the browser.

## ZK-060 — WASM build for shared core
Status: DONE  
Priority: P0  
Dependencies: M5

Acceptance criteria:

- crypto/core compiles for browser target;
- narrow typed JS boundary;
- no raw Vault Key exposure to React APIs where avoidable.

Completion notes:
- Configured browser target `wasm32-unknown-unknown` across `zk-protocol`, `zk-crypto`, `zk-core`, and created a dedicated `crates/zk-wasm` crate compiled as `cdylib` and `rlib`.
- Configured browser-compatible CSPRNG via `getrandom = { version = "0.2", features = ["js"] }` for `wasm32` in `zk-crypto` and `zk-wasm`, and enabled the `js` feature for `uuid`.
- Implemented `WasmVaultSession` encapsulating `VaultSession` and `InMemorySearchIndex` strictly within WASM linear memory. The raw `VaultKey` bytes are never returned to JavaScript/React code; JS only holds an opaque `WasmVaultSession` handle, satisfying SEC-002 and Criterion 3.
- Implemented narrow, typed JS boundary exposing:
  - Vault lifecycle: `init_vault`, `unlock_vault`, `unlock_with_recovery_key`, `WasmVaultInitResult`.
  - Vault operations: `encrypt_note`, `decrypt_note`, `index_note`, `remove_from_index`, `search`, `rewrap_passphrase`, `is_unlocked`, `lock`.
  - Typed results: `WasmPlaintextNote`, `WasmSearchResult`, `WasmRewrapResult`.
  - Standalone envelope and KDF helpers for test suites and compatibility testing.
- Generated browser package (`pkg/`) and TypeScript type definitions (`zk_wasm.d.ts`) using `wasm-pack`.
- Added WASM target compilation check (`cargo check --target wasm32-unknown-unknown -p zk-protocol -p zk-crypto -p zk-core -p zk-wasm`) to `./scripts/ci.sh`.
- Added unit tests in `crates/zk-wasm/src/lib.rs` verifying full lifecycle, note encryption/decryption, in-memory search, passphrase rewrapping, and dual-target error handling. All workspace checks in `./scripts/ci.sh` pass cleanly.

---

## ZK-061 — Native/WASM crypto compatibility suite
Status: DONE  
Priority: P0  
Dependencies: ZK-060

Acceptance criteria:

- native encrypt → WASM decrypt;
- WASM encrypt → native decrypt;
- vault wrapper compatibility;
- failure vectors match.

Completion notes:
- Implemented comprehensive bi-directional cross-runtime test coverage between native Rust and browser WebAssembly.
- Native Encrypt → WASM Decrypt:
  - Verified WASM decryption of native-encrypted short notes, large notes (>64KB Markdown), multibyte UTF-8 text (accents, emojis, Japanese characters), raw binary attachments, and the static committed Envelope v1 test vector.
  - Decryption in WASM validates 100% byte-for-byte fidelity and tag canonicalization.
- WASM Encrypt → Native Decrypt:
  - Notes encrypted in WASM decrypt cleanly in native `zk-core` / `zk-crypto`.
  - Verified newline normalization (CRLF -> Unix LF), tag canonicalization (lowercase, deduplicated, sorted), and raw binary payload encryption/decryption round-trips.
- Vault Wrapper Compatibility:
  - Verified Argon2id KEK derivation parity against RFC 9106 deterministic test vector (`007f6b258779db1c07dda5ff432b9025b66d7ec395ed9acba7939210b3ed97b8`) and random salts.
  - Verified bi-directional key wrapping and unwrapping under KEK (`wrap_vault_key` / `unwrap_vault_key`).
  - Verified recovery phrase formatting, checksum validation, and recovery unlocking in both runtimes.
  - Verified passphrase rewrapping across runtimes (native init -> WASM rewrap -> native unlock; WASM init -> native rewrap -> WASM unlock), confirming old passphrases fail closed.
- Failure Vectors Match:
  - Verified identical fail-closed behavior across native and WASM runtimes for: wrong passphrase, wrong recovery key, corrupted recovery phrase checksum, single-bit ciphertext tampering, tampered AAD (`object_id`, `object_kind`, unsupported `envelope_version: 2`), corrupted nonce, truncated nonce, tampered Poly1305 MAC tag, invalid base64, and malformed JSON.
- Test suites & automation:
  - `crates/zk-wasm/tests/wasm_crypto_compat.rs`: 7 tests runnable both natively and inside the Node.js WebAssembly VM via `wasm-pack test --node`.
  - `crates/zk-wasm/src/bin/native_compat_harness.rs`: Native cryptographic harness binary for cross-process JSON-RPC communication.
  - `tests/wasm_crypto_compat.test.mjs`: 27 live cross-runtime integration tests using `node:test` verifying live native-WASM interoperability.
  - Integrated into `./scripts/ci.sh` (Steps 6 & 7). All 7 quality gates pass cleanly.

---

## ZK-062 — Web Worker boundary
Status: DONE  
Priority: P0  
Dependencies: ZK-060

Acceptance criteria:

- crypto/decrypt/search/sync heavy operations run in worker where practical;
- React does not own persistent key state;
- message API documented.

Completion notes:
- Implemented Web Worker cryptographic boundary in `apps/web/src/worker/`:
  - `protocol.ts`: Strongly typed RPC message protocol with discriminated unions (`WorkerRequest`, `WorkerResponse`, `WorkerBroadcastEvent`, `WorkerErrorCode`).
  - `vault-handler.ts`: Encapsulates `zk-wasm` execution and holds the active `WasmVaultSession` exclusively within worker memory. Heavy operations (Argon2id KDF derivation, note envelope encryption, single and batch note decryption, in-memory search indexing, full-text search querying, passphrase rewrapping, and vault locking) are executed entirely off the main thread.
  - `worker.ts`: Dual-runtime worker entrypoint supporting both browser Web Workers (`self.onmessage` / `self.postMessage`) and Node.js `worker_threads` for automated CI testing.
  - `client.ts`: Typed `VaultWorkerClient` providing a Promise-based API with request correlation ID matching, timeout handling, and `onLock` broadcast subscription.
- React and UI layer isolation:
  - React components and main thread state never possess raw `VaultKey`, KEKs, or the `WasmVaultSession` handle (SEC-001, SEC-002, Criterion 2).
  - React state only receives safe DTOs (`PlaintextNoteDto`, `SearchResultDto`, `VaultStatusDto`).
  - Locking zeroizes WASM session memory, flushes search index terms, and broadcasts `VAULT_LOCKED` to clear UI note states.
- Documented message API in `docs/protocol/worker-api.md`, specifying security invariants, message envelopes, error codes, and the complete 12-operation catalog.
- Added comprehensive unit and end-to-end multi-threaded test suites in `apps/web/test/`:
  - `worker-protocol.test.ts`: Serialization, error codes, and broadcast validation.
  - `worker-client.test.ts`: Multi-threaded worker tests verifying initialization, note encryption/decryption/batch, search indexing/querying, rewrapping, fail-closed locking, recovery unlocks, correlation ID concurrency, and client key isolation.
- Integrated Web target into `./scripts/ci.sh` (Step 8: `npm run typecheck && npm test`). All 8 CI quality gates pass cleanly.

---

## ZK-063 — IndexedDB encrypted adapter
Status: DONE  
Priority: P0  
Dependencies: ZK-021, ZK-060

Acceptance criteria:

- same storage semantics as native adapter;
- note ciphertext persists;
- pending queue/cursor persists;
- browser storage inspection reveals no plaintext note content.

Completion notes:
- Implemented `IndexedDbStorage` in `apps/web/src/storage/indexeddb.ts` and models in `apps/web/src/storage/models.ts` with exact semantic parity to the native SQLite adapter:
  - `ObjectStore`: `putObject`, `getObject`, `listObjects` (active only, filtered by protocol kind, include deleted tombstones), `markDeleted` (recording tombstone envelope and revision), and `purgeObject`.
  - `MutationStore`: Strict FIFO queue ordering (`listPendingMutations` and `listMutationsForObject` sorted by `created_at` ascending), `updateMutationStatus` (`Pending`, `InFlight`, `Failed`), retry count tracking, `pendingMutationCount`, and `removeMutation`.
  - `BaseVersionStore`: Base envelope retention for three-way conflict merging (`putBaseVersion`, `getBaseVersion`, `listBaseVersions` ascending), `pruneBaseVersions`, and `clearBaseVersions`.
  - `SyncStateStore`: Monotonic `sync_cursor` tracking and device metadata persistence.
  - `ConflictStore`: `putConflict`, `getConflict`, `getActiveConflictForObject`, `listConflicts` (filtered by resolved state), `resolveConflict` (with candidate envelope), and `deleteConflict`.
- Note ciphertext persistence:
  - Tested persistence across database closing and reopening (simulating browser tab close/reopen), confirming all stored objects and base versions retain full `EncryptedEnvelope` payloads.
- Pending queue and cursor persistence:
  - Verified queued mutations and sync cursors survive restarts without data loss or reordering.
- Zero-Knowledge Security Audit (SEC-009):
  - Implemented automated recursive audit verifying that raw database inspection across all 5 stores (`objects`, `mutations`, `base_versions`, `sync_state`, `conflicts`) reveals zero plaintext note titles, bodies, tags, or passphrases. Envelopes contain only base64 ciphertexts and nonces.
- Added comprehensive unit and integration test suite in `apps/web/test/indexeddb.test.ts` (7 tests, all passing). All 8 CI quality gates in `./scripts/ci.sh` pass cleanly.

---

## ZK-064 — Unlock screen
Status: DONE  
Priority: P0  
Dependencies: ZK-062, ZK-063

Acceptance criteria:

- [x] passphrase remains client-side;
- [x] clear locked/unlocked states;
- [x] failure does not reveal sensitive detail.

Implementation notes:
- Created `VaultContext` and `VaultStore` in `apps/web/src/context/VaultContext.tsx` implementing the complete vault state machine (`UNINITIALIZED`, `LOCKED`, `UNLOCKING`, `UNLOCKED`) using React `useSyncExternalStore` and dynamic property getters.
- Built `UnlockScreen`, `LockVaultButton`, and `VaultStatusBadge` in `apps/web/src/components/UnlockScreen.tsx`:
  - Password inputs strictly use `type="password"`, `spellCheck={false}`, and proper `autoComplete` attributes, preventing cleartext exposure (SEC-001).
  - Component state for passphrases and recovery phrase inputs is wiped immediately upon submission in a `finally` block to minimize in-memory retention.
  - Initial vault creation workflow renders formatted 9-group recovery key with copy-to-clipboard functionality and mandatory acknowledgment checkbox before entering vault.
  - Safe error sanitization strictly maps worker and crypto exceptions to non-revealing generic messages without leaking cipher parameters, AEAD tags, or stack traces (SEC-003, SEC-010).
- Added comprehensive unit and integration test suite in `apps/web/test/unlock-screen.test.tsx` (7 tests covering SSR rendering, masked attributes, state machine transitions, lock broadcasts, and real Worker thread integration).
- All 8 CI quality gates in `./scripts/ci.sh` pass cleanly (26/26 web tests pass).

---

## ZK-065 — Notes list/editor
Status: DONE  
Priority: P1  
Dependencies: ZK-064

Acceptance criteria:

- [x] create/edit/delete;
- [x] Markdown source editor;
- [x] autosave to encrypted local state;
- [x] offline operation.

Implementation notes:
- Implemented `NotesContext` and `NotesStore` in `apps/web/src/context/NotesContext.tsx`:
  - Full note CRUD operations (create, edit, delete, batch load).
  - Debounced autosave (600ms) with immediate manual flush on navigation, blur, or shortcut (Ctrl+S).
  - Encrypts note envelopes in Web Worker (`client.encryptNote`) and persists encrypted state to IndexedDB `objects` store with incremented revision (SEC-001, SEC-006).
  - Enqueues `PendingMutation` (`Upsert` or `Delete`) in IndexedDB `mutations` store for offline-first sync (SEC-007).
  - Tombstone deletion semantics via `storage.markDeleted` and `client.removeFromIndex` (SEC-008).
  - Complete memory sanitization on vault lock: in-memory notes and selection are wiped immediately upon `handleVaultLocked` (SEC-009).
- Created safe, zero-dependency Markdown parser and HTML renderer in `apps/web/src/utils/markdown.ts` with XSS sanitization (`escapeHtml`, `sanitizeUrl`).
- Implemented React UI components:
  - `MarkdownEditor` in `apps/web/src/components/MarkdownEditor.tsx` featuring Markdown source editing, syntax toolbar shortcuts, tags management, view modes (Source, Split, Preview), real-time save status badge, and deletion confirmation modal.
  - `NotesList` in `apps/web/src/components/NotesList.tsx` with sidebar list, relative timestamp formatting, tags pills, new note button, and real-time query filtering.
  - `NotesWorkspace` in `apps/web/src/components/NotesWorkspace.tsx` combining two-pane split layout, top navbar, offline indicator, and vault lock controls.
- Added comprehensive unit and integration test suite in `apps/web/test/notes-editor.test.tsx` (8 tests covering markdown parsing, XSS prevention, store lifecycle, zero-knowledge storage audit, UI rendering, and real Web Worker thread integration).
- All 8 CI quality gates in `./scripts/ci.sh` pass cleanly (34/34 web tests pass).

---

## ZK-066 — Web search
Status: DONE  
Priority: P1  
Dependencies: ZK-065

Acceptance criteria:

- [x] in-memory local search;
- [x] no server query;
- [x] lock clears searchable plaintext state.

Implementation notes:
- Created `SearchContext` in `apps/web/src/context/SearchContext.tsx`:
  - Direct integration with Web Worker search API (`client.search(query)`).
  - Debounced search query dispatch (150ms) with immediate manual search trigger.
  - Zero server query guarantee: search terms and results run 100% locally in the browser/worker process without network transmission (SEC-001).
  - Global shortcut listener (Cmd+K / Ctrl+K) for opening the quick-search palette.
  - Complete memory sanitization on vault lock: in-memory search query, cached results, snippets, and open modals are wiped immediately when vault locks (SEC-009).
- Implemented UI search components:
  - `SearchBar` in `apps/web/src/components/SearchBar.tsx` featuring search icon, responsive input, live loading spinner, clear button, and platform-specific shortcut badge (⌘K / Ctrl+K).
  - `SearchModal` in `apps/web/src/components/SearchModal.tsx` command palette modal with backdrop, auto-focus input, snippet display, relevance score badges, and keyboard navigation (ArrowUp, ArrowDown, Enter to navigate to note, Esc to close).
  - Integrated `SearchBar` and `SearchModal` directly into the `NotesWorkspace` navigation header.
- Added comprehensive test suite in `apps/web/test/web-search.test.tsx` (6 tests covering in-memory local query execution, score ranking, zero-network validation, lock-clearing of plaintext search state, UI rendering, and real Web Worker thread integration).
- All 8 CI quality gates in `./scripts/ci.sh` pass cleanly (40/40 web tests pass).

---

## ZK-067 — Web sync status
Status: DONE  
Priority: P1  
Dependencies: ZK-065, M5

Acceptance criteria:

Display:

```text
offline
syncing
synced
pending changes
conflict
error
```

without leaking note content.

Completion notes:
- Created `SyncStore` and `SyncProvider` in `apps/web/src/context/SyncContext.tsx` handling all 6 required states: `offline`, `syncing`, `synced`, `pending changes`, `conflict`, and `error`.
- Implemented `sanitizeSyncErrorMessage` to strictly redact and sanitize error messages, guaranteeing note titles, note content, and auth tokens are never leaked in UI error states or logs (SEC-001, SEC-003).
- Built `SyncStatusIndicator` in `apps/web/src/components/SyncStatusIndicator.tsx` featuring status icons, exact labels, queue and conflict badge counts, and an interactive popover detailing sanitized sync metrics, a manual "Sync Now" trigger, and an offline mode toggle.
- Integrated `SyncStatusIndicator` directly into `NotesWorkspace` header navbar.
- Created `apps/web/test/sync-status.test.tsx` verifying all 6 sync states, state transitions, and zero-knowledge leak-free guarantees.
- Ran `./scripts/ci.sh`: all 8 CI quality gates pass cleanly (47/47 web tests pass).

---

## ZK-068 — Web conflict resolver
Status: DONE  
Priority: P0  
Dependencies: ZK-053, ZK-065

Acceptance criteria:

- compare local/remote;
- use merge candidate;
- manual resolution;
- preserve-both action.

Completion notes:
- Built three-way text diff3 and structured note merge engine in `apps/web/src/utils/diff3.ts`, supporting non-overlapping line auto-merging, clean identical change merging, standard diff3 conflict markers (`<<<<<<< LOCAL`, `=======`, `>>>>>>> REMOTE`), and deterministic set-based tag merging.
- Created `ConflictStore` and `ConflictProvider` in `apps/web/src/context/ConflictContext.tsx`, managing active conflicts, side-by-side in-memory envelope decryption, and all 4 resolution strategies (Keep Local, Keep Remote, Candidate/Manual Merge, and Preserve Both).
- Built `ConflictResolverModal` in `apps/web/src/components/ConflictResolverModal.tsx` featuring side-by-side comparison of local vs remote revisions, titles, tags, and bodies; one-click "Use Merge Candidate"; interactive manual merge editor with diff3 markers; and "Preserve Both (Duplicate Local)".
- Integrated conflict detection and actions into `MarkdownEditor.tsx` (active conflict banner), `NotesList.tsx` (per-note warning badges), `SyncStatusIndicator.tsx` (popover resolution trigger), and `NotesWorkspace.tsx`.
- Created comprehensive test suite in `apps/web/test/conflict-resolver.test.tsx` verifying diff3 mechanics, side-by-side comparison, all resolution actions, CAS revision tracking, and zero-knowledge security guarantees (SEC-001, SEC-003, SEC-009).
- Validated via `./scripts/ci.sh`: all 8 quality gates pass cleanly (59/59 web tests pass).

---

## ZK-069 — Browser security headers/CSP
Status: DONE  
Priority: P0  
Dependencies: ZK-065

Acceptance criteria:

- restrictive CSP;
- no third-party runtime script requirement;
- no inline unsafe script unless explicitly justified;
- clickjacking/content-type hardening;
- deployment documentation.

Completion notes:
- Implemented `security_headers_middleware` in `apps/server/src/app.rs` injecting restrictive Content Security Policy (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;`), anti-clickjacking headers (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), MIME-type protection (`X-Content-Type-Options: nosniff`), zero-leakage referrer policy (`Referrer-Policy: no-referrer`), cross-origin isolation (`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`), hardware lock-down (`Permissions-Policy`), and HSTS.
- Created hardened `apps/web/index.html` with CSP meta tags, `nosniff`, `no-referrer`, zero third-party script requirements, and zero inline scripts.
- Authored production-ready deployment configurations in `deploy/nginx/security-headers.conf`, `deploy/nginx/notes.conf`, and `deploy/caddy/Caddyfile`.
- Authored comprehensive documentation in `docs/deployment/web-security.md` covering threat model, header rationale, WASM memory isolation, and multi-platform deployment instructions.
- Added tests in `apps/server/src/app.rs` (`test_browser_security_headers_and_csp`) and `apps/web/test/security-headers.test.ts` verifying header presence, strict CSP directives, zero external script tags, and zero third-party runtime dependencies.
- Passed all 8 CI quality gates via `./scripts/ci.sh` (64/64 web tests pass).

---

### M6 Gate

Status: PASSED  
Automated verification in `tests/wasm_crypto_compat.test.mjs::"M6 Gate: CLI create -> sync -> web pull/decrypt -> web edit offline -> sync -> CLI pull/decrypt"`.

Same account can:

```text
CLI create → sync → web pull/decrypt
web edit offline → sync
CLI pull/decrypt
```

Native/WASM compatibility suite must pass.
- Full cross-runtime cycle verified: CLI creates note -> syncs -> Web pulls and decrypts via WASM -> Web edits offline and re-encrypts -> syncs -> CLI pulls and decrypts updated note.
- Native/WASM compatibility suite: 28/28 tests passed (`./scripts/ci.sh` step 7).
- Web application test suite: 64/64 tests passed (`./scripts/ci.sh` step 8).
- All 8 repository CI quality gates pass cleanly.

---

# M7 — Authentication, recovery, and device security

## ZK-070 — Authentication abstraction
Status: DONE  
Priority: P0  
Dependencies: M3

Acceptance criteria:

- server auth independent of vault passphrase;
- access tokens never logged;
- auth middleware owns account identity.

Completion notes:
- Protocol layer (`crates/zk-protocol`):
  - Defined `AuthToken` in `crates/zk-protocol/src/auth.rs` implementing `Zeroize` and `ZeroizeOnDrop` for automatic memory scrubbing, with custom `fmt::Debug` and `fmt::Display` implementations unconditionally redacting secrets as `[REDACTED]` (SEC-003).
  - Defined protocol session models `AuthenticatedSession` and `SessionResponse` for strongly-typed server session exchange.
  - Added protocol canonical error constants `ERROR_AUTH_EXPIRED`, `ERROR_AUTH_REVOKED`, and `ERROR_DEVICE_REVOKED` in `crates/zk-protocol/src/constants.rs`.
- Client sync adapter (`crates/zk-sync`):
  - Updated `NativeHttpSyncAdapter` with custom `fmt::Debug` redacting active auth tokens.
  - Added typed `set_token(Option<AuthToken>)` and `get_token() -> Option<AuthToken>` alongside existing string APIs.
- Database & migrations (`apps/server`):
  - Created migration `migrations/007_server_sessions.sql` establishing the `sessions` table (with `session_id`, `account_id`, `device_id`, `token_hash`, `display_name`, `created_at`, `expires_at`, `revoked_at`) and indexes on `account_id` and `(account_id, device_id)`.
  - Registered migration 7 in `apps/server/src/db/migrations.rs` and added `TABLE_SESSIONS`, `INDEX_SESSIONS_ACCOUNT_ID`, `INDEX_SESSIONS_DEVICE_ID`, and `SessionRow` in `apps/server/src/db/schema.rs`.
  - Added session and device methods to `ServerDb`: `create_session` (generating 256-bit CSPRNG tokens and persisting only BLAKE2s digests `token_hash`), `validate_session_token`, `revoke_session`, `revoke_all_sessions_for_account`, `revoke_device_sessions`, `register_device`, `revoke_device`, `is_device_revoked`, `list_devices`, and `list_sessions`.
- Server authentication & middleware (`apps/server`):
  - Enhanced `AuthenticatedAccount` with `device_id` and `session_id`.
  - Enhanced `AuthError` with `ExpiredToken`, `RevokedToken`, and `DeviceRevoked`, mapping to generic HTTP 401/403 responses that never echo tokens.
  - Implemented `authenticate_bearer_token` verifying cryptographic session digests against `sessions` (and legacy account UUID fallback for backwards test compatibility).
  - Implemented `auth_middleware` intercepting all protected routes (`/v1/vault/bootstrap`, `/v1/sync/*`), verifying tokens, validating cross-account and cross-device boundaries, and injecting `AuthenticatedAccount` into request extensions. Handlers consume `AuthenticatedAccount` from extensions directly.
  - Public health endpoints (`/health`, `/v1/health`) bypass authentication.
- Tests & verification:
  - Added unit tests in `crates/zk-protocol/src/auth.rs`, `crates/zk-sync/src/adapter.rs`, and `apps/server/src/auth.rs`.
  - Added integration test suite in `apps/server/tests/server_authentication_abstraction_tests.rs` covering passphrase independence, token logging redaction, full auth middleware lifecycle, expiration, revocation, and device cascading revocation.
  - Validated via `./scripts/ci.sh` (all 8 quality gates passed cleanly).

---

## ZK-071 — Passkey/WebAuthn web auth
Status: DONE  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- register;
- sign in;
- revoke session;
- no vault passphrase reuse.

Completion notes:
- Protocol layer (`crates/zk-protocol`):
  - Defined WebAuthn models in `crates/zk-protocol/src/webauthn.rs`: `WebAuthnRpInfo`, `WebAuthnUserInfo`, `WebAuthnRegisterStartRequest`, `WebAuthnRegisterStartResponse`, `WebAuthnRegisterFinishRequest`, `WebAuthnRegisterFinishResponse`, `WebAuthnLoginStartRequest`, `WebAuthnLoginStartResponse`, `WebAuthnLoginFinishRequest`, `WebAuthnLoginFinishResponse`, `RevokeSessionRequest`, `RevokeSessionResponse`.
  - Added canonical error codes in `constants.rs`: `ERROR_WEBAUTHN_CHALLENGE_EXPIRED`, `ERROR_WEBAUTHN_CHALLENGE_NOT_FOUND`, `ERROR_WEBAUTHN_VERIFICATION_FAILED`, `ERROR_WEBAUTHN_CREDENTIAL_NOT_FOUND`, `ERROR_WEBAUTHN_CREDENTIAL_EXISTS`.
- Server storage & migrations (`apps/server`):
  - Authored migration `migrations/008_webauthn_credentials.sql` creating `webauthn_credentials` and `webauthn_challenges` tables with appropriate indexes.
  - Updated `apps/server/src/db/migrations.rs`, `schema.rs`, and `error.rs` to track migration 008.
  - Implemented WebAuthn methods on `ServerDb`: `create_webauthn_challenge`, `consume_webauthn_challenge` (single-use validation with TTL enforcement), `register_webauthn_credential`, `get_webauthn_credential`, `update_webauthn_credential_usage`, and session revocation.
- Server route handlers (`apps/server/src/routes/auth.rs`):
  - Implemented `webauthn_register_start_handler`, `webauthn_register_finish_handler`, `webauthn_login_start_handler`, `webauthn_login_finish_handler`, and `revoke_session_handler`.
  - Enforced SEC-001/SEC-002: Active payload inspection via `contains_forbidden_keys` strictly rejects any submission containing passphrase or vault key material ("no vault passphrase reuse").
  - Wired public WebAuthn routes and protected session revocation routes into `create_app` in `apps/server/src/app.rs`.
- Web client adapter (`apps/web`):
  - Authored `apps/web/src/auth/webauthn.ts` supporting base64url transformations, `startRegistration`, `finishRegistration`, `startLogin`, `finishLogin`, and `revokeSession`.
  - Created `apps/web/src/context/AuthContext.tsx` (`AuthProvider`, `useAuth`) wiring session state management.
  - Wrapped `AuthProvider` into root `App.tsx` and exported in `index.ts`.
- Tests & verification:
  - Integration test suite in `apps/server/tests/server_webauthn_tests.rs` (5/5 tests passing).
  - Unit test suite in `apps/web/test/webauthn.test.ts` (6/6 tests passing, bringing total web suite to 70/70 passing).
  - Validated via `./scripts/ci.sh` (all 8 quality gates passed cleanly).

---

## ZK-072 — CLI login/device authorization
Status: DONE  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- secure account authorization flow;
- token persistence uses platform secure storage where possible;
- revocation supported.

Completion notes:
- Protocol layer (`crates/zk-protocol`):
  - Defined device authorization models in `crates/zk-protocol/src/auth.rs`: `DeviceAuthRequest`, `DeviceAuthResponse`, and `SessionStatusResponse`.
  - Added unit tests verifying model serialization/deserialization and redacting secret token in Debug formatting.
- Server endpoints (`apps/server`):
  - Implemented `device_authorize_handler` in `apps/server/src/routes/auth.rs` mapped to `POST /v1/auth/device/authorize` and `POST /v1/auth/cli/login`.
  - Enforced SEC-001/SEC-002: payload inspection via `contains_forbidden_keys` strictly rejects any passphrase or vault key submission.
  - Enforced revocation checking: fails closed with 403 Forbidden (`ERROR_DEVICE_REVOKED`) if the target device is revoked.
  - Implemented `session_status_handler` mapped to `GET /v1/auth/session/status` and `GET /v1/auth/whoami` under `auth_middleware`.
- CLI authentication and persistence (`apps/cli`):
  - Authored `apps/cli/src/auth.rs` managing `StoredAuthSession`, device identity, `api_device_authorize`, `api_verify_token`, `api_revoke_session`, and `api_query_status`.
  - Token persistence: session credentials saved to `.auth_session` with strict POSIX mode `0600` permissions (owner read/write only); file contents are zeroized before deletion on logout.
  - Device identity: persistent client device ID managed in `device.json`.
  - Secret redaction: `StoredAuthSession` unconditionally formats secret token as `[REDACTED]` in `Debug` output (SEC-003).
  - CLI subcommands:
    - `zk-note login`: supports `--server`, `--account-id`, `--device-name`, `--device-id`, and `--token`, with interactive fallback when args omitted.
    - `zk-note logout`: revokes active session on server and securely clears local `.auth_session`.
    - `zk-note whoami`: queries session status from server, displaying account and device IDs without ever printing raw tokens; gracefully handles remote session/device revocation.
    - `zk-note status`: updated to display server authentication status alongside vault lock state.
- Tests & verification:
  - Server integration suite in `apps/server/tests/server_device_auth_tests.rs` (5/5 passing).
  - CLI integration suite in `apps/cli/src/main.rs` and `apps/cli/src/auth.rs` (34/34 passing).
  - Validated via `./scripts/ci.sh` (all 8 quality gates passed cleanly).

---

## ZK-073 — Recovery UX
Status: DONE  
Priority: P0  
Dependencies: ZK-013, M6

Acceptance criteria:

- recovery key displayed/exported safely;
- user warned server cannot recover lost key;
- recovery flow restores Vault Key;
- new passphrase can be set.

Completion notes:
- Core (`crates/zk-core/src/vault.rs`): Added `VaultManager::set_new_passphrase` which rewraps the existing `VaultKey` under a fresh KEK derived from a new master passphrase and fresh salt/nonce, preserving the VaultKey and existing recovery key envelope unchanged.
- Web UI (`apps/web`):
  - In `UnlockScreen.tsx`: Added formatted export download (`zk-notes-recovery-key.txt`) and clipboard copy with prominent warning that the zero-knowledge server cannot recover lost keys and data loss is permanent if both credentials are lost.
  - In `UnlockScreen.tsx`: Added post-recovery flow (`recoveryUnlocked`) prompting the user to set a new master passphrase (minimum 8 characters with confirmation) using `rewrapPassphrase`, with an option to skip and enter directly.
  - In `SecurityRecoveryModal.tsx`: Created modal presenting zero-knowledge security guarantees, recovery key invariants, safe offline storage guidelines, and in-vault passphrase rotation without touching stored ciphertexts.
  - Wired `SecurityRecoveryModal` into `NotesWorkspace.tsx` and exported from `apps/web/src/index.ts`.
  - Added unit and worker integration tests in `apps/web/test/unlock-screen.test.tsx` verifying safe export, warning display, and passphrase rewrap preserving note decryptability and recovery key validity (72/72 passing).
- CLI (`apps/cli`):
  - In `commands.rs`: Updated `cmd_unlock` to support optional `--new-passphrase` rotation upon unlock.
  - In `commands.rs`: Implemented `cmd_recover` (`zk-note recover`) with clear zero-knowledge warning banner, 288-bit recovery key restoration of `VaultKey`, optional interactive or flag-based new passphrase prompt/reset via atomic temporary file rename, immediate session unlock, and optional `--export-receipt` safe file output with zero secret leakage.
  - In `main.rs`: Added `Commands::Recover` and updated `Commands::Unlock` with `--new-passphrase`. Added comprehensive CLI tests for recovery UX, note decryptability, old passphrase rejection, and receipt export (36/36 passing).
- Verified with `./scripts/ci.sh` (all 8 quality gates passing cleanly).

---

## ZK-074 — Password change UX
Status: DONE  
Priority: P1  
Dependencies: ZK-017

Acceptance criteria:

- rewrap only;
- old object ciphertext unchanged;
- recovery wrapper remains valid unless intentionally rotated.

Completion notes:
- CLI (`apps/cli`):
  - In `commands.rs`: Implemented `cmd_passwd` (`zk-note passwd`, aliases: `change-password`, `password`).
  - Verifies current master passphrase fails closed before allowing rotation.
  - Prompts for new passphrase with minimum 8-character length validation and confirmation matching.
  - Re-wraps existing `VaultKey` with a fresh KEK derived from new passphrase and fresh salt/nonce via `VaultManager::set_new_passphrase`.
  - Atomically replaces `vault.json` using atomic temporary file rename (`vault.json.tmp.<pid>`).
  - Preserves unchanged `recovery_wrapped_vault_key` envelope in `VaultBootstrap` verbatim.
  - Guarantees zero modification to stored SQLite note ciphertexts; notes remain decryptable under preserved VaultKey.
  - Added CLI integration tests in `apps/cli/src/main.rs::test_cli_passwd_command_lifecycle` verifying authentication verification, fail-closed behavior on wrong old passphrase, note decryptability, rejection of old passphrase on unlock, and continued validity of recovery key (37/37 passing).
- Web UI (`apps/web`):
  - In `apps/web/src/worker/protocol.ts`, `vault-handler.ts`, and `client.ts`: Enhanced `REWRAP_PASSPHRASE` message payload to support verifying `oldPassphrase` against the current stored `wrappedVaultKey` and KDF parameters using `zk.unlock_vault` prior to re-wrapping. If old passphrase fails verification, rejects with `WorkerErrorCode.DECRYPTION_FAILED` ("Current master passphrase is incorrect.").
  - In `apps/web/src/context/VaultContext.tsx`: Updated `rewrapPassphrase` and `sanitizeError` to pass `oldPassphrase` and current bootstrap envelopes to worker client and handle error messages cleanly.
  - In `apps/web/src/components/SecurityRecoveryModal.tsx`: Updated "Change Passphrase" tab to require `Current Master Passphrase`, `New Master Passphrase`, and `Confirm New Passphrase`, clearing inputs from component memory immediately upon submit and close.
  - In `apps/web/test/unlock-screen.test.tsx`: Added end-to-end worker integration tests verifying fail-closed rejection on wrong current passphrase, note decryptability, old passphrase invalidation, and recovery key validity (73/73 passing).
- Quality gates: All 8 CI quality gates in `./scripts/ci.sh` pass cleanly.

---

## ZK-075 — Device list/revoke
Status: DONE  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- list authorized devices/sessions;
- revoke;
- revoked device cannot sync with invalidated credentials;
- encrypted data model unchanged.

Implementation notes:
- Protocol (`crates/zk-protocol/src/auth.rs`): Added `DeviceInfo`, `DeviceListResponse`, `RevokeDeviceRequest`, and `RevokeDeviceResponse` structs with serialization/deserialization tests.
- Server (`apps/server`):
  - Added endpoints `GET /v1/devices`, `DELETE /v1/devices/{device_id}`, and `POST /v1/devices/revoke`.
  - Enforced device revocation check prior to session check in `ServerDb::validate_session_token`, ensuring revoked devices immediately fail closed across sync pull and mutations with HTTP 401 and error code `ERROR_DEVICE_REVOKED`.
  - Added integration tests covering device registration, listing, cross-account authorization isolation, cascading active session invalidation, and sync rejection.
- CLI (`apps/cli`):
  - Added `api_list_devices` and `api_revoke_device` in `apps/cli/src/auth.rs`.
  - Implemented `cmd_device_list` and `cmd_device_revoke` in `apps/cli/src/commands.rs`.
  - Added `zk-note device [list|revoke]` CLI subcommands with tabular and JSON output, clearing local session if the current device was revoked.
  - Added end-to-end multi-client test `test_cli_device_list_and_revoke` in `apps/cli/src/main.rs`.
- Web Client (`apps/web`):
  - Added `DeviceInfo`, `listDevices`, and `revokeDevice` API helpers in `apps/web/src/auth/webauthn.ts`.
  - Integrated `listDevices` and `revokeDevice` into `AuthContext` and `AuthProvider`.
  - Created accessible `DeviceManagementModal` displaying authorized devices, current device badging, active/revoked status, and confirmation before revoking.
  - Added `📱 Devices` button in `NotesWorkspace` navbar.
  - Added unit and SSR component tests in `apps/web/test/device-management.test.tsx`.
- Security invariants preserved:
  - SEC-001 / SEC-002: Plaintext notes, Vault Keys, and passphrases are never transmitted or handled during device listing/revoking.
  - SEC-003: Tokens and credentials are never logged.
  - Encrypted note format and database schema remain untouched.
- Quality gates: All 8 CI gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-076 — Auto-lock policy
Status: DONE  
Priority: P1  
Dependencies: M6

Acceptance criteria:

- configurable idle lock;
- explicit lock;
- secret/plaintext in-memory state disposed best-effort.

Completion notes:
- Shared Core (`crates/zk-core`):
  - Added `now_epoch_secs()` supporting both native and wasm32 targets (`crates/zk-core/src/time.rs`).
  - Extended `VaultSession` (`crates/zk-core/src/vault.rs`) with `idle_timeout_secs: Option<u64>` and `last_active_secs: u64`.
  - Added methods `with_idle_timeout`, `set_idle_timeout`, `idle_timeout`, `last_active_secs`, `touch`, and `check_idle_timeout` which automatically locks the session and purges the volatile search index when idle timeout is exceeded.
  - Added unit test `test_vault_session_idle_timeout_and_auto_lock`.
- WASM Bridge (`crates/zk-wasm`):
  - Bound `set_idle_timeout`, `idle_timeout`, `touch`, and `check_idle_timeout` on `WasmVaultSession`.
- CLI Client (`apps/cli`):
  - Upgraded session storage (`apps/cli/src/session.rs`) to store JSON `SessionEnvelope` containing `key`, `created_at`, `last_active_at`, and `idle_timeout_secs` while maintaining full backward compatibility with raw 32-byte session files.
  - `load_session_key_and_touch` and `load_session_key` verify idle expiration; if expired, the session file is securely zeroed across its entire length, unlinked from disk, and fails closed with `CliError::VaultLocked`.
  - Added `autolock` command (`apps/cli/src/commands.rs` and `apps/cli/src/main.rs`) to inspect and update idle timeout policies (`zk-note autolock [timeout_mins]`).
  - Added `--timeout <MINUTES>` flag to `zk-note unlock`.
  - Added integration test `test_cli_auto_lock_policy_lifecycle` verifying configuration, activity tracking, auto-lock on expiration, and explicit lock.
- Web Client (`apps/web`):
  - In `VaultStore` and `VaultContext` (`apps/web/src/context/VaultContext.tsx`):
    - Added configurable `autoLockTimeoutMinutes` (default 15m), stored in `localStorage` under `zk_autolock_minutes` (0 disables auto-lock).
    - Periodic idle checker (every 2s, unref'd in Node test environments) and `visibilitychange` listener invoke `checkIdleLock()`, locking the vault on inactivity.
    - Throttled window user activity listeners (`mousedown`, `keydown`, `touchstart`, `scroll`, `mousemove`) invoke `recordActivity()`.
    - Best-effort secret disposal: `VaultSession.lock()` zeroizes key material and clears search indexes; `NotesStore.handleVaultLocked()` purges all decrypted notes and drafts from memory (`this.notes = []`).
  - In `SecurityRecoveryModal` (`apps/web/src/components/SecurityRecoveryModal.tsx`):
    - Added "Auto-Lock" tab with radio choices (5m, 15m, 30m, 60m, Never) and immediate "Lock Vault Now" action button.
  - Added unit and UI tests in `apps/web/test/unlock-screen.test.tsx` verifying idle lock triggering, activity reset, and modal rendering.
- Quality gates: All 8 CI gates pass cleanly via `./scripts/ci.sh`.

---

# M8 — Encrypted attachments

## ZK-080 — Attachment cryptographic format
Status: DONE  
Priority: P0  
Dependencies: M1

Acceptance criteria:

- random Attachment Key;
- chunk format versioned;
- unique nonce per chunk;
- authenticated chunk index/attachment ID via AAD.

Completion notes:
- Strongly typed `AttachmentKey`: 256-bit symmetric key (`[u8; 32]`) defined in `crates/zk-crypto/src/keys.rs` with `ZeroizeOnDrop`, constant-time equality comparison, and CSPRNG generation (`AttachmentKey::generate()`).
- Attachment protocol models: Defined `EncryptedChunk`, `AttachmentManifest`, and binary format with magic header `ZKCK` in `crates/zk-protocol/src/attachment.rs`. Added constants `ATTACHMENT_CHUNK_VERSION_V1`, `DEFAULT_ATTACHMENT_CHUNK_SIZE` (4 MiB), and `MAX_ATTACHMENT_SIZE` (100 MiB) in `crates/zk-protocol/src/constants.rs`.
- Cryptographic chunk operations in `crates/zk-crypto/src/attachment.rs`:
  - `build_chunk_aad`: Binds format version, attachment ID, chunk index, and total chunks.
  - `encrypt_chunk` / `encrypt_chunk_with_rng`: Generates unique 24-byte random nonce per chunk and encrypts using XChaCha20-Poly1305 with AAD.
  - `decrypt_chunk`: Decrypts and authenticates chunk; fails closed on wrong key, corrupted ciphertext, or tampered AAD.
  - `encrypt_chunk_binary` / `decrypt_chunk_binary`: High-performance binary serialization bypassing base64 allocations.
  - `wrap_attachment_key` / `unwrap_attachment_key`: Wraps and unwraps `AttachmentKey` under master `VaultKey` with AAD binding.
- Tests added: Round-trip encrypt/decrypt (JSON and binary), wrong key failure, tampered ciphertext, tampered chunk index, tampered attachment ID, tampered total chunks, truncated nonce, and unsupported version.
- Quality gates: All 8 CI gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-081 — Chunked native encryption
Status: DONE  
Priority: P0  
Dependencies: ZK-080

Acceptance criteria:

- streaming/chunked operation;
- corrupted chunk fails;
- no need to buffer entire large file in memory.

Completion notes:
- Implemented streaming chunked encryption and decryption in `crates/zk-core/src/attachment.rs`:
  - `encrypt_attachment_stream_with_sink`: Streams from any `std::io::Read` without loading the full file into memory; buffers at most one chunk (`params.chunk_size`, defaulting to 4 MiB) and passes encrypted chunks to an output sink callback.
  - `encrypt_attachment_stream`: Collects encrypted chunks into a vector while incrementally computing BLAKE2b-512 content integrity hash.
  - `encrypt_attachment_file`: Streams file from disk directly to chunked ciphertext without buffering the entire file.
  - `decrypt_attachment_stream_with_source`: Streams decrypted plaintext directly to any `std::io::Write` sink, verifying sequential ordering (0, 1, ..., N-1), total chunk count consistency, and BLAKE2b content hash integrity.
  - `decrypt_attachment_to_file`: Decrypts chunks directly to disk with automatic fail-closed cleanup if verification or decryption fails.
- Strict security invariants enforced:
  - Any corrupted chunk, tampered ciphertext, out-of-order chunk, or missing chunk fails closed immediately (`CoreError::Crypto` / `AttachmentError`).
  - Strict size enforcement against `MAX_ATTACHMENT_SIZE` (100 MiB).
- Comprehensive unit tests added in `crates/zk-core/src/attachment.rs` covering streaming round-trip, empty file streaming, corrupted chunks, out-of-order chunks, missing chunks, oversize rejection, and file-to-file round trip.
- Quality gates: All 8 CI gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-082 — Ciphertext blob server API
Status: DONE  
Priority: P1  
Dependencies: ZK-081

Acceptance criteria:

- opaque blob IDs;
- authorization;
- size quotas;
- no filename/MIME plaintext.

Completion notes:
- Migration and schema:
  - Created `migrations/009_ciphertext_blobs.sql` adding `blobs` table (`account_id`, `blob_id`, `size`, `data`, `created_at`, `updated_at`, PK `(account_id, blob_id)`) and index `idx_blobs_account_id`.
  - Registered migration 9 in `apps/server/src/db/migrations.rs` and updated `ALL_TABLES`/`ALL_INDEXES` in `apps/server/src/db/schema.rs`.
- Server storage operations (`apps/server/src/db/store.rs`):
  - `put_blob`: Upserts opaque ciphertext bytes; enforces single blob size limit (`max_blob_size`) and account aggregate storage quota (`account_blob_quota`).
  - `get_blob`: Retrieves blob data strictly scoped to authenticated `account_id` (returns `None` for cross-account or missing blobs).
  - `delete_blob`: Deletes blob strictly scoped to authenticated `account_id`.
  - `get_account_blob_usage`: Computes total storage consumed by account's blobs.
- Server API endpoints (`apps/server/src/routes/blob.rs` and `apps/server/src/app.rs`):
  - `PUT /v1/blobs/{blob_id}`: Accepts binary/octet-stream ciphertext chunk; enforces authentication, opaque blob ID format, max blob size, and aggregate quota; returns 201 Created.
  - `GET /v1/blobs/{blob_id}`: Returns raw ciphertext chunk with `Content-Type: application/octet-stream`; returns 404 Not Found if missing or belonging to another account.
  - `DELETE /v1/blobs/{blob_id}`: Deletes chunk; returns 200 OK or 404 Not Found.
- Security and zero-knowledge invariants (SEC-001, SEC-002, SEC-003):
  - Opaque IDs: strictly validates 1-128 alphanumeric, hyphen, or underscore characters.
  - Authorization: routes are protected by `auth_middleware`; cross-account access is strictly prevented.
  - Plaintext leakage prevention: requests containing metadata headers (such as `x-filename`, `x-mime-type`, `x-note-id`) are immediately rejected with 400 Bad Request (`PLAINTEXT_METADATA_FORBIDDEN`). No plaintext note or file fields exist in the schema or endpoints.
- Integration tests added:
  - `apps/server/tests/server_blob_tests.rs`: Comprehensive coverage of full put/get/delete lifecycle, cross-account isolation, unauthenticated/revoked token rejection, single blob size limit enforcement (HTTP 413), account aggregate storage quota enforcement (HTTP 413), forbidden plaintext header rejection, and invalid blob ID validation.
  - `apps/server/tests/server_db_migration_tests.rs`: Verified migration 9 clean state, idempotency, foreign key cascade, primary key uniqueness, and schema zero-knowledge invariants.
- Quality gates: All 8 CI gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-083 — Attachment manifest integration
Status: DONE  
Priority: P1  
Dependencies: ZK-082

Acceptance criteria:

- name/MIME/size metadata encrypted;
- note references stable attachment ID;
- delete/update semantics defined.

Completion notes:
- Attachment manifest envelope encryption:
  - Added `encrypt_attachment_manifest` and `decrypt_attachment_manifest` in `crates/zk-core/src/attachment.rs`.
  - Serializes `AttachmentManifest` (containing name, mime, size, chunk_count, chunk_size, content_hash) into JSON and encrypts into standard `EncryptedEnvelope` with `OBJECT_KIND_ATTACHMENT_MANIFEST = 4`, wrapping `AttachmentKey` under `VaultKey` with AAD authentication.
  - Decryption fails closed if ciphertext is tampered or key is invalid.
- Note attachment reference model & domain helpers:
  - Added `add_attachment_to_note`, `remove_attachment_from_note`, and `find_orphaned_attachments` in `crates/zk-core/src/attachment.rs`.
  - Notes reference stable attachment IDs in `note.attachments: Vec<String>`.
  - Set-based 3-way merge in `crates/zk-sync/src/merge.rs` (`merge_attachments`) ensures convergent conflict resolution across concurrent devices.
- CLI attachment management commands (`apps/cli/src/commands.rs`):
  - `cmd_attach`: Reads file, creates random `AttachmentKey` and attachment ID, chunks/encrypts data, stores encrypted manifest object (`OBJECT_KIND_ATTACHMENT_MANIFEST`), updates note's attachment list, and enqueues pending sync mutations.
  - `cmd_detach`: Removes attachment ID from note, enqueues note update mutation, and writes tombstone for manifest object with pending delete mutation.
  - `cmd_attachments`: Lists attachments for a note by decrypting their stored manifests.
  - Updated `cmd_show` to display note attachments.
- Unit and integration tests:
  - Added unit tests in `crates/zk-core/src/attachment.rs` for manifest encryption/decryption round trip and note attachment lifecycle.
  - Added CLI integration test `test_attachment_attach_list_detach_lifecycle` in `apps/cli/src/main.rs`.
- Quality gates: All 8 CI quality gates pass cleanly via `./scripts/ci.sh`.


---

## ZK-084 — Web attachment support
Status: DONE  
Priority: P1  
Dependencies: ZK-083, M6

Acceptance criteria:

- encrypt before upload;
- decrypt after download;
- progress shown;
- network sees ciphertext only.

Completion notes:
- WebAssembly attachment operations (`crates/zk-wasm/src/lib.rs`):
  - Added `attachments: Vec<String>` to `WasmPlaintextNote`.
  - Exported `WasmAttachmentManifest` and `WasmDecryptedManifest` via `wasm-bindgen`.
  - Added session methods to `WasmVaultSession`: `encrypt_note_with_attachments`, `encrypt_attachment_manifest`, `decrypt_attachment_manifest`, `encrypt_attachment_chunk` (with binary ZKCK wire format serialization), and `decrypt_attachment_chunk` (validating format, version, and AAD).
  - Exported standalone helpers: `wasm_generate_attachment_key`, `wasm_compute_content_hash`, and `wasm_calculate_chunk_count`.
  - Added comprehensive wasm unit test `test_wasm_attachment_manifest_and_chunks` and recompiled via `wasm-pack build --target web crates/zk-wasm --out-dir pkg`.
- Dedicated Web Worker integration (`apps/web/src/worker/`):
  - Updated `PlaintextNoteDto` to include `attachments: string[]`.
  - Defined `AttachmentManifestDto` and worker request/response RPC protocol types for attachment key generation, content hashing, manifest encryption/decryption, and chunk encryption/decryption.
  - Implemented handlers in `vault-handler.ts` delegating to active `WasmVaultSession` without exposing key material to the UI thread.
  - Extended `VaultWorkerClient` with type-safe asynchronous worker call wrappers.
- IndexedDB ciphertext blob caching (`apps/web/src/storage/indexeddb.ts`):
  - Bumped schema version to `DB_SCHEMA_VERSION = 2` with new `blobs` object store.
  - Added `putBlob`, `getBlob`, `deleteBlob`, and `listBlobIds` APIs for storing encrypted chunk bytes locally.
- Web Attachment Manager (`apps/web/src/attachments/manager.ts`):
  - Implemented `AttachmentManager` orchestrating chunked upload and download workflows.
  - Enforced 100 MiB file size limit (`MAX_ATTACHMENT_SIZE`).
  - Chunked streaming (4 MiB default) with unique 24-byte nonces and AAD binding per chunk.
  - Progress callbacks reporting `encrypting`, `uploading`, `downloading`, `decrypting`, and `complete` phases with accurate percentage calculations.
  - Generates and encrypts `AttachmentManifest` envelope (object kind 4) under active VaultKey and enqueues sync mutation.
  - Verifies BLAKE2b content hash and chunk integrity upon download, failing closed immediately if ciphertext or AAD is tampered (SEC-010).
  - Tombstone deletion lifecycle: `deleteAttachment` marks manifest object deleted, enqueues delete mutation with `expected_revision`, and scrubs cached blobs.
- UI & Editor integration (`apps/web/src/context/NotesContext.tsx`, `apps/web/src/components/MarkdownEditor.tsx`):
  - Integrated `AttachmentManager` into `NotesContext` (`attachFile`, `detachAttachment`, `downloadAttachment`, `getAttachmentManifests`, `attachmentProgress`).
  - Rendered Attachments section in `MarkdownEditor` with file upload trigger, progress bar indicator, attachment chips with file size formatting, download action, and detach action.
  - Extended note 3-way merge (`apps/web/src/utils/diff3.ts`) with set-based attachment ID merging.
- Security & Zero-Knowledge validation:
  - Added `apps/web/test/attachments.test.ts` covering worker chunk crypto, manifest crypto, multi-chunk upload/download roundtrip, progress event emissions, oversized file rejection, tampered chunk fail-closed enforcement, and network traffic inspection.
  - Verified network traffic sees CIPHERTEXT ONLY: `PUT /v1/blobs/{blob_id}` transfers binary ZKCK wire format with `Content-Type: application/octet-stream`; URLs, headers, and request bodies contain zero plaintext filenames, MIME types, or note content (SEC-001, SEC-002, SEC-003).
- Quality gates: All 8 CI quality gates pass cleanly via `./scripts/ci.sh`.


---

# M9 — Hardening and release candidate

## ZK-090 — Protocol property tests
Status: DONE  
Priority: P0  
Dependencies: M8

Acceptance criteria:

- random object/revision sequences;
- no invalid silent state transitions;
- idempotency property;
- cursor monotonicity property.

Completion notes:
- Implemented dedicated property testing suite in `apps/server/tests/protocol_property_tests.rs`:
  - `test_property_no_invalid_silent_state_transitions`: Verified strict compare-and-swap state machine semantics (non-existent object requires `expected_revision = 0`; existing objects require exact matching revision; stale or future revisions reject with `Conflict`; tombstones increment revision monotonically; stale writes cannot silently resurrect deleted objects; explicit updates after deletion require matching revision).
  - `test_property_idempotency_exact_replay_preserves_state`: Proved that replaying identical accepted mutations repeatedly returns original revision and server sequence without allocating new sequence numbers or modifying database state; verified that altered payload replays reject with `ReplayMismatch`.
  - `test_property_cursor_monotonicity_and_pagination`: Proved strict sequence monotonicity across sequential writes ($S_{k+1} > S_k$); verified pagination across multiple page sizes ($L \in \{1, 2, 3, 5, 7, 10, 25, 50\}$) ensuring cursor advances strictly monotonically ($C_{k+1} > C_k$), all changes are visited without omissions or duplicates, and trailing cursor queries return empty pages with `has_more = false`.
  - `test_property_randomized_multi_object_sequence_simulation`: Built a 500-step model-based randomized fuzz test across 10 distinct object IDs, validating state transitions, idempotency, and sequence monotonicity against an in-memory reference model at every step.
- Quality gates: All 8 CI quality gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-091 — Concurrency stress suite
Status: DONE  
Priority: P0  
Dependencies: M5

Acceptance criteria:

- concurrent writers;
- duplicate mutation races;
- server restart;
- network retry;
- no duplicate accepted logical mutation.

Completion notes:
- Implemented comprehensive concurrency stress test suite in `apps/server/tests/concurrency_stress_tests.rs`:
  - `test_stress_concurrent_writers_same_object_cas_race`: 50 concurrent writers raced to update the same object from revision 1; verified that exactly 1 writer succeeded with revision 2, and exactly 49 writers were rejected with HTTP 409 Conflict containing current revision 2.
  - `test_stress_concurrent_writers_distinct_objects`: 50 concurrent writers created 50 distinct objects simultaneously; verified that all 50 succeeded and received strictly unique sequence numbers spanning `1..=50` with no duplicates or gaps.
  - `test_stress_duplicate_mutation_races`: 50 concurrent tasks fired the exact same mutation ID and payload simultaneously; verified that all tasks received identical `PushResponse` with revision 1 and server sequence 1, and only 1 logical sequence was allocated.
  - `test_stress_network_retry_lost_response`: Simulated dropped responses across multiple consecutive revisions; verified that client retries yielded idempotent responses and no duplicate logical mutations were created.
  - `test_stress_server_restart_persistence_and_sequence_continuity`: Booted on-disk SQLite database, committed mutations 1 and 2, terminated server connection, re-opened SQLite database in a new server instance, and verified sequence allocator continued monotonically (mutation 3 received sequence 3), idempotency cache survived restart, and change streams were intact.
  - `test_stress_mixed_concurrent_workload_no_duplicate_logical_mutations`: Launched 30 concurrent workers performing mixed updates and retries across 10 objects, verifying global invariant that total sequences allocated matched exact logical successes and no duplicate sequence numbers were issued.
- Quality gates: All 8 CI quality gates pass cleanly via `./scripts/ci.sh`.

---

## ZK-092 — Plaintext leakage test suite
Status: DONE  
Priority: P0  
Dependencies: M6

Scan/test:

- server DB;
- server logs;
- API captures;
- browser IndexedDB;
- native SQLite;
- crash/error messages.

Acceptance criteria:

No note title/body/tag plaintext in prohibited locations.

Implementation notes:
- Implemented comprehensive server and native client leakage test suite in `apps/server/tests/plaintext_leakage_tests.rs`:
  - Canary secrets injected across test fixtures: `CANARY_TITLE`, `CANARY_BODY`, `CANARY_TAG_1`, `CANARY_TAG_2`, `CANARY_ATTACHMENT_NAME`, `CANARY_ATTACHMENT_MIME`, `CANARY_ATTACHMENT_DATA`, and `CANARY_PASSPHRASE`.
  - Audited Server DB: Scanned every row, column, text field, and BLOB across all tables (`accounts`, `vault_roots`, `sync_objects`, `object_history`, `blobs`, `devices`, `sessions`), followed by a raw binary byte scan of the SQLite `.sqlite` database file on disk.
  - Audited Server Application Logs: In-memory tracing subscriber capturing all log records emitted during vault bootstrap, note creation, blob upload/download, and sync pull. Verified zero canary matches.
  - Audited Full API Captures: Captured HTTP request/response URLs, headers, and bodies across `/v1/vault/bootstrap`, `/v1/sync/push`, `/v1/blobs/{id}`, and `/v1/sync/changes`. Verified zero canary leakage.
  - Audited Native Client SQLite Persistence: Created and mutated encrypted notes with `zk-storage::SqliteStorage` (verifying `objects`, `base_versions`, `pending_mutations`, `conflicts`), and scanned both table contents and raw disk bytes of the `.sqlite` file.
  - Audited Crash/Error Responses: Tested HTTP 409 Conflict, HTTP 400 Bad Request with malformed JSON containing canaries, HTTP 404 Object Not Found, and HTTP 404 Missing Blob. Verified error payloads never reflect canary plaintext.
- Implemented browser-side leakage test suite in `apps/web/test/plaintext-leakage.test.ts`:
  - IndexedDB Audit: Populated all 6 object stores (`objects`, `base_versions`, `mutations`, `conflicts`, `blobs`, `sync_state`) and inspected raw serialized store entries via direct IndexedDB transactions, verifying 0 canary occurrences.
  - Network Payloads: Verified that client-side `PushRequest` and blob requests contain no forbidden properties (`title`, `body`, `tags`, `passphrase`, `filename`, `mime_type`).
  - Error Reporting: Verified that client error formatting sanitizes note contexts and never leaks titles, bodies, or passphrases.
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-093 — Dependency and supply-chain audit
Status: DONE  
Priority: P0  
Dependencies: M8

Acceptance criteria:

- Rust audit tooling;
- npm audit/review;
- vulnerable dependency policy;
- lockfiles present;
- crypto dependencies manually reviewed.

Implementation notes:
- Audited all workspace dependencies using `cargo-audit` against the RustSec Advisory Database (scanned 191 crates, 0 vulnerabilities found).
- Audited web dependencies via `npm audit --audit-level=moderate` (scanned all dependencies, 0 vulnerabilities found).
- Authored formal policy and audit report in `docs/threat-model/dependency-audit.md`:
  - Defined vulnerability remediation SLA (Critical within 24h, High within 72h, Medium/Low within 14 days).
  - Reviewed and documented all cryptographic dependencies (`chacha20poly1305`, `argon2`, `blake2`, `zeroize`, `rand_core`/`getrandom`, `subtle`, `base64ct`), confirming verified RustCrypto implementations, constant-time guarantees, memory zeroization on drop, and 192-bit nonce collision resistance.
  - Verified lockfile presence (`Cargo.lock` and `apps/web/package-lock.json`) and committed state.
  - Verified supply-chain hardening: zero external runtime CDN scripts, zero trackers/analytics, and root `#![forbid(unsafe_code)]`.
- Created automated audit script `scripts/audit.sh` and wired it into CI gate 9 in `scripts/ci.sh`.
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-094 — Browser XSS/CSP security review
Status: DONE  
Priority: P0  
Dependencies: ZK-069

Acceptance criteria:

- CSP tested;
- dangerous HTML rendering inventory;
- Markdown renderer sanitization;
- no third-party origin script execution.

Implementation notes:
- Hardened `apps/web/src/utils/markdown.ts`:
  - Enforced strict character validation in `sanitizeUrl` rejecting whitespace, quotes, angle brackets, backslashes, and control characters to prevent HTML attribute breakout.
  - Applied `escapeHtml` to link `href` attributes as defense-in-depth.
- Created `apps/web/test/xss-csp-review.test.ts` implementing a comprehensive penetration suite:
  - Validated raw `<script>` tags across casing and nested structures are escaped to `&lt;`.
  - Validated HTML event handlers (`onload`, `onerror`, `onfocus`, etc.) and object/iframe embeds are neutralized.
  - Validated dangerous link URI schemes (`javascript:`, `vbscript:`, `data:`, `file:`, obfuscated control chars) are neutralized to `#`.
  - Validated attribute breakout payloads (`" onclick="alert(1)"`) are neutralized.
  - Validated safe Markdown formatting and links remain fully operational with `rel="noopener noreferrer"`.
  - Validated CSP directives in `index.html` as well as Nginx and Caddy deployment templates.
- Authored detailed security review in `docs/threat-model/web-security-review.md`:
  - Detailed Content Security Policy directive rationale and exfiltration mitigations (`connect-src 'self'`).
  - Audited and documented dangerous HTML rendering sink inventory across all components.
  - Documented browser hardening headers (`nosniff`, `DENY`, `no-referrer`, `COOP/COEP`).
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-095 — Authorization penetration tests
Status: DONE  
Priority: P0  
Dependencies: M7

Acceptance criteria:

- IDOR attempts;
- cross-account object guesses;
- blob access;
- history access;
- revoked credential tests.

Implementation notes:
- Implemented comprehensive penetration test suite in `apps/server/tests/authorization_penetration_tests.rs`:
  - IDOR Mutation & Deletion: Verified that Account B attempting to update or delete Account A's object returns HTTP 404 (`ERROR_OBJECT_NOT_FOUND`) without leaking object existence, leaving Account A's object revision and content intact.
  - Cross-Account Object Guesses: Probed with 20 randomly generated UUIDs under CAS updates; all returned HTTP 404 without timing side-channels.
  - Ciphertext Blob IDOR: Account A uploaded a blob; Account B's GET and HEAD requests returned HTTP 404. Account B uploading under the identical blob ID created an isolated record without corrupting or overwriting Account A's blob data.
  - History & Sync Stream Isolation: Verified that Account B pulling `/v1/sync/changes` receives strictly Account B's mutations, completely isolating Account A's mutations.
  - Revoked Session Credentials: Explicitly revoked an active session token via `db.revoke_session` and verified that subsequent requests to all protected endpoints (`/v1/sync/changes`, `/v1/devices`, `/v1/auth/session/status`, `/v1/blobs/*`) fail immediately with HTTP 401 Unauthorized.
  - Revoked Device Credentials: Created a second session and revoked the entire device via `DELETE /v1/devices/{id}`; verified all sessions bound to that device are immediately rejected with HTTP 401 Unauthorized (`ERROR_DEVICE_REVOKED`).
  - Forged / Malformed Tokens: Tested missing tokens, wrong auth schemes (`Basic`), non-session tokens, SQL injection strings, and forged JWT structures; all fail closed with HTTP 401 Unauthorized.
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-096 — Backup/restore test
Status: DONE  
Priority: P1  
Dependencies: M7

Acceptance criteria:

- restore server DB from backup;
- server still contains ciphertext only;
- fresh authorized client can sync and decrypt with user-held secrets.

Implementation notes:
- Implemented end-to-end database backup and restoration test suite in `apps/server/tests/backup_restore_tests.rs`:
  - Database Backup: Initialized an on-disk SQLite server instance, bootstrapped a user vault with Argon2id KDF and wrapped VaultKey, and populated active notes, multi-revision updates, tombstone deletions, and encrypted blob attachments. Generated a transactionally consistent online backup snapshot via `VACUUM INTO`.
  - Zero-Knowledge Backup Audit: Audited every table and row in the backup SQLite database file, as well as the raw disk bytes. Confirmed zero occurrences of note titles, bodies, tags, attachment plaintexts, or vault passphrases (SEC-001, SEC-002).
  - Server Restoration: Restored the backup file into a completely separate, fresh server instance.
  - Client Decryption: A fresh client connected to the restored server, fetched the vault bootstrap, derived the KEK from user-held passphrase, unwrapped the VaultKey, pulled sync changes, and decrypted all notes:
    - Note 1 decrypted with verified title, body, and tags.
    - Note 2 decrypted with verified latest Revision 2 update.
    - Note 3 verified as an un-resurrected deletion tombstone (Revision 2).
    - Downloaded and decrypted the ciphertext blob chunk, verifying original document plaintext.
  - Operational Continuity: Verified the restored server continues compare-and-swap (CAS) push mutations and monotonic sequence allocations for new client notes without regression or sequence collisions.
- Updated `apps/server/src/routes/sync.rs` to accept `after`, `since`, and `cursor` query parameters interchangeably for cursor synchronization.
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-097 — Threat model review
Status: DONE  
Priority: P0  
Dependencies: ZK-092, ZK-094, ZK-095

Acceptance criteria:

- `docs/threat-model/` updated;
- known residual risks listed;
- web-origin trust limitation clearly documented.

Implementation notes:
- Authored comprehensive application threat model review in `docs/threat-model/threat-model-review.md`:
  - Detailed system trust boundaries across passive eavesdroppers, compromised server/cloud operators, malicious multi-tenant peers, and local multi-user workstations.
  - Formally analyzed and documented the **Web-Origin Trust Limitation** (the fundamental web crypto delivery paradox): analyzed risks of compromised server origins serving malicious JavaScript, detailed mitigations (strict CSP, COOP/COEP, Web Worker key isolation, no third-party scripts), and documented high-assurance guidance recommending compiled/signed native CLI (`zk-note`) or self-hosted origins.
  - Documented known residual risks: traffic analysis/metadata leakage, volatile RAM remanence across JS/WASM runtimes, browser extension attacks, and offline dictionary exhaustion against weak user passphrases.
  - Created a complete mapping matrix connecting invariants SEC-001 through SEC-010 to concrete automated test suites.
- Created `docs/threat-model/README.md` indexing all security reviews and threat model documentation.
- All gates verified clean via `./scripts/ci.sh`.

---

## ZK-098 — External security review preparation
Status: DONE  
Priority: P1  
Dependencies: ZK-097

Acceptance criteria:

Prepare:

- architecture diagram;
- protocol doc;
- crypto ADR;
- threat model;
- test commands;
- reproducible demo accounts/data;
- list of security claims.

Completion notes:
- Authored comprehensive external security review package in `docs/security-review-package.md`:
  - System architecture Mermaid diagram documenting trust boundaries, Web Worker RPC isolation, native CLI core, untrusted network TLS boundary, and server CAS engine.
  - Links to wire protocol specification (`docs/protocol/v1.md`), Web Worker API spec (`docs/protocol/worker-api.md`), cryptographic architecture ADR (`docs/adr/0003-cryptographic-architecture.md`), CLI editor security review (`docs/threat-model/cli-editor-security.md`), web security review (`docs/threat-model/web-security-review.md`), dependency audit (`docs/threat-model/dependency-audit.md`), and comprehensive threat model review (`docs/threat-model/threat-model-review.md`).
  - Cataloged 7 formal verified security claims (`CLAIM-01` through `CLAIM-07`) mapping to invariants `SEC-001` through `SEC-010` and their corresponding test suites.
  - Detailed auditor verification commands covering full repository CI gate (`./scripts/ci.sh`) and targeted test suites for plaintext leakage, concurrency stress, protocol properties, authorization penetration, backup/restore, browser XSS/CSP, and IndexedDB storage audits.
  - Documented reproducible demo credentials, Argon2id KDF parameters, recovery key formats, and cross-runtime test vectors (`crates/zk-crypto/tests/test_vectors.rs` and `tests/wasm_crypto_compat.test.mjs`).
- Verified via `./scripts/ci.sh`.

---

## ZK-099 — Release candidate gate
Status: DONE  
Priority: P0  
Dependencies: all required P0/P1 V1 tasks

Acceptance criteria:

- all P0 V1 tasks DONE;
- selected P1 V1 tasks DONE;
- full CI green;
- two-client offline conflict demo passes;
- recovery demo passes;
- no prohibited plaintext leakage found;
- release notes include known limitations.

Completion notes:
- Verified all P0 and P1 V1 tasks across Milestone 0 through Milestone 9 are marked `DONE` with 0 remaining tasks.
- Created dedicated Release Candidate verification test suite in `apps/server/tests/release_candidate_tests.rs`:
  - `test_rc_two_client_offline_conflict_demo`: Spun up live HTTP sync server and two independent client instances with isolated SQLite databases. Demonstrated initial note creation, sync, concurrent offline editing based on the same revision, CAS rejection of stale edit (`409 Conflict`), local conflict preservation of base/local/remote envelopes, 3-way merge resolution, re-encryption, push, and remote convergence. Audited raw server SQLite bytes to guarantee zero plaintext leakage.
  - `test_rc_recovery_lifecycle_demo`: Demonstrated full vault initialization with Argon2id master passphrase and 288-bit formatted `RecoveryKey`, note creation and encryption, simulated passphrase loss (wrong passphrase fails closed), vault unlock using recovery key, rotation to a new master passphrase, verification that old passphrase fails closed, new passphrase unlocks successfully, and 100% data integrity across all notes (zero data loss).
- Created executable demonstration runner `scripts/demo_rc.sh` allowing automated one-step verification (`./scripts/demo_rc.sh`).
- Verified zero prohibited plaintext leakage across server database, server logs, network captures, native client SQLite files, and browser IndexedDB stores via `apps/server/tests/plaintext_leakage_tests.rs` and `apps/web/test/plaintext-leakage.test.ts`.
- Authored release notes in `docs/release-notes-v1.0.0-rc1.md` documenting architecture, security guarantees, test suite results, deployment instructions, and known limitations / residual risks (Web crypto delivery paradox / origin trust limitation, workstation endpoint compromise boundaries, traffic analysis/metadata side-channels, weak passphrase offline exhaustion, and forward secrecy boundaries).
- Successfully executed full 9-gate repository CI gate (`./scripts/ci.sh`) with 100% passing checks.

---

# Suggested first execution sequence for an AI agent

Start exactly here:

```text
ZK-001
ZK-002
ZK-003
ZK-004
ZK-005
ZK-006
M0 gate

ZK-010
ZK-011
ZK-012
ZK-013
ZK-014
ZK-015
ZK-016
ZK-017
ZK-018
M1 gate

ZK-020
...
```

Do not parallelize the first cryptographic tasks across agents unless protocol types and crypto ADRs are already frozen.

---

# Recommended AI-agent prompt pattern

Use:

```text
Read AGENTS.md, MASTER_SPEC.md, and TASKS.md.

Implement task ZK-XXX only.

Before coding:
- inspect existing code and dependencies;
- restate the relevant invariants internally;
- do not redesign unrelated components.

During implementation:
- satisfy every acceptance criterion;
- add appropriate tests;
- preserve backward compatibility for durable formats.

Before finishing:
- run relevant quality gates;
- update TASKS.md with status and a short implementation note;
- report files changed, tests run, and remaining risks.

Do not start another task.
```

This gives the coding agent a bounded objective and prevents "helpful" architecture drift.

---

# Sprint interpretation

If a human wants Scrum-like grouping, use these milestones as sprint goals rather than fixed-duration sprints:

```text
Sprint 0 → M0 repository/protocol
Sprint 1 → M1 crypto
Sprint 2 → M2 local CLI
Sprint 3 → M3 server
Sprint 4 → M4 sync
Sprint 5 → M5 conflicts
Sprint 6 → M6 web
Sprint 7 → M7 recovery/auth
Sprint 8 → M8 attachments
Sprint 9 → M9 security/release
```

Do not force a sprint to finish on a calendar date if its security/correctness gate is red.

For this project, milestone correctness is more important than Scrum velocity.
