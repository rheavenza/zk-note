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
Status: TODO  
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

---

## ZK-054 — CLI conflict commands
Status: TODO  
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

---

## ZK-055 — Guarded LWW policy option
Status: TODO  
Priority: P2  
Dependencies: ZK-053, ZK-028

Acceptance criteria:

- optional policy documented;
- selected visible head may use LWW;
- losing revision always recoverable;
- CAS remains enforced.

Do not enable by default in V1 without explicit product decision.

---

## ZK-056 — Delete-vs-edit conflict
Status: TODO  
Priority: P0  
Dependencies: ZK-053, ZK-037

Acceptance criteria:

- stale edit cannot resurrect deleted note;
- conflict UX distinguishes deletion;
- user can explicitly restore as new/current revision.

---

## ZK-057 — Conflict integration matrix
Status: TODO  
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

---

### M5 Gate

Two clients edit the same revision offline.

After synchronization:

- server does not overwrite silently;
- both contents remain recoverable;
- client resolves and produces a new accepted revision.

---

# M6 — Web/WASM client

Goal: reuse the proven core in the browser.

## ZK-060 — WASM build for shared core
Status: TODO  
Priority: P0  
Dependencies: M5

Acceptance criteria:

- crypto/core compiles for browser target;
- narrow typed JS boundary;
- no raw Vault Key exposure to React APIs where avoidable.

---

## ZK-061 — Native/WASM crypto compatibility suite
Status: TODO  
Priority: P0  
Dependencies: ZK-060

Acceptance criteria:

- native encrypt → WASM decrypt;
- WASM encrypt → native decrypt;
- vault wrapper compatibility;
- failure vectors match.

---

## ZK-062 — Web Worker boundary
Status: TODO  
Priority: P0  
Dependencies: ZK-060

Acceptance criteria:

- crypto/decrypt/search/sync heavy operations run in worker where practical;
- React does not own persistent key state;
- message API documented.

---

## ZK-063 — IndexedDB encrypted adapter
Status: TODO  
Priority: P0  
Dependencies: ZK-021, ZK-060

Acceptance criteria:

- same storage semantics as native adapter;
- note ciphertext persists;
- pending queue/cursor persists;
- browser storage inspection reveals no plaintext note content.

---

## ZK-064 — Unlock screen
Status: TODO  
Priority: P0  
Dependencies: ZK-062, ZK-063

Acceptance criteria:

- passphrase remains client-side;
- clear locked/unlocked states;
- failure does not reveal sensitive detail.

---

## ZK-065 — Notes list/editor
Status: TODO  
Priority: P1  
Dependencies: ZK-064

Acceptance criteria:

- create/edit/delete;
- Markdown source editor;
- autosave to encrypted local state;
- offline operation.

---

## ZK-066 — Web search
Status: TODO  
Priority: P1  
Dependencies: ZK-065

Acceptance criteria:

- in-memory local search;
- no server query;
- lock clears searchable plaintext state.

---

## ZK-067 — Web sync status
Status: TODO  
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

---

## ZK-068 — Web conflict resolver
Status: TODO  
Priority: P0  
Dependencies: ZK-053, ZK-065

Acceptance criteria:

- compare local/remote;
- use merge candidate;
- manual resolution;
- preserve-both action.

---

## ZK-069 — Browser security headers/CSP
Status: TODO  
Priority: P0  
Dependencies: ZK-065

Acceptance criteria:

- restrictive CSP;
- no third-party runtime script requirement;
- no inline unsafe script unless explicitly justified;
- clickjacking/content-type hardening;
- deployment documentation.

---

### M6 Gate

Same account can:

```text
CLI create → sync → web pull/decrypt
web edit offline → sync
CLI pull/decrypt
```

Native/WASM compatibility suite must pass.

---

# M7 — Authentication, recovery, and device security

## ZK-070 — Authentication abstraction
Status: TODO  
Priority: P0  
Dependencies: M3

Acceptance criteria:

- server auth independent of vault passphrase;
- access tokens never logged;
- auth middleware owns account identity.

---

## ZK-071 — Passkey/WebAuthn web auth
Status: TODO  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- register;
- sign in;
- revoke session;
- no vault passphrase reuse.

---

## ZK-072 — CLI login/device authorization
Status: TODO  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- secure account authorization flow;
- token persistence uses platform secure storage where possible;
- revocation supported.

---

## ZK-073 — Recovery UX
Status: TODO  
Priority: P0  
Dependencies: ZK-013, M6

Acceptance criteria:

- recovery key displayed/exported safely;
- user warned server cannot recover lost key;
- recovery flow restores Vault Key;
- new passphrase can be set.

---

## ZK-074 — Password change UX
Status: TODO  
Priority: P1  
Dependencies: ZK-017

Acceptance criteria:

- rewrap only;
- old object ciphertext unchanged;
- recovery wrapper remains valid unless intentionally rotated.

---

## ZK-075 — Device list/revoke
Status: TODO  
Priority: P1  
Dependencies: ZK-070

Acceptance criteria:

- list authorized devices/sessions;
- revoke;
- revoked device cannot sync with invalidated credentials;
- encrypted data model unchanged.

---

## ZK-076 — Auto-lock policy
Status: TODO  
Priority: P1  
Dependencies: M6

Acceptance criteria:

- configurable idle lock;
- explicit lock;
- secret/plaintext in-memory state disposed best-effort.

---

# M8 — Encrypted attachments

## ZK-080 — Attachment cryptographic format
Status: TODO  
Priority: P0  
Dependencies: M1

Acceptance criteria:

- random Attachment Key;
- chunk format versioned;
- unique nonce per chunk;
- authenticated chunk index/attachment ID via AAD.

---

## ZK-081 — Chunked native encryption
Status: TODO  
Priority: P0  
Dependencies: ZK-080

Acceptance criteria:

- streaming/chunked operation;
- corrupted chunk fails;
- no need to buffer entire large file in memory.

---

## ZK-082 — Ciphertext blob server API
Status: TODO  
Priority: P1  
Dependencies: ZK-081

Acceptance criteria:

- opaque blob IDs;
- authorization;
- size quotas;
- no filename/MIME plaintext.

---

## ZK-083 — Attachment manifest integration
Status: TODO  
Priority: P1  
Dependencies: ZK-082

Acceptance criteria:

- name/MIME/size metadata encrypted;
- note references stable attachment ID;
- delete/update semantics defined.

---

## ZK-084 — Web attachment support
Status: TODO  
Priority: P1  
Dependencies: ZK-083, M6

Acceptance criteria:

- encrypt before upload;
- decrypt after download;
- progress shown;
- network sees ciphertext only.

---

# M9 — Hardening and release candidate

## ZK-090 — Protocol property tests
Status: TODO  
Priority: P0  
Dependencies: M8

Acceptance criteria:

- random object/revision sequences;
- no invalid silent state transitions;
- idempotency property;
- cursor monotonicity property.

---

## ZK-091 — Concurrency stress suite
Status: TODO  
Priority: P0  
Dependencies: M5

Acceptance criteria:

- concurrent writers;
- duplicate mutation races;
- server restart;
- network retry;
- no duplicate accepted logical mutation.

---

## ZK-092 — Plaintext leakage test suite
Status: TODO  
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

---

## ZK-093 — Dependency and supply-chain audit
Status: TODO  
Priority: P0  
Dependencies: M8

Acceptance criteria:

- Rust audit tooling;
- npm audit/review;
- vulnerable dependency policy;
- lockfiles present;
- crypto dependencies manually reviewed.

---

## ZK-094 — Browser XSS/CSP security review
Status: TODO  
Priority: P0  
Dependencies: ZK-069

Acceptance criteria:

- CSP tested;
- dangerous HTML rendering inventory;
- Markdown renderer sanitization;
- no third-party origin script execution.

---

## ZK-095 — Authorization penetration tests
Status: TODO  
Priority: P0  
Dependencies: M7

Acceptance criteria:

- IDOR attempts;
- cross-account object guesses;
- blob access;
- history access;
- revoked credential tests.

---

## ZK-096 — Backup/restore test
Status: TODO  
Priority: P1  
Dependencies: M7

Acceptance criteria:

- restore server DB from backup;
- server still contains ciphertext only;
- fresh authorized client can sync and decrypt with user-held secrets.

---

## ZK-097 — Threat model review
Status: TODO  
Priority: P0  
Dependencies: ZK-092, ZK-094, ZK-095

Acceptance criteria:

- `docs/threat-model/` updated;
- known residual risks listed;
- web-origin trust limitation clearly documented.

---

## ZK-098 — External security review preparation
Status: TODO  
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

---

## ZK-099 — Release candidate gate
Status: TODO  
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
