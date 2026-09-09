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
Status: TODO  
Priority: P0  
Dependencies: ZK-010, ZK-011

Acceptance criteria:

- random Vault Key generated;
- Vault Key wrapped by KEK using AEAD;
- unwrap returns identical key;
- wrong KEK fails closed;
- tampered wrapper fails closed.

---

## ZK-013 — Recovery Key wrapping
Status: TODO  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- random Recovery Key generated;
- same Vault Key independently wrapped;
- Recovery Key can restore Vault Key;
- wrong Recovery Key fails;
- recovery representation has checksum or typo-detection strategy documented.

---

## ZK-014 — Object Key wrapping
Status: TODO  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- per-object random key;
- wrapped using Vault Key;
- object ID/kind bound via AAD according to protocol;
- tampered AAD fails.

---

## ZK-015 — Object payload encryption
Status: TODO  
Priority: P0  
Dependencies: ZK-014

Acceptance criteria:

- XChaCha20-Poly1305 encrypt/decrypt;
- random unique nonce per encryption;
- wrong Object Key fails;
- ciphertext tamper fails;
- unknown envelope version fails.

---

## ZK-016 — Encrypted envelope v1
Status: TODO  
Priority: P0  
Dependencies: ZK-014, ZK-015

Acceptance criteria:

- complete envelope type implemented;
- serialization round-trip;
- malformed input rejected;
- no secret values exposed through Debug/Display;
- compatibility test vector committed.

---

## ZK-017 — Vault password rewrap
Status: TODO  
Priority: P0  
Dependencies: ZK-012

Acceptance criteria:

- old passphrase unwraps Vault Key;
- new passphrase derives new KEK;
- Vault Key identity stays unchanged;
- existing object ciphertext remains unchanged.

---

## ZK-018 — Crypto negative/fuzz test harness
Status: TODO  
Priority: P1  
Dependencies: ZK-016

Acceptance criteria:

- malformed envelope corpus;
- truncated inputs;
- unknown versions;
- modified nonce/ciphertext/AAD;
- no panic on untrusted envelope bytes.

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

Do not implement server persistence before M1 is green.

---

# M2 — Local-only encrypted CLI

Goal: prove the note model and encrypted persistence without networking.

## ZK-020 — Plaintext note model
Status: TODO  
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

---

## ZK-021 — Local storage traits
Status: TODO  
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

---

## ZK-022 — SQLite encrypted cache
Status: TODO  
Priority: P0  
Dependencies: ZK-021

Acceptance criteria:

- migrations exist;
- encrypted envelopes persisted;
- no plaintext title/body/tag columns;
- reopen preserves encrypted objects;
- tests inspect DB schema/content for plaintext leakage.

---

## ZK-023 — Vault init/unlock/lock CLI
Status: TODO  
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

---

## ZK-024 — Create/show/list local notes
Status: TODO  
Priority: P0  
Dependencies: ZK-020, ZK-023

Acceptance criteria:

- create encrypted note;
- show decrypts only while unlocked;
- list works using locally decrypted state while unlocked;
- database contains ciphertext only.

---

## ZK-025 — `$EDITOR` edit flow
Status: TODO  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- temporary edit handling documented;
- plaintext temp-file risk explicitly mitigated or clearly surfaced;
- updated note re-encrypted;
- editor failure does not corrupt prior note.

Security note:

Prefer secure temporary-file behavior. If plaintext temp files cannot be eliminated, document the native-client threat boundary and cleanup behavior.

---

## ZK-026 — Local delete/tombstone model
Status: TODO  
Priority: P0  
Dependencies: ZK-024

Acceptance criteria:

- delete becomes local tombstone state;
- deletion revision intent represented;
- history/base state remains available.

---

## ZK-027 — Local search
Status: TODO  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- title/body/tag search;
- search operates only while unlocked;
- persistent DB has no plaintext index;
- lock clears in-memory index.

---

## ZK-028 — Local history
Status: TODO  
Priority: P1  
Dependencies: ZK-024

Acceptance criteria:

- encrypted previous versions retained locally;
- history command can display selected revision while unlocked.

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
Status: TODO  
Priority: P0  
Dependencies: M0

Acceptance criteria:

- Axum server starts;
- configuration loading;
- health endpoint;
- structured logs with redaction policy.

---

## ZK-031 — PostgreSQL schema/migrations
Status: TODO  
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

---

## ZK-032 — Vault bootstrap API
Status: TODO  
Priority: P0  
Dependencies: ZK-031

Acceptance criteria:

- server stores only KDF params + wrapped keys;
- no passphrase API field;
- get/bootstrap round-trip;
- cross-account access denied.

---

## ZK-033 — Server sequence allocator
Status: TODO  
Priority: P0  
Dependencies: ZK-031

Acceptance criteria:

- monotonic per account;
- transactional;
- concurrency test proves uniqueness/order.

---

## ZK-034 — CAS mutation endpoint
Status: TODO  
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

---

## ZK-035 — Mutation idempotency
Status: TODO  
Priority: P0  
Dependencies: ZK-034

Acceptance criteria:

- same mutation ID/same request returns original result;
- no additional revision/server sequence;
- same mutation ID with incompatible payload returns explicit replay mismatch error;
- concurrency test for duplicate simultaneous retries.

---

## ZK-036 — Pull changes endpoint
Status: TODO  
Priority: P0  
Dependencies: ZK-033, ZK-034

Acceptance criteria:

- ordered `server_seq`;
- pagination;
- cursor semantics documented;
- tombstones included;
- no missed rows under concurrent writes.

---

## ZK-037 — Tombstone persistence server-side
Status: TODO  
Priority: P0  
Dependencies: ZK-034

Acceptance criteria:

- delete mutation is revisioned;
- stale edit against tombstone conflicts;
- deleted object remains sync-visible.

---

## ZK-038 — Authorization isolation tests
Status: TODO  
Priority: P0  
Dependencies: ZK-032, ZK-036

Acceptance criteria:

- account A cannot fetch/mutate B objects;
- guessed object IDs do not bypass ownership;
- history access isolated.

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
Status: TODO  
Priority: P0  
Dependencies: M3

Acceptance criteria:

- protocol models shared from `zk-protocol`;
- authenticated requests abstracted;
- network errors typed;
- no plaintext payload fields.

---

## ZK-041 — Pending mutation queue
Status: TODO  
Priority: P0  
Dependencies: ZK-021, ZK-040

Acceptance criteria:

- local edits generate mutation IDs;
- mutations survive process restart;
- base revision recorded;
- mutation removed only after durable accepted result.

---

## ZK-042 — Durable sync cursor
Status: TODO  
Priority: P0  
Dependencies: ZK-021, ZK-036

Acceptance criteria:

- cursor advances only after local durable application;
- crash simulation does not skip remote changes.

---

## ZK-043 — Pull remote changes
Status: TODO  
Priority: P0  
Dependencies: ZK-040, ZK-042

Acceptance criteria:

- paginated pull;
- encrypted changes stored first;
- unlocked client can decrypt/apply;
- locked sync behavior explicitly defined.

Recommended V1 locked behavior:

Store remote ciphertext durably and defer plaintext reconciliation until unlock.

---

## ZK-044 — Push pending changes
Status: TODO  
Priority: P0  
Dependencies: ZK-041, ZK-043

Acceptance criteria:

- expected revision supplied;
- accepted writes clear queue;
- lost-response retry uses same mutation ID;
- conflict leaves local mutation recoverable.

---

## ZK-045 — Pull-before-push orchestration
Status: TODO  
Priority: P0  
Dependencies: ZK-043, ZK-044

Acceptance criteria:

- deterministic sync cycle;
- retryable network failure;
- final cursor consistent;
- no mutation silently dropped.

---

## ZK-046 — Two-client integration harness
Status: TODO  
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

---

### M4 Gate

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

No plaintext is present in server DB.

---

# M5 — Conflict resolution and guarded LWW

Goal: make multi-device offline conflicts safe and usable.

## ZK-050 — Persist encrypted BASE versions
Status: TODO  
Priority: P0  
Dependencies: ZK-041

Acceptance criteria:

- pending edit stores reference/base ciphertext;
- restart preserves merge capability;
- plaintext BASE is not persisted.

---

## ZK-051 — Structured three-way merge engine
Status: TODO  
Priority: P0  
Dependencies: ZK-020, ZK-050

Acceptance criteria:

- unchanged/local-only/remote-only field cases;
- identical concurrent changes;
- divergent scalar changes reported as conflict;
- deterministic tag merge.

---

## ZK-052 — Markdown body diff3
Status: TODO  
Priority: P0  
Dependencies: ZK-051

Acceptance criteria:

- non-overlapping edits auto-merge;
- overlapping edits become explicit conflict;
- no side silently discarded;
- deterministic tests.

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
