# AGENTS.md

## Purpose

This repository implements a zero-knowledge, offline-first note-taking application with:

- end-to-end client-side encryption;
- a server that stores only ciphertext and minimal sync metadata;
- a shared Rust client core;
- a terminal client;
- a web client using the shared core through WebAssembly;
- guarded synchronization that prevents silent overwrite of stale offline edits.

This file defines the operating rules for any AI coding agent working in the repository.

---

## 1. Source of truth

Before changing code, read these files in order:

1. `AGENTS.md`
2. `MASTER_SPEC.md`
3. `TASKS.md`
4. any README or ADR relevant to the component being changed.

Priority when instructions conflict:

1. security invariants in `MASTER_SPEC.md`;
2. explicit acceptance criteria in the current task;
3. architecture decisions in `MASTER_SPEC.md`;
4. repository conventions;
5. implementation convenience.

Do not silently change an invariant or architecture decision. If a task appears to require doing so, stop that task and record the conflict in `TASKS.md` under `BLOCKED / SPEC QUESTION`.

---

## 2. Agent execution model

Work on exactly one task ID at a time unless the current task explicitly requires multiple tightly coupled changes.

For each task:

1. Read the task, dependencies, acceptance criteria, and relevant spec sections.
2. Inspect existing code before proposing structure.
3. Make the smallest coherent implementation.
4. Add or update tests.
5. Run the required checks.
6. Fix failures caused by the change.
7. Update task status and implementation notes in `TASKS.md`.
8. Summarize:
   - files changed;
   - behavior implemented;
   - tests run;
   - any unresolved risks or follow-up work.

Do not begin the next task automatically if the current task is blocked or if a quality gate fails.

---

## 3. Absolute security rules

These are non-negotiable.

### SEC-001 — plaintext never crosses the network

Note plaintext, note titles, tags, attachment filenames, attachment MIME metadata, search terms associated with stored note content, Vault Keys, Note Keys, Attachment Keys, and derived plaintext indexes MUST NOT be transmitted to the application server.

Authentication traffic is separate and may contain normal authentication metadata.

### SEC-002 — server cannot decrypt user content

The server MUST NOT possess:

- Vault Keys;
- Note Keys;
- Attachment Keys;
- vault passphrases;
- password-derived Key Encryption Keys;
- plaintext note bodies;
- plaintext note metadata.

### SEC-003 — no secrets in logs

Never log:

- passphrases;
- decrypted keys;
- plaintext notes;
- plaintext attachment metadata;
- decrypted search indexes;
- full authorization tokens;
- recovery keys.

Use redacted identifiers where diagnostics are necessary.

### SEC-004 — authenticated encryption only

Application content encryption MUST use the cipher suite defined in `MASTER_SPEC.md`.

Do not replace the crypto suite, KDF, key sizes, envelope format, or nonce strategy without an explicit spec task.

### SEC-005 — nonce uniqueness

Never reuse a nonce with the same key.

Use cryptographically secure random generation or the explicitly specified nonce derivation scheme.

### SEC-006 — conflict safety

The server MUST NOT silently overwrite an object when the caller's `expected_revision` differs from the current revision.

All mutable object writes use compare-and-swap semantics.

### SEC-007 — retry safety

Every client mutation MUST have an idempotency identifier.

Retrying the exact same accepted mutation must not create another revision.

### SEC-008 — deletion safety

Deletions are revisioned tombstones. Stale clients must not be able to resurrect deleted objects without an explicit conflict-resolution path.

### SEC-009 — local persistence is encrypted

Persistent local note caches MUST store encrypted content.

Plaintext may exist only in process memory while the vault is unlocked, except for deliberate user exports.

### SEC-010 — cryptographic errors fail closed

Authentication/decryption failures MUST produce an error.

Never return partially decrypted data, substitute empty plaintext, or attempt to "recover" corrupted ciphertext silently.

---

## 4. Do not improvise cryptography

Do not:

- invent custom ciphers;
- use XOR encryption;
- use AES-CBC without authenticated composition;
- encrypt directly with the user's password;
- use timestamps as nonces;
- reuse one long-lived content key for every purpose;
- serialize keys to application logs;
- downgrade KDF parameters for test convenience in production code paths.

Tests may use faster explicit test parameters if they are clearly isolated behind test-only APIs.

---

## 5. Architecture boundaries

The shared Rust core owns:

- key derivation and wrapping;
- envelope encryption/decryption;
- note serialization;
- local note model;
- mutation model;
- sync state machine;
- conflict detection;
- three-way merge logic;
- tombstone semantics;
- local search abstraction;
- protocol models shared with clients.

The web UI owns:

- presentation;
- user interaction;
- browser storage adapters;
- browser/network adapters;
- Web Worker orchestration.

The CLI/TUI owns:

- terminal presentation;
- command parsing;
- editor integration;
- native storage/network adapters.

The server owns:

- account authentication;
- authorization;
- opaque encrypted-object persistence;
- compare-and-swap revision checks;
- idempotency;
- sync sequence allocation;
- device/session metadata;
- quotas/rate limits;
- ciphertext attachment storage.

The server MUST NOT implement note merging, note search, tag filtering, Markdown parsing, plaintext conflict resolution, or note semantics.

---

## 6. Repository target structure

Use this structure unless a task explicitly changes it:

```text
/
├── AGENTS.md
├── MASTER_SPEC.md
├── TASKS.md
├── Cargo.toml
├── crates/
│   ├── zk-core/
│   ├── zk-crypto/
│   ├── zk-protocol/
│   ├── zk-storage/
│   └── zk-sync/
├── apps/
│   ├── cli/
│   ├── web/
│   └── server/
├── migrations/
├── docs/
│   ├── adr/
│   ├── protocol/
│   └── threat-model/
└── scripts/
```

Avoid cyclic dependencies between crates.

Preferred dependency direction:

```text
zk-protocol
   ↑
zk-crypto
   ↑
zk-core
   ↑
zk-sync
   ↑
app adapters
```

Exact boundaries may be refined, but crypto and protocol types must remain UI-independent.

---

## 7. Coding standards

### Rust

- stable Rust;
- `rustfmt`;
- `clippy` with warnings treated as errors in CI where practical;
- no `unsafe` unless justified in an ADR;
- prefer typed errors over stringly typed errors;
- never `unwrap()` on untrusted/runtime data in production paths;
- use `zeroize` or equivalent for key material where practical;
- use constant-time library primitives rather than handwritten equality for secrets.

### TypeScript

- strict TypeScript;
- no implicit `any`;
- no secret/key material in React component state if avoidable;
- crypto and bulk decryption should execute through the shared WASM core, preferably in a Web Worker;
- no third-party runtime scripts, analytics, tag managers, or ad SDKs.

### SQL

- migrations are append-only after merge;
- all object writes must preserve CAS semantics;
- uniqueness constraints must enforce idempotency where possible;
- indexes must support sync-by-sequence and object-by-owner lookup.

---

## 8. Tests required

Changes must include tests proportional to risk.

### Crypto tests

Must include:

- encrypt/decrypt round trip;
- wrong key fails;
- tampered ciphertext fails;
- tampered AAD fails;
- nonce length validation;
- envelope version rejection;
- cross-runtime test vectors where WASM/native parity matters.

### Sync tests

Must include:

- clean write;
- stale expected revision rejected;
- duplicate mutation is idempotent;
- two-device offline conflict;
- deletion tombstone conflict;
- pull cursor ordering;
- retry after lost response;
- conflict preservation.

### Server tests

Must include:

- cross-account access denial;
- CAS behavior;
- idempotency;
- monotonic sync sequence;
- tombstone persistence;
- pagination/cursor behavior;
- malformed payload handling.

### UI tests

Focus on:

- locked/unlocked state;
- no plaintext persisted accidentally;
- conflict UI state;
- recovery warnings;
- offline queue status.

---

## 9. Quality gates

Before marking a task complete, run the checks that exist for the touched subsystem.

Target repository-wide gates:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Web target:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Security-focused test suites must be runnable independently.

If a tool is not yet configured, create the missing setup only if it belongs to the current task; otherwise note it as follow-up.

---

## 10. Dependency policy

Prefer mature, actively maintained libraries.

For security-sensitive dependencies:

- minimize direct dependencies;
- pin reproducible versions through lockfiles;
- avoid abandoned crypto libraries;
- never copy cryptographic code from random snippets;
- record major crypto dependency choices in an ADR.

Do not add a dependency when a small standard-library implementation is safer and simpler, except for cryptographic functionality, where vetted libraries are preferred.

---

## 11. Protocol compatibility

Persisted encrypted data and server protocol data are versioned.

Never make an incompatible change to:

- encrypted envelopes;
- KDF parameter representation;
- wrapped-key representation;
- sync mutation format;
- tombstone semantics;
- cursor semantics;

without:

1. bumping the appropriate version;
2. adding migration/backward-read behavior where required;
3. adding compatibility tests;
4. documenting the change.

---

## 12. Definition of done

A task is DONE only when:

- acceptance criteria are satisfied;
- implementation compiles/builds;
- relevant tests pass;
- no known security invariant is violated;
- no plaintext content is introduced into server APIs/logging;
- documentation is updated when behavior or protocol changed;
- `TASKS.md` contains a short completion note.

"Code written" is not equivalent to DONE.

---

## 13. Commit guidance

Prefer one logical task per commit.

Suggested format:

```text
<type>(<area>): <TASK-ID> short description
```

Examples:

```text
feat(crypto): ZK-011 implement vault key wrapping
feat(sync): ZK-031 add CAS mutation handling
test(sync): ZK-034 cover lost-response idempotent retry
docs(spec): ZK-006 record envelope ADR
```

Do not claim a security property in a commit message unless tests/spec support it.

---

## 14. When blocked

Record:

```text
BLOCKED / SPEC QUESTION
Task:
Reason:
Relevant invariant/spec section:
Options:
Recommended option:
```

Do not resolve ambiguity by weakening security.

---

## 15. Agent behavior for large tasks

If a task appears larger than one coherent reviewable change:

1. split it into subtasks in `TASKS.md`;
2. preserve the original acceptance criteria;
3. establish dependencies;
4. implement the smallest prerequisite first.

Avoid broad "refactor everything" changes.

---

## 16. Project north star

The application should remain useful offline, resilient under multi-device edits, and incapable of exposing decrypted user content through ordinary server compromise.

When forced to choose between convenience and silent data loss, choose data preservation.

When forced to choose between convenience and server-side plaintext knowledge, choose zero knowledge.
