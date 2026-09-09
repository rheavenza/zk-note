# MASTER_SPEC.md

# Zero-Knowledge Notes — Master Technical Specification

Status: Draft v0.1  
Working repository name: `zk-notes`  
Primary implementation language: Rust  
Clients: terminal/CLI + web  
Server model: zero-knowledge ciphertext store + sync coordinator

---

# 1. Product statement

Build an offline-first note-taking application in which user content is encrypted locally before any network transmission.

The server stores unreadable ciphertext and minimal operational metadata required for synchronization, authentication, authorization, quotas, and device/session management.

The first production-capable release must support:

- vault creation and unlock;
- encrypted notes;
- Markdown body text;
- tags and title stored inside ciphertext;
- offline creation/edit/delete;
- encrypted local persistence;
- terminal client;
- web client;
- multi-device synchronization;
- guarded compare-and-swap updates;
- conflict preservation and client-side merge;
- tombstone deletion;
- local search;
- recovery key;
- encrypted history;
- basic device/session management.

Real-time multi-user collaboration is explicitly deferred.

---

# 2. Product principles

## P-001 Zero knowledge

The server must not be able to decrypt stored user content.

## P-002 Offline first

The client must remain useful without network connectivity.

## P-003 No silent data loss

A stale client write must never silently destroy a newer remote edit.

## P-004 Client owns semantics

The client understands notes, tags, search, merge behavior, and plaintext.

The server understands opaque encrypted objects and revisions.

## P-005 Version everything durable

Encrypted formats and sync protocol formats must be explicitly versioned.

## P-006 Conservative cryptography

Use established authenticated-encryption and password-KDF libraries. No custom primitive design.

---

# 3. Threat model

## 3.1 In scope

The design should protect note contents against:

- stolen server database;
- stolen server backups;
- stolen object-storage buckets;
- curious database operators;
- server administrators without control of an unlocked client;
- network observers;
- accidental server logging;
- cross-account server authorization bugs, to the extent application controls can prevent them.

## 3.2 Partially in scope

### Malicious application server

Native/CLI clients should remain resistant to a server attempting to infer plaintext, provided the signed client binary is trustworthy and cryptographic protocol checks remain intact.

The hosted web client has a weaker trust boundary because the server/CDN can potentially serve malicious JavaScript that steals secrets after unlock.

Mitigations:

- strict Content Security Policy;
- no third-party runtime JavaScript;
- no analytics/tag-manager scripts;
- Subresource Integrity where relevant;
- dependency pinning;
- reproducible/static build pipeline where practical;
- Web Worker isolation;
- optional self-hostable static web build;
- long-term possibility of signed desktop/native client.

Do not claim that a web deployment is cryptographically safe from a malicious origin operator.

## 3.3 Out of scope

The first release does not protect against:

- malware with access to the unlocked client;
- keyloggers;
- compromised operating systems;
- browser extensions with sufficient privileges;
- users revealing their recovery key/passphrase;
- shoulder surfing;
- attacks against deliberately exported plaintext files.

---

# 4. Identity, authentication, and encryption separation

Authentication answers:

> Is this requester allowed to access this account's ciphertext?

Encryption answers:

> Can this client decrypt the ciphertext?

These systems are independent.

Recommended server authentication:

- Passkey/WebAuthn for web;
- device/browser-assisted login or token provisioning for CLI;
- revocable short-lived access sessions;
- refresh/session material stored using platform-appropriate secure storage.

The vault passphrase is NOT the server account password.

The vault passphrase must never be transmitted to the server.

---

# 5. Cryptographic design

## 5.1 Algorithms

Initial cipher suite:

```text
KDF: Argon2id
Content AEAD: XChaCha20-Poly1305
Key sizes: 256 bits
XChaCha nonce: 192 bits
Random source: operating-system CSPRNG
```

Use a mature library compatible with libsodium behavior where practical.

All encrypted envelope formats carry a version and cipher-suite identifier.

## 5.2 Key hierarchy

```text
Vault Passphrase
      │
      ▼
   Argon2id
      │
      ▼
KEK (Key Encryption Key)
      │
      └──────── unwrap/wrap ────────┐
                                     ▼
                               Vault Key
                                  256-bit
                                     │
                   ┌─────────────────┼─────────────────┐
                   ▼                 ▼                 ▼
              Note Key A        Note Key B       Object Key N
                256-bit           256-bit           256-bit
                   │                 │                 │
                   ▼                 ▼                 ▼
             Note payload      Note payload      Other object
```

Each encrypted logical object receives a random Object Key.

Attachments receive independent Attachment Keys.

## 5.3 Vault creation

Client:

1. Generates random KDF salt.
2. Benchmarks/selects approved Argon2id parameters.
3. Derives KEK from vault passphrase.
4. Generates random 256-bit Vault Key.
5. AEAD-wraps Vault Key using KEK.
6. Generates Recovery Key.
7. Independently wraps Vault Key under the Recovery Key.
8. Persists only wrapped forms and KDF parameters.
9. Displays the Recovery Key exactly when required by product UX.

Server may store:

```json
{
  "crypto_version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<bytes>",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1
  },
  "wrapped_vault_key": {
    "cipher_suite": "xchacha20poly1305",
    "nonce": "<bytes>",
    "ciphertext": "<bytes>"
  },
  "recovery_wrapped_vault_key": {
    "cipher_suite": "xchacha20poly1305",
    "nonce": "<bytes>",
    "ciphertext": "<bytes>"
  }
}
```

Exact production Argon2 parameters may be calibrated by device. The encoded parameters are authoritative for future unlocks.

## 5.4 Password change

Changing the passphrase MUST NOT require decrypting and re-encrypting every note.

Process:

1. derive old KEK;
2. unwrap Vault Key;
3. derive new KEK;
4. create a new wrapped Vault Key envelope;
5. replace wrapped envelope after successful local verification.

## 5.5 Recovery

The user-controlled Recovery Key can unwrap the same Vault Key.

If both the vault passphrase and Recovery Key are lost, server-side recovery is impossible by design.

The UI must communicate this before vault creation completes.

## 5.6 Object encryption

Each object:

1. generate random Object Key;
2. serialize plaintext object using canonical application serialization;
3. encrypt plaintext with Object Key;
4. wrap Object Key using Vault Key;
5. upload both ciphertext envelopes.

Conceptual envelope:

```json
{
  "envelope_version": 1,
  "object_id": "uuid",
  "object_kind": 1,
  "wrapped_key": {
    "nonce": "<bytes>",
    "ciphertext": "<bytes>"
  },
  "payload": {
    "nonce": "<bytes>",
    "ciphertext": "<bytes>"
  }
}
```

Visible metadata authenticated as AAD should include at minimum:

```text
protocol/envelope version
account/vault identifier
object identifier
object kind
```

Revision is primarily a server synchronization field. If included in AAD, the exact interaction with client-side encryption and retries must be specified before implementation.

## 5.7 Plaintext note model

Initial plaintext note schema:

```json
{
  "schema_version": 1,
  "title": "string",
  "body": "markdown string",
  "tags": ["string"],
  "created_at": "client timestamp",
  "updated_at": "client timestamp",
  "attachments": []
}
```

The entire object is encrypted.

Do not expose title or tags to the server for indexing.

---

# 6. Metadata leakage policy

The first version accepts unavoidable/operational leakage of:

- account identifier;
- opaque random object identifiers;
- opaque object kind code if required by storage routing;
- object ciphertext byte length;
- per-object revision;
- global/per-account sync sequence;
- server receive/update timestamps;
- deletion/tombstone state;
- device/session identifiers;
- request timing and IP metadata inherent to network service.

The server must not receive plaintext:

- titles;
- note bodies;
- tags;
- attachment names;
- attachment MIME type;
- notebook names;
- search index;
- conflict text.

Future padding or metadata-hiding schemes are optional enhancements.

---

# 7. Durable encrypted object model

The server treats user data as opaque objects.

Initial kinds:

```text
1 = NOTE
2 = NOTEBOOK
3 = USER_SETTINGS
4 = ATTACHMENT_MANIFEST
5 = RESERVED
```

Object kind codes are protocol values and must not be repurposed.

A note's title/body/tags remain encrypted.

---

# 8. Server data model

Illustrative PostgreSQL schema:

```sql
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL
);

CREATE TABLE vaults (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    crypto_version INTEGER NOT NULL,
    kdf_algorithm TEXT NOT NULL,
    kdf_params JSONB NOT NULL,
    kdf_salt BYTEA NOT NULL,
    wrapped_vault_key BYTEA NOT NULL,
    recovery_wrapped_vault_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE encrypted_objects (
    account_id UUID NOT NULL REFERENCES accounts(id),
    object_id UUID NOT NULL,
    object_kind SMALLINT NOT NULL,
    revision BIGINT NOT NULL,
    server_seq BIGINT NOT NULL,
    envelope_version INTEGER NOT NULL,
    wrapped_key BYTEA NOT NULL,
    payload BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, object_id)
);

CREATE UNIQUE INDEX encrypted_objects_account_seq_idx
ON encrypted_objects(account_id, server_seq);

CREATE TABLE object_history (
    account_id UUID NOT NULL,
    object_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    server_seq BIGINT NOT NULL,
    envelope_version INTEGER NOT NULL,
    wrapped_key BYTEA NOT NULL,
    payload BYTEA NOT NULL,
    is_deleted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, object_id, revision)
);

CREATE TABLE processed_mutations (
    account_id UUID NOT NULL,
    mutation_id UUID NOT NULL,
    object_id UUID NOT NULL,
    resulting_revision BIGINT,
    resulting_server_seq BIGINT,
    response_body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, mutation_id)
);

CREATE TABLE devices (
    account_id UUID NOT NULL,
    device_id UUID NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ,
    last_ack_server_seq BIGINT NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (account_id, device_id)
);
```

Implementation may normalize encoded envelopes into nonce/ciphertext columns, but the server must not parse plaintext content.

Server sequence allocation must be monotonic per account. Transactional allocation is required.

---

# 9. Synchronization model

## 9.1 Terms

`object_id`  
Random stable identifier.

`revision`  
Monotonic revision number for one object.

`server_seq`  
Monotonic account-level sequence assigned to every accepted object mutation.

`expected_revision`  
Revision the client believes is current and upon which its mutation was based.

`mutation_id`  
Random unique ID identifying a logical mutation for idempotent retries.

`sync_cursor`  
Highest contiguous server sequence processed by a client.

## 9.2 Create

For a new object:

```text
expected_revision = 0
```

If object does not exist:

```text
result revision = 1
```

If the object already exists, reject as conflict unless the mutation is an idempotent replay.

## 9.3 Update compare-and-swap

Client submits:

```json
{
  "mutation_id": "uuid",
  "object_id": "uuid",
  "expected_revision": 7,
  "object_kind": 1,
  "envelope": "<opaque encrypted bytes>"
}
```

Server transaction:

1. check if mutation ID already processed;
2. if yes, return original result;
3. lock/read object row;
4. compare current revision to `expected_revision`;
5. if unequal, reject with conflict metadata/current ciphertext;
6. allocate next server sequence;
7. append previous/current state to history according to retention policy;
8. write new encrypted object;
9. increment revision;
10. persist processed mutation result;
11. commit.

## 9.4 Conflict response

Response includes enough encrypted/current metadata for client resolution:

```json
{
  "error": "revision_conflict",
  "object_id": "uuid",
  "expected_revision": 7,
  "current_revision": 8,
  "current_server_seq": 92,
  "current_envelope": "<opaque ciphertext>"
}
```

The server does not decide the winning note content.

## 9.5 Pull

```http
GET /v1/sync/changes?after=<server_seq>&limit=<n>
```

Returns ordered accepted mutations/current object versions after the supplied cursor.

Example:

```json
{
  "changes": [
    {
      "server_seq": 93,
      "object_id": "uuid",
      "revision": 5,
      "object_kind": 1,
      "is_deleted": false,
      "envelope": "..."
    }
  ],
  "next_cursor": 93,
  "has_more": false
}
```

Cursor advancement occurs only after local durable processing succeeds.

## 9.6 Pull-before-push strategy

Default sync cycle:

```text
1. load local durable cursor
2. PULL remote changes after cursor
3. durably store encrypted remote changes
4. decrypt/apply while unlocked
5. reconcile against local pending mutations
6. PUSH pending mutations
7. handle accepted/conflicted results
8. PULL once more if pushes produced remote-visible sequences
9. persist final cursor
```

Exact optimization can evolve, but correctness takes priority over fewer round trips.

## 9.7 Idempotency

A mutation ID represents one logical mutation.

If server accepted it but response was lost:

```text
retry same mutation_id
→ return same accepted result
→ do not increment revision again
```

Mutation-id retention must be long enough to cover realistic client retry/offline intervals. Initial implementation may retain indefinitely.

---

# 10. Conflict resolution

## 10.1 Required states

For an offline edit:

```text
BASE   = plaintext revision the user edited from
LOCAL  = local edited plaintext
REMOTE = newly fetched remote plaintext
```

The local client needs access to BASE to perform a three-way merge.

BASE may be retained as encrypted local history rather than plaintext on disk.

## 10.2 Field-aware merge

For structured note fields:

- field changed only locally → keep local;
- field changed only remotely → keep remote;
- identical local/remote change → keep change;
- divergent change to same scalar field → conflict;
- tags → set-based three-way merge where safe;
- attachment manifests → merge by stable attachment ID, otherwise conflict.

## 10.3 Markdown body merge

Use a deterministic three-way merge algorithm.

If non-overlapping edits can be merged, create a merged local candidate.

If overlapping edits cannot be resolved safely, do not discard either side.

Represent conflict in local client state and present:

- base;
- local;
- remote;
- optional generated merge candidate.

The user may choose local, remote, manual merged result, or duplicate-as-separate-note where supported.

## 10.4 Guarded LWW

If product UX later permits automatic last-write-wins:

- winner may become current visible head;
- losing revision must remain recoverable in encrypted history;
- server must still use CAS;
- LWW selection occurs client-side or as a deterministic opaque revision policy that does not inspect plaintext;
- no unrecoverable overwrite.

V1 default: preserve conflict and require deterministic auto-merge or explicit resolution.

---

# 11. Deletion model

Delete is a normal revisioned mutation producing a tombstone:

```text
is_deleted = true
```

Tombstones participate in revision checks and sync.

Example:

```text
Remote revision 9 = deleted
Stale offline client based on revision 7 = edited
```

The stale edit cannot overwrite revision 9.

It becomes a delete-vs-edit conflict requiring local resolution.

V1 tombstones may be retained indefinitely.

Future garbage collection requires proof that all relevant active devices have advanced beyond the tombstone plus a documented retention policy.

---

# 12. Local persistence

## 12.1 Native/CLI

Preferred storage:

```text
SQLite
```

Persistent note content remains encrypted.

Suggested tables:

```text
local_objects
pending_mutations
sync_state
encrypted_base_versions
device_state
```

The database may contain operational local metadata such as revision, server sequence, queue status, and random IDs.

## 12.2 Browser

Preferred storage:

```text
IndexedDB
```

Persistent cached note objects remain encrypted.

Plaintext decrypted notes/search indexes should reside in memory while unlocked.

Closing or locking the vault clears in-memory plaintext structures as best as the runtime permits.

---

# 13. Search

V1 search is client-side only.

After unlock:

```text
decrypt cached notes
→ build in-memory local index
→ search title/body/tags locally
```

No plaintext search query or search index is sent to the server.

Initial search implementation can be a simple normalized substring/token search.

Full-text indexing may later use a local-only engine.

---

# 14. Attachments

Deferred until core note sync is stable, but architecture is specified now.

Each attachment gets a random 256-bit Attachment Key.

Large attachments are chunked, e.g. target chunk size 4–16 MiB.

Each chunk uses authenticated encryption with a unique nonce.

Encrypted attachment manifest contains plaintext-only-to-client metadata:

```json
{
  "attachment_id": "uuid",
  "name": "image.png",
  "mime": "image/png",
  "size": 123456,
  "chunk_count": 3,
  "content_hash": "optional local integrity metadata"
}
```

The manifest itself is encrypted inside the parent note or as a dedicated encrypted object.

Server blob store sees opaque IDs, ciphertext chunks, and sizes.

The initial attachment API may use pre-signed upload/download URLs if the storage backend supports them, as long as no plaintext metadata is exposed.

---

# 15. Server API v1

Exact JSON/base64 encoding conventions must be documented in `docs/protocol/v1.md`.

Proposed endpoints:

```text
POST   /v1/auth/...
POST   /v1/vault/bootstrap
GET    /v1/vault/bootstrap
PUT    /v1/vault/wrapped-key

GET    /v1/sync/changes
POST   /v1/sync/push

GET    /v1/devices
DELETE /v1/devices/{device_id}

PUT    /v1/blobs/{blob_id}
GET    /v1/blobs/{blob_id}

GET    /v1/account
DELETE /v1/account
```

There should be no server endpoints such as:

```text
/search-notes
/notes-by-tag
/render-markdown
/merge-note
```

because those require semantic knowledge the server should not have.

---

# 16. Shared Rust core

Target crates:

## `zk-protocol`

Owns:

- protocol version constants;
- object kinds;
- sync request/response models;
- error codes;
- serialization compatibility.

## `zk-crypto`

Owns:

- secure random generation;
- KDF wrapper;
- KEK derivation;
- Vault Key wrapping;
- Recovery Key wrapping;
- Object Key generation;
- object envelope encryption/decryption;
- crypto version parsing;
- key zeroization wrappers.

## `zk-core`

Owns:

- plaintext note model;
- encrypted-object orchestration;
- vault lifecycle;
- note create/edit/delete transformations.

## `zk-sync`

Owns:

- pending mutation state machine;
- pull/push orchestration;
- conflict detection;
- three-way merge;
- cursor advancement rules.

## `zk-storage`

Defines traits for:

- encrypted object store;
- pending mutation store;
- base revision store;
- sync state store.

Native SQLite and browser IndexedDB implementations are adapters.

---

# 17. CLI specification

Initial commands:

```text
zk-note init
zk-note login
zk-note unlock
zk-note lock

zk-note new
zk-note edit <note-id>
zk-note show <note-id>
zk-note list
zk-note search <query>
zk-note tag <note-id> <tag>
zk-note delete <note-id>

zk-note sync
zk-note conflicts
zk-note resolve <conflict-id>
zk-note history <note-id>

zk-note device list
zk-note device revoke <device-id>
```

`edit` should support `$EDITOR`.

CLI should remain useful offline.

Commands that require unlock should fail with a clear locked-vault error rather than auto-requesting sensitive information through insecure mechanisms.

---

# 18. Web specification

Recommended stack:

```text
React + TypeScript
Rust shared core compiled to WASM
Web Worker for crypto/sync-heavy work
IndexedDB encrypted cache
```

The Vault Key should not be placed in global React state.

Suggested primary screens:

```text
Unlock
Notes list
Editor
Search
Conflict resolver
Trash/history
Devices
Security/recovery
Sync status
```

Security headers should include a strict CSP and other standard hardening appropriate to deployment.

No third-party runtime analytics in the application origin.

---

# 19. State machines

## 19.1 Vault

```text
UNINITIALIZED
    │ create/import
    ▼
LOCKED
    │ valid unlock
    ▼
UNLOCKED
    │ lock / timeout / app close
    ▼
LOCKED
```

## 19.2 Local object

```text
CLEAN
  │ edit
  ▼
DIRTY
  │ enqueue
  ▼
PENDING
  ├── accepted ──► CLEAN
  └── conflict ──► CONFLICT
                      │ resolve
                      ▼
                   PENDING
```

## 19.3 Sync engine

```text
IDLE
 → PULLING
 → APPLYING_REMOTE
 → RECONCILING
 → PUSHING
 → FINALIZING
 → IDLE
```

Failures return to a retryable state without losing queued mutations.

---

# 20. Error taxonomy

Stable protocol/client categories:

```text
AUTH_REQUIRED
AUTH_FORBIDDEN
VAULT_LOCKED
CRYPTO_UNSUPPORTED_VERSION
CRYPTO_AUTH_FAILED
INVALID_ENVELOPE
REVISION_CONFLICT
MUTATION_REPLAY_MISMATCH
OBJECT_NOT_FOUND
OBJECT_DELETED
SYNC_CURSOR_INVALID
RATE_LIMITED
NETWORK_UNAVAILABLE
LOCAL_STORAGE_FAILURE
SERVER_FAILURE
```

Never convert crypto authentication failure into a generic "empty note".

---

# 21. Observability

Server metrics may track:

- requests;
- latency;
- status/error categories;
- opaque object counts;
- ciphertext byte counts;
- sync lag;
- mutation conflict rate;
- authentication events.

Server observability must not contain plaintext content.

Client diagnostics should redact secret material and provide an explicit user-controlled export if debug logs are ever implemented.

---

# 22. Security and correctness test plan

## 22.1 Crypto properties

Required tests:

- round-trip object encryption;
- wrong Vault Key cannot unwrap Object Key;
- wrong Object Key cannot decrypt payload;
- ciphertext bit flip fails;
- nonce bit flip fails;
- AAD mutation fails;
- unknown crypto version rejected;
- password change preserves Vault Key identity;
- recovery key recovers same Vault Key;
- native/WASM compatibility vectors.

## 22.2 Sync concurrency

Model at least these scenarios:

### Scenario A — clean sequential edit

```text
A downloads r1
A writes → r2
B pulls r2
B writes → r3
```

No conflicts.

### Scenario B — two-device offline edit

```text
A and B download r5
A writes → server r6
B attempts expected r5
→ reject conflict
```

No silent overwrite.

### Scenario C — lost response

```text
A sends mutation M
server commits r6
response lost
A retries M
→ same r6 response
```

No r7 created.

### Scenario D — delete versus stale edit

```text
A deletes r9 → r10 tombstone
B edits based on r9
B push rejected
```

No resurrection.

### Scenario E — pull crash

```text
client fetches through seq 100
local durable write fails after seq 97
restart cursor remains 97
re-fetch 98..100
```

No missed updates.

### Scenario F — history preservation

Conflicting or superseded revisions remain decryptable according to retention policy.

---

# 23. Security review gates

Before any public release:

1. threat model review;
2. crypto design review;
3. dependency audit;
4. fuzz/negative testing of envelope parsing;
5. authorization testing;
6. concurrency testing under real PostgreSQL transactions;
7. browser CSP/XSS review;
8. secret/logging review;
9. backup/restore test using ciphertext only;
10. recovery-key UX test.

For a serious security product, obtain external cryptographic/application security review before claiming strong production security.

---

# 24. Non-goals for V1

Do not block V1 on:

- real-time collaborative editing;
- CRDT;
- shared team vaults;
- server-side encrypted search;
- rich-text WYSIWYG;
- mobile apps;
- browser extensions;
- public-note publishing;
- AI note processing;
- OCR;
- calendar/tasks integration.

Markdown notes plus reliable zero-knowledge sync is the goal.

---

# 25. Future architecture hooks

The design should not prevent:

- multi-recipient object-key wrapping for sharing;
- shared vaults;
- stronger native client attestation/update signing;
- CRDT-backed collaborative note bodies;
- object padding;
- encrypted full-text index synchronization;
- key rotation;
- attachment deduplication using privacy-preserving strategies.

Do not implement these until core sync correctness is proven.

---

# 26. Development strategy

Use milestone-driven incremental delivery.

Each milestone must leave the repository runnable and tested.

Recommended order:

```text
M0 repository + protocol foundations
M1 cryptographic core
M2 local-only CLI
M3 zero-knowledge server
M4 offline multi-device sync
M5 conflict resolution + history
M6 web/WASM client
M7 recovery/auth/device hardening
M8 attachments
M9 security hardening + release candidate
```

Do not begin the web UI before the core crypto, encrypted local persistence, and basic sync protocol are tested from the CLI.

The CLI is the reference client for correctness.

---

# 27. V1 acceptance criteria

V1 is ready for release-candidate security review when:

- two independent clients can create/edit/delete notes offline;
- all durable note content is encrypted locally;
- server database contains no note plaintext;
- stale writes receive conflicts rather than overwriting;
- duplicate mutation retries are idempotent;
- tombstones prevent stale resurrection;
- conflict resolution preserves both local and remote content;
- search works locally while unlocked;
- lock removes usable plaintext state from the application;
- password change rewraps rather than re-encrypting every note;
- recovery key restores access;
- terminal client is usable;
- web client uses the same crypto/protocol core;
- native/WASM test vectors match;
- relevant test suites pass;
- threat model and protocol documentation are current.
