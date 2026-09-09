# ADR-0002: Protocol V1 Foundation and Synchronization Model

## Status

Accepted

## Context

The zero-knowledge notes system requires a rock-solid, unambiguous synchronization protocol operating over untrusted network channels and backed by a zero-knowledge server. The server must coordinate multi-device state transitions without knowing note contents, titles, or tags (**SEC-001**, **SEC-002**).

To satisfy core requirements:
- **No silent data loss**: A stale client write must never overwrite a newer remote edit (**SEC-006**, **P-003**).
- **Retry safety**: Network interruptions and retransmissions must not produce duplicate revisions (**SEC-007**).
- **Deletion safety**: Stale edits must not silently resurrect deleted objects (**SEC-008**).
- **Offline-first cursor progress**: Clients must process updates durably before advancing sync state.

## Decision

### 1. Protocol and Envelope Versioning

The protocol strictly separates wire protocol negotiation from envelope encryption formatting:
- `PROTOCOL_VERSION_V1 = 1`: Governs sync endpoints, JSON schemas, mutation semantics, and cursor parameters.
- `ENVELOPE_VERSION_V1 = 1`: Governs the binary/ciphertext format of encrypted payloads.

Per **AGENTS.md §11**, all durable or transmitted protocol structures are versioned. Any breaking changes require incrementing the relevant version and providing backward-compatibility paths.

### 2. Object Identifiers (`object_id`)

- Each encrypted entity (note, notebook, settings, attachment manifest) is identified by a randomly generated 128-bit UUID v4 (`object_id`).
- Generated client-side upon initial creation.
- Stable across revisions and tombstones.
- Scoped to the authenticated account on the server; cross-account access is strictly rejected.

### 3. Object Kinds (`object_kind`)

Objects are categorized by an immutable 16-bit integer discriminant:
- `1 = NOTE`: Encrypted note body, title, tags, and timestamps.
- `2 = NOTEBOOK`: Encrypted notebook grouping.
- `3 = USER_SETTINGS`: Encrypted user preferences and configuration.
- `4 = ATTACHMENT_MANIFEST`: Encrypted attachment metadata and chunk list.
- `5 = RESERVED`: Reserved for future expansion.

Discriminant values are protocol constants and must never be reallocated or redefined. The server uses `object_kind` for storage routing and quota accounting without inspecting ciphertext content.

### 4. Revisions and Compare-And-Swap (`revision`, `expected_revision`)

- Each object maintains an integer `revision` (64-bit unsigned, starting at `1`).
- When creating a new object, the client submits `expected_revision = 0`. If the object does not already exist, the server commits it at `revision = 1`.
- When updating an object, the client must submit the current `revision` it observed as `expected_revision`.
- The server executes a compare-and-swap (CAS) check within a database transaction:
  - If `stored.revision == request.expected_revision`, the write is accepted and revision increments to `stored.revision + 1`.
  - If `stored.revision != request.expected_revision`, the mutation is rejected with `REVISION_CONFLICT`, returning the current revision and latest ciphertext envelope for client-side resolution.

### 5. Server Sequence (`server_seq`)

- The server assigns a strictly monotonic, gap-free 64-bit integer sequence (`server_seq`) per account for every accepted mutation.
- `server_seq` provides a global commit log order across all objects owned by an account.
- Sequences are allocated transactionally to prevent duplicate or skipped sequence numbers.

### 6. Mutation Identifiers (`mutation_id`) and Idempotency

- Every mutation submitted by a client includes a client-generated UUID v4 (`mutation_id`).
- The server records processed mutations in a `processed_mutations` table keyed by `(account_id, mutation_id)`.
- If a client retries a mutation with an identical `mutation_id`:
  - If the request payload matches the recorded mutation, the server returns the original accepted result without incrementing `revision` or allocating a new `server_seq` (**SEC-007**).
  - If the payload conflicts with the recorded mutation, the server returns `MUTATION_REPLAY_MISMATCH`.

### 7. Cursor Semantics (`sync_cursor`)

- A client tracks its sync state via `sync_cursor`, representing the highest contiguous `server_seq` successfully processed and durably committed to local storage.
- Initial sync starts at `INITIAL_SYNC_CURSOR = 0`.
- Incremental sync pulls changes via `GET /v1/sync/changes?after=<sync_cursor>&limit=<n>`, returning records with `server_seq > sync_cursor`.
- **Durable advancement rule**: The client must persist remote ciphertext to local encrypted storage *before* advancing the local `sync_cursor`. If the client crashes mid-sync, the cursor remains at the last safe sequence, guaranteeing no remote mutations are skipped.

### 8. Deletion and Tombstones

- Deletion is a revisioned mutation setting `is_deleted = true`.
- Tombstones participate in CAS revision checks and sequence allocation identically to updates.
- Stale client edits based on pre-deletion revisions receive a `REVISION_CONFLICT`, preventing resurrection races (**SEC-008**).

## Consequences

- Clear constants defined in `crates/zk-protocol` serve as the single source of truth across both client and server.
- The server coordinates revisions and ordering without ever having access to plaintext or keys.
- Client retry, crash-recovery, and multi-device conflict detection are deterministic and mathematically bounded.
