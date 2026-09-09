# ADR 0005: Guarded Last-Write-Wins (LWW) Policy Option

## Status

Accepted (Optional client-side policy; Manual conflict preservation remains V1 default).

## Context

When multiple devices edit the same note concurrently while offline, both clients base their edits on the same base revision (e.g., revision $R$). The first client to synchronize pushes its revision successfully, advancing the server object to revision $R+1$. When the second client connects, its push contains `expected_revision = R`. The application server enforces compare-and-swap (CAS, SEC-006) and rejects the second push with a `revision_conflict` (status 409) containing the current remote revision $R+1$ and its encrypted envelope.

In Zero-Knowledge Notes:
- Plaintext cannot be inspected or merged on the server (SEC-001, SEC-002).
- Stale writes must never silently overwrite or destroy concurrent edits (SEC-006, SEC-008).
- The default V1 policy preserves the conflict in durable storage (`ConflictStore`), creates a line-level diff3 merge candidate, and requires explicit user resolution (`zk-note resolve <id>`).

However, certain note-taking workflows or collaborative user preferences benefit from automated conflict resolution where the latest edit automatically becomes visible, provided that **no data is lost**.

## Decision

We define the **Guarded Last-Write-Wins (LWW)** policy (`ConflictPolicy::GuardedLww`) as an optional, client-side conflict resolution mechanism in `zk-sync`.

### 1. Opt-In Policy (V1 Default Remains Manual)

In accordance with `MASTER_SPEC.md` § 10.4:
- The default conflict policy for all sync cycles and push operations is `ConflictPolicy::Manual`.
- `ConflictPolicy::GuardedLww` is strictly an opt-in policy configured via `PushOptions` / `SyncCycleOptions`.
- It must not be enabled by default in V1 without an explicit product decision.

### 2. Winner Visible Head Selection

When a push is rejected due to a revision conflict under Guarded LWW:
- The client compares the local edit timestamp (`mutation.created_at` or decrypted note `updated_at`) with the remote conflict timestamp (`remote_note.updated_at` or metadata timestamp).
- If timestamps are identical, deterministic tie-breaking is applied using ciphertext payload lexicographical order to prevent multi-device oscillation.
- The winning revision immediately becomes the current visible head in local storage (`ObjectStore::put_object`).

### 3. Lossless Guarantee: Losing Revision Always Recoverable

Guarded LWW is **guarded** because the losing revision is **never unrecoverably discarded**:
- **If Local Wins**: The remote envelope is archived in `BaseVersionStore::put_base_version` under the remote revision number. The user can view or recover it at any time via `zk-note history <id>`.
- **If Remote Wins**: The local envelope is archived in `BaseVersionStore::put_base_version`. Any stale local pending mutation is removed from the queue.
- In both cases, a `ConflictRecord` is persisted in `ConflictStore` marked as resolved, preserving both `local_envelope` and `remote_envelope` in ciphertext form (SEC-009).

### 4. Strict Server Compare-and-Swap (CAS) Enforcement

Server CAS is never bypassed:
- When Local wins, the client enqueues a retry mutation with `expected_revision = remote_revision`.
- On the next sync push, the server validates `expected_revision == current_revision`. If valid, the server accepts the mutation and allocates the next sequence number.
- If the remote server revision has advanced again in the meantime, the server rejects with another CAS conflict, maintaining 100% revision integrity.
- Plaintext is never transmitted, and the server remains completely zero-knowledge (SEC-001, SEC-002).

## Consequences

- Applications can provide seamless, automatic multi-device synchronization without blocking the UI on minor conflicts.
- Accidental data loss is mathematically prevented: historical losing revisions remain decryptable by the vault owner from local history.
- The server protocol remains unchanged, retaining opaque revision compare-and-swap guarantees.
