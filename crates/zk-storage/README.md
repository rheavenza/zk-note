# zk-storage

Storage abstraction traits, domain storage models, and in-memory test doubles for zero-knowledge note synchronization and persistence.

## Architecture & Boundaries

Following `AGENTS.md` and `MASTER_SPEC.md`, `zk-storage` defines pure interfaces and test doubles without imposing native storage dependencies (such as SQLite) on core crates:
- **`zk-core` / `zk-storage`**: No SQLite or native database dependencies.
- **`MemoryStorage`**: In-memory, thread-safe test double implementing all storage traits.
- **`rusqlite` / SQLite**: Implemented separately in native adapters (`ZK-022`).
- **IndexedDB**: Implemented separately in browser WASM adapters.

## Core Storage Traits

### 1. `ObjectStore`

Manages durable encrypted objects and tombstones:
- `get_object(object_id)`: Retrieve encrypted envelope and metadata.
- `put_object(object)`: Persist or update an encrypted object.
- `list_objects(filter)`: Query objects by kind, optionally including deleted tombstones.
- `mark_deleted(object_id, revision, envelope, updated_at)`: Record a revisioned tombstone.
- `purge_object(object_id)`: Hard-delete an object from local cache.

### 2. `MutationStore`

Manages locally queued mutations awaiting synchronization with the application server:
- `enqueue_mutation(mutation)`: Queue a new mutation with a unique idempotency ID.
- `get_mutation(mutation_id)`: Retrieve a pending mutation.
- `list_pending_mutations()`: Retrieve all pending mutations in processing order.
- `list_mutations_for_object(object_id)`: Retrieve pending mutations targeting a specific object.
- `remove_mutation(mutation_id)`: Dequeue an acknowledged mutation upon sync success.
- `update_mutation_status(mutation_id, status, retry_count)`: Track in-flight or failed attempts.
- `pending_mutation_count()`: Count outstanding mutations awaiting sync.

### 3. `BaseVersionStore`

Retains base encrypted envelopes required to perform three-way conflict merges (`BASE`, `LOCAL`, `REMOTE`):
- `get_base_version(object_id, revision)`: Retrieve base envelope.
- `put_base_version(object_id, revision, envelope)`: Store base envelope.
- `prune_base_versions(object_id, older_than_revision)`: Prune obsolete base versions.
- `clear_base_versions(object_id)`: Clear all base versions for an object.

### 4. `SyncStateStore`

Tracks contiguous synchronization cursors and device state:
- `get_sync_state()`: Retrieve current sync cursor and device metadata.
- `set_sync_cursor(cursor)`: Advance cursor upon successful sync page processing.
- `set_sync_state(state)`: Update complete sync state.

### 5. `LocalStorage`

Composite trait combining `ObjectStore`, `MutationStore`, `BaseVersionStore`, and `SyncStateStore`. Automatically implemented for any type implementing all four traits.

## Test Double (`MemoryStorage`)

`MemoryStorage` provides a thread-safe, in-memory reference implementation of `LocalStorage` for unit and integration testing without database setup.
