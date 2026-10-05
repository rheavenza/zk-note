# ADR-0008 — Native vault identity, explicit linking, and journaled local replacement

Status: Accepted (ZK-110)

## Decision

SSH/bearer account authentication does not select or initialize a vault. Each
machine owns an independent encrypted `notes.db`, `vault.json`, local device
identity and unlock session. Never share the SQLite cache using NFS, Syncthing,
cloud drives or another machine. Only HTTPS encrypted-object APIs coordinate
machines; HTTP is permitted for loopback development only.

`vault-link.json` v1 binds exactly `server_origin`, `account_id` and
`vault_fingerprint`. Origins use the native authentication URL validator.
Links use create-new temporary files, file fsync, rename and parent-directory
fsync; malformed/unknown-version/noncanonical records fail closed. Links are
independent of `.auth_session` and contain no keys or bearer token.

The shared `zk-core::vault_identity` identity is `blake2s-v1:` followed by 64
lowercase hex characters. BLAKE2s-256 hashes, in order:

1. Literal ASCII `zk-note-vault-id-v1` (19 bytes, no NUL).
2. Crypto version as a four-byte unsigned big-endian integer.
3. Recovery wrapper cipher suite as ASCII, framed by its four-byte BE byte length.
4. Decoded recovery-wrapper nonce bytes, framed by four-byte BE length.
5. Decoded recovery-wrapper ciphertext bytes, framed by four-byte BE length.

Do not include JSON serialization, KDF or password-wrapper bytes. Passphrase
rotation preserves the recovery wrapper and therefore this identity. Independently
initialized vaults have independent random recovery wrappers. The identity
identifies this encrypted recovery envelope; rotating it would require an explicit
future identity migration. No server UUID/schema migration is introduced.

Before native SyncEngine execution, validate link origin/account/local identity,
then GET the authenticated remote bootstrap and validate its identity. Missing,
corrupt or mismatching bindings disable both sync pull and push. Guard failures
never repair, relink, initialize or overwrite anything. Explicit Link uploads the
local encrypted bootstrap only if the remote bootstrap is absent; an existing
same identity may be adopted explicitly, a different identity is refused.

## Pull-only restore and local replacement

Preflight verifies the saved bearer session online (account/device/session IDs),
validates the remote bootstrap, identifies current/target associations and counts
Pending, InFlight, Failed, unresolved conflicts and unconfirmed local objects.
The existing cache is inspected without migrations/writes using an immutable
read-only SQLite connection **only if its WAL is absent/empty**. A nonempty WAL
is refused, never ignored: finish normal local cache access/close/checkpoint
before retrying preflight. This prevents undercounting and sidecar changes before
confirmation. SQLite's immutable mode omits WAL updates and is therefore unsafe
for an uncheckpointed cache; it must not be used without the explicit WAL check.
See [SQLite URI semantics](https://sqlite.org/uri.html) and
[SQLite WAL requirements](https://sqlite.org/wal.html).

Restore requires no existing vault/cache/link. Replacement explicitly discards
this machine's local vault/cache and queued/conflicted changes, never uploads
them, and never alters/deletes the server vault. Replacement requires typed
`REPLACE LOCAL VAULT` in an interactive CLI or the dedicated TUI confirmation
mode; noninteractive CLI requires `--discard-local`.

After confirmation, create `.replace-<UUID>/` in the same data directory; write
the fetched encrypted bootstrap and unlock locally using VaultManager. KDF
validation accepts Argon2id with 8*lanes..262144 KiB, 1..16 iterations, 1..16
lanes, and 8..64 salt bytes; wrappers require the existing v1 cipher suite,
24-byte nonces and 48-byte ciphertexts. Bounds prevent remote allocation abuse,
and parameters are never weakened/substituted. Pull from cursor 0 through the
existing shared `pull_remote_changes`, including tombstones, with no push code
path. Pull without the note-specific unlocked decoder, then validate every active
staged envelope through the shared core kind dispatcher: the existing note decoder
for kind 1 and attachment-manifest decoder for kind 4. Authenticate wrapped keys,
payload and AAD and decode the typed model; scrub temporary decoded metadata and
redact underlying decoder errors. Check stored ID/kind against the envelope.
Tombstones retain the existing opaque-envelope semantics. Notebook/settings kinds
2/3 currently have no shipped producer/plaintext model and, like other unsupported
active kinds, fail closed rather than bypass validation. Future supported kinds
must extend the central dispatcher. No attachment blob download is implied by
restoring its manifest. Verify durable cursor/empty queue,
checkpoint WAL with busy rejection, close/reopen/close the staged DB, fsync its
file and directory and persist/verify the staged link. Drop removes failed stages.

## Crash recovery

The native process holds an OS exclusive lock on the data-directory descriptor
throughout its lifetime. It excludes another CLI/TUI opening this directory and
is released by the OS on process death. Native callers embedded in tests/services
must likewise own `NativeDataGuard` when coordinating concurrent file operations.
No new dependency or unsafe code is needed (stable Rust File locking).

After complete staging, drop active DB handles, scrub in-memory VaultKey/plaintext
UI/search/edit buffers and clear `.session`. Checkpoint and close the old DB.
Preserve `.auth_session`, `device.json` and agent/key state. Fsync old files and
write `.replace-transaction.json` v1 with UUID, target identity, old-file presence
bitmap and phase:

- `Prepared`: old generation may be partly moved to `.backup-<UUID>/`.
- `OldMoved`: all old vault/DB/link and associated WAL/SHM have been moved.
- `NewInstalled`: all three staged vault/DB/link files are installed.
- `Committed`: installation is durable; old backup can be discarded.

Fsync affected directories after each rename; phase records use atomic fsynced
replacement. Before opening any active vault/cache, recover an existing journal:
uncommitted phases restore old files from backup; committed phase keeps the new
generation. Rollback copies backups through atomic writes and retains backups
until journal removal is durable, so interrupted rollback can repeat. Only then
remove backup/staging directories. No three-file rename is described as atomic.
The journal, not a mixed active directory, defines which generation may be opened.
Malformed journal prevents vault access. Startup cleans abandoned staging,
backups and write-temporary files only under the exclusive directory lock.

Fault tests cover all 12 swap transitions with real SQLite cursors and unlockable
bootstraps, all 12 staging transitions, actual injected cursor persistence failure,
first/later page failure, wrong secrets, WAL reopen, auth/device preservation and
zero push during discard. The supported durability model is local Unix filesystem
rename + file/directory fsync, not network/shared filesystems. Encrypted discarded
cache files are unlinked; this is not a secure-erasure guarantee for SSD snapshots.

## Consequences and scope

No server API/schema changes, SSH auth changes, new sync engine or background
execution changes. Restore/replacement leaves the vault locked and server auth
intact. `zk-note unlock` or the masked TUI prompt unlocks it locally afterward.
Existing legacy unlinked vaults require an explicit Link before remote sync.
The remote bootstrap remains create-once: local passphrase rotation does not
propagate a replacement password wrapper to the server/other machines. They may
restore using the original remote passphrase or recovery key; a future explicit
bootstrap-update protocol is a separate spec decision. ZK-111 owns asynchronous
sync execution/timeouts/cancellation and the real CLI sync command.
