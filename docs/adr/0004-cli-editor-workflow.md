# ADR 0004: CLI $EDITOR Workflow, Frontmatter Representation, and Ephemeral File Lifecycle

## Status

Accepted

## Context

The terminal client (`zk-note`) needs an interactive note editing flow (`zk-note edit <note-id>`). External terminal text editors (`nano`, `vim`, `emacs`, `helix`, etc.) expect to read and write a physical or virtual file on the filesystem.

Zero-Knowledge Notes enforces strict invariants:
- Plaintext must never cross the network.
- Persistent local databases must store ciphertext only.
- Plaintext on disk must be minimized, securely protected, and promptly zeroized upon session termination.
- Stale or corrupted edits must not overwrite or corrupt existing stored revisions.
- Three-way conflict merge requires access to the base revision that the user edited from.

## Decision

1. **Frontmatter Representation**:
   Temporary files are formatted in standard Markdown with YAML-compatible frontmatter containing note metadata:
   ```markdown
   ---
   title: My Note Title
   tags: [work, crypto]
   ---

   Note Markdown body content...
   ```
   This allows users to edit the title, tags, and body within their favorite editor simultaneously.

2. **RAM-Disk Preference (`tmpfs`)**:
   On Linux systems, the CLI prioritizes `/dev/shm` and `$XDG_RUNTIME_DIR` (virtual memory tmpfs) over physical non-volatile storage to eliminate flash storage remanence.

3. **Strict Unix Permissions**:
   Temporary files are created with mode `0600` (`-rw-------`), and temporary directories with mode `0700` (`drwx------`).

4. **Guaranteed Zeroization via RAII (`TempFileGuard`)**:
   An RAII drop guard manages the file. Upon completion, cancellation, signal interruption, or error, the file content is overwritten with zeroes (`0x00`), committed with `sync_all()`, and unlinked with `std::fs::remove_file()`.

5. **Atomic Re-Encryption & Base Revision Retention**:
   - If the edited file is identical to the original, the operation finishes as a no-op without bumping the revision.
   - If changed, the updated note is validated, re-encrypted with a new random Object Key under the session `VaultKey`, and committed to SQLite (`local_objects`).
   - The prior encrypted envelope is stored in `encrypted_base_versions` via `BaseVersionStore::put_base_version`, preserving three-way merge capability.
   - An upsert mutation is added to `pending_mutations`.

6. **Failure Atomicity**:
   If the editor exits with a non-zero exit code or the edited content fails schema validation, the database write is aborted. The previous encrypted note remains intact and uncorrupted.

## Consequences

- Terminal users enjoy a native `$EDITOR` experience with standard Markdown tools.
- Plaintext risk is strictly bounded to volatile memory where available and protected by OS permission boundaries.
- Future multi-device synchronization conflicts can deterministically merge concurrent edits against the recorded base version.
