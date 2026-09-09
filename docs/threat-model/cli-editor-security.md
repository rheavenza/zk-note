# Threat Model: Native CLI Temporary Plaintext Files & `$EDITOR` Security

## 1. Overview & Threat Boundary

Zero-Knowledge Notes is designed to protect user notes with end-to-end client-side encryption. The server and network layer never see note plaintext, note titles, or metadata.

When using the native terminal client (`zk-note`), users can edit notes interactively using their system's `$EDITOR` (or `$VISUAL`). Because external text editors operate on filesystem paths, a temporary plaintext file must be materialized on the local client machine for the duration of the edit session.

This document defines the threat boundary, security controls, failure modes, and residual risks of this workflow.

---

## 2. Threat Boundary Definition

The threat boundary for the CLI editor workflow is the **local client machine**:

- **In-scope threats**:
  - Other non-root unprivileged users on a multi-user system.
  - Plaintext persistence on non-volatile physical storage after the edit session ends.
  - Plaintext remnants surviving abnormal editor terminations, process crashes, or signals.
  - Partial or corrupted writes corrupting the durable encrypted local database.
- **Out-of-scope threats**:
  - Full local system compromise by root/administrator.
  - Malicious editor executables deliberately exfiltrating buffers.
  - Active kernel-level keyloggers or DMA hardware attacks.
  - Physical memory extraction while the process is actively running in RAM.

---

## 3. Defense-in-Depth Mitigations

To mitigate the risk of temporary plaintext exposure, `zk-note edit` implements the following defenses:

### 3.1 Memory-Backed Filesystem Preference (RAM Disk)
- **Linux (`/dev/shm` / `XDG_RUNTIME_DIR`)**: The CLI first attempts to place temporary edit files in virtual memory (`tmpfs`).
- **RAM Isolation**: Files placed in `/dev/shm` or `/run/user/<UID>` reside purely in volatile RAM and do not persist to physical disk blocks, eliminating flash memory wear-leveling remanence.
- **Fallback**: If no RAM-backed filesystem is accessible, the CLI falls back to the system temp directory or vault data directory.

### 3.2 Restrictive Access Permissions
- **File Mode (`0600`)**: Temporary files are created exclusively with read/write permissions for the current user (`-rw-------`). Other users on a shared machine cannot read or open the file.
- **Directory Mode (`0700`)**: Any intermediate directories created for temporary edits enforce owner-only access (`drwx------`).

### 3.3 Random Unpredictable Paths
- Temporary edit filenames incorporate cryptographically secure UUID v4 tokens (e.g. `zk-note-edit-<uuid>.md`).
- Files are opened using `create_new(true)` (O_CREAT | O_EXCL) to prevent symlink hijacking and time-of-check to time-of-use (TOCTOU) race conditions.

### 3.4 Guaranteed Zeroization & RAII Cleanup
- **Drop Guard (`TempFileGuard`)**: An RAII guard manages the lifecycle of the temporary file.
- **Zeroization**: Prior to unlinking, the file's allocated bytes are overwritten with zeroes (`0x00`) in memory and committed via `sync_all()`.
- **Automatic Deletion**: The temporary file is immediately removed from the filesystem when the guard is dropped, whether the edit succeeds, is cancelled, encounters an error, or panics.

### 3.5 Failure Atomicity & Prior Version Protection
- If the editor process exits with a non-zero exit status, or if validation of the edited content fails (e.g., exceeding size limits or malformed syntax), the local database is **never updated**.
- The existing revision, encrypted envelope, and metadata remain completely uncorrupted.
- The base version of the note is archived in `BaseVersionStore` prior to overwriting, ensuring that future synchronization conflicts can perform deterministic three-way merges.

---

## 4. Residual Risks & User Recommendations

Users operating in high-security environments should be aware of the following residual considerations:

1. **Editor Swap / Backup Files**:
   - Some editors (such as `vim` or `emacs`) may create auxiliary files (e.g., `.swp`, `~` backup files) in the working directory.
   - *Recommendation*: Configure editors to disable swapfiles for sensitive paths (e.g. `set noswapfile` in vim) or configure swap files to write to memory.
2. **Encrypted Swap**:
   - Systems without swap encryption might theoretically page dirty memory blocks to swap partitions under extreme memory pressure.
   - *Recommendation*: Use full-disk encryption (LUKS / BitLocker / FileVault) and encrypted swap.
3. **Core Dumps**:
   - Crash dumps could contain memory pages from the process.
   - *Recommendation*: Disable core dumps (`ulimit -c 0`) on production machines.
