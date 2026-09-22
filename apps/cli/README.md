# `zk-note` — Zero-Knowledge Terminal Client

`zk-note` is a full-featured terminal / CLI client for the Zero-Knowledge note-taking system. It features end-to-end client-side encryption (`XChaCha20-Poly1305`), local SQLite encrypted persistence, seamless `$EDITOR` workflow with memory zeroization, interactive 3-way conflict resolution, and offline-first synchronization.

---

## 1. Installation & Building

Compile the release binary from the repository root:

```bash
cargo build --release --bin zk-note
```

Optionally install into your `$PATH`:
```bash
cp target/release/zk-note /usr/local/bin/
```

Verify installation:
```bash
zk-note --help
```

---

## 2. Local Storage Layout

By default, `zk-note` stores its data in your standard system user data directory:
- **Linux**: `~/.local/share/zk-notes/`
- **macOS**: `~/Library/Application Support/zk-notes/`

You can override the storage location for any command via the global `--data-dir <path>` argument or by setting the `ZK_DATA_DIR` environment variable.

### Directory Structure:
```text
~/.local/share/zk-notes/
├── vault.json          # Encrypted VaultBootstrap (wrapped vault key, Argon2id salt & params)
├── notes.db            # Local encrypted SQLite cache (objects, mutations, conflicts, blobs)
└── session.json        # Ephemeral session token with auto-lock expiration (permissions: 0600)
```

> **Security Guarantee (SEC-009)**: `notes.db` stores **only** ciphertext envelopes. Note titles, tags, bodies, and attachment chunks are never written to disk unencrypted.

---

## 3. Command Reference & Usage Guide

### 3.1 Vault Setup & Authentication

#### Initialize a New Vault
```bash
zk-note init
```
Prompts for a master passphrase and outputs a formatted **288-bit Recovery Key** (e.g. `C46996A9-769472A5-...`).
*Store this recovery key in a secure, offline location.*

#### Unlock Vault Session
```bash
# Unlock interactively with master passphrase
zk-note unlock

# Unlock using formatted recovery key
zk-note unlock --recovery-key "C46996A9-769472A5-..."

# Configure auto-lock idle timeout (in minutes)
zk-note unlock --timeout 30
```

#### Lock Vault Session
```bash
zk-note lock
```
Purges the active session key and search indices from memory, returning the client to a fail-closed state (`SEC-010`).

#### Auto-Lock Policy
```bash
# View current auto-lock timeout
zk-note autolock

# Set idle timeout to 20 minutes (0 to disable)
zk-note autolock --timeout 20
```

#### Change Master Passphrase
```bash
zk-note passwd
```
Re-derives a fresh Key Encryption Key (KEK) using Argon2id and re-wraps the existing `VaultKey` without data re-encryption.

#### Recover Lost Passphrase
```bash
zk-note recover --recovery-key "C46996A9-769472A5-..."
```
Restores vault access using the 288-bit recovery key, verifies the embedded BLAKE2b checksum, and prompts for a new master passphrase with zero data loss.

---

### 3.2 Note Management

#### Create a New Note
```bash
# Interactive or parameterized creation
zk-note new --title "System Architecture" --body "Design notes..." --tag "docs,arch"

# Pipe content from stdin
cat design.md | zk-note new --title "Design Spec" --tag "spec"
```

#### List Notes
```bash
# List all active notes
zk-note list

# Filter notes by tag
zk-note list --tag docs

# Include deleted tombstones
zk-note list --include-deleted

# Output as JSON
zk-note list --json
```

#### View a Note
```bash
zk-note show <note-id>
```
Displays title, revision, update timestamp, tags, and decrypted Markdown body.

#### Edit a Note with `$EDITOR`
```bash
zk-note edit <note-id>
```
Opens the note in your preferred text editor (`$VISUAL`, `$EDITOR`, or falling back to `nano`/`vi`).

The editor buffer uses clean YAML Markdown frontmatter:
```markdown
---
title: System Architecture
tags:
  - docs
  - arch
---
# Architectural Specifications
Detailed content here...
```
Upon saving and exiting, `zk-note`:
1. Parses the frontmatter and body.
2. Validates schema and limits.
3. Archives the previous revision as a base version for 3-way conflict merges.
4. Encrypts the updated note with a fresh 192-bit nonce.
5. Zeroes and unlinks the temporary file.

#### Search Notes (Full-Text In-Memory)
```bash
# Multi-field search over title, body, and tags
zk-note search "cryptography architecture"

# Tag-targeted search
zk-note search "#crypto argon2"
```
Search runs in volatile memory only while unlocked. Search indices are completely scrubbed when the vault locks (`SEC-009`).

#### Note Revision History
```bash
# View revision history log
zk-note history <note-id>

# View decrypted contents at revision 2
zk-note history <note-id> --revision 2
```

#### Delete a Note
```bash
# Delete note (creates revisioned tombstone for safe synchronization)
zk-note delete <note-id>

# Permanent hard-purge from local storage (erases all historical revisions)
zk-note delete <note-id> --purge
```

---

### 3.3 Encrypted Attachments

Attach arbitrary binary files (images, PDFs, documents) to notes. Attachments are encrypted in 256 KiB chunks with isolated derived keys.

```bash
# Attach a file
zk-note attach <note-id> ./diagram.png --name "Architecture Diagram"

# List attachments on a note
zk-note attachments <note-id>

# Detach and remove an attachment
zk-note detach <note-id> <attachment-id>
```

---

### 3.4 Multi-Device Synchronization & Server Authentication

#### Connect to Sync Server
```bash
zk-note login --server http://127.0.0.1:8080 --account-id <uuid> --token <auth-token>
```

#### Check Sync & Device Identity
```bash
zk-note whoami
zk-note status
```

#### Manage Authorized Devices
```bash
# List all authorized devices on your account
zk-note device list

# Revoke a lost or compromised device
zk-note device revoke <device-id>
```

---

### 3.5 Conflict Detection & Resolution

When concurrent offline edits occur on multiple devices, the server rejects stale updates with HTTP 409 Conflict (`SEC-006`). `zk-note` preserves both versions in a durable `ConflictRecord`:

```bash
# List unresolved conflicts
zk-note conflicts

# Interactively resolve a conflict
zk-note resolve <conflict-id>

# Resolution strategy flags:
zk-note resolve <conflict-id> --merge      # Open 3-way diff3 merge in $EDITOR
zk-note resolve <conflict-id> --local      # Keep local version (overrides remote on next sync)
zk-note resolve <conflict-id> --remote     # Discard local edits, accept remote version
zk-note resolve <conflict-id> --duplicate  # Accept remote and fork local changes into a new note
```

### 3.6 Interactive Terminal UI (`zk-note tui`)

Launch the lazygit-style interactive terminal UI:
```bash
zk-note tui
```
or with a custom data directory:
```bash
zk-note --data-dir /path/to/data tui
```

#### Responsive Constraints
- **Minimum Terminal Size**: `80 x 24` columns and rows.
- If the terminal is resized below 80x24, the TUI safely suspends the multi-pane display and renders a dedicated `Terminal Too Small` view showing current and required dimensions without panicking or leaking decrypted content.

#### Locked / Unlocked Lifecycle
- **Locked State**: If the vault is locked or has no active session upon launch, the TUI displays a centered masked unlock modal.
- **Passphrase Entry**: Passphrase characters are masked (`*`), and the input buffer is zeroized in memory on unlock or cancel.
- **Explicit Lock (`l`)**: Pressing `l` immediately locks the vault session, zeroizes all decrypted note contents, search terms, conflict records, and edit buffers, and returns to the locked modal.
- **Idle Auto-Lock**: The TUI runs an internal tick handler that checks the existing session timeout. If the session expires due to inactivity, it triggers the exact same zeroizing lock path.

#### External Editor Workflow (`E`)
- Pressing `E` on any note temporarily suspends raw terminal mode and the alternate screen via `TerminalGuard::suspend`.
- The note is opened in `$VISUAL` or `$EDITOR` (falling back to `nano`/`vi`) using the existing secure `TempFileGuard` mechanism in a RAM-backed tmpfs (`/dev/shm`, `$XDG_RUNTIME_DIR`) with `0600` permissions.
- When the editor exits, the temporary file is zeroized before unlinking, the updated note is encrypted and saved, and the TUI resumes seamlessly.

#### Keybinding Cheat Sheet

| Mode / View | Key | Action |
| :--- | :--- | :--- |
| **Global / Navigation** | `j` / `Down` | Move down in notes or conflict list |
| | `k` / `Up` | Move up in notes or conflict list |
| | `g` | Jump to first item |
| | `G` | Jump to last item |
| | `Enter` | Open selected note into preview / focus pane |
| | `Tab` | Cycle focus forward (Notes -> Preview -> Metadata) |
| | `Shift+Tab` / `BackTab` | Cycle focus backward |
| | `Esc` | Return focus to Notes list / close modals |
| | `?` | Toggle Help overlay modal |
| | `q` | Quit TUI |
| | `l` | Explicitly lock vault and purge decrypted buffers |
| **Note Operations** | `n` | Create new note (inline editor) |
| | `e` | Inline edit current note (title, tags, body) |
| | `E` | External edit current note via `$EDITOR` (`TempFileGuard`) |
| | `d` | Delete current note (confirmation gated) |
| | `/` | Incremental in-memory search across notes |
| | `s` | Trigger manual guarded sync |
| | `c` | Open Conflicts overlay view |
| **Search Mode (`/`)** | `Enter` / `Esc` | Finish search and keep filter / navigate results |
| | `Backspace` | Erase character from search query |
| | Any text | Filter note list dynamically in memory |
| **Inline Editor (`n` / `e`)** | `Tab` | Cycle field (Title -> Tags -> Body) |
| | `Ctrl+S` | Save note and return to normal mode |
| | `Esc` | Cancel editing (discards unsaved draft) |
| **Delete Confirmation (`d`)** | `y` / `Y` / `Enter` | Confirm deletion (creates revisioned tombstone) |
| | `n` / `N` / `Esc` | Cancel deletion |
| **Conflicts View (`c`)** | `j` / `k` | Navigate conflict list |
| | `k` / `l` / `1` | Keep Local revision |
| | `r` / `2` | Accept Remote revision |
| | `m` / `3` | 3-way Merge candidate |
| | `d` / `4` | Duplicate (fork local into new note) |
| | `u` / `5` | Restore / Keep Local (for tombstone conflict) |
| | `Esc` / `q` / `c` | Close conflicts view |
| **Locked Screen** | `Enter` | Submit passphrase to unlock |
| | `Backspace` | Delete masked character |
| | `Esc` / `q` | Quit application |

---

## 4. Security Guarantees & Threat Boundaries

1. **Temporary File Zeroization (`TempFileGuard`)**:
   - `zk-note edit` creates temporary files in RAM-backed tmpfs (`/dev/shm`, `$XDG_RUNTIME_DIR`) whenever possible.
   - Temporary files are created with strict `0600` permissions (read/write by owner only).
   - An RAII drop guard overwrites the temporary file with zeroes and calls `sync_all()` before unlinking.

2. **Locked State Fail-Closed (`SEC-010`)**:
   - When the vault is locked, all note reading, editing, listing, and searching commands immediately fail with `VaultLocked`.
   - The session key is zeroized via `zeroize::ZeroizeOnDrop`.

3. **Plaintext Isolation (`SEC-001`, `SEC-002`)**:
   - Plaintext exists only in volatile process memory while unlocked.
   - Persistent SQLite databases contain exclusively encrypted envelopes.
