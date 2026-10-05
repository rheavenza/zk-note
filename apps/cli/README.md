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

`zk-note` synchronizes opaque encrypted note envelopes with a zero-knowledge sync server.

#### Agent-first account authentication

The operator registers a public Ed25519 key on the native server (ADR-0007).
Load the corresponding private key into your local agent; zk-note talks through
`SSH_AUTH_SOCK` and never reads/exports the private key:

```bash
ssh-add ~/.ssh/id_ed25519
zk-note login --server https://notes.example.com
# Explicitly select one loaded identity (mandatory with multiple keys in scripts):
zk-note login --server https://notes.example.com --identity SHA256:<fingerprint>
zk-note ssh-key list
zk-note ssh-key add ~/.ssh/laptop.pub --label laptop
zk-note ssh-key revoke <credential-id>
```

Only plain `ssh-ed25519` is supported. Zero compatible identities gives a safe
error; one is automatic; multiple identities offer a numbered terminal prompt.
Noninteractive login requires `--identity` (`--fingerprint` alias) when multiple
keys exist. Direct private identity-file parsing/decryption is not supported.
The existing `--token` path below remains compatible with valid bearer sessions.
SSH login uses the fixed server device label `SSH native client`; `--device-name`
applies to token-based device authorization.

#### Server URL Validation & Security Rules
- **HTTPS Required for Remote**: Insecure HTTP is prohibited for remote servers to prevent bearer token interception.
- **Local Development Loopback**: Plain HTTP is permitted strictly for loopback hosts (`localhost`, `127.0.0.1`, `[::1]`).
- **Canonical Origins**: URLs must not contain credentials, query parameters, URL fragments, or arbitrary paths.

#### Connect & Authorize Device
```bash
zk-note login --server http://127.0.0.1:8080 --account-id <uuid> --token <auth-token>
```
Credentials use the existing `.auth_session` file, atomically replaced with POSIX `0600` permissions. Failed authentication preserves the previous saved session. Full bearer tokens are never printed.

#### Sign-Out & Server Revocation Behavior
```bash
zk-note logout
```
Signing out revokes the session on the sync server before deleting local credentials. If the server is offline or unreachable, local credentials are intentionally preserved with a truthful warning so the user can retry revocation when connectivity is restored.

#### Authentication vs. Vault Linking / Sync
> **Important**: Signing in authorizes this terminal device with the server account. It does **not** link, upload, replace, or restore your vault. Vault synchronization is a separate, guarded operation (`s` in the TUI; the CLI sync implementation is ZK-111) that uses compare-and-swap (CAS) revision checks to prevent silent overwrites.

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
| | `a` | Open server connection & account authentication modal |
| **Note Operations** | `n` | Create new note (inline editor) |
| | `e` | Inline edit current note (title, tags, body) |
| | `E` | External edit current note via `$EDITOR` (`TempFileGuard`) |
| | `d` | Delete current note (confirmation gated) |
| | `/` | Incremental in-memory search across notes |
| | `s` | Trigger manual guarded sync |
| | `c` | Open Conflicts overlay view |
| **Server / Account (`a`)** | `Tab` / `Down` | Cycle fields (Server URL -> Token -> Token Connect -> SSH Agent -> Sign Out) |
| | `Shift+Tab` / `Up` | Cycle fields backward |
| | `Enter` | Submit / execute focused action |
| | `Ctrl+X` | Trigger Sign Out & remote session revocation |
| | `Ctrl+R` | Refresh server connection status |
| | `Esc` | Close modal and zeroize token buffer |
| **Search Mode (`/`)** | `Enter` / `Esc` | Finish search and keep filter / navigate results |
| | `Backspace` | Erase character from search query |
| | Any text | Filter note list dynamically in memory |
| **Inline Editor (`n` / `e`)** | `Tab` | Cycle field (Title -> Tags -> Body) |
| | `Ctrl+S` | Save note and return to normal mode |
| | `Esc` | Cancel editing (discards unsaved draft) |
| **Delete Confirmation (`d`)** | `y` / `Y` / `Enter` | Confirm deletion (creates revisioned tombstone) |
| | `n` / `N` / `Esc` | Cancel deletion |
| **Conflicts View (`c`)** | `j` / `Down` | Move down in conflict list |
| | `k` / `Up` | Move up in conflict list |
| | `1` / `l` | Keep Local revision |
| | `2` / `r` | Accept Remote revision |
| | `3` / `m` | 3-way Merge candidate |
| | `4` / `d` | Duplicate (fork local into new note) |
| | `R` | Restore (for tombstone / delete conflict) |
| | `Esc` / `q` | Close conflicts view |
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
   - The server never receives Vault Keys, Note Keys, passphrases, note plaintext, or search queries.

4. **Secret Hygiene & Token Protection (`SEC-003`)**:
   - Session tokens and passphrases are entered with masked feedback (`*`), never echoed in terminal history.
   - Bearer tokens are redacted in all `Debug` representations, error messages, and logs.
   - In-memory token buffers are aggressively scrubbed using `Zeroize` upon submission, cancellation, vault lock, application quit, and drop.

5. **Server Isolation & Honest Status**:
   - Failed or offline authorization attempts never overwrite or invalidate existing valid local sessions.
   - Sign-out attempts server revocation before deleting local credentials; if offline, credentials are preserved with an actionable warning to allow retry.
   - Signing in never automatically uploads, links, replaces, or replaces a local vault.


### SSH authentication in the Account modal

Open Account with `a`, enter the intended server URL, tab to **SSH Agent** and
press Enter to discover keys. The modal displays `ssh-ed25519`, SHA256 fingerprint
and sanitized agent comment. Left/Right cycles deterministically sorted keys;
Enter authenticates with the selected key; `r` reloads identities. An empty token
with the Connect button also discovers SSH identities. Token input and its
existing authorization path remain available. Escape scrubs token input and
clears pending modal work without changing a valid session. Successful SSH login
uses the existing authenticated state, account badge, startup verification,
status, logout and device/session controls.

SSH sessions expire after one hour; reauthenticate with the agent. A credential
binds to its first local device UUID; keep the data directory/device identity.
Use one key per machine. Key revocation blocks new SSH login and revokes its
pinned device and active sessions plus derived key sessions. Other machine keys
remain usable. Login creates only an account session; it never initializes,
links, restores, uploads or unlocks a vault. ZK-110 provides explicit vault linking/restoration independently of login.

### Explicit native vault link, restore and local replacement (ZK-110)

Each machine must have its own data directory, `vault.json`, `notes.db`, device
identity and SSH session. Do **not** synchronize/share `notes.db` with Syncthing,
NFS or cloud drives. Signing in authenticates an account; it never links a vault.

First machine, with an initialized local vault:

```bash
zk-note login --server https://notes.example.com
zk-note vault status
zk-note vault link
zk-note tui
```

Link explicitly creates the encrypted remote bootstrap if absent, or adopts an
existing bootstrap with the same stable vault identity. A different remote vault
is refused without POST/overwrite. Successful server persistence is required
before `vault-link.json` is written. TUI `s` runs existing guarded sync; the CLI
`sync` implementation remains ZK-111 scope.

Second machine, with no local vault/cache, authenticates independently to the
same account then restores:

```bash
zk-note login --server https://notes.example.com
zk-note vault restore
zk-note unlock
zk-note tui
```

The restore passphrase prompt is masked. Use `vault restore --recovery-key` for a masked recovery-key prompt. Supplying
`--recovery-key <key>` or `--passphrase <passphrase>` is also supported.
Prefer masked interactive input because shell arguments/history are visible to
other local tools. In the TUI, Ctrl+V opens the vault modal, even while locked;
Ctrl+A opens account authentication separately. Choose Restore, then Tab switches
between masked passphrase and recovery-key input. Esc cancels and scrubs inputs.
All unwrap/decryption happens locally; passphrases, recovery keys, VaultKey,
plaintext titles/bodies/tags and search terms never enter network payloads.

Restore builds an independent staged cache, pulls ciphertext and tombstones from
cursor 0 and never pushes. It installs bootstrap/cache/link only after validation,
complete pull and durable WAL checkpoint/close. It leaves the restored vault
locked and preserves the server auth session and device identity.

To explicitly discard this machine's local state and rebuild from its currently
authenticated account/server:

```bash
zk-note vault replace-from-server
# Read account/server/vault identity and pending/in-flight/failed/conflict counts.
# Type exactly: REPLACE LOCAL VAULT
# Enter the remote vault passphrase locally.
```

Noninteractive replacement requires `--discard-local`, plus an explicitly
supplied local unlock secret. Without confirmation no replacement staging or
sync push occurs. TUI Replace uses a dedicated warning/counts screen and the same
typed confirmation before masked unlock. Pending, in-flight, failed and conflicted
local work is discarded **without upload**. This action never replaces/deletes
anything on the server. Authentication and `device.json` survive; the old local
unlock session and plaintext UI state are cleared before installation.

Preflight refuses a nonempty/uncheckpointed WAL rather than omit unsynced work
or mutate the cache before confirmation. Close other cache users and perform a
normal local read/open-close (for example unlock then `zk-note list`) to complete
SQLite recovery/checkpoint before retrying. Every native process holds an exclusive
lock on its local data directory; concurrent CLI/TUI use of that directory is
refused. Local Unix filesystems with atomic rename and file/directory fsync are
the supported crash-durability model.

`vault-link.json` is separate from `.auth_session` and binds normalized origin,
account ID and `blake2s-v1:` recovery-envelope identity. Sync fails closed for
missing/corrupt links, wrong server/account, local identity mismatch, missing
remote bootstrap or remote identity mismatch. It never repairs or relinks inside
sync. Local passphrase rotation preserves vault identity, but does not overwrite
the create-once remote bootstrap; remote passphrase propagation needs a future
explicit protocol. Restore from the server may require its original passphrase
or the recovery key. See [ADR-0008](../../docs/adr/0008-native-vault-link-and-local-replacement.md)
for framing, journal phases, crash recovery and verification details.
