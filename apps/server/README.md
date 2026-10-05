# `zk-server` — Zero-Knowledge Sync & Ciphertext Storage Server

`zk-server` is a lightweight, high-performance synchronization coordinator and ciphertext storage engine built with [Axum](https://github.com/tokio-rs/axum) and [rusqlite](https://github.com/rusqlite/rusqlite).

In strict adherence to **SEC-002**, the server operates as an untrusted ciphertext repository. It has **no dependency** on client cryptographic primitives (`zk-crypto`) or plaintext models (`zk-core`). It cannot decrypt note bodies, note titles, tags, attachment payloads, search indexes, or user keys.

---

## Architecture & Zero-Knowledge Responsibilities

The server owns:
- **Compare-And-Swap (CAS) Mutation Handling**: Atomic `expected_revision` validation preventing stale offline overwrites (`SEC-006`).
- **Mutation Idempotency**: Deduplicating retried client mutations via 32-byte cryptographic payload digests (`SEC-007`).
- **Monotonic Sequence Allocation**: Per-account transactionally safe incremental sequences for pull ordering.
- **Opaque Blob / Attachment Chunks**: Content-addressed 256 KiB encrypted chunk storage with quota enforcement.
- **Device & Session Authorization**: WebAuthn passkey registration, bearer token validation, and instant device revocation (`ZK-070`, `ZK-072`, `ZK-075`).
- **Revisioned Tombstones**: Durable deletion tombstone persistence preventing stale resurrection (`SEC-008`).

The server **NEVER** performs:
- Note decryption, parsing, or Markdown rendering.
- Plaintext full-text search, tag filtering, or title indexing.
- Plaintext conflict resolution or note merges.

---

## Configuration & Environment Variables

`zk-server` is configured via environment variables or CLI invocation:

| Environment Variable | CLI Fallback | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `ZK_SERVER_HOST` | `HOST` | `127.0.0.1` | Network interface to bind (use `0.0.0.0` for all interfaces). |
| `ZK_SERVER_PORT` | `PORT` | `8080` | TCP port to listen on. |
| `ZK_SERVER_DB_PATH` | `DATABASE_PATH` | *(in-memory)* | Path to persistent SQLite database file on disk (e.g. `/var/lib/zk-notes/server.db`). |
| `ZK_SERVER_LOG_LEVEL` | `RUST_LOG` | `info` | Logging filter directive (e.g. `info`, `warn`, `debug,zk_server=trace`). |
| `ZK_SERVER_LOG_FORMAT` | `LOG_FORMAT` | `json` | Log output format: `json` (production structured) or `text` (human-readable). |
| `ZK_SERVER_MAX_BLOB_SIZE` | `MAX_BLOB_SIZE` | `104857600` (100 MiB) | Maximum allowed size of a single encrypted attachment chunk. |
| `ZK_SERVER_ACCOUNT_BLOB_QUOTA` | `ACCOUNT_BLOB_QUOTA` | `1073741824` (1 GiB) | Aggregate encrypted blob storage quota per account. |
| `ZK_WEBAUTHN_RP_ID` | none | `localhost` | WebAuthn relying-party ID; set this to the API hostname in production. |
| `ZK_WEBAUTHN_ORIGIN` | none | `http://localhost:5173` | Exact browser origin accepted in WebAuthn client data. |

---

## REST API Overview

API endpoints are versioned under `/v1`. Protected ciphertext and account-management routes require bearer authentication; health and authentication-challenge/proof routes are public.

### 1. Health & Diagnostics
- `GET /health` or `GET /v1/health`: Returns JSON `{"status":"pass"}` and system timestamp. Does not require authentication.

### 2. Vault Bootstrap Lifecycle
- `POST /v1/vault/bootstrap`: Stores the initial encrypted `VaultBootstrap` record (wrapped vault key, Argon2id KDF parameters, recovery key wrapper). Fails closed if the vault is already initialized for the account.
- `GET /v1/vault/bootstrap`: Retrieves the stored `VaultBootstrap` record required to derive the KEK and unwrap the vault key client-side.

### 3. Synchronization & CAS Mutation
- `POST /v1/sync/push`: Enqueues an atomic mutation with Compare-And-Swap verification (`expected_revision`).
  - Returns `200 OK` with accepted revision and sequence if `expected_revision == current_revision`.
  - Returns `409 Conflict` if the object has already advanced beyond `expected_revision` (`SEC-006`).
  - Returns existing revision idempotently if the exact mutation ID was already committed (`SEC-007`).
- `GET /v1/sync/pull?after=<seq>&limit=50`: Pulls incremental encrypted changes ordered by monotonic sequence. Accepts `after`, `since`, or `cursor` query parameters.

### 4. Encrypted Blobs & Attachments
- `POST /v1/blobs`: Uploads an opaque, encrypted attachment chunk addressed by its BLAKE2b digest (`SEC-001`, `SEC-002`).
- `GET /v1/blobs/:digest`: Downloads the raw encrypted blob chunk.
- `DELETE /v1/blobs/:digest`: Deletes an encrypted chunk.

### 5. Authentication & Device Authorization
- `POST /v1/auth/login`: Authenticates device with credentials / token and issues an authorized session token.
- `POST /v1/auth/logout`: Revokes the active session token.
- `GET /v1/auth/whoami`: Returns authenticated account ID, device ID, and session status.
- `GET /v1/devices`: Lists authorized client devices and active sessions for the account.
- `DELETE /v1/devices/:id`: Revokes an authorized device and immediately invalidates all its active sessions.
- `POST /v1/auth/webauthn/register/start`, `POST /v1/auth/webauthn/register/finish`: WebAuthn passkey enrollment.
- `POST /v1/auth/webauthn/login/start`, `POST /v1/auth/webauthn/login/finish`: WebAuthn passkey authentication.

---

## Production Deployment

### 1. Build Native Binary

```bash
cargo build --release --bin zk-server
```
The optimized binary will be located at `target/release/zk-server`.

### 2. Systemd Service Setup (Linux)

Create `/etc/systemd/system/zk-server.service`:

```ini
[Unit]
Description=Zero-Knowledge Notes Sync Server
After=network.target

[Service]
Type=simple
User=zknotes
Group=zknotes
WorkingDirectory=/var/lib/zk-notes
Environment=ZK_SERVER_HOST=127.0.0.1
Environment=ZK_SERVER_PORT=8080
Environment=ZK_SERVER_DB_PATH=/var/lib/zk-notes/server.db
Environment=ZK_SERVER_LOG_LEVEL=info
Environment=ZK_SERVER_LOG_FORMAT=json
ExecStart=/usr/local/bin/zk-server
Restart=always
RestartSec=5s

# Security sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/zk-notes
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo mkdir -p /var/lib/zk-notes
sudo chown -R zknotes:zknotes /var/lib/zk-notes
sudo systemctl daemon-reload
sudo systemctl enable --now zk-server
```

### 3. Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM rust:1.80-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --bin zk-server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite
WORKDIR /var/lib/zk-notes
COPY --from=builder /app/target/release/zk-server /usr/local/bin/zk-server

ENV ZK_SERVER_HOST=0.0.0.0
ENV ZK_SERVER_PORT=8080
ENV ZK_SERVER_DB_PATH=/var/lib/zk-notes/server.db
ENV ZK_SERVER_LOG_LEVEL=info
ENV ZK_SERVER_LOG_FORMAT=json

EXPOSE 8080
VOLUME ["/var/lib/zk-notes"]
ENTRYPOINT ["/usr/local/bin/zk-server"]
```

Build and run:
```bash
docker build -t zk-server .
docker run -d \
  --name zk-server \
  -p 8080:8080 \
  -v zk_data:/var/lib/zk-notes \
  zk-server
```

### 4. Reverse Proxy Setup (Nginx)

When deploying behind Nginx, terminate TLS and inject mandatory security headers (`deploy/nginx/security-headers.conf`):

```nginx
upstream zk_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name notes-api.example.com;

    ssl_certificate /etc/letsencrypt/live/notes.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/notes.example.com/privkey.pem;

    include /etc/nginx/snippets/security-headers.conf;

    location / {
        proxy_pass http://zk_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
    }
}
```

---

## Backup & Disaster Recovery

Because all note contents and metadata are encrypted client-side, the server SQLite database can be safely backed up over untrusted networks.

### Live Hot Backup (`VACUUM INTO`)
Execute an atomic snapshot while the server is live without read or write interruption:

```bash
sqlite3 /var/lib/zk-notes/server.db "VACUUM INTO '/backups/server-backup-$(date +%Y%m%d%H%M%S).db';"
```

### Restore Procedure
To restore from a backup snapshot:
1. Stop the `zk-server` service: `sudo systemctl stop zk-server`
2. Replace `/var/lib/zk-notes/server.db` with the backup file.
3. Restart the service: `sudo systemctl start zk-server`
4. Connected clients will automatically synchronize from their durable cursors without data loss.

---

## Log Redaction & Security Invariants

In accordance with **SEC-003**, `zk-server` automatically strips and redacts sensitive credentials and headers from tracing logs:
- `Authorization: Bearer [REDACTED]`
- `X-Session-Token: [REDACTED]`
- `Cookie: [REDACTED]`

Passphrases, recovery keys, and decrypted content never enter server memory, making leakages mathematically impossible.


## Username/password authentication status

ZK-108 is blocked at its mandatory Worker Argon2id feasibility gate under the
operator-confirmed Workers Free 10 ms CPU budget. Password registration/login,
credential migrations and browser password controls are not yet available.
Passkeys and existing session/revocation behavior remain supported. Account
authentication and the vault passphrase remain separate; signing in does not
link, upload, restore or unlock the local vault. No schema or deployment
configuration changes are required for this evidence-only change.

See [measured CPU results, reproduction and options](../../docs/tickets/ZK-108-argon2-feasibility.md).


## Native SSH authentication and operator provisioning (ZK-109)

Set a persistent SQLite path and the exact public origin. No-argument
`zk-server` startup is preserved:

```bash
export ZK_SERVER_DB_PATH=/var/lib/zk-notes/server.db
export ZK_SSH_AUTH_ORIGIN=https://notes.example.com
zk-server account create --ssh-key ~/.ssh/id_ed25519.pub --label desktop
zk-server account add-ssh-key <account-id> --ssh-key ~/.ssh/laptop.pub --label laptop
zk-server
```

Provisioning uses the same database and append-only migrations as server startup.
It reads bounded public `.pub` files through the shared server-auth parser,
accepts only plain `ssh-ed25519`, and prints account ID, credential ID and SHA256
fingerprint. No bypass bearer token or vault is created. Duplicate keys (including
revoked ones), unknown/inactive accounts, private input and unsupported keys fail
clearly. No public HTTP admin/bootstrap route is added.

`ZK_SSH_AUTH_ORIGIN` defaults to `http://127.0.0.1:8080`. Configure it explicitly
for custom ports and remote deployment. It must be a canonical URL origin:
lowercase ASCII/IDNA host, canonical port/IPv6 form, no default port, trailing
slash, credentials, path, query or fragment. HTTPS is required remotely; HTTP is
permitted only for localhost/loopback. Host/forwarding/Origin headers cannot alter
it. Clients refuse to sign challenges for a different intended origin.

Public `/v1/auth/ssh/start` and `/finish` exchange a one-use 32-byte CSPRNG
challenge (120-second TTL) and SSH Ed25519 proof for the existing bearer session
(one-hour TTL). Authenticated `/v1/auth/ssh/keys` supports list/add and
`DELETE /v1/auth/ssh/keys/{credential_id}` supports account-scoped revoke.
Use one key per machine: first authentication pins the key to that device UUID.
Revoking the key revokes that device and all its active sessions, plus sessions
derived from the key. Existing device/session/logout revocation still applies.

SSH serves authentication over HTTPS only; no port 22, SSH sync transport,
private-key upload, vault passphrase or vault operation is involved. Workers SSH
authentication is outside this ticket. See [ADR-0007](../../docs/adr/0007-native-ssh-authentication.md)
and [protocol v1](../../docs/protocol/v1.md).
