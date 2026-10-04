# Same-origin web client on Termux

The browser must load the web app and call `/v1` on one HTTPS origin for the
server's configured WebAuthn RP ID and exact origin. A local HTTP development
page cannot authenticate against a server configured for a different HTTPS
domain. The Account panel has an editable Server address, but passkey actions
remain unavailable when the page and selected API origins differ.

The optional Termux layout serves the production web build through Caddy on a
loopback port and proxies `/v1/*` and `/health` to the native API. Tailscale
Funnel terminates HTTPS and forwards its notes port to this Caddy listener.
Other Funnel ports and applications are independent.

## Build and deploy

1. Build WASM and the web client: `wasm-pack build --target web crates/zk-wasm
   --out-dir pkg`, then `cd apps/web && npm ci && npm run build`.
2. Package only `dist/index.html` and the current `dist/assets` directory. Do
   not publish `dist/test` or compiler output from older builds.
3. Copy `scripts/notes-web.Caddyfile` to the Termux home directory as
   `notes-web.Caddyfile`. Extract the asset package into a new release directory
   under `/root/workspace/zk-notes-web/releases` inside Debian. Point
   `/root/workspace/zk-notes-web/current` to the tested release.
4. Install `scripts/termux-notes-web-run` as the runit `run` script for a
   `zk-notes-web` service, with `termux-notes-web-log-run` under `log/run`.
   Validate the Caddyfile before starting the service.
5. Verify local `http://127.0.0.1:8091/` serves the web HTML, assets load,
   `/health` reaches the API, and protected `/v1` routes still require auth.
   Move only the notes Funnel listener to port 8091, then repeat those checks
   at the configured HTTPS origin. Confirm other Funnel ports remain healthy.

The native API remains on port 8090 for direct LAN access. The browser app
should be opened at the HTTPS origin configured by `ZK_WEBAUTHN_ORIGIN`; its
Server address field defaults to that same origin. The selected address is
stored without credentials. Changing it clears the current browser session.
Browser storage is scoped to the page origin. An existing vault created on a
local development origin will not appear automatically at the HTTPS origin; use
the encrypted **link** / **restore** flow (ZK-105/ZK-107) to move a vault between
origins without exposing plaintext.

## Deployment acceptance checklist (ZK-107)

Verify each item on the target deployment before calling a release synchronized.
None of these values are secrets, but keep operator hostnames and addresses out
of committed files.

1. **API origin / same-origin behavior.** The web page and `/v1` must share one
   origin. The reverse proxy forwards `/v1/*` and `/health` to the API; the
   browser never needs a cross-origin API address for passkeys.
2. **HTTPS requirement.** Serve the app over HTTPS. `ZK_WEBAUTHN_ORIGIN` must be
   the exact browser origin including scheme and port; a plain-HTTP page cannot
   authenticate against an HTTPS RP configuration.
3. **WebAuthn RP compatibility.** `ZK_WEBAUTHN_RP_ID` must be the host's domain
   (or a registrable parent). Registration and sign-in fail closed in the browser
   before opening the authenticator when the page origin is incompatible.
4. **Encrypted storage.** Confirm notes persist as ciphertext in IndexedDB, that
   the account-scoped database is used after linking, and that locking removes
   plaintext from the page.
5. **Linking.** Sign in, then explicitly **Link vault to account**; confirm the
   upload contains only the encrypted bootstrap and crypto metadata.
6. **Restore.** On a second browser/profile, sign in and **Restore vault from
   account**, then unlock locally. Notes must be readable only after decryption.
7. **Sync.** **Sync Now** must reach a **synced** state only after a real server
   round trip; `last_sync_at` must not advance for local-only or failed operations.
8. **Offline.** With the API unreachable, edits stay **pending** and durable across
   a reload, then upload on reconnect.
9. **Conflicts.** Concurrent edits produce a visible, persisted conflict that
   survives reload and lock/unlock and is never auto-resolved.
10. **Authentication expiry.** Expiring or revoking the session leaves local notes
    usable, keeps the scoped database selected, and shows **sign in to sync**;
    re-authenticating resumes sync without losing the queued mutation ids.

Locked-pull (ciphertext pulled while the vault is locked, decrypted only after
unlock) is covered by `apps/web/test/sync-engine.test.tsx`.

## Rollback

Point the notes Funnel back to the API's port 8090 and stop `zk-notes-web`.
The API database and Chibisafe routes are unchanged. Keep the prior web
release available so the `current` symlink can be restored without rebuilding.
