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
local development origin will not appear automatically at the HTTPS origin;
the encrypted vault-link/restore flow is tracked separately in ZK-105.

## Rollback

Point the notes Funnel back to the API's port 8090 and stop `zk-notes-web`.
The API database and Chibisafe routes are unchanged. Keep the prior web
release available so the `current` symlink can be restored without rebuilding.
