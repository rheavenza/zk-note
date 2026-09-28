# ZK-101 addendum — TUI server connection and native authentication

State: READY for the existing ZK-101 worker branch
Source: user request of 2026-09-28; web reference: https://github.com/rheavenza/zk-note/pull/5
PR under repair: https://github.com/rheavenza/zk-note/pull/2
Starting implementation head: `c425e1bd52cb0544c7c678db3e55d13bea8c1cf9`
Current target `master`: `46682e8722c37d5a45a6051db9a46d1f71f54786`

## Objective

Finish the TUI's server connection workflow by allowing a user to enter a server
address, authorize this terminal with an existing account session token, inspect
connection/account state, and sign out. Resolve PR #2's conflict with current
`master` on the same worker branch. Preserve the existing CLI and guarded sync
behavior. The web client in PR #5 provides the UX reference for an editable
origin, honest local-only/offline/expired status, and account controls; it does
not provide a reusable native passkey ceremony or vault linking.

## Dependencies and constraints

- ZK-101 TUI and native CLI auth (`apps/cli/src/auth.rs`, ZK-072) are present.
- PR #5 is merged to `master`; its browser passkey flow is origin/RP bound.
- ADR 0006 requires an existing valid account session token for CLI device
  authorization. Do not invent an unauthenticated token or device-provisioning
  path, expose a full token, or copy browser session storage into the terminal.
- Authentication and vault unlock remain independent. Signing in must not send
  vault passphrase, Vault Key, note plaintext, or search terms to the server.
- Account sign-in alone does not upload, link, replace, or restore a vault.
  Existing guarded sync may run only under its existing safety rules.

## Acceptance criteria

1. The TUI has a discoverable server/account view or modal with a server URL
   field, masked token field, connect/authorize action, current server/account/
   device status, sign-out action, and clear cancellation/help. The normal view
   shows whether the client is local-only, authenticated, offline, expired or
   revoked, syncing, synced, conflicted, or in error without claiming a remote
   success when no server call succeeded.
2. Connection uses the existing native `api_verify_token` and
   `api_device_authorize` behavior and the existing session persistence. Factor
   non-printing auth operations into a shared client service used by both CLI
   and TUI where overlapping logic exists. Never shell out to `zk-note login`.
3. The token is entered without echo, redacted from `Debug` and errors, erased
   from input state on success, cancel, lock, and exit, and never appears in
   logs, URLs, screenshots, or test snapshots. Credentials use the existing
   restricted storage permissions. Invalid, expired, or revoked credentials
   fail closed with actionable, secret-free status.
4. Server URL validation prevents accidental token disclosure to a malformed
   or insecure remote address. HTTPS is required for non-loopback servers;
   allow local development loopback HTTP. A server change must not silently
   reuse a previous account session or overwrite local vault data. An offline
   or failed authorization leaves the prior valid local session intact unless
   the user explicitly signs out or confirms replacing it.
5. Sign-out uses the existing server revocation semantics. If revocation fails
   or the server is offline, do not falsely report success or silently delete
   credentials needed to retry; show a truthful recoverable state.
6. The `s` shortcut remains a manual guarded sync action. The UI must not
   report `Synced` merely because the user entered an address or token. It must
   state clearly that auth does not link/restore a vault; remote bootstrap
   mismatch or absence must not silently replace a local vault.
7. Existing non-interactive CLI commands, flags, JSON shapes, exit behavior,
   and tests remain compatible. No new server protocol, crypto format, or
   plaintext persistence is introduced.
8. Merge current `master` into the worker branch and resolve PR #2's actual
   conflict in `TASKS.md` by preserving both ZK-101 review history and the
   merged web ZK-104 plus ZK-105–107 roadmap. Do not alter unrelated web code.
   A clean merge result and target-base SHA must be recorded.
9. Update CLI/TUI documentation with the server connection keys, token
   provisioning prerequisite, sign-out behavior, security limits, and the
   distinction between authentication and vault linking/sync.

## Verification and evidence

Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test -p zk-cli`, `cargo test --workspace`, `cargo build --release --bin zk-note`,
`./scripts/ci.sh`, `python3 scripts/smoke_tui.py`, and `git diff --check`.

Add tests for URL validation, masked input and erasure, valid authorization,
invalid/revoked/expired token, offline failure, previous-session preservation,
server change isolation, sign-out revocation failure, status truthfulness, and
CLI compatibility. Use a synthetic local test server and disposable encrypted
vault; do not depend on production credentials or a live public endpoint.

The worker handoff must include the merge target SHA, new head SHA, commands and
results, behavioral/test evidence for criteria 1–9, synthetic TUI capture or
TestBackend output for the account view, any gaps, and reproducibility steps.
Codex will independently review the exact new head before any verdict.

## Fallback

If a full browser-to-terminal passkey handoff is required to make token
provisioning usable, stop and propose a separate server/web device-approval
ticket. Do not implement an unauthenticated grant endpoint or display/copy a
browser bearer token. Keep the existing `zk-note login` path available and
document its prerequisite. If current `master` changes while working, report
the new base and re-merge before presenting a reviewable head.
