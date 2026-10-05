# ZK-108 Argon2id feasibility — BLOCKED / SPEC QUESTION

Measured on 2026-10-04, from base
`93a8f408ddb277555a1d4eb4b766ac32fe6a7866`.
The operator explicitly confirmed **Workers Free, 10 ms CPU per request**.

## Decision

Operator decision recorded on 2026-10-05: **retain existing passkey behavior and
defer ZK-108 for now**. Username/password and further web expansion are on hold;
issue #14 / ZK-109–ZK-112 is the active native/TUI remote multi-device milestone.
This PR is a feasibility/blocker record only. ZK-108 remains `BLOCKED / SPEC
QUESTION`, and issue #9 must stay open rather than being closed as implemented.


Stop ZK-108 before adding password endpoints, credentials, migrations, or UI.
All five tested OWASP Argon2id parameter sets exceeded the required CPU budget
in the project's local workerd execution environment. Do not lower password
hashing strength to fit Workers Free. This is a measured feasibility blocker,
not a completed password-auth implementation.

The primary production candidate was Argon2id v19, memory 19,456 KiB (19 MiB),
time cost 2, parallelism 1, 32-byte output and a fresh 16-byte CSPRNG salt.
No production parameters have been deployed. No weaker test parameters exist.
The other configurations below are OWASP-listed memory/time tradeoffs, not
weakened test settings. These server-password candidates were chosen independently
of the client vault KDF's 64 MiB / 3 iterations.

Guidance checked on 2026-10-04:

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id): server-password Argon2id baseline and memory/time alternatives.
- [Cloudflare Worker limits](https://developers.cloudflare.com/workers/platform/limits/): Workers Free has 10 ms CPU per invocation and 128 MB isolate memory; Paid permits a substantially larger CPU budget.
- [RustCrypto Argon2 0.5.3](https://docs.rs/argon2/0.5.3/argon2/): PHC encoded hashes and library `PasswordVerifier` API.

## Measured results

AMD Ryzen 5 7600X, x86_64 Linux; Rust 1.98.1; Node 26.10.0;
RustCrypto `argon2` 0.5.3; wasm-bindgen 0.2.128; wasm-opt 132 with `-O`,
matching worker-build 0.8.6's default optimization; Miniflare
5.20260921.0-alpha; workerd 1.20260921.1; compatibility date 2026-09-01.

All rows use Argon2id v19 and parallelism 1. Native values are mean wall time
for five warm samples, after discarding the first of six. Worker phase values
are mean process CPU for those five warm samples. Aggregate Worker CPU includes
six hashes, six correct-password verifications and six wrong-password
verifications (18 separate requests).

| Memory KiB | Iterations | Native hash ms | Native verify ms | Worker hash CPU ms | Worker verify CPU ms | Worker aggregate CPU / operation ms |
| --- | --- | --- | --- | --- | --- | --- |
| 47104 | 1 | 12.91 | 12.59 | 28 | 24 | 27.22 |
| 19456 | 2 | 8.62 | 8.91 | 20 | 20 | 20.56 |
| 12288 | 3 | 7.86 | 7.93 | 20 | 20 | 18.89 |
| 9216 | 4 | 7.74 | 7.92 | 18 | 20 | 18.33 |
| 7168 | 5 | 7.52 | 7.36 | 14 | 20 | 17.78 |

The isolated workerd process's `/proc/<pid>/stat` user+system CPU counters
are read by the host. `CLK_TCK=100` means a 10 ms accounting quantum; individual
phase measurements are coarse. Aggregate measurements reduce that uncertainty
to less than 0.56 ms per operation. Eighteen empty health requests used 10 ms
CPU total (~0.56 ms/request); even subtracting this baseline leaves every
configuration over 10 ms. The smallest aggregate was 320 ms across 18 operations,
against 180 ms total allowed by a 10 ms per-operation budget. D1, authorization,
credential lookup, rate limiting and session issuance are absent from the probe
and would need additional request budget.

Raw evidence (synthetic credentials only, no verifier/token/password output):

- [Native samples](ZK-108-evidence/native-argon2.jsonl)
- [Local workerd samples and aggregate CPU](ZK-108-evidence/workerd-argon2.jsonl)

## Limits of the evidence

This is actual WASM execution in local **workerd**, not native Rust substituted
for a Worker test. Miniflare does not enforce the deployed Free-plan CPU quota.
The probe returned HTTP 200 locally; no remote Error 1102 is claimed. Hardware
and deployed scheduling can differ. These results do not prove impossibility on
every Cloudflare host, but do not establish safe operation within the required
budget, so the acceptance gate cannot pass. No staging/production deployment,
DNS change, account upgrade or remote CPU-limit smoke was performed. Peak isolate
memory was not profiled because CPU already blocks feasibility.

## Reproduction

The isolated crate is outside the application workspace and has its own pinned
lockfile. It is never imported by server/client code, Wrangler configuration,
or production deployment scripts. It only uses an obvious synthetic password.
The Worker retains a probe verifier in ephemeral isolate memory and returns only
success and encoded parameter names. No application account, D1 or vault is used.

From the repository root, with Rust, the WASM target, wasm-pack,
matching wasm-bindgen CLI, wasm-opt, and installed Worker Node dependencies:

```bash
cargo test --locked --manifest-path apps/cloudflare-worker/tests/argon2-probe/Cargo.toml
cargo fmt --manifest-path apps/cloudflare-worker/tests/argon2-probe/Cargo.toml --check
cargo clippy --locked --manifest-path apps/cloudflare-worker/tests/argon2-probe/Cargo.toml --all-targets -- -D warnings
cargo run --locked --release --manifest-path apps/cloudflare-worker/tests/argon2-probe/Cargo.toml
wasm-pack build apps/cloudflare-worker/tests/argon2-probe --target web --release --locked
node apps/cloudflare-worker/tests/argon2-probe.mjs
```

The Node CPU-accounting probe requires Linux `/proc` and permission to spawn
local workerd. It fails visibly if exactly one child workerd cannot be identified.
On this restricted host, matching cached worker-build tools were used with
`wasm-pack --mode no-install`; dependencies were resolved offline. Network access
and local listener tests required sandbox escalation. No credentials were read.

## BLOCKED / SPEC QUESTION

Task: ZK-108.

Reason: Secure tested Argon2id verification exceeds the explicitly required
Workers Free 10 ms CPU budget in local workerd.

Relevant invariant/spec section: MASTER_SPEC §4 authentication/encryption
separation, §2 P-006 conservative cryptography; ticket criterion 12; user instruction
to stop rather than weaken Argon2id.

Options:

1. Explicitly approve Workers Paid with a sufficient bounded CPU budget, then
   rerun feasibility including production backend overhead and abuse controls.
2. Keep ciphertext/sync on Workers Free, move account-password verification to a
   trusted native authentication service. This requires a separately approved
   authentication trust/session integration decision and availability design.
3. Keep passkey-only authentication on Workers Free and defer password auth.

Recommended option for now (selected operator decision): option 3, retain existing
passkey behavior and defer ZK-108 while issue #14 / ZK-109–ZK-112 proceeds.
Workers Paid remains a documented future alternative if username/password parity
on both backends is resumed. Resuming password authentication requires a separate
explicit operator/spec decision and renewed feasibility checks; no plan or
architecture change is made here.

## Acceptance mapping

| Ticket criterion | Implementation/test/evidence |
| --- | --- |
| 1 Web password register/login + passkey UX | Blocked; no password UI added. Existing passkey UX retained. |
| 2 Common account/session authorization | Blocked; existing session code untouched. |
| 3 Separate credential storage, no raw persistence/logging | No credential schema added; probe uses synthetic data and prints only timing/parameters. |
| 4 Vetted Argon2id, unique salt, PHC/version/library verification | Isolated probe `src/lib.rs` and `production_parameters_and_verification` test; production integration blocked. |
| 5 Native/Worker password endpoint parity | Blocked; no password endpoints added. Existing shared contract remains a regression gate. |
| 6 Append-only native/D1 uniqueness migrations | Blocked; no migrations added or changed. |
| 7 Generic login failures + bounded brute force | Blocked; no password login service exposed. |
| 8 Browser password non-persistence | No password browser inputs/adapter/context added. |
| 9 Fail-visible sign-out/revocation | Existing implementation untouched; existing regression suites rerun. |
| 10 Password-account passkey enrollment | Blocked; password accounts do not yet exist. |
| 11 Auth cannot automatically link/restore/unlock vault | Application code unchanged; probe has no vault or client-crypto dependency. |
| 12 Stop on Worker Argon2 budget failure | Satisfied: measured five secure parameter sets in local workerd; task marked BLOCKED / SPEC QUESTION. |

Quality-gate results are recorded in the ticket after verification completes.
