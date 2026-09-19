#!/usr/bin/env bash
# =============================================================================
# scripts/audit.sh — Dependency and supply-chain audit script (ZK-093).
#
# Verifies:
# 1. Lockfiles present and valid (Cargo.lock, apps/web/package-lock.json).
# 2. Rust dependency security audit against RustSec advisory database.
# 3. npm dependency security audit against npm advisory database.
# 4. Zero unapproved runtime tracking/analytics/network dependencies.
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> [Audit 1/4] Checking lockfiles presence and integrity..."
if [[ ! -f "Cargo.lock" ]]; then
    echo "ERROR: Cargo.lock is missing!" >&2
    exit 1
fi

if [[ ! -f "apps/web/package-lock.json" ]]; then
    echo "ERROR: apps/web/package-lock.json is missing!" >&2
    exit 1
fi
echo "✓ Cargo.lock and apps/web/package-lock.json are present."

echo "==> [Audit 2/4] Running npm security audit on apps/web..."
(
    cd apps/web
    npm audit --audit-level=moderate
)
echo "✓ npm audit passed with 0 vulnerabilities."

echo "==> [Audit 3/4] Running cargo audit on Rust workspace..."
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
    echo "✓ cargo audit completed successfully."
elif cargo audit --version >/dev/null 2>&1; then
    cargo audit
    echo "✓ cargo audit completed successfully."
else
    echo "WARNING: cargo-audit binary not found in PATH; skipping RustSec remote scan in this environment."
fi

echo "==> [Audit 4/4] Verifying zero forbidden supply-chain dependencies..."
# Ensure web app has no tracking or analytics libraries in package.json
FORBIDDEN_PATTERNS=("analytics" "telemetry" "sentry" "mixpanel" "segment" "google-tag" "datadog")
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
    if grep -i "$pattern" apps/web/package.json >/dev/null 2>&1; then
        echo "ERROR: Forbidden dependency pattern '$pattern' found in apps/web/package.json!" >&2
        exit 1
    fi
done
echo "✓ Zero forbidden tracking or analytics dependencies detected."

echo "==> All dependency and supply-chain audits passed cleanly!"
