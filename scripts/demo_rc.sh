#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$HOME/.npm-global/bin:$PATH"
else
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "================================================================================"
echo " ZERO-KNOWLEDGE NOTES — RELEASE CANDIDATE (v1.0.0-RC1) DEMONSTRATION"
echo "================================================================================"
echo "This script executes automated end-to-end demonstrations of the two critical"
echo "acceptance criteria required for Milestone 9 release candidate gate (ZK-099):"
echo "  1. Two-Client Offline Conflict & Convergence Demo (SEC-001, SEC-006, SEC-009)"
echo "  2. Passphrase Loss, Recovery Key Unwrap, and Zero-Loss Rotation Demo (SEC-010)"
echo "================================================================================"
echo ""

cargo test -p zk-server --test release_candidate_tests -- --nocapture --test-threads=1

echo ""
echo "================================================================================"
echo " [SUCCESS] All Release Candidate verification demonstrations passed!"
echo "================================================================================"
