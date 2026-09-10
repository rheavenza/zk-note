#!/usr/bin/env bash
set -euo pipefail

echo "==> 1. Checking format (cargo fmt --check)..."
cargo fmt --check

echo "==> 2. Running clippy (cargo clippy --workspace --all-targets --all-features -- -D warnings)..."
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> 3. Verifying locked dependencies (cargo check --workspace --locked)..."
cargo check --workspace --locked

echo "==> 4. Running workspace tests (cargo test --workspace --all-targets --all-features)..."
cargo test --workspace --all-targets --all-features

echo "==> 5. Verifying WASM target compilation (cargo check --target wasm32-unknown-unknown)..."
cargo check --target wasm32-unknown-unknown -p zk-protocol -p zk-crypto -p zk-core -p zk-wasm

echo "==> 6. Running WASM-in-Node tests (wasm-pack test --node crates/zk-wasm)..."
wasm-pack test --node crates/zk-wasm

echo "==> 7. Running Native/WASM cross-runtime crypto compatibility suite (node --test)..."
wasm-pack build --target web crates/zk-wasm --out-dir pkg
cargo build --bin native_compat_harness
node --test tests/wasm_crypto_compat.test.mjs

echo "==> 8. Running Web worker checks and test suite (npm run typecheck && npm test)..."
(cd apps/web && npm run typecheck && npm test)

echo "==> All CI quality gates passed successfully!"
