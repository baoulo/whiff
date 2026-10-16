#!/usr/bin/env bash
# Local checks that mirror .github/workflows/ci.yml
# (fmt, clippy, test, docs, coverage, repo checks, each-feature, MSRV, wasm,
# deny/audit, fuzz smoke). Optional tools are skipped with an install hint.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MSRV="1.88"
SKIPPED=()

run() {
  echo ""
  echo "==> $*"
  "$@"
}

skip() {
  echo ""
  echo "==> $1 (skipped — $2)"
  SKIPPED+=("$1")
}

has_toolchain() {
  rustup toolchain list 2>/dev/null | grep -q "^$1"
}

# --- lint -------------------------------------------------------------------
run cargo fmt --all -- --check
(cd fuzz && run cargo fmt -- --check)
run cargo clippy --all-targets --features dev -- -D warnings
run cargo clippy --all-targets --no-default-features --features common -- -D warnings

# --- test (`dev` implies `full`: every extractor, the CLI and whiff-dev) -----
run cargo test --features dev
run cargo test --no-default-features --features common --lib --tests
RUSTDOCFLAGS="-D warnings" run cargo doc --no-deps --all-features

# --- coverage ---------------------------------------------------------------
echo ""
echo "==> cargo llvm-cov (CI gate: ≥80% lines)"
if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo "error: cargo-llvm-cov is required. Install with:" >&2
  echo "  rustup component add llvm-tools-preview" >&2
  echo "  cargo install cargo-llvm-cov" >&2
  exit 1
fi
if ! cargo llvm-cov --features dev --lcov --output-path lcov.info \
  --ignore-filename-regex 'src/main\.rs|src/bin/' \
  --fail-under-lines 80; then
  echo "error: line coverage is below 80% — CI Coverage will fail." >&2
  exit 1
fi

# --- repo checks: catalogue, dependency budget, plugin boundary --------------
run cargo run -q --features dev --bin whiff-dev -- catalogue --check
run cargo run -q --features dev --bin whiff-dev -- check-deps
run cargo run -q --features dev --bin whiff-dev -- check-boundary

# --- each feature on its own -------------------------------------------------
if cargo hack --version >/dev/null 2>&1; then
  run cargo hack check --each-feature --no-dev-deps
else
  skip "cargo hack check --each-feature" "install with: cargo install cargo-hack"
fi

# --- MSRV ------------------------------------------------------------------
if has_toolchain "$MSRV"; then
  run rustup run "$MSRV" cargo check --features full,cli
else
  skip "MSRV $MSRV check" "install with: rustup toolchain install $MSRV --profile minimal"
fi

# --- wasm --------------------------------------------------------------------
if rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  run cargo build --lib --target wasm32-unknown-unknown --no-default-features --features full
else
  skip "wasm32 build" "install with: rustup target add wasm32-unknown-unknown"
fi

# --- licences and advisories --------------------------------------------------
run cargo deny check

if cargo audit --version >/dev/null 2>&1; then
  run cargo audit
else
  skip "cargo audit" "install with: cargo install cargo-audit"
fi

# --- fuzz smoke ------------------------------------------------------------------
if has_toolchain nightly && cargo fuzz --version >/dev/null 2>&1; then
  (cd fuzz && RUSTFLAGS="" run cargo +nightly fuzz run extract -- -max_total_time="${FUZZ_SECONDS:-60}")
else
  skip "fuzz smoke" "install with: rustup toolchain install nightly && cargo install cargo-fuzz"
fi

echo ""
if [ ${#SKIPPED[@]} -eq 0 ]; then
  echo "All CI checks passed."
else
  echo "All CI checks passed, except ${#SKIPPED[@]} skipped (CI still runs them):"
  printf '  - %s\n' "${SKIPPED[@]}"
fi
