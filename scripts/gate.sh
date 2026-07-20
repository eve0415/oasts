#!/usr/bin/env bash
# Combined gate: Rust (fmt + clippy) and TS (oxfmt check + type-aware oxlint) halves run in
# parallel; the script fails if either half fails. This is the Claude Code Stop-hook target.
set -uo pipefail
cd "$(dirname "$0")/.."

cargo run --quiet -p oasts-gen || { echo "gate: config generation failed" >&2; exit 1; }

rust_gate() {
  cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
}

ts_gate() {
  cd packages/oasts && pnpm exec oxfmt --check . && pnpm exec oxlint
}

rust_gate &
rust_pid=$!
ts_gate &
ts_pid=$!

status=0
wait "$rust_pid" || { echo "gate: rust half failed" >&2; status=1; }
wait "$ts_pid" || { echo "gate: ts half failed" >&2; status=1; }
exit "$status"
