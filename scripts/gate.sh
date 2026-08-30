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
  # Each half runs in a subshell and its status is kept: a plain sequence would return only the
  # last command's, so a failure in packages/oasts vanished whenever the runtime half passed.
  local status=0
  (cd packages/oasts && pnpm exec oxfmt --check . && pnpm exec oxlint) || status=1
  (cd crates/oasts-core/runtime && pnpm exec oxfmt --check . && pnpm exec oxlint) || status=1
  return "$status"
}

rust_gate &
rust_pid=$!
ts_gate &
ts_pid=$!

status=0
wait "$rust_pid" || { echo "gate: rust half failed" >&2; status=1; }
wait "$ts_pid" || { echo "gate: ts half failed" >&2; status=1; }
exit "$status"
