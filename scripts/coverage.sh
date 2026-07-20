#!/usr/bin/env bash
# Coverage gate: 100% lines. Exclusions: the CLI main() glue in crates/oasts/src/main.rs, and
# crates/oasts-napi -- its #[napi] macro glue only executes inside a Node process, so its logic
# is unit-tested in cargo test but measured by the Node-side E2E suite instead of this gate.
# crates/oasts-bench is also excluded: the bench harness is a measurement tool whose correctness
# gates are its own unit tests, and its process-spawning pipeline is exercised by running the
# harness itself, not by line coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo llvm-cov --workspace --fail-under-lines 100 --ignore-filename-regex 'main\.rs|oasts-napi|oasts-bench' "$@"
