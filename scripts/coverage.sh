#!/usr/bin/env bash
# Coverage gate: 100% lines. Sole exclusion: the CLI main() glue in crates/oasts/src/main.rs.
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo llvm-cov --workspace --fail-under-lines 100 --ignore-filename-regex 'main\.rs' "$@"
