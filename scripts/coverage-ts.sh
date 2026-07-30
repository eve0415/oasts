#!/usr/bin/env bash
# Node-side coverage gate: node:test over packages/oasts/src at 100% lines/branches/functions.
# Spawned-process smoke tests live outside this gate (child processes are not instrumented).
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$repo_root/packages/oasts" && node --test \
  --experimental-test-coverage \
  --test-coverage-include='src/**' \
  --test-coverage-lines=100 \
  --test-coverage-branches=100 \
  --test-coverage-functions=100 \
  'test/*.test.ts')

# '*.ts' does not cross '/', so runtime test data under test/ is excluded from coverage.
if [[ -n "$(find "$repo_root/crates/oasts-core/runtime/test" -maxdepth 1 -name '*.test.ts' -print -quit)" ]]; then
  # --harmony-temporal is what makes the transform runtime's Temporal codecs reachable at all;
  # without it every Temporal entry point returns its temporal-unavailable failure and its happy
  # path is dead. The failure path stays covered in the same run, because the suite removes the
  # global for the length of one test.
  (cd "$repo_root/crates/oasts-core/runtime" && node --harmony-temporal --test \
    --experimental-test-coverage \
    --test-coverage-include='*.ts' \
    --test-coverage-lines=100 \
    --test-coverage-branches=100 \
    --test-coverage-functions=100 \
    'test/*.test.ts')
fi
