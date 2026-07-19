#!/usr/bin/env bash
# Node-side coverage gate: node:test over packages/oasts/src at 100% lines/branches/functions.
# Spawned-process smoke tests live outside this gate (child processes are not instrumented).
set -euo pipefail
cd "$(dirname "$0")/../packages/oasts"
exec node --test \
  --experimental-test-coverage \
  --test-coverage-include='src/**' \
  --test-coverage-lines=100 \
  --test-coverage-branches=100 \
  --test-coverage-functions=100 \
  'test/*.test.ts'
