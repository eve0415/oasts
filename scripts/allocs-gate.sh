#!/usr/bin/env bash
# Drift gate for the per-stage allocation tracker.
# bench/allocs.yaml pins system-allocator counters per compile stage for every gated
# (committed: true) fixture in bench/manifest.yaml. Only allocs/deallocs counts are compared:
# byte totals and realloc counts embed the checkout's absolute path length (the loader
# canonicalizes source paths), so they are recorded as evidence but not gated. A count mismatch
# means the oasts-core compile pipeline's allocation behavior changed — a real regression (or
# a genuine, reviewable improvement) that must be re-recorded with `--update`, never silently
# absorbed.
# Runs release: the committed counters were measured under the release profile, and debug's extra
# instrumentation would make every key fail this gate for reasons unrelated to a real regression.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo run --release --quiet -p oasts-bench --bin allocs -- --check
echo "allocs-gate: bench/allocs.yaml matches the measured gated keys"
