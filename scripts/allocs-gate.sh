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
#
# Why the largest fixtures are ungated: their emit counters are not reproducible run to run. Two
# `--update` runs over identical code move github-3.0 by ~98 allocs, github-3.0-zod by ~86, and
# stripe-3.0 by ~48. That noise floor is what disqualifies them from the gate — but it is small, so
# their recorded numbers still carry signal and a change that moves one well past it (this branch
# moved github-3.0-zod emit by -13249) must be re-recorded like any gated key. A blanket `--update`
# is the wrong instrument for that: it also rewrites the keys that only moved within the noise,
# which buries the one real delta in a diff of churn. Re-record the keys you moved.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo run --release --quiet -p oasts-bench --bin allocs -- --check
echo "allocs-gate: bench/allocs.yaml matches the measured gated keys"
