#!/usr/bin/env bash
# Entry-gate integrity check for the MSW-artifact frozen test artifacts, plus the msw peer-range
# consistency check (see entry-gate.sh for what each covers).
set -euo pipefail
exec "$(dirname "$0")/entry-gate.sh" msw crates/oasts-core/src/msw_peer.rs msw
