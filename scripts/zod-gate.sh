#!/usr/bin/env bash
# Entry-gate integrity check for the zod-artifact frozen test artifacts, plus the zod peer-range
# consistency check (see entry-gate.sh for what each covers).
set -euo pipefail
exec "$(dirname "$0")/entry-gate.sh" zod crates/oasts-core/src/zod_peer.rs zod
