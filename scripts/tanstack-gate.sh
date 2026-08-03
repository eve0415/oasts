#!/usr/bin/env bash
# Entry-gate integrity check for the tanstack-artifact frozen test artifacts.
# The frozen documents, configs, compile-assert, and key vectors were authored from the pinned
# descriptor and key-factory contract BEFORE the implementation existed; the implementation is
# written to satisfy them, never the reverse. This gate pins each file's SHA-256 in
# fixtures/tanstack-entry-gate.yaml — a mismatch means a frozen file was edited after the freeze,
# which invalidates the test-first guarantee.
#
# Unlike msw-gate.sh and zod-gate.sh there is no peer-range consistency check here: generated
# tanstack code imports no TanStack package, so there is no version range to keep honest across the
# manifest, the generator, and the README.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fixtures/tanstack-entry-gate.yaml
status=0
count=0
while read -r expected path; do
  actual=$(sha256sum "$path" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "tanstack-gate: $path hash mismatch" >&2
    status=1
  fi
  count=$((count + 1))
done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

if [[ "$count" -eq 0 ]]; then
  echo "tanstack-gate: no entries parsed from $manifest" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
echo "tanstack-gate: all $count frozen files match"
