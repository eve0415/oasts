#!/usr/bin/env bash
# Entry-gate integrity check for the date/time transform frozen test artifacts.
# The frozen vector file was authored from the pinned transform contract BEFORE the implementation
# existed; the implementation is written to satisfy it, never the reverse. This gate pins each
# file's SHA-256 in fixtures/transform-entry-gate.yaml — a mismatch means a frozen file was edited
# after the freeze, which invalidates the test-first guarantee.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fixtures/transform-entry-gate.yaml
status=0
count=0
while read -r expected path; do
  actual=$(sha256sum "$path" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "transform-gate: $path hash mismatch" >&2
    status=1
  fi
  count=$((count + 1))
done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

if [[ "$count" -eq 0 ]]; then
  echo "transform-gate: no entries parsed from $manifest" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
echo "transform-gate: all $count frozen files match"
