#!/usr/bin/env bash
# Entry-gate integrity check for the filters frozen test artifacts.
# compile-assert/cases.ts was authored from the filtering contract before any output existed and
# passed unmodified against the first generated tree. The fixture document and its configs were
# settled alongside the implementation. This gate pins each file's SHA-256 in
# fixtures/filters-entry-gate.yaml so that a later edit to any of them is a deliberate re-freeze
# rather than a quiet adjustment of the bar the implementation is held to.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fixtures/filters-entry-gate.yaml
status=0
count=0
while read -r expected path; do
  actual=$(sha256sum "$path" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "filters-gate: $path hash mismatch" >&2
    status=1
  fi
  count=$((count + 1))
done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

if [[ "$count" -eq 0 ]]; then
  echo "filters-gate: no entries parsed from $manifest" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
echo "filters-gate: all $count frozen files match"
