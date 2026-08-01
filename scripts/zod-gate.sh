#!/usr/bin/env bash
# Entry-gate integrity check for the zod-artifact frozen test artifacts.
# The frozen matrix/vector/fixture files were authored from the pinned zod contract BEFORE the
# implementation existed; the implementation is written to satisfy them, never the reverse. This
# gate pins each file's SHA-256 in fixtures/zod-entry-gate.yaml — a mismatch means a frozen file was
# edited after the freeze, which invalidates the test-first guarantee.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fixtures/zod-entry-gate.yaml
status=0
count=0
while read -r expected path; do
  actual=$(sha256sum "$path" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "zod-gate: $path hash mismatch" >&2
    status=1
  fi
  count=$((count + 1))
done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

if [[ "$count" -eq 0 ]]; then
  echo "zod-gate: no entries parsed from $manifest" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
echo "zod-gate: all $count frozen files match"

# The supported zod range lives in two places that cannot see each other: the peer range consumers
# install against, and the constant the generator warns from. They only stay honest if something
# compares them.
source=crates/oasts-core/src/zod_peer.rs
declared=$(node -e 'process.stdout.write(require("./packages/oasts/package.json").peerDependencies.zod)')
major=$(sed -n 's/^const SUPPORTED_MAJOR: u64 = \([0-9]\+\);$/\1/p' "$source")
minor=$(sed -n 's/^const MINIMUM_MINOR: u64 = \([0-9]\+\);$/\1/p' "$source")
if [[ -z "$major" || -z "$minor" ]]; then
  echo "zod-gate: could not read the supported zod version from $source" >&2
  exit 1
fi
if [[ "$declared" != "^$major.$minor.0" ]]; then
  echo "zod-gate: peer range '$declared' does not match $source's '^$major.$minor.0'" >&2
  exit 1
fi
if ! grep -qF "needs \`zod\` $declared in your project" README.md; then
  echo "zod-gate: README does not name the supported zod range '$declared'" >&2
  exit 1
fi
echo "zod-gate: peer range, generator, and README agree on $declared"
