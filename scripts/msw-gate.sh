#!/usr/bin/env bash
# Entry-gate integrity check for the MSW-artifact frozen test artifacts.
# The frozen document, config, compile-assert, and handler-error vectors were authored from the
# pinned handler contract BEFORE the implementation existed; the implementation is written to
# satisfy them, never the reverse. This gate pins each file's SHA-256 in
# fixtures/msw-entry-gate.yaml — a mismatch means a frozen file was edited after the freeze, which
# invalidates the test-first guarantee.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest=fixtures/msw-entry-gate.yaml
status=0
count=0
while read -r expected path; do
  actual=$(sha256sum "$path" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "msw-gate: $path hash mismatch" >&2
    status=1
  fi
  count=$((count + 1))
done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

if [[ "$count" -eq 0 ]]; then
  echo "msw-gate: no entries parsed from $manifest" >&2
  exit 1
fi
if [[ "$status" -ne 0 ]]; then
  exit 1
fi
echo "msw-gate: all $count frozen files match"

# The supported msw range lives in three places that cannot see each other: the peer range consumers
# install against, the constants the generator warns from, and the range the README tells a reader
# to install. They only stay honest if something compares them.
source=crates/oasts-core/src/msw_peer.rs
declared=$(node -e 'process.stdout.write(require("./packages/oasts/package.json").peerDependencies.msw)')
major=$(sed -n 's/^const SUPPORTED_MAJOR: u64 = \([0-9]\+\);$/\1/p' "$source")
minor=$(sed -n 's/^const MINIMUM_MINOR: u64 = \([0-9]\+\);$/\1/p' "$source")
if [[ -z "$major" || -z "$minor" ]]; then
  echo "msw-gate: could not read the supported msw version from $source" >&2
  exit 1
fi
if [[ "$declared" != "^$major.$minor.0" ]]; then
  echo "msw-gate: peer range '$declared' does not match $source's '^$major.$minor.0'" >&2
  exit 1
fi
if ! grep -qF "needs \`msw\` $declared in your project" README.md; then
  echo "msw-gate: README does not name the supported msw range '$declared'" >&2
  exit 1
fi
echo "msw-gate: peer range, generator, and README agree on $declared"
