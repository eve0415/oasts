#!/usr/bin/env bash
# Entry-gate integrity check for a named set of frozen test artifacts.
# Frozen vector/fixture files are authored from a pinned contract BEFORE the implementation that
# satisfies them exists, never the reverse. This gate pins each file's SHA-256 in
# fixtures/<name>-entry-gate.yaml — a mismatch means a frozen file was edited after the freeze,
# which invalidates the test-first guarantee.
#
# Usage: entry-gate.sh <name> [peer-source-path peer-package-name]
# The optional peer arguments add a consistency check across three places that otherwise cannot
# see each other: the peer dependency range consumers install against
# (packages/oasts/package.json), the SUPPORTED_MAJOR/MINIMUM_MINOR constants the generator warns
# from (peer-source-path), and the range README.md tells a reader to install.
#
# Usage: entry-gate.sh   (no arguments)
# Sweeps every fixtures/*-entry-gate.yaml manifest that doesn't already have its own standalone
# wrapper script (msw-gate.sh, zod-gate.sh — those cover "msw" and "zod" themselves, with their
# extra peer-range check). This is what runs when something globs scripts/*.sh directly, so that
# path still checks every freeze rather than silently dropping the ones folded in here.
set -euo pipefail
cd "$(dirname "$0")/.."

check_manifest() {
  local name=$1
  local manifest="fixtures/${name}-entry-gate.yaml"
  local status=0
  local count=0
  local expected path actual
  while read -r expected path; do
    actual=$(sha256sum "$path" | cut -d' ' -f1)
    if [[ "$actual" != "$expected" ]]; then
      echo "${name}-gate: $path hash mismatch" >&2
      status=1
    fi
    count=$((count + 1))
  done < <(awk '/^  - path: /{p=$3} /^    sha256: /{print $2, p}' "$manifest")

  if [[ "$count" -eq 0 ]]; then
    echo "${name}-gate: no entries parsed from $manifest" >&2
    return 1
  fi
  if [[ "$status" -ne 0 ]]; then
    return 1
  fi
  echo "${name}-gate: all $count frozen files match"
}

peer_range_check() {
  local name=$1
  local source=$2
  local package=$3
  local declared major minor
  declared=$(node -e "process.stdout.write(require('./packages/oasts/package.json').peerDependencies[process.argv[1]])" "$package")
  major=$(sed -n 's/^const SUPPORTED_MAJOR: u64 = \([0-9]\+\);$/\1/p' "$source")
  minor=$(sed -n 's/^const MINIMUM_MINOR: u64 = \([0-9]\+\);$/\1/p' "$source")
  if [[ -z "$major" || -z "$minor" ]]; then
    echo "${name}-gate: could not read the supported $package version from $source" >&2
    return 1
  fi
  if [[ "$declared" != "^$major.$minor.0" ]]; then
    echo "${name}-gate: peer range '$declared' does not match $source's '^$major.$minor.0'" >&2
    return 1
  fi
  if ! grep -qF "needs \`$package\` $declared in your project" README.md; then
    echo "${name}-gate: README does not name the supported $package range '$declared'" >&2
    return 1
  fi
  echo "${name}-gate: peer range, generator, and README agree on $declared"
}

if [[ $# -eq 0 ]]; then
  status=0
  for manifest in fixtures/*-entry-gate.yaml; do
    name=$(basename "$manifest" -entry-gate.yaml)
    case "$name" in
      msw | zod) continue ;;
    esac
    check_manifest "$name" || status=1
  done
  exit "$status"
fi

check_manifest "$1"
if [[ $# -ge 3 ]]; then
  peer_range_check "$1" "$2" "$3"
fi
