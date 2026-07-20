#!/usr/bin/env bash
# Report the generated one-operation client bundle size without enforcing the deferred ceiling.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root=$PWD
binary=target/debug/oasts
work=""

finish() {
  status=$?
  trap - EXIT
  if [[ -n "$work" ]]; then
    rm -rf -- "$work"
  fi
  if ((status != 0)); then
    echo "WARNING: client core runtime size report failed with status $status" >&2
  fi
  exit 0
}
trap finish EXIT

if [[ ! -x "$binary" ]]; then
  cargo build -p oasts
fi

work=$(mktemp -d)
fixture="$work/client-showcase-3.1"
entry="$fixture/entry.ts"
bundle="$work/client-core.mjs"
compressed="$bundle.gz"

cp -r fixtures/client-showcase-3.1 "$fixture"
(cd "$fixture" && "$repo_root/$binary" generate --config oasts.yaml)

printf '%s\n' \
  'import { getPetShowcase, getPetShowcaseOrThrow } from "./generated/client/operations/getpetshowcase.js";' \
  'export { getPetShowcase, getPetShowcaseOrThrow };' \
  >"$entry"

# Call the esbuild binary directly rather than through `pnpm exec`: pnpm's deps-status
# preflight hard-fails under this repo's devEngines pin even when esbuild is installed.
esbuild_bin="$repo_root/crates/oasts-core/runtime/node_modules/.bin/esbuild"
if [[ ! -x "$esbuild_bin" ]]; then
  (cd "$repo_root/crates/oasts-core/runtime" && pnpm install)
fi
"$esbuild_bin" "$entry" --bundle --minify --format=esm --outfile="$bundle"
gzip -9 -c "$bundle" >"$compressed"

raw_bytes=$(wc -c <"$bundle")
gzip_bytes=$(wc -c <"$compressed")
ceiling=3072

echo "Client core runtime size report (report-only)"
echo "raw: $((raw_bytes)) bytes"
echo "gzip: $((gzip_bytes)) bytes"
echo "ceiling: $ceiling bytes gzip"
if ((gzip_bytes > ceiling)); then
  echo "WARNING: gzip size $((gzip_bytes)) bytes exceeds the $ceiling-byte ceiling"
fi
