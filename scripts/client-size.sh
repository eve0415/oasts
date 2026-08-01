#!/usr/bin/env bash
# Report generated per-operation client bundle sizes without enforcing the deferred ceiling.
#
# One operation is not a representative sample: a bodyless unsecured GET is the cheapest shape a
# document can produce, so tuning against it alone would report "the gate got smaller" rather than
# "an operation ships only what it uses". The matrix below spans the axes that decide what links —
# request body kind and security — so a change that helps one shape and regresses another is visible.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root=$PWD
binary=target/debug/oasts
work=""

# fixture:operation-module:label — one bundle per row, each entry point importing exactly one
# operation module the way a consumer's tree-shaking bundler would see it.
cases=(
  "client-showcase-3.1:getpetshowcase:bodyless GET, unsecured"
  "client-showcase-3.1:uploadshowcase:multipart POST, unsecured"
  "client-showcase-3.1:submitformshowcase:urlencoded POST, unsecured"
  "client-showcase-3.1:contentshowcase:content-negotiated POST, unsecured"
  "auth-showcase-3.1:orheaderoauth:bodyless GET, bearer or header key"
)

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

# Call the esbuild binary directly rather than through `pnpm exec`: pnpm's deps-status
# preflight hard-fails under this repo's devEngines pin even when esbuild is installed.
esbuild_bin="$repo_root/crates/oasts-core/runtime/node_modules/.bin/esbuild"
if [[ ! -x "$esbuild_bin" ]]; then
  (cd "$repo_root/crates/oasts-core/runtime" && pnpm install)
fi

work=$(mktemp -d)
ceiling=3072

echo "Client core runtime size report (report-only)"
echo "ceiling: $ceiling bytes gzip"
printf '%-8s  %-8s  %s\n' "raw" "gzip" "operation"

over=0
for case in "${cases[@]}"; do
  fixture=${case%%:*}
  rest=${case#*:}
  module=${rest%%:*}
  label=${rest#*:}

  root="$work/$fixture"
  if [[ ! -d "$root" ]]; then
    cp -r "fixtures/$fixture" "$root"
    (cd "$root" && "$repo_root/$binary" generate --config oasts.yaml >/dev/null)
  fi

  entry="$root/entry-$module.ts"
  bundle="$work/$fixture-$module.mjs"
  printf '%s\n' \
    "export * from \"./generated/client/operations/$module.js\";" \
    >"$entry"
  "$esbuild_bin" "$entry" --bundle --minify --format=esm --log-level=error --outfile="$bundle"
  # -n drops the source filename and mtime from the gzip header: without it each row would carry
  # its own operation name in the compressed bytes, so two identical bundles would report different
  # sizes purely from name length.
  gzip -9 -n -c "$bundle" >"$bundle.gz"

  raw_bytes=$(wc -c <"$bundle")
  gzip_bytes=$(wc -c <"$bundle.gz")
  printf '%-8s  %-8s  %s (%s)\n' "$raw_bytes" "$gzip_bytes" "$module" "$label"
  if ((gzip_bytes > ceiling)); then
    over=$((over + 1))
  fi
done

if ((over > 0)); then
  echo "WARNING: $over of ${#cases[@]} operations exceed the $ceiling-byte gzip ceiling"
fi
