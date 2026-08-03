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

# The tanstack artifact, report-only and outside the per-operation ceiling above: a descriptor is a
# thin wrapper over the operation it imports, so its bundle is the client operation's cost plus the
# one key binding it names, not an independent budget. Two numbers are printed — the descriptor
# bundle, and keys.ts on its own at corpus scale, which is the figure the flat-binding split exists
# to keep off every consumer who does not ask for it.
echo
echo "TanStack artifact size report (report-only, no ceiling)"
printf '%-8s  %-8s  %s\n' "raw" "gzip" "bundle"

tanstack_root="$work/tanstack-showcase-3.1"
cp -r fixtures/tanstack-showcase-3.1 "$tanstack_root"
(cd "$tanstack_root" && "$repo_root/$binary" generate --config oasts-tanstack.yaml >/dev/null 2>&1)

tanstack_entry="$tanstack_root/entry-query.ts"
printf '%s\n' \
  'export * from "./generated-tanstack/tanstack/operations/getpet.js";' \
  >"$tanstack_entry"
tanstack_bundle="$work/tanstack-one-query.mjs"
"$esbuild_bin" "$tanstack_entry" --bundle --minify --format=esm --log-level=error \
  --outfile="$tanstack_bundle"
gzip -9 -n -c "$tanstack_bundle" >"$tanstack_bundle.gz"
printf '%-8s  %-8s  %s\n' \
  "$(wc -c <"$tanstack_bundle")" "$(wc -c <"$tanstack_bundle.gz")" \
  "one query descriptor (tanstack-showcase-3.1)"

# keys.ts alone, at corpus scale. github-3.0 is the largest committed document, so this is the
# number a consumer who imports the composed `keys` object pays and a consumer who imports a leaf
# binding does not.
keys_root="$work/github-keys"
if [[ -f fixtures/github-3.0/openapi.json ]]; then
  cp -r fixtures/github-3.0 "$keys_root"
  rm -rf -- "$keys_root"/generated*
  cat >"$keys_root/oasts-tanstack.yaml" <<'YAML'
schemaVersion: 1
input:
  path: ./openapi.json
output: ./generated-tanstack
artifacts:
  types: true
  client: true
  tanstack: true
client:
  authEnforcement: types
  baseUrl:
    source: runtime
validation:
  engine: 'off'
  unchecked: allow
YAML
  if (cd "$keys_root" && "$repo_root/$binary" generate --config oasts-tanstack.yaml) \
    >"$keys_root/generate.log" 2>&1; then
    keys_file="$keys_root/generated-tanstack/tanstack/keys.ts"
    gzip -9 -n -c "$keys_file" >"$keys_file.gz"
    printf '%-8s  %-8s  %s\n' \
      "$(wc -c <"$keys_file")" "$(wc -c <"$keys_file.gz")" \
      "keys.ts standalone (github-3.0, $(grep -c '^export const' "$keys_file") bindings)"
  else
    echo "  (github-3.0 did not generate; skipping the corpus-scale keys.ts row)"
  fi
else
  echo "  (fixtures/github-3.0/openapi.json absent; skipping the corpus-scale keys.ts row)"
fi
