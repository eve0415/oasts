#!/usr/bin/env bash
# Build the browser compiler and publish it to the playground's archive.
# Usage: scripts/playground-wasm.sh [--local]
#
# The site ships no compiler of its own: every version the playground offers comes from the R2
# archive, which is why a release reaches the playground without the site being rebuilt. This
# script is what puts a build there. With --local it seeds the miniflare bucket `wrangler dev`
# reads, so a checkout can run the playground without touching the real archive.
set -euo pipefail

cd "$(dirname "$0")/.."

bucket=oasts-playground
scope=--remote
config=()

if [[ ${1:-} == "--local" ]]; then
  scope=--local
  # The local bucket belongs to the built worker config, which is what `wrangler dev` runs.
  config=(-c dist/server/wrangler.json)
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [[ -z $version ]]; then
  echo "playground-wasm: could not read the workspace version from Cargo.toml" >&2
  exit 1
fi

label=${PLAYGROUND_LABEL:-$version}

cargo build --quiet -p oasts-wasm --profile wasm --target wasm32-unknown-unknown

# The options form is generated from the config schema, so it has to be the schema this exact
# compiler enforces — stored beside the module and selected with it.
cargo run --quiet -p oasts-gen

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

built=$PWD/target/wasm32-unknown-unknown/wasm/oasts_wasm.wasm
immutable='public, max-age=31536000, immutable'

put() {
  pnpm -C www exec wrangler r2 object put "$bucket/$1" \
    --file "$2" --content-type "$3" --cache-control "$4" "$scope" "${config[@]}" >/dev/null
}

put "oasts-$label.wasm" "$built" application/wasm "$immutable"
put "config-$label.json" "$PWD/schemas/config-v1.json" application/json "$immutable"

# Read-modify-write of the one mutable object. Releases are serialised by tag, so there is no
# concurrent writer to race with. Listing is deliberately avoided: it is R2's costly class.
if ! pnpm -C www exec wrangler r2 object get "$bucket/versions.json" \
  --file "$work/existing.json" "$scope" "${config[@]}" >/dev/null 2>&1; then
  echo '{"versions":[]}' >"$work/existing.json"
fi

LABEL="$label" EXISTING="$work/existing.json" CURRENT="${PLAYGROUND_CURRENT:-}" \
  node --input-type=module >"$work/versions.json" <<'NODE'
import { readFileSync } from "node:fs";

const version = process.env.LABEL;
const existing = JSON.parse(readFileSync(process.env.EXISTING, "utf8"));
const versions = (existing.versions ?? []).filter((entry) => entry.version !== version);

versions.push({
  version,
  url: `/playground/wasm/oasts-${version}.wasm`,
  schema: `/playground/wasm/config-${version}.json`,
});

// Only a release claims the default. Anything else joins the list without displacing it —
// otherwise publishing a branch build would point every visitor at unreleased code. The
// fallback covers the first publish, when there is no default to keep.
const current = process.env.CURRENT === "1" ? version : (existing.current ?? version);

process.stdout.write(JSON.stringify({ current, versions }, null, 1));
NODE

put versions.json "$work/versions.json" application/json 'public, max-age=300'

echo "playground-wasm: published $label ($(stat -c%s "$built") B) to the $scope archive"
