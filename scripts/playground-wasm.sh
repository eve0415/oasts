#!/usr/bin/env bash
# Build the browser compiler and publish it to the playground's archive.
# Usage: scripts/playground-wasm.sh [--local | --remote]
#
# The site ships no compiler of its own: every version the playground offers comes from the R2
# archive, which is why a release reaches the playground without the site being rebuilt. This
# script is what puts a build there.
#
# The default seeds the miniflare bucket `wrangler dev` reads, so a checkout can run the
# playground — and this script can sit among the gates — without touching anything shared.
# `--remote` writes the archive every visitor reads and is therefore deliberate: it demands
# credentials and an explicit label up front, so a working tree can never quietly overwrite a
# published version's build.
set -euo pipefail

cd "$(dirname "$0")/.."

bucket=oasts-playground
scope=--local
# The local bucket belongs to the built worker config, which is what `wrangler dev` runs.
config=(-c dist/server/wrangler.json)

if (($# > 1)); then
  # Only the first argument is read, so `--remote --local` would publish remotely while the
  # operator believes the trailing --local won.
  echo "playground-wasm: expected at most one argument, got $#" >&2
  exit 1
fi

case ${1:-} in
  "" | --local) ;;
  --remote)
    scope=--remote
    config=()
    ;;
  *)
    # A misspelt --remote would otherwise fall through to the local bucket and report success,
    # leaving the operator believing the archive was updated.
    echo "playground-wasm: unknown argument '$1'; expected --local or --remote" >&2
    exit 1
    ;;
esac

if [[ $scope == --remote ]]; then
  if [[ -z ${PLAYGROUND_LABEL:-} ]]; then
    echo "playground-wasm: --remote requires PLAYGROUND_LABEL. Falling back to the workspace" \
      "version would overwrite that release's published build with this tree's." >&2
    exit 1
  fi
  if [[ -z ${CLOUDFLARE_API_TOKEN:-} || -z ${CLOUDFLARE_ACCOUNT_ID:-} ]]; then
    echo "playground-wasm: --remote requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID." \
      "Without them wrangler fails partway through, after some objects are already written." >&2
    exit 1
  fi
elif [[ ! -f www/dist/server/wrangler.json ]]; then
  echo "playground-wasm: www/dist/server/wrangler.json is missing, so there is no local bucket" \
    "to seed. Build the site first: pnpm -C www install && pnpm -C www build." >&2
  exit 1
fi

label=${PLAYGROUND_LABEL:-}
if [[ -z $label ]]; then
  label=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
  if [[ -z $label ]]; then
    echo "playground-wasm: could not read the workspace version from Cargo.toml" >&2
    exit 1
  fi
fi

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
#
# An absent manifest is normal on the first publish and starts an empty one. Any other failure
# must stop here: rebuilding from empty after a transport or credential fault would rewrite the
# archive's index without the versions already in it, and hand `current` to this build.
#
# Absence is matched on R2's own vocabulary rather than one rendering of it, because the local
# emulator and the REST API word it differently and only the emulator's wording can be tested
# from a checkout. An unrecognised message therefore stops the publish rather than emptying the
# index -- the safe direction, and the first publish into an empty bucket is the only thing it
# can wrongly refuse.
if ! pnpm -C www exec wrangler r2 object get "$bucket/versions.json" \
  --file "$work/existing.json" "$scope" "${config[@]}" >/dev/null 2>"$work/get.err"; then
  if ! grep -qE 'The specified (object )?key does not exist|NoSuchKey|code: 10007' \
    "$work/get.err"; then
    echo "playground-wasm: could not read $bucket/versions.json, and it is not merely absent." \
      "Refusing to rewrite the archive index from an empty one:" >&2
    cat "$work/get.err" >&2
    exit 1
  fi
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

echo "playground-wasm: published $label ($(stat -c%s "$built") B) to the ${scope#--} archive"
