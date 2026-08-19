#!/usr/bin/env bash
# Stage the WebAssembly compiler and its version manifest into the docs site.
# Usage: scripts/playground-wasm.sh
#
# The playground compiles in the browser, so the module is a static asset of the site rather
# than an npm dependency. Every build stages the compiler built from this checkout; releases
# published since the playground landed are fetched alongside it, so the version selector fills
# in going forward without anything being committed as a binary.
set -euo pipefail

cd "$(dirname "$0")/.."

target=www/public/playground/wasm
manifest=$target/current.json
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

if [[ -z $version ]]; then
  echo "playground-wasm: could not read the workspace version from Cargo.toml" >&2
  exit 1
fi

# A preview build is anything that is not the tagged release of this exact version.
label=$version
if [[ -n ${PLAYGROUND_PREVIEW_LABEL:-} ]]; then
  label="$PLAYGROUND_PREVIEW_LABEL"
fi

cargo build --quiet -p oasts-wasm --profile wasm --target wasm32-unknown-unknown

# The options form is generated from the config schema, so it has to be the schema this exact
# compiler enforces — staged next to the module and selected with it.
cargo run --quiet -p oasts-gen

mkdir -p "$target"
built=target/wasm32-unknown-unknown/wasm/oasts_wasm.wasm
install -m 644 "$built" "$target/oasts-$label.wasm"
install -m 644 schemas/config-v1.json "$target/config-$label.json"


echo "playground-wasm: staged $label ($(stat -c%s "$built") B)"

# The released list lives in R2 and is written when a release publishes, so nothing here needs
# to reach for it. This file describes only the build in this checkout.
{
  printf '{\n  "version": "%s",\n  "url": "/playground/wasm/oasts-%s.wasm",\n  "schema": "/playground/wasm/config-%s.json"\n}\n' "$label" "$label" "$label"
} >"$manifest"

echo "playground-wasm: wrote $manifest"
