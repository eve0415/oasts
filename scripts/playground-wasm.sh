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
manifest=$target/versions.json
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

# Releases carry their own module from the next release onward. Fetching is best-effort: a
# missing asset means that release predates the playground, which is not an error.
released=()
if command -v gh >/dev/null 2>&1 && [[ -z ${PLAYGROUND_SKIP_RELEASES:-} ]]; then
  while read -r tag; do
    [[ -z $tag ]] && continue
    tag_version=${tag#v}
    [[ $tag_version == "$label" ]] && continue
    if gh release download "$tag" --pattern 'oasts-*.wasm' --pattern 'config-*.json' --dir "$target" --clobber >/dev/null 2>&1; then
      released+=("$tag_version")
      echo "playground-wasm: fetched $tag_version"
    fi
  done < <(gh release list --limit 50 --json tagName --jq '.[].tagName' 2>/dev/null || true)
fi

{
  printf '{\n  "current": "%s",\n  "versions": [\n' "$label"
  printf '    { "version": "%s", "url": "/playground/wasm/oasts-%s.wasm", "schema": "/playground/wasm/config-%s.json" }' "$label" "$label" "$label"
  for previous in "${released[@]}"; do
    printf ',\n    { "version": "%s", "url": "/playground/wasm/oasts-%s.wasm", "schema": "/playground/wasm/config-%s.json" }' "$previous" "$previous" "$previous"
  done
  printf '\n  ]\n}\n'
} >"$manifest"

echo "playground-wasm: wrote $manifest with $((1 + ${#released[@]})) version(s)"
