#!/usr/bin/env bash
# Typecheck generated fixture output under tsc --strict.
# Usage: scripts/verify-ts.sh (needs node/pnpm; run after `cargo build`)
# Uses the workspace-pinned typescript via pnpm exec: the repo's devEngines requires pnpm
# (npm/npx hard-fail on it), and a pinned compiler keeps this gate deterministic.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=target/debug/oasts
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pnpm exec tsc -p crates/oasts-core/runtime
for f in petstore-3.0 tictactoe-3.1; do
  cp -r "fixtures/$f" "$work/$f"
  (cd "$work/$f" && "$OLDPWD/$bin" generate)
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/$f"/generated/types/**/*.ts
  echo "tsc --strict ok: $f"
done

shopt -s globstar

# Shared body for the client and validators fixture checks: copy the fixture, strip any prior
# generated output, generate under one config and typecheck it, then regenerate into a sibling dir
# and diff to prove generation is byte-stable. The gate label and message differ per caller, so they
# are passed in; the working-dir name is the caller's to choose because later steps reopen specific
# ones by path. Args: fixture config work-dir gate-label message.
generate_and_verify() {
  local f=$1 cfg=$2 d=$3 label=$4 message=$5
  cp -r "fixtures/$f" "$d"
  rm -rf "$d"/generated "$d"/generated-client "$d"/generated-validators
  (cd "$d" && "$OLDPWD/$bin" generate --config "$cfg")
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$d"/generated*/**/*.ts
  echo "tsc --strict $label ok: $message"
  cp -r "fixtures/$f" "$d-repeat"
  rm -rf "$d-repeat"/generated "$d-repeat"/generated-client "$d-repeat"/generated-validators
  (cd "$d-repeat" && "$OLDPWD/$bin" generate --config "$cfg")
  diff -r "$d"/generated* "$d-repeat"/generated*
  echo "double-generation byte identity ok: $message"
}

for f in client-showcase-3.1 petstore-3.0 tictactoe-3.1 auth-showcase-3.1; do
  # A fixture whose client config lives in a separate file says so on disk.
  fixture_config=oasts.yaml
  if [[ -f "fixtures/$f/oasts-client.yaml" ]]; then
    fixture_config=oasts-client.yaml
  fi
  generate_and_verify "$f" "$fixture_config" "$work/client-$f" client "$f"
done

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-auth-showcase-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: auth-showcase-3.1"

# Validators fixtures: one fixture can carry several configs, so these run as explicit
# (fixture, config) pairs instead of joining the one-config-per-fixture client loop above.
validators_runs=(
  "validators-showcase-3.1 oasts.yaml"
  "validators-showcase-3.1 oasts-client.yaml"
  "validators-readonly-3.1 oasts.yaml"
  "petstore-3.0 oasts-validators.yaml"
)
for run in "${validators_runs[@]}"; do
  f=${run% *}
  cfg=${run#* }
  generate_and_verify "$f" "$cfg" "$work/validators-$f-${cfg%.yaml}" validators "$f ($cfg)"
done

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/validators-validators-showcase-3.1-oasts/compile-assert/cases.ts"
echo "compile-assert matrix ok: validators-showcase-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/validators-validators-readonly-3.1-oasts/compile-assert/cases.ts"
echo "compile-assert matrix ok: validators-readonly-3.1"

OASTS_VALIDATORS_GENERATED_ROOT="$work/validators-validators-showcase-3.1-oasts/generated" node --test crates/oasts-core/runtime/test-conformance/
echo "validators conformance ok: validators-showcase-3.1"

# The showcase schemas carry no readOnly/writeOnly, so its vectors never execute the
# request/response position-variant validators. Run the same harness against validators-readonly-3.1
# with the readonly vector set to exercise them (the request variant accepting a body that the
# neutral validator rejects is the exact bug this guards).
OASTS_VALIDATORS_GENERATED_ROOT="$work/validators-validators-readonly-3.1-oasts/generated" OASTS_VALIDATORS_CONFORMANCE_FIXTURE=readonly node --test crates/oasts-core/runtime/test-conformance/
echo "validators conformance ok: validators-readonly-3.1"

node --test crates/oasts-core/runtime/test-e2e/
