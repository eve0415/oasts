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
  rm -rf "$d"/generated "$d"/generated-client "$d"/generated-validators "$d"/generated-zod "$d"/generated-zod-client
  (cd "$d" && "$OLDPWD/$bin" generate --config "$cfg")
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$d"/generated*/**/*.ts
  echo "tsc --strict $label ok: $message"
  cp -r "fixtures/$f" "$d-repeat"
  rm -rf "$d-repeat"/generated "$d-repeat"/generated-client "$d-repeat"/generated-validators
  (cd "$d-repeat" && "$OLDPWD/$bin" generate --config "$cfg")
  diff -r "$d"/generated* "$d-repeat"/generated*
  echo "double-generation byte identity ok: $message"
}

generate_and_verify anchors-3.1 oasts.yaml "$work/anchors-3.1" types "anchors-3.1"
# Components named after TypeScript's global generics and after the client's own kernel imports.
# Both configs matter: the types/validators artifacts break in the module that declares the
# component, the client artifact in the operation module that imports one as a parameter type.
generate_and_verify builtin-name-shadow-3.0 oasts.yaml "$work/builtin-name-shadow-3.0" types "builtin-name-shadow-3.0"
generate_and_verify builtin-name-shadow-3.0 oasts-client.yaml "$work/client-builtin-name-shadow-3.0" client "builtin-name-shadow-3.0 (client)"
generate_and_verify defs-entry-3.1 oasts.yaml "$work/defs-entry-3.1" types "defs-entry-3.1"
generate_and_verify empty-enum-3.1 oasts.yaml "$work/empty-enum-3.1" types "empty-enum-3.1"
generate_and_verify document-root-ref-3.1 oasts.yaml "$work/document-root-ref-3.1" types "document-root-ref-3.1"
generate_and_verify inline-schema-names-3.0 oasts.yaml "$work/inline-schema-names-3.0" types "inline-schema-names-3.0"
generate_and_verify operation-name-shadow-3.0 oasts.yaml "$work/operation-name-shadow-3.0" types "operation-name-shadow-3.0"
generate_and_verify operation-name-shadow-3.0 oasts-client.yaml "$work/client-operation-name-shadow-3.0" client "operation-name-shadow-3.0 (client)"
generate_and_verify reserved-word-escape-3.1 oasts.yaml "$work/reserved-word-escape-3.1" types "reserved-word-escape-3.1"
generate_and_verify variant-name-shadow-3.0 oasts.yaml "$work/variant-name-shadow-3.0" types "variant-name-shadow-3.0"
generate_and_verify variant-name-shadow-3.0 oasts-client.yaml "$work/client-variant-name-shadow-3.0" client "variant-name-shadow-3.0 (client)"
generate_and_verify uninhabitable-allof-3.0 oasts.yaml "$work/uninhabitable-allof-3.0" client "uninhabitable-allof-3.0"

# deepObject carries one document per conformance mode, because the extended-only shapes (array,
# untyped) are a hard OASTS1419 under the strict default and so cannot share a document.
generate_and_verify deep-object-3.0 oasts.yaml "$work/deep-object-strict" client "deep-object-3.0 (strict)"
generate_and_verify deep-object-3.0 oasts-compat.yaml "$work/deep-object-extended" client "deep-object-3.0 (extended)"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-builtin-name-shadow-3.0/compile-assert/cases.ts"
echo "compile-assert matrix ok: builtin-name-shadow-3.0"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/operation-name-shadow-3.0/compile-assert/cases.ts"
echo "compile-assert matrix ok: operation-name-shadow-3.0"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/variant-name-shadow-3.0/compile-assert/cases.ts"
echo "compile-assert matrix ok: variant-name-shadow-3.0"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/uninhabitable-allof-3.0/compile-assert/cases.ts"
echo "compile-assert matrix ok: uninhabitable-allof-3.0"

for f in client-showcase-3.1 petstore-3.0 tictactoe-3.1 auth-showcase-3.1 server-variables-enum-3.1 relative-server-3.1 wire-fidelity-3.1 media-classification-3.1 multipart-response-3.0; do
  # A fixture whose client config lives in a separate file says so on disk.
  fixture_config=oasts.yaml
  if [[ -f "fixtures/$f/oasts-client.yaml" ]]; then
    fixture_config=oasts-client.yaml
  fi
  generate_and_verify "$f" "$fixture_config" "$work/client-$f" client "$f"
done

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-client-showcase-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: client-showcase-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-auth-showcase-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: auth-showcase-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-server-variables-enum-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: server-variables-enum-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-relative-server-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: relative-server-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-media-classification-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: media-classification-3.1"

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-multipart-response-3.0/compile-assert/cases.ts"
echo "compile-assert matrix ok: multipart-response-3.0"

# Webhooks showcase carries two configs. Run each with double-generation byte-identity: the
# types-only config proves webhooks/callbacks emit in a client-free artifact; the client config
# proves the same webhook/callback types coexist with the client and its typed response headers.
# The compile-assert reads the client output, which carries both the types and the client.
generate_and_verify webhooks-showcase-3.1 oasts.yaml "$work/webhooks-showcase-types" types "webhooks-showcase-3.1 (types)"
generate_and_verify webhooks-showcase-3.1 oasts-client.yaml "$work/webhooks-showcase-client" client "webhooks-showcase-3.1 (client)"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/webhooks-showcase-client/compile-assert/cases.ts"
echo "compile-assert matrix ok: webhooks-showcase-3.1"

# Validators fixtures: one fixture can carry several configs, so these run as explicit
# (fixture, config) pairs instead of joining the one-config-per-fixture client loop above.
validators_runs=(
  "media-validation-3.1 oasts.yaml"
  "validators-showcase-3.1 oasts.yaml"
  "validators-showcase-3.1 oasts-client.yaml"
  "validators-readonly-3.1 oasts.yaml"
  "validators-conjunction-ref-3.1 oasts.yaml"
  "validators-cfa-limit-3.1 oasts.yaml"
  "validators-identical-delegate-3.1 oasts.yaml"
  "variant-name-shadow-3.0 oasts.yaml"
  "petstore-3.0 oasts-validators.yaml"
  "webhooks-showcase-3.1 oasts-validators.yaml"
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

OASTS_VALIDATORS_GENERATED_ROOT="$work/validators-webhooks-showcase-3.1-oasts-validators/generated-validators" OASTS_VALIDATORS_CONFORMANCE_FIXTURE=webhooks node --test crates/oasts-core/runtime/test-conformance/
echo "validators conformance ok: webhooks-showcase-3.1"

# Zod gets its own block rather than joining the loop above: emitted zod schemas import `zod`, so
# both tsc and node need a node_modules that resolves it, and the package lives in the runtime
# workspace rather than the repo root. Symlinking it into the work tree is what makes the generated
# output loadable from a temp directory at all.
repo=$PWD
zod_work="$work/zod-validators-showcase-3.1"
cp -r fixtures/validators-showcase-3.1 "$zod_work"
rm -rf "$zod_work"/generated "$zod_work"/generated-client "$zod_work"/generated-validators "$zod_work"/generated-zod "$zod_work"/generated-zod-client
ln -s "$repo/crates/oasts-core/runtime/node_modules" "$zod_work/node_modules"
(cd "$zod_work" && "$repo/$bin" generate --config oasts-zod.yaml)
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$zod_work"/generated-zod/**/*.ts
echo "tsc --strict zod ok: validators-showcase-3.1"

cp -r fixtures/validators-showcase-3.1 "$zod_work-repeat"
rm -rf "$zod_work-repeat"/generated "$zod_work-repeat"/generated-client "$zod_work-repeat"/generated-validators "$zod_work-repeat"/generated-zod "$zod_work-repeat"/generated-zod-client
(cd "$zod_work-repeat" && "$repo/$bin" generate --config oasts-zod.yaml)
diff -r "$zod_work"/generated-zod "$zod_work-repeat"/generated-zod
echo "double-generation byte identity ok: validators-showcase-3.1 (zod)"

# The client bound to the zod engine. Emitted client bytes differ from the generated-engine build
# only in the two import lines per operation module, so this proves the binding is a directory swap
# and nothing else — and that the emitted client still typechecks against zod's entry points.
(cd "$zod_work" && "$repo/$bin" generate --config oasts-zod-client.yaml)
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$zod_work"/generated-zod-client/**/*.ts
echo "tsc --strict zod-client ok: validators-showcase-3.1"

# The zod artifact's own vectors, plus the dual-engine suite. Both roots come from the same showcase
# document under two configs, which is what makes the pairwise verdict/value comparison meaningful:
# the engines are compared against each other, not each against its own expectations.
OASTS_ZOD_GENERATED_ROOT="$zod_work/generated-zod" \
  OASTS_VALIDATORS_GENERATED_ROOT="$work/validators-validators-showcase-3.1-oasts/generated" \
  node --test crates/oasts-core/runtime/test-conformance/zod-runner.ts
echo "zod + dual-engine conformance ok: validators-showcase-3.1"

node --test crates/oasts-core/runtime/test-e2e/
