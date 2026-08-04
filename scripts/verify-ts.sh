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
# ones by path. A 6th argument links the runtime's node_modules into the tree, which the zod rows
# need and nothing else does — only the tree tsc runs on, since `--moduleResolution bundler`
# resolves from the importing file's own tree and the repeat tree is only ever diffed.
# Args: fixture config work-dir gate-label message [link-node-modules].
generate_and_verify() {
  local f=$1 cfg=$2 d=$3 label=$4 message=$5 link=${6:-}
  cp -r "fixtures/$f" "$d"
  rm -rf "$d"/generated*
  if [[ -n "$link" ]]; then
    ln -s "$PWD/crates/oasts-core/runtime/node_modules" "$d/node_modules"
  fi
  (cd "$d" && "$OLDPWD/$bin" generate --config "$cfg")
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$d"/generated*/**/*.ts
  echo "tsc --strict $label ok: $message"
  cp -r "fixtures/$f" "$d-repeat"
  rm -rf "$d-repeat"/generated*
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

# The date/time transform showcase, one row per representation plus the validation-bound build.
# Each row is a distinct emitted pipeline, not a re-run of the same one: the two Temporal modes
# convert at different positions from the Date mode, and the validated row is the only one where a
# request validator and a request conversion are emitted into the same function body.
for transform_config in oasts-date oasts-date-validated oasts-temporal oasts-plaindate; do
  generate_and_verify transform-showcase-3.1 "$transform_config.yaml" \
    "$work/transform-$transform_config" transform "transform-showcase-3.1 ($transform_config)"
done

# The `allOf` merges whose branches name a converting component. Only tsc over the emitted tree
# decides these: both surfaces of a merged object have to assign, and a merge that writes one key
# twice widens it to `Date | string`, which no assertion over the emitted string would catch.
for composition_config in oasts-date oasts-temporal; do
  generate_and_verify transform-composition-3.1 "$composition_config.yaml" \
    "$work/composition-$composition_config" transform \
    "transform-composition-3.1 ($composition_config)"
done

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

# Zod rows go through the shared helper like everything else, with the node_modules link turned on:
# emitted zod schemas import `zod`, both tsc and node need to resolve it, and the package lives in
# the runtime workspace rather than the repo root.
#
# What each row buys:
#   - zod / zod-mini: the same document under both flavors. Mini's emitted schemas import a
#     different entry point and spell catchall and the cycle annotation differently, then satisfy
#     the SAME frozen vectors classic does — running the vectors twice rather than writing a second
#     set is the point, since a mini-specific expectation file could absorb a real divergence.
#   - the two client rows: the client bound to the zod engine under each flavor. Emitted client
#     bytes differ from the generated-engine build only in the two import lines per operation
#     module, so this proves the binding is a directory swap and nothing else, and that the flavor
#     and the binding compose — the client emitter picks the artifact by directory and never names
#     an entry point.
#   - petstore under mini: the showcase has no response headers, so its output never reaches the
#     one emission site whose type identity is flavor-sensitive — the response-header schema, which
#     renders as `z.custom<T>()`, `ZodCustom` under classic and `ZodMiniCustom` under mini.
zod_runs=(
  "validators-showcase-3.1 oasts-zod.yaml zod-showcase"
  "validators-showcase-3.1 oasts-zod-mini.yaml zod-showcase-mini"
  "validators-showcase-3.1 oasts-zod-client.yaml zod-showcase-client"
  "validators-showcase-3.1 oasts-zod-mini-client.yaml zod-showcase-mini-client"
  "petstore-3.0 oasts-zod-mini.yaml zod-petstore-mini"
)
for run in "${zod_runs[@]}"; do
  read -r fixture config dir <<<"$run"
  generate_and_verify "$fixture" "$config" "$work/$dir" zod "$fixture ($config)" link
done

# The msw artifact. Emitted handlers import `msw` bare, so this row needs the node_modules link the
# zod rows use. The compile-assert runs TWICE, with exactOptionalPropertyTypes off and then on:
# the no-payload responder guard has to reject `body: undefined` under both, and an optional `never`
# still admits undefined when the flag is off, so a single run would certify only half the contract.
generate_and_verify msw-showcase-3.1 oasts-msw.yaml "$work/msw-showcase" msw "msw-showcase-3.1" link
# A media entry with no schema, or one admitting every instance, still has to produce a body type
# MSW accepts. This is the shape real vendor documents hit and the showcase does not.
generate_and_verify msw-unconstrained-body-3.1 oasts-msw.yaml "$work/msw-unconstrained" msw \
  "msw-unconstrained-body-3.1" link
generate_and_verify msw-enum-parameters-3.1 oasts-msw.yaml "$work/msw-enum-parameters" msw \
  "msw-enum-parameters-3.1" link
generate_and_verify msw-openapi-msw-3.1 oasts-msw.yaml "$work/msw-openapi-msw" msw \
  "msw-openapi-msw-3.1" link
# The response surface under a date/time transform. The request surface is refused by name
# (OASTS1508/OASTS1509), so this document declares responses only: the handler declares the
# application type and `JSON.stringify` produces the wire the client's codecs parse.
generate_and_verify transform-msw-3.1 oasts-msw.yaml "$work/transform-msw" msw \
  "transform-msw-3.1" link

# The tanstack artifact. Descriptors import no TanStack package, so unlike the msw and zod rows this
# one needs no node_modules link — if it ever does, something started depending on a peer.
generate_and_verify tanstack-showcase-3.1 oasts-tanstack.yaml "$work/tanstack-showcase" tanstack \
  "tanstack-showcase-3.1"
# The same document under a non-string date/time representation. A query key must hold wire values,
# so the descriptor encodes before it keys — and so must the invalidation list, or a mutation would
# name an entity key holding an application value that no query ever stored.
generate_and_verify tanstack-showcase-3.1 oasts-tanstack-date.yaml "$work/tanstack-showcase-date" \
  tanstack "tanstack-showcase-3.1 (date)"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
  --moduleResolution bundler "$work/tanstack-showcase/compile-assert/cases.ts"
echo "compile-assert matrix ok: tanstack-showcase-3.1"

# The two key-factory naming diagnostics, asserted on exit code rather than only in unit tests: the
# frozen documents exist to be generable (or not) end to end, and a gate that never runs them would
# let the fixtures rot.
cp -r fixtures/tanstack-segment-collision-3.1 "$work/tanstack-collision"
if (cd "$work/tanstack-collision" && "$OLDPWD/$bin" generate --config oasts-tanstack.yaml) \
  >"$work/tanstack-collision.log" 2>&1; then
  echo "verify-ts: the colliding path-segment document generated instead of failing" >&2
  exit 1
fi
grep -q 'OASTS1512' "$work/tanstack-collision.log" \
  || { echo "verify-ts: colliding segments did not report OASTS1512" >&2; exit 1; }
grep -q 'naming.overrides.pathSegments' "$work/tanstack-collision.log" \
  || { echo "verify-ts: the collision diagnostic named no resolution" >&2; exit 1; }
echo "segment collision refused: tanstack-segment-collision-3.1"

generate_and_verify tanstack-segment-override-3.1 oasts-tanstack.yaml "$work/tanstack-override" \
  tanstack "tanstack-segment-override-3.1"
(cd "$work/tanstack-override" && "$OLDPWD/$bin" generate --config oasts-tanstack.yaml) \
  >"$work/tanstack-override.log" 2>&1
grep -q 'OASTS1513' "$work/tanstack-override.log" \
  || { echo "verify-ts: an unmatched pathSegments override did not warn" >&2; exit 1; }
echo "segment override resolves the collision and warns on an unmatched key"

# Configured artifact directories, nested. Everything above runs at the default one-segment layout,
# where a hardcoded `../` count and a real relative-path computation are indistinguishable — these
# two rows are the ones that tell them apart. The tanstack showcase relocates the whole
# cross-artifact graph at once (types, client, codecs, tanstack, validators, zod and the runtime);
# the msw showcase covers the two depths msw imports the types artifact from. tsc resolving the
# emitted tree is the proof: every specifier is computed from where its file actually landed.
generate_and_verify tanstack-showcase-3.1 oasts-directories.yaml "$work/directories-tanstack" \
  directories "tanstack-showcase-3.1 (relocated artifacts)" link
generate_and_verify msw-showcase-3.1 oasts-directories.yaml "$work/directories-msw" \
  directories "msw-showcase-3.1 (relocated artifacts)" link

# The frozen key vectors, against both representations at once: the pairing is the point, since the
# transform vectors assert that an application value in and a wire string out land on the same
# cache entry the string-mode run produced.
OASTS_TANSTACK_GENERATED_ROOT="$work/tanstack-showcase/generated-tanstack" \
  OASTS_TANSTACK_DATE_GENERATED_ROOT="$work/tanstack-showcase-date/generated-tanstack-date" \
  node --test crates/oasts-core/runtime/test-conformance/tanstack-keys-runner.ts
echo "tanstack key vectors ok: tanstack-showcase-3.1"

OASTS_TANSTACK_GENERATED_ROOT="$work/tanstack-showcase/generated-tanstack" \
  node --test crates/oasts-core/runtime/test-e2e/tanstack.test.ts
echo "tanstack descriptors drive a real query client ok: tanstack-showcase-3.1"

# Both the compile-assert AND the emitted tree are typechecked under exactOptionalPropertyTypes off
# and on. The compile-assert needs it because the no-payload responder guard has to reject
# `body: undefined` either way. The emitted tree needs it because a consumer may well have the flag
# on, and a projected parameter group that is only valid with it off would not compile for them —
# `generate_and_verify` alone runs with it off and would never notice.
for exact_optional in false true; do
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
    --moduleResolution bundler --exactOptionalPropertyTypes "$exact_optional" \
    "$work/msw-showcase/compile-assert/cases.ts"
  echo "compile-assert matrix ok: msw-showcase-3.1 (exactOptionalPropertyTypes=$exact_optional)"
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
    --moduleResolution bundler --exactOptionalPropertyTypes "$exact_optional" \
    "$work/msw-enum-parameters/compile-assert/cases.ts"
  echo "compile-assert matrix ok: msw-enum-parameters-3.1 (exactOptionalPropertyTypes=$exact_optional)"
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
    --moduleResolution bundler --exactOptionalPropertyTypes "$exact_optional" \
    --noUnusedLocals --noUnusedParameters \
    "$work/msw-openapi-msw/compile-assert/cases.ts"
  echo "compile-assert matrix ok: msw-openapi-msw-3.1 (exactOptionalPropertyTypes=$exact_optional)"
  for tree in msw-showcase msw-unconstrained msw-enum-parameters msw-openapi-msw; do
    pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
      --moduleResolution bundler --exactOptionalPropertyTypes "$exact_optional" \
      --noUnusedLocals --noUnusedParameters \
      "$work/$tree"/generated-msw/**/*.ts
    echo "emitted tree ok: $tree (exactOptionalPropertyTypes=$exact_optional)"
  done
done

# An assertion about coverage rather than a run, so it sits outside the loop: if petstore ever stops
# emitting a response-header schema, the row above silently stops testing what it is there for.
grep -rq 'z.custom<' "$work/zod-petstore-mini/generated-zod-mini/zod/operations" \
  || { echo "verify-ts: petstore mini output no longer covers the response-header schema" >&2; exit 1; }

# The zod artifact's own vectors, plus the dual-engine suite. Both roots come from the same showcase
# document under two configs, which is what makes the pairwise verdict/value comparison meaningful:
# the engines are compared against each other, not each against its own expectations.
for flavor in zod-showcase/generated-zod zod-showcase-mini/generated-zod-mini; do
  OASTS_ZOD_GENERATED_ROOT="$work/$flavor" \
    OASTS_VALIDATORS_GENERATED_ROOT="$work/validators-validators-showcase-3.1-oasts/generated" \
    node --test crates/oasts-core/runtime/test-conformance/zod-runner.ts
  echo "zod + dual-engine conformance ok: validators-showcase-3.1 ($flavor)"
done

node --test crates/oasts-core/runtime/test-e2e/
