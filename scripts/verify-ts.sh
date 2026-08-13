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

# The consumer compiler-flag matrix. None of these five flags is part of `strict`, so
# output a consumer with a stricter tsconfig cannot compile passes a `--strict`-only gate. The claim
# the artifacts make is that their output compiles in the consumer's project rather than in ours, so
# the bar is checked where every other output contract in this repo is checked: over an emitted tree.
#
# exactOptionalPropertyTypes runs off AND on. On-only would admit a shape valid only *with* the
# flag, which breaks consumers who have it off — the mirror of the hole the msw block below closes.
#
# This list is the contract. A claim made anywhere else that the gate does not check here is
# exactly the drift these rows exist to end.
#
# Args: label exact-optional file... — the files come last because a tree expands to many of them.
strict_flag_matrix() {
  local label=$1 exact_optional=$2
  shift 2
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
    --moduleResolution bundler --noUncheckedIndexedAccess --noUnusedLocals --noUnusedParameters \
    --exactOptionalPropertyTypes "$exact_optional" --noImplicitOverride \
    "$@"
  echo "consumer flag matrix ok: $label (exactOptionalPropertyTypes=$exact_optional)"
}

# Every emitted component file must be named by some other file in the same tree. A component
# the pruner keeps but nothing imports is a disagreement between two walks: the pruner keeps any
# component a `$ref` names anywhere, so the emitter's import walk has to name the same set the
# renderer does. It did not for `allOf`, whose `$ref` members were inlined by body — the file was
# written, and the field that should have pointed at it restated its shape anonymously instead.
#
# Only sound while pruning is on: `filters.orphans: true` means the document deliberately keeps
# components no operation reaches, so those fixtures opt out.
#
# The known-orphan list below is debt, not design, and it is deliberately enumerated rather than
# skipped by fixture so that a NEW orphan in any of these documents still fails. Every entry is one
# pre-existing defect of a single family: a form, multipart, or non-JSON body types itself from
# flattened fields or from its media classification instead of naming its schema, so the pruner
# keeps a component the emitter never references. Reproduced identically at v0.0.3, so none of it
# comes from `allOf` identity — closing it means deciding how a non-JSON body names its schema,
# which is its own change.
#   form-composition-3.1  Forum/Text/NestedLeft*/NestedRight — urlencoded and multipart request
#                         bodies whose properties the client flattens into field descriptors.
#   tictactoe-3.1         ErrorMessage — a `text/html` response typed `string` by classification.
#   transform-composition-3.1  the per-component codec modules for a form-composed body.
#   strict-flags-3.1      Manifest — a multipart response part.
#   multipart-response-3.0  SnippetFiles — likewise, in both the types and validators trees.
# The key is fixture plus file basename, not the full tree path, so one entry covers a component
# orphaned under several of a fixture's configs — and, the cost of that, does not notice the same
# basename newly orphaned in a tree it was fine in before.
orphan_debt=(
  "form-composition-3.1/forum.ts"
  "form-composition-3.1/nestedleftbase.ts"
  "form-composition-3.1/nestedleftextra.ts"
  "form-composition-3.1/nestedright.ts"
  "form-composition-3.1/text.ts"
  "tictactoe-3.1/errormessage.ts"
  "transform-composition-3.1/audited.ts"
  "transform-composition-3.1/left.ts"
  "transform-composition-3.1/required.ts"
  "transform-composition-3.1/right.ts"
  "strict-flags-3.1/manifest.ts"
  "multipart-response-3.0/snippetfiles.ts"
)

# Args: work-dir config fixture.
assert_no_orphan_components() {
  local d=$1 cfg=$2 fixture=$3
  if [[ -f "$d/$cfg" ]] && grep -qE '^[[:space:]]*orphans:[[:space:]]*true' "$d/$cfg"; then
    return 0
  fi
  # One pass over the tree collecting the file every relative import/re-export specifier
  # actually names, resolved against the importing file's own directory. Matching the
  # resolved path rather than the exported name is what makes this exact: a sibling artifact
  # declares and imports the SAME component names independently — the validators tree writes
  # its own `export interface Pet` and its operations import it — so a name-based search let
  # a validators-tree import satisfy a types-tree component. Paths cannot collide that way,
  # and a comment or property key that happens to spell a component name cannot match at all.
  local referenced source specifier
  referenced=$(grep -roE "from +['\"][^'\"]+['\"]" "$d"/generated* --include='*.ts' -H 2>/dev/null \
    | while IFS= read -r hit; do
        source=${hit%%:from *}
        specifier=${hit##*from }
        specifier=${specifier#[\'\"]}
        specifier=${specifier%[\'\"]}
        [[ $specifier == .* ]] || continue
        printf '%s\n' "$(cd "$(dirname "$source")" 2>/dev/null && realpath -m "${specifier%.js}.ts")"
      done | sort -u || true)
  local file names found=0
  while IFS= read -r file; do
    mapfile -t names < <(grep -oE '^export (interface|type|const|function|declare) [A-Za-z_$][A-Za-z0-9_$]*' \
      "$file" | awk '{print $3}' | sort -u)
    # Fail loud rather than skip. A component file with no export this recognizes means the
    # emitter grew a declaration form the extractor does not know, and silently skipping it
    # would retire the check for that shape without anyone noticing.
    if [[ ${#names[@]} -eq 0 ]]; then
      echo "verify-ts: no exported name found in $file; the orphan check cannot read it" >&2
      found=1
      continue
    fi
    if grep -qxF "$file" <<<"$referenced"; then
      continue
    fi
    if [[ " ${orphan_debt[*]} " == *" $fixture/$(basename "$file") "* ]]; then
      continue
    fi
    echo "verify-ts: generated component is import-orphaned: $file (exports: ${names[*]})" >&2
    found=1
  done < <(find "$d"/generated* -path '*/components/*.ts' 2>/dev/null | sort)
  assert_no_orphan_declarations "$d" "$fixture" || found=1
  return "$found"
}

# A file is "referenced" as soon as ONE of its exports is imported, so the check above sees nothing
# when a component file is imported for its own declaration while a second declaration beside it is
# named by nobody. That is what a request/response twin for an unused position looked like: a live
# file with a dead export inside it.
#
# Scoped to the derived names in the types tree, and deliberately not wider:
#   * the component's own declaration is contractual — every named component is exported as a public
#     declaration — and is unreferenced by construction whenever an operation reaches the component
#     through a variant instead, so requiring an importer for it would fire on nearly every root;
#   * the validators, zod, client and transform trees export their component modules as the public
#     API a consumer calls (`petValidator`, `petSchema`, `decodePet`). An export nothing else in the
#     tree imports is the normal shape of a public entry point there, not a dead declaration.
# What is left is exactly the compiler's own invention: `{Name}Request`, `{Name}Response`, and the
# wire twins composed onto them. Nothing outside the emitted tree is promised those names, so each
# one has to be named by some other file in the same tree or it is not API, it is debt.
# Empty, and worth keeping that way. Two known survivors exist in the pinned corpus rather than in
# any fixture this gate generates — `workers_multipart-script` and
# `workers_script-and-version-settings-item` in cloudflare-3.0, whose request variants no site names
# because a multipart body flattens to per-field descriptors. That is the same cause as the
# `form-composition-3.1` entries in the file-level list above, reached through
# `components/requestBodies`; entries for them here could never fire, and a debt list that cannot
# fire reads as coverage this gate does not have.
declaration_debt=()

# Args: work-dir fixture.
assert_no_orphan_declarations() {
  local d=$1 fixture=$2
  # Every (resolved target file, imported name) pair in the tree. Generated imports are always one
  # line, which this relies on; a wrapped clause would silently read as no import at all, so the
  # extractor fails loud below if it ever meets an import line it cannot resolve to a specifier.
  local pairs
  pairs=$(
    grep -rHoE '^import (type )?\{[^}]*\} from "[^"]+"' "$d"/generated* --include='*.ts' 2>/dev/null \
      | while IFS= read -r hit; do
          local src=${hit%%:import *} clause=${hit#*:} spec names target
          spec=${clause##*from \"}; spec=${spec%\"}
          [[ $spec == .* ]] || continue
          names=${clause#*\{}; names=${names%%\}*}
          target=$(cd "$(dirname "$src")" 2>/dev/null && realpath -m "${spec%.js}.ts")
          # `A as B` imports A from the target; B is only this module's local name for it.
          tr ',' '\n' <<<"$names" \
            | sed -E 's/[[:space:]]+as[[:space:]]+.*//; s/^[[:space:]]*//; s/[[:space:]]*$//' \
            | while IFS= read -r n; do
                [[ -n $n ]] && printf '%s\t%s\n' "$target" "$n"
              done
        done | sort -u
  )
  local raw file base lower name found=0
  while IFS= read -r raw; do
    [[ -n $raw ]] || continue
    # `find` over a directory argument can yield `//`, which realpath normalizes away on the import
    # side. Compare normalized paths or nothing ever matches and the check silently passes.
    file=$(realpath -m "$raw")
    base=$(basename "$file" .ts | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]')
    while IFS= read -r name; do
      [[ -n $name ]] || continue
      lower=$(tr -cd 'a-zA-Z0-9' <<<"$name" | tr '[:upper:]' '[:lower:]')
      [[ $lower == "$base" ]] && continue
      grep -qxF "$file	$name" <<<"$pairs" && continue
      if [[ " ${declaration_debt[*]} " == *" $fixture/$(basename "$file"):$name "* ]]; then
        continue
      fi
      echo "verify-ts: generated declaration is import-orphaned: $name in $file" >&2
      found=1
    done < <(grep -oE '^export (interface|type) [A-Za-z_$][A-Za-z0-9_$]*' "$file" | awk '{print $3}' | sort -u)
  done < <(find "$d"/generated* -path '*/types/components/*.ts' 2>/dev/null | sort)
  return "$found"
}

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
  assert_no_orphan_components "$d" "$cfg" "$f"
  # The consumer flag matrix over every emitted tree, exactOptionalPropertyTypes off and
  # on. `--strict` alone is the bar this gate used to hold, and it is a bar no consumer compiles at:
  # none of these five flags is part of `strict`, so output that only passes `--strict` can still be
  # uncompilable in the project it was generated into.
  for exact_optional in false true; do
    strict_flag_matrix "$message" "$exact_optional" "$d"/generated*/**/*.ts
  done
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
# The composition-identity matrix: one probe pair in every shape that can carry a `$ref`. The
# 3.1 row also carries a component reached only through an `allOf`, which is the orphan the
# import walk used to leave behind; the 3.0 row exists for `nullable`, which 3.1 does not have.
generate_and_verify composition-identity-3.1 oasts.yaml "$work/composition-identity-3.1" types "composition-identity-3.1"
generate_and_verify composition-identity-3.0 oasts.yaml "$work/composition-identity-3.0" types "composition-identity-3.0"
# Each schema-fidelity compile assertion consumes all three config outputs. The shared helper keeps
# every config isolated for its own consumer matrix and repeat-generation diff; the two links then
# assemble those verified trees beside the default one without generating a fourth time.
for fidelity in schema-fidelity-3.1 schema-fidelity-3.0; do
  generate_and_verify "$fidelity" oasts.yaml "$work/$fidelity" types "$fidelity (default)"
  generate_and_verify "$fidelity" oasts-tagged.yaml "$work/$fidelity-tagged" types \
    "$fidelity (tagged)"
  generate_and_verify "$fidelity" oasts-bigint.yaml "$work/$fidelity-bigint" client \
    "$fidelity (bigint)"
  ln -s "$work/$fidelity-tagged/generated-tagged" "$work/$fidelity/generated-tagged"
  ln -s "$work/$fidelity-bigint/generated-bigint" "$work/$fidelity/generated-bigint"
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext \
    --moduleResolution bundler "$work/$fidelity/compile-assert/cases.ts"
  echo "compile-assert matrix ok: $fidelity"
done
# A request/response twin is emitted for a position the document uses the component at, not for
# every position its shape would split at. Every component in this fixture carries both markers, so
# shape alone would give each of them both twins. The compile assertions import the twins that
# should not exist under `@ts-expect-error`: a resurrected dead twin is not a type error by itself,
# so requiring the import to fail is the only way to assert it stayed dead.
generate_and_verify variant-position-3.1 oasts.yaml "$work/variant-position-3.1" types "variant-position-3.1"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/variant-position-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: variant-position-3.1"
# `not` splits three ways on the types surface: provably empty renders `never` (agreeing with the
# validator that rejects every value), a `not` of nothing is a no-op, and everything in between
# keeps its sibling type and reports the narrowing it could not apply. The compile assertions are
# what pin the first case — it used to render `unknown`, which accepts every value the shipped
# validator rejects.
generate_and_verify negation-3.1 oasts.yaml "$work/negation-3.1" types "negation-3.1"
pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/negation-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: negation-3.1"
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
for identity in composition-identity-3.1 composition-identity-3.0; do
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/$identity/compile-assert/cases.ts"
  echo "compile-assert matrix ok: $identity"
done

for f in client-showcase-3.1 petstore-3.0 tictactoe-3.1 auth-showcase-3.1 server-variables-enum-3.1 relative-server-3.1 wire-fidelity-3.1 media-classification-3.1 form-composition-3.1 multipart-response-3.0 streaming-3.1; do
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
generate_and_verify int64-transform-3.1 oasts.yaml "$work/int64-transform" transform "int64-transform-3.1"
generate_and_verify int64-transform-3.1 oasts-validated.yaml "$work/int64-transform-validated" transform "int64-transform-3.1 (validated)"
generate_and_verify int64-transform-3.1 oasts-zod.yaml "$work/int64-transform-zod" transform "int64-transform-3.1 (zod)" link

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

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-form-composition-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: form-composition-3.1"

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
# The same streaming document under a date/time representation. It is the only row where streaming
# and the conversion layer are crossed, which is where an event payload rendered on the wrong
# surface shows up — as a result type the emitted module cannot satisfy.
generate_and_verify streaming-3.1 oasts-transform.yaml "$work/streaming-transform" transform \
  "streaming-3.1 (date)"
# Both per-event halves at once. They are independent switches, so this is the only row where one
# per-event wrapper both validates and converts — and the only one that typechecks a validator call
# against the wire type the codec then consumes.
generate_and_verify streaming-3.1 oasts-transform-validated.yaml "$work/streaming-transform-validated" \
  transform "streaming-3.1 (date, validated)"
# Streaming responses reach a resolver as a byte stream it framed itself; the two streaming request
# bodies are skipped, and this row is what proves the skip leaves the rest of the tree compiling.
generate_and_verify streaming-3.1 oasts-msw.yaml "$work/streaming-msw" msw "streaming-3.1" link

# The tanstack artifact. Descriptors import no TanStack package, so unlike the msw and zod rows this
# one needs no node_modules link — if it ever does, something started depending on a peer.
generate_and_verify tanstack-showcase-3.1 oasts-tanstack.yaml "$work/tanstack-showcase" tanstack \
  "tanstack-showcase-3.1"
# Every streaming operation is skipped here, so this row is the proof that the skip leaves a
# module set that still resolves rather than a descriptor index naming files that were never written.
generate_and_verify streaming-3.1 oasts-tanstack.yaml "$work/streaming-tanstack" tanstack \
  "streaming-3.1"
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

# The two fixtures authored for the flag matrix. strict-flags-3.1 carries one document under every
# artifact; unused-helper-regions-3.1 is the counter-case, a client selecting none of the
# label/matrix/delimited-object/content helpers — the only shape that can see a helper the emitter
# cannot strip, because those are unused exactly when nothing selects them.
strict_flag_runs=(
  "strict-flags-3.1 oasts.yaml strict-flags-types"
  "strict-flags-3.1 oasts-client.yaml strict-flags-client"
  "strict-flags-3.1 oasts-zod.yaml strict-flags-zod"
  "strict-flags-3.1 oasts-zod-mini.yaml strict-flags-zod-mini"
  "strict-flags-3.1 oasts-msw.yaml strict-flags-msw"
  "strict-flags-3.1 oasts-tanstack.yaml strict-flags-tanstack"
  "strict-flags-3.1 oasts-transform.yaml strict-flags-transform"
  "unused-helper-regions-3.1 oasts.yaml unused-helper-regions"
)
for run in "${strict_flag_runs[@]}"; do
  read -r fixture config dir <<<"$run"
  generate_and_verify "$fixture" "$config" "$work/$dir" strict-flags "$fixture ($config)" link
done

# The compile-assert reads the client tree. It is the only thing that can decide the emitted
# `CallArgs` scheme parameter question: the alias is consumed by `Transport<S>`-typed call sites,
# the orThrow companion and the aggregate, none of which an assertion over emitted text can reach.
for exact_optional in false true; do
  strict_flag_matrix "strict-flags-3.1 compile-assert" "$exact_optional" \
    "$work/strict-flags-client/compile-assert/cases.ts"
done

# Filtering: every scenario config generates a distinct tree, and each is held to the same
# consumer flag matrix and double-generation byte identity as everything else. The compile-assert
# reads the default tree, where the only filter excludes the `/admin/` path prefix.
filters_runs=(
  "filters-showcase-3.1 oasts.yaml filters-showcase"
  "filters-showcase-3.1 oasts-tags.yaml filters-showcase-tags"
  "filters-showcase-3.1 oasts-orphans-kept.yaml filters-showcase-orphans-kept"
  "filters-showcase-3.1 oasts-deprecated.yaml filters-showcase-deprecated"
)
for run in "${filters_runs[@]}"; do
  read -r fixture config dir <<<"$run"
  generate_and_verify "$fixture" "$config" "$work/$dir" filters "$fixture ($config)"
done

for exact_optional in false true; do
  strict_flag_matrix "filters-showcase-3.1 compile-assert" "$exact_optional" \
    "$work/filters-showcase/compile-assert/cases.ts"
done

node --test crates/oasts-core/runtime/test-e2e/index.js
# Separate process on purpose; test-e2e/streaming-index.js says why.
node --test crates/oasts-core/runtime/test-e2e/streaming-index.js
