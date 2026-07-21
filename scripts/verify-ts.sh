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
for f in client-showcase-3.1 petstore-3.0 tictactoe-3.1 auth-showcase-3.1; do
  # A fixture whose client config lives in a separate file says so on disk.
  fixture_config=oasts.yaml
  if [[ -f "fixtures/$f/oasts-client.yaml" ]]; then
    fixture_config=oasts-client.yaml
  fi
  cp -r "fixtures/$f" "$work/client-$f"
  rm -rf "$work/client-$f"/generated "$work/client-$f"/generated-client
  (cd "$work/client-$f" && "$OLDPWD/$bin" generate --config "$fixture_config")
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-$f"/generated*/**/*.ts
  echo "tsc --strict client ok: $f"
  cp -r "fixtures/$f" "$work/client-$f-repeat"
  rm -rf "$work/client-$f-repeat"/generated "$work/client-$f-repeat"/generated-client
  (cd "$work/client-$f-repeat" && "$OLDPWD/$bin" generate --config "$fixture_config")
  diff -r "$work/client-$f"/generated* "$work/client-$f-repeat"/generated*
  echo "double-generation byte identity ok: $f"
done

pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-auth-showcase-3.1/compile-assert/cases.ts"
echo "compile-assert matrix ok: auth-showcase-3.1"

node --test crates/oasts-core/runtime/test-e2e/
