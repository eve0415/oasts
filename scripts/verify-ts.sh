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
for f in client-showcase-3.1 petstore-3.0; do
  cp -r "fixtures/$f" "$work/client-$f"
  fixture_config=oasts.yaml
  if [[ "$f" == petstore-3.0 ]]; then
    fixture_config=oasts-client.yaml
  fi
  (cd "$work/client-$f" && "$OLDPWD/$bin" generate --config "$fixture_config")
  pnpm exec tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/client-$f"/generated*/**/*.ts
  echo "tsc --strict client ok: $f"
done

cp -r fixtures/tictactoe-3.1 "$work/client-tictactoe-3.1"
if (cd "$work/client-tictactoe-3.1" && "$OLDPWD/$bin" generate --config oasts-client.yaml) 2>"$work/tictactoe-client.stderr"; then
  echo "client-enabled tictactoe unexpectedly generated" >&2
  exit 1
fi
if ! grep -q 'OASTS1430' "$work/tictactoe-client.stderr"; then
  echo "client-enabled tictactoe did not report OASTS1430" >&2
  exit 1
fi
echo "client rejection ok: tictactoe-3.1 OASTS1430"

cp -r fixtures/client-showcase-3.1 "$work/client-showcase-repeat"
(cd "$work/client-showcase-repeat" && "$OLDPWD/$bin" generate --config oasts.yaml)
diff -r "$work/client-client-showcase-3.1/generated" "$work/client-showcase-repeat/generated"
echo "double-generation byte identity ok: client-showcase-3.1"

node --test crates/oasts-core/runtime/test-e2e/
