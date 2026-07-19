#!/usr/bin/env bash
# Typecheck generated fixture output under tsc --strict.
# Usage: scripts/verify-ts.sh (needs node/npx; run after `cargo build`)
set -euo pipefail
cd "$(dirname "$0")/.."
bin=target/debug/oasts
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for f in petstore-3.0 tictactoe-3.1; do
  cp -r "fixtures/$f" "$work/$f"
  (cd "$work/$f" && "$OLDPWD/$bin" generate)
  npx --yes -p typescript@latest tsc --strict --noEmit --skipLibCheck false --target es2022 --module esnext --moduleResolution bundler "$work/$f"/generated/types/**/*.ts
  echo "tsc --strict ok: $f"
done
