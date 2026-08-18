#!/usr/bin/env bash
# WebAssembly gate: the browser front-end emits the bytes the CLI writes.
# Usage: scripts/wasm-gate.sh (needs node; builds what it needs)
#
# The comparison is the point. A playground that shows different output from the compiler it
# advertises is worse than no playground, and nothing else in the repository compares the two
# front-ends -- verify-ts.sh only ever regenerates through the CLI.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cargo build --quiet -p oasts --profile dev
cargo build --quiet -p oasts-wasm --profile wasm --target wasm32-unknown-unknown
wasm=target/wasm32-unknown-unknown/wasm/oasts_wasm.wasm

# One config for both halves, so the read path is the only thing that differs. `tsconfig` is off
# because the ambient probe is the one input outside version, config and document that reaches
# emitted bytes, and a browser has no ancestor directories to probe.
cat > "$work/oasts.json" <<'JSON'
{
  "schemaVersion": 1,
  "input": { "path": "openapi.yaml" },
  "output": "generated",
  "typescript": { "tsconfig": "off" },
  "artifacts": {
    "types": true,
    "client": true,
    "validators": true,
    "zod": true,
    "tanstack": true,
    "msw": true
  },
  "validation": { "engine": "generated", "request": true, "response": true }
}
JSON

for fixture in petstore-3.0 client-showcase-3.1 tictactoe-3.1; do
  mkdir -p "$work/$fixture"
  cp "fixtures/$fixture/openapi.yaml" "$work/$fixture/openapi.yaml"
  cp "$work/oasts.json" "$work/$fixture/oasts.json"
  (cd "$work/$fixture" && "$OLDPWD/target/debug/oasts" generate --config oasts.json >/dev/null)
done

cat > "$work/compare.mjs" <<'JS'
import { readFileSync, readdirSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { join, relative, sep } from "node:path";

const [wasmPath, work, ...fixtures] = process.argv.slice(2);
const bytes = readFileSync(wasmPath);

const module = new WebAssembly.Module(bytes);
const imports = WebAssembly.Module.imports(module);
if (imports.length !== 0) {
  console.error(`wasm-gate: the module declares ${imports.length} imports; it must declare none`);
  console.error(JSON.stringify(imports, null, 2));
  process.exit(1);
}

const { instance } = await WebAssembly.instantiate(bytes, {});
const { memory, oasts_alloc, oasts_free, oasts_generate } = instance.exports;

function generate(request) {
  const encoded = new TextEncoder().encode(JSON.stringify(request));
  const inPtr = oasts_alloc(encoded.length);
  new Uint8Array(memory.buffer, inPtr, encoded.length).set(encoded);
  const outPtr = oasts_generate(inPtr, encoded.length);
  oasts_free(inPtr, encoded.length);
  const length = new DataView(memory.buffer).getUint32(outPtr, true);
  const body = new TextDecoder().decode(new Uint8Array(memory.buffer, outPtr + 4, length));
  oasts_free(outPtr, 4 + length);
  return JSON.parse(body);
}

// `.oasts-manifest.json` is the writer's drift record, not emitted code: `pipeline::compile`
// never produces it and a host that writes nothing has nothing to record.
const WRITE_PATH_ONLY = new Set([".oasts-manifest.json"]);

function tree(root) {
  const files = new Map();
  const walk = (directory) => {
    for (const entry of readdirSync(directory)) {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) {
        walk(path);
      } else {
        const relativePath = relative(root, path).split(sep).join("/");
        if (!WRITE_PATH_ONLY.has(relativePath)) {
          files.set(relativePath, readFileSync(path, "utf8"));
        }
      }
    }
  };
  walk(root);
  return files;
}

const config = JSON.parse(readFileSync(join(work, "oasts.json"), "utf8"));
let failed = false;

for (const fixture of fixtures) {
  const written = tree(join(work, fixture, "generated"));
  const result = generate({
    spec: readFileSync(join(work, fixture, "openapi.yaml"), "utf8"),
    config,
  });

  if (result.error !== null) {
    console.error(`wasm-gate: ${fixture}: the module refused the request: ${result.error}`);
    failed = true;
    continue;
  }
  const errors = result.diagnostics.filter((entry) => entry.severity === "error");
  if (errors.length !== 0) {
    console.error(`wasm-gate: ${fixture}: compilation failed`);
    for (const error of errors) console.error(`  ${error.code}: ${error.message}`);
    failed = true;
    continue;
  }

  const emitted = new Map(result.files.map((file) => [file.path, file.content]));
  // Sorted so the first difference reported is the same one on every machine.
  const paths = [...new Set([...written.keys(), ...emitted.keys()])].sort();
  const difference = paths.find((path) => written.get(path) !== emitted.get(path));
  if (difference !== undefined) {
    const absent = !written.has(difference) ? "the CLI" : !emitted.has(difference) ? "the module" : null;
    console.error(
      absent === null
        ? `wasm-gate: ${fixture}: contents differ at ${difference}`
        : `wasm-gate: ${fixture}: ${absent} did not emit ${difference}`,
    );
    failed = true;
    continue;
  }
  console.log(`wasm output matches the CLI byte for byte: ${fixture} (${paths.length} files)`);
}

const gzipped = gzipSync(bytes, { level: 9 }).length;
console.log(`wasm artifact: ${bytes.length} B raw, ${gzipped} B gzipped`);
process.exit(failed ? 1 : 0);
JS

node "$work/compare.mjs" "$wasm" "$work" petstore-3.0 client-showcase-3.1 tictactoe-3.1
