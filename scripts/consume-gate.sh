#!/usr/bin/env bash
# Prove generated clients resolve, bundle, tree-shake, and run as consumed artifacts.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root=$PWD
binary=target/debug/oasts
runtime_root="$repo_root/crates/oasts-core/runtime"
work=""

finish() {
  status=$?
  trap - EXIT
  if [[ -n "$work" && -d "$work" ]]; then
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap finish EXIT

if [[ ! -x "$binary" ]]; then
  cargo build -p oasts
fi

# Call the tool binaries directly rather than through `pnpm exec`: pnpm's deps-status
# preflight hard-fails under this repo's devEngines pin even when the tools are installed.
esbuild_bin="$runtime_root/node_modules/.bin/esbuild"
rollup_bin="$runtime_root/node_modules/.bin/rollup"
tsc_bin="$runtime_root/node_modules/.bin/tsc"
vite_bin="$runtime_root/node_modules/.bin/vite"
if [[ ! -x "$esbuild_bin" || ! -x "$rollup_bin" || ! -x "$tsc_bin" || ! -x "$vite_bin" ]]; then
  (cd "$runtime_root" && pnpm install)
fi

work=$(mktemp -d)

# Args: work-dir-name import-extension [fixture-dir relative to the repo root] [config file name].
generate_fixture() {
  local name=$1 import_extension=$2
  local source_dir=${3:-fixtures/client-showcase-3.1}
  local config=${4:-oasts.yaml}
  local destination="$work/$name"
  cp -r "$repo_root/$source_dir" "$destination"
  # Glob rather than a hand-kept list: every artifact writes under a `generated*` directory, and a
  # list here silently stops stripping the moment a new one lands. `generated-zod*` was already
  # being missed.
  rm -rf -- "$destination"/generated*
  printf '\nemit:\n  importExtension: "%s"\n' "$import_extension" >>"$destination/$config"
  printf '{"type":"module"}\n' >"$destination/package.json"
  if ! (cd "$destination" && "$repo_root/$binary" generate --config "$config") >"$destination/generate.log" 2>&1; then
    cat "$destination/generate.log" >&2
    return 1
  fi
}

generate_fixture client-showcase-js .js
generate_fixture client-showcase-none none
fixture="$work/client-showcase-js"

whole_entry="$fixture/whole-client.ts"
tree_entry="$fixture/one-operation.ts"
printf '%s\n' \
  'export * from "./generated/client/api.js";' \
  'export * from "./generated/runtime/result.js";' \
  'export * from "./generated/runtime/transport.js";' \
  >"$whole_entry"
printf '%s\n' \
  'import { getPetShowcase } from "./generated/client/operations/getpetshowcase.js";' \
  'import { createTransport } from "./generated/runtime/transport.js";' \
  'export { createTransport, getPetShowcase };' \
  >"$tree_entry"

bundler_log_has_failure_warning() {
  local log=$1
  grep -Eiq 'warning[^[:cntrl:]]*(unresolved|external|missing export)|(unresolved import|unexpected external|missing export)' "$log"
}

run_esbuild() {
  local entry=$1 output=$2 metafile=$3 log=$4
  if ! "$esbuild_bin" "$entry" --bundle --format=esm --platform=neutral --target=es2022 --outfile="$output" --metafile="$metafile" >"$log" 2>&1; then
    cat "$log" >&2
    return 1
  fi
  if bundler_log_has_failure_warning "$log"; then
    cat "$log" >&2
    echo "consume gate: esbuild emitted a resolution/export/external warning" >&2
    return 1
  fi
  node --input-type=module - "$metafile" <<'NODE'
import { readFile } from "node:fs/promises";

const metafile = JSON.parse(await readFile(process.argv[2], "utf8"));
const externalImports = Object.values(metafile.outputs)
  .flatMap((output) => output.imports)
  .filter((imported) => imported.external);
if (externalImports.length > 0) {
  throw new Error(`esbuild left unexpected external imports: ${externalImports.map((item) => item.path).join(", ")}`);
}
NODE
}

vite_config="$work/vite.config.mjs"
cat >"$vite_config" <<'VITE_CONFIG'
function requiredEnvironment(name) {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

const entry = requiredEnvironment("OASTS_VITE_ENTRY");
const outDir = requiredEnvironment("OASTS_VITE_OUT_DIR");
const fileName = requiredEnvironment("OASTS_VITE_FILE_NAME");
const minify = process.env.OASTS_VITE_MINIFY === "true" ? "esbuild" : false;
const fatalWarning = /unresolved|external|missing export/iu;

export default {
  logLevel: "info",
  build: {
    target: "es2022",
    lib: {
      entry,
      formats: ["es"],
      fileName: () => fileName,
    },
    outDir,
    emptyOutDir: false,
    minify,
    rollupOptions: {
      external: () => false,
      onwarn(warning, defaultHandler) {
        const detail = `${String(warning.code)}: ${warning.message}`;
        if (
          warning.code === "UNRESOLVED_IMPORT" ||
          warning.code === "MISSING_EXPORT" ||
          fatalWarning.test(detail)
        ) {
          throw new Error(`fatal Rollup warning: ${detail}`);
        }
        defaultHandler(warning);
      },
      output: {
        inlineDynamicImports: true,
      },
      plugins: [
        {
          name: "oasts-no-external-imports",
          generateBundle(_options, bundle) {
            for (const output of Object.values(bundle)) {
              if (
                output.type === "chunk" &&
                (output.imports.length > 0 || output.dynamicImports.length > 0)
              ) {
                this.error(
                  `unexpected emitted imports in ${output.fileName}: ${[
                    ...output.imports,
                    ...output.dynamicImports,
                  ].join(", ")}`,
                );
              }
            }
          },
        },
      ],
    },
  },
};
VITE_CONFIG

run_vite() {
  local entry=$1 out_dir=$2 file_name=$3 minify=$4 log=$5
  if ! OASTS_VITE_ENTRY="$entry" \
    OASTS_VITE_OUT_DIR="$out_dir" \
    OASTS_VITE_FILE_NAME="$file_name" \
    OASTS_VITE_MINIFY="$minify" \
    "$vite_bin" build --config "$vite_config" >"$log" 2>&1; then
    cat "$log" >&2
    return 1
  fi
  if bundler_log_has_failure_warning "$log"; then
    cat "$log" >&2
    echo "consume gate: Vite/Rollup emitted a resolution/export/external warning" >&2
    return 1
  fi
  if [[ ! -f "$out_dir/$file_name" ]]; then
    cat "$log" >&2
    echo "consume gate: Vite did not emit $out_dir/$file_name" >&2
    return 1
  fi
}

bundle_dir="$work/bundles"
mkdir -p "$bundle_dir"
esbuild_bundle="$bundle_dir/esbuild-whole.mjs"
vite_bundle="$bundle_dir/vite-whole.mjs"
run_esbuild "$whole_entry" "$esbuild_bundle" "$work/esbuild-whole.json" "$work/esbuild-whole.log"
run_vite "$whole_entry" "$bundle_dir" "$(basename "$vite_bundle")" false "$work/vite-whole.log"
echo "ok: bundler matrix (esbuild ESM + Vite 7 library ESM through Rollup)"

tree_bundle="$bundle_dir/vite-one.mjs"
run_vite "$tree_entry" "$bundle_dir" "$(basename "$tree_bundle")" true "$work/vite-tree.log"
tree_report=$(
  node --input-type=module - "$fixture/generated/client/operations" getPetShowcase "$tree_bundle" <<'NODE'
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const operationsDirectory = process.argv[2];
const selectedOperationId = process.argv[3];
const bundlePath = process.argv[4];
const operationFiles = (await readdir(operationsDirectory))
  .filter((name) => name.endsWith(".ts"))
  .sort();
const operations = [];

for (const file of operationFiles) {
  const source = await readFile(path.join(operationsDirectory, file), "utf8");
  const descriptor = source.match(
    /const descriptor: OperationDescriptor = \{[\s\S]*?\n  operationId: "([^"]+)",[\s\S]*?\n  method: "[A-Z]+",\n  path: (\[[\s\S]*?\n  \]),\n  params:/u,
  );
  const sourcePointer = source.match(
    /^\/\/ Source: .*#\/paths\/(.+)\/(?:get|put|post|delete|patch|head|options|trace)$/mu,
  );
  if (descriptor === null || sourcePointer === null) {
    throw new Error(`could not derive operation metadata from ${file}`);
  }
  const operationId = descriptor[1];
  const descriptorPath = descriptor[2];
  const encodedPath = sourcePointer[1];
  if (operationId === undefined || descriptorPath === undefined || encodedPath === undefined) {
    throw new Error(`incomplete operation metadata in ${file}`);
  }
  operations.push({
    operationId,
    pathTemplate: encodedPath.replaceAll("~1", "/").replaceAll("~0", "~"),
    pathSignature: `path:${descriptorPath
      .replaceAll(/,\s*\]/gu, "]")
      .replaceAll(/\s/gu, "")
      .replace(/,+$/u, "")},`,
  });
}

if (operations.length < 3) {
  throw new Error(`tree-shaking fixture has only ${String(operations.length)} operations`);
}
const selected = operations.find((operation) => operation.operationId === selectedOperationId);
if (selected === undefined) {
  throw new Error(`selected operation ${selectedOperationId} is missing`);
}
const compactBundle = (await readFile(bundlePath, "utf8")).replaceAll(/\s/gu, "");
const includesSelectedId = compactBundle.includes(JSON.stringify(selected.operationId));
const includesSelectedPath = compactBundle.includes(selected.pathSignature);
if (!includesSelectedId || !includesSelectedPath) {
  throw new Error(
    `selected operation ${selected.operationId} or ${selected.pathTemplate} was tree-shaken (id=${String(includesSelectedId)}, path=${String(includesSelectedPath)})`,
  );
}

const otherOperations = operations.filter(
  (operation) => operation.operationId !== selectedOperationId,
);
for (const operation of otherOperations) {
  if (
    compactBundle.includes(JSON.stringify(operation.operationId)) ||
    compactBundle.includes(operation.pathSignature)
  ) {
    throw new Error(
      `tree-shaken bundle still contains ${operation.operationId} (${operation.pathTemplate})`,
    );
  }
}
process.stdout.write(`${String(otherOperations.length)} other generated path templates absent`);
NODE
)
tree_bytes=$(wc -c <"$tree_bundle")
echo "ok: tree-shaking ($tree_report; $((tree_bytes)) bytes, report-only)"

# The tanstack key factory exports one flat binding per path node *and* a composed `keys` object.
# The flat bindings exist solely so an operation module can import one leaf: a bundler cannot drop
# unused properties of an object it references at all, so a module reaching through `keys` would
# retain every path's key data. That is a claim about bundler behaviour, so it is asserted here
# rather than measured in client-size.sh — a number that drifts upward reads as noise, a bundle
# that still contains another path's binding is a defect.
generate_fixture tanstack-tree-js .js fixtures/tanstack-showcase-3.1 oasts-tanstack.yaml
tanstack_fixture="$work/tanstack-tree-js"
tanstack_entry="$tanstack_fixture/one-query.ts"
printf '%s\n' \
  'import { getPetQuery } from "./generated-tanstack/tanstack/operations/getpet.js";' \
  'import { createTransport } from "./generated-tanstack/runtime/transport.js";' \
  'export { createTransport, getPetQuery };' \
  >"$tanstack_entry"
tanstack_bundle="$bundle_dir/vite-tanstack-one.mjs"
run_vite "$tanstack_entry" "$bundle_dir" "$(basename "$tanstack_bundle")" true "$work/vite-tanstack.log"
tanstack_report=$(
  node --input-type=module - "$tanstack_fixture/generated-tanstack/tanstack/keys.ts" apiPetsByPetId "$tanstack_bundle" <<'NODE'
import { readFile } from "node:fs/promises";

const keysPath = process.argv[2];
const selectedBinding = process.argv[3];
const bundlePath = process.argv[4];

// Binding *names* are renamed by the minifier, so this asserts on the key data instead: the string
// literals each path node contributes to its key. Those are the payload the flat-binding split
// exists to keep out of a bundle that did not ask for them, and they survive minification because
// they are data rather than identifiers.
const keysSource = await readFile(keysPath, "utf8");
const bindings = [...keysSource.matchAll(/^export const (\w+) = (?:\([^)]*\) => )?(\[.*\]) as const;$/gmu)]
  .map(([, name, key]) => ({ name, literals: [...key.matchAll(/"([^"]*)"/gu)].map((m) => m[1]) }));
if (bindings.length < 5) {
  throw new Error(`key factory has only ${String(bindings.length)} flat bindings`);
}
const selected = bindings.find((binding) => binding.name === selectedBinding);
if (selected === undefined) {
  throw new Error(`selected binding ${selectedBinding} is missing from ${keysPath}`);
}

const bundle = await readFile(bundlePath, "utf8");
const present = (literal) => bundle.includes(JSON.stringify(literal));

const missing = selected.literals.filter((literal) => !present(literal));
if (missing.length !== 0) {
  throw new Error(`the imported query's own key data was tree-shaken: ${missing.join(", ")}`);
}

// Only literals no surviving binding legitimately needs. `"api"` and `"pets"` are on the selected
// binding's own path, so their presence proves nothing either way and they are not evidence.
const ownLiterals = new Set(selected.literals);
const foreign = [
  ...new Set(
    bindings
      .filter((binding) => binding.name !== selectedBinding)
      .flatMap((binding) => binding.literals)
      .filter((literal) => !ownLiterals.has(literal)),
  ),
];
if (foreign.length < 5) {
  throw new Error(`only ${String(foreign.length)} foreign key literals to test against`);
}
const retained = foreign.filter(present);
if (retained.length !== 0) {
  throw new Error(
    `bundle still contains key data for unrelated paths: ${retained.map((l) => JSON.stringify(l)).join(", ")}`,
  );
}
process.stdout.write(
  `${String(bindings.length - 1)} other path-node bindings' key data absent (${String(foreign.length)} literals checked)`,
);
NODE
)
tanstack_bytes=$(wc -c <"$tanstack_bundle")
echo "ok: tanstack tree-shaking ($tanstack_report; $((tanstack_bytes)) bytes, report-only)"

typecheck_generated() {
  local generated_root=$1 module=$2 resolution=$3
  local sources=()
  mapfile -t sources < <(find "$generated_root" -type f -name '*.ts' -print | sort)
  "$tsc_bin" \
    --strict \
    --noEmit \
    --skipLibCheck false \
    --target es2022 \
    --module "$module" \
    --moduleResolution "$resolution" \
    "${sources[@]}"
}

typecheck_generated "$work/client-showcase-js/generated" esnext bundler
typecheck_generated "$work/client-showcase-js/generated" nodenext nodenext
typecheck_generated "$work/client-showcase-none/generated" esnext bundler
none_nodenext_log="$work/none-nodenext.log"
if typecheck_generated "$work/client-showcase-none/generated" nodenext nodenext >"$none_nodenext_log" 2>&1; then
  echo "consume gate: emit.importExtension none unexpectedly resolved under nodenext" >&2
  exit 1
fi
if ! grep -Eq 'error TS283[45]: Relative import paths need explicit file extensions' "$none_nodenext_log"; then
  cat "$none_nodenext_log" >&2
  echo "consume gate: none/nodenext failed for an unexpected reason" >&2
  exit 1
fi
echo "ok: module resolution (.js/bundler pass, .js/nodenext pass, none/bundler pass, none/nodenext expected fail)"

node --input-type=module - "$vite_bundle" "$repo_root/crates/oasts-core/runtime/test-e2e/harness.ts" <<'NODE'
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const clientModule = await import(pathToFileURL(process.argv[2]).href);
const harnessModule = await import(pathToFileURL(process.argv[3]).href);
const createTransport = harnessModule.requiredFunction(clientModule, "createTransport");
const api = harnessModule.requiredRecord(clientModule.api, "bundled aggregate api");
const getPetShowcase = harnessModule.requiredFunction(api, "getPetShowcase");
const server = harnessModule.createScriptedServer();
let started = false;

try {
  server.scriptRoute("GET", "/pets/p_123", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"p_123","name":"Bundled"}'),
  });
  const baseUrl = await server.start();
  started = true;
  const transport = createTransport({
    baseUrl,
    headers: { "X-Consume-Gate": "vite-bundle" },
  });
  const result = harnessModule.requiredRecord(
    await getPetShowcase(transport, { path: { petId: "p_123" } }),
    "bundled client result",
  );
  assert.equal(server.requests.length, 1);
  const received = server.requiredRequest(0);
  assert.equal(received.method, "GET");
  assert.equal(received.url, "/pets/p_123");
  assert.equal(
    harnessModule.requestHeader(received, "Accept"),
    "application/json, text/plain",
  );
  assert.equal(
    harnessModule.requestHeader(received, "X-Consume-Gate"),
    "vite-bundle",
  );
  assert.equal(result.outcome, 200);
  assert.equal(result.ok, true);
  assert.deepEqual(result.data, { id: "p_123", name: "Bundled" });
} finally {
  if (started) {
    await server.stop();
  }
}
NODE
echo "ok: runtime consumption (Vite-built ESM bundle, no node:module resolution hook)"
