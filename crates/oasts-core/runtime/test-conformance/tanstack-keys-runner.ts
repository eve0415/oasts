// Conformance runner for the generated tanstack artifact's query keys. This file is NOT frozen: it
// is the harness that drives the frozen vectors in ./vectors-tanstack-keys.ts against freshly
// generated showcase output trees, and it may be adjusted as the emitter moves.
//
// Locating the output: set OASTS_TANSTACK_GENERATED_ROOT to the generated root (the directory that
// contains `tanstack/`, `client/` and `runtime/`) produced by generating
// fixtures/tanstack-showcase-3.1 with the default date/time representation, and
// OASTS_TANSTACK_DATE_GENERATED_ROOT to the same document generated under `types.dateTime: date`.
// Both are needed because the frozen set spans both: two of its four exports describe a key built
// from an application value that has to reach wire form before it is keyed. When either variable is
// unset or its tree has no `tanstack/` directory, the whole suite skips with a diagnostic, so
// `node --test` over this file stays green before the artifact is generated.
//
// A missing *tree* skips. A missing *operation module* does not: a vector whose descriptor module
// is absent fails, because "the emitter stopped emitting this descriptor" is precisely the
// regression these vectors exist to catch, and a skip would hide it.
//
// HOW KEYS ARE COMPARED. By TanStack's own `hashKey`, never by deep equality — the vector file's
// header states the rule and the reasoning. `hashKey` is the function that decides cache identity:
// it sorts object keys and drops undefined-valued properties, so comparing through it freezes
// exactly the cache-identity facts the contract promises and nothing else.
//
// The generated trees import their siblings with `.js` specifiers over on-disk `.ts` files, so this
// runner reuses ../test-e2e/resolve-generated.mjs to retry a failing `.js` resolution at the sibling
// `.ts` path, exactly as the client end-to-end suite does.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { register } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { hashKey } from "@tanstack/query-core";

type ExportedFunction = (...arguments_: unknown[]) => unknown;

/** A loaded operation module, or the failure that stopped it from loading. */
type LoadedModule =
  | { readonly kind: "module"; readonly exports: Readonly<Record<string, unknown>> }
  | { readonly kind: "failure"; readonly message: string };

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function isExportedFunction(value: unknown): value is ExportedFunction {
  return typeof value === "function";
}

/** The generated module file for an operation is its lowercased name: `getReportJson` → `getreportjson.ts`. */
function operationModulePath(root: string, operation: string): string {
  return join(root, "tanstack/operations", `${operation.toLowerCase()}.ts`);
}

// Every operation named by a vector set, loaded once. Loading eagerly rather than inside each test
// is what keeps the two module-resolution hooks below from tripping over each other; a load failure
// is carried into the test that needs it instead of aborting the run.
async function loadOperationModules(
  root: string,
  operations: Iterable<string>,
): Promise<ReadonlyMap<string, LoadedModule>> {
  const loaded = new Map<string, LoadedModule>();
  for (const operation of new Set(operations)) {
    const file = operationModulePath(root, operation);
    if (!existsSync(file)) {
      loaded.set(operation, {
        kind: "failure",
        message: `no descriptor module was emitted at ${file}`,
      });
      continue;
    }
    try {
      const exports: unknown = await import(pathToFileURL(file).href);
      loaded.set(
        operation,
        isRecord(exports)
          ? { kind: "module", exports }
          : { kind: "failure", message: `${file} did not evaluate to a module namespace` },
      );
    } catch (cause) {
      loaded.set(operation, {
        kind: "failure",
        message: `${file} failed to load: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }
  }
  return loaded;
}

function requiredExport(
  modules: ReadonlyMap<string, LoadedModule>,
  operation: string,
  exportName: string,
  label: string,
): ExportedFunction {
  const loaded = modules.get(operation);
  if (loaded === undefined) {
    assert.fail(`${label}: operation '${operation}' was never loaded`);
  }
  if (loaded.kind === "failure") {
    assert.fail(`${label}: ${loaded.message}`);
  }
  const value = loaded.exports[exportName];
  if (!isExportedFunction(value)) {
    assert.fail(
      `${label}: export '${exportName}' is missing or not a function; available exports: ${Object.keys(loaded.exports).toSorted().join(", ")}`,
    );
  }
  return value;
}

/** The transport a descriptor factory is handed. It is never dispatched here — only keys are read. */
async function loadTransport(root: string): Promise<unknown> {
  const module: unknown = await import(pathToFileURL(join(root, "runtime/transport.ts")).href);
  if (!isRecord(module)) {
    assert.fail(`${root}: runtime/transport.ts did not evaluate to a module namespace`);
  }
  const createTransport = module.createTransport;
  if (!isExportedFunction(createTransport)) {
    assert.fail(`${root}: runtime/transport.ts exports no createTransport function`);
  }
  return createTransport({ baseUrl: "https://tanstack.example.test/v1" });
}

function queryKeyOf(descriptor: unknown, label: string): readonly unknown[] {
  if (!isRecord(descriptor)) {
    assert.fail(`${label}: the descriptor factory did not return an object`);
  }
  const queryKey = descriptor.queryKey;
  if (!isUnknownArray(queryKey)) {
    assert.fail(`${label}: the descriptor's queryKey is not an array`);
  }
  return queryKey;
}

function affectsOf(value: unknown, label: string): readonly (readonly unknown[])[] {
  if (!isUnknownArray(value)) {
    assert.fail(`${label}: the invalidation list is not an array`);
  }
  return value.map((entry, index) => {
    if (!isUnknownArray(entry)) {
      assert.fail(`${label}: invalidation entry ${String(index)} is not a query key array`);
    }
    return entry;
  });
}

// Replaces the string at `path` with the Date it denotes, rebuilding only the objects along the way.
// The frozen vectors carry ISO strings so they stay readable and hashable; the descriptor under a
// date/time transform must be called with the application value instead.
function reviveAt(value: unknown, path: readonly string[], label: string): unknown {
  const [head, ...rest] = path;
  if (head === undefined) {
    if (typeof value !== "string") {
      assert.fail(`${label}: a dateFields entry must name a frozen ISO string`);
    }
    const revived = new Date(value);
    if (Number.isNaN(revived.getTime())) {
      assert.fail(`${label}: '${value}' is not a valid instant`);
    }
    return revived;
  }
  if (!isRecord(value)) {
    assert.fail(`${label}: a dateFields entry walks through '${head}', which is not an object`);
  }
  if (!(head in value)) {
    assert.fail(
      `${label}: a dateFields entry names '${head}', which the frozen input does not carry`,
    );
  }
  return { ...value, [head]: reviveAt(value[head], rest, label) };
}

function reviveDates(
  input: Readonly<Record<string, unknown>>,
  dateFields: readonly (readonly string[])[],
  label: string,
): Readonly<Record<string, unknown>> {
  let revived: Readonly<Record<string, unknown>> = input;
  for (const field of dateFields) {
    const next = reviveAt(revived, field, label);
    if (!isRecord(next)) {
      assert.fail(`${label}: reviving '${field.join(".")}' did not yield an object`);
    }
    revived = next;
  }
  return revived;
}

function assertKeyMatches(actual: readonly unknown[], expected: readonly unknown[], label: string) {
  assert.strictEqual(
    hashKey(actual),
    hashKey(expected),
    `${label}: the descriptor's key is not the frozen key under TanStack's own hash`,
  );
}

const stringRoot = process.env.OASTS_TANSTACK_GENERATED_ROOT;
const dateRoot = process.env.OASTS_TANSTACK_DATE_GENERATED_ROOT;

function missingTree(name: string, root: string | undefined): string | undefined {
  if (root === undefined) {
    return `set ${name} to the generated output root to run tanstack key conformance`;
  }
  if (!existsSync(join(root, "tanstack"))) {
    return `${name} (${root}) has no tanstack/ directory; generate the tanstack artifact first`;
  }
  return undefined;
}

const skip =
  missingTree("OASTS_TANSTACK_GENERATED_ROOT", stringRoot) ??
  missingTree("OASTS_TANSTACK_DATE_GENERATED_ROOT", dateRoot);

if (skip !== undefined || stringRoot === undefined || dateRoot === undefined) {
  test("tanstack key conformance", { skip: skip ?? "no generated tree" }, () => {});
} else {
  const { AFFECTS_VECTORS, KEY_VECTORS, TRANSFORM_AFFECTS_VECTORS, TRANSFORM_KEY_VECTORS } =
    await import("./vectors-tanstack-keys.ts");

  const hookUrl = new URL("../test-e2e/resolve-generated.mjs", import.meta.url);

  // Two trees, one hook module. Registering it twice shares its module state — the second
  // registration clobbers the first root, which is why the auth E2E suite registers a single root
  // covering both of its trees. These two roots have no useful common ancestor (they are independent
  // env vars), so instead each root is registered immediately before everything under it is loaded,
  // and nothing under the string tree is imported afterwards.
  register(hookUrl, { data: { generatedRootUrl: pathToFileURL(stringRoot).href } });
  const stringTransport = await loadTransport(stringRoot);
  const stringModules = await loadOperationModules(stringRoot, [
    ...KEY_VECTORS.map((vector) => vector.operation),
    ...AFFECTS_VECTORS.map((vector) => vector.operation),
  ]);

  register(hookUrl, { data: { generatedRootUrl: pathToFileURL(dateRoot).href } });
  const dateTransport = await loadTransport(dateRoot);
  const dateModules = await loadOperationModules(dateRoot, [
    ...TRANSFORM_KEY_VECTORS.map((vector) => vector.operation),
    ...TRANSFORM_AFFECTS_VECTORS.map((vector) => vector.operation),
  ]);

  // A suite that registers no tests passes. Every vector set is therefore asserted non-empty, so an
  // export that lost its contents cannot read as a green run.
  test("every frozen vector set carries vectors", () => {
    assert.ok(KEY_VECTORS.length > 0, "KEY_VECTORS is empty");
    assert.ok(AFFECTS_VECTORS.length > 0, "AFFECTS_VECTORS is empty");
    assert.ok(TRANSFORM_KEY_VECTORS.length > 0, "TRANSFORM_KEY_VECTORS is empty");
    assert.ok(TRANSFORM_AFFECTS_VECTORS.length > 0, "TRANSFORM_AFFECTS_VECTORS is empty");
  });

  for (const vector of KEY_VECTORS) {
    test(`key/${vector.name}`, () => {
      const label = `key/${vector.name}`;
      const factory = requiredExport(
        stringModules,
        vector.operation,
        `${vector.operation}Query`,
        label,
      );
      const actual = queryKeyOf(factory(stringTransport, vector.input), label);
      assertKeyMatches(actual, vector.key, label);
    });
  }

  // The single most important property in the frozen set, and the one no individual vector states:
  // the same request path text reached through a literal segment and through a parameter must land
  // on different cache entries. If these ever hash the same, a prefix invalidation aimed at one
  // silently takes the other with it.
  test("key/a literal segment and a parameter of the same text are different cache entries", () => {
    const label = "key/literal-versus-parameter";
    const literal = KEY_VECTORS.find((vector) => vector.name === "literal segment");
    const entity = KEY_VECTORS.find((vector) => vector.name === "entity");
    assert.ok(literal !== undefined, "the 'literal segment' vector is missing");
    assert.ok(entity !== undefined, "the 'entity' vector is missing");
    const literalKey = queryKeyOf(
      requiredExport(
        stringModules,
        literal.operation,
        `${literal.operation}Query`,
        label,
      )(stringTransport, literal.input),
      label,
    );
    const entityKey = queryKeyOf(
      requiredExport(
        stringModules,
        entity.operation,
        `${entity.operation}Query`,
        label,
      )(stringTransport, entity.input),
      label,
    );
    assert.notStrictEqual(
      hashKey(literalKey),
      hashKey(entityKey),
      `${label}: /pets/mine as a literal segment and as a petId value hash to the same cache entry`,
    );
  });

  for (const vector of AFFECTS_VECTORS) {
    test(`affects/${vector.name}`, () => {
      const label = `affects/${vector.name}`;
      const affects = requiredExport(
        stringModules,
        vector.operation,
        `${vector.operation}MutationAffects`,
        label,
      );
      const actual = affectsOf(affects(vector.input), label);
      assert.strictEqual(
        actual.length,
        vector.affects.length,
        `${label}: the invalidation list has the wrong length`,
      );
      for (const [index, expected] of vector.affects.entries()) {
        const entry = actual[index];
        assert.ok(entry !== undefined, `${label}: invalidation entry ${String(index)} is missing`);
        assertKeyMatches(entry, expected, `${label}[${String(index)}]`);
      }
    });
  }

  for (const vector of TRANSFORM_KEY_VECTORS) {
    test(`transform key/${vector.name}`, () => {
      const label = `transform key/${vector.name}`;
      const input = reviveDates(vector.input, vector.dateFields, label);
      const factory = requiredExport(
        dateModules,
        vector.operation,
        `${vector.operation}Query`,
        label,
      );
      const actual = queryKeyOf(factory(dateTransport, input), label);
      assertKeyMatches(actual, vector.key, label);
    });
  }

  for (const vector of TRANSFORM_AFFECTS_VECTORS) {
    test(`transform affects/${vector.name}`, () => {
      const label = `transform affects/${vector.name}`;
      const input = reviveDates(vector.input, vector.dateFields, label);
      const affects = requiredExport(
        dateModules,
        vector.operation,
        `${vector.operation}MutationAffects`,
        label,
      );
      const actual = affectsOf(affects(input), label);
      assert.strictEqual(
        actual.length,
        vector.affects.length,
        `${label}: the invalidation list has the wrong length`,
      );
      for (const [index, expected] of vector.affects.entries()) {
        const entry = actual[index];
        assert.ok(entry !== undefined, `${label}: invalidation entry ${String(index)} is missing`);
        assertKeyMatches(entry, expected, `${label}[${String(index)}]`);
      }
    });
  }
}
