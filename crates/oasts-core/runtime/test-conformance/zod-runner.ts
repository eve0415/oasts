// Conformance runner for the zod artifact. This file is NOT frozen: it is the harness that drives
// the frozen vectors in ./vectors-zod-conformance.ts against a freshly generated showcase output
// tree, and it may be adjusted as the emitter lands.
//
// Locating the output: set OASTS_ZOD_GENERATED_ROOT to the generated root (the directory that
// contains `zod/`) produced by generating fixtures/validators-showcase-3.1 with a zod-enabled
// config. When the variable is unset or that tree has no `zod/` directory, every test is skipped
// with a diagnostic, so `node --test` over this directory stays green before the emitter exists.
//
// Setting OASTS_VALIDATORS_GENERATED_ROOT as well turns on the dual-engine suite, which is the
// point of the whole exercise: the two engines must produce identical verdicts and
// identical success values on one shared document. It drives the ALREADY-FROZEN validators vectors
// rather than a second copy, so neither engine can be scored against expectations written for it.
//
// Success values are compared structurally, never by serialization. The generated-validators engine
// returns the input by reference; zod reconstructs the object, putting declared properties first and
// unknown keys after. The success value is required to be structurally identical to the
// input, which key reordering satisfies. Issue messages and issue counts are deliberately NOT
// compared: the spec asks the engines to agree on verdicts and values, not on issue prose, and the
// two engines have genuinely different issue models.

import assert from "node:assert/strict";
import { existsSync, readdirSync } from "node:fs";
import { register } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import type { ZodConformanceCase } from "./vectors-zod-conformance.ts";

type ValidateResult = {
  readonly value?: unknown;
  readonly issues?: readonly unknown[] | undefined;
};

type StandardSchemaLike = {
  readonly "~standard": {
    readonly validate: (value: unknown) => ValidateResult | Promise<ValidateResult>;
  };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStandardSchema(value: unknown): value is StandardSchemaLike {
  if (!isRecord(value) || !("~standard" in value)) {
    return false;
  }
  const std = value["~standard"];
  if (!isRecord(std) || !("validate" in std)) {
    return false;
  }
  return typeof std.validate === "function";
}

async function loadExports(root: string, artifact: string): Promise<ReadonlyMap<string, unknown>> {
  const exportsByName = new Map<string, unknown>();
  for (const group of ["components", "operations", "webhooks", "callbacks"]) {
    const groupDir = join(root, artifact, group);
    if (!existsSync(groupDir)) {
      continue;
    }
    for (const entry of readdirSync(groupDir).toSorted()) {
      if (entry.endsWith(".d.ts") || !(entry.endsWith(".ts") || entry.endsWith(".js"))) {
        continue;
      }
      const loaded: unknown = await import(pathToFileURL(join(groupDir, entry)).href);
      if (!isRecord(loaded)) {
        continue;
      }
      for (const [name, value] of Object.entries(loaded)) {
        exportsByName.set(name, value);
      }
    }
  }
  return exportsByName;
}

// Standard Schema v1 permits a path segment to be either a key or a `{ key }` wrapper. Zod emits
// bare keys today; normalizing both keeps the comparison independent of that choice.
function normalizePath(path: unknown, label: string): (string | number)[] {
  assert.ok(Array.isArray(path), `${label}: issue path must be an array`);
  return path.map((segment: unknown) => {
    const key = isRecord(segment) && "key" in segment ? segment.key : segment;
    assert.ok(
      typeof key === "string" || typeof key === "number",
      `${label}: path segments must be strings or numbers`,
    );
    return key;
  });
}

function validateSync(schema: unknown, input: unknown, label: string): ValidateResult {
  assert.ok(isStandardSchema(schema), `${label}: export is not a Standard Schema`);
  const outcome = schema["~standard"].validate(input);
  if (outcome instanceof Promise) {
    assert.fail(`${label}: schemas must validate synchronously, never return a Promise`);
  }
  return outcome;
}

function lookup(exports: ReadonlyMap<string, unknown>, name: string, label: string): unknown {
  const found = exports.get(name);
  if (found === undefined) {
    assert.fail(
      `${label}: export '${name}' was not found; available exports: ${[...exports.keys()].toSorted().join(", ")}`,
    );
  }
  return found;
}

function runZodCase(testCase: ZodConformanceCase, schemas: ReadonlyMap<string, unknown>): void {
  const schema = lookup(schemas, testCase.schema, testCase.id);
  const outcome = validateSync(schema, testCase.input, testCase.id);
  if (testCase.expected.verdict === "pass") {
    assert.strictEqual(
      outcome.issues,
      undefined,
      `${testCase.id}: expected pass but the schema reported issues`,
    );
    // The assert-only value contract: structurally identical to the input, so no unknown-key
    // stripping, no defaults injection, no coercion.
    assert.deepStrictEqual(
      outcome.value,
      testCase.input,
      `${testCase.id}: a passing validation must return a value deep-equal to the input`,
    );
    return;
  }
  const issues = outcome.issues;
  assert.ok(issues !== undefined, `${testCase.id}: expected fail but the schema reported success`);
  const actualPaths = issues.map((issue, index) => {
    assert.ok(isRecord(issue), `${testCase.id}[${index}]: issue must be an object`);
    return normalizePath(issue.path, `${testCase.id}[${index}]`);
  });
  assert.deepStrictEqual(
    actualPaths,
    testCase.expected.issuePaths.map((path) => [...path]),
    `${testCase.id}: issue paths must match the frozen vector, in order`,
  );
}

const zodRoot = process.env.OASTS_ZOD_GENERATED_ROOT;
const zodDir = zodRoot === undefined ? undefined : join(zodRoot, "zod");

if (zodRoot === undefined || zodDir === undefined || !existsSync(zodDir)) {
  const skip =
    zodRoot === undefined
      ? "set OASTS_ZOD_GENERATED_ROOT to the generated output root to run zod conformance"
      : `OASTS_ZOD_GENERATED_ROOT (${zodRoot}) has no zod/ directory; generate the zod artifact first`;
  test("zod conformance", { skip }, () => {});
} else {
  register(new URL("../test-e2e/resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(zodRoot).href },
  });

  const schemas = await loadExports(zodRoot, "zod");
  const { cases } = await import("./vectors-zod-conformance.ts");

  for (const testCase of cases) {
    test(testCase.id, () => {
      runZodCase(testCase, schemas);
    });
  }

  // --- dual-engine suite ---------------------------------------------------------------------
  const validatorsRoot = process.env.OASTS_VALIDATORS_GENERATED_ROOT;
  const validatorsDir =
    validatorsRoot === undefined ? undefined : join(validatorsRoot, "validators");

  if (validatorsRoot === undefined || validatorsDir === undefined || !existsSync(validatorsDir)) {
    test(
      "dual-engine conformance",
      {
        skip: "set OASTS_VALIDATORS_GENERATED_ROOT alongside OASTS_ZOD_GENERATED_ROOT to compare engines",
      },
      () => {},
    );
  } else {
    register(new URL("../test-e2e/resolve-generated.mjs", import.meta.url), {
      data: { generatedRootUrl: pathToFileURL(validatorsRoot).href },
    });

    const validators = await loadExports(validatorsRoot, "validators");
    // The frozen validators vectors, driven against both engines. The export naming rule is the
    // only mapping: the two artifacts allocate names from the same pass, so a validator and its
    // schema differ by suffix alone.
    const { cases: sharedCases } = await import("./vectors-validators-conformance.ts");

    // A suite that quietly compares fewer pairs than the frozen set contains is exactly the failure
    // this design exists to prevent, so the comparisons are counted and the count is asserted. On
    // its own, "every registered case passed" cannot tell a full run from an empty one.
    let compared = 0;

    for (const testCase of sharedCases) {
      const schemaName = `${testCase.validator.replace(/Validator$/u, "")}Schema`;
      test(`dual-engine/${testCase.id}`, () => {
        const label = `dual-engine/${testCase.id}`;
        const validatorOutcome = validateSync(
          lookup(validators, testCase.validator, label),
          testCase.input,
          label,
        );
        const schemaOutcome = validateSync(
          lookup(schemas, schemaName, label),
          testCase.input,
          label,
        );

        const validatorPassed = validatorOutcome.issues === undefined;
        const schemaPassed = schemaOutcome.issues === undefined;
        assert.strictEqual(
          schemaPassed,
          validatorPassed,
          `${label}: engines disagree — validators ${validatorPassed ? "passed" : "failed"}, zod ${schemaPassed ? "passed" : "failed"}`,
        );

        compared += 1;
        if (!validatorPassed) {
          return;
        }
        // Both engines must hand back the same value, and it must be the input's structure.
        assert.deepStrictEqual(
          schemaOutcome.value,
          validatorOutcome.value,
          `${label}: engines returned different success values`,
        );
        assert.deepStrictEqual(
          schemaOutcome.value,
          testCase.input,
          `${label}: the success value must be structurally identical to the input`,
        );
      });
    }

    // Registered last, so every case above has run by the time this executes.
    test("dual-engine covers every frozen validators vector", () => {
      assert.ok(sharedCases.length > 0, "the frozen validators vector set must not be empty");
      assert.strictEqual(
        compared,
        sharedCases.length,
        `only ${compared} of ${sharedCases.length} frozen vectors were compared across engines`,
      );
    });
  }
}
