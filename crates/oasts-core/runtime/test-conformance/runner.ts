// Conformance runner for the generated validators artifact. This file is NOT frozen: it is the
// harness that drives the frozen vectors in ./vectors-validators-conformance.ts against a freshly
// generated showcase output tree, and it may be adjusted as the emitter lands.
//
// Locating the output: set OASTS_VALIDATORS_GENERATED_ROOT to the generated root (the directory that
// contains `validators/` and `types/`) produced by generating fixtures/validators-showcase-3.1 with
// a validators-enabled config. When the variable is unset or that tree has no `validators/`
// directory yet, every conformance test is skipped with a diagnostic, so `node --test` over this
// directory stays green before the emitter exists.
//
// The generated validators import their siblings with `.js` specifiers over on-disk `.ts` files, so
// this runner reuses ../test-e2e/resolve-generated.mjs to retry a failing `.js` resolution at the
// sibling `.ts` path, exactly as the client end-to-end suite does.

import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { register } from "node:module";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import type { ConformanceCase } from "./vectors-validators-conformance.ts";

type MatrixRow = { readonly keyword: string; readonly disposition: string };

type ValidateResult = {
  readonly value?: unknown;
  readonly issues?: readonly unknown[] | undefined;
};

type StandardSchemaLike = {
  readonly "~standard": {
    readonly validate: (value: unknown) => ValidateResult | Promise<ValidateResult>;
  };
};

type NormalizedIssue = {
  readonly message: string;
  readonly path: readonly (string | number)[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
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

// A strict line-based reader for the fixed block-YAML matrix this repo authors. It pairs each
// `- keyword:` with the `disposition:` that follows it in the same row; anything unexpected throws.
function parseMatrixRows(source: string): readonly MatrixRow[] {
  const rows: MatrixRow[] = [];
  let pendingKeyword: string | undefined;
  for (const rawLine of source.split("\n")) {
    const line = rawLine.trimEnd();
    const trimmed = line.trimStart();
    if (trimmed.startsWith("#") || trimmed.length === 0) {
      continue;
    }
    const keyword = matchField(trimmed, "- keyword:") ?? matchField(trimmed, "keyword:");
    if (keyword !== undefined) {
      pendingKeyword = keyword;
      continue;
    }
    const disposition = matchField(trimmed, "disposition:");
    if (disposition !== undefined) {
      if (pendingKeyword === undefined) {
        throw new Error(`matrix disposition '${disposition}' has no preceding keyword`);
      }
      if (disposition !== "exact" && disposition !== "annotation" && disposition !== "reject") {
        throw new Error(
          `matrix keyword '${pendingKeyword}' has invalid disposition '${disposition}'`,
        );
      }
      rows.push({ keyword: pendingKeyword, disposition });
      pendingKeyword = undefined;
    }
  }
  if (rows.length === 0) {
    throw new Error("keyword matrix produced no rows");
  }
  return rows;
}

function matchField(line: string, prefix: string): string | undefined {
  if (!line.startsWith(prefix)) {
    return undefined;
  }
  const value = line.slice(prefix.length).trim();
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    return value.slice(1, -1);
  }
  return value;
}

async function loadValidatorExports(validatorsDir: string): Promise<ReadonlyMap<string, unknown>> {
  const exportsByName = new Map<string, unknown>();
  for (const group of ["components", "operations", "webhooks", "callbacks"]) {
    const groupDir = join(validatorsDir, group);
    if (!existsSync(groupDir)) {
      continue;
    }
    for (const entry of readdirSync(groupDir).toSorted()) {
      if (entry.endsWith(".d.ts") || !(entry.endsWith(".ts") || entry.endsWith(".js"))) {
        continue;
      }
      const moduleUrl = pathToFileURL(join(groupDir, entry)).href;
      const loaded: unknown = await import(moduleUrl);
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

function normalizeIssue(issue: unknown, label: string): NormalizedIssue {
  assert.ok(isRecord(issue), `${label}: issue must be a plain object`);
  assert.strictEqual(
    Object.getPrototypeOf(issue),
    Object.prototype,
    `${label}: issue must be a plain object`,
  );
  assert.deepStrictEqual(
    Object.keys(issue).toSorted(),
    ["message", "path"],
    `${label}: issue must have exactly the message and path keys`,
  );
  assert.ok(typeof issue.message === "string", `${label}: message must be a string`);
  assert.ok(isUnknownArray(issue.path), `${label}: path must be an array`);
  const path: (string | number)[] = [];
  for (const segment of issue.path) {
    assert.ok(
      typeof segment === "string" || typeof segment === "number",
      `${label}: path segments must be strings or numbers`,
    );
    path.push(segment);
  }
  return { message: issue.message, path };
}

function runCase(testCase: ConformanceCase, validators: ReadonlyMap<string, unknown>): void {
  const schema = validators.get(testCase.validator);
  if (schema === undefined) {
    assert.fail(
      `${testCase.id}: validator export '${testCase.validator}' was not found; available exports: ${[...validators.keys()].toSorted().join(", ")}`,
    );
  }
  assert.ok(
    isStandardSchema(schema),
    `${testCase.id}: export '${testCase.validator}' is not a Standard Schema`,
  );
  const outcome = schema["~standard"].validate(testCase.input);
  if (outcome instanceof Promise) {
    assert.fail(`${testCase.id}: validators must validate synchronously, never return a Promise`);
  }
  const issues = outcome.issues;
  if (testCase.expected.verdict === "pass") {
    assert.strictEqual(
      issues,
      undefined,
      `${testCase.id}: expected pass but the validator reported issues`,
    );
    assert.strictEqual(
      outcome.value,
      testCase.input,
      `${testCase.id}: a passing validation must return the input value by reference`,
    );
    return;
  }
  assert.ok(
    issues !== undefined,
    `${testCase.id}: expected fail but the validator reported success`,
  );
  assert.ok(Array.isArray(issues), `${testCase.id}: issues must be an array`);
  assert.strictEqual(
    Object.getPrototypeOf(issues),
    Array.prototype,
    `${testCase.id}: issues must be a plain array`,
  );
  const normalized = issues.map((issue, index) =>
    normalizeIssue(issue, `${testCase.id}[${index}]`),
  );
  assert.deepStrictEqual(
    normalized,
    testCase.expected.issues.map((issue) => ({ message: issue.message, path: [...issue.path] })),
    `${testCase.id}: issue array must match the frozen vector exactly, in document order`,
  );
}

const generatedRoot = process.env.OASTS_VALIDATORS_GENERATED_ROOT;
const validatorsDir = generatedRoot === undefined ? undefined : join(generatedRoot, "validators");

if (generatedRoot === undefined || validatorsDir === undefined || !existsSync(validatorsDir)) {
  const skip =
    generatedRoot === undefined
      ? "set OASTS_VALIDATORS_GENERATED_ROOT to the generated output root to run validators conformance"
      : `OASTS_VALIDATORS_GENERATED_ROOT (${generatedRoot}) has no validators/ directory; generate the validators artifact first`;
  test("validators conformance", { skip }, () => {});
} else {
  register(new URL("../test-e2e/resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });

  const validators = await loadValidatorExports(validatorsDir);

  // The vector set is fixture-selected: the default showcase set is scoped to the keyword matrix,
  // while the readonly set targets the readOnly/writeOnly request/response validator split (a
  // variance the showcase schemas never carry). The matrix-coverage self-checks below therefore
  // apply only to the showcase set.
  const fixture = process.env.OASTS_VALIDATORS_CONFORMANCE_FIXTURE ?? "showcase";
  const cases: readonly ConformanceCase[] =
    fixture === "readonly"
      ? (await import("./vectors-validators-readonly-conformance.ts")).cases
      : fixture === "webhooks"
        ? (await import("./vectors-validators-webhooks-conformance.ts")).cases
        : (await import("./vectors-validators-conformance.ts")).cases;

  for (const testCase of cases) {
    test(testCase.id, () => {
      runCase(testCase, validators);
    });
  }

  if (fixture === "showcase") {
    const repoRoot = resolve(import.meta.dirname, "../../../..");
    const matrixRows = parseMatrixRows(
      readFileSync(join(repoRoot, "fixtures/validators-keyword-matrix.yaml"), "utf8"),
    );
    const knownRows = new Set(matrixRows.map((row) => row.keyword));
    const exactRows = matrixRows
      .filter((row) => row.disposition === "exact")
      .map((row) => row.keyword);

    test("every conformance case names a real matrix row", () => {
      for (const testCase of cases) {
        assert.ok(
          knownRows.has(testCase.matrixRow),
          `case '${testCase.id}' references unknown matrix row '${testCase.matrixRow}'`,
        );
      }
    });

    test("every exact matrix row has at least one pass and one fail case", () => {
      const passRows = new Set<string>();
      const failRows = new Set<string>();
      for (const testCase of cases) {
        if (testCase.expected.verdict === "pass") {
          passRows.add(testCase.matrixRow);
        } else {
          failRows.add(testCase.matrixRow);
        }
      }
      const uncovered = exactRows.filter((row) => !passRows.has(row) || !failRows.has(row));
      assert.deepStrictEqual(
        uncovered,
        [],
        `exact matrix rows missing a pass and/or fail case: ${uncovered.join(", ")}`,
      );
    });
  }
}
