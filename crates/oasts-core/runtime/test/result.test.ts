import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  FROZEN_FAILURE_MODEL,
  FROZEN_STREAM_FAILURE,
  FROZEN_TRANSFORM_ERROR,
} from "./frozen-declarations.ts";
import { ApiError, TransformError, unwrap } from "../result.ts";

const source = readFileSync(new URL("../result.ts", import.meta.url), "utf8");
const failureAliasSegment = FROZEN_FAILURE_MODEL.slice(
  0,
  FROZEN_FAILURE_MODEL.indexOf("export declare class ApiError"),
).trimEnd();
const transformAliasSegment = FROZEN_TRANSFORM_ERROR.slice(
  0,
  FROZEN_TRANSFORM_ERROR.indexOf("\n\nexport declare class TransformError"),
);
const transformAliasLines = transformAliasSegment.split("\n");

function frozenDeclarationLines(block: string, header: string): string[] {
  const classText = block.slice(block.indexOf(header));
  return classText
    .split("\n")
    .filter((line) => line.trimStart().startsWith("readonly "))
    .map((line) => line.split("//")[0].trimEnd());
}

test("Standard Schema types come from an erasable module", () => {
  assert.ok(source.includes("import type * as StandardSchemaV1 from './standard-schema.ts';"));
  assert.ok(!source.includes("namespace"));
});

test("result declarations preserve frozen source blocks", () => {
  assert.ok(source.includes(failureAliasSegment));
  assert.ok(source.includes(FROZEN_STREAM_FAILURE));
  for (const line of transformAliasLines) {
    assert.ok(source.includes(line));
  }
});

test("result classes preserve their frozen surface", () => {
  assert.ok(source.includes("export class ApiError<Failed> extends Error {"));
  assert.ok(source.includes("export class TransformError extends Error {"));

  for (const line of frozenDeclarationLines(
    FROZEN_FAILURE_MODEL,
    "export declare class ApiError",
  )) {
    if (line.includes("readonly name:")) {
      // The real class uses override plus an initializer to establish Error.name at runtime.
      assert.equal(new ApiError({}).name, "ApiError");
    } else {
      assert.ok(source.includes(line));
    }
  }
  for (const line of frozenDeclarationLines(
    FROZEN_TRANSFORM_ERROR,
    "export declare class TransformError",
  )) {
    if (line.includes("readonly name:")) {
      // The real class uses override plus an initializer to establish Error.name at runtime.
      assert.equal(
        new TransformError({
          direction: "request",
          code: "invalid-wire-value",
          sourcePointer: { logicalSourceId: "source", jsonPointer: "#" },
          applicationPath: [],
          cause: undefined,
        }).name,
        "TransformError",
      );
    } else {
      assert.ok(source.includes(line));
    }
  }
});

test("ApiError preserves the failed result by identity", () => {
  const failed = { ok: false as const, error: "failed" };
  const error = new ApiError(failed);

  assert.equal(error.message, "Oasts API call failed");
  assert.equal(error.result, failed);
  assert.equal(error.name, "ApiError");
  assert.ok(error instanceof ApiError);
  assert.ok(error instanceof Error);
});

test("TransformError preserves every field", () => {
  const fields = {
    direction: "response" as const,
    code: "invalid-application-value" as const,
    sourcePointer: { logicalSourceId: "petstore", jsonPointer: "/Pet/id" },
    applicationPath: ["id", 0] as const,
    cause: new Error("bad value"),
  };
  const error = new TransformError(fields);

  assert.equal(error.name, "TransformError");
  assert.equal(error.direction, fields.direction);
  assert.equal(error.code, fields.code);
  assert.equal(error.sourcePointer, fields.sourcePointer);
  assert.equal(error.applicationPath, fields.applicationPath);
  assert.equal(error.cause, fields.cause);
});

test("unwrap returns data or throws the complete failed branch", () => {
  const data = { id: "pet_123" };
  assert.equal(unwrap({ ok: true as const, data }), data);

  const failed = { ok: false as const, error: "failed" };
  assert.throws(
    () => unwrap(failed),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.result, failed);
      return true;
    },
  );
});
