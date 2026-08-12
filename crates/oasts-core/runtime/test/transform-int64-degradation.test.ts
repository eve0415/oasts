import assert from "node:assert/strict";
import { test } from "node:test";

import { TransformError } from "../result.ts";

const POINTER = {
  logicalSourceId: "workspace/openapi.yaml",
  jsonPointer: "/components/schemas/Counter/properties/id",
};
const PATH: readonly (string | number)[] = ["body", "id"];

test("int64 encoding degrades independently when raw JSON is unavailable", async () => {
  const saved = Object.getOwnPropertyDescriptor(JSON, "rawJSON");
  Object.defineProperty(JSON, "rawJSON", { value: undefined, configurable: true });
  try {
    const { encodeInt64 } = await import("../transform-runtime.ts");

    assert.equal(encodeInt64(42n, POINTER, PATH), 42);
    assert.throws(
      () => encodeInt64(12_345_678_901_234_567_890n, POINTER, PATH),
      (error: unknown) => {
        assert.ok(error instanceof TransformError);
        assert.equal(error.direction, "request");
        assert.equal(error.code, "invalid-application-value");
        assert.deepEqual(error.sourcePointer, POINTER);
        assert.deepEqual(error.applicationPath, PATH);
        return true;
      },
    );
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(JSON, "rawJSON");
    } else {
      Object.defineProperty(JSON, "rawJSON", saved);
    }
  }
});
