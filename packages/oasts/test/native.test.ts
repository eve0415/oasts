import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";

import { CliFailure } from "../src/diagnostics.ts";
import { loadNative } from "../src/native.ts";

test("loadNative wraps binding load failures", async () => {
  const previous = process.env.NAPI_RS_NATIVE_LIBRARY_PATH;
  process.env.NAPI_RS_NATIVE_LIBRARY_PATH = join(process.cwd(), "missing-oasts-binding.node");
  try {
    await assert.rejects(loadNative(), (error: unknown) => {
      assert.ok(error instanceof CliFailure);
      assert.equal(error.exitCode, 2);
      assert.match(error.renderedStderr, /error\[OASTS1023\]: native module load failed:/);
      return true;
    });
  } finally {
    if (previous === undefined) {
      delete process.env.NAPI_RS_NATIVE_LIBRARY_PATH;
    } else {
      process.env.NAPI_RS_NATIVE_LIBRARY_PATH = previous;
    }
  }
});
