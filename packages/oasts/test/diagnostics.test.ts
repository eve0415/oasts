import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CliFailure,
  configFailure,
  fromNativeError,
  fromNativeLoadError,
  render,
} from "../src/diagnostics.ts";

test("render matches the core stderr dialect", () => {
  const rendered = render([
    { code: "OASTS0012", severity: "error", message: "boom", sourceId: "oasts.config.ts" },
    { code: "OASTS4202", severity: "warning", message: "structural" },
  ]);
  assert.equal(
    rendered,
    "error[OASTS0012]: boom\n  --> oasts.config.ts:1:1\nwarning[OASTS4202]: structural\n",
  );
});

test("configFailure carries exit code 2 with optional source", () => {
  const located = configFailure("OASTS0012", "boom", "config.ts");
  assert.equal(located.exitCode, 2);
  assert.match(located.renderedStderr, /--> config.ts:1:1/);
  const bare = configFailure("OASTS0012", "boom");
  assert.doesNotMatch(bare.renderedStderr, /-->/);
});

test("fromNativeError parses structured napi reasons", () => {
  const failure = fromNativeError(
    new Error(
      JSON.stringify({ exitCode: 2, renderedStderr: "error[OASTS0011]: none\n", diagnostics: [] }),
    ),
  );
  assert.equal(failure.exitCode, 2);
  assert.equal(failure.renderedStderr, "error[OASTS0011]: none\n");
});

test("fromNativeError wraps unstructured failures", () => {
  const plain = fromNativeError(new Error("segfault adjacent"));
  assert.equal(plain.exitCode, 2);
  assert.match(plain.renderedStderr, /native invocation failed: segfault adjacent/);

  const wrongShape = fromNativeError(new Error(JSON.stringify({ unrelated: true })));
  assert.match(wrongShape.renderedStderr, /native invocation failed/);

  const nonError = fromNativeError("just a string");
  assert.match(nonError.renderedStderr, /native invocation failed: just a string/);

  assert.ok(plain instanceof CliFailure);
});

test("fromNativeLoadError renders an exit 2 diagnostic", () => {
  const error = fromNativeLoadError(new Error("missing binary"));
  assert.equal(error.exitCode, 2);
  assert.equal(
    error.renderedStderr,
    "error[OASTS1023]: native module load failed: missing binary\n",
  );

  const thrownValue = fromNativeLoadError("missing value");
  assert.match(thrownValue.renderedStderr, /native module load failed: missing value/);
});
