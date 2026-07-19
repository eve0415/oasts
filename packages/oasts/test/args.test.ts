import assert from "node:assert/strict";
import { test } from "node:test";

import { ArgsError, parse } from "../src/args.ts";

test("parses generate with every flag", () => {
  const args = parse([
    "generate",
    "--check",
    "--config",
    "custom.yaml",
    "--spec",
    "a",
    "--spec",
    "b",
    "--locked",
  ]);
  assert.deepEqual(args, {
    command: "generate",
    config: "custom.yaml",
    check: true,
    specs: ["a", "b"],
    locked: true,
  });
});

test("parses bare commands with defaults", () => {
  assert.deepEqual(parse(["check"]), { command: "check", check: false, specs: [], locked: false });
  assert.deepEqual(parse(["watch"]), { command: "watch", check: false, specs: [], locked: false });
});

test("rejects missing, unknown, and duplicated commands", () => {
  assert.throws(() => parse([]), ArgsError);
  assert.throws(() => parse(["deploy"]), ArgsError);
  assert.throws(() => parse(["generate", "extra"]), ArgsError);
});

test("rejects unknown flags and misplaced --check", () => {
  assert.throws(() => parse(["generate", "--unknown"]), ArgsError);
  assert.throws(() => parse(["check", "--check"]), ArgsError);
});
