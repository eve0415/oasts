import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { run } from "../src/cli.ts";

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "../../../fixtures/petstore-3.0");

interface Invocation {
  code: number;
  stdout: string;
  stderr: string;
}

async function invoke(argv: readonly string[], cwd: string): Promise<Invocation> {
  let stdout = "";
  let stderr = "";
  const code = await run(
    argv,
    cwd,
    {
      write(text) {
        stdout += text;
      },
    },
    {
      write(text) {
        stderr += text;
      },
    },
  );
  return { code, stdout, stderr };
}

function scriptFixture(): string {
  const directory = mkdtempSync(join(tmpdir(), "oasts-cli-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(directory, "openapi.yaml"));
  writeFileSync(
    join(directory, "oasts.config.ts"),
    'export default { schemaVersion: 1, input: { path: "./openapi.yaml" }, output: "./generated" };\n',
  );
  return directory;
}

function yamlFixture(): string {
  const directory = mkdtempSync(join(tmpdir(), "oasts-cli-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(directory, "openapi.yaml"));
  copyFileSync(join(FIXTURE, "oasts.yaml"), join(directory, "oasts.yaml"));
  return directory;
}

test("generate and check succeed with a script config", async () => {
  const directory = scriptFixture();
  const generated = await invoke(["generate"], directory);
  assert.equal(generated.code, 0, generated.stderr);
  assert.match(generated.stdout, /^generated \d+ files\n$/);
  assert.equal(generated.stderr, "");

  const checked = await invoke(["check"], directory);
  assert.equal(checked.code, 0, checked.stderr);
  assert.equal(checked.stdout, "check ok\n");

  const clean = await invoke(["generate", "--check"], directory);
  assert.equal(clean.code, 0, clean.stderr);
  assert.equal(clean.stdout, "check ok\n");
});

test("generate --check reports drift with exit 1", async () => {
  const directory = scriptFixture();
  assert.equal((await invoke(["generate"], directory)).code, 0);
  const manifest: unknown = JSON.parse(
    readFileSync(join(directory, "generated/.oasts-manifest.json"), "utf8"),
  );
  assert.ok(typeof manifest === "object" && manifest !== null && "files" in manifest);
  const files = manifest.files;
  assert.ok(Array.isArray(files) && typeof files[0] === "string");
  writeFileSync(join(directory, "generated", files[0]), "edited\n");

  const drifted = await invoke(["generate", "--check"], directory);
  assert.equal(drifted.code, 1);
  assert.equal(drifted.stdout, "");
  assert.match(drifted.stderr, /edited: /);
});

test("data configs pass through without script evaluation", async () => {
  const directory = yamlFixture();
  const generated = await invoke(["generate", "--config", "oasts.yaml"], directory);
  assert.equal(generated.code, 0, generated.stderr);
  assert.match(generated.stdout, /^generated \d+ files\n$/);
});

test("warnings reach stderr on successful runs", async () => {
  const directory = mkdtempSync(join(tmpdir(), "oasts-cli-"));
  writeFileSync(
    join(directory, "openapi.json"),
    '{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Choice":{"oneOf":[{"type":"string"},{"type":"integer"}],"discriminator":{"propertyName":"kind"}}}}}',
  );
  writeFileSync(
    join(directory, "oasts.config.ts"),
    // A schema-only document: every component is unreachable, so pruning is opted out of.
    'export default { schemaVersion: 1, input: { path: "./openapi.json" }, output: "./generated", filters: { orphans: true } };\n',
  );
  const generated = await invoke(["generate"], directory);
  assert.equal(generated.code, 0);
  assert.match(generated.stderr, /warning\[OASTS1304\]/);
});

test("usage, watch, discovery, spec, and config failures exit 2", async () => {
  const empty = mkdtempSync(join(tmpdir(), "oasts-cli-"));
  const usage = await invoke(["generate", "--unknown"], empty);
  assert.equal(usage.code, 2);
  assert.match(usage.stderr, /Usage: oasts/);

  const watch = await invoke(["watch"], empty);
  assert.equal(watch.code, 2);
  assert.match(watch.stderr, /error\[OASTS0222\]: the watch command is not supported/);

  const undiscovered = await invoke(["check"], empty);
  assert.equal(undiscovered.code, 2);
  assert.match(undiscovered.stderr, /error\[OASTS0011\]/);

  const spec = await invoke(["generate", "--spec", "petstore"], scriptFixture());
  assert.equal(spec.code, 2);
  assert.match(spec.stderr, /error\[OASTS0062\]/);

  const invalid = scriptFixture();
  writeFileSync(join(invalid, "oasts.config.ts"), "export default Promise.resolve({});\n");
  const asyncConfig = await invoke(["generate"], invalid);
  assert.equal(asyncConfig.code, 2);
  assert.match(asyncConfig.stderr, /error\[OASTS0013\]: config default export is a promise/);

  const badSchema = scriptFixture();
  writeFileSync(
    join(badSchema, "oasts.config.ts"),
    'export default { schemaVersion: 2, input: { path: "./openapi.yaml" }, output: "./generated" };\n',
  );
  const rejected = await invoke(["generate"], badSchema);
  assert.equal(rejected.code, 2);
  assert.match(rejected.stderr, /error\[OASTS0041\]/);
});

test("input errors from the core exit 1", async () => {
  const directory = scriptFixture();
  writeFileSync(
    join(directory, "openapi.yaml"),
    "openapi: '2.0'\ninfo: { title: Invalid, version: 1.0.0 }\npaths: {}\n",
  );
  const failed = await invoke(["generate"], directory);
  assert.equal(failed.code, 1);
  assert.match(failed.stderr, /error\[OASTS1101\]/);
});

test("unexpected non-CliFailure errors exit 2", async () => {
  const directory = scriptFixture();
  let stderr = "";
  const stderrSink = {
    write(text: string) {
      stderr += text;
    },
  };
  const throwingError = await run(
    ["generate"],
    directory,
    {
      write() {
        throw new Error("broken pipe");
      },
    },
    stderrSink,
  );
  assert.equal(throwingError, 2);
  assert.match(stderr, /error: broken pipe/);

  stderr = "";
  const throwingValue = await run(
    ["generate"],
    directory,
    {
      write() {
        throw "not an error object";
      },
    },
    stderrSink,
  );
  assert.equal(throwingValue, 2);
  assert.match(stderr, /error: not an error object/);
});
