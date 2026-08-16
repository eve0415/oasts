import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadScriptConfig } from "../src/config/load.ts";
import { CliFailure } from "../src/diagnostics.ts";

function writeConfig(source: string, name = "oasts.config.ts"): string {
  const directory = mkdtempSync(join(tmpdir(), "oasts-load-"));
  const path = join(directory, name);
  writeFileSync(path, source);
  return path;
}

async function expectFailure(
  promise: Promise<string>,
  code: string,
  pattern: RegExp,
): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof CliFailure);
    assert.equal(error.exitCode, 2);
    assert.match(error.renderedStderr, new RegExp(`error\\[${code}\\]`));
    assert.match(error.renderedStderr, pattern);
    return true;
  });
}

test("loads a TypeScript config and returns JSON text", async () => {
  const path = writeConfig(
    "const config: { schemaVersion: number } = { schemaVersion: 1 };\nexport default config;\n",
  );
  assert.deepEqual(JSON.parse(await loadScriptConfig(path)), { schemaVersion: 1 });
});

test("cache-busts between imports of the same path", async () => {
  const path = writeConfig("export default { schemaVersion: 1 };\n");
  assert.deepEqual(JSON.parse(await loadScriptConfig(path)), { schemaVersion: 1 });
  writeFileSync(path, "export default { schemaVersion: 2 };\n");
  assert.deepEqual(JSON.parse(await loadScriptConfig(path)), { schemaVersion: 2 });
});

test("rejects Node versions below the type-stripping floor", async () => {
  const path = writeConfig("export default {};\n");
  await expectFailure(loadScriptConfig(path, "20.19.0"), "OASTS0012", /requires Node >= 24/);
  await expectFailure(loadScriptConfig(path, "not-a-version"), "OASTS0012", /requires Node >= 24/);
});

test("reports import failures", async () => {
  const path = writeConfig("throw new Error('boom at import');\n", "oasts.config.mjs");
  await expectFailure(
    loadScriptConfig(path),
    "OASTS0012",
    /failed to import config module: boom at import/,
  );
});

test("rejects missing, function, non-object, and promise defaults", async () => {
  await expectFailure(
    loadScriptConfig(writeConfig("export const named = 1;\n")),
    "OASTS0012",
    /no default export/,
  );
  await expectFailure(
    loadScriptConfig(writeConfig("export default () => ({});\n")),
    "OASTS0012",
    /is a function/,
  );
  await expectFailure(
    loadScriptConfig(writeConfig("export default 42;\n")),
    "OASTS0012",
    /must be an object/,
  );
  await expectFailure(
    loadScriptConfig(writeConfig("export default null;\n")),
    "OASTS0012",
    /must be an object/,
  );
  await expectFailure(
    loadScriptConfig(writeConfig("export default Promise.resolve({});\n")),
    "OASTS0012",
    /is a promise/,
  );
  await expectFailure(
    loadScriptConfig(writeConfig("export default { then: () => ({}) };\n")),
    "OASTS0012",
    /is a promise/,
  );
});

test("rejects non-serializable exports with the offending path", async () => {
  await expectFailure(
    loadScriptConfig(writeConfig("export default { spec: { hooks: [() => 1] } };\n")),
    "OASTS0013",
    /functions cannot be represented in JSON at spec\.hooks\[0\]/,
  );
});
