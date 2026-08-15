/**
 * End-to-end parity suite, run OUTSIDE the coverage gate
 * (`scripts/coverage-ts.sh` covers `test/`; child processes are not
 * instrumented, so spawned-binary tests live here): the Node CLI, driven
 * through the built `dist/cli.js` bundle, must produce output byte-identical
 * to the Rust binary run against the equivalent YAML config.
 */

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = join(PACKAGE_ROOT, "../..");
const FIXTURE = join(REPO_ROOT, "fixtures/petstore-3.0");
const BIN = join(PACKAGE_ROOT, "dist/cli.js");
const RUST_BIN = join(REPO_ROOT, "target/debug/oasts");

// The repo's Rust toolchain pin only applies inside the repo, so build there
// once and spawn the produced binary from the temp working directories.
execFileSync("cargo", ["build", "--quiet", "-p", "oasts"], { cwd: REPO_ROOT });

function nodeCli(
  args: readonly string[],
  cwd: string,
): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: "utf8" });
  assert.equal(result.error, undefined);
  return { status: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

function treeBytes(root: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const entry of readdirSync(root, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) {
      const absolute = join(entry.parentPath, entry.name);
      entries.set(absolute.slice(root.length + 1), readFileSync(absolute, "latin1"));
    }
  }
  return entries;
}

test("TS-config output is byte-identical to the Rust binary's YAML-config output", () => {
  const rustDirectory = mkdtempSync(join(tmpdir(), "oasts-e2e-rust-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(rustDirectory, "openapi.yaml"));
  copyFileSync(join(FIXTURE, "oasts.yaml"), join(rustDirectory, "oasts.yaml"));
  execFileSync(RUST_BIN, ["generate"], { cwd: rustDirectory });

  const nodeDirectory = mkdtempSync(join(tmpdir(), "oasts-e2e-node-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(nodeDirectory, "openapi.yaml"));
  writeFileSync(
    join(nodeDirectory, "oasts.config.ts"),
    `import { defineConfig } from ${JSON.stringify(join(PACKAGE_ROOT, "config.ts"))};

export default defineConfig({
  schemaVersion: 1,
  input: { path: "./openapi.yaml" },
  output: "./generated",
});
`,
  );
  const generated = nodeCli(["generate"], nodeDirectory);
  assert.equal(generated.status, 0, generated.stderr);
  assert.match(generated.stdout, /^generated \d+ files\n$/);

  const rustTree = treeBytes(join(rustDirectory, "generated"));
  const nodeTree = treeBytes(join(nodeDirectory, "generated"));
  assert.deepEqual([...nodeTree.keys()].toSorted(), [...rustTree.keys()].toSorted());
  for (const [path, bytes] of rustTree) {
    assert.equal(nodeTree.get(path), bytes, path);
  }

  const clean = nodeCli(["generate", "--check"], nodeDirectory);
  assert.equal(clean.status, 0, clean.stderr);
  assert.equal(clean.stdout, "check ok\n");

  const [firstFile] = [...nodeTree.keys()].filter((path) => path.endsWith(".ts")).toSorted();
  assert.notEqual(firstFile, undefined);
  writeFileSync(join(nodeDirectory, "generated", firstFile ?? ""), "edited\n");
  const drifted = nodeCli(["generate", "--check"], nodeDirectory);
  assert.equal(drifted.status, 1);
  assert.match(drifted.stderr, /edited: /);
});

test("invalid script config exits 2 through the spawned bin", () => {
  const directory = mkdtempSync(join(tmpdir(), "oasts-e2e-invalid-"));
  copyFileSync(join(FIXTURE, "openapi.yaml"), join(directory, "openapi.yaml"));
  writeFileSync(join(directory, "oasts.config.ts"), "export default Promise.resolve({});\n");
  const result = nodeCli(["generate"], directory);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /error\[OASTS0013\]: config default export is a promise/);
});

test("the standalone Rust binary still rejects script configs with OASTS9001", () => {
  const directory = mkdtempSync(join(tmpdir(), "oasts-e2e-rust-script-"));
  writeFileSync(join(directory, "oasts.config.ts"), "export default {};\n");
  const result = spawnSync(RUST_BIN, ["generate"], { cwd: directory, encoding: "utf8" });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /error\[OASTS9001\]/);
});
