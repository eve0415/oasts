// End-to-end coverage of per-media response validation: one 200 declaring two JSON media entries
// whose schemas are mutually exclusive, so validating the wrong entry's schema is observable rather
// than silently equivalent. Each vector serves a body under one content type and asserts the arm
// that ran was that entry's own.
//
// Generated modules cross the dynamic-import boundary as `unknown` and are narrowed with the
// harness guards, so no generated symbol is imported at type-check time.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { access, cp, mkdtemp, rm } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import {
  createScriptedServer,
  requiredFunction,
  requiredRecord,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/media-validation-3.1");

const JSON_MEDIA = "application/json";
const VND_MEDIA = "application/vnd.api+json";
// Valid under application/json, invalid under application/vnd.api+json, and vice versa.
const JSON_BODY = '{"id":"r_1"}';
const VND_BODY = '{"code":7}';

const harness = createScriptedServer();
const { routes, requests, scriptRoute } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let readReport: ExportedFunction;

before(async () => {
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new Error(
      `media-validation E2E requires ${binary}; run \`cargo build -p oasts\` before this suite`,
    );
  }

  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-media-validation-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "media-validation-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  execFileSync(binary, ["generate", "--config", "oasts.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  const generatedRoot = path.join(fixtureRoot, "generated");

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });
  const operationModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/readreport.ts")).href
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  readReport = requiredFunction(operationModule, "readReport");
  createTransport = requiredFunction(transportModule, "createTransport");

  baseUrl = await harness.start();
});

beforeEach(() => {
  routes.clear();
  requests.length = 0;
});

after(async () => {
  await harness.stop();
  await rm(temporaryRoot, { recursive: true, force: true });
});

async function call(contentType: string, body: string): Promise<Readonly<Record<string, unknown>>> {
  scriptRoute("GET", "/report", {
    status: 200,
    headers: [["Content-Type", contentType]],
    body: Buffer.from(body),
  });
  return requiredRecord(
    await readReport(createTransport({ baseUrl }), {}),
    `${contentType} result`,
  );
}

for (const [contentType, body] of [
  [JSON_MEDIA, JSON_BODY],
  [VND_MEDIA, VND_BODY],
] as const) {
  test(`a body valid under ${contentType} passes under ${contentType}`, async () => {
    const result = await call(contentType, body);
    assert.equal(result.outcome, 200);
    assert.equal(result.ok, true);
    assert.equal(result.contentType, contentType);
  });
}

for (const [served, body, other] of [
  [VND_MEDIA, JSON_BODY, JSON_MEDIA],
  [JSON_MEDIA, VND_BODY, VND_MEDIA],
] as const) {
  test(`a body valid only under ${other} fails validation when served as ${served}`, async () => {
    // The core of the correlation: this body would pass the *other* entry's validator, so a client
    // still checking the first declared JSON entry would let it through.
    const result = await call(served, body);
    assert.equal(result.outcome, "response-validation");
    assert.equal(result.match, 200);
    assert.equal(result.status, 200);
    assert.ok(Array.isArray(result.issues) && result.issues.length > 0, String(result.issues));
  });
}
