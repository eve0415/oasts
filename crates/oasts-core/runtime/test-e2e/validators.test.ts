// End-to-end coverage of the generated validation binding: the showcase fixture is generated with
// `validation.engine: generated` (request + response), then its client operations are driven against
// the scripted local server. The suite proves the wrapper short-circuits an invalid request before
// any fetch, rejects a malformed documented body after decode, round-trips a valid exchange, and
// propagates a validation failure through the orThrow convention. Generated modules cross the
// dynamic-import boundary as `unknown` and are narrowed with the harness guards, so no generated
// symbol is imported at type-check time and no `as`/`any`/`!` is needed.

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
const fixtureSource = path.join(repoRoot, "fixtures/validators-showcase-3.1");

// A syntactically valid RFC 4122 UUID: nodeId passes its format check, so the only request issue in
// the invalid case is the out-of-range maxDepth.
const NODE_ID = "00000000-0000-0000-0000-000000000000";

// The pinned issue for an out-of-range query value, rooted at its wire location.
const MAX_DEPTH_ISSUE = [{ message: "less than minimum 1", path: ["query", "maxDepth"] }];

const harness = createScriptedServer();
const { routes, requests, scriptRoute } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let getTree: ExportedFunction;
let getTreeOrThrow: ExportedFunction;
let createPet: ExportedFunction;
let ApiError: ExportedFunction;

before(async () => {
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new Error(
      `validators E2E requires ${binary}; run \`cargo build -p oasts\` before this suite`,
    );
  }

  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-validators-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "validators-showcase-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  execFileSync(binary, ["generate", "--config", "oasts-client.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  const generatedRoot = path.join(fixtureRoot, "generated-client");

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });
  const getTreeModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/gettree.ts")).href
  );
  const createPetModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/createpet.ts")).href
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  const resultModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/result.ts")).href
  );
  getTree = requiredFunction(getTreeModule, "getTree");
  getTreeOrThrow = requiredFunction(getTreeModule, "getTreeOrThrow");
  createPet = requiredFunction(createPetModule, "createPet");
  createTransport = requiredFunction(transportModule, "createTransport");
  ApiError = requiredFunction(resultModule, "ApiError");

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

function transport(): unknown {
  return createTransport({ baseUrl });
}

test("an out-of-range request value fails as request-validation before any fetch", async () => {
  // maxDepth 0 is below its minimum; nodeId is valid, so exactly one issue is collected and the
  // wrapper returns the request-failure branch without dispatching.
  const result = requiredRecord(
    await getTree(transport(), { nodeId: NODE_ID, maxDepth: 0 }),
    "getTree request-validation result",
  );
  assert.equal(result.kind, "request-failure");
  const error = requiredRecord(result.error, "request failure error");
  assert.equal(error.kind, "request-validation");
  assert.deepEqual(error.issues, MAX_DEPTH_ISSUE);
  assert.equal(requests.length, 0);
});

test("a malformed documented 200 body fails as response-validation with body-rooted issues", async () => {
  // The 200 body validates against Pet: id is the wrong type and name is missing, so two body-rooted
  // issues are collected and the documented branch becomes a response-failure preserving its meta.
  scriptRoute("POST", "/pets", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":5}'),
  });
  const result = requiredRecord(
    await createPet(transport(), { body: {} }),
    "createPet response-validation result",
  );
  assert.equal(result.kind, "response-failure");
  assert.equal(result.match, "200");
  assert.equal(result.status, 200);
  const error = requiredRecord(result.error, "response failure error");
  assert.equal(error.kind, "response-validation");
  assert.deepEqual(error.issues, [
    { message: "expected type string", path: ["id"] },
    { message: "missing required property name", path: [] },
  ]);
  assert.equal(requiredRecord(result.meta, "response failure meta").status, 200);
  assert.equal(requests.length, 1);
});

test("a valid round-trip returns ok with the served body", async () => {
  // A valid request and a valid documented body pass both checks, so the ok result and its decoded
  // data flow through unchanged.
  const served = { value: "root" };
  scriptRoute("GET", `/tree/${NODE_ID}`, {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from(JSON.stringify(served)),
  });
  const result = requiredRecord(
    await getTree(transport(), { nodeId: NODE_ID }),
    "getTree ok result",
  );
  assert.equal(result.kind, "response");
  assert.equal(result.ok, true);
  assert.equal(result.match, "200");
  assert.deepEqual(result.data, served);
  assert.equal(requests.length, 1);
});

test("the orThrow variant throws ApiError carrying the request-validation failure", async () => {
  // orThrow delegates to the validated base function and unwraps, so a request-validation failure
  // throws ApiError whose preserved result is the same request-failure branch — and still no fetch.
  await assert.rejects(
    async () => getTreeOrThrow(transport(), { nodeId: NODE_ID, maxDepth: 0 }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.ok(error instanceof ApiError);
      const failed = requiredRecord(requiredRecord(error, "ApiError").result, "ApiError result");
      assert.equal(failed.kind, "request-failure");
      const failure = requiredRecord(failed.error, "ApiError request failure");
      assert.equal(failure.kind, "request-validation");
      assert.deepEqual(failure.issues, MAX_DEPTH_ISSUE);
      return true;
    },
  );
  assert.equal(requests.length, 0);
});
