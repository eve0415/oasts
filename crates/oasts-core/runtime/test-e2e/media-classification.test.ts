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
  requestHeader,
  requiredFunction,
  requiredRecord,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/media-classification-3.1");

const harness = createScriptedServer();
const { requests, routes, scriptRoute, requiredRequest } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let sendTextJson: ExportedFunction;

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-media-classification-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "media-classification-3.1");
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
    pathToFileURL(path.join(generatedRoot, "client/operations/sendtextjson.ts")).href
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  sendTextJson = requiredFunction(operationModule, "sendTextJson");
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

test("text/json sends a text request and decodes a JSON response", async () => {
  scriptRoute("POST", "/json", {
    status: 202,
    headers: [["Content-Type", "text/json"]],
    body: Buffer.from('{"accepted":true}'),
  });

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await sendTextJson(transport, { body: "hello" }),
    "text/json result",
  );
  const received = requiredRequest(0);

  assert.equal(requestHeader(received, "Content-Type"), "text/json");
  assert.equal(requestHeader(received, "Accept"), "text/json");
  assert.equal(received.body.toString("utf8"), "hello");
  assert.equal(result.outcome, 202);
  assert.deepEqual(result.data, { accepted: true });
});
