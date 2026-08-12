import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { access, cp, mkdtemp, rm, symlink } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import {
  createScriptedServer,
  requiredFunction,
  requiredRecord,
  requestHeader,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/int64-transform-3.1");
const EXACT_INT64 = 12_345_678_901_234_567_890n;
const EXACT_DIGITS = "12345678901234567890";
const ROUNDED_AMOUNT = Number("9007199254740995");

async function operation(root: string, file: string, name: string): Promise<ExportedFunction> {
  const module: unknown = await import(
    pathToFileURL(path.join(root, `client/operations/${file}.ts`)).href
  );
  return requiredFunction(module, name);
}

const harness = createScriptedServer();
const { requests, routes, scriptRoute, requiredRequest } = harness;

let baseUrl: string;
let temporaryRoot: string;
let generatedRoot: string;
let createTransport: ExportedFunction;
let getLatestCounter: ExportedFunction;
let recordCounter: ExportedFunction;
let readCounter: ExportedFunction;
let readContentCounter: ExportedFunction;
let submitCounterForm: ExportedFunction;
let submitCounterMultipart: ExportedFunction;
let validatedCreateTransport: ExportedFunction;
let validatedGetLatestCounter: ExportedFunction;
let validatedRecordCounter: ExportedFunction;
let zodCreateTransport: ExportedFunction;
let zodGetLatestCounter: ExportedFunction;
let zodRecordCounter: ExportedFunction;

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-int64-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "int64-transform-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  await symlink(
    path.join(repoRoot, "crates/oasts-core/runtime/node_modules"),
    path.join(fixtureRoot, "node_modules"),
  );
  for (const config of ["oasts.yaml", "oasts-validated.yaml", "oasts-zod.yaml"]) {
    execFileSync(binary, ["generate", "--config", config], {
      cwd: fixtureRoot,
      stdio: "pipe",
    });
  }
  generatedRoot = path.join(fixtureRoot, "generated");
  const validatedRoot = path.join(fixtureRoot, "generated-validated");
  const zodRoot = path.join(fixtureRoot, "generated-zod");

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(fixtureRoot).href },
  });
  getLatestCounter = await operation(generatedRoot, "getlatestcounter", "getLatestCounter");
  recordCounter = await operation(generatedRoot, "recordcounter", "recordCounter");
  readCounter = await operation(generatedRoot, "readcounter", "readCounter");
  readContentCounter = await operation(generatedRoot, "readcontentcounter", "readContentCounter");
  submitCounterForm = await operation(generatedRoot, "submitcounterform", "submitCounterForm");
  submitCounterMultipart = await operation(
    generatedRoot,
    "submitcountermultipart",
    "submitCounterMultipart",
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  createTransport = requiredFunction(transportModule, "createTransport");
  validatedGetLatestCounter = await operation(
    validatedRoot,
    "getlatestcounter",
    "getLatestCounter",
  );
  validatedRecordCounter = await operation(validatedRoot, "recordcounter", "recordCounter");
  const validatedTransportModule: unknown = await import(
    pathToFileURL(path.join(validatedRoot, "runtime/transport.ts")).href
  );
  validatedCreateTransport = requiredFunction(validatedTransportModule, "createTransport");
  zodGetLatestCounter = await operation(zodRoot, "getlatestcounter", "getLatestCounter");
  zodRecordCounter = await operation(zodRoot, "recordcounter", "recordCounter");
  const zodTransportModule: unknown = await import(
    pathToFileURL(path.join(zodRoot, "runtime/transport.ts")).href
  );
  zodCreateTransport = requiredFunction(zodTransportModule, "createTransport");
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

test('emitted client scopes exact revival to int64 and sends raw bytes equal {"id":12345678901234567890}', async () => {
  const responseBytes = Buffer.from(`{"id":${EXACT_DIGITS},"amount":9007199254740995}`);
  scriptRoute("GET", "/counters/latest", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });
  scriptRoute("POST", "/counters", {
    status: 201,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });

  const transport = createTransport({ baseUrl });
  const readResult = requiredRecord(
    await getLatestCounter(transport, {}),
    "getLatestCounter result",
  );
  assert.equal(readResult.outcome, 200);
  const data = requiredRecord(readResult.data, "getLatestCounter data");
  assert.equal(data.id, EXACT_INT64);
  assert.equal(data.amount, ROUNDED_AMOUNT);

  const writeResult = requiredRecord(
    await recordCounter(transport, { body: { id: EXACT_INT64 } }),
    "recordCounter result",
  );
  assert.equal(writeResult.outcome, 201);
  assert.equal(requiredRequest(1).body.toString("utf8"), `{"id":${EXACT_DIGITS}}`);
});

test("generated validation preserves the exact int64 response and request", async () => {
  const responseBytes = Buffer.from(`{"id":${EXACT_DIGITS},"amount":9007199254740995}`);
  scriptRoute("GET", "/counters/latest", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });
  scriptRoute("POST", "/counters", {
    status: 201,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });

  const transport = validatedCreateTransport({ baseUrl });
  const readResult = requiredRecord(
    await validatedGetLatestCounter(transport, {}),
    "validated getLatestCounter result",
  );
  assert.equal(readResult.outcome, 200);
  const data = requiredRecord(readResult.data, "validated response data");
  assert.equal(data.id, EXACT_INT64);
  assert.equal(data.amount, ROUNDED_AMOUNT);

  const writeResult = requiredRecord(
    await validatedRecordCounter(transport, { body: { id: EXACT_INT64 } }),
    "validated recordCounter result",
  );
  assert.equal(writeResult.outcome, 201);
  assert.equal(requiredRequest(1).body.toString("utf8"), `{"id":${EXACT_DIGITS}}`);
});

test("Zod validation preserves the exact int64 response and request", async () => {
  const responseBytes = Buffer.from(`{"id":${EXACT_DIGITS},"amount":9007199254740995}`);
  scriptRoute("GET", "/counters/latest", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });
  scriptRoute("POST", "/counters", {
    status: 201,
    headers: [["Content-Type", "application/json"]],
    body: responseBytes,
  });

  const transport = zodCreateTransport({ baseUrl });
  const readResult = requiredRecord(
    await zodGetLatestCounter(transport, {}),
    "Zod getLatestCounter result",
  );
  assert.equal(readResult.outcome, 200);
  const data = requiredRecord(readResult.data, "Zod response data");
  assert.equal(data.id, EXACT_INT64);
  assert.equal(data.amount, ROUNDED_AMOUNT);

  const writeResult = requiredRecord(
    await zodRecordCounter(transport, { body: { id: EXACT_INT64 } }),
    "Zod recordCounter result",
  );
  assert.equal(writeResult.outcome, 201);
  assert.equal(requiredRequest(1).body.toString("utf8"), `{"id":${EXACT_DIGITS}}`);
});

test("path, query, header, and content-JSON parameters keep exact bigint digits", async () => {
  scriptRoute("GET", `/counters/${EXACT_DIGITS}?cursor=${EXACT_DIGITS}`, { status: 204 });
  scriptRoute("GET", `/content?filter=${EXACT_DIGITS}`, { status: 204 });
  const transport = createTransport({ baseUrl });

  const flatResult = requiredRecord(
    await readCounter(transport, {
      path: { id: EXACT_INT64 },
      query: { cursor: EXACT_INT64 },
      header: { "X-Trace": EXACT_INT64 },
    }),
    "readCounter result",
  );
  assert.equal(flatResult.outcome, 204);
  assert.equal(requestHeader(requiredRequest(0), "X-Trace"), EXACT_DIGITS);

  const contentResult = requiredRecord(
    await readContentCounter(transport, { query: { filter: EXACT_INT64 } }),
    "readContentCounter result",
  );
  assert.equal(contentResult.outcome, 204);
  assert.equal(requiredRequest(1).url, `/content?filter=${EXACT_DIGITS}`);
});

test("urlencoded and multipart text fields keep exact bigint digits", async () => {
  scriptRoute("POST", "/form", { status: 204 });
  scriptRoute("POST", "/multipart", { status: 204 });
  const transport = createTransport({ baseUrl });

  const formResult = requiredRecord(
    await submitCounterForm(transport, { body: { id: EXACT_INT64 } }),
    "submitCounterForm result",
  );
  assert.equal(formResult.outcome, 204);
  assert.equal(requiredRequest(0).body.toString("utf8"), `id=${EXACT_DIGITS}`);

  const multipartResult = requiredRecord(
    await submitCounterMultipart(transport, { body: { id: EXACT_INT64 } }),
    "submitCounterMultipart result",
  );
  assert.equal(multipartResult.outcome, 204);
  assert.match(requiredRequest(1).body.toString("utf8"), new RegExp(`\\r\\n${EXACT_DIGITS}\\r\\n`));
});

test("degraded runtime keeps safe int64 and returns transform failures for unsafe values", () => {
  const childEnvironment: NodeJS.ProcessEnv = {
    ...process.env,
    OASTS_INT64_GENERATED_ROOT: generatedRoot,
  };
  delete childEnvironment.NODE_TEST_CONTEXT;
  const output = execFileSync(
    process.execPath,
    ["--test", path.join(import.meta.dirname, "int64-degradation.test.ts")],
    {
      encoding: "utf8",
      env: childEnvironment,
    },
  );
  assert.match(output, /ℹ pass 4/u);
  assert.match(output, /ℹ fail 0/u);
});
