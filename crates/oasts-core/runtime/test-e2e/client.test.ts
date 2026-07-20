// Consumption strategy: generated output uses relative `.js` specifiers over on-disk `.ts`
// files because emit.importExtension is limited to `".js" | "none"`. This suite registers a
// `node:module` customization hook that retries a failing relative `.js` resolution at the
// sibling `.ts` path. The hook is resolution-only, performs no transformation beyond Node's
// own type stripping, and is scoped to the generated temporary directory.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, cp, mkdtemp, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import { MULTIPART_BODY_VECTORS, type MultipartBodyVector } from "../test/vectors-multipart.ts";
import { STYLE_VECTORS, type StyleVector } from "../test/vectors-styles.ts";

type ExportedFunction = (...arguments_: unknown[]) => unknown;
type HeaderEntry = readonly [string, string];
type CapturedRequest = {
  readonly method: string;
  readonly url: string;
  readonly rawHeaderEntries: readonly HeaderEntry[];
  readonly body: Buffer;
};
type ScriptedResponse = {
  readonly status: number;
  readonly headers?: readonly HeaderEntry[];
  readonly body?: Uint8Array;
  readonly delayBodyMs?: number;
};
type ExpectedMultipartPart = {
  readonly name: string;
  readonly filename?: string;
  readonly contentType: string;
  readonly payload: Uint8Array;
};

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/client-showcase-3.1");
const routes = new Map<string, ScriptedResponse>();
const requests: CapturedRequest[] = [];

let server: Server;
let baseUrl: string;
let temporaryRoot: string;
let generatedRoot: string;
let createTransport: ExportedFunction;
let aggregateApi: Readonly<Record<string, unknown>>;
let getPetShowcase: ExportedFunction;
let getPetShowcaseOrThrow: ExportedFunction;
let getLabelShowcase: ExportedFunction;
let getLabelShowcaseOrThrow: ExportedFunction;
let getMatrixShowcase: ExportedFunction;
let headHealthShowcase: ExportedFunction;
let selectMediaShowcase: ExportedFunction;
let submitFormShowcase: ExportedFunction;
let uploadShowcase: ExportedFunction;
let ApiError: ExportedFunction;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredRecord(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function isExportedFunction(value: unknown): value is ExportedFunction {
  return typeof value === "function";
}

function requiredFunction(module: unknown, name: string): ExportedFunction {
  const value = requiredRecord(module, "generated module")[name];
  if (!isExportedFunction(value)) {
    throw new TypeError(`generated export ${name} must be a function`);
  }
  return value;
}

function headerEntries(rawHeaders: readonly string[]): readonly HeaderEntry[] {
  const entries: HeaderEntry[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (name === undefined || value === undefined) {
      throw new TypeError("node:http produced an incomplete raw header entry");
    }
    entries.push([name, value]);
  }
  return entries;
}

function routeKey(method: string, url: string): string {
  return `${method} ${url}`;
}

function scriptRoute(method: string, url: string, response: ScriptedResponse): void {
  routes.set(routeKey(method, url), response);
}

function requestHeader(request: CapturedRequest, name: string): string | undefined {
  const normalized = name.toLowerCase();
  return request.rawHeaderEntries.find(
    ([headerName]) => headerName.toLowerCase() === normalized,
  )?.[1];
}

function requiredRequest(index: number): CapturedRequest {
  const request = requests[index];
  if (request === undefined) {
    throw new TypeError(`captured request ${String(index)} is missing`);
  }
  return request;
}

function localTransport(config: Readonly<Record<string, unknown>> = {}): unknown {
  return createTransport({ ...config, baseUrl });
}

function requiredStyleVector(
  label: string,
  predicate: (vector: StyleVector) => boolean,
): StyleVector {
  const vector = STYLE_VECTORS.find(predicate);
  if (vector === undefined) {
    throw new TypeError(`STYLE_VECTORS is missing ${label}`);
  }
  return vector;
}

function renamedStyleExpected(vector: StyleVector, parameterName: string): string {
  return vector.expected.replaceAll(vector.paramName, parameterName);
}

function firstMultipartVector(): MultipartBodyVector {
  const vector = MULTIPART_BODY_VECTORS[0];
  if (vector === undefined) {
    throw new TypeError("MULTIPART_BODY_VECTORS is empty");
  }
  return vector;
}

function multipartExpectation(parts: readonly ExpectedMultipartPart[]): {
  readonly boundary: string;
  readonly body: Buffer;
} {
  const hash = createHash("sha256");
  for (const part of parts) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(part.payload.byteLength));
    hash.update(length);
    hash.update(part.payload);
  }
  const boundary = `oxb-${hash.digest("hex").slice(0, 24)}`;
  const body: Buffer[] = [];
  for (const [index, part] of parts.entries()) {
    const disposition =
      part.filename === undefined
        ? `Content-Disposition: form-data; name="${part.name}"`
        : `Content-Disposition: form-data; name="${part.name}"; filename="${part.filename}"`;
    const prefix = index === 0 ? `--${boundary}\r\n` : `\r\n--${boundary}\r\n`;
    const encapsulated = `${disposition}\r\nContent-Type: ${part.contentType}\r\n\r\n`;
    assert.equal(encapsulated.includes(boundary), false);
    assert.equal(Buffer.from(part.payload).includes(Buffer.from(boundary)), false);
    body.push(Buffer.from(prefix + encapsulated), Buffer.from(part.payload));
  }
  body.push(Buffer.from(`\r\n--${boundary}--`));
  return { boundary, body: Buffer.concat(body) };
}

async function captureRequest(request: IncomingMessage): Promise<CapturedRequest> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return {
    method: request.method ?? "",
    url: request.url ?? "",
    rawHeaderEntries: headerEntries(request.rawHeaders),
    body: Buffer.concat(chunks),
  };
}

before(async () => {
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new Error(
      `client E2E requires ${binary}; run \`cargo build -p oasts\` before this suite`,
    );
  }

  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-client-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "client-showcase-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  execFileSync(binary, ["generate", "--config", "oasts.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  generatedRoot = path.join(fixtureRoot, "generated");

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });
  const aggregateModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/api.ts")).href
  );
  const operationModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/getpetshowcase.ts")).href
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  const resultModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/result.ts")).href
  );
  aggregateApi = requiredRecord(
    requiredRecord(aggregateModule, "aggregate module").api,
    "aggregate api",
  );
  getPetShowcase = requiredFunction(operationModule, "getPetShowcase");
  createTransport = requiredFunction(transportModule, "createTransport");
  ApiError = requiredFunction(resultModule, "ApiError");
  assert.strictEqual(aggregateApi.getPetShowcase, getPetShowcase);
  getPetShowcaseOrThrow = requiredFunction(aggregateApi, "getPetShowcaseOrThrow");
  getLabelShowcase = requiredFunction(aggregateApi, "getLabelShowcase");
  getLabelShowcaseOrThrow = requiredFunction(aggregateApi, "getLabelShowcaseOrThrow");
  getMatrixShowcase = requiredFunction(aggregateApi, "getMatrixShowcase");
  headHealthShowcase = requiredFunction(aggregateApi, "headHealthShowcase");
  selectMediaShowcase = requiredFunction(aggregateApi, "selectMediaShowcase");
  submitFormShowcase = requiredFunction(aggregateApi, "submitFormShowcase");
  uploadShowcase = requiredFunction(aggregateApi, "uploadShowcase");

  server = createServer((request: IncomingMessage, response: ServerResponse) => {
    captureRequest(request)
      .then((captured) => {
        requests.push(captured);
        const scripted = routes.get(routeKey(captured.method, captured.url));
        if (scripted === undefined) {
          response.writeHead(500, { "Content-Type": "text/plain" });
          response.end(`No scripted response for ${captured.method} ${captured.url}`);
          return;
        }
        for (const [name, value] of scripted.headers ?? []) {
          response.setHeader(name, value);
        }
        response.writeHead(scripted.status);
        const end = (): void => {
          response.end(scripted.body);
        };
        if (scripted.delayBodyMs === undefined) {
          end();
        } else {
          response.flushHeaders();
          setTimeout(end, scripted.delayBodyMs);
        }
      })
      .catch((error: unknown) => {
        response.destroy(error instanceof Error ? error : new Error("request capture failed"));
      });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new TypeError("node:http did not bind an IP socket");
  }
  baseUrl = `http://127.0.0.1:${String(address.port)}`;
});

beforeEach(() => {
  routes.clear();
  requests.length = 0;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  await rm(temporaryRoot, { recursive: true, force: true });
});

test("JSON GET round-trips through the default fetch and local server", async () => {
  // transport baseUrl overrides the server and default fetch is real.
  const body = Buffer.from('{"id":"p_123","name":"Mochi"}');
  scriptRoute("GET", "/pets/p_123", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body,
  });

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await getPetShowcase(transport, { petId: "p_123" }), "GET result");

  assert.equal(requests.length, 1);
  const received = requests[0];
  assert.ok(received);
  assert.equal(received.method, "GET");
  assert.equal(received.url, "/pets/p_123");
  assert.equal(requestHeader(received, "Accept"), "application/json, text/plain");
  assert.equal(result.kind, "response");
  assert.equal(result.ok, true);
  assert.equal(result.match, "200");
  assert.deepEqual(result.data, { id: "p_123", name: "Mochi" });
  assert.equal(requiredRecord(result.meta, "response meta").url, `${baseUrl}/pets/p_123`);
});

test("showcase parameter styles match the committed wire vectors", async () => {
  // every style family declared by the showcase is asserted at the server.
  const simple = requiredStyleVector(
    "path simple primitive",
    (vector) =>
      vector.location === "path" &&
      vector.style === "simple" &&
      !vector.explode &&
      typeof vector.value === "string",
  );
  const formExplode = requiredStyleVector(
    "query form exploded array",
    (vector) =>
      vector.location === "query" &&
      vector.style === "form" &&
      vector.explode &&
      Array.isArray(vector.value),
  );
  const formCompact = requiredStyleVector(
    "query form compact array",
    (vector) =>
      vector.location === "query" &&
      vector.style === "form" &&
      !vector.explode &&
      Array.isArray(vector.value),
  );
  const spaces = requiredStyleVector(
    "query spaceDelimited",
    (vector) => vector.location === "query" && vector.style === "spaceDelimited",
  );
  const pipes = requiredStyleVector(
    "query pipeDelimited",
    (vector) => vector.location === "query" && vector.style === "pipeDelimited",
  );
  const deepObject = requiredStyleVector(
    "query deepObject",
    (vector) => vector.location === "query" && vector.style === "deepObject",
  );
  const header = requiredStyleVector(
    "header simple primitive",
    (vector) =>
      vector.location === "header" &&
      vector.style === "simple" &&
      !vector.explode &&
      typeof vector.value === "string",
  );
  const expectedUrl =
    `/pets/${simple.expected}?` +
    [
      renamedStyleExpected(formExplode, "tags"),
      renamedStyleExpected(formCompact, "fields"),
      renamedStyleExpected(spaces, "spaces"),
      renamedStyleExpected(pipes, "pipes"),
      renamedStyleExpected(deepObject, "filter"),
    ].join("&");
  scriptRoute("GET", expectedUrl, {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"blue","name":"Vector"}'),
  });

  await getPetShowcase(localTransport(), {
    petId: simple.value,
    tags: formExplode.value,
    fields: formCompact.value,
    spaces: spaces.value,
    pipes: pipes.value,
    filter: deepObject.value,
    "X-Trace": header.value,
  });

  assert.equal(requests.length, 1);
  assert.equal(requiredRequest(0).url, expectedUrl);
  assert.equal(requestHeader(requiredRequest(0), "X-Trace"), header.expected);

  const label = requiredStyleVector(
    "path label primitive",
    (vector) =>
      vector.location === "path" &&
      vector.style === "label" &&
      !vector.explode &&
      typeof vector.value === "string",
  );
  scriptRoute("GET", `/labels/${label.expected}`, { status: 204 });
  await getLabelShowcase(localTransport(), { labelId: label.value });
  assert.equal(requiredRequest(1).url, `/labels/${label.expected}`);

  const matrix = requiredStyleVector(
    "path matrix exploded object",
    (vector) =>
      vector.location === "path" &&
      vector.style === "matrix" &&
      vector.explode &&
      typeof vector.value === "object" &&
      !Array.isArray(vector.value),
  );
  const matrixValue = requiredRecord(matrix.value, "matrix vector value");
  const matrixExpected = matrix.expected.replaceAll("R", "row").replaceAll("G", "column");
  scriptRoute("GET", `/matrix/${matrixExpected}`, { status: 204 });
  await getMatrixShowcase(localTransport(), {
    matrixId: { row: matrixValue.R, column: matrixValue.G },
  });
  assert.equal(requiredRequest(2).url, `/matrix/${matrixExpected}`);
});

test("response media selection prefers an exact declared type", async () => {
  // exact media wins and JSON is decoded to an object payload.
  scriptRoute("GET", "/media-selection", {
    status: 200,
    headers: [["Content-Type", "Application/JSON; charset=utf-8"]],
    body: Buffer.from('{"value":"exact"}'),
  });
  const result = requiredRecord(
    await selectMediaShowcase(localTransport(), {}),
    "exact media result",
  );
  assert.equal(result.kind, "response");
  assert.equal(result.contentType, "application/json");
  assert.equal(typeof result.data, "object");
  assert.deepEqual(result.data, { value: "exact" });
});

test("response media selection falls back to the declared type range", async () => {
  // a concrete text type matches text/* and decodes to a string.
  scriptRoute("GET", "/media-selection", {
    status: 200,
    headers: [["Content-Type", "text/csv; charset=utf-8"]],
    body: Buffer.from("range,payload"),
  });
  const result = requiredRecord(
    await selectMediaShowcase(localTransport(), {}),
    "range media result",
  );
  assert.equal(result.kind, "response");
  assert.equal(result.contentType, "text/*");
  assert.equal(typeof result.data, "string");
  assert.equal(result.data, "range,payload");
});

test("response media selection rejects an unmatched concrete type", async () => {
  // a non-empty unmatched Content-Type is response-decode, never guessed.
  scriptRoute("GET", "/media-selection", {
    status: 200,
    headers: [["Content-Type", "image/png"]],
    body: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
  });
  const result = requiredRecord(
    await selectMediaShowcase(localTransport(), {}),
    "unmatched media result",
  );
  const error = requiredRecord(result.error, "unmatched media error");
  assert.equal(result.kind, "response-failure");
  assert.equal(result.match, "200");
  assert.equal(error.kind, "response-decode");
  assert.match(String(error.message), /image\/png does not match declared content/u);
});

test("unmatched responses preserve all four UnknownHttpError body kinds", async () => {
  // unmatched bodies map one-to-one to empty/json/text/binary.
  const cases: readonly {
    readonly label: string;
    readonly headers: readonly HeaderEntry[];
    readonly body: Uint8Array;
    readonly kind: string;
    readonly expectedBody: unknown;
  }[] = [
    { label: "empty", headers: [], body: Buffer.alloc(0), kind: "empty", expectedBody: undefined },
    {
      label: "json",
      headers: [["Content-Type", "application/problem+json"]],
      body: Buffer.from('{"code":"teapot"}'),
      kind: "json",
      expectedBody: { code: "teapot" },
    },
    {
      label: "text",
      headers: [["Content-Type", "text/plain; charset=utf-8"]],
      body: Buffer.from("teapot"),
      kind: "text",
      expectedBody: "teapot",
    },
    {
      label: "binary",
      headers: [],
      body: Buffer.from([0, 255, 1]),
      kind: "binary",
      expectedBody: Buffer.from([0, 255, 1]),
    },
  ];

  for (const scenario of cases) {
    const url = `/labels/.${scenario.label}`;
    scriptRoute("GET", url, {
      status: 418,
      headers: scenario.headers,
      body: scenario.body,
    });
    const result = requiredRecord(
      await getLabelShowcase(localTransport(), { labelId: scenario.label }),
      `${scenario.label} unmatched result`,
    );
    const error = requiredRecord(result.error, `${scenario.label} unmatched error`);
    assert.equal(result.kind, "unmatched-response");
    assert.equal(result.status, 418);
    assert.equal(error.kind, scenario.kind);
    if (scenario.kind === "binary") {
      assert.ok(error.body instanceof ArrayBuffer);
      assert.deepEqual(Buffer.from(error.body), scenario.expectedBody);
    } else {
      assert.deepEqual(error.body, scenario.expectedBody);
    }
  }
});

test("HEAD produces undefined data without reading a body", async () => {
  // HEAD is statically bodyless regardless of declared content.
  scriptRoute("HEAD", "/health", { status: 200 });
  const result = requiredRecord(await headHealthShowcase(localTransport(), {}), "HEAD result");
  assert.equal(requiredRequest(0).method, "HEAD");
  assert.equal(result.kind, "response");
  assert.equal(result.data, undefined);
  assert.equal(result.contentType, undefined);
});

test("an exact 204 response produces undefined data", async () => {
  // an exact 204 key is statically bodyless.
  scriptRoute("GET", "/labels/.bodyless", { status: 204 });
  const result = requiredRecord(
    await getLabelShowcase(localTransport(), { labelId: "bodyless" }),
    "204 result",
  );
  assert.equal(result.kind, "response");
  assert.equal(result.match, "204");
  assert.equal(result.data, undefined);
});

test("a default content branch rejects a dynamic 204 response", async () => {
  // bodyless status 204 cannot satisfy content declared by default.
  scriptRoute("GET", "/pets/dynamic-bodyless", {
    status: 204,
    headers: [["Content-Type", "application/json"]],
  });
  const result = requiredRecord(
    await getPetShowcase(localTransport(), { petId: "dynamic-bodyless" }),
    "dynamic bodyless result",
  );
  const error = requiredRecord(result.error, "dynamic bodyless error");
  assert.equal(result.kind, "response-failure");
  assert.equal(result.match, "default");
  assert.equal(error.kind, "response-decode");
  assert.match(String(error.message), /bodyless status 204.*default/u);
});

test("a pre-aborted signal stops the default transport before the server", async () => {
  // the dependent signal preserves pre-abort state and reason with no send.
  const reason = { phase: "before-dispatch" };
  const controller = new AbortController();
  controller.abort(reason);
  const result = requiredRecord(
    await getLabelShowcase(
      localTransport(),
      { labelId: "pre-abort" },
      {
        signal: controller.signal,
      },
    ),
    "pre-abort result",
  );
  const error = requiredRecord(result.error, "pre-abort error");
  assert.equal(requests.length, 0);
  assert.equal(result.kind, "request-failure");
  assert.equal(error.kind, "aborted");
  assert.strictEqual(error.reason, reason);
});

test("a mid-flight abort stops a default-fetch body read", async () => {
  // later abort propagation preserves the reason on globalThis.fetch.
  const reason = { phase: "body-read" };
  const controller = new AbortController();
  let markResponse: (() => void) | undefined;
  const responseStarted = new Promise<void>((resolve) => {
    markResponse = resolve;
  });
  scriptRoute("GET", "/pets/mid-abort", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"mid-abort","name":"Slow"}'),
    delayBodyMs: 250,
  });
  const transport = localTransport({
    middleware: [
      {
        onResponse(): void {
          markResponse?.();
        },
      },
    ],
  });
  const pending = getPetShowcase(
    transport,
    { petId: "mid-abort" },
    {
      signal: controller.signal,
    },
  );
  await responseStarted;
  controller.abort(reason);
  const result = requiredRecord(await pending, "mid-abort result");
  const error = requiredRecord(result.error, "mid-abort error");
  assert.equal(requests.length, 1);
  assert.equal(result.kind, "response-failure");
  assert.equal(error.kind, "aborted");
  assert.strictEqual(error.reason, reason);
});

test("injected fetch preserves pre-abort and mid-flight dependent-signal semantics", async () => {
  // the injection seam receives a non-identical dependent signal with its reason.
  const preReason = { phase: "injected-before" };
  const preController = new AbortController();
  preController.abort(preReason);
  let injectedCalls = 0;
  const preTransport = localTransport({
    fetch: (request: Request): Promise<Response> => {
      injectedCalls += 1;
      return globalThis.fetch(request);
    },
  });
  const preResult = requiredRecord(
    await getLabelShowcase(
      preTransport,
      { labelId: "injected-pre" },
      {
        signal: preController.signal,
      },
    ),
    "injected pre-abort result",
  );
  const preError = requiredRecord(preResult.error, "injected pre-abort error");
  assert.equal(injectedCalls, 0);
  assert.equal(requests.length, 0);
  assert.equal(preError.kind, "aborted");
  assert.strictEqual(preError.reason, preReason);

  const midReason = { phase: "injected-body" };
  const midController = new AbortController();
  let observedSignal: AbortSignal | undefined;
  let markResponse: (() => void) | undefined;
  const responseStarted = new Promise<void>((resolve) => {
    markResponse = resolve;
  });
  scriptRoute("GET", "/pets/injected-mid", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"injected-mid","name":"Slow"}'),
    delayBodyMs: 250,
  });
  const midTransport = localTransport({
    fetch: (request: Request): Promise<Response> => {
      injectedCalls += 1;
      observedSignal = request.signal;
      return globalThis.fetch(request);
    },
    middleware: [
      {
        onResponse(): void {
          markResponse?.();
        },
      },
    ],
  });
  const pending = getPetShowcase(
    midTransport,
    { petId: "injected-mid" },
    {
      signal: midController.signal,
    },
  );
  await responseStarted;
  assert.ok(observedSignal);
  assert.notStrictEqual(observedSignal, midController.signal);
  midController.abort(midReason);
  const midResult = requiredRecord(await pending, "injected mid-abort result");
  const midError = requiredRecord(midResult.error, "injected mid-abort error");
  assert.equal(injectedCalls, 1);
  assert.equal(midResult.kind, "response-failure");
  assert.equal(midError.kind, "aborted");
  assert.strictEqual(midError.reason, midReason);
  assert.equal(observedSignal.aborted, true);
  assert.strictEqual(observedSignal.reason, midReason);
});

test("request middleware replacement hooks chain in registration order", async () => {
  // each replacement becomes the next hook's current Request.
  const order: string[] = [];
  scriptRoute("GET", "/labels/.replacement-chain", { status: 204 });
  const transport = localTransport({
    middleware: [
      {
        onRequest(request: Request): Request {
          order.push("first");
          const headers = new Headers(request.headers);
          headers.set("X-First", "one");
          return new Request(request, { headers });
        },
      },
      {
        onRequest(request: Request): Request {
          order.push(request.headers.get("X-First") ?? "missing");
          const headers = new Headers(request.headers);
          headers.set("X-Second", "two");
          return new Request(request, { headers });
        },
      },
    ],
  });
  await getLabelShowcase(transport, { labelId: "replacement-chain" });
  assert.deepEqual(order, ["first", "one"]);
  assert.equal(requestHeader(requiredRequest(0), "X-First"), "one");
  assert.equal(requestHeader(requiredRequest(0), "X-Second"), "two");
});

test("void request middleware may mutate headers in place", async () => {
  // void retains the mutated current Request and revalidates it.
  scriptRoute("GET", "/labels/.void-mutation", { status: 204 });
  const transport = localTransport({
    middleware: [
      {
        onRequest(request: Request): void {
          request.headers.set("X-Mutated", "yes");
        },
      },
    ],
  });
  await getLabelShowcase(transport, { labelId: "void-mutation" });
  assert.equal(requestHeader(requiredRequest(0), "X-Mutated"), "yes");
});

test("forbidden middleware headers fail before Node sends a request", async () => {
  // Oasts rejects Cookie even though Node undici preserves it.
  const transport = localTransport({
    middleware: [
      {
        onRequest(request: Request): Request {
          const headers = new Headers(request.headers);
          headers.set("Cookie", "session=forbidden");
          return new Request(request, { headers });
        },
      },
    ],
  });
  const result = requiredRecord(
    await getLabelShowcase(transport, { labelId: "forbidden" }),
    "forbidden middleware result",
  );
  const error = requiredRecord(result.error, "forbidden middleware error");
  assert.equal(requests.length, 0);
  assert.equal(result.kind, "request-failure");
  assert.equal(error.kind, "request-middleware");
});

test("response middleware replacements chain across status and body changes", async () => {
  // status matching and decoding use only the final replacement Response.
  const observedStatuses: number[] = [];
  scriptRoute("GET", "/pets/response-chain", {
    status: 503,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"code":503,"message":"origin"}'),
  });
  const transport = localTransport({
    middleware: [
      {
        onResponse(response: Response): Response {
          observedStatuses.push(response.status);
          return new Response("intermediate", {
            status: 202,
            headers: { "Content-Type": "text/plain" },
          });
        },
      },
      {
        onResponse(response: Response): Response {
          observedStatuses.push(response.status);
          return new Response('{"id":"response-chain","name":"Final"}', {
            status: 200,
            headers: { "Content-Type": "application/json", "X-Final": "yes" },
          });
        },
      },
    ],
  });
  const result = requiredRecord(
    await getPetShowcase(transport, { petId: "response-chain" }),
    "response replacement result",
  );
  const meta = requiredRecord(result.meta, "response replacement meta");
  assert.deepEqual(observedStatuses, [503, 202]);
  assert.equal(result.kind, "response");
  assert.equal(result.status, 200);
  assert.deepEqual(result.data, { id: "response-chain", name: "Final" });
  assert.ok(meta.headers instanceof Headers);
  assert.equal(meta.headers.get("X-Final"), "yes");
});

test("response middleware may not consume the current body", async () => {
  // bodyUsed after a hook is a response-middleware failure.
  scriptRoute("GET", "/pets/consumed", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"consumed","name":"Body"}'),
  });
  const transport = localTransport({
    middleware: [
      {
        async onResponse(response: Response): Promise<void> {
          await response.text();
        },
      },
    ],
  });
  const result = requiredRecord(
    await getPetShowcase(transport, { petId: "consumed" }),
    "consumed response result",
  );
  const error = requiredRecord(result.error, "consumed response error");
  assert.equal(result.kind, "response-failure");
  assert.equal(error.kind, "response-middleware");
});

test("fetchOptions separates a frozen extension sidecar from standard keys", async () => {
  // unknown fields retain identity in the sidecar; cache stays on RequestInit.
  const next = { revalidate: 60 };
  let capturedExtensions: Readonly<Record<string, unknown>> | undefined;
  let capturedRequest: Request | undefined;
  const transport = localTransport({
    fetch: (
      request: Request,
      extensions?: Readonly<Record<string, unknown>>,
    ): Promise<Response> => {
      capturedRequest = request;
      capturedExtensions = extensions;
      return Promise.resolve(new Response(null, { status: 204 }));
    },
  });
  await getLabelShowcase(
    transport,
    { labelId: "sidecar" },
    {
      fetchOptions: { next, cache: "no-store" },
    },
  );
  assert.ok(capturedRequest);
  assert.ok(capturedExtensions);
  assert.equal(Object.isFrozen(capturedExtensions), true);
  assert.strictEqual(capturedExtensions.next, next);
  assert.equal("cache" in capturedExtensions, false);
  assert.equal(capturedRequest.cache, "no-store");
  assert.equal(requests.length, 0);
});

test("multipart upload bytes follow the pinned boundary and body grammar", async () => {
  // raw bytes and the unquoted boundary are asserted at the server.
  const vector = firstMultipartVector();
  const textPart = vector.parts.find((part) => part.name === "field1");
  const filePart = vector.parts.find((part) => part.name === "file1");
  if (textPart === undefined || filePart === undefined || filePart.filename === undefined) {
    throw new TypeError("the first multipart vector must contain its text and file material");
  }
  const metadataPayload = Buffer.from('{"category":"demo"}');
  const titlePayload = Buffer.from(textPart.payloadAscii);
  const filePayload = Buffer.from(filePart.payloadAscii);
  const expected = multipartExpectation([
    {
      name: "metadata",
      contentType: "application/json",
      payload: metadataPayload,
    },
    { name: "title", contentType: textPart.contentType, payload: titlePayload },
    {
      name: "file",
      filename: filePart.filename,
      contentType: filePart.contentType,
      payload: filePayload,
    },
  ]);
  scriptRoute("POST", "/uploads", { status: 204 });
  await uploadShowcase(localTransport(), {
    body: {
      metadata: { body: { category: "demo" }, contentType: "application/json" },
      title: textPart.payloadAscii,
      file: new File([filePayload], filePart.filename, { type: filePart.contentType }),
    },
  });
  const received = requiredRequest(0);
  const contentType = requestHeader(received, "Content-Type");
  assert.equal(contentType, `multipart/form-data; boundary=${expected.boundary}`);
  assert.doesNotMatch(contentType ?? "", /boundary="/u);
  assert.deepEqual(received.body, expected.body);
});

test("form-urlencoded body is byte-exact on the wire", async () => {
  // Encoding Object style serialization determines the exact body string.
  const labels = requiredStyleVector(
    "form-urlencoded compact array",
    (vector) =>
      vector.location === "query" &&
      vector.style === "form" &&
      !vector.explode &&
      Array.isArray(vector.value),
  );
  const expected = `name=Ada%20Lovelace&${renamedStyleExpected(labels, "labels")}`;
  scriptRoute("POST", "/forms", { status: 204 });
  await submitFormShowcase(localTransport(), {
    body: { name: "Ada Lovelace", labels: labels.value },
  });
  assert.equal(requiredRequest(0).body.toString("utf8"), expected);
});

test("redirect metadata reports the post-redirect provenance URL", async () => {
  // fetchedResponse.url records route B after a default-fetch redirect.
  scriptRoute("GET", "/labels/.redirect-a", {
    status: 302,
    headers: [["Location", "/labels/redirect-b"]],
  });
  scriptRoute("GET", "/labels/redirect-b", { status: 204 });
  const result = requiredRecord(
    await getLabelShowcase(localTransport(), { labelId: "redirect-a" }),
    "redirect result",
  );
  const meta = requiredRecord(result.meta, "redirect meta");
  assert.equal(requests.length, 2);
  assert.equal(meta.url, `${baseUrl}/labels/redirect-b`);
});

test("response replacement retains redirected provenance", async () => {
  // new Response has no URL, so metadata keeps the pre-hook redirect URL.
  scriptRoute("GET", "/labels/.replaced-a", {
    status: 302,
    headers: [["Location", "/labels/replaced-b"]],
  });
  scriptRoute("GET", "/labels/replaced-b", { status: 204 });
  const transport = localTransport({
    middleware: [
      {
        onResponse(): Response {
          return new Response(null, { status: 204 });
        },
      },
    ],
  });
  const result = requiredRecord(
    await getLabelShowcase(transport, { labelId: "replaced-a" }),
    "replacement provenance result",
  );
  assert.equal(
    requiredRecord(result.meta, "replacement provenance meta").url,
    `${baseUrl}/labels/replaced-b`,
  );
});

test("synthetic injected responses fall back to the request URL", async () => {
  // an injected empty-url Response uses finalRequest.url as provenance.
  let fetchedUrl: string | undefined;
  const transport = localTransport({
    fetch: (request: Request): Promise<Response> => {
      fetchedUrl = request.url;
      return Promise.resolve(new Response(null, { status: 204 }));
    },
  });
  const result = requiredRecord(
    await getLabelShowcase(transport, { labelId: "synthetic" }),
    "synthetic response result",
  );
  const meta = requiredRecord(result.meta, "synthetic response meta");
  assert.equal(fetchedUrl, `${baseUrl}/labels/.synthetic`);
  assert.equal(meta.url, fetchedUrl);
  assert.equal(requests.length, 0);
});

test("generated OrThrow exports return data and throw ApiError with the failed result", async () => {
  // OrThrow returns data or throws ApiError preserving its result.
  scriptRoute("GET", "/pets/or-throw-success", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"id":"or-throw-success","name":"Success"}'),
  });
  const data = await getPetShowcaseOrThrow(localTransport(), { petId: "or-throw-success" });
  assert.deepEqual(data, { id: "or-throw-success", name: "Success" });

  scriptRoute("GET", "/labels/.or-throw-failure", {
    status: 418,
    headers: [["Content-Type", "text/plain"]],
    body: Buffer.from("failure"),
  });
  await assert.rejects(
    async () => getLabelShowcaseOrThrow(localTransport(), { labelId: "or-throw-failure" }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.ok(error instanceof ApiError);
      const apiError = requiredRecord(error, "ApiError");
      const preservedResult = apiError.result;
      assert.strictEqual(apiError.result, preservedResult);
      const failed = requiredRecord(preservedResult, "ApiError result");
      assert.equal(failed.kind, "unmatched-response");
      assert.equal(failed.status, 418);
      assert.equal(error.name, "ApiError");
      assert.equal(error.message, "Oasts API call failed");
      return true;
    },
  );
});
