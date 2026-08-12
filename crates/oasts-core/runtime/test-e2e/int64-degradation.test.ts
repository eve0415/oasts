import assert from "node:assert/strict";
import { register } from "node:module";
import path from "node:path";
import { before, test } from "node:test";
import { pathToFileURL } from "node:url";

import { requiredFunction, requiredRecord, type ExportedFunction } from "./harness.ts";

const generatedRoot = process.env.OASTS_INT64_GENERATED_ROOT;
if (generatedRoot === undefined) {
  throw new TypeError("OASTS_INT64_GENERATED_ROOT is required");
}

register(new URL("./resolve-generated.mjs", import.meta.url), {
  data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
});

type JsonReviver = (
  key: string,
  value: unknown,
  context?: { readonly source?: unknown },
) => unknown;
const nativeParse = JSON.parse;
Object.defineProperty(JSON, "rawJSON", { configurable: true, value: undefined });
Object.defineProperty(JSON, "parse", {
  configurable: true,
  value: (text: string, reviver?: JsonReviver): unknown =>
    nativeParse(
      text,
      reviver === undefined
        ? undefined
        : (key: string, value: unknown): unknown => reviver(key, value),
    ),
});

let createTransport: ExportedFunction;
let getLatestCounter: ExportedFunction;
let recordCounter: ExportedFunction;

before(async () => {
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  const getModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/getlatestcounter.ts")).href
  );
  const recordModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/operations/recordcounter.ts")).href
  );
  createTransport = requiredFunction(transportModule, "createTransport");
  getLatestCounter = requiredFunction(getModule, "getLatestCounter");
  recordCounter = requiredFunction(recordModule, "recordCounter");
});

function responseTransport(body: string): unknown {
  return createTransport({
    baseUrl: "https://int64.example.test",
    fetch: (): Promise<Response> =>
      Promise.resolve(
        new Response(body, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
  });
}

test("without reviver context, a safe int64 still decodes to bigint", async () => {
  const result = requiredRecord(
    await getLatestCounter(responseTransport('{"id":42}'), {}),
    "safe degraded result",
  );
  assert.equal(result.outcome, 200);
  assert.equal(requiredRecord(result.data, "safe degraded data").id, 42n);
});

test("without reviver context, an unsafe int64 returns response-transform instead of throwing", async () => {
  await assert.doesNotReject(async () => {
    const result = requiredRecord(
      await getLatestCounter(responseTransport('{"id":12345678901234567890}'), {}),
      "unsafe degraded result",
    );
    assert.equal(result.outcome, "response-transform");
    const error = requiredRecord(result.error, "unsafe degraded error");
    assert.equal(error.direction, "response");
    assert.equal(error.code, "invalid-wire-value");
  });
});

test("without rawJSON, a safe bigint still serializes as exact JSON digits", async () => {
  let requestBytes = "";
  const transport = createTransport({
    baseUrl: "https://int64.example.test",
    fetch: async (request: Request): Promise<Response> => {
      requestBytes = await request.text();
      return new Response('{"id":42}', {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    },
  });
  const result = requiredRecord(
    await recordCounter(transport, { body: { id: 42n } }),
    "safe degraded request result",
  );
  assert.equal(result.outcome, 201);
  assert.equal(requestBytes, '{"id":42}');
});

test("without rawJSON, an unsafe bigint returns request-transform before fetch", async () => {
  let fetchCalls = 0;
  const transport = createTransport({
    baseUrl: "https://int64.example.test",
    fetch: (): Promise<Response> => {
      fetchCalls += 1;
      return Promise.resolve(new Response(null, { status: 201 }));
    },
  });
  const result = requiredRecord(
    await recordCounter(transport, { body: { id: 12_345_678_901_234_567_890n } }),
    "unsafe degraded request result",
  );
  assert.equal(result.outcome, "request-transform");
  const error = requiredRecord(result.error, "unsafe degraded request error");
  assert.equal(error.direction, "request");
  assert.equal(error.code, "invalid-application-value");
  assert.equal(fetchCalls, 0);
});
