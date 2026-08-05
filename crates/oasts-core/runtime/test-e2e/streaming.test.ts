// Drives the generated streaming client against a real node:http server writing a body in chunks,
// so the framing, the resolve-at-headers timing, cancellation and mid-stream failure are measured
// on an actual socket rather than on a hand-built ReadableStream this repo also wrote.

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
  type ScriptedChunk,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/streaming-3.1");
const SSE_HEADERS = [["Content-Type", "text/event-stream"]] as const;

const harness = createScriptedServer();
const { requests, routes, scriptRoute } = harness;

let baseUrl: string;
let temporaryRoot: string;
let createTransport: ExportedFunction;
let watchTicks: ExportedFunction;
// The same operation from the tree generated with a date/time representation and response
// validation both on, so one yielded event proves the per-event wrapper runs both halves.
let convertedWatchTicks: ExportedFunction;
let watchGuardedTicks: ExportedFunction;
let downloadBlob: ExportedFunction;
let publishTicks: ExportedFunction;
let drainTicks: ExportedFunction;

const encoder = new TextEncoder();

function chunk(text: string, delayMs?: number): ScriptedChunk {
  return delayMs === undefined
    ? { bytes: encoder.encode(text) }
    : { bytes: encoder.encode(text), delayMs };
}

function transport(): unknown {
  return createTransport({ baseUrl });
}

// Every success arm here carries a handle, so the tests want the handle and the narrowing that
// proves it is on the success arm — not a re-derivation of the result shape in each test.
function successData(result: unknown): unknown {
  const record = requiredRecord(result, "result");
  assert.equal(record.ok, true, `expected a success arm, got ${JSON.stringify(record.outcome)}`);
  return record.data;
}

function failureError(result: unknown): unknown {
  const record = requiredRecord(result, "result");
  assert.equal(record.ok, false, "expected a documented failure arm");
  return record.error;
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return typeof value === "object" && value !== null && Symbol.asyncIterator in value;
}

function asyncIterable(value: unknown): AsyncIterable<unknown> {
  assert.ok(isAsyncIterable(value), "a server-sent-event branch resolves an async iterable");
  return value;
}

function byteStream(value: unknown): ReadableStream<Uint8Array> {
  assert.ok(value instanceof ReadableStream, "a raw streaming branch resolves a ReadableStream");
  return value;
}

async function collect(events: AsyncIterable<unknown>): Promise<unknown[]> {
  const seen: unknown[] = [];
  for await (const event of events) {
    seen.push(event);
  }
  return seen;
}

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-streaming-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "streaming-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  for (const config of ["oasts.yaml", "oasts-transform-validated.yaml"]) {
    execFileSync(binary, ["generate", "--config", config], { cwd: fixtureRoot, stdio: "pipe" });
  }
  const generatedRoot = path.join(fixtureRoot, "generated");
  const convertedRoot = path.join(fixtureRoot, "generated-transform-validated");

  // One registration covering both trees. Registering the hook module twice would share its module
  // state and clobber the first root — the fixture root is the common ancestor, so one root does.
  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(fixtureRoot).href },
  });
  const load = async (base: string): Promise<unknown> =>
    import(pathToFileURL(path.join(generatedRoot, `client/operations/${base}.ts`)).href);

  watchTicks = requiredFunction(await load("watchticks"), "watchTicks");
  watchGuardedTicks = requiredFunction(await load("watchguardedticks"), "watchGuardedTicks");
  downloadBlob = requiredFunction(await load("downloadblob"), "downloadBlob");
  publishTicks = requiredFunction(await load("publishticks"), "publishTicks");
  drainTicks = requiredFunction(await load("drainticks"), "drainTicks");
  convertedWatchTicks = requiredFunction(
    await import(pathToFileURL(path.join(convertedRoot, "client/operations/watchticks.ts")).href),
    "watchTicks",
  );
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
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

test("yields one typed event per frame, with the data field JSON-decoded", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [
      chunk('data: {"seq":1}\n\n'),
      chunk('event: tick\nid: 7\ndata: {"seq":2,"label":"two"}\n\n'),
    ],
  });
  const events = await collect(asyncIterable(successData(await watchTicks(transport(), {}))));
  assert.deepEqual(events, [
    { data: { seq: 1 } },
    { data: { seq: 2, label: "two" }, event: "tick", id: "7" },
  ]);
});

test("the result resolves before the body has finished, which is the whole point", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    // The second frame is held back well past the point the result is awaited; a buffered branch
    // could not resolve until it arrived.
    chunks: [chunk('data: {"seq":1}\n\n'), chunk('data: {"seq":2}\n\n', 120)],
  });
  const started = Date.now();
  const handle = asyncIterable(successData(await watchTicks(transport(), {})));
  assert.ok(Date.now() - started < 100, "the result resolved at the response headers");
  assert.equal((await collect(handle)).length, 2);
});

test("a frame split across chunk boundaries is still one event", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"se'), chunk('q":3}\n'), chunk("\n")],
  });
  const events = await collect(asyncIterable(successData(await watchTicks(transport(), {}))));
  assert.deepEqual(events, [{ data: { seq: 3 } }]);
});

test("a documented non-2xx stream is a failure arm carrying its own handle", async () => {
  scriptRoute("GET", "/ticks/guarded", {
    status: 503,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"reason":"draining"}\n\n')],
  });
  const result = await watchGuardedTicks(transport(), {});
  assert.equal(requiredRecord(result, "result").outcome, 503);
  const events = await collect(asyncIterable(failureError(result)));
  assert.deepEqual(events, [{ data: { reason: "draining" } }]);
});

test("a raw branch resolves the byte stream itself, unparsed", async () => {
  scriptRoute("GET", "/blob", {
    status: 200,
    headers: [["Content-Type", "application/octet-stream"]],
    chunks: [chunk("alpha"), chunk("beta")],
  });
  const stream = byteStream(successData(await downloadBlob(transport(), {})));
  let text = "";
  for await (const bytes of stream) {
    assert.ok(bytes instanceof Uint8Array);
    text += new TextDecoder().decode(bytes);
  }
  assert.equal(text, "alphabeta");
});

test("a socket killed mid-stream rejects the iterator with the progress made", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":1}\n\n'), { destroy: true, delayMs: 10 }],
  });
  const events = asyncIterable(successData(await watchTicks(transport(), {})));
  const seen: unknown[] = [];
  const failure = await (async () => {
    try {
      for await (const event of events) {
        seen.push(event);
      }
    } catch (error: unknown) {
      return error;
    }
    return undefined;
  })();
  assert.equal(seen.length, 1);
  const record = requiredRecord(failure, "stream failure");
  assert.equal(record.kind, "sse");
  assert.equal(record.eventsYielded, 1);
});

test("abandoning the loop closes the response, and the server sees it", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [
      chunk('data: {"seq":1}\n\n'),
      chunk('data: {"seq":2}\n\n', 500),
      chunk('data: {"seq":3}\n\n', 500),
    ],
  });
  const cancelledBefore = harness.cancelledResponses();
  for await (const event of asyncIterable(successData(await watchTicks(transport(), {})))) {
    assert.deepEqual(event, { data: { seq: 1 } });
    break;
  }
  // The close travels over a real socket, so it is observed rather than assumed synchronously.
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(harness.cancelledResponses(), cancelledBefore + 1);
});

test("consuming an event stream twice is refused rather than silently empty", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":1}\n\n')],
  });
  const events = asyncIterable(successData(await watchTicks(transport(), {})));
  assert.equal((await collect(events)).length, 1);
  await assert.rejects(async () => collect(events));
});

test("a caller abort rejects with the caller's own reason, not a stream failure", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":1}\n\n'), chunk('data: {"seq":2}\n\n', 500)],
  });
  const controller = new AbortController();
  const events = asyncIterable(
    successData(await watchTicks(transport(), {}, { signal: controller.signal })),
  );
  const iterator = events[Symbol.asyncIterator]();
  await iterator.next();
  controller.abort("caller changed its mind");
  await assert.rejects(
    async () => iterator.next(),
    (error: unknown) => {
      assert.equal(error, "caller changed its mind");
      return true;
    },
  );
});

test("a streaming request body reaches the server as the bytes the caller wrote", async () => {
  scriptRoute("POST", "/publish", { status: 204 });
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
      controller.enqueue(encoder.encode('data: {"seq":2}\n\n'));
      controller.close();
    },
  });
  const result = await publishTicks(transport(), { body });
  assert.equal(requiredRecord(result, "result").outcome, 204);
  assert.equal(
    harness.requiredRequest(0).body.toString("utf8"),
    'data: {"seq":1}\n\ndata: {"seq":2}\n\n',
  );
});

test("an event that fails its schema stops the stream with the issues that failed", async () => {
  // The schema requires `seq` to be an integer. The first event is well-formed and must be
  // delivered; the second is checked at yield time, before the consumer sees it and before the
  // progress counter moves — so the failure reports one event yielded, not two.
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":1}\n\n'), chunk('data: {"seq":"not a number"}\n\n')],
  });
  const events = asyncIterable(successData(await watchTicks(transport(), {})));
  const seen: unknown[] = [];
  const failure = await (async () => {
    try {
      for await (const event of events) {
        seen.push(event);
      }
    } catch (error: unknown) {
      return error;
    }
    return undefined;
  })();
  assert.deepEqual(seen, [{ data: { seq: 1 } }]);
  const record = requiredRecord(failure, "stream failure");
  assert.equal(record.kind, "sse");
  assert.equal(record.eventsYielded, 1);
  assert.ok(Array.isArray(record.cause), "the cause is the issue list that failed");
  assert.equal(record.cause.length, 1);
});

test("a yielded event arrives converted, not in its wire form", async () => {
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":1,"at":"2026-08-04T10:20:30Z"}\n\n')],
  });
  const events = await collect(
    asyncIterable(successData(await convertedWatchTicks(transport(), {}))),
  );
  assert.equal(events.length, 1);
  const event = requiredRecord(events[0], "event");
  const data = requiredRecord(event.data, "event data");
  assert.ok(data.at instanceof Date, "the date/time field arrived as a Date");
  assert.equal(data.at.toISOString(), "2026-08-04T10:20:30.000Z");
  assert.equal(data.seq, 1);
});

test("an event is validated before it is converted, and the validator sees the wire value", async () => {
  // `at` is a string on the wire and a `Date` in the application form. A validator running after
  // the codec would see the `Date` and reject it; that it reports the *seq* issue instead — one
  // issue, from the wire value — is what fixes the order.
  scriptRoute("GET", "/ticks", {
    status: 200,
    headers: [...SSE_HEADERS],
    chunks: [chunk('data: {"seq":"not a number","at":"2026-08-04T10:20:30Z"}\n\n')],
  });
  const events = asyncIterable(successData(await convertedWatchTicks(transport(), {})));
  const failure = await (async () => {
    try {
      for await (const event of events) {
        assert.fail(`no event should be yielded, got ${JSON.stringify(event)}`);
      }
    } catch (error: unknown) {
      return error;
    }
    return undefined;
  })();
  const record = requiredRecord(failure, "stream failure");
  assert.equal(record.kind, "sse");
  assert.equal(record.eventsYielded, 0);
  assert.ok(Array.isArray(record.cause), "the cause is the issue list that failed");
  assert.equal(record.cause.length, 1);
});

test("a bodyless status declaring a stream delivers undefined, never a handle", async () => {
  scriptRoute("GET", "/drain", { status: 204 });
  const result = await drainTicks(transport(), {});
  const record = requiredRecord(result, "result");
  assert.equal(record.outcome, 204);
  assert.equal(record.ok, true);
  assert.equal(record.data, undefined);
});
