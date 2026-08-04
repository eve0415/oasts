// Date/time transform end-to-end: the only check in the tree that can tell "a codec call was
// emitted into the operation body" from "no codec call was emitted". The unit tests cover the
// kernel against the frozen vectors and the emitter against its own strings; neither observes
// whether the generated client actually calls one. This suite drives the GENERATED showcase client
// through a real local server and inspects both the application values it hands back and the raw
// bytes it puts on the wire.
//
// Consumption strategy is the client/auth suites': generate into a mkdtemp tree by exec'ing the
// built binary, register the `node:module` hook that retries a relative `.js` specifier at the
// sibling `.ts`, and load generated modules across the dynamic-import boundary as `unknown` so no
// generated symbol is imported at type-check time.

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
  requestHeader,
  type ExportedFunction,
} from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/transform-showcase-3.1");

// One generated operation, loaded across the dynamic-import boundary as `unknown` and narrowed by
// `requiredFunction`, so no generated symbol is imported at type-check time.
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
let createTransport: ExportedFunction;
let readEvent: ExportedFunction;
let getLatestEvent: ExportedFunction;
let submitEventForm: ExportedFunction;
let uploadEvent: ExportedFunction;
let submitDiscriminatedEvent: ExportedFunction;
let readNegotiatedEvent: ExportedFunction;
let readEventTimings: ExportedFunction;
let readEventExtensions: ExportedFunction;
// The same document under `validation.request: true`. Its request validators run on whatever the
// conversion produced, so a call that would be well-formed on the wire and ill-formed as an
// application value is what distinguishes the two orderings.
let validatedReadEvent: ExportedFunction;
let validatedGetLatestEvent: ExportedFunction;

before(async () => {
  await access(binary, constants.X_OK);
  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-transform-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "transform-showcase-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  for (const config of ["oasts-date.yaml", "oasts-date-validated.yaml"]) {
    execFileSync(binary, ["generate", "--config", config], { cwd: fixtureRoot, stdio: "pipe" });
  }
  const generatedRoot = path.join(fixtureRoot, "generated-date");
  const validatedRoot = path.join(fixtureRoot, "generated-date-validated");

  // One registration covering both trees. The hook keeps a single root in module scope, so
  // registering it twice would leave only the second tree's specifiers rewritten; the fixture root
  // is the nearest prefix that contains both.
  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(fixtureRoot).href },
  });
  readEvent = await operation(generatedRoot, "readevent", "readEvent");
  getLatestEvent = await operation(generatedRoot, "getlatestevent", "getLatestEvent");
  submitEventForm = await operation(generatedRoot, "submiteventform", "submitEventForm");
  uploadEvent = await operation(generatedRoot, "uploadevent", "uploadEvent");
  submitDiscriminatedEvent = await operation(
    generatedRoot,
    "submitdiscriminatedevent",
    "submitDiscriminatedEvent",
  );
  readNegotiatedEvent = await operation(
    generatedRoot,
    "readnegotiatedevent",
    "readNegotiatedEvent",
  );
  readEventTimings = await operation(generatedRoot, "readeventtimings", "readEventTimings");
  readEventExtensions = await operation(
    generatedRoot,
    "readeventextensions",
    "readEventExtensions",
  );
  validatedReadEvent = await operation(validatedRoot, "readevent", "readEvent");
  validatedGetLatestEvent = await operation(validatedRoot, "getlatestevent", "getLatestEvent");
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

const OCCURRED_AT = new Date("2024-03-01T12:00:00.000Z");
// The canonical encoding of OCCURRED_AT, percent-encoded as one path segment.
const OCCURRED_AT_PATH = "2024-03-01T12%3A00%3A00.000Z";

// The latest-event route carries no request-surface transform, so scripting it needs no prediction
// about what the request pipeline does to the URL.
function scriptLatest(body: string, status = 200): void {
  scriptRoute("GET", "/events/latest", {
    status,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from(body),
  });
}

test("a response body property decodes to the application representation", async () => {
  scriptLatest('{"id":"e1","occurredAt":"2024-03-01T12:00:00Z"}');

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await getLatestEvent(transport, {}), "getLatestEvent result");

  assert.equal(result.outcome, 200);
  const data = requiredRecord(result.data, "getLatestEvent data");
  assert.ok(data.occurredAt instanceof Date, "occurredAt should decode to a Date");
  assert.equal(data.occurredAt.getTime(), OCCURRED_AT.getTime());
  assert.equal(data.id, "e1");
});

test("a request value encodes to its canonical wire form before serialization", async () => {
  const transport = createTransport({ baseUrl });
  await readEvent(transport, {
    path: { occurredAt: OCCURRED_AT },
    query: { since: new Date("2023-01-02T03:04:05.678Z") },
  });

  const received = requiredRequest(0);
  assert.equal(
    received.url,
    `/events/${OCCURRED_AT_PATH}?since=2023-01-02T03%3A04%3A05.678Z`,
    "both the path and the query value should carry canonical RFC 3339 text",
  );
});

test("a form field encodes before urlencoded serialization", async () => {
  scriptRoute("POST", "/events/form", { status: 204 });

  const transport = createTransport({ baseUrl });
  await submitEventForm(transport, { body: { occurredAt: OCCURRED_AT, label: "form" } });

  const received = requiredRequest(0);
  assert.equal(requestHeader(received, "content-type"), "application/x-www-form-urlencoded");
  const fields = new URLSearchParams(received.body.toString("utf8"));
  assert.equal(fields.get("occurredAt"), "2024-03-01T12:00:00.000Z");
  assert.equal(fields.get("label"), "form");
});

test("a multipart field encodes before part serialization", async () => {
  scriptRoute("POST", "/events/multipart", { status: 204 });

  const transport = createTransport({ baseUrl });
  await uploadEvent(transport, { body: { occurredAt: OCCURRED_AT, label: "multipart" } });

  const received = requiredRequest(0);
  assert.match(requestHeader(received, "content-type") ?? "", /^multipart\/form-data; boundary=/);
  const body = received.body.toString("utf8");
  assert.match(body, /name="occurredAt"/);
  assert.match(body, /2024-03-01T12:00:00\.000Z/);
  assert.match(body, /name="label"/);
  assert.match(body, /multipart/);
});

test("a discriminated body converts only the selected media arm", async () => {
  scriptRoute("POST", "/events/discriminated", { status: 204 });

  const transport = createTransport({ baseUrl });
  await submitDiscriminatedEvent(transport, {
    body: {
      contentType: "application/json",
      body: { occurredAt: OCCURRED_AT, label: "json" },
    },
  });

  const received = requiredRequest(0);
  assert.equal(requestHeader(received, "content-type"), "application/json");
  const body: unknown = JSON.parse(received.body.toString("utf8"));
  assert.deepEqual(requiredRecord(body, "discriminated request body"), {
    occurredAt: "2024-03-01T12:00:00.000Z",
    label: "json",
  });
});

// One route, three negotiated payloads. Only a real server can settle which codec ran: the branch
// declares one arm per media entry, and the emitted narrowing picks between them on a header the
// type system never sees.
function scriptNegotiated(contentType: string, body: string): void {
  scriptRoute("GET", "/events/negotiated", {
    status: 200,
    headers: [["Content-Type", contentType]],
    body: Buffer.from(body),
  });
}

test("a discriminated response converts the arm its content type selected", async () => {
  scriptNegotiated("application/vnd.summary+json", '{"summarisedAt":"2024-03-01T12:00:00Z"}');

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await readNegotiatedEvent(transport, {}),
    "readNegotiatedEvent result",
  );

  assert.equal(result.contentType, "application/vnd.summary+json");
  const data = requiredRecord(result.data, "readNegotiatedEvent data");
  assert.ok(data.summarisedAt instanceof Date, "summarisedAt should decode to a Date");
  assert.equal(data.summarisedAt.getTime(), OCCURRED_AT.getTime());
  // The other JSON arm's property is not in this payload, and its codec must not have run: it would
  // have thrown on the absent required value rather than returned this arm.
  assert.equal(data.occurredAt, undefined);
});

test("a sibling arm of the same status converts through its own codec", async () => {
  scriptNegotiated("application/json", '{"id":"e1","occurredAt":"2024-03-01T12:00:00Z"}');

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await readNegotiatedEvent(transport, {}),
    "readNegotiatedEvent result",
  );

  assert.equal(result.contentType, "application/json");
  const data = requiredRecord(result.data, "readNegotiatedEvent data");
  assert.ok(data.occurredAt instanceof Date, "occurredAt should decode to a Date");
  assert.equal(data.id, "e1");
});

test("an arm no codec is bound to is handed back unconverted", async () => {
  scriptNegotiated("text/plain", "2024-03-01T12:00:00Z");

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await readNegotiatedEvent(transport, {}),
    "readNegotiatedEvent result",
  );

  assert.equal(result.contentType, "text/plain");
  assert.equal(result.data, "2024-03-01T12:00:00Z");
});

test("an index signature converts the keys its declared members do not cover", async () => {
  scriptRoute("GET", "/events/timings", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"startedAt":"2024-03-01T12:00:00Z","finishedAt":"2024-03-01T12:00:00Z"}'),
  });

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await readEventTimings(transport, {}), "readEventTimings result");
  const data = requiredRecord(result.data, "readEventTimings data");

  // The declared member and the undeclared one both arrive converted, and neither was converted
  // twice — a second pass over an already-decoded value would have thrown.
  assert.ok(data.startedAt instanceof Date, "the declared member should decode to a Date");
  assert.ok(data.finishedAt instanceof Date, "the index signature key should decode to a Date");
  assert.equal(data.finishedAt.getTime(), OCCURRED_AT.getTime());
});

test("a pattern property converts only the keys its index signature types", async () => {
  scriptRoute("GET", "/events/extensions", {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from('{"x-recorded":"2024-03-01T12:00:00Z","note":"kept as is"}'),
  });

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await readEventExtensions(transport, {}),
    "readEventExtensions result",
  );
  const data = requiredRecord(result.data, "readEventExtensions data");

  assert.ok(data["x-recorded"] instanceof Date, "a matching key should decode to a Date");
  // The type says nothing about a key the pattern does not match, so neither does the conversion.
  assert.equal(data["note"], "kept as is");
});

test("a wire value the grammar refuses is a response-transform failure", async () => {
  scriptLatest('{"id":"e1","occurredAt":"not a timestamp"}');

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await getLatestEvent(transport, {}), "getLatestEvent result");

  assert.equal(result.outcome, "response-transform");
  assert.equal(result.ok, false);
  assert.equal(result.match, 200);
  const error = requiredRecord(result.error, "transform error");
  assert.equal(error.direction, "response");
  assert.equal(error.code, "invalid-wire-value");
  assert.deepEqual(error.applicationPath, ["occurredAt"]);
});

test("a wire body of the wrong container shape is a result arm, not a throw", async () => {
  // Every leaf the grammar would reject is already covered above. This is the other half: a body
  // that decodes as JSON but is not the shape the schema declares, so the conversion faults while
  // walking it rather than while parsing a leaf. The contract makes no distinction — a decode that
  // cannot produce an application value is a `response-transform` arm either way.
  scriptLatest("null");

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await getLatestEvent(transport, {}), "getLatestEvent result");

  assert.equal(result.outcome, "response-transform");
  const error = requiredRecord(result.error, "transform error");
  assert.equal(error.direction, "response");
  assert.equal(error.code, "invalid-wire-value");
});

test("a documented error body decodes like any other response body", async () => {
  scriptLatest('{"message":"gone","detectedAt":"2024-03-01T12:00:00Z"}', 410);

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(await getLatestEvent(transport, {}), "getLatestEvent result");

  assert.equal(result.outcome, "4XX");
  const error = requiredRecord(result.error, "getLatestEvent error body");
  assert.ok(error.detectedAt instanceof Date, "detectedAt should decode to a Date");
  assert.equal(error.detectedAt.getTime(), OCCURRED_AT.getTime());
});

test("request validators observe the encoded values, not the caller's", async () => {
  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await validatedReadEvent(transport, {
      path: { occurredAt: OCCURRED_AT },
      query: { since: OCCURRED_AT, window: [OCCURRED_AT, OCCURRED_AT] },
    }),
    "readEvent result",
  );

  // Every one of those parameters validates against `type: string, format: date-time`, and the
  // array against an array of them. A validator running before the conversion would see `Date`
  // objects and report four type violations; running after it, none.
  assert.notEqual(
    result.outcome,
    "request-validation",
    `a well-formed call must not fail request validation: ${JSON.stringify(result)}`,
  );
  const received = requiredRequest(0);
  assert.match(
    received.url,
    /^\/events\/2024-03-01T12%3A00%3A00\.000Z\?/,
    "the validated build must still put canonical wire text on the wire",
  );
  assert.ok(
    received.url.includes("window=2024-03-01T12%3A00%3A00.000Z"),
    `the array parameter must serialize element-wise after conversion: ${received.url}`,
  );
});

test("a rejecting decode is response-transform even with response validation off", async () => {
  scriptLatest('{"id":"e1","occurredAt":"not a timestamp"}');

  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await validatedGetLatestEvent(transport, {}),
    "getLatestEvent result",
  );

  assert.equal(result.outcome, "response-transform");
  assert.notEqual(result.outcome, "response-validation");
});

test("an application value no wire string represents is a request-transform failure", async () => {
  const transport = createTransport({ baseUrl });
  const result = requiredRecord(
    await readEvent(transport, { path: { occurredAt: new Date(Number.NaN) } }),
    "readEvent result",
  );

  assert.equal(result.outcome, "request-transform");
  assert.equal(result.ok, false);
  const error = requiredRecord(result.error, "transform error");
  assert.equal(error.direction, "request");
  assert.equal(error.code, "invalid-application-value");
  assert.equal(requests.length, 0, "a rejected encode must not reach the transport");
});
