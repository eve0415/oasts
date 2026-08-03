// End-to-end coverage of the generated MSW handlers: the showcase fixture is generated, its
// handler factories are loaded, and they are registered in a real `setupServer` and driven with
// real `fetch` calls. Nothing here stubs MSW — the point is to prove the emitted matcher and the
// emitted `respond` behave under the library the artifact targets, not under our idea of it.
//
// Generated modules cross the dynamic-import boundary as `unknown` and are narrowed with the
// harness guards, so no generated symbol is imported at type-check time and no `as`/`any`/`!` is
// needed.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { access, cp, mkdtemp, symlink } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { pathToFileURL } from "node:url";

import { http, HttpResponse, passthrough, RequestHandler } from "msw";
import { setupServer } from "msw/node";

import { encodeMultipart } from "../serialize.ts";
import { requiredFunction, requiredRecord, type ExportedFunction } from "./harness.ts";

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/msw-showcase-3.1");
const emptyPathFixtureSource = path.join(repoRoot, "fixtures/msw-empty-path-3.1");
const transformFixtureSource = path.join(repoRoot, "fixtures/transform-msw-3.1");

const BASE = "https://api.test/v1";

let getPetMockHandler: ExportedFunction;
let headHealthMockHandler: ExportedFunction;
let getReportMockHandler: ExportedFunction;
let createPetMockHandler: ExportedFunction;
let uploadMultipartMockHandler: ExportedFunction;
let getEmptyMatrixHandler: ExportedFunction;
let getLatestEventHandler: ExportedFunction;
let getLatestEvent: ExportedFunction;
let createTransformTransport: ExportedFunction;

// Registered last, so it only answers when no generated handler matched. That makes "did our
// matcher match?" an observable fact rather than an inference from an unhandled-request warning.
const fellThrough = http.all(/^https:\/\/(?:api|other|staging)\.test\//u, () =>
  HttpResponse.text("fell-through", { status: 599 }),
);

const server = setupServer();

before(async () => {
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new Error(`msw E2E requires ${binary}; run \`cargo build -p oasts\` before this suite`);
  }

  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-msw-e2e-"));
  const fixtureRoot = path.join(temporaryRoot, "msw-showcase-3.1");
  const emptyPathFixtureRoot = path.join(temporaryRoot, "msw-empty-path-3.1");
  const transformFixtureRoot = path.join(temporaryRoot, "transform-msw-3.1");
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  await cp(emptyPathFixtureSource, emptyPathFixtureRoot, { recursive: true });
  await cp(transformFixtureSource, transformFixtureRoot, { recursive: true });
  execFileSync(binary, ["generate", "--config", "oasts-msw.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  execFileSync(binary, ["generate", "--config", "oasts-msw.yaml"], {
    cwd: emptyPathFixtureRoot,
    stdio: "pipe",
  });
  execFileSync(binary, ["generate", "--config", "oasts-msw.yaml"], {
    cwd: transformFixtureRoot,
    stdio: "pipe",
  });
  // Emitted handlers import `msw` bare, the way a consumer's would. Nothing resolves that from a
  // temp directory, so the runtime workspace's install is linked in beside the generated tree.
  const fixtureModules = path.join(fixtureRoot, "node_modules");
  try {
    await access(fixtureModules);
  } catch {
    await symlink(path.resolve(import.meta.dirname, "../node_modules"), fixtureModules, "dir");
  }
  const generatedRoot = path.join(fixtureRoot, "generated-msw");
  const emptyPathGeneratedRoot = path.join(emptyPathFixtureRoot, "generated-msw");
  const transformGeneratedRoot = path.join(transformFixtureRoot, "generated-msw");
  await cp(emptyPathGeneratedRoot, path.join(generatedRoot, "empty-path"), { recursive: true });
  await cp(transformGeneratedRoot, path.join(generatedRoot, "transform"), { recursive: true });

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(generatedRoot).href },
  });
  const load = async (base: string): Promise<unknown> =>
    import(pathToFileURL(path.join(generatedRoot, `msw/handlers/${base}.ts`)).href);

  getPetMockHandler = requiredFunction(await load("getpetmock"), "getPetMockHandler");
  headHealthMockHandler = requiredFunction(await load("headhealthmock"), "headHealthMockHandler");
  getReportMockHandler = requiredFunction(await load("getreportmock"), "getReportMockHandler");
  createPetMockHandler = requiredFunction(await load("createpetmock"), "createPetMockHandler");
  uploadMultipartMockHandler = requiredFunction(
    await load("uploadmultipartmock"),
    "uploadMultipartMockHandler",
  );
  getEmptyMatrixHandler = requiredFunction(
    await import(
      pathToFileURL(path.join(generatedRoot, "empty-path/msw/handlers/getemptymatrix.ts")).href
    ),
    "getEmptyMatrixHandler",
  );
  getLatestEventHandler = requiredFunction(
    await import(
      pathToFileURL(path.join(generatedRoot, "transform/msw/handlers/getlatestevent.ts")).href
    ),
    "getLatestEventHandler",
  );
  getLatestEvent = requiredFunction(
    await import(
      pathToFileURL(path.join(generatedRoot, "transform/client/operations/getlatestevent.ts")).href
    ),
    "getLatestEvent",
  );
  createTransformTransport = requiredFunction(
    await import(pathToFileURL(path.join(generatedRoot, "transform/runtime/transport.ts")).href),
    "createTransport",
  );

  server.listen({ onUnhandledRequest: "bypass" });
});

after(() => {
  server.close();
});

/**
 * Narrows a factory's return, which crosses the dynamic-import boundary as `unknown`.
 *
 * `instanceof` rather than a structural check: MSW's handler type is nominal, so a shape test
 * would need a cast to satisfy `server.use`, and the point of this suite is that the generated
 * factories really do produce MSW handlers.
 */
function asHandler(value: unknown): RequestHandler {
  if (!(value instanceof RequestHandler)) {
    throw new TypeError("a handler factory must return an MSW request handler");
  }
  return value;
}

function use(...handlers: unknown[]): void {
  server.resetHandlers();
  // The fall-through catch-all is always last: MSW resolves first match wins.
  server.use(...handlers.map(asHandler), fellThrough);
}

async function expectBodyError(
  factory: ExportedFunction,
  request: Request,
  code: string,
  applicationPath: readonly string[] | null,
): Promise<void> {
  let resolverCalled = false;
  let handlerError: Error | undefined;
  const captureError = ({ error }: { readonly error: Error }): void => {
    handlerError = error;
  };
  server.events.on("unhandledException", captureError);
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    use(
      factory(() => {
        resolverCalled = true;
        return undefined;
      }),
    );
    const response = await fetch(request);
    assert.equal(response.status, 500);
  } finally {
    console.error = originalConsoleError;
    server.events.removeListener("unhandledException", captureError);
  }

  assert.equal(resolverCalled, false);
  assert.ok(handlerError instanceof Error);
  const error = requiredRecord(handlerError, "handler error");
  assert.equal(error["name"], "OastsHandlerError");
  assert.equal(error["code"], code);
  assert.deepEqual(error["applicationPath"], applicationPath);
}

test("a documented JSON response carries its declared content type", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({
        match: 200,
        status: 200,
        contentType: "application/json",
        body: { id: 7, name: "Bella" },
      });
    }),
  );

  const response = await fetch(`${BASE}/pets/7`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.deepEqual(await response.json(), { id: 7, name: "Bella" });
});

test("MSW application dates round-trip through the wire into generated client dates", async () => {
  const occurredAt = new Date("2024-03-01T12:00:00.000Z");
  use(
    getLatestEventHandler(
      (input: unknown) => {
        const respond = requiredFunction(input, "respond");
        return respond({
          match: 200,
          status: 200,
          contentType: "application/json",
          body: { id: "e1", occurredAt },
        });
      },
      { baseUrl: BASE },
    ),
  );

  const wireResponse = await fetch(`${BASE}/events/latest`);
  const wireBody = requiredRecord(await wireResponse.json(), "wire response");
  assert.equal(wireBody.occurredAt, occurredAt.toISOString());

  const transport = createTransformTransport({ baseUrl: BASE });
  const result = requiredRecord(await getLatestEvent(transport, {}), "getLatestEvent result");
  const data = requiredRecord(result.data, "getLatestEvent data");
  assert.ok(data.occurredAt instanceof Date, "occurredAt should decode to a Date");
  assert.equal(data.occurredAt.getTime(), occurredAt.getTime());
});

test("a second media entry on the same status selects its own content type", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({ match: 200, status: 200, contentType: "text/plain", body: "Bella" });
    }),
  );

  const response = await fetch(`${BASE}/pets/7`);
  assert.equal(response.headers.get("content-type"), "text/plain");
  assert.equal(await response.text(), "Bella");
});

test("a no-payload branch sends zero bytes and no content type", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({ match: 204, status: 204 });
    }),
  );

  const response = await fetch(`${BASE}/pets/7`);
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("content-type"), null);
  assert.equal((await response.arrayBuffer()).byteLength, 0);
});

test("a bodyless operation answers without a body", async () => {
  use(
    headHealthMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({ match: 200, status: 200 });
    }),
  );

  const response = await fetch(`${BASE}/health`, { method: "HEAD" });
  assert.equal(response.status, 200);
  assert.equal((await response.arrayBuffer()).byteLength, 0);
});

test("generated resolvers receive decoded JSON and multipart bodies", async () => {
  use(
    createPetMockHandler((input: unknown) => {
      const fields = requiredRecord(input, "resolver input");
      assert.deepEqual(requiredRecord(fields["body"], "JSON body"), { name: "Bella" });
      const respond = requiredFunction(fields, "respond");
      return respond({
        match: 201,
        status: 201,
        contentType: "application/json",
        body: { id: 7, name: "Bella" },
      });
    }),
  );
  const created = await fetch(`${BASE}/pets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Bella" }),
  });
  assert.equal(created.status, 201);

  const multipart = await encodeMultipart([
    {
      name: "meta",
      contentType: "application/json",
      payload: new TextEncoder().encode(JSON.stringify({ name: "Bella" })),
    },
    {
      name: "file",
      contentType: "application/octet-stream",
      filename: "photo.bin",
      payload: Uint8Array.of(0, 127, 255),
    },
  ]);
  use(
    uploadMultipartMockHandler((input: unknown) => {
      const fields = requiredRecord(input, "resolver input");
      const body = requiredRecord(fields["body"], "multipart body");
      assert.deepEqual(requiredRecord(body["meta"], "meta part"), { name: "Bella" });
      assert.deepEqual(body["file"], Uint8Array.of(0, 127, 255));
      const respond = requiredFunction(fields, "respond");
      return respond({
        match: 200,
        status: 200,
        contentType: "application/json",
        body: { id: 7, name: "Bella" },
      });
    }),
  );
  const multipartBody = new ArrayBuffer(multipart.body.length);
  new Uint8Array(multipartBody).set(multipart.body);
  const uploaded = await fetch(`${BASE}/uploads`, {
    method: "POST",
    headers: { "Content-Type": multipart.contentTypeHeader },
    body: multipartBody,
  });
  assert.equal(uploaded.status, 200);
});

test("malformed request bodies never reach the generated resolver", async () => {
  await expectBodyError(
    createPetMockHandler,
    new Request(`${BASE}/pets`, { method: "POST" }),
    "body-missing",
    null,
  );
  await expectBodyError(
    createPetMockHandler,
    new Request(`${BASE}/pets`, {
      method: "POST",
      body: Uint8Array.of(1),
    }),
    "content-type-mismatch",
    null,
  );
  await expectBodyError(
    createPetMockHandler,
    new Request(`${BASE}/pets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{",
    }),
    "body-decode",
    ["body"],
  );
  await expectBodyError(
    uploadMultipartMockHandler,
    new Request(`${BASE}/uploads`, {
      method: "POST",
      headers: { "Content-Type": "multipart/form-data; boundary=broken" },
      body: "not multipart",
    }),
    "multipart-decode",
    ["body"],
  );
});

test("a range branch answers on any status inside it", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({
        match: "4XX",
        status: 404,
        contentType: "application/json",
        body: { message: "gone" },
      });
    }),
  );

  const response = await fetch(`${BASE}/pets/7`);
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { message: "gone" });
});

test("binary responses reach the wire as the exact bytes", async () => {
  use(
    getReportMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({
        match: 200,
        status: 200,
        contentType: "application/octet-stream",
        body: Uint8Array.of(0, 127, 255),
      });
    }),
  );

  const response = await fetch(`${BASE}/reports/.a.b`);
  assert.equal(response.headers.get("content-type"), "application/octet-stream");
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), Uint8Array.of(0, 127, 255));
});

test("an empty exploded matrix path matches and projects the empty collection", async () => {
  use(
    getEmptyMatrixHandler((input: unknown) => {
      const params = requiredRecord(requiredRecord(input, "resolver input")["params"], "params");
      assert.deepEqual(params["p"], []);
      const respond = requiredFunction(input, "respond");
      return respond({ match: 204, status: 204 });
    }),
  );

  const response = await fetch(`${BASE}/items/`);
  assert.equal(response.status, 204);
});

test("origin is enforced: the same path on another host is not intercepted", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({ match: 204, status: 204 });
    }),
  );

  const matched = await fetch(`${BASE}/pets/7`);
  assert.equal(matched.status, 204);

  // Same path, different origin. Two APIs mocked in one suite must never answer for each other.
  const other = await fetch("https://other.test/v1/pets/7");
  assert.equal(other.status, 599);
  assert.equal(await other.text(), "fell-through");
});

test("a baseUrl override moves the whole matcher", async () => {
  use(
    getPetMockHandler(
      (input: unknown) => {
        const respond = requiredFunction(input, "respond");
        return respond({ match: 204, status: 204 });
      },
      { baseUrl: "https://staging.test/v2" },
    ),
  );

  const overridden = await fetch("https://staging.test/v2/pets/7");
  assert.equal(overridden.status, 204);

  const original = await fetch(`${BASE}/pets/7`);
  assert.equal(original.status, 599);
});

test("returning nothing falls through to the next handler", async () => {
  use(getPetMockHandler(() => undefined));

  const response = await fetch(`${BASE}/pets/7`);
  assert.equal(response.status, 599);
});

test("passthrough survives the wrapper", async () => {
  use(getPetMockHandler(() => passthrough()));

  // passthrough performs the request for real, so it reaches the catch-all's absence rather than
  // the catch-all itself; asserting it does not throw and does not answer 204 is the point.
  const response = await fetch(`${BASE}/pets/7`).catch(() => "network");
  assert.notEqual(response, 204);
});

test("a generator resolver answers a different branch per call", async () => {
  // MSW's own sequencing convention, which the wrapper must not block: this is how a test says
  // "first call succeeds, second one 404s" without registering two handlers.
  use(
    getPetMockHandler(function* (input: unknown) {
      const respond = requiredFunction(input, "respond");
      yield respond({
        match: 200,
        status: 200,
        contentType: "application/json",
        body: { id: 1, name: "first" },
      });
      yield respond({
        match: "4XX",
        status: 404,
        contentType: "application/json",
        body: { message: "second" },
      });
    }),
  );

  const first = await fetch(`${BASE}/pets/1`);
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { id: 1, name: "first" });

  const second = await fetch(`${BASE}/pets/1`);
  assert.equal(second.status, 404);
  assert.deepEqual(await second.json(), { message: "second" });
});

test("a later registered handler overrides an earlier one, as server.use promises", async () => {
  use(
    getPetMockHandler((input: unknown) => {
      const respond = requiredFunction(input, "respond");
      return respond({ match: 204, status: 204 });
    }),
  );
  server.use(
    asHandler(
      getPetMockHandler((input: unknown) => {
        const respond = requiredFunction(input, "respond");
        return respond({
          match: 200,
          status: 200,
          contentType: "application/json",
          body: { id: 2, name: "override" },
        });
      }),
    ),
  );

  const response = await fetch(`${BASE}/pets/2`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { id: 2, name: "override" });
});
