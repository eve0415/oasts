import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { OastsHandlerError, respondWith } from "../msw-runtime.ts";
import { handlerErrorConstructionVectors } from "../test-conformance/vectors-msw-handler-error.ts";

describe("OastsHandlerError", () => {
  test("constructs from every frozen vector", () => {
    for (const vector of handlerErrorConstructionVectors) {
      const error = new OastsHandlerError({
        code: vector.code,
        sourcePointer: vector.sourcePointer,
        applicationPath: vector.applicationPath,
        cause: new Error(vector.label),
      });
      assert.equal(error.name, "OastsHandlerError", vector.label);
      assert.equal(error.code, vector.code, vector.label);
      assert.deepEqual(error.sourcePointer, vector.sourcePointer, vector.label);
      assert.deepEqual(error.applicationPath, vector.applicationPath, vector.label);
      assert.ok(error.cause instanceof Error, vector.label);
      assert.ok(error instanceof Error, vector.label);
      assert.ok(error instanceof OastsHandlerError, vector.label);
    }
  });

  test("covers every declared code", () => {
    const covered = new Set(handlerErrorConstructionVectors.map((vector) => vector.code));
    assert.deepEqual([...covered].toSorted(), [
      "body-decode",
      "body-missing",
      "content-type-mismatch",
      "multipart-decode",
      "parameter-decode",
    ]);
  });

  test("covers both the null and non-null application-path forms", () => {
    assert.ok(handlerErrorConstructionVectors.some((vector) => vector.applicationPath === null));
    assert.ok(handlerErrorConstructionVectors.some((vector) => vector.applicationPath !== null));
  });
});

// The map an operation's handler passes in. Its keys are that operation's declared content types,
// so the kernel never classifies one itself.
const PAYLOADS = {
  "application/json": "json",
  "application/json; charset=utf-8": "json",
  "application/problem+json": "json",
  "text/json": "text",
  "text/plain; charset=iso-8859-1": "text",
  "application/octet-stream": "binary",
  "text/event-stream": "stream",
} as const;

describe("respondWith", () => {
  test("hands a resolver's stream to the response untouched", async () => {
    // The resolver owns the framing — the frame encoder is exported for it — so the kernel must
    // not buffer, re-encode, or otherwise interpose on the bytes it was given.
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"seq":1}\n\n'));
        controller.close();
      },
    });
    const response = respondWith(200, "text/event-stream", stream, PAYLOADS);
    assert.equal(response.headers.get("Content-Type"), "text/event-stream");
    assert.equal(await response.text(), 'data: {"seq":1}\n\n');
  });

  test("an absent streaming body is an empty response, not an error", async () => {
    const response = respondWith(200, "text/event-stream", undefined, PAYLOADS);
    assert.equal(await response.text(), "");
  });

  test("a streaming body that is not a stream is refused", () => {
    assert.throws(
      () => respondWith(200, "text/event-stream", "data: hi", PAYLOADS),
      /must be a ReadableStream/u,
    );
  });

  test("serializes JSON with the declared content type", async () => {
    const response = respondWith(201, "application/json; charset=utf-8", { id: 1 }, PAYLOADS);
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("Content-Type"), "application/json; charset=utf-8");
    assert.deepEqual(await response.json(), { id: 1 });

    const problem = respondWith(422, "application/problem+json", { message: "invalid" }, PAYLOADS);
    assert.equal(problem.headers.get("Content-Type"), "application/problem+json");
    assert.deepEqual(await problem.json(), { message: "invalid" });

    const undefinedBody = respondWith(200, "application/json", undefined, PAYLOADS);
    assert.equal(await undefinedBody.text(), "");
  });

  test("native JSON serialization cannot encode a bigint response", () => {
    assert.throws(
      () => respondWith(200, "application/json", { id: 42n }, PAYLOADS),
      /serialize a BigInt/u,
    );
  });

  test("preserves text and its declared content type", async () => {
    const response = respondWith(202, "text/plain; charset=iso-8859-1", "accepted", PAYLOADS);
    assert.equal(response.status, 202);
    assert.equal(response.headers.get("Content-Type"), "text/plain; charset=iso-8859-1");
    assert.equal(await response.text(), "accepted");
  });

  test("preserves binary bytes and their declared content type", async () => {
    const response = respondWith(
      200,
      "application/octet-stream",
      Uint8Array.of(0, 127, 255),
      PAYLOADS,
    );
    assert.equal(response.headers.get("Content-Type"), "application/octet-stream");
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), Uint8Array.of(0, 127, 255));
  });

  test("emits a null body without a content type for no-payload responses", async () => {
    const response = respondWith(204, null, null, PAYLOADS);
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("Content-Type"), null);
    assert.equal(await response.text(), "");
  });

  test("serializes every JSON-family media the compiler recognises, parameters and suffixes included", async () => {
    // A body typed as its declared schema must reach the wire as JSON for every media the compiler
    // calls JSON — including a parameterized type and a structured suffix. The kernel used to
    // decide this itself with a rule that missed those, and wrote `[object Object]` instead.
    for (const contentType of [
      "application/json",
      "application/json; charset=utf-8",
      "application/problem+json",
    ]) {
      const response = respondWith(200, contentType, { message: "hello" }, PAYLOADS);
      assert.equal(response.headers.get("Content-Type"), contentType);
      assert.deepEqual(await response.json(), { message: "hello" }, contentType);
    }
  });

  test("refuses a content type the operation never declared", () => {
    // Unreachable through the typed surface. Guessing here would put the wrong bytes on the wire,
    // so untyped JavaScript gets an error rather than a silent best effort.
    assert.throws(
      () => respondWith(200, "application/vnd.unknown", { a: 1 }, PAYLOADS),
      /not declared/,
    );
  });

  test("refuses a binary body that is not bytes", () => {
    assert.throws(
      () => respondWith(200, "application/octet-stream", { a: 1 }, PAYLOADS),
      /must be bytes/,
    );
    const empty = respondWith(200, "application/octet-stream", null, PAYLOADS);
    assert.equal(empty.headers.get("Content-Type"), "application/octet-stream");
  });

  test("rejects own media keys on a no-payload response", () => {
    for (const response of [{ contentType: undefined }, { body: undefined }, { body: null }]) {
      assert.throws(() => respondWith(204, null, response, PAYLOADS), /no-payload response/);
    }
    assert.throws(
      () => Reflect.apply(respondWith, undefined, [204, undefined, null, PAYLOADS]),
      /no-payload response/,
    );
  });
});

const sharedDeclarations = (source: string): string[] => {
  const text = readFileSync(new URL(source, import.meta.url), "utf8");
  return text
    .split("\n")
    .filter((line) => /^export type (SourcePointer|ApplicationPath) =/.test(line))
    .map((line) => line.trim())
    .toSorted();
};

describe("shared declaration drift", () => {
  // The MSW kernel may not import the client result runtime, so it re-declares SourcePointer and
  // ApplicationPath. That is only safe while the two spellings stay identical: a widened copy here
  // would let a handler describe a source location the rest of the compiler cannot.
  test("SourcePointer and ApplicationPath match the client runtime verbatim", () => {
    const declarations = sharedDeclarations;
    const client = declarations("../result.ts");
    const msw = declarations("../msw-runtime.ts");
    assert.equal(client.length, 2, "expected both declarations in the client runtime");
    assert.deepEqual(msw, client);
  });
});
