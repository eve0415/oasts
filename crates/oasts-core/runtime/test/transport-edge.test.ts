import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { isRequestPhaseFailure, requestFailure } from "./result-narrowing.ts";

import {
  createTransport,
  execute,
  type BodyEncoder,
  binaryBody,
  discriminatedBody,
  jsonBody,
  multipartBody,
  textBody,
  urlencodedBody,
  type ExecutionResult,
  type MultipartFieldPlan,
  type OperationDescriptor,
} from "../transport.ts";
import {
  serializeHeaderSimple,
  serializeQueryDeepObject,
  serializeQueryForm,
  serializeQuerySpaceDelimited,
} from "../serialize.ts";

function operation(overrides: Partial<OperationDescriptor> = {}): OperationDescriptor {
  return {
    operationId: "edgeOperation",
    method: "POST",
    path: [[{ kind: "literal", text: "/edge" }]],
    params: [],
    body: null,
    accept: null,
    credentialHeaders: [],
    security: null,
    responses: [],
    baseUrl: { kind: "literal", value: "https://example.com/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

function multipartField(overrides: Partial<MultipartFieldPlan> = {}): MultipartFieldPlan {
  return {
    name: "value",
    required: true,
    repeated: false,
    wrapper: false,
    payload: "text",
    contentType: { kind: "fixed", value: "text/plain" },
    filename: false,
    ...overrides,
  };
}

async function requestEncode(body: BodyEncoder, value: unknown): Promise<ExecutionResult> {
  return execute(
    createTransport({ fetch: async () => new Response(null, { status: 404 }) }),
    operation({ body }),
    { body: value },
  );
}

describe("descriptor boundary validation", () => {
  test("reads parameter values only from record location groups", async () => {
    let url = "";
    const descriptor = operation({
      params: [
        {
          name: "value",
          location: "query",
          required: true,
          serialize: serializeQueryForm,
          allowReserved: false,
        },
      ],
    });
    const present = await execute(
      createTransport({
        fetch: async (request) => {
          url = request.url;
          return new Response(null, { status: 404 });
        },
      }),
      descriptor,
      { query: { value: "nested" } },
    );

    assert.equal(present.outcome, "unmatched");
    assert.equal(url, "https://example.com/api/edge?value=nested");
    for (const input of [{}, { query: "not a record" }]) {
      const absent = requestFailure(await execute(createTransport({}), descriptor, input));
      assert.equal(absent.outcome, "request-encode");
    }
  });

  test("maps missing plans, required parameters, invalid values, and serializer errors", async () => {
    const descriptors: readonly (readonly [
      OperationDescriptor,
      Readonly<Record<string, unknown>>,
    ])[] = [
      [operation({ path: [[{ kind: "param", name: "missingPlan" }]] }), {}],
      [
        operation({
          params: [
            {
              name: "required",
              location: "query",
              required: true,
              serialize: serializeQueryForm,
              allowReserved: false,
            },
          ],
        }),
        {},
      ],
      [
        operation({
          params: [
            {
              name: "value",
              location: "query",
              required: true,
              serialize: serializeQueryForm,
              allowReserved: false,
            },
          ],
        }),
        { query: { value: { nested: null } } },
      ],
      [
        operation({
          params: [
            {
              name: "value",
              location: "query",
              required: true,
              serialize() {
                throw new Error("serializer failed");
              },
              allowReserved: false,
            },
          ],
        }),
        { query: { value: "x" } },
      ],
      [
        operation({
          params: [
            {
              name: "value",
              location: "query",
              required: true,
              serialize() {
                throw 7;
              },
              allowReserved: false,
            },
          ],
        }),
        { query: { value: "x" } },
      ],
      [
        operation({
          path: [[{ kind: "param", name: "optionalPath" }]],
          params: [
            {
              name: "optionalPath",
              location: "path",
              required: false,
              serialize: serializeQueryForm,
              allowReserved: false,
            },
          ],
        }),
        {},
      ],
    ];

    for (const [descriptor, input] of descriptors) {
      const result = requestFailure(await execute(createTransport({}), descriptor, input));
      assert.equal(result.outcome, "request-encode");
    }
  });

  test("omits absent optional and empty query fragments while appending to existing query", async () => {
    let url = "";
    const result = await execute(
      createTransport({
        fetch: async (request) => {
          url = request.url;
          return new Response(null, { status: 404 });
        },
      }),
      operation({
        path: [[{ kind: "literal", text: "/edge?existing=one" }]],
        params: [
          {
            name: "absent",
            location: "query",
            required: false,
            serialize: serializeQueryForm,
            allowReserved: false,
          },
          {
            name: "empty",
            location: "query",
            required: true,
            serialize() {
              return "";
            },
            allowReserved: false,
          },
          {
            name: "value",
            location: "query",
            required: true,
            serialize: serializeQueryForm,
            allowReserved: false,
          },
        ],
      }),
      { query: { empty: "ignored", value: "two" } },
    );

    assert.equal(result.outcome, "unmatched");
    assert.equal(url, "https://example.com/api/edge?existing=one&value=two");
  });

  test("accepts direct references to shape-specific serializers", async () => {
    let url = "";
    await execute(
      createTransport({
        fetch: async (request) => {
          url = request.url;
          return new Response(null, { status: 404 });
        },
      }),
      operation({
        params: [
          {
            name: "filter",
            location: "query",
            required: true,
            serialize: serializeQueryDeepObject,
            allowReserved: false,
          },
          {
            name: "ids",
            location: "query",
            required: true,
            serialize: serializeQuerySpaceDelimited,
            allowReserved: false,
          },
        ],
      }),
      { query: { filter: { state: "open" }, ids: [1, 2] } },
    );

    assert.equal(url, "https://example.com/api/edge?filter[state]=open&ids=1%202");
  });

  test("rejects relative literal bases and unresolved template placeholders", async () => {
    const relative = requestFailure(
      await execute(
        createTransport({}),
        operation({ baseUrl: { kind: "literal", value: "/relative" } }),
        {},
      ),
    );
    const placeholder = requestFailure(
      await execute(
        createTransport({}),
        operation({
          baseUrl: {
            kind: "server",
            index: 0,
            servers: [{ url: "https://{known}.example/{unknown}", variables: [["known", "ok"]] }],
          },
        }),
        {},
      ),
    );

    assert.equal(relative.outcome, "request-encode");
    assert.equal(placeholder.outcome, "request-encode");
  });

  test("a configured baseUrl short-circuits an unresolved server placeholder", async () => {
    // With a baseUrl set the server URL is discarded, so an unresolved `{unknown}` in it is moot:
    // the operation resolves against the fallback instead of failing.
    let captured: Request | undefined;
    const result = await execute(
      createTransport({
        baseUrl: "https://fallback.example/v1",
        fetch: async (request) => {
          captured = request;
          return new Response(null, { status: 204 });
        },
      }),
      operation({
        baseUrl: {
          kind: "server",
          index: 0,
          servers: [{ url: "https://{known}.example/{unknown}", variables: [["known", "ok"]] }],
        },
      }),
      {},
    );

    assert.ok(!isRequestPhaseFailure(result));
    assert.ok(captured);
    assert.ok(captured.url.startsWith("https://fallback.example"), captured.url);
  });

  test("validates form-urlencoded body shape and fields", async () => {
    const plan: BodyEncoder = urlencodedBody("application/x-www-form-urlencoded", [
      { name: "required", required: true },
      { name: "optional", required: false },
    ]);
    for (const value of ["not an object", {}, { required: null }]) {
      const result = requestFailure(await requestEncode(plan, value));
      assert.equal(result.outcome, "request-encode");
    }

    let encoded = "";
    await execute(
      createTransport({
        fetch: async (request) => {
          encoded = await request.text();
          return new Response(null, { status: 404 });
        },
      }),
      operation({ body: plan }),
      { body: { required: "present" } },
    );
    assert.equal(encoded, "required=present");
  });

  test("validates content-based urlencoded wrappers, media, and payload kinds", async () => {
    const wrapped: BodyEncoder = urlencodedBody("application/x-www-form-urlencoded", [
      {
        name: "icon",
        required: false,
        payloads: ["text", "text"],
        contentType: { kind: "selected", admitted: ["image/png", "image/jpeg"] },
      },
    ]);
    // A non-object wrapper is rejected; a contentType outside the admitted list does not select.
    for (const value of [
      { icon: "not a wrapper" },
      { icon: { body: "x", contentType: "image/gif" } },
    ]) {
      assert.equal(requestFailure(await requestEncode(wrapped, value)).outcome, "request-encode");
    }

    // A plan whose payloads list has no entry for the selected media type has no payload kind.
    const missingKind: BodyEncoder = urlencodedBody("application/x-www-form-urlencoded", [
      { name: "x", required: false, payloads: [] },
    ]);
    assert.equal(
      requestFailure(await requestEncode(missingKind, { x: "v" })).outcome,
      "request-encode",
    );

    // A text payload requires a ParamValue, and a required content field cannot be missing.
    const text: BodyEncoder = urlencodedBody("application/x-www-form-urlencoded", [
      { name: "note", required: true, payloads: ["text"] },
    ]);
    assert.equal(
      requestFailure(await requestEncode(text, { note: { deep: { x: 1 } } })).outcome,
      "request-encode",
    );
    assert.equal(requestFailure(await requestEncode(text, {})).outcome, "request-encode");
  });

  test("validates primitive top-level body plans", async () => {
    const cases: readonly (readonly [BodyEncoder, unknown])[] = [
      [jsonBody("application/json"), undefined],
      [textBody("text/plain"), 1],
      [binaryBody("application/octet-stream"), "bytes"],
      [discriminatedBody([["application/json", jsonBody("application/json")]]), "not a wrapper"],
    ];
    for (const [plan, value] of cases) {
      const result = requestFailure(await requestEncode(plan, value));
      assert.equal(result.outcome, "request-encode");
    }

    let text = "";
    await execute(
      createTransport({
        fetch: async (request) => {
          text = await request.text();
          return new Response(null, { status: 404 });
        },
      }),
      operation({ body: textBody("text/plain") }),
      { body: "plain" },
    );
    assert.equal(text, "plain");
  });
});

describe("multipart descriptor boundary", () => {
  test("accepts exact media parameters, binary sources, JSON, and filename defaults", async () => {
    let body = "";
    const result = await execute(
      createTransport({
        fetch: async (request) => {
          body = await request.text();
          return new Response(null, { status: 404 });
        },
      }),
      operation({
        body: multipartBody([
          multipartField({
            name: "selected",
            wrapper: true,
            contentType: { kind: "fixed", value: "text/plain; charset=utf-8" },
          }),
          multipartField({
            name: "files",
            repeated: true,
            payload: "binary",
            contentType: { kind: "fixed", value: "application/octet-stream" },
            filename: true,
          }),
          multipartField({
            name: "json",
            payload: "json",
            contentType: { kind: "none" },
          }),
        ]),
      }),
      {
        body: {
          selected: { body: "ok", contentType: "text/plain; charset=UTF-8" },
          files: [Uint8Array.of(1), new File(["file"], "upload.bin")],
          json: { ok: true },
        },
      },
    );

    assert.equal(result.outcome, "unmatched");
    assert.match(body, /filename="upload.bin"/u);
    assert.match(body, /\{"ok":true\}/u);
  });

  test("rejects malformed wrappers, fields, payloads, media, and filenames", async () => {
    const cases: readonly (readonly [MultipartFieldPlan, unknown])[] = [
      [multipartField(), undefined],
      [multipartField({ required: false }), null],
      [multipartField({ repeated: true }), "not an array"],
      [multipartField({ repeated: true }), [null]],
      [multipartField({ wrapper: true }), "not a wrapper"],
      [multipartField({ wrapper: true }), { contentType: "text/plain" }],
      [
        multipartField({ wrapper: true, filename: true }),
        { body: "x", contentType: "text/plain", filename: 4 },
      ],
      [multipartField({ payload: "binary" }), "not binary"],
      [multipartField({ payload: "text" }), 4],
      [multipartField({ payload: "json" }), () => undefined],
      [multipartField({ contentType: { kind: "selected", admitted: ["text/*"] } }), "x"],
      [
        multipartField({
          wrapper: true,
          contentType: { kind: "selected", admitted: ["not-media"] },
        }),
        { body: "x", contentType: "text/plain" },
      ],
      [
        multipartField({
          wrapper: true,
          contentType: { kind: "fixed", value: "text/plain" },
        }),
        { body: "x", contentType: "text/plain; charset=utf-8" },
      ],
      [
        multipartField({
          wrapper: true,
          contentType: { kind: "fixed", value: "text/plain; charset=ascii" },
        }),
        { body: "x", contentType: "text/plain; charset=utf-8" },
      ],
      // A wrapped field whose payloads list has no entry for the selected admitted index has no
      // payload kind, so the part cannot be serialized.
      [
        multipartField({
          wrapper: true,
          payloads: [],
          contentType: { kind: "selected", admitted: ["text/plain"] },
        }),
        { body: "x", contentType: "text/plain" },
      ],
    ];

    const notObject = requestFailure(await requestEncode(multipartBody([]), "not an object"));
    assert.equal(notObject.outcome, "request-encode");

    for (const [field, value] of cases) {
      const body = value === undefined ? {} : { value };
      const result = requestFailure(await requestEncode(multipartBody([field]), body));
      assert.equal(result.outcome, "request-encode");
    }
  });
});

describe("request boundary ownership", () => {
  test("rejects generated forbidden names and values but admits safe override values", async () => {
    const headerPlan = {
      location: "header" as const,
      required: true,
      serialize: serializeHeaderSimple,
      allowReserved: false,
    };
    for (const [name, value] of [
      ["Cookie", "a=b"],
      ["Proxy-Test", "blocked"],
      ["X-Method-Override", "track"],
    ]) {
      const result = requestFailure(
        await execute(createTransport({}), operation({ params: [{ ...headerPlan, name }] }), {
          header: { [name]: value },
        }),
      );
      assert.equal(result.outcome, "request-encode");
    }

    let safeValue = "";
    await execute(
      createTransport({
        fetch: async (request) => {
          safeValue = request.headers.get("x-method-override") ?? "";
          return new Response(null, { status: 404 });
        },
      }),
      operation({ params: [{ ...headerPlan, name: "X-Method-Override" }] }),
      { header: { "X-Method-Override": "PATCH" } },
    );
    assert.equal(safeValue, "PATCH");
  });

  test("maps Request construction errors and a middleware-time abort before fetch", async () => {
    const invalidInit = requestFailure(
      await execute(createTransport({}), operation({ fetchDefaults: { mode: "not-a-mode" } }), {}),
    );
    assert.equal(invalidInit.outcome, "request-encode");

    const reason = new Error("abort after hook");
    const controller = new AbortController();
    let sent = false;
    const aborted = requestFailure(
      await execute(
        createTransport({
          middleware: [
            {
              async onRequest() {
                queueMicrotask(() => controller.abort(reason));
              },
            },
          ],
          fetch: async () => {
            sent = true;
            return new Response();
          },
        }),
        operation(),
        {},
        { signal: controller.signal },
      ),
    );
    assert.equal(aborted.outcome, "aborted");
    assert.equal(aborted.reason, reason);
    assert.equal(sent, false);
  });

  test("uses global fetch with the same frozen sidecar contract", async () => {
    const originalFetch = globalThis.fetch;
    const extension = { tags: ["edge"] };
    let captured: RequestInit | undefined;
    let capturedNext: unknown;
    globalThis.fetch = async (_request, sidecar) => {
      captured = sidecar;
      capturedNext = sidecar !== undefined && "next" in sidecar ? sidecar.next : undefined;
      return new Response(null, { status: 404 });
    };
    try {
      const result = await execute(
        createTransport({}),
        operation({ fetchDefaults: { next: extension } }),
        {},
      );
      assert.equal(result.outcome, "unmatched");
    } finally {
      globalThis.fetch = originalFetch;
    }

    assert.ok(captured);
    assert.ok(Object.isFrozen(captured));
    assert.equal(capturedNext, extension);
  });
});

// The abort classifier reads the abort reason's shape, never which API produced the signal: a
// DOMException named TimeoutError is a timeout, everything else is a cancellation. That is why a
// hand-built TimeoutError classifies as a timeout, and why a polyfilled AbortSignal.timeout that
// rejects with a plain Error correctly would not.
type AbortVector = {
  readonly label: string;
  readonly timeout: boolean;
  /** A signal not yet aborted, plus the trigger that aborts it (a no-op for a timer signal). */
  readonly start: () => { readonly signal: AbortSignal; readonly abort: () => void };
};

function controllerVector(
  label: string,
  timeout: boolean,
  reason: () => readonly [unknown] | null,
): AbortVector {
  return {
    label,
    timeout,
    start: () => {
      const controller = new AbortController();
      const carried = reason();
      return {
        signal: controller.signal,
        abort: () => {
          if (carried === null) {
            controller.abort();
          } else {
            controller.abort(carried[0]);
          }
        },
      };
    },
  };
}

const ABORT_VECTORS: readonly AbortVector[] = [
  {
    label: "AbortSignal.timeout",
    timeout: true,
    // The timer fires on its own, so the trigger has nothing to do.
    start: () => ({ signal: AbortSignal.timeout(1), abort: () => {} }),
  },
  controllerVector("bare controller.abort()", false, () => null),
  controllerVector("controller.abort(new Error())", false, () => [new Error("x")]),
  controllerVector("controller.abort(a hand-built TimeoutError)", true, () => [
    new DOMException("x", "TimeoutError"),
  ]),
];

async function settled(signal: AbortSignal): Promise<AbortSignal> {
  if (!signal.aborted) {
    await new Promise<void>((resolve) => {
      signal.addEventListener("abort", () => resolve(), { once: true });
    });
  }
  return signal;
}

describe("abort and timeout classification", () => {
  for (const vector of ABORT_VECTORS) {
    test(`pre-dispatch: ${vector.label} is ${vector.timeout ? "timeout" : "aborted"}`, async () => {
      const { signal, abort } = vector.start();
      abort();
      await settled(signal);
      let sent = false;
      const failure = requestFailure(
        await execute(
          createTransport({
            fetch: async () => {
              sent = true;
              return new Response();
            },
          }),
          operation(),
          {},
          { signal },
        ),
      );

      assert.equal(sent, false);
      assert.equal(failure.outcome, vector.timeout ? "timeout" : "aborted");
      if (failure.outcome === "timeout" || failure.outcome === "aborted") {
        assert.equal(failure.reason, signal.reason);
      }
    });

    test(`mid-body-read: ${vector.label} is ${
      vector.timeout ? "response-timeout" : "response-aborted"
    }`, async () => {
      // The signal is still live at dispatch — a pre-aborted one never reaches the body read — so
      // the abort is triggered once the request is in flight and errors the body stream.
      const { signal, abort } = vector.start();
      const result = await execute(
        createTransport({
          fetch: async (request) => {
            const body = new ReadableStream<Uint8Array>({
              start(streamController) {
                request.signal.addEventListener(
                  "abort",
                  () => streamController.error(request.signal.reason),
                  { once: true },
                );
              },
            });
            abort();
            return new Response(body, { headers: { "Content-Type": "application/json" } });
          },
        }),
        operation(),
        {},
        { signal },
      );

      assert.equal(result.outcome, vector.timeout ? "response-timeout" : "response-aborted");
      if (result.outcome === "response-timeout" || result.outcome === "response-aborted") {
        assert.equal(result.reason, signal.reason);
      }
    });
  }
});
