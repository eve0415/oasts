import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { ApiError } from "../result.ts";
import { isDocumented, responseFailure } from "./result-narrowing.ts";
import {
  createTransport,
  execute,
  executeOrThrow,
  type ExecutionResult,
  type OperationDescriptor,
  type ResponsePlan,
} from "../transport.ts";

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function responsePlan(overrides: Partial<ResponsePlan> = {}): ResponsePlan {
  return {
    match: "200",
    kind: "exact",
    status: 200,
    bodyless: false,
    media: [["application/json", "json"]],
    hasContentTypeDiscriminant: false,
    ...overrides,
  };
}

function operation(overrides: Partial<OperationDescriptor> = {}): OperationDescriptor {
  return {
    operationId: "responseOperation",
    method: "GET",
    path: [[{ kind: "literal", text: "/response" }]],
    params: [],
    body: null,
    accept: "application/json",
    credentialHeaders: ["Authorization"],
    security: null,
    responses: [responsePlan()],
    baseUrl: { kind: "literal", value: "https://example.com/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

async function callWith(response: Response, descriptor = operation()): Promise<ExecutionResult> {
  return execute(createTransport({ fetch: async () => response }), descriptor, {});
}

describe("response matching and decoding", () => {
  test("matches exact, then range, then default, then unmatched", async () => {
    const descriptor = operation({
      responses: [
        responsePlan({
          match: "default",
          kind: "default",
          status: null,
          media: [["text/plain", "text"]],
        }),
        responsePlan({
          match: "2XX",
          kind: "range",
          status: null,
          media: [["text/plain", "text"]],
        }),
        responsePlan({ match: "200", media: [["text/plain", "text"]] }),
      ],
    });

    const exact = await callWith(
      new Response("exact", { status: 200, headers: { "Content-Type": "text/plain" } }),
      descriptor,
    );
    const range = await callWith(
      new Response("range", { status: 201, headers: { "Content-Type": "text/plain" } }),
      descriptor,
    );
    const fallback = await callWith(
      new Response("default", { status: 418, headers: { "Content-Type": "text/plain" } }),
      descriptor,
    );
    const unmatched = await callWith(
      new Response("unknown", { status: 418, headers: { "Content-Type": "text/plain" } }),
      operation({ responses: [responsePlan({ media: [["text/plain", "text"]] })] }),
    );

    // An exact key is keyed by its numeric status, a range or `default` key by its own literal.
    assert.equal(exact.outcome, 200);
    assert.equal(exact.ok, true);
    assert.equal(isDocumented(exact) && exact.ok ? exact.data : undefined, "exact");
    assert.equal(range.outcome, "2XX");
    assert.equal(range.ok, true);
    assert.equal(fallback.outcome, "default");
    assert.equal(fallback.ok, false);
    assert.equal(isDocumented(fallback) && !fallback.ok ? fallback.error : undefined, "default");
    assert.equal(unmatched.outcome, "unmatched");
  });

  test("selects response media exact, then type range, then any range", async () => {
    const result = await callWith(
      new Response("exact decoder", {
        headers: { "Content-Type": "Application/Problem+JSON; Charset=UTF-8" },
      }),
      operation({
        responses: [
          responsePlan({
            media: [
              ["*/*", "binary"],
              ["application/*", "json"],
              ["application/problem+json", "text"],
            ],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result));
    assert.equal(result.ok, true);
    if (isDocumented(result) && result.ok) {
      assert.equal(result.data, "exact decoder");
      assert.equal(result.contentType, "application/problem+json");
      assert.equal(
        result.meta.headers.get("content-type"),
        "Application/Problem+JSON; Charset=UTF-8",
      );
    }
  });

  test("returns data for 2xx and error for documented non-2xx responses", async () => {
    const success = await callWith(
      new Response('{"id":1}', { headers: { "Content-Type": "application/json" } }),
    );
    const error = await callWith(
      new Response('{"message":"bad"}', {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
      operation({ responses: [responsePlan({ match: "400", status: 400 })] }),
    );

    assert.deepEqual(isDocumented(success) && success.ok ? success.data : undefined, {
      id: 1,
    });
    assert.deepEqual(isDocumented(error) && !error.ok ? error.error : undefined, {
      message: "bad",
    });
  });

  test("decodes unsafe integer tokens losslessly only on a marked JSON body", async () => {
    const body =
      '{"id":12345678901234567890,"nested":[-12345678901234567890],"safe":42,"float":9007199254740992.5,"other":9007199254740993}';
    const marked = await callWith(
      new Response(body, { headers: { "Content-Type": "application/json" } }),
      operation({
        responses: [
          responsePlan({
            media: [
              ["application/json", { json: "int64", revive: (_value, lossless) => lossless }],
            ],
          }),
        ],
      }),
    );
    const ordinary = await callWith(
      new Response(body, { headers: { "Content-Type": "application/json" } }),
    );

    assert.ok(isDocumented(marked) && marked.ok);
    if (isDocumented(marked) && marked.ok) {
      assert.deepEqual(marked.data, {
        id: 12345678901234567890n,
        nested: [-12345678901234567890n],
        safe: 42,
        float: Number("9007199254740992.5"),
        other: 9007199254740993n,
      });
    }
    assert.ok(isDocumented(ordinary) && ordinary.ok);
    if (isDocumented(ordinary) && ordinary.ok) {
      const data = ordinary.data;
      assert.equal(isRecord(data) ? typeof data.id : "missing", "number");
    }
  });

  test("keeps unrelated unsafe integer fields on their declared number surface", async () => {
    const result = await callWith(
      new Response('{"id":9007199254740993,"amount":9007199254740995}', {
        headers: { "Content-Type": "application/json" },
      }),
      operation({
        responses: [
          responsePlan({
            media: [
              [
                "application/json",
                {
                  json: "int64",
                  revive: (value, lossless) => {
                    if (!isRecord(value) || !isRecord(lossless)) {
                      return value;
                    }
                    return { ...value, id: lossless.id };
                  },
                },
              ],
            ],
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result) && result.ok);
    if (isDocumented(result) && result.ok) {
      assert.deepEqual(result.data, {
        id: 9_007_199_254_740_993n,
        amount: Number("9007199254740995"),
      });
    }
  });

  test("accepts null and zero-byte bodies on no-payload branches", async () => {
    const descriptor = operation({ responses: [responsePlan({ media: [] })] });
    const nullBody = await callWith(new Response(null), descriptor);
    const zeroBytes = await callWith(new Response(""), descriptor);

    assert.equal(isDocumented(nullBody) && nullBody.ok ? nullBody.data : "bad", undefined);
    assert.equal(isDocumented(zeroBytes) && zeroBytes.ok ? zeroBytes.data : "bad", undefined);
  });

  test("decodes range, any-range, and binary response media", async () => {
    const range = await callWith(
      new Response("range", { headers: { "Content-Type": "application/xml" } }),
      operation({
        responses: [
          responsePlan({
            media: [["application/*", "text"]],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );
    const anyRange = await callWith(
      new Response(Uint8Array.of(3, 4), { headers: { "Content-Type": "image/png" } }),
      operation({
        responses: [responsePlan({ media: [["*/*", "binary"]], hasContentTypeDiscriminant: true })],
      }),
    );

    assert.ok(isDocumented(range));
    assert.equal(isDocumented(range) ? range.contentType : undefined, "application/*");
    assert.equal(isDocumented(range) && range.ok ? range.data : undefined, "range");
    assert.ok(isDocumented(anyRange));
    if (isDocumented(anyRange) && anyRange.ok) {
      assert.equal(anyRange.contentType, "*/*");
      assert.deepEqual(
        new Uint8Array(anyRange.data instanceof ArrayBuffer ? anyRange.data : []),
        Uint8Array.of(3, 4),
      );
    }
  });

  test("carries declared wildcard discriminants on non-2xx branches", async () => {
    const result = await callWith(
      new Response("error", {
        status: 400,
        headers: { "Content-Type": "text/plain" },
      }),
      operation({
        responses: [
          responsePlan({
            match: "400",
            status: 400,
            media: [["text/*", "text"]],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );

    assert.ok(isDocumented(result));
    if (isDocumented(result) && !result.ok) {
      assert.equal(result.error, "error");
      assert.equal(result.contentType, "text/*");
    }
  });
});

describe("response media specificity", () => {
  const tiers = operation({
    responses: [
      responsePlan({
        media: [
          ["application/json;stream=watch", "json"],
          ["application/json", "json"],
          ["application/*", "text"],
          ["*/*", "binary"],
        ],
        hasContentTypeDiscriminant: true,
      }),
    ],
  });

  test("selects each tier by the most specific declared key", async () => {
    const watch = await callWith(
      new Response('{"type":"ADDED"}', {
        headers: { "Content-Type": "application/json;stream=watch" },
      }),
      tiers,
    );
    const bare = await callWith(
      new Response('{"id":1}', { headers: { "Content-Type": "application/json" } }),
      tiers,
    );
    const range = await callWith(
      new Response("range", { headers: { "Content-Type": "application/xml" } }),
      tiers,
    );
    const any = await callWith(
      new Response(Uint8Array.of(7), { headers: { "Content-Type": "image/png" } }),
      tiers,
    );

    assert.equal(
      isDocumented(watch) ? watch.contentType : undefined,
      "application/json;stream=watch",
    );
    assert.deepEqual(isDocumented(watch) && watch.ok ? watch.data : undefined, {
      type: "ADDED",
    });
    assert.equal(isDocumented(bare) ? bare.contentType : undefined, "application/json");
    assert.deepEqual(isDocumented(bare) && bare.ok ? bare.data : undefined, { id: 1 });
    assert.equal(isDocumented(range) ? range.contentType : undefined, "application/*");
    assert.equal(isDocumented(range) && range.ok ? range.data : undefined, "range");
    assert.equal(isDocumented(any) ? any.contentType : undefined, "*/*");
  });

  test("matches charset case-insensitively and returns the declared literal", async () => {
    const result = await callWith(
      new Response('{"id":2}', {
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }),
      operation({
        responses: [
          responsePlan({
            media: [
              ["application/json;charset=UTF-8", "json"],
              ["application/json", "json"],
            ],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );
    assert.equal(
      isDocumented(result) ? result.contentType : undefined,
      "application/json;charset=UTF-8",
    );
  });

  test("falls back to the bare arm when a parameter value differs", async () => {
    const result = await callWith(
      new Response('{"id":3}', {
        headers: { "Content-Type": "application/json;stream=other" },
      }),
      operation({
        responses: [
          responsePlan({
            media: [
              ["application/json;stream=watch", "json"],
              ["application/json", "json"],
            ],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );
    assert.equal(isDocumented(result) ? result.contentType : undefined, "application/json");
  });

  test("breaks specificity ties between equal keys by canonical byte order", async () => {
    const declaredOrders = [
      [
        ["application/json;b=2", "json"],
        ["application/json;a=1", "json"],
      ],
      [
        ["application/json;a=1", "json"],
        ["application/json;b=2", "json"],
      ],
    ] satisfies ResponsePlan["media"][];
    for (const media of declaredOrders) {
      const result = await callWith(
        new Response('{"id":4}', {
          headers: { "Content-Type": "application/json;a=1;b=2" },
        }),
        operation({
          responses: [responsePlan({ media, hasContentTypeDiscriminant: true })],
        }),
      );
      assert.equal(isDocumented(result) ? result.contentType : undefined, "application/json;a=1");
    }
  });

  test("skips malformed declared keys", async () => {
    const result = await callWith(
      new Response('{"id":6}', { headers: { "Content-Type": "application/json" } }),
      operation({
        responses: [
          responsePlan({
            media: [
              ["", "json"],
              ["application/json", "json"],
            ],
            hasContentTypeDiscriminant: true,
          }),
        ],
      }),
    );
    assert.equal(isDocumented(result) ? result.contentType : undefined, "application/json");
  });

  test("fails to decode when no declared key applies", async () => {
    for (const media of [
      [["text/*;charset=utf-8", "text"]], // a range key never carries parameters
      [["*/*;q=1", "binary"]], // an any key never carries parameters
      [["*/json", "json"]], // a wildcard type is not a concrete essence
      [["application/json", "json"]], // essence mismatch against the response
    ] satisfies ResponsePlan["media"][]) {
      const result = responseFailure(
        await callWith(
          new Response("body", { headers: { "Content-Type": "text/plain" } }),
          operation({
            responses: [responsePlan({ media, hasContentTypeDiscriminant: true })],
          }),
        ),
      );
      assert.equal(result.outcome, "response-decode");
    }
  });
});

describe("response decode failures", () => {
  test("maps malformed JSON and preserves the decode cause", async () => {
    const result = responseFailure(
      await callWith(new Response("{", { headers: { "Content-Type": "application/json" } })),
    );

    assert.equal(result.match, 200);
    assert.equal(result.outcome, "response-decode");
    if (result.outcome === "response-decode") {
      assert.ok(result.cause instanceof SyntaxError);
    }
  });

  test("rejects bytes on static bodyless and no-payload branches", async () => {
    const staticBodyless = responseFailure(
      await callWith(
        new Response("unexpected"),
        operation({ responses: [responsePlan({ bodyless: true, media: [] })] }),
      ),
    );
    const noPayload = responseFailure(
      await callWith(
        new Response("unexpected"),
        operation({ responses: [responsePlan({ media: [] })] }),
      ),
    );

    assert.equal(staticBodyless.outcome, "response-decode");
    assert.equal(noPayload.outcome, "response-decode");
  });

  test("rejects dynamic bodyless status with declared content and names status and key", async () => {
    for (const status of [204, 205, 304]) {
      const result = responseFailure(
        await callWith(
          new Response(null, { status }),
          operation({
            responses: [
              responsePlan({
                match: status === 304 ? "default" : "2XX",
                kind: status === 304 ? "default" : "range",
                status: null,
                media: [["application/json", "json"]],
              }),
            ],
          }),
        ),
      );

      assert.equal(result.outcome, "response-decode");
      if (result.outcome === "response-decode") {
        assert.match(result.message, new RegExp(String(status), "u"));
        assert.match(result.message, status === 304 ? /default/u : /2XX/u);
      }
    }
  });

  test("does not guess declared media when Content-Type is missing or unmatched", async () => {
    for (const response of [
      new Response('{"ok":true}'),
      new Response('{"ok":true}', { headers: { "Content-Type": "text/plain" } }),
    ]) {
      const result = responseFailure(await callWith(response));
      assert.equal(result.outcome, "response-decode");
    }
  });

  test("maps an abort during body read to response-stage aborted", async () => {
    const reason = { code: "read-stop" };
    const controller = new AbortController();
    const result = await execute(
      createTransport({
        middleware: [
          {
            onResponse() {
              controller.abort(reason);
            },
          },
        ],
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
          return new Response(body, { headers: { "Content-Type": "application/json" } });
        },
      }),
      operation(),
      {},
      { signal: controller.signal },
    );

    const failure = responseFailure(result);
    assert.equal(failure.outcome, "response-aborted");
    assert.equal(failure.reason, reason);
    assert.equal(failure.status, 200);
    assert.equal(failure.match, 200);
  });

  test("maps a non-abort body stream error to response-decode", async () => {
    const cause = new Error("stream failed");
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(cause);
      },
    });
    const failure = responseFailure(
      await callWith(new Response(body, { headers: { "Content-Type": "application/json" } })),
    );

    assert.equal(failure.outcome, "response-decode");
    if (failure.outcome === "response-decode") {
      assert.equal(failure.cause, cause);
    }
  });

  test("accepts a zero-byte static bodyless branch", async () => {
    const result = await callWith(
      new Response(""),
      operation({ responses: [responsePlan({ bodyless: true, media: [] })] }),
    );

    assert.ok(isDocumented(result));
    assert.equal(isDocumented(result) && result.ok ? result.data : "bad", undefined);
  });

  test("rejects malformed, wildcard, missing, and malformed-plan response media", async () => {
    const missing = new Response(Uint8Array.of(1));
    const malformed = new Response("x", { headers: { "Content-Type": "not-media" } });
    const wildcard = new Response("x", { headers: { "Content-Type": "*/*" } });
    const malformedPlan = new Response("x", { headers: { "Content-Type": "text/plain" } });
    for (const [response, descriptor] of [
      [missing, operation()],
      [malformed, operation()],
      [wildcard, operation()],
      [malformedPlan, operation({ responses: [responsePlan({ media: [["not-media", "text"]] })] })],
    ] as const) {
      const failure = responseFailure(await callWith(response, descriptor));
      assert.equal(failure.outcome, "response-decode");
    }
  });
});

describe("unknown HTTP errors", () => {
  test("constructs empty, JSON, text, and binary variants one-to-one", async () => {
    const descriptor = operation({ responses: [] });
    const empty = await callWith(
      new Response(null, { status: 404, headers: { "Content-Type": "application/json" } }),
      descriptor,
    );
    const json = await callWith(
      new Response('{"code":7}', {
        status: 404,
        headers: { "Content-Type": "application/problem+json" },
      }),
      descriptor,
    );
    const text = await callWith(
      new Response("missing", {
        status: 404,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }),
      descriptor,
    );
    const bytes = Uint8Array.of(0, 255);
    const binary = await callWith(
      new Response(bytes, { status: 404, headers: { "Content-Type": "image/png" } }),
      descriptor,
    );

    assert.deepEqual(empty.outcome === "unmatched" ? empty.error : undefined, {
      kind: "empty",
      contentType: "application/json",
      body: undefined,
    });
    assert.deepEqual(json.outcome === "unmatched" ? json.error : undefined, {
      kind: "json",
      contentType: "application/problem+json",
      body: { code: 7 },
    });
    assert.deepEqual(text.outcome === "unmatched" ? text.error : undefined, {
      kind: "text",
      contentType: "application/x-www-form-urlencoded",
      body: "missing",
    });
    assert.equal(binary.outcome, "unmatched");
    if (binary.outcome === "unmatched") {
      // UnknownHttpError keeps its own `kind`: a body-representation tag, not a result tier.
      assert.equal(binary.error.kind, "binary");
      if (binary.error.kind === "binary") {
        assert.equal(binary.error.contentType, "image/png");
        assert.deepEqual(new Uint8Array(binary.error.body), bytes);
      }
    }
  });

  test("classifies exact JSON, text types, and missing media independently", async () => {
    const descriptor = operation({ responses: [] });
    const json = await callWith(
      new Response('{"exact":true}', {
        status: 404,
        headers: { "Content-Type": "application/json" },
      }),
      descriptor,
    );
    const text = await callWith(
      new Response("plain", { status: 404, headers: { "Content-Type": "text/plain" } }),
      descriptor,
    );
    const missing = await callWith(new Response(Uint8Array.of(8), { status: 404 }), descriptor);

    assert.equal(json.outcome === "unmatched" ? json.error.kind : undefined, "json");
    assert.equal(text.outcome === "unmatched" ? text.error.kind : undefined, "text");
    assert.equal(missing.outcome === "unmatched" ? missing.error.kind : undefined, "binary");
  });

  test("turns malformed unmatched JSON into response-decode with a null match", async () => {
    const failure = responseFailure(
      await callWith(
        new Response("{", {
          status: 404,
          headers: { "Content-Type": "application/json" },
        }),
        operation({ responses: [] }),
      ),
    );

    assert.equal(failure.match, null);
    assert.equal(failure.outcome, "response-decode");
  });
});

describe("response middleware and metadata", () => {
  test("chains replacements and void mutations exactly once with shared context", async () => {
    const events: string[] = [];
    const contexts: object[] = [];
    const fetched = new Response("ignored", {
      status: 202,
      headers: { "Content-Type": "text/plain" },
    });
    Object.defineProperty(fetched, "url", { value: "https://redirected.example/final" });
    const result = await execute(
      createTransport({
        middleware: [
          {
            onRequest(_request, context) {
              contexts.push(context);
            },
            onResponse(_response, context) {
              events.push("first");
              contexts.push(context);
              return new Response('{"source":"replacement"}', {
                status: 200,
                headers: { "Content-Type": "application/json", "X-Chain": "replacement" },
              });
            },
          },
          {
            onResponse(response, context) {
              events.push("second");
              contexts.push(context);
              response.headers.set("X-Void", "visible");
            },
          },
          {
            onResponse(response, context) {
              events.push(`${response.headers.get("x-chain")}/${response.headers.get("x-void")}`);
              contexts.push(context);
            },
          },
        ],
        fetch: async () => fetched,
      }),
      operation(),
      {},
    );

    assert.deepEqual(events, ["first", "second", "replacement/visible"]);
    assert.ok(contexts.every((context) => context === contexts[0]));
    assert.ok(isDocumented(result));
    if (isDocumented(result)) {
      assert.equal(result.meta.url, "https://redirected.example/final");
      assert.equal(result.meta.headers.get("x-void"), "visible");
    }
  });

  test("maps consumed bodies and thrown hooks to response-middleware", async () => {
    const thrown = new Error("response hook failed");
    const consumed = responseFailure(
      await execute(
        createTransport({
          middleware: [
            {
              async onResponse(response) {
                await response.text();
              },
            },
          ],
          fetch: async () =>
            new Response('{"ok":true}', { headers: { "Content-Type": "application/json" } }),
        }),
        operation(),
        {},
      ),
    );
    const hookError = responseFailure(
      await execute(
        createTransport({
          middleware: [
            {
              onResponse() {
                throw thrown;
              },
            },
          ],
          fetch: async () => new Response(null, { status: 202, headers: { "X-Live": "yes" } }),
        }),
        operation(),
        {},
      ),
    );

    assert.equal(consumed.outcome, "response-middleware");
    assert.equal(consumed.status, 200);
    assert.equal(hookError.outcome, "response-middleware");
    assert.equal(hookError.status, 202);
    assert.equal(hookError.meta.headers.get("x-live"), "yes");
    if (hookError.outcome === "response-middleware") {
      assert.equal(hookError.cause, thrown);
    }
  });

  test("snapshots final headers and falls back to the request provenance URL", async () => {
    const live = new Response('{"ok":true}', {
      headers: { "Content-Type": "application/json", "X-Live": "before" },
    });
    const result = await callWith(live);
    live.headers.set("X-Live", "after");

    assert.ok(isDocumented(result));
    if (isDocumented(result)) {
      assert.equal(result.meta.url, "https://example.com/api/response");
      assert.equal(result.meta.headers.get("x-live"), "before");
      assert.notEqual(result.meta.headers, live.headers);
    }
  });
});

describe("executeOrThrow", () => {
  test("resolves a { data, meta } envelope and throws ApiError with the complete failed result", async () => {
    const { data, meta } = await executeOrThrow(
      createTransport({
        fetch: async () =>
          new Response('{"id":9}', { headers: { "Content-Type": "application/json" } }),
      }),
      operation(),
      {},
    );
    assert.deepEqual(data, { id: 9 });
    assert.equal(meta.status, 200);

    await assert.rejects(
      executeOrThrow(
        createTransport({ fetch: async () => new Response("missing", { status: 404 }) }),
        operation({ responses: [] }),
        {},
      ),
      (error: unknown) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.result.outcome, "unmatched");
        assert.equal(error.result.ok, false);
        assert.equal(error.result.status, 404);
        const preserved = error.result;
        assert.equal(error.result, preserved);
        return true;
      },
    );
  });
});
