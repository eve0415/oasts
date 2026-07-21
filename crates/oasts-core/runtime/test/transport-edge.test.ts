import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  createTransport,
  execute,
  type BodyPlan,
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
    security: [],
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

function requestFailure(result: ExecutionResult): ExecutionResult & {
  readonly kind: "request-failure";
} {
  assert.equal(result.kind, "request-failure");
  if (result.kind !== "request-failure") {
    throw new Error("expected request failure");
  }
  return result;
}

async function requestEncode(body: BodyPlan, value: unknown): Promise<ExecutionResult> {
  return execute(
    createTransport({ fetch: async () => new Response(null, { status: 404 }) }),
    operation({ body }),
    { body: value },
  );
}

describe("descriptor boundary validation", () => {
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
        { value: { nested: null } },
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
        { value: "x" },
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
        { value: "x" },
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
      assert.equal(result.error.kind, "request-encode");
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
      { empty: "ignored", value: "two" },
    );

    assert.equal(result.kind, "unmatched-response");
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
      { filter: { state: "open" }, ids: [1, 2] },
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

    assert.equal(relative.error.kind, "request-encode");
    assert.equal(placeholder.error.kind, "request-encode");
  });

  test("validates form-urlencoded body shape and fields", async () => {
    const plan: BodyPlan = {
      kind: "form-urlencoded",
      contentType: "application/x-www-form-urlencoded",
      fields: [
        { name: "required", required: true },
        { name: "optional", required: false },
      ],
    };
    for (const value of ["not an object", {}, { required: null }]) {
      const result = requestFailure(await requestEncode(plan, value));
      assert.equal(result.error.kind, "request-encode");
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

  test("validates primitive top-level body plans", async () => {
    const cases: readonly (readonly [BodyPlan, unknown])[] = [
      [{ kind: "json", contentType: "application/json" }, undefined],
      [{ kind: "text", contentType: "text/plain" }, 1],
      [{ kind: "binary", contentType: "application/octet-stream" }, "bytes"],
      [
        {
          kind: "content-discriminated",
          arms: [["application/json", { kind: "json", contentType: "application/json" }]],
        },
        "not a wrapper",
      ],
    ];
    for (const [plan, value] of cases) {
      const result = requestFailure(await requestEncode(plan, value));
      assert.equal(result.error.kind, "request-encode");
    }

    let text = "";
    await execute(
      createTransport({
        fetch: async (request) => {
          text = await request.text();
          return new Response(null, { status: 404 });
        },
      }),
      operation({ body: { kind: "text", contentType: "text/plain" } }),
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
        body: {
          kind: "multipart",
          fields: [
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
          ],
        },
      }),
      {
        body: {
          selected: { body: "ok", contentType: "text/plain; charset=UTF-8" },
          files: [Uint8Array.of(1), new File(["file"], "upload.bin")],
          json: { ok: true },
        },
      },
    );

    assert.equal(result.kind, "unmatched-response");
    assert.match(body, /filename="upload.bin"/u);
    assert.match(body, /\{"ok":true\}/u);
  });

  test("rejects malformed wrappers, fields, payloads, media, headers, and filenames", async () => {
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
      [multipartField({ wrapper: true }), { body: "x", contentType: "text/plain", headers: "bad" }],
      [
        multipartField({ wrapper: true }),
        { body: "x", contentType: "text/plain", headers: { "X-Part": 4 } },
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
    ];

    const notObject = requestFailure(
      await requestEncode({ kind: "multipart", fields: [] }, "not an object"),
    );
    assert.equal(notObject.error.kind, "request-encode");

    for (const [field, value] of cases) {
      const body = value === undefined ? {} : { value };
      const result = requestFailure(
        await requestEncode({ kind: "multipart", fields: [field] }, body),
      );
      assert.equal(result.error.kind, "request-encode");
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
          [name]: value,
        }),
      );
      assert.equal(result.error.kind, "request-encode");
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
      { "X-Method-Override": "PATCH" },
    );
    assert.equal(safeValue, "PATCH");
  });

  test("maps Request construction errors and a middleware-time abort before fetch", async () => {
    const invalidInit = requestFailure(
      await execute(createTransport({}), operation({ fetchDefaults: { mode: "not-a-mode" } }), {}),
    );
    assert.equal(invalidInit.error.kind, "request-encode");

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
    assert.deepEqual(aborted.error, { kind: "aborted", reason });
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
      assert.equal(result.kind, "unmatched-response");
    } finally {
      globalThis.fetch = originalFetch;
    }

    assert.ok(captured);
    assert.ok(Object.isFrozen(captured));
    assert.equal(capturedNext, extension);
  });
});
