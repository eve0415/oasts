import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  createTransport,
  execute,
  type ExecutionResult,
  type OperationDescriptor,
} from "../transport.ts";
import {
  serializeHeaderSimple,
  serializePathSimple,
  serializeQueryFormExplode,
} from "../serialize.ts";

function operation(overrides: Partial<OperationDescriptor> = {}): OperationDescriptor {
  return {
    operationId: "testOperation",
    method: "GET",
    path: [[{ kind: "literal", text: "/resource" }]],
    params: [],
    body: null,
    accept: null,
    credentialHeaders: ["Authorization"],
    responses: [],
    baseUrl: { kind: "literal", value: "https://descriptor.example/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

function requestFailure(result: ExecutionResult | Response): ExecutionResult & {
  readonly kind: "request-failure";
} {
  assert.ok(!(result instanceof Response));
  assert.equal(result.kind, "request-failure");
  if (result.kind !== "request-failure") {
    throw new Error("expected a request failure");
  }
  return result;
}

describe("request serialization and fetch contract", () => {
  test("serializes parameters and preserves operation-owned request fields", async () => {
    let capturedRequest: Request | undefined;
    let capturedSidecar: Readonly<Record<string, unknown>> | undefined;
    const next = { revalidate: 60 };
    const transport = createTransport({
      baseUrl: "https://override.example/root/",
      headers: { "X-Layer": "transport", "X-Transport": "yes" },
      credentials: "include",
      fetch: async (request, sidecar) => {
        capturedRequest = request;
        capturedSidecar = sidecar;
        return new Response(null, { status: 200 });
      },
    });

    await execute(
      transport,
      operation({
        method: "POST",
        path: [[{ kind: "literal", text: "/pets/" }], [{ kind: "param", name: "petId" }]],
        params: [
          {
            name: "petId",
            location: "path",
            required: true,
            serialize: serializePathSimple,
            allowReserved: false,
          },
          {
            name: "tag",
            location: "query",
            required: false,
            serialize: serializeQueryFormExplode,
            allowReserved: false,
          },
          {
            name: "X-Layer",
            location: "header",
            required: true,
            serialize: serializeHeaderSimple,
            allowReserved: false,
          },
        ],
        body: { kind: "json", contentType: "application/json" },
        accept: "application/json, text/*",
        fetchDefaults: { credentials: "same-origin", redirect: "follow" },
      }),
      {
        petId: "a/b",
        tag: ["red", "blue"],
        "X-Layer": "parameter",
        body: { name: "Ada" },
      },
      {
        headers: { "x-layer": "call", "X-Call": "yes" },
        fetchOptions: {
          method: "DELETE",
          body: "caller body",
          headers: { Accept: "caller" },
          credentials: "omit",
          redirect: "manual",
          next,
        },
      },
    );

    assert.ok(capturedRequest);
    assert.equal(capturedRequest.method, "POST");
    assert.equal(capturedRequest.url, "https://override.example/root/pets/a%2Fb?tag=red&tag=blue");
    assert.equal(capturedRequest.credentials, "omit");
    assert.equal(capturedRequest.redirect, "manual");
    assert.equal(capturedRequest.headers.get("x-layer"), "parameter");
    assert.equal(capturedRequest.headers.get("x-transport"), "yes");
    assert.equal(capturedRequest.headers.get("x-call"), "yes");
    assert.equal(capturedRequest.headers.get("content-type"), "application/json");
    assert.equal(capturedRequest.headers.get("accept"), "application/json, text/*");
    assert.deepEqual(await capturedRequest.json(), { name: "Ada" });
    assert.ok(capturedSidecar);
    assert.ok(Object.isFrozen(capturedSidecar));
    assert.equal(capturedSidecar.next, next);
    assert.equal(capturedSidecar.method, "DELETE");
    assert.equal(capturedSidecar.body, "caller body");
  });

  test("resolves server templates with transport variable overrides", async () => {
    let url = "";
    const transport = createTransport({
      serverVariables: { region: "west" },
      fetch: async (request) => {
        url = request.url;
        return new Response();
      },
    });

    await execute(
      transport,
      operation({
        baseUrl: {
          kind: "server",
          index: 0,
          servers: [
            {
              url: "https://{region}.example/{version}",
              variables: [
                ["region", "east"],
                ["version", "v1"],
              ],
            },
          ],
        },
      }),
      {},
    );

    assert.equal(url, "https://west.example/v1/resource");
  });

  test("serializes form-urlencoded and binary bodies", async () => {
    const requests: Request[] = [];
    const transport = createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response();
      },
    });

    await execute(
      transport,
      operation({
        method: "POST",
        body: {
          kind: "form-urlencoded",
          contentType: "application/x-www-form-urlencoded",
          fields: [
            { name: "name", required: true },
            { name: "tag", required: false, explode: true },
          ],
        },
      }),
      { body: { name: "A B", tag: ["one", "two"] } },
    );
    const bytes = Uint8Array.of(0, 1, 255);
    await execute(
      transport,
      operation({
        method: "POST",
        body: { kind: "binary", contentType: "application/octet-stream" },
      }),
      { body: bytes },
    );

    assert.equal(await requests[0].text(), "name=A%20B&tag=one&tag=two");
    assert.deepEqual(new Uint8Array(await requests[1].arrayBuffer()), bytes);
  });

  test("expands multipart wrappers and repeated fields in plan order", async () => {
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response();
      },
    });

    await execute(
      transport,
      operation({
        method: "POST",
        body: {
          kind: "multipart",
          fields: [
            {
              name: "note",
              required: true,
              repeated: false,
              wrapper: true,
              payload: "text",
              contentType: { kind: "selected", admitted: ["text/*"] },
              filename: true,
              cte: "8bit",
            },
            {
              name: "tags",
              required: true,
              repeated: true,
              wrapper: false,
              payload: "text",
              contentType: { kind: "fixed", value: "text/plain" },
              filename: false,
            },
            {
              name: "optional",
              required: false,
              repeated: false,
              wrapper: false,
              payload: "text",
              contentType: { kind: "none" },
              filename: false,
            },
          ],
        },
      }),
      {
        body: {
          note: {
            body: "héllo",
            contentType: "Text/Plain; Charset=UTF-8",
            headers: { "X-Part": "yes" },
            filename: "note.txt",
          },
          tags: ["one", "two"],
        },
      },
    );

    assert.ok(captured);
    assert.equal(
      captured.headers.get("content-type")?.startsWith("multipart/form-data; boundary=oxb-"),
      true,
    );
    const body = await captured.text();
    assert.match(body, /name="note"; filename="note.txt"/u);
    assert.match(body, /Content-Type: text\/plain; charset=utf-8/u);
    assert.match(body, /X-Part: yes/u);
    assert.match(body, /Content-Transfer-Encoding: 8bit/u);
    assert.equal(body.match(/name="tags"/gu)?.length, 2);
    assert.doesNotMatch(body, /name="optional"/u);
  });

  test("selects content-discriminated request arms by media tier", async () => {
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response();
      },
    });

    await execute(
      transport,
      operation({
        method: "POST",
        body: {
          kind: "content-discriminated",
          arms: [
            ["application/*", { kind: "json", contentType: "application/json" }],
            ["*/*", { kind: "text", contentType: "text/plain" }],
          ],
        },
      }),
      { body: { contentType: "Application/Problem+JSON; Charset=UTF-8", body: { code: 4 } } },
    );

    assert.ok(captured);
    assert.equal(captured.headers.get("content-type"), "application/problem+json; charset=utf-8");
    assert.deepEqual(await captured.json(), { code: 4 });
  });
});

describe("request failures", () => {
  test("returns request-encode when no absolute base URL resolves", async () => {
    const transport = createTransport({});
    const result = requestFailure(
      await execute(transport, operation({ baseUrl: { kind: "runtime" } }), {}),
    );

    assert.equal(result.error.kind, "request-encode");
    assert.match(result.error.kind === "request-encode" ? result.error.message : "", /base URL/u);
  });

  test("returns request-encode for unresolved server state", async () => {
    const result = requestFailure(
      await execute(
        createTransport({}),
        operation({
          baseUrl: { kind: "server", index: 1, servers: [] },
        }),
        {},
      ),
    );

    assert.equal(result.error.kind, "request-encode");
  });

  test("returns request-encode for missing, malformed, range, or unmatched content selections", async () => {
    const descriptor = operation({
      method: "POST",
      body: {
        kind: "content-discriminated",
        arms: [["application/json", { kind: "json", contentType: "application/json" }]],
      },
    });
    for (const body of [
      { body: {} },
      { contentType: "bad", body: {} },
      { contentType: "application/*", body: {} },
      { contentType: "text/plain", body: {} },
    ]) {
      const result = requestFailure(await execute(createTransport({}), descriptor, { body }));
      assert.equal(result.error.kind, "request-encode");
    }
  });

  test("rejects operation-owned and credential headers case-insensitively", async () => {
    const cases: readonly (readonly [HeadersInit, OperationDescriptor])[] = [
      [{ "content-TYPE": "text/plain" }, operation()],
      [{ aCcEpT: "text/plain" }, operation({ accept: "application/json" })],
      [{ "X-Api-Key": "secret" }, operation({ credentialHeaders: ["x-api-key"] })],
    ];

    for (const [headers, descriptor] of cases) {
      const result = requestFailure(
        await execute(createTransport({}), descriptor, {}, { headers }),
      );
      assert.equal(result.error.kind, "request-encode");
    }
  });

  test("rejects reserved transport defaults only once the operation is known", async () => {
    const result = requestFailure(
      await execute(
        createTransport({ headers: { Accept: "text/plain" } }),
        operation({ accept: "application/json" }),
        {},
      ),
    );

    assert.equal(result.error.kind, "request-encode");
  });

  test("maps multipart present-null and CTE violations to request-encode", async () => {
    const field = {
      name: "note",
      required: true,
      repeated: false,
      wrapper: false,
      payload: "text" as const,
      contentType: { kind: "fixed" as const, value: "text/plain" },
      filename: false,
      cte: "7bit" as const,
    };
    const descriptor = operation({ method: "POST", body: { kind: "multipart", fields: [field] } });

    for (const body of [{ note: null }, { note: "é" }]) {
      const result = requestFailure(await execute(createTransport({}), descriptor, { body }));
      assert.equal(result.error.kind, "request-encode");
    }
  });

  test("validates caller-supplied multipart Content-Transfer-Encoding", async () => {
    const descriptor = operation({
      method: "POST",
      body: {
        kind: "multipart",
        fields: [
          {
            name: "note",
            required: true,
            repeated: false,
            wrapper: true,
            payload: "text",
            contentType: { kind: "fixed", value: "text/plain" },
            filename: false,
          },
        ],
      },
    });

    for (const note of [
      {
        body: "ascii",
        contentType: "text/plain",
        headers: { "Content-Transfer-Encoding": "base64" },
      },
      {
        body: "é",
        contentType: "text/plain",
        headers: { "Content-Transfer-Encoding": "7bit" },
      },
    ]) {
      const result = requestFailure(
        await execute(createTransport({}), descriptor, { body: { note } }),
      );
      assert.equal(result.error.kind, "request-encode");
    }

    let captured: Request | undefined;
    await execute(
      createTransport({
        fetch: async (request) => {
          captured = request;
          return new Response();
        },
      }),
      descriptor,
      {
        body: {
          note: {
            body: "ascii",
            contentType: "text/plain",
            headers: { "Content-Transfer-Encoding": "7bit" },
          },
        },
      },
    );
    assert.ok(captured);
    assert.match(await captured.text(), /Content-Transfer-Encoding: 7bit\r\n/u);
  });

  test("returns the dependent signal's reason for a pre-dispatch abort", async () => {
    const reason = { code: "stop" };
    const controller = new AbortController();
    controller.abort(reason);
    let sent = false;
    const result = requestFailure(
      await execute(
        createTransport({
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

    assert.deepEqual(result.error, { kind: "aborted", reason });
    assert.equal(sent, false);
  });

  test("maps fetch rejection to network and abort-shaped rejection to aborted", async () => {
    const cause = new Error("offline");
    const network = requestFailure(
      await execute(createTransport({ fetch: async () => Promise.reject(cause) }), operation(), {}),
    );
    assert.deepEqual(network.error, { kind: "network", cause });

    const reason = new Error("cancelled");
    const controller = new AbortController();
    const aborted = requestFailure(
      await execute(
        createTransport({
          fetch: async (request) => {
            controller.abort(reason);
            return Promise.reject(request.signal.reason);
          },
        }),
        operation(),
        {},
        { signal: controller.signal },
      ),
    );
    assert.deepEqual(aborted.error, { kind: "aborted", reason });
  });
});

describe("request middleware", () => {
  test("chains replacements and void mutations with one frozen context", async () => {
    const events: string[] = [];
    const contexts: object[] = [];
    let sent: Request | undefined;
    const transport = createTransport({
      middleware: [
        {
          onRequest(request, context) {
            events.push("first");
            contexts.push(context);
            return new Request(request, { headers: { "X-Chain": "replacement" } });
          },
        },
        {
          onRequest(request, context) {
            events.push("second");
            contexts.push(context);
            request.headers.set("X-Void", "visible");
          },
        },
        {
          onRequest(request, context) {
            events.push(`${request.headers.get("x-chain")}/${request.headers.get("x-void")}`);
            contexts.push(context);
          },
        },
      ],
      fetch: async (request) => {
        sent = request;
        return new Response();
      },
    });

    await execute(transport, operation(), {});

    assert.deepEqual(events, ["first", "second", "replacement/visible"]);
    assert.ok(sent);
    assert.equal(sent.headers.get("x-void"), "visible");
    assert.equal(contexts[0], contexts[1]);
    assert.equal(contexts[1], contexts[2]);
    assert.ok(Object.isFrozen(contexts[0]));
  });

  test("uses a dependent signal rather than the caller signal", async () => {
    const controller = new AbortController();
    let finalSignal: AbortSignal | undefined;
    await execute(
      createTransport({
        fetch: async (request) => {
          finalSignal = request.signal;
          return new Response();
        },
      }),
      operation(),
      {},
      { signal: controller.signal },
    );

    assert.ok(finalSignal);
    assert.notEqual(finalSignal, controller.signal);
    controller.abort("later");
    assert.equal(finalSignal.aborted, true);
    assert.equal(finalSignal.reason, "later");
  });

  test("rejects forbidden replacement, mutation, method override, and thrown hooks without send", async () => {
    const thrown = new Error("hook failed");
    const hooks = [
      (request: Request) => new Request(request, { headers: { Cookie: "a=b" } }),
      (request: Request) => {
        request.headers.set("Sec-Test", "blocked");
      },
      (request: Request) => {
        request.headers.set("X-HTTP-Method-Override", "trace");
      },
      () => {
        throw thrown;
      },
    ];

    for (const hook of hooks) {
      let sends = 0;
      const result = requestFailure(
        await execute(
          createTransport({
            middleware: [{ onRequest: hook }],
            fetch: async () => {
              sends += 1;
              return new Response();
            },
          }),
          operation(),
          {},
        ),
      );
      assert.equal(result.error.kind, "request-middleware");
      assert.equal(sends, 0);
      if (hook === hooks[3] && result.error.kind === "request-middleware") {
        assert.equal(result.error.cause, thrown);
      }
    }
  });
});
