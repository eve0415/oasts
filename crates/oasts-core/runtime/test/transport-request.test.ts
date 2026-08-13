import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { RequestPhaseFailure } from "../result.ts";
import { requestFailure as narrowRequestFailure } from "./result-narrowing.ts";
import {
  binaryBody,
  createTransport,
  discriminatedBody,
  execute,
  jsonBody,
  multipartBody,
  textBody,
  urlencodedBody,
  type ExecutionResult,
  type OperationDescriptor,
  type ParamPlan,
} from "../transport.ts";
import {
  serializeContentJsonQuery,
  serializeHeaderSimple,
  serializePathLabel,
  serializePathLabelExplode,
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
    security: null,
    responses: [],
    baseUrl: { kind: "literal", value: "https://descriptor.example/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

function requestFailure(result: ExecutionResult | Response): RequestPhaseFailure {
  assert.ok(!(result instanceof Response));
  return narrowRequestFailure(result);
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
        body: jsonBody("application/json"),
        accept: "application/json, text/*",
        fetchDefaults: { credentials: "same-origin", redirect: "follow" },
      }),
      {
        path: { petId: "a/b" },
        query: { tag: ["red", "blue"] },
        header: { "X-Layer": "parameter" },
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

  test("serializes bigint parameters and text form fields without precision loss", async () => {
    const requests: Request[] = [];
    const transport = createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response();
      },
    });
    const id = 12345678901234567890n;

    await execute(
      transport,
      operation({
        method: "POST",
        path: [
          [
            { kind: "literal", text: "/resource/" },
            { kind: "param", name: "id" },
          ],
        ],
        params: [
          {
            name: "id",
            location: "path",
            required: true,
            serialize: serializePathSimple,
            allowReserved: false,
          },
          {
            name: "after",
            location: "query",
            required: true,
            serialize: serializeQueryFormExplode,
            allowReserved: false,
          },
          {
            name: "X-Id",
            location: "header",
            required: true,
            serialize: serializeHeaderSimple,
            allowReserved: false,
          },
        ],
      }),
      { path: { id }, query: { after: id }, header: { "X-Id": id } },
    );
    await execute(
      transport,
      operation({
        method: "POST",
        body: urlencodedBody("application/x-www-form-urlencoded", [{ name: "id", required: true }]),
      }),
      { body: { id } },
    );
    await execute(
      transport,
      operation({
        method: "POST",
        body: multipartBody([
          {
            name: "id",
            required: true,
            repeated: false,
            wrapper: false,
            payload: "text",
            contentType: { kind: "fixed", value: "text/plain" },
            filename: false,
          },
        ]),
      }),
      { body: { id } },
    );

    assert.equal(requests[0].url, `https://descriptor.example/api/resource/${id}?after=${id}`);
    assert.equal(requests[0].headers.get("x-id"), String(id));
    assert.equal(await requests[1].text(), `id=${id}`);
    assert.match(await requests[2].text(), new RegExp(`\\r\\n\\r\\n${id}\\r\\n`, "u"));
  });

  test("forwards a content JSON parameter's raw object value past the ParamValue guard", async () => {
    let url = "";
    const transport = createTransport({
      fetch: async (request) => {
        url = request.url;
        return new Response();
      },
    });

    await execute(
      transport,
      operation({
        params: [
          {
            name: "filter",
            location: "query",
            required: true,
            serialize: serializeContentJsonQuery,
            allowReserved: false,
            content: true,
          },
        ],
      }),
      { query: { filter: { status: ["open", "closed"] } } },
    );

    assert.equal(
      url,
      "https://descriptor.example/api/resource?filter=%7B%22status%22%3A%5B%22open%22%2C%22closed%22%5D%7D",
    );
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

  test("resolves relative server descriptors against the transport base URL", async () => {
    const urls: string[] = [];
    const transport = createTransport({
      baseUrl: "https://transport.example/root/",
      fetch: async (request) => {
        urls.push(request.url);
        return new Response();
      },
    });

    for (const serverUrl of ["/api/{version}", "/api/{version}/"] as const) {
      await execute(
        transport,
        operation({
          baseUrl: {
            kind: "server",
            index: 0,
            servers: [
              {
                url: serverUrl,
                variables: [["version", "v2"]],
              },
            ],
          },
        }),
        {},
      );
    }

    assert.deepEqual(urls, [
      "https://transport.example/api/v2/resource",
      "https://transport.example/api/v2/resource",
    ]);
  });

  test("keeps transport base URL precedence over an absolute server descriptor", async () => {
    let url = "";
    const transport = createTransport({
      baseUrl: "https://transport.example/root/",
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
          servers: [{ url: "https://server.example/api", variables: [] }],
        },
      }),
      {},
    );

    assert.equal(url, "https://transport.example/root/resource");
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
        body: urlencodedBody("application/x-www-form-urlencoded", [
          { name: "name", required: true },
          { name: "tag", required: false, explode: true },
        ]),
      }),
      { body: { name: "A B", tag: ["one", "two"] } },
    );
    const bytes = Uint8Array.of(0, 1, 255);
    await execute(
      transport,
      operation({
        method: "POST",
        body: binaryBody("application/octet-stream"),
      }),
      { body: bytes },
    );

    assert.equal(await requests[0].text(), "name=A%20B&tag=one&tag=two");
    assert.deepEqual(new Uint8Array(await requests[1].arrayBuffer()), bytes);
  });

  test("serializes content-based urlencoded fields per selected payload kind", async () => {
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
        body: urlencodedBody("application/x-www-form-urlencoded", [
          { name: "profile", required: false, payloads: ["json"] },
          {
            name: "icon",
            required: false,
            payloads: ["text", "text"],
            contentType: { kind: "selected", admitted: ["image/png", "image/jpeg"] },
          },
          { name: "f", required: false, payloads: ["text"] },
          { name: "n", required: false, payloads: ["text"] },
        ]),
      }),
      {
        body: {
          profile: { nickname: "Ada", age: 36 },
          icon: { body: "iVBORw0KGgo", contentType: "image/png" },
          f: ["a", "b"],
          n: 5,
        },
      },
    );

    // profile → JSON: keys serialize in insertion order, then RFC1866 percent-encoding.
    // icon → wrapped text: the base64url alphabet is RFC3986-unreserved, so the selected value
    //   passes through with no surrounding %22 (proving text routing, not JSON quoting).
    // f → text array: one form pair per item (regression guard against comma-joining).
    // n → text number: rendered as the decimal string.
    assert.equal(
      await requests[0].text(),
      "profile=%7B%22nickname%22%3A%22Ada%22%2C%22age%22%3A36%7D&icon=iVBORw0KGgo&f=a&f=b&n=5",
    );
  });

  test("indexes payload kind by the selected media, not payloads[0]", async () => {
    // Heterogeneous payloads (`["json", "text"]`) prove the selected media type indexes into
    // `payloads`: reading `payloads[0]` for every selection would quote the text variant as JSON.
    // Selecting text/plain (index 1) yields the bare value; selecting application/json (index 0)
    // yields the `%22`-quoted JSON — byte-different, so a wrong index fails.
    const requests: Request[] = [];
    const transport = createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response();
      },
    });
    const wrapped = operation({
      method: "POST",
      body: urlencodedBody("application/x-www-form-urlencoded", [
        {
          name: "data",
          required: true,
          payloads: ["json", "text"],
          contentType: { kind: "selected", admitted: ["application/json", "text/plain"] },
        },
      ]),
    });

    await execute(transport, wrapped, {
      body: { data: { body: "hi", contentType: "text/plain" } },
    });
    await execute(transport, wrapped, {
      body: { data: { body: "hi", contentType: "application/json" } },
    });

    assert.equal(await requests[0].text(), "data=hi");
    assert.equal(await requests[1].text(), "data=%22hi%22");
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
        body: multipartBody([
          {
            name: "note",
            required: true,
            repeated: false,
            wrapper: true,
            payload: "text",
            contentType: { kind: "selected", admitted: ["text/*"] },
            filename: true,
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
        ]),
      }),
      {
        body: {
          note: {
            body: "héllo",
            contentType: "Text/Plain; Charset=UTF-8",
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
    assert.equal(body.match(/name="tags"/gu)?.length, 2);
    assert.doesNotMatch(body, /name="optional"/u);
  });

  test("multipart indexes the payload kind by the selected media, not payloads[0]", async () => {
    // Heterogeneous payloads (`["json", "text"]`) prove the selected media indexes into `payloads`:
    // reading payloads[0] would serialize the text selection as JSON, stamping text/plain on a
    // JSON-quoted body. Selecting text/plain (index 1) writes the bare value; application/json
    // (index 0) writes the `"`-quoted JSON — byte-different, so a wrong index fails.
    const requests: Request[] = [];
    const transport = createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response();
      },
    });
    const wrapped = operation({
      method: "POST",
      body: multipartBody([
        {
          name: "data",
          required: true,
          repeated: false,
          wrapper: true,
          payload: "json",
          payloads: ["json", "text"],
          contentType: { kind: "selected", admitted: ["application/json", "text/plain"] },
          filename: false,
        },
      ]),
    });

    await execute(transport, wrapped, {
      body: { data: { body: "hi", contentType: "text/plain" } },
    });
    await execute(transport, wrapped, {
      body: { data: { body: "hi", contentType: "application/json" } },
    });

    const textPart = await requests[0].text();
    assert.match(textPart, /Content-Type: text\/plain/u);
    assert.ok(textPart.includes("\r\n\r\nhi\r\n"), textPart);
    const jsonPart = await requests[1].text();
    assert.match(jsonPart, /Content-Type: application\/json/u);
    assert.ok(jsonPart.includes('\r\n\r\n"hi"\r\n'), jsonPart);
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
        body: discriminatedBody([
          ["application/*", jsonBody("application/json")],
          ["*/*", textBody("text/plain")],
        ]),
      }),
      { body: { contentType: "Application/Problem+JSON; Charset=UTF-8", body: { code: 4 } } },
    );

    assert.ok(captured);
    assert.equal(captured.headers.get("content-type"), "application/problem+json; charset=utf-8");
    assert.deepEqual(await captured.json(), { code: 4 });
  });

  // Three request literals whose members are optional. A plan that declares nothing for one of
  // them is not the same as a plan that declares it undefined, and the wire has to agree — these
  // pin what "the plan said nothing" actually sends.
  test("undeclared optional members send the default wire, not an undefined one", async () => {
    const requests: Request[] = [];
    const transport = createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response();
      },
    });

    // A urlencoded field with no style/explode/allowReserved takes the form defaults, which are
    // form/exploded/not-reserved — the same wire an explicit undefined would have produced.
    await execute(
      transport,
      operation({
        method: "POST",
        body: urlencodedBody("application/x-www-form-urlencoded", [
          { name: "tags", required: true },
        ]),
      }),
      { body: { tags: ["one", "two"] } },
    );
    assert.equal(await requests[0]?.text(), "tags=one&tags=two");

    // A multipart part whose plan declares no filename carries no filename directive at all.
    await execute(
      transport,
      operation({
        method: "POST",
        body: multipartBody([
          {
            name: "note",
            required: true,
            repeated: false,
            wrapper: false,
            payload: "text",
            contentType: { kind: "none" },
            filename: false,
          },
        ]),
      }),
      { body: { note: "hello" } },
    );
    const multipart = await requests[1]?.text();
    assert.ok(multipart?.includes('Content-Disposition: form-data; name="note"'));
    assert.ok(!multipart?.includes("filename"));

    // A call with no signal still produces a request carrying the transport's dependent signal.
    await execute(transport, operation({ method: "GET" }), {});
    assert.ok(requests[2]?.signal instanceof AbortSignal);
    assert.equal(requests[2]?.signal.aborted, false);
  });
});

describe("request failures", () => {
  // A path segment that IS a dot segment is removed by every WHATWG entry point — the URL
  // constructor, the pathname setter and the Request constructor — for the %2e spellings as well
  // as the bare ones. Nothing can be sent, so the choice is between failing and requesting a
  // different URL than the caller asked for. An empty label parameter serializes to "." and an
  // exploded label over two empty members to "..", which pops a whole segment.
  test("refuses a path segment a URL would resolve away", async () => {
    for (const [label, serialize, value] of [
      ["empty label scalar", serializePathLabel, ""],
      ["empty exploded label scalar", serializePathLabelExplode, ""],
      ["exploded label over empty members", serializePathLabelExplode, ["", ""]],
      ["a literal dot-dot value", serializePathSimple, ".."],
    ] satisfies readonly (readonly [string, ParamPlan["serialize"], unknown])[]) {
      let fetched = false;
      const transport = createTransport({
        fetch: async () => {
          fetched = true;
          return new Response(null, { status: 204 });
        },
      });
      const result = requestFailure(
        await execute(
          transport,
          operation({
            path: [
              [{ kind: "literal", text: "/labelNo" }],
              [
                { kind: "literal", text: "/" },
                { kind: "param", name: "p" },
              ],
            ],
            params: [
              { name: "p", location: "path", required: true, serialize, allowReserved: false },
            ],
          }),
          { path: { p: value } },
        ),
      );

      assert.equal(result.outcome, "request-encode", label);
      assert.match(
        result.outcome === "request-encode" ? result.message : "",
        /path segment/u,
        label,
      );
      assert.equal(fetched, false, label);
    }
  });

  // The other side of the same check: label output that merely starts with a dot is not a dot
  // segment and must reach the wire byte-identical.
  test("keeps a non-empty label parameter's dot", async () => {
    let requested = "";
    const transport = createTransport({
      fetch: async (request) => {
        requested = request.url;
        return new Response(null, { status: 204 });
      },
    });

    await execute(
      transport,
      operation({
        path: [
          [{ kind: "literal", text: "/labelNo" }],
          [
            { kind: "literal", text: "/" },
            { kind: "param", name: "p" },
          ],
        ],
        params: [
          {
            name: "p",
            location: "path",
            required: true,
            serialize: serializePathLabel,
            allowReserved: false,
          },
        ],
      }),
      { path: { p: ["3", "4", "5"] } },
    );

    assert.equal(requested, "https://descriptor.example/api/labelNo/.3,4,5");
  });

  // The %2e spellings are dot segments to the URL parser, but a caller cannot produce one through
  // a serializer: the percent is itself encoded, so "%2E" arrives as "%252E" and addresses a real
  // segment. Asserted so the guard above is never widened into rejecting it.
  test("sends a literal percent-encoded dot as an ordinary segment", async () => {
    let requested = "";
    const transport = createTransport({
      fetch: async (request) => {
        requested = request.url;
        return new Response(null, { status: 204 });
      },
    });

    await execute(
      transport,
      operation({
        path: [
          [{ kind: "literal", text: "/simpleNo" }],
          [
            { kind: "literal", text: "/" },
            { kind: "param", name: "p" },
          ],
        ],
        params: [
          {
            name: "p",
            location: "path",
            required: true,
            serialize: serializePathSimple,
            allowReserved: false,
          },
        ],
      }),
      { path: { p: "%2E" } },
    );

    assert.equal(requested, "https://descriptor.example/api/simpleNo/%252E");
  });

  test("returns request-encode when no absolute base URL resolves", async () => {
    const transport = createTransport({});
    const result = requestFailure(
      await execute(transport, operation({ baseUrl: { kind: "runtime" } }), {}),
    );

    assert.equal(result.outcome, "request-encode");
    assert.match(result.outcome === "request-encode" ? result.message : "", /base URL/u);
  });

  test("returns request-encode for unresolved server state", async () => {
    for (const baseUrl of [
      { kind: "server", index: 1, servers: [] },
      {
        kind: "server",
        index: 0,
        servers: [{ url: "/relative", variables: [] }],
      },
    ] satisfies OperationDescriptor["baseUrl"][]) {
      const result = requestFailure(await execute(createTransport({}), operation({ baseUrl }), {}));

      assert.equal(result.outcome, "request-encode");
    }
  });

  test("returns request-encode for missing, malformed, range, or unmatched content selections", async () => {
    const descriptor = operation({
      method: "POST",
      body: discriminatedBody([["application/json", jsonBody("application/json")]]),
    });
    for (const body of [
      { body: {} },
      { contentType: "bad", body: {} },
      { contentType: "application/*", body: {} },
      { contentType: "text/plain", body: {} },
    ]) {
      const result = requestFailure(await execute(createTransport({}), descriptor, { body }));
      assert.equal(result.outcome, "request-encode");
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
      assert.equal(result.outcome, "request-encode");
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

    assert.equal(result.outcome, "request-encode");
  });

  test("maps a present-null multipart field to request-encode", async () => {
    const field = {
      name: "note",
      required: true,
      repeated: false,
      wrapper: false,
      payload: "text" as const,
      contentType: { kind: "fixed" as const, value: "text/plain" },
      filename: false,
    };
    const descriptor = operation({ method: "POST", body: multipartBody([field]) });

    const result = requestFailure(
      await execute(createTransport({}), descriptor, { body: { note: null } }),
    );
    assert.equal(result.outcome, "request-encode");
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

    assert.equal(result.outcome, "aborted");
    assert.equal(result.reason, reason);
    assert.equal(sent, false);
  });

  test("maps fetch rejection to network and abort-shaped rejection to aborted", async () => {
    // A real fetch() rejection is already a TypeError and passes through by identity.
    const platformCause = new TypeError("fetch failed");
    const platform = requestFailure(
      await execute(
        createTransport({ fetch: async () => Promise.reject(platformCause) }),
        operation(),
        {},
      ),
    );
    assert.equal(platform.outcome, "network");
    assert.equal(platform.cause, platformCause);

    // An injected fetch can reject with anything; the declared TypeError is then established by
    // construction, carrying the original where a platform TypeError carries its own detail.
    for (const thrown of [new Error("offline"), "offline", null, { code: "ENOTFOUND" }]) {
      const network = requestFailure(
        await execute(
          createTransport({ fetch: async () => Promise.reject(thrown) }),
          operation(),
          {},
        ),
      );
      assert.equal(network.outcome, "network");
      if (network.outcome === "network") {
        assert.ok(network.cause instanceof TypeError);
        assert.equal(network.cause.cause, thrown);
      }
    }

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
    assert.equal(aborted.outcome, "aborted");
    assert.equal(aborted.reason, reason);
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
      assert.equal(result.outcome, "request-middleware");
      assert.equal(sends, 0);
      if (hook === hooks[3] && result.outcome === "request-middleware") {
        assert.equal(result.cause, thrown);
      }
    }
  });
});
