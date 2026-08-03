import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { createTransport, type Middleware } from "../transport.ts";
import { withInput, withRequestSignal } from "../tanstack-runtime.ts";

async function fetchImpl(): Promise<Response> {
  return new Response();
}

/** Dispatches a request through a transport's middleware chain and returns what would be sent. */
async function dispatched(
  transport: ReturnType<typeof createTransport>,
  request: Request,
): Promise<Request> {
  let current = request;
  for (const middleware of transport.middleware) {
    const replacement = await middleware.onRequest?.(current, {
      operationId: "probe",
      method: "GET",
      url: new URL(current.url),
      selectedAuth: null,
    });
    if (replacement !== undefined) {
      current = replacement;
    }
  }
  return current;
}

describe("withRequestSignal", () => {
  test("leaves every other transport field untouched", () => {
    const middleware: Middleware = { onResponse: (response) => response };
    const transport = createTransport({
      baseUrl: "https://example.test",
      headers: { "X-Base": "1" },
      fetch: fetchImpl,
      middleware: [middleware],
      credentials: "include",
    });

    const wrapped = withRequestSignal(transport, new AbortController().signal);

    assert.equal(wrapped.baseUrl, transport.baseUrl);
    assert.equal(wrapped.fetch, transport.fetch);
    assert.equal(wrapped.credentials, transport.credentials);
    assert.deepEqual(wrapped.headers, transport.headers);
  });

  test("appends its middleware after the transport's own, preserving registration order", () => {
    const order: string[] = [];
    const first: Middleware = {
      onRequest: () => {
        order.push("first");
      },
    };
    const transport = createTransport({ baseUrl: "https://example.test", middleware: [first] });
    const wrapped = withRequestSignal(transport, new AbortController().signal);

    assert.equal(transport.middleware.length, 1);
    assert.equal(wrapped.middleware.length, 2);
    assert.equal(wrapped.middleware[0], first);
  });

  test("aborting the framework signal aborts the dispatched request", async () => {
    const framework = new AbortController();
    const transport = createTransport({ baseUrl: "https://example.test" });
    const wrapped = withRequestSignal(transport, framework.signal);

    const request = await dispatched(wrapped, new Request("https://example.test/probe"));
    assert.equal(request.signal.aborted, false);

    const reason = new Error("framework cancel");
    framework.abort(reason);
    assert.equal(request.signal.aborted, true);
    assert.equal(request.signal.reason, reason);
  });

  test("aborting the caller's own signal aborts the dispatched request", async () => {
    const caller = new AbortController();
    const framework = new AbortController();
    const transport = createTransport({ baseUrl: "https://example.test" });
    const wrapped = withRequestSignal(transport, framework.signal);

    const request = await dispatched(
      wrapped,
      new Request("https://example.test/probe", { signal: caller.signal }),
    );
    assert.equal(request.signal.aborted, false);

    const reason = new Error("caller cancel");
    caller.abort(reason);
    assert.equal(request.signal.aborted, true);
    assert.equal(request.signal.reason, reason);
  });

  test("an already-aborted framework signal aborts the dispatched request immediately", async () => {
    const reason = new Error("cancelled before dispatch");
    const transport = createTransport({ baseUrl: "https://example.test" });
    const wrapped = withRequestSignal(transport, AbortSignal.abort(reason));

    const request = await dispatched(wrapped, new Request("https://example.test/probe"));
    assert.equal(request.signal.aborted, true);
    assert.equal(request.signal.reason, reason);
  });

  test("the replacement request keeps the referrer policy the client configured", async () => {
    // Fetch resets referrer and referrer policy whenever the Request constructor's init is
    // non-empty, so a query would otherwise silently fall back to the browser default while the
    // same operation called through the client kept its configured policy.
    const transport = createTransport({ baseUrl: "https://example.test" });
    const wrapped = withRequestSignal(transport, new AbortController().signal);

    const request = await dispatched(
      wrapped,
      new Request("https://example.test/probe", { referrerPolicy: "no-referrer" }),
    );
    assert.equal(request.referrerPolicy, "no-referrer");
  });

  test("the replacement request keeps the original's method, url and headers", async () => {
    const transport = createTransport({ baseUrl: "https://example.test" });
    const wrapped = withRequestSignal(transport, new AbortController().signal);

    const request = await dispatched(
      wrapped,
      new Request("https://example.test/probe?a=1", {
        method: "GET",
        headers: { "X-Probe": "kept" },
      }),
    );
    assert.equal(request.method, "GET");
    assert.equal(request.url, "https://example.test/probe?a=1");
    assert.equal(request.headers.get("X-Probe"), "kept");
  });
});

describe("withInput", () => {
  test("appends the sections when the caller supplied any of them", () => {
    const key = ["api", "search"] as const;
    assert.deepEqual(withInput(key, { query: { q: "cat" } }), [
      "api",
      "search",
      { query: { q: "cat" } },
    ]);
  });

  test("keeps a section that is present but empty", () => {
    // A caller who passed `{}` is not the same cache entry as a caller who passed nothing, so an
    // empty-but-defined section is still supplied input.
    const key = ["api", "search"] as const;
    assert.deepEqual(withInput(key, { query: {} }), ["api", "search", { query: {} }]);
  });

  test("returns the key unchanged when every section is undefined", () => {
    // This is what keeps a query's key the same length as its own path key, so a mutation's
    // invalidation entry can still match it with `exact: true`.
    const key = ["api", "events", { occurredAt: "2026-08-03" }] as const;
    assert.equal(withInput(key, { query: undefined }), key);
    assert.equal(withInput(key, { query: undefined, header: undefined }), key);
  });

  test("appends when only a later section is supplied", () => {
    const key = ["api", "search"] as const;
    assert.deepEqual(withInput(key, { query: undefined, cookie: { session: "s" } }), [
      "api",
      "search",
      { query: undefined, cookie: { session: "s" } },
    ]);
  });
});
