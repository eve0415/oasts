import assert from "node:assert/strict";
import { test } from "node:test";

import type { OperationDescriptor, ResponsePlan } from "../transport.ts";

type JsonReviver = (
  key: string,
  value: unknown,
  context?: { readonly source?: unknown },
) => unknown;

function responsePlan(): ResponsePlan {
  return {
    match: "200",
    kind: "exact",
    status: 200,
    bodyless: false,
    media: [["application/json", { json: "int64" }]],
    hasContentTypeDiscriminant: false,
  };
}

function operation(): OperationDescriptor {
  return {
    operationId: "getCounter",
    method: "GET",
    path: [[{ kind: "literal", text: "/counter" }]],
    params: [],
    body: null,
    accept: "application/json",
    credentialHeaders: [],
    security: null,
    responses: [responsePlan()],
    baseUrl: { kind: "literal", value: "https://example.test" },
    fetchDefaults: {},
  };
}

test("marked int64 JSON degrades independently when parse context is unavailable", async () => {
  const saved = Object.getOwnPropertyDescriptor(JSON, "parse");
  const nativeParse = JSON.parse;
  Object.defineProperty(JSON, "parse", {
    configurable: true,
    value: (text: string, reviver?: JsonReviver): unknown =>
      nativeParse(
        text,
        reviver === undefined
          ? undefined
          : (key: string, value: unknown): unknown => reviver(key, value),
      ),
  });
  try {
    const { createTransport, execute } = await import("../transport.ts");
    const transport = createTransport({
      fetch: async (): Promise<Response> =>
        new Response('{"safe":42,"unsafe":12345678901234567890}', {
          headers: { "Content-Type": "application/json" },
        }),
    });

    const result = await execute(transport, operation(), {});

    assert.equal(result.outcome, 200);
    assert.equal(result.ok, true);
    if (result.outcome === 200 && result.ok) {
      assert.deepEqual(result.data, {
        safe: 42,
        unsafe: Number("12345678901234567890"),
      });
    }
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(JSON, "parse");
    } else {
      Object.defineProperty(JSON, "parse", saved);
    }
  }
});
