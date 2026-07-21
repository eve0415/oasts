import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { createTransport } from "../transport.ts";
import {
  FROZEN_CALL_OPTIONS,
  FROZEN_MIDDLEWARE,
  FROZEN_TRANSPORT_CONFIG_AND_OPERATION_CONTEXT,
} from "./frozen-declarations.ts";

const source = readFileSync(new URL("../transport.ts", import.meta.url), "utf8");

test("transport declarations preserve frozen source blocks", () => {
  assert.ok(source.includes(FROZEN_TRANSPORT_CONFIG_AND_OPERATION_CONTEXT));
  assert.ok(source.includes(FROZEN_CALL_OPTIONS));
  assert.ok(source.includes(FROZEN_MIDDLEWARE));
});

describe("createTransport", () => {
  test("copies, normalizes, and freezes every owned config container", () => {
    const serverVariables = { region: "east" };
    const auth = { bearer: () => "secret" };
    const middleware = [{}];
    const headers: [string, string][] = [["X-Default", "  value  "]];
    const transport = createTransport({
      baseUrl: "https://example.com/api/",
      serverVariables,
      auth,
      headers,
      middleware,
      credentials: "include",
    });

    serverVariables.region = "west";
    middleware.push({});

    assert.equal(transport.baseUrl, "https://example.com/api/");
    assert.deepEqual(transport.serverVariables, { region: "east" });
    assert.notEqual(transport.serverVariables, serverVariables);
    assert.notEqual(transport.auth, auth);
    assert.notEqual(transport.middleware, middleware);
    assert.deepEqual(transport.headers, [["x-default", "value"]]);
    assert.equal(transport.credentials, "include");
    assert.equal("setConfig" in transport, false);
    assert.ok(Object.isFrozen(transport));
    assert.ok(Object.isFrozen(transport.serverVariables));
    assert.ok(Object.isFrozen(transport.auth));
    assert.ok(Object.isFrozen(transport.headers));
    assert.ok(Object.isFrozen(transport.headers[0]));
    assert.ok(Object.isFrozen(transport.middleware));
  });

  test("allows mode-independent construction without a base URL", () => {
    const transport = createTransport({
      headers: {
        Accept: "application/json",
        Authorization: "transport credential",
        "Content-Type": "application/json",
      },
    });

    assert.equal(transport.baseUrl, undefined);
    assert.deepEqual(transport.headers, [
      ["accept", "application/json"],
      ["authorization", "transport credential"],
      ["content-type", "application/json"],
    ]);
  });

  test("rejects invalid configured base URLs", () => {
    assert.throws(
      () => createTransport({ baseUrl: "/relative" }),
      /baseUrl must be an absolute URL/u,
    );
  });

  test("rejects default headers outside the Headers byte domain", () => {
    assert.throws(() => createTransport({ headers: { "Bad Header": "value" } }), TypeError);
    assert.throws(() => createTransport({ headers: { Good: "value\nnext" } }), TypeError);
    assert.throws(() => createTransport({ headers: { Good: "\u{100}" } }), TypeError);
  });
});
