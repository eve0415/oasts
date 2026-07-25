import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { RequestPhaseFailure } from "../result.ts";
import {
  AmbientClientCertificate,
  AmbientCookieCredential,
  createTransport,
  execute,
  type AuthContext,
  type AuthCredential,
  type AuthOverrides,
  type AuthProvider,
  type ExecutionResult,
  type OperationContext,
  type OperationDescriptor,
} from "../transport.ts";
import {
  BASIC_VECTORS,
  BEARER_VECTORS,
  COOKIE_SENTINEL_VECTORS,
  HEADER_KEY_VECTORS,
  HTTP_SCHEME_VECTORS,
  MUTUAL_TLS_VECTORS,
  QUERY_KEY_VECTORS,
  type AuthFailure as VectorAuthFailure,
} from "./vectors-auth-serialization.ts";
import {
  AUTH_SELECTION_SCENARIOS,
  type AuthSelectionScenario,
  type DummyCredential,
  type SchemeKind,
  type SchemeUse,
} from "./vectors-auth-selection.ts";

type AuthError = Extract<RequestPhaseFailure, { readonly outcome: "auth" }>;

function operation(overrides: Partial<OperationDescriptor> = {}): OperationDescriptor {
  return {
    operationId: "authOperation",
    method: "GET",
    path: [[{ kind: "literal", text: "/resource" }]],
    params: [],
    body: null,
    accept: null,
    credentialHeaders: ["Authorization", "X-API-Key"],
    security: [],
    responses: [],
    baseUrl: { kind: "literal", value: "https://auth.example/api" },
    fetchDefaults: {},
    ...overrides,
  };
}

function authFailure(result: ExecutionResult): AuthError {
  if (result.outcome !== "auth") {
    throw new Error(`expected auth failure, received ${String(result.outcome)}`);
  }
  return result;
}

function assertVectorFailure(
  result: ExecutionResult,
  expected: VectorAuthFailure,
  requests: readonly Request[],
): void {
  const failure = authFailure(result);
  assert.equal(failure.outcome, expected.failure);
  assert.match(failure.message, new RegExp(expected.messageIncludes, "u"));
  assert.equal(requests.length, 0);
}

function security(name: string, kind: SchemeKind, param?: string): OperationDescriptor["security"] {
  return [[{ name, kind, param, scopes: [] }]];
}

async function executeWithCredential(
  descriptor: OperationDescriptor,
  credential: AuthCredential,
  input: Readonly<Record<string, unknown>> = {},
): Promise<{
  readonly result: ExecutionResult;
  readonly requests: readonly Request[];
}> {
  const requests: Request[] = [];
  const result = await execute(
    createTransport({
      fetch: async (request) => {
        requests.push(request);
        return new Response(null, { status: 200 });
      },
    }),
    descriptor,
    input,
    { auth: { scheme: credential } },
  );
  return { result, requests };
}

function dummyCredential(dummy: DummyCredential): AuthCredential {
  switch (dummy.type) {
    case "token":
      return dummy.token;
    case "basic":
      return { username: dummy.username, password: dummy.password };
    case "apiKey":
      return dummy.value;
    case "ambientCookie":
      return AmbientCookieCredential;
  }
  throw new Error("unsupported dummy credential");
}

function credentialForKind(kind: SchemeKind): AuthCredential {
  switch (kind) {
    case "basic":
      return { username: "provider", password: "password" };
    case "bearer":
    case "oauth2":
    case "openIdConnect":
      return "providerToken";
    case "apiKeyHeader":
    case "apiKeyQuery":
      return "providerKey";
    case "apiKeyCookie":
      return AmbientCookieCredential;
  }
  throw new Error("unsupported scheme kind");
}

function schemeUse(scenario: AuthSelectionScenario, name: string): SchemeUse {
  for (const alternative of scenario.alternatives) {
    for (const use of alternative) {
      if (use.scheme === name) {
        return use;
      }
    }
  }
  throw new Error(`missing scheme use for ${name}`);
}

function scenarioSecurity(scenario: AuthSelectionScenario): OperationDescriptor["security"] {
  return scenario.alternatives.map((alternative) =>
    alternative.map((use) => ({
      name: use.scheme,
      kind: use.kind,
      param: use.param,
      scopes: use.scopes ?? [],
    })),
  );
}

function scenarioOverrides(scenario: AuthSelectionScenario): AuthOverrides | undefined {
  if (scenario.perCall === undefined || scenario.perCall === "anonymous") {
    return scenario.perCall;
  }
  const overrides: Record<string, AuthCredential> = {};
  for (const [name, dummy] of Object.entries(scenario.perCall)) {
    overrides[name] = dummyCredential(dummy);
  }
  return overrides;
}

describe("frozen auth serialization vectors", () => {
  for (const kind of ["bearer", "oauth2", "openIdConnect"] as const) {
    for (const vector of BEARER_VECTORS) {
      test(`${kind}: ${vector.name}`, async () => {
        const { result, requests } = await executeWithCredential(
          operation({ security: security("scheme", kind) }),
          vector.input.token,
        );
        if (typeof vector.expected !== "string") {
          assertVectorFailure(result, vector.expected, requests);
          return;
        }
        assert.equal(requests.length, 1);
        const request = requests[0];
        assert.ok(request);
        assert.equal(`Authorization: ${request.headers.get("Authorization")}`, vector.expected);
      });
    }
  }

  for (const vector of BASIC_VECTORS) {
    test(`basic: ${vector.name}`, async () => {
      const { result, requests } = await executeWithCredential(
        operation({ security: security("scheme", "basic") }),
        vector.input,
      );
      if (typeof vector.expected !== "string") {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(`Authorization: ${request.headers.get("Authorization")}`, vector.expected);
    });
  }

  for (const vector of HEADER_KEY_VECTORS) {
    test(`apiKeyHeader: ${vector.name}`, async () => {
      const { result, requests } = await executeWithCredential(
        operation({
          credentialHeaders: [vector.input.headerName],
          security: security("scheme", "apiKeyHeader", vector.input.headerName),
        }),
        vector.input.value,
      );
      if (typeof vector.expected !== "string") {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(
        `${vector.input.headerName}: ${request.headers.get(vector.input.headerName)}`,
        vector.expected,
      );
    });
  }

  for (const vector of QUERY_KEY_VECTORS) {
    test(`apiKeyQuery: ${vector.name}`, async () => {
      const params: OperationDescriptor["params"] =
        vector.input.existingQuery.length === 0
          ? []
          : [
              {
                name: "ordinaryQuery",
                location: "query",
                required: true,
                serialize: () => vector.input.existingQuery,
                allowReserved: false,
              },
            ];
      const input =
        vector.input.existingQuery.length === 0 ? {} : { query: { ordinaryQuery: true } };
      const { result, requests } = await executeWithCredential(
        operation({
          params,
          security: security("scheme", "apiKeyQuery", vector.input.keyName),
        }),
        vector.input.keyValue,
        input,
      );
      if (typeof vector.expected !== "string") {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(new URL(request.url).search.slice(1), vector.expected);
    });
  }

  for (const vector of COOKIE_SENTINEL_VECTORS) {
    test(`apiKeyCookie: ${vector.name}`, async () => {
      const credential =
        vector.input.kind === "ambient" ? AmbientCookieCredential : vector.input.value;
      const { result, requests } = await executeWithCredential(
        operation({
          credentialHeaders: [],
          security: security("scheme", "apiKeyCookie", "session"),
        }),
        credential,
      );
      if (!("noHeader" in vector.expected)) {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(request.headers.has("Cookie"), false);
      assert.deepEqual([...request.headers], []);
    });
  }

  for (const vector of HTTP_SCHEME_VECTORS) {
    test(`httpScheme: ${vector.name}`, async () => {
      const credential: AuthCredential =
        vector.input.credential.kind === "valid"
          ? { credentials: vector.input.credential.credentials }
          : {
              username: vector.input.credential.username,
              password: vector.input.credential.password,
            };
      const { result, requests } = await executeWithCredential(
        operation({
          security: [
            [{ name: "scheme", kind: "httpScheme", scheme: vector.input.scheme, scopes: [] }],
          ],
        }),
        credential,
      );
      if (typeof vector.expected !== "string") {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(`Authorization: ${request.headers.get("Authorization")}`, vector.expected);
    });
  }

  for (const vector of MUTUAL_TLS_VECTORS) {
    test(`mutualTls: ${vector.name}`, async () => {
      // Map the symbolic ambient entry onto the AmbientClientCertificate symbol, mirroring how the
      // cookie-sentinel loop maps its ambient entry onto AmbientCookieCredential.
      const credential: AuthCredential =
        vector.input.kind === "ambient" ? AmbientClientCertificate : vector.input.value;
      const { result, requests } = await executeWithCredential(
        operation({
          credentialHeaders: [],
          security: [[{ name: "scheme", kind: "mutualTls", scopes: [] }]],
        }),
        credential,
      );
      if (!("noHeader" in vector.expected)) {
        assertVectorFailure(result, vector.expected, requests);
        return;
      }
      assert.equal(requests.length, 1);
      const request = requests[0];
      assert.ok(request);
      assert.equal(request.headers.has("Authorization"), false);
      assert.deepEqual([...request.headers], []);
    });
  }
});

describe("frozen auth selection scenarios", () => {
  for (const scenario of AUTH_SELECTION_SCENARIOS) {
    test(scenario.name, async () => {
      const providerCalls: string[] = [];
      const providerContexts: AuthContext[] = [];
      const providerCause = new Error(`provider failure for ${scenario.name}`);
      const providers: Record<string, AuthProvider> = {};
      for (const configured of scenario.configured) {
        providers[configured.scheme] = (context) => {
          providerCalls.push(configured.scheme);
          providerContexts.push(context);
          if (configured.behavior === "throw") {
            throw providerCause;
          }
          if (configured.behavior === "null") {
            return null;
          }
          return credentialForKind(schemeUse(scenario, configured.scheme).kind);
        };
      }

      const requests: Request[] = [];
      const operationContexts: OperationContext[] = [];
      const result = await execute(
        createTransport({
          auth: providers,
          middleware: [
            {
              onRequest: (request, context) => {
                operationContexts.push(context);
              },
            },
          ],
          fetch: async (request) => {
            requests.push(request);
            return new Response(null, { status: 200 });
          },
        }),
        operation({ security: scenarioSecurity(scenario) }),
        {},
        { auth: scenarioOverrides(scenario) },
      );

      if ("failure" in scenario.expected) {
        const failure = authFailure(result);
        assert.deepEqual(failure.triedAlternatives, scenario.expected.triedAlternatives);
        assert.equal(requests.length, 0);
        assert.equal(operationContexts.length, 0);
        if (scenario.expected.causePreserved === true) {
          assert.equal(failure.cause, providerCause);
        } else {
          assert.equal("cause" in failure, false);
        }
        if (scenario.expected.messageIncludes !== undefined) {
          assert.match(failure.message, new RegExp(scenario.expected.messageIncludes, "u"));
        }
      } else {
        assert.equal(requests.length, 1);
        assert.equal(operationContexts.length, 1);
        const context = operationContexts[0];
        assert.ok(context);
        assert.deepEqual(context.selectedAuth, scenario.expected.selected);
        if (scenario.expected.providerCalls !== undefined) {
          assert.deepEqual(providerCalls, scenario.expected.providerCalls);
        }
        if (scenario.expected.providerContext !== undefined) {
          const expected = scenario.expected.providerContext;
          const contexts = providerContexts.filter(
            (providerContext) => providerContext.scheme === expected.scheme,
          );
          assert.equal(contexts.length, 1);
          const providerContext = contexts[0];
          assert.ok(providerContext);
          assert.equal(providerContext.operationId, "authOperation");
          assert.equal(providerContext.scheme, expected.scheme);
          assert.deepEqual(providerContext.scopes, expected.scopes);
          assert.equal(providerContext.url, "https://auth.example/api/resource");
        }
      }
    });
  }
});

describe("auth runtime boundaries", () => {
  // Ambient-sentinel acceptance and the plain-string rejection are covered by MUTUAL_TLS_VECTORS in
  // the frozen-vectors describe; this case exceeds them by rejecting the wrong ambient *symbol*
  // (AmbientCookieCredential), a different input type than the vector's string.
  test("rejects a non-sentinel mutual TLS credential", async () => {
    const { result, requests } = await executeWithCredential(
      operation({
        credentialHeaders: [],
        security: [[{ name: "scheme", kind: "mutualTls", scopes: [] }]],
      }),
      AmbientCookieCredential,
    );
    assert.match(authFailure(result).message, /ambient client certificate/u);
    assert.equal(requests.length, 0);
  });

  // Verbatim serialization and the LF-in-credentials rejection are covered by HTTP_SCHEME_VECTORS.
  // These two cases exceed the vectors: control bytes in the scheme NAME (the vector injects them in
  // the credentials), and a non-object string credential (the vector's wrong shape is a basic pair).
  test("rejects header-control injection in the generic HTTP scheme name", async () => {
    const { result, requests } = await executeWithCredential(
      operation({
        security: [
          [{ name: "scheme", kind: "httpScheme", scheme: "Digest\r\nX-Injected: yes", scopes: [] }],
        ],
      }),
      { credentials: "proof" },
    );
    assert.match(authFailure(result).message, /control character/u);
    assert.equal(requests.length, 0);
  });

  test("rejects a non-object generic HTTP credential", async () => {
    const { result, requests } = await executeWithCredential(
      operation({
        security: [[{ name: "scheme", kind: "httpScheme", scheme: "Digest", scopes: [] }]],
      }),
      "not-an-object",
    );
    assert.match(authFailure(result).message, /credentials string/u);
    assert.equal(requests.length, 0);
  });

  for (const boundary of [
    {
      name: "string for basic",
      kind: "basic",
      credential: "not-basic",
      message: "basic",
    },
    {
      name: "object for bearer",
      kind: "bearer",
      credential: { username: "user", password: "secret" },
      message: "b64token",
    },
    {
      name: "sentinel for header API key",
      kind: "apiKeyHeader",
      param: "X-API-Key",
      credential: AmbientCookieCredential,
      message: "string",
    },
    {
      name: "object for query API key",
      kind: "apiKeyQuery",
      param: "api_key",
      credential: { username: "user", password: "secret" },
      message: "string",
    },
    {
      name: "object for cookie API key",
      kind: "apiKeyCookie",
      param: "session",
      credential: { username: "user", password: "secret" },
      message: "ambient",
    },
  ] as const) {
    test(`rejects ${boundary.name} as auth`, async () => {
      const { result, requests } = await executeWithCredential(
        operation({ security: security("scheme", boundary.kind, boundary.param) }),
        boundary.credential,
      );
      const failure = authFailure(result);
      assert.match(failure.message, new RegExp(boundary.message, "u"));
      assert.equal(requests.length, 0);
    });
  }

  for (const boundary of [
    { kind: "apiKeyHeader", message: "header name" },
    { kind: "apiKeyQuery", message: "query name" },
  ] as const) {
    test(`rejects ${boundary.kind} without its declared parameter name`, async () => {
      const { result, requests } = await executeWithCredential(
        operation({ security: security("scheme", boundary.kind) }),
        "key",
      );
      const failure = authFailure(result);
      assert.match(failure.message, new RegExp(boundary.message, "u"));
      assert.equal(requests.length, 0);
    });
  }

  test("enters anonymous when every remaining alternative is a duplicated empty one", async () => {
    const requests: Request[] = [];
    const result = await execute(
      createTransport({
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({
        security: [[{ name: "bearerAuth", kind: "bearer", scopes: [] }], [], []],
      }),
      {},
    );
    assert.equal(requests.length, 1);
    const request = requests[0];
    assert.ok(request);
    assert.equal(request.headers.get("Authorization"), null);
    assert.notEqual(result.outcome, "auth");
  });

  test("accepts an empty header API key without normalization", async () => {
    const { requests } = await executeWithCredential(
      operation({ security: security("scheme", "apiKeyHeader", "X-API-Key") }),
      "",
    );
    assert.equal(requests.length, 1);
    const request = requests[0];
    assert.ok(request);
    assert.equal(request.headers.get("X-API-Key"), "");
  });

  test("appends two query API keys from one alternative in member order", async () => {
    const requests: Request[] = [];
    await execute(
      createTransport({
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({
        security: [
          [
            { name: "first", kind: "apiKeyQuery", param: "first_key", scopes: [] },
            { name: "second", kind: "apiKeyQuery", param: "second_key", scopes: [] },
          ],
        ],
      }),
      {},
      { auth: { first: "one", second: "two" } },
    );
    assert.equal(requests.length, 1);
    const request = requests[0];
    assert.ok(request);
    assert.equal(new URL(request.url).search, "?first_key=one&second_key=two");
  });

  test("fails closed when a descriptor carries an unrecognized scheme kind", async () => {
    // The kind union is closed at generation time; a drifted or hand-built descriptor smuggled
    // past the static type must fail closed, never silently skip the member's credential.
    const drifted = new Proxy(
      operation({ security: security("scheme", "apiKeyCookie", "session") }),
      {
        get: (target, property, receiver) =>
          property === "security"
            ? [[{ name: "scheme", kind: "unrecognized", scopes: [] }]]
            : Reflect.get(target, property, receiver),
      },
    );
    const { result, requests } = await executeWithCredential(drifted, AmbientCookieCredential);
    const failure = authFailure(result);
    assert.match(failure.message, /unrecognized/u);
    assert.equal(requests.length, 0);
  });

  test("fails closed when a configured provider is not callable at runtime", async () => {
    const configured = new Proxy(
      { scheme: () => "validToken" },
      { get: () => ({ invalid: true }) },
    );
    const requests: Request[] = [];
    const result = await execute(
      createTransport({
        auth: configured,
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({ security: [...security("scheme", "bearer"), []] }),
      {},
    );
    const failure = authFailure(result);
    assert.deepEqual(failure.triedAlternatives, [["scheme"]]);
    assert.equal(requests.length, 0);
  });

  test("validates a provider return value at the runtime boundary", async () => {
    const provider = new Proxy(() => "validToken", { apply: () => undefined });
    const requests: Request[] = [];
    const result = await execute(
      createTransport({
        auth: { scheme: provider },
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({ security: security("scheme", "bearer") }),
      {},
    );
    const failure = authFailure(result);
    assert.match(failure.message, /b64token/u);
    assert.equal(requests.length, 0);
  });

  test("applies auth headers after generated content headers", async () => {
    const requests: Request[] = [];
    await execute(
      createTransport({
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({
        method: "POST",
        body: { kind: "json", contentType: "application/json" },
        accept: "application/json",
        credentialHeaders: ["Accept", "Content-Type"],
        security: [
          [
            { name: "acceptKey", kind: "apiKeyHeader", param: "Accept", scopes: [] },
            {
              name: "contentKey",
              kind: "apiKeyHeader",
              param: "Content-Type",
              scopes: [],
            },
          ],
        ],
      }),
      { body: { value: true } },
      { auth: { acceptKey: "auth-accept", contentKey: "auth-content" } },
    );
    assert.equal(requests.length, 1);
    const request = requests[0];
    assert.ok(request);
    assert.equal(request.headers.get("Accept"), "auth-accept");
    assert.equal(request.headers.get("Content-Type"), "auth-content");
  });

  test("passes providers the URL before appending an auth query", async () => {
    const contexts: AuthContext[] = [];
    const requests: Request[] = [];
    await execute(
      createTransport({
        auth: {
          scheme: (context) => {
            contexts.push(context);
            return "providerKey";
          },
        },
        fetch: async (request) => {
          requests.push(request);
          return new Response(null, { status: 200 });
        },
      }),
      operation({
        params: [
          {
            name: "ordinary",
            location: "query",
            required: true,
            serialize: () => "ordinary=1",
            allowReserved: false,
          },
        ],
        security: security("scheme", "apiKeyQuery", "token"),
      }),
      { query: { ordinary: true } },
    );
    assert.equal(contexts.length, 1);
    assert.equal(contexts[0]?.url, "https://auth.example/api/resource?ordinary=1");
    assert.equal(
      requests[0]?.url,
      "https://auth.example/api/resource?ordinary=1&token=providerKey",
    );
  });

  test("reports every alternative evaluated before selected-auth serialization fails", async () => {
    let providerCalled = false;
    const result = await execute(
      createTransport({
        auth: {
          bearerA: () => {
            providerCalled = true;
            return "providerToken";
          },
        },
      }),
      operation({
        security: [
          [{ name: "bearerA", kind: "bearer", scopes: [] }],
          [{ name: "basicB", kind: "basic", scopes: [] }],
        ],
      }),
      {},
      { auth: { basicB: "not-basic" } },
    );
    const failure = authFailure(result);
    assert.deepEqual(failure.triedAlternatives, [["bearerA"], ["basicB"]]);
    assert.equal(providerCalled, false);
    assert.equal(failure.message.includes("not-basic"), false);
  });
});
