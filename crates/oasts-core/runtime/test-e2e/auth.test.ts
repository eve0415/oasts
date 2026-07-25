// Auth end-to-end: every assertion drives a GENERATED client through its transport to a real
// local node:http server and inspects the raw bytes that arrived. Consumption strategy is the
// same as client.test.ts — generate into a mkdtemp directory by exec'ing the built binary, then
// register a `node:module` resolution hook that retries a failing relative `.js` specifier at the
// sibling `.ts` path (emit.importExtension only produces `".js" | "none"`). Generated modules are
// loaded through the dynamic-import boundary as `unknown` and narrowed with runtime guards, so no
// generated symbol is ever imported at type-check time.
//
// The committed fixture is generated once in authEnforcement: types mode. The same fixture source
// is copied a second time, its copied oasts.yaml switched to authEnforcement: runtime, and
// generated into a separate tree; the committed fixture is never touched. The runtime tree differs
// from the types tree ONLY in the compile-time CallArgs of each operation (runtime mode makes the
// options element always optional) — the emitted transport and execution path are byte-identical,
// so the runtime-mode reruns of the bearer, null-provider, and unsatisfiable-alternatives
// scenarios must observe identical wire bytes and identical failure shapes. Because the E2E
// consumes both trees through the identical untyped call site, the runtime-mode unsatisfiable
// rerun also exercises the documented edge: a missing-auth call that would be a compile error in
// types mode compiles in runtime mode and fails at runtime with the auth failure naming the tried
// alternatives.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { constants } from "node:fs";
import { access, cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { register } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import { BASIC_VECTORS } from "../test/vectors-auth-serialization.ts";
import {
  createScriptedServer,
  requiredFunction,
  requiredRecord,
  requestHeader,
  type CapturedRequest,
  type ExportedFunction,
} from "./harness.ts";

type GeneratedClient = {
  readonly createTransport: ExportedFunction;
  readonly inheritedRootOnly: ExportedFunction;
  readonly andBasicHeader: ExportedFunction;
  readonly orHeaderOauth: ExportedFunction;
  readonly queryKeyOp: ExportedFunction;
  readonly anonymousIncluded: ExportedFunction;
  readonly sameKindOr: ExportedFunction;
};

const repoRoot = path.resolve(import.meta.dirname, "../../../..");
const binary = path.join(repoRoot, "target/debug/oasts");
const fixtureSource = path.join(repoRoot, "fixtures/auth-showcase-3.1");
const hookUrl = new URL("./resolve-generated.mjs", import.meta.url);

const harness = createScriptedServer();
const { routes, requests, scriptRoute, requiredRequest } = harness;

const AUTHORIZATION_PREFIX = "Authorization: ";
// Per-operation tokens for the concurrency scenario: each concurrently-dispatched call must carry
// exactly its own token, correlated at the server by request URL.
const CONCURRENT_INHERITED_TOKEN = "concurrent-inherited-token";
const CONCURRENT_ANONYMOUS_TOKEN = "concurrent-anonymous-token";
const CONCURRENT_TOKEN: Readonly<Record<string, string>> = {
  inheritedRootOnly: CONCURRENT_INHERITED_TOKEN,
  anonymousIncluded: CONCURRENT_ANONYMOUS_TOKEN,
};
// Staggered so the operation dispatched first resolves its credential last, interleaving the two
// async credential resolutions — a transport that shared credential state would cross the tokens.
const CONCURRENT_DELAY_MS: Readonly<Record<string, number>> = {
  inheritedRootOnly: 40,
  anonymousIncluded: 10,
};

let baseUrl: string;
let temporaryRoot: string;
let typesClient: GeneratedClient;
let runtimeClient: GeneratedClient;

function scriptOkJson(url: string): void {
  scriptRoute("GET", url, {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from("{}"),
  });
}

function requestByUrl(url: string): CapturedRequest {
  const request = requests.find((candidate) => candidate.url === url);
  if (request === undefined) {
    throw new TypeError(`no captured request for ${url}`);
  }
  return request;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function authContextOperationId(context: unknown): string {
  const operationId = requiredRecord(context, "auth context").operationId;
  if (typeof operationId !== "string") {
    throw new TypeError("auth context operationId must be a string");
  }
  return operationId;
}

// The generated aggregate api and its own runtime transport, loaded from one generated tree.
async function loadClient(generatedRoot: string): Promise<GeneratedClient> {
  const transportModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "runtime/transport.ts")).href
  );
  const apiModule: unknown = await import(
    pathToFileURL(path.join(generatedRoot, "client/api.ts")).href
  );
  const createTransport = requiredFunction(transportModule, "createTransport");
  const api = requiredRecord(requiredRecord(apiModule, "aggregate module").api, "aggregate api");
  return {
    createTransport,
    inheritedRootOnly: requiredFunction(api, "inheritedRootOnly"),
    andBasicHeader: requiredFunction(api, "andBasicHeader"),
    orHeaderOauth: requiredFunction(api, "orHeaderOauth"),
    queryKeyOp: requiredFunction(api, "queryKeyOp"),
    anonymousIncluded: requiredFunction(api, "anonymousIncluded"),
    sameKindOr: requiredFunction(api, "sameKindOr"),
  };
}

function transportFor(client: GeneratedClient, config: Readonly<Record<string, unknown>>): unknown {
  return client.createTransport({ ...config, baseUrl });
}

function authError(resultValue: unknown, label: string): Readonly<Record<string, unknown>> {
  const result = requiredRecord(resultValue, `${label} result`);
  assert.equal(result.outcome, "auth");
  return result;
}

async function generateClient(name: string, toRuntimeMode: boolean): Promise<string> {
  const fixtureRoot = path.join(temporaryRoot, `auth-showcase-3.1-${name}`);
  await cp(fixtureSource, fixtureRoot, { recursive: true });
  if (toRuntimeMode) {
    const configPath = path.join(fixtureRoot, "oasts.yaml");
    const original = await readFile(configPath, "utf8");
    const patched = original.replace("authEnforcement: types", "authEnforcement: runtime");
    if (patched === original) {
      throw new Error("copied oasts.yaml did not contain authEnforcement: types to switch");
    }
    await writeFile(configPath, patched);
  }
  execFileSync(binary, ["generate", "--config", "oasts.yaml"], {
    cwd: fixtureRoot,
    stdio: "pipe",
  });
  return path.join(fixtureRoot, "generated");
}

// Scenarios reused across both enforcement modes; each proves identical runtime behavior.

async function assertBearerExactBytes(client: GeneratedClient, label: string): Promise<void> {
  // A bearerAuth provider token becomes exactly `Bearer <token>` on the wire.
  const token = "root-bearer-token-abc123";
  scriptOkJson("/inherited");
  const transport = transportFor(client, { auth: { bearerAuth: () => token } });
  const result = await client.inheritedRootOnly(transport, {});
  assert.equal(requests.length, 1);
  assert.equal(requestHeader(requiredRequest(0), "Authorization"), `Bearer ${token}`);
  assert.equal(requiredRecord(result, `${label} bearer result`).outcome, 200);
}

async function assertNullProviderFailsClosed(
  client: GeneratedClient,
  label: string,
): Promise<void> {
  // anonymousIncluded is bearerAuth OR anonymous: a null credentialed provider with no per-call
  // opt-in never silently downgrades to anonymous — it fails closed, sending nothing.
  const transport = transportFor(client, { auth: { bearerAuth: () => null } });
  const result = await client.anonymousIncluded(transport, {});
  const error = authError(result, `${label} null-provider`);
  assert.deepEqual(error.triedAlternatives, [["bearerAuth"]]);
  assert.equal(requests.length, 0);
}

async function assertUnsatisfiableFailsClosed(
  client: GeneratedClient,
  label: string,
): Promise<void> {
  // sameKindOr is bearerAuth OR bearerAlt with no configured source: an auth failure naming every
  // evaluated alternative, no request sent, and no credential value in the message.
  const transport = transportFor(client, {});
  const result = await client.sameKindOr(transport, {});
  const error = authError(result, `${label} unsatisfiable`);
  assert.deepEqual(error.triedAlternatives, [["bearerAuth"], ["bearerAlt"]]);
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(error.message), /Bearer /u);
}

before(async () => {
  try {
    await access(binary, constants.X_OK);
  } catch {
    throw new Error(`auth E2E requires ${binary}; run \`cargo build\` before this suite`);
  }

  temporaryRoot = await mkdtemp(path.join(tmpdir(), "oasts-auth-e2e-"));
  const typesGeneratedRoot = await generateClient("types", false);
  const runtimeGeneratedRoot = await generateClient("runtime", true);

  // One resolution hook rooted at the shared temp dir, which contains both generated trees:
  // the same hook module registered twice would share state and clobber the first root, so a
  // single registration whose root is the common ancestor covers both trees' `.js`→`.ts` retries.
  register(hookUrl, { data: { generatedRootUrl: pathToFileURL(temporaryRoot).href } });
  typesClient = await loadClient(typesGeneratedRoot);
  runtimeClient = await loadClient(runtimeGeneratedRoot);

  baseUrl = await harness.start();
});

beforeEach(() => {
  routes.clear();
  requests.length = 0;
});

after(async () => {
  await harness.stop();
  await rm(temporaryRoot, { recursive: true, force: true });
});

test("bearer provider sends exact Authorization bytes (types mode)", async () => {
  await assertBearerExactBytes(typesClient, "types");
});

test("basic provider serializes the frozen non-ASCII vector bytes", async () => {
  // The exact Basic bytes are derived from the frozen BASIC_VECTORS entry, never recomputed.
  const vector = BASIC_VECTORS.find((candidate) => candidate.name === "non-ascii-nfc");
  if (vector === undefined || typeof vector.expected !== "string") {
    throw new TypeError("BASIC_VECTORS is missing the non-ascii-nfc success vector");
  }
  if (!vector.expected.startsWith(AUTHORIZATION_PREFIX)) {
    throw new TypeError("basic vector expected must be a full Authorization header line");
  }
  const expectedAuthorization = vector.expected.slice(AUTHORIZATION_PREFIX.length);
  scriptOkJson("/and");
  // andBasicHeader is a single AND alternative (basicAuth AND headerKey); both are serialized and
  // only the basic Authorization bytes are asserted against the vector.
  const transport = transportFor(typesClient, {
    auth: {
      basicAuth: () => vector.input,
      headerKey: () => "header-key-companion",
    },
  });
  const result = await typesClient.andBasicHeader(transport, {});
  assert.equal(requests.length, 1);
  const received = requiredRequest(0);
  assert.equal(requestHeader(received, "Authorization"), expectedAuthorization);
  assert.equal(requestHeader(received, "X-Api-Key"), "header-key-companion");
  assert.equal(requiredRecord(result, "basic result").outcome, 200);
});

test("header API-key provider injects exact X-Api-Key bytes", async () => {
  // orHeaderOauth is headerKey OR oauthFlow; only headerKey is configured, so it is selected.
  const apiKey = "header-api-key-abc123";
  scriptOkJson("/or");
  const transport = transportFor(typesClient, { auth: { headerKey: () => apiKey } });
  const result = await typesClient.orHeaderOauth(transport, {});
  assert.equal(requests.length, 1);
  const received = requiredRequest(0);
  assert.equal(requestHeader(received, "X-Api-Key"), apiKey);
  assert.equal(requestHeader(received, "Authorization"), undefined);
  assert.equal(requiredRecord(result, "header key result").outcome, 200);
});

test("query API-key provider appends api_key with no Authorization header", async () => {
  // queryKeyOp carries no other query content, so api_key stands as the sole query field.
  const apiKey = "query-api-key-value123";
  const expectedUrl = `/query-key?api_key=${apiKey}`;
  scriptRoute("GET", expectedUrl, {
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: Buffer.from("{}"),
  });
  const transport = transportFor(typesClient, { auth: { queryKey: () => apiKey } });
  const result = await typesClient.queryKeyOp(transport, {});
  assert.equal(requests.length, 1);
  const received = requiredRequest(0);
  assert.equal(received.url, expectedUrl);
  assert.equal(requestHeader(received, "Authorization"), undefined);
  assert.equal(requiredRecord(result, "query key result").outcome, 200);
});

test("anonymous alternative sends unauthenticated when no providers are configured", async () => {
  // anonymousIncluded is bearerAuth OR anonymous; nothing credentialed is configured, so the
  // anonymous alternative is entered and the request goes out with no Authorization header.
  scriptOkJson("/anonymous");
  const transport = transportFor(typesClient, {});
  const result = await typesClient.anonymousIncluded(transport, {});
  assert.equal(requests.length, 1);
  assert.equal(requestHeader(requiredRequest(0), "Authorization"), undefined);
  assert.equal(requiredRecord(result, "anonymous result").outcome, 200);
});

test("null bearer provider without opt-in fails closed (types mode)", async () => {
  await assertNullProviderFailsClosed(typesClient, "types");
});

test("null bearer provider with anonymous opt-in sends unauthenticated after evaluating the credentialed alternative", async () => {
  // The 'anonymous' opt-in is permission, not a skip: the bearerAuth provider still runs (returns
  // null) before the anonymous fallback is taken and the unauthenticated request is sent.
  let invocations = 0;
  scriptOkJson("/anonymous");
  const transport = transportFor(typesClient, {
    auth: {
      bearerAuth: () => {
        invocations += 1;
        return null;
      },
    },
  });
  const result = await typesClient.anonymousIncluded(transport, {}, { auth: "anonymous" });
  assert.equal(requests.length, 1);
  assert.equal(requestHeader(requiredRequest(0), "Authorization"), undefined);
  assert.equal(invocations, 1);
  assert.equal(requiredRecord(result, "anonymous opt-in result").outcome, 200);
});

test("per-call bearer override wins and the transport provider is never invoked", async () => {
  // Per-call auth short-circuits selection, so token B reaches the wire and the provider (token A)
  // is never called.
  let invocations = 0;
  const providerToken = "provider-token-A";
  const perCallToken = "per-call-token-B";
  scriptOkJson("/inherited");
  const transport = transportFor(typesClient, {
    auth: {
      bearerAuth: () => {
        invocations += 1;
        return providerToken;
      },
    },
  });
  const result = await typesClient.inheritedRootOnly(
    transport,
    {},
    {
      auth: { bearerAuth: perCallToken },
    },
  );
  assert.equal(requests.length, 1);
  assert.equal(requestHeader(requiredRequest(0), "Authorization"), `Bearer ${perCallToken}`);
  assert.equal(invocations, 0);
  assert.equal(requiredRecord(result, "override result").outcome, 200);
});

test("unsatisfiable same-kind alternatives fail closed with tried alternatives (types mode)", async () => {
  await assertUnsatisfiableFailsClosed(typesClient, "types");
});

test("concurrent requests carry isolated per-call credentials", async () => {
  // Two operations share one transport whose async bearerAuth provider returns a per-operation
  // token after a staggered delay. Firing both with Promise.all interleaves the two credential
  // resolutions; each captured request must still carry exactly its own token.
  const providerCalls: string[] = [];
  scriptOkJson("/inherited");
  scriptOkJson("/anonymous");
  const transport = transportFor(typesClient, {
    auth: {
      bearerAuth: async (context: unknown): Promise<string> => {
        const operationId = authContextOperationId(context);
        providerCalls.push(operationId);
        const token = CONCURRENT_TOKEN[operationId];
        const delayMs = CONCURRENT_DELAY_MS[operationId];
        if (token === undefined || delayMs === undefined) {
          throw new TypeError(`unexpected operationId ${operationId}`);
        }
        await delay(delayMs);
        return token;
      },
    },
  });
  const [inheritedResult, anonymousResult] = await Promise.all([
    typesClient.inheritedRootOnly(transport, {}),
    typesClient.anonymousIncluded(transport, {}),
  ]);
  assert.equal(requests.length, 2);
  assert.equal(
    requestHeader(requestByUrl("/inherited"), "Authorization"),
    `Bearer ${CONCURRENT_INHERITED_TOKEN}`,
  );
  assert.equal(
    requestHeader(requestByUrl("/anonymous"), "Authorization"),
    `Bearer ${CONCURRENT_ANONYMOUS_TOKEN}`,
  );
  assert.deepEqual(providerCalls.toSorted(), ["anonymousIncluded", "inheritedRootOnly"]);
  assert.equal(requiredRecord(inheritedResult, "concurrent inherited result").outcome, 200);
  assert.equal(requiredRecord(anonymousResult, "concurrent anonymous result").outcome, 200);
});

test("bearer provider sends exact Authorization bytes (runtime mode)", async () => {
  await assertBearerExactBytes(runtimeClient, "runtime");
});

test("null bearer provider without opt-in fails closed (runtime mode)", async () => {
  await assertNullProviderFailsClosed(runtimeClient, "runtime");
});

test("unsatisfiable same-kind alternatives fail closed with tried alternatives (runtime mode)", async () => {
  // In runtime mode this missing-auth call compiles (the generated options element is optional)
  // and fails at runtime with the same auth failure and tried alternatives as types mode.
  await assertUnsatisfiableFailsClosed(runtimeClient, "runtime");
});
