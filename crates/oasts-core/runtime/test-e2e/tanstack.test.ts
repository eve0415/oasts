// The generated tanstack artifact driven through a real TanStack `QueryClient`.
//
// Everything else that covers this artifact reasons about it structurally: the compile-assert
// matrix pins the descriptor's types against locally declared option shapes, and the conformance
// runner hashes emitted keys against frozen vectors. Neither can tell whether a real cache accepts
// a descriptor, whether the keys it builds actually partition that cache, or whether a cancellation
// travels from the cache down to the request the transport dispatched. That is what this suite is
// for, so it uses `@tanstack/query-core` itself — no framework, no DOM.
//
// Locating the output: set OASTS_TANSTACK_GENERATED_ROOT to the generated root (the directory that
// contains `tanstack/`, `client/` and `runtime/`) produced by generating
// fixtures/tanstack-showcase-3.1 under its default config. When the variable is unset or that tree
// has no `tanstack/` directory, the suite skips with a diagnostic, so `node --test` over this
// directory stays green before the artifact is generated.
//
// The generated tree imports its siblings with `.js` specifiers over on-disk `.ts` files, so this
// suite reuses ./resolve-generated.mjs to retry a failing `.js` resolution at the sibling `.ts`
// path, exactly as the client end-to-end suite does. Generated modules are loaded across the
// dynamic-import boundary as `unknown` and narrowed by the harness guards, so no generated symbol
// is imported at type-check time — the tree is gitignored and absent on a fresh checkout.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { register } from "node:module";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { pathToFileURL } from "node:url";

import { hashKey, QueryClient } from "@tanstack/query-core";

import {
  createScriptedServer,
  requiredFunction,
  requiredRecord,
  type ExportedFunction,
  type ScriptedResponse,
} from "./harness.ts";

/** The structural half of a query descriptor: what an adapter needs and what this suite drives. */
type QueryDescriptor = {
  readonly queryKey: readonly unknown[];
  readonly queryFn: ExportedFunction;
};

// The failed branch GetPetQueryError carries — `ApiError<Extract<GetPetResult, { ok: false }>>`
// narrowed to the operation's one documented failure. The generated type is deliberately NOT
// imported: the fixture tree is gitignored, so a static import would break the type gate on a fresh
// checkout. Restating the shape here and assigning the thrown value to it is the type-level half of
// the 404 assertion below; the identity `GetPetQueryError === ApiError<Extract<GetPetResult, { ok:
// false }>>` is pinned in fixtures/tanstack-showcase-3.1/compile-assert/cases.ts, which tsc runs
// against the generated tree.
type GetPetTypedFailure = {
  readonly outcome: 404;
  readonly ok: false;
  readonly status: 404;
  readonly error: { readonly message: string };
};

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function isGetPetTypedFailure(value: unknown): value is GetPetTypedFailure {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  if (!("outcome" in value) || value.outcome !== 404) {
    return false;
  }
  if (!("ok" in value) || value.ok !== false) {
    return false;
  }
  if (!("status" in value) || value.status !== 404) {
    return false;
  }
  if (!("error" in value) || typeof value.error !== "object" || value.error === null) {
    return false;
  }
  return "message" in value.error && typeof value.error.message === "string";
}

function asQueryDescriptor(value: unknown, label: string): QueryDescriptor {
  const descriptor = requiredRecord(value, `${label} descriptor`);
  const queryKey = descriptor.queryKey;
  if (!isUnknownArray(queryKey)) {
    assert.fail(`${label}: the descriptor's queryKey is not an array`);
  }
  return { queryKey, queryFn: requiredFunction(descriptor, "queryFn") };
}

function affectsOf(value: unknown, label: string): readonly (readonly unknown[])[] {
  if (!isUnknownArray(value)) {
    assert.fail(`${label}: the invalidation list is not an array`);
  }
  return value.map((entry, index) => {
    if (!isUnknownArray(entry)) {
      assert.fail(`${label}: invalidation entry ${String(index)} is not a query key array`);
    }
    return entry;
  });
}

/** Resolves the reason a promise rejected with, and fails the test when it resolves instead. */
async function rejection(promise: Promise<unknown>, label: string): Promise<unknown> {
  const resolved = Symbol("resolved");
  const outcome: unknown = await promise.then(
    () => resolved,
    (error: unknown) => error,
  );
  if (outcome === resolved) {
    assert.fail(`${label}: expected a rejection, but the query resolved`);
  }
  return outcome;
}

function jsonResponse(status: number, body: string): ScriptedResponse {
  return { status, headers: [["Content-Type", "application/json"]], body: Buffer.from(body) };
}

// A transport `fetch` that never settles on its own, so a test controls exactly when — and by which
// route — the in-flight request ends. It also hands back the Request it was dispatched with, which
// is the only place the merged signal can be observed from outside the transport.
type HangingFetch = {
  readonly fetch: (request: Request) => Promise<Response>;
  readonly dispatched: Promise<Request>;
};

function createHangingFetch(): HangingFetch {
  let announce: ((request: Request) => void) | undefined;
  const dispatched = new Promise<Request>((resolve) => {
    announce = resolve;
  });
  return {
    dispatched,
    fetch: (request) =>
      new Promise<Response>((_resolve, reject) => {
        announce?.(request);
        if (request.signal.aborted) {
          reject(request.signal.reason);
          return;
        }
        request.signal.addEventListener("abort", () => {
          reject(request.signal.reason);
        });
      }),
  };
}

const generatedRoot = process.env.OASTS_TANSTACK_GENERATED_ROOT;

const skip =
  generatedRoot === undefined
    ? "set OASTS_TANSTACK_GENERATED_ROOT to the generated output root to run the tanstack E2E suite"
    : existsSync(path.join(generatedRoot, "tanstack"))
      ? undefined
      : `OASTS_TANSTACK_GENERATED_ROOT (${generatedRoot}) has no tanstack/ directory; generate the tanstack artifact first`;

if (skip !== undefined || generatedRoot === undefined) {
  test("tanstack end to end", { skip: skip ?? "no generated tree" }, () => {});
} else {
  const root: string = generatedRoot;

  register(new URL("./resolve-generated.mjs", import.meta.url), {
    data: { generatedRootUrl: pathToFileURL(root).href },
  });

  async function generated(file: string): Promise<unknown> {
    return import(pathToFileURL(path.join(root, file)).href);
  }

  const createTransport = requiredFunction(
    await generated("runtime/transport.ts"),
    "createTransport",
  );
  const ApiError = requiredFunction(await generated("runtime/result.ts"), "ApiError");
  const listPetsQuery = requiredFunction(
    await generated("tanstack/operations/listpets.ts"),
    "listPetsQuery",
  );
  const getPetQuery = requiredFunction(
    await generated("tanstack/operations/getpet.ts"),
    "getPetQuery",
  );
  const getMyPetQuery = requiredFunction(
    await generated("tanstack/operations/getmypet.ts"),
    "getMyPetQuery",
  );
  const searchQuery = requiredFunction(
    await generated("tanstack/operations/search.ts"),
    "searchQuery",
  );
  const updatePetModule = await generated("tanstack/operations/updatepet.ts");
  const updatePetMutation = requiredFunction(updatePetModule, "updatePetMutation");
  const updatePetMutationAffects = requiredFunction(updatePetModule, "updatePetMutationAffects");

  const harness = createScriptedServer();
  const { requests, routes, scriptRoute } = harness;

  let baseUrl: string;
  let transport: unknown;
  let client: QueryClient;

  function countRequests(method: string, url: string): number {
    return requests.filter((request) => request.method === method && request.url === url).length;
  }

  before(async () => {
    baseUrl = await harness.start();
    transport = createTransport({ baseUrl });
  });

  beforeEach(() => {
    routes.clear();
    requests.length = 0;
    // A fresh cache per test, so `getQueryCache().getAll()` means "what this test put there".
    // `retry: false` keeps request counts honest, and an infinite gcTime schedules no collection
    // timer, which would otherwise keep the runner's event loop alive well past the last assertion.
    client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Number.POSITIVE_INFINITY } },
    });
  });

  after(async () => {
    await harness.stop();
  });

  test("a mutation's invalidation list refetches exactly the queries it names", async () => {
    scriptRoute("GET", "/pets", jsonResponse(200, '[{"id":"7","name":"Rex"}]'));
    scriptRoute("GET", "/pets/7", jsonResponse(200, '{"id":"7","name":"Rex"}'));
    scriptRoute("GET", "/search?q=cat", jsonResponse(200, "[]"));
    scriptRoute("PUT", "/pets/7", jsonResponse(200, '{"id":"7","name":"Rexy"}'));

    const collection = asQueryDescriptor(listPetsQuery(transport, {}), "listPetsQuery");
    const entity = asQueryDescriptor(
      getPetQuery(transport, { path: { petId: "7" } }),
      "getPetQuery",
    );
    const unrelated = asQueryDescriptor(
      searchQuery(transport, { query: { q: "cat" } }),
      "searchQuery",
    );

    await client.fetchQuery(collection);
    await client.fetchQuery(entity);
    await client.fetchQuery(unrelated);
    assert.equal(countRequests("GET", "/pets"), 1);
    assert.equal(countRequests("GET", "/pets/7"), 1);
    assert.equal(countRequests("GET", "/search?q=cat"), 1);

    const input = { path: { petId: "7" }, body: { name: "Rexy" } };
    const mutationFn = requiredFunction(updatePetMutation(transport), "mutationFn");
    const mutated = requiredRecord(await mutationFn(input), "updatePet payload");
    assert.equal(mutated.name, "Rexy");

    const seededPets = countRequests("GET", "/pets");
    const seededEntity = countRequests("GET", "/pets/7");
    const seededSearch = countRequests("GET", "/search?q=cat");

    // What an application does with the emitted list: hand every entry to invalidateQueries.
    // `refetchType: "all"` because these queries have no observers here — the default only refetches
    // active ones, and "was it refetched" is the property under test.
    const affects = affectsOf(updatePetMutationAffects(input), "updatePetMutationAffects");
    assert.equal(affects.length, 2);
    for (const entry of affects) {
      await client.invalidateQueries({ queryKey: entry, refetchType: "all" });
    }

    // The collection key is a prefix of the entity key, so one invalidation may already cover both;
    // the contract is that each named query refetched at least once and the unnamed one never did.
    assert.ok(countRequests("GET", "/pets") > seededPets, "the collection query did not refetch");
    assert.ok(countRequests("GET", "/pets/7") > seededEntity, "the entity query did not refetch");
    assert.equal(
      countRequests("GET", "/search?q=cat"),
      seededSearch,
      "a query under an unrelated key root refetched",
    );
  });

  test("a literal path segment and a parameter of the same text are two cache entries", async () => {
    // Both queries request the same URL. If the key factory rendered the literal segment the way it
    // renders a parameter value, they would share one cache entry and one would serve the other's
    // data — so the distinctness is asserted through TanStack's own hasher, not through our arrays.
    scriptRoute("GET", "/pets/mine", jsonResponse(200, '{"id":"mine","name":"Rex"}'));

    const literal = asQueryDescriptor(getMyPetQuery(transport, {}), "getMyPetQuery");
    const parameter = asQueryDescriptor(
      getPetQuery(transport, { path: { petId: "mine" } }),
      "getPetQuery",
    );

    await client.fetchQuery(literal);
    await client.fetchQuery(parameter);
    assert.equal(countRequests("GET", "/pets/mine"), 2);

    const cached = client.getQueryCache().getAll();
    assert.equal(cached.length, 2, "the two queries did not produce two cache entries");
    assert.deepStrictEqual(
      cached.map((query) => query.queryHash).toSorted(),
      [hashKey(literal.queryKey), hashKey(parameter.queryKey)].toSorted(),
    );

    await client.invalidateQueries({ queryKey: literal.queryKey, refetchType: "all" });
    assert.equal(
      countRequests("GET", "/pets/mine"),
      3,
      "the literal-segment query did not refetch",
    );

    const parameterEntry = cached.find((query) => query.queryHash === hashKey(parameter.queryKey));
    assert.ok(parameterEntry !== undefined, "the parameter query left no cache entry");
    assert.equal(
      parameterEntry.state.isInvalidated,
      false,
      "invalidating the literal-segment query also invalidated the parameter query",
    );
  });

  test("cancelling through the QueryClient aborts the request the transport dispatched", async () => {
    const hanging = createHangingFetch();
    const hangingTransport = createTransport({ baseUrl, fetch: hanging.fetch });
    const descriptor = asQueryDescriptor(
      getPetQuery(hangingTransport, { path: { petId: "7" } }),
      "getPetQuery",
    );

    const pending = client.fetchQuery(descriptor);
    const dispatched = await hanging.dispatched;
    assert.equal(dispatched.signal.aborted, false);

    await client.cancelQueries({ queryKey: descriptor.queryKey });

    // The signal TanStack hands the queryFn reaches the dispatched Request through
    // withRequestSignal's AbortSignal.any merge. The query's own promise rejects with query-core's
    // CancelledError rather than the client's outcome, because cancelQueries reverts the query.
    assert.equal(dispatched.signal.aborted, true);
    await rejection(pending, "cancelled query");
  });

  test("a caller signal in CallOptions aborts the request and surfaces as the aborted outcome", async () => {
    const hanging = createHangingFetch();
    const hangingTransport = createTransport({ baseUrl, fetch: hanging.fetch });
    const controller = new AbortController();
    const descriptor = asQueryDescriptor(
      getPetQuery(hangingTransport, { path: { petId: "7" } }, { signal: controller.signal }),
      "getPetQuery",
    );

    const pending = client.fetchQuery(descriptor);
    const dispatched = await hanging.dispatched;
    assert.equal(dispatched.signal.aborted, false);

    controller.abort();
    assert.equal(dispatched.signal.aborted, true);

    // Nothing cancelled the query itself, so the failure travels back out of the client as its own
    // aborted outcome rather than being replaced by the cache's cancellation.
    const error = await rejection(pending, "caller-aborted query");
    assert.ok(error instanceof ApiError);
    const result = requiredRecord(requiredRecord(error, "ApiError").result, "ApiError result");
    assert.equal(result.outcome, "aborted");
    assert.equal(result.ok, false);
  });

  test("a documented 404 rejects the query with the typed failure branch", async () => {
    scriptRoute("GET", "/pets/missing", jsonResponse(404, '{"message":"no such pet"}'));

    const descriptor = asQueryDescriptor(
      getPetQuery(transport, { path: { petId: "missing" } }),
      "getPetQuery",
    );

    const error = await rejection(client.fetchQuery(descriptor), "getPet 404");
    assert.ok(error instanceof Error);
    assert.ok(error instanceof ApiError);
    assert.equal(error.name, "ApiError");
    const result = requiredRecord(error, "ApiError").result;

    assert.ok(
      isGetPetTypedFailure(result),
      "the thrown ApiError does not carry the operation's documented 404 branch",
    );
    // Assigning the narrowed value to the restated GetPetQueryError branch is the type-level half:
    // this line stops compiling if the runtime shape and the declared shape drift apart.
    const typed: GetPetTypedFailure = result;
    assert.equal(typed.outcome, 404);
    assert.equal(typed.status, 404);
    assert.equal(typed.ok, false);
    assert.equal(typed.error.message, "no such pet");
  });
}
