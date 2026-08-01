import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";

import { serializeQueryForm } from "../serialize.ts";
import { isRequestPhaseFailure, requestFailure } from "./result-narrowing.ts";
import {
  createTransport,
  execute,
  jsonBody,
  type OperationDescriptor,
  type ParamPlan,
} from "../transport.ts";

// The real Request, captured before any per-test override. StrippingRequest emulates a browser: the
// WHATWG Fetch forbidden-request-header list drops `Cookie` during Request construction. Node's real
// undici keeps it, which is what the un-overridden layer-1 tests exercise.
const RealRequest = globalThis.Request;

class StrippingRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    if (init?.headers === undefined) {
      super(input, init);
      return;
    }
    const headers = new Headers(init.headers);
    headers.delete("cookie");
    super(input, { ...init, headers });
  }
}

function installStrippingRequest(): void {
  globalThis.Request = StrippingRequest;
}

// Emulates a body-consuming middleware: reconstructing the dispatch probe from a Request whose body
// was already read throws TypeError, exactly the copy-construct failure the dispatch guard performs.
class UnreconstructableRequest extends Request {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    if (input instanceof Request) {
      throw new TypeError("Request body is already used");
    }
    super(input, init);
  }
}

afterEach(() => {
  globalThis.Request = RealRequest;
  Reflect.deleteProperty(globalThis, "document");
  Reflect.deleteProperty(globalThis, "location");
});

const SAME_ORIGIN = "https://api.cookie.test";

function cookieOperation(params: readonly ParamPlan[]): OperationDescriptor {
  return {
    operationId: "cookieOp",
    method: "GET",
    path: [[{ kind: "literal", text: "/resource" }]],
    params,
    body: null,
    accept: null,
    credentialHeaders: [],
    security: null,
    responses: [],
    baseUrl: { kind: "literal", value: `${SAME_ORIGIN}/v1` },
    fetchDefaults: {},
  };
}

function cookieParam(name: string, required: boolean): ParamPlan {
  return {
    name,
    location: "cookie",
    required,
    // A cookie parameter reuses the query-form serializer; location drives Cookie framing.
    serialize: serializeQueryForm,
    allowReserved: false,
  };
}

const sid = cookieParam("sid", true);
const theme = cookieParam("theme", false);

// A minimal document.cookie jar. Reading returns the whole "a=1; b=2" string; assigning parses off
// the trailing attributes (path, etc.) and stores only the name=value pair, exactly as the browser
// accessor does — the getter never echoes attributes. `writes` records the raw assigned strings so a
// test can assert the attributes that were sent (e.g. an explicit `; path=/`).
type MutableJar = {
  cookie: string;
  readValue(name: string): string | null;
  readonly writes: readonly string[];
};

function storeCookiePair(store: Map<string, string>, pair: string): void {
  const attributesStart = pair.indexOf(";");
  const nameValue = attributesStart === -1 ? pair : pair.slice(0, attributesStart);
  const separator = nameValue.indexOf("=");
  store.set(nameValue.slice(0, separator), nameValue.slice(separator + 1));
}

function makeJar(initial: string): MutableJar {
  const store = new Map<string, string>();
  const writes: string[] = [];
  if (initial.length !== 0) {
    for (const entry of initial.split("; ")) {
      storeCookiePair(store, entry);
    }
  }
  return {
    get cookie(): string {
      return Array.from(store, ([name, value]) => `${name}=${value}`).join("; ");
    },
    set cookie(pair: string) {
      writes.push(pair);
      storeCookiePair(store, pair);
    },
    readValue(name: string): string | null {
      return store.get(name) ?? null;
    },
    get writes(): readonly string[] {
      return writes;
    },
  };
}

describe("cookie parameter dispatch", () => {
  test("layer 1: undici keeps the joined Cookie header in declared order", async () => {
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response(null, { status: 204 });
      },
    });
    const descriptor = cookieOperation([
      {
        name: "region",
        location: "query",
        required: false,
        serialize: serializeQueryForm,
        allowReserved: false,
      },
      sid,
      theme,
      cookieParam("absent", false),
    ]);

    const result = await execute(transport, descriptor, {
      query: { region: "us" },
      cookie: { sid: "abc", theme: "dark" },
    });

    assert.ok(captured);
    // The guard inspects the actual constructed Request; the custom fetch receives that probe.
    assert.equal(captured.headers.get("cookie"), "sid=abc; theme=dark");
    // A query parameter is not a cookie, and an absent optional cookie is skipped.
    assert.equal(captured.url, `${SAME_ORIGIN}/v1/resource?region=us`);
    assert.ok(!isRequestPhaseFailure(result));
  });

  test("layer 1: a POST JSON body survives the cookie probe reconstruction", async () => {
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response(null, { status: 204 });
      },
    });
    const descriptor: OperationDescriptor = {
      ...cookieOperation([sid, theme]),
      method: "POST",
      body: jsonBody("application/json"),
    };
    const payload = { name: "Ada", nested: { count: 2 } };

    const result = await execute(transport, descriptor, {
      cookie: { sid: "abc", theme: "dark" },
      body: payload,
    });

    assert.ok(captured);
    // Adding the Cookie header rebuilds the Request; the JSON body must transfer to the probe rather
    // than be consumed by the reconstruction — the probe body hazard the guard flags.
    assert.equal(captured.headers.get("cookie"), "sid=abc; theme=dark");
    assert.equal(captured.headers.get("content-type"), "application/json");
    assert.equal(await captured.text(), JSON.stringify(payload));
    assert.ok(!isRequestPhaseFailure(result));
  });

  test("no present cookie parameter leaves dispatch untouched", async () => {
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response(null, { status: 204 });
      },
    });

    await execute(transport, cookieOperation([theme]), { cookie: {} });

    assert.ok(captured);
    assert.equal(captured.headers.get("cookie"), null);
  });

  test("layer 1 -> 3: a stripping environment with no document fails, naming the params", async () => {
    installStrippingRequest();
    let sends = 0;
    const result = requestFailure(
      await execute(
        createTransport({
          fetch: async () => {
            sends += 1;
            return new Response();
          },
        }),
        cookieOperation([sid, theme]),
        { cookie: { sid: "abc", theme: "dark" } },
      ),
    );

    assert.equal(sends, 0);
    assert.equal(result.outcome, "cookie-params-unsendable");
    assert.deepEqual(result.names, ["sid", "theme"]);
  });

  test("layer 2: a same-origin document jar carries the cookies and the probe is dispatched", async () => {
    installStrippingRequest();
    const jar = makeJar("prior=1");
    Reflect.set(globalThis, "document", jar);
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    let captured: Request | undefined;
    const transport = createTransport({
      fetch: async (request) => {
        captured = request;
        return new Response(null, { status: 204 });
      },
    });

    const result = await execute(transport, cookieOperation([sid, theme]), {
      cookie: { sid: "abc", theme: "dark" },
    });

    assert.ok(captured);
    // The dispatched probe carries no Cookie header — the document jar delivers the cookies.
    assert.equal(captured.headers.get("cookie"), null);
    assert.equal(jar.readValue("sid"), "abc");
    assert.equal(jar.readValue("theme"), "dark");
    assert.ok(!isRequestPhaseFailure(result));
  });

  test("layer 2 writes each cookie with an explicit path=/ so it scopes to the API route", async () => {
    installStrippingRequest();
    const jar = makeJar("");
    Reflect.set(globalThis, "document", jar);
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    const result = await execute(
      createTransport({ fetch: async () => new Response(null, { status: 204 }) }),
      cookieOperation([sid, theme]),
      { cookie: { sid: "abc", theme: "dark" } },
    );

    assert.ok(!isRequestPhaseFailure(result));
    // Without an explicit path the browser scopes the cookie to the document's default path, which
    // can exclude the API route even though the read-back (from the document URL) verifies.
    assert.deepEqual(jar.writes, ["sid=abc; path=/", "theme=dark; path=/"]);
    assert.equal(jar.readValue("sid"), "abc");
    assert.equal(jar.readValue("theme"), "dark");
  });

  test("layer 2 -> 3: credentials 'omit' attaches nothing, so it falls through to failure", async () => {
    installStrippingRequest();
    const jar = makeJar("");
    Reflect.set(globalThis, "document", jar);
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    let sends = 0;
    const result = requestFailure(
      await execute(
        createTransport({
          credentials: "omit",
          fetch: async () => {
            sends += 1;
            return new Response();
          },
        }),
        cookieOperation([sid]),
        { cookie: { sid: "abc" } },
      ),
    );

    assert.equal(sends, 0);
    // A jar read-back would falsely verify, so the guard must stop before writing: the browser
    // attaches nothing in omit mode, which is the silent drop cookie-params-unsendable exists to catch.
    assert.deepEqual(jar.writes, []);
    assert.equal(result.outcome, "cookie-params-unsendable");
    assert.deepEqual(result.names, ["sid"]);
  });

  test("layer 2 -> 3: a document that rejects the write falls through to failure", async () => {
    installStrippingRequest();
    const store = new Map<string, string>();
    const rejectingJar = {
      get cookie(): string {
        // The browser rejected every write, so the read-back is always empty.
        return "";
      },
      set cookie(pair: string) {
        const attributesStart = pair.indexOf(";");
        const nameValue = attributesStart === -1 ? pair : pair.slice(0, attributesStart);
        const separator = nameValue.indexOf("=");
        store.set(nameValue.slice(0, separator), nameValue.slice(separator + 1));
      },
    };
    Reflect.set(globalThis, "document", rejectingJar);
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    let sends = 0;
    const result = requestFailure(
      await execute(
        createTransport({
          fetch: async () => {
            sends += 1;
            return new Response();
          },
        }),
        cookieOperation([sid]),
        { cookie: { sid: "abc" } },
      ),
    );

    assert.equal(sends, 0);
    assert.equal(store.get("sid"), "abc");
    assert.equal(result.outcome, "cookie-params-unsendable");
    assert.deepEqual(result.names, ["sid"]);
  });

  test("layer 3: a cross-origin document is not used", async () => {
    installStrippingRequest();
    Reflect.set(globalThis, "document", makeJar(""));
    Reflect.set(globalThis, "location", { origin: "https://evil.test" });
    const result = requestFailure(
      await execute(
        createTransport({ fetch: async () => new Response() }),
        cookieOperation([sid]),
        { cookie: { sid: "abc" } },
      ),
    );

    assert.equal(result.outcome, "cookie-params-unsendable");
    assert.deepEqual(result.names, ["sid"]);
  });

  test("layer 3: malformed document shapes are rejected by the cookie-jar guard", async () => {
    installStrippingRequest();
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    for (const badDocument of [null, {}, { cookie: 42 }]) {
      Reflect.set(globalThis, "document", badDocument);
      const result = requestFailure(
        await execute(
          createTransport({ fetch: async () => new Response() }),
          cookieOperation([sid]),
          { cookie: { sid: "abc" } },
        ),
      );
      assert.equal(result.outcome, "cookie-params-unsendable");
    }
  });

  test("a probe reconstruction TypeError is caught, not thrown", async () => {
    // The dispatch guard rebuilds the Request; a consumed body makes that throw. The stage used to
    // sit outside try/catch, so the TypeError escaped as a rejection, breaking never-throws.
    globalThis.Request = UnreconstructableRequest;
    const result = requestFailure(
      await execute(
        createTransport({ fetch: async () => new Response() }),
        cookieOperation([sid]),
        { cookie: { sid: "abc" } },
      ),
    );
    assert.equal(result.outcome, "request-encode");
  });

  test("a hostile document.cookie getter is caught, not thrown", async () => {
    installStrippingRequest();
    Reflect.set(globalThis, "location", { origin: SAME_ORIGIN });
    Reflect.set(globalThis, "document", {
      get cookie(): string {
        throw new Error("SecurityError: cookie access is blocked");
      },
      set cookie(_pair: string) {},
    });
    const result = requestFailure(
      await execute(
        createTransport({ fetch: async () => new Response() }),
        cookieOperation([sid]),
        { cookie: { sid: "abc" } },
      ),
    );
    assert.equal(result.outcome, "request-encode");
  });

  test("layer 3: malformed location shapes are rejected by the same-origin guard", async () => {
    installStrippingRequest();
    Reflect.set(globalThis, "document", makeJar(""));
    for (const badLocation of [undefined, null, {}, { origin: 42 }]) {
      if (badLocation === undefined) {
        Reflect.deleteProperty(globalThis, "location");
      } else {
        Reflect.set(globalThis, "location", badLocation);
      }
      const result = requestFailure(
        await execute(
          createTransport({ fetch: async () => new Response() }),
          cookieOperation([sid]),
          { cookie: { sid: "abc" } },
        ),
      );
      assert.equal(result.outcome, "cookie-params-unsendable");
    }
  });
});
