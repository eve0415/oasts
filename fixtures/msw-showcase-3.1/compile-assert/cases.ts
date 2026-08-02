// Type-level assertions for the MSW handler artifact.
//
// Authored from the pinned handler contract before the emitter existed, and frozen: the
// implementation is written to satisfy this file, never the reverse. It has no runtime behavior
// and is typechecked only after the emitter writes the sibling ../generated-msw tree, so it does
// NOT typecheck today.
//
// It is typechecked TWICE — once with exactOptionalPropertyTypes off and once on. The no-payload
// guard below is the reason: an optional `never` still admits `undefined` when that flag is off,
// so a guard resting on `?: never` would pass one run and fail the other.
//
// Imports use `.js` suffixes because emit.importExtension resolves to `.js` over the on-disk `.ts`.

import { http, passthrough } from "msw";

import { getPetMockHandler } from "../generated-msw/msw/handlers/getpetmock.js";
import { createPetMockHandler } from "../generated-msw/msw/handlers/createpetmock.js";
import { headHealthMockHandler } from "../generated-msw/msw/handlers/headhealthmock.js";
import { uploadMultipartMockHandler } from "../generated-msw/msw/handlers/uploadmultipartmock.js";
import { getReportMockHandler } from "../generated-msw/msw/handlers/getreportmock.js";
import { OastsHandlerError } from "../generated-msw/msw/runtime.js";
import type { Pet } from "../generated-msw/types/components/pet.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// ---------------------------------------------------------------------------
// 1. Request projection. Values arrive decoded by the inverse of their declared
//    serialization, never as the raw strings MSW hands a hand-written handler.
// ---------------------------------------------------------------------------

getPetMockHandler(({ request, params, query, headers, cookies, respond }) => {
  const petId: number = params.petId;
  const tags: readonly string[] | undefined = query.tags;
  const minAge: number | undefined = query.filter?.minAge;
  const requestId: string | undefined = headers["X-Request-Id"];
  void petId;
  void tags;
  void minAge;
  void requestId;

  // The raw Request stays reachable for anything the projection does not cover.
  const url: string = request.url;
  void url;
  // MSW's own cookie record is passed through unchanged.
  const raw: Record<string, string> = cookies;
  void raw;

  // @ts-expect-error a path parameter declared as an integer is not a string here
  const wrong: string = params.petId;
  void wrong;

  // @ts-expect-error the document declares no such parameter
  void query.undeclared;

  return respond({ match: 204, status: 204 });
});

// A label-style array path parameter still projects to its declared array type.
getReportMockHandler(({ params, query, cookies, respond }) => {
  const reportId: readonly string[] = params.reportId;
  const window: readonly string[] | undefined = query.window;
  const session: string | undefined = cookies.session;
  void reportId;
  void window;
  void session;
  return respond({
    match: 200,
    status: 200,
    contentType: "application/octet-stream",
    body: new Uint8Array([1, 2, 3]),
  });
});

// A multipart body projects per-part, with the JSON part decoded and the binary part as bytes.
uploadMultipartMockHandler(({ body, respond }) => {
  const name: string = body.meta.name;
  const file: Uint8Array = body.file;
  void name;
  void file;
  return respond({
    match: 200,
    status: 200,
    contentType: "application/json",
    body: { id: 1, name },
  });
});

// ---------------------------------------------------------------------------
// 2. `respond` correlates match, status, contentType and body.
// ---------------------------------------------------------------------------

getPetMockHandler(({ respond }) =>
  respond({ match: 200, status: 200, contentType: "application/json", body: { id: 1, name: "a" } })
);

// The same status declares a second media type carrying a different schema.
getPetMockHandler(({ respond }) =>
  respond({ match: 200, status: 200, contentType: "text/plain", body: "Bella" })
);

getPetMockHandler(({ respond }) =>
  // @ts-expect-error the text arm's body is a string, not the JSON schema
  respond({ match: 200, status: 200, contentType: "text/plain", body: { id: 1, name: "a" } })
);

getPetMockHandler(({ respond }) =>
  // @ts-expect-error the document declares no image/png entry on this response
  respond({ match: 200, status: 200, contentType: "image/png", body: "x" })
);

getPetMockHandler(({ respond }) =>
  // @ts-expect-error 418 is not a declared response key for this operation
  respond({ match: 418, status: 418, contentType: "application/json", body: { message: "x" } })
);

// A range key keeps the broad number status, since excluding literals from number is inexpressible.
getPetMockHandler(({ respond }) =>
  respond({ match: "4XX", status: 404, contentType: "application/json", body: { message: "gone" } })
);

getPetMockHandler(({ respond }) =>
  respond({ match: "default", status: 500, contentType: "application/json", body: { message: "x" } })
);

// An exact key's status is the literal it was declared under.
createPetMockHandler(({ body, respond }) => {
  const name: string = body.name;
  return respond({ match: 201, status: 201, contentType: "application/json", body: { id: 1, name } });
});

createPetMockHandler(({ respond }) =>
  // @ts-expect-error an exact declared key fixes its own status
  respond({ match: 201, status: 200, contentType: "application/json", body: { id: 1, name: "a" } })
);

// ---------------------------------------------------------------------------
// 3. The no-payload guard. These are the pairs that must behave identically
//    under both exactOptionalPropertyTypes settings.
// ---------------------------------------------------------------------------

// Positive: absence is the only accepted form.
getPetMockHandler(({ respond }) => respond({ match: 204, status: 204 }));
headHealthMockHandler(({ respond }) => respond({ match: 200, status: 200 }));

getPetMockHandler(({ respond }) =>
  // @ts-expect-error a no-payload branch rejects an explicitly undefined body
  respond({ match: 204, status: 204, body: undefined })
);

getPetMockHandler(({ respond }) =>
  // @ts-expect-error a no-payload branch rejects an explicitly undefined contentType
  respond({ match: 204, status: 204, contentType: undefined })
);

getPetMockHandler(({ respond }) =>
  // @ts-expect-error a no-payload branch rejects a real body
  respond({ match: 204, status: 204, contentType: "application/json", body: { id: 1, name: "a" } })
);

headHealthMockHandler(({ respond }) =>
  // @ts-expect-error a bodyless operation's only branch takes no body
  respond({ match: 200, status: 200, body: undefined })
);

// A stored argument is rejected the same way. Excess-property freshness cannot reach this one, so
// the guard is the only thing standing between it and a silently accepted body.
const storedNoPayload: { match: 204; status: 204; body: undefined } = {
  match: 204,
  status: 204,
  body: undefined,
};
getPetMockHandler(({ respond }) =>
  // @ts-expect-error the guard reads keyof, so it holds for a stored argument too
  respond(storedNoPayload)
);

// ---------------------------------------------------------------------------
// 4. MSW's own resolver escape hatches survive the wrapper.
// ---------------------------------------------------------------------------

// Falling through to the next handler.
getPetMockHandler(() => undefined);

// Performing the request for real.
getPetMockHandler(() => passthrough());

// Async resolvers.
getPetMockHandler(async ({ respond }) => {
  await Promise.resolve();
  return respond({ match: 204, status: 204 });
});

// Generator resolvers, which is how MSW expresses a per-call sequence.
getPetMockHandler(function* ({ respond }) {
  yield respond({ match: 200, status: 200, contentType: "application/json", body: { id: 1, name: "a" } });
  yield respond({ match: "4XX", status: 404, contentType: "application/json", body: { message: "gone" } });
});

// ---------------------------------------------------------------------------
// 5. The factory produces a real MSW handler, and baseUrl requiredness is typed.
// ---------------------------------------------------------------------------

type AssertHandlerIsMswHandler = Expect<
  Equal<ReturnType<typeof getPetMockHandler>, ReturnType<typeof http.get>>
>;

// This document's server is absolute and fully substituted, so it supplies the default origin and
// the option is optional.
getPetMockHandler(({ respond }) => respond({ match: 204, status: 204 }), {});
getPetMockHandler(({ respond }) => respond({ match: 204, status: 204 }), {
  baseUrl: "https://other.test/v1",
});
getPetMockHandler(({ respond }) => respond({ match: 204, status: 204 }));

// ---------------------------------------------------------------------------
// 6. The malformed-input error is exported with its frozen shape.
// ---------------------------------------------------------------------------

declare const handlerError: OastsHandlerError;
type AssertErrorName = Expect<Equal<(typeof handlerError)["name"], "OastsHandlerError">>;
type AssertErrorCodes = Expect<
  Equal<
    (typeof handlerError)["code"],
    "parameter-decode" | "content-type-mismatch" | "body-decode" | "multipart-decode" | "body-missing"
  >
>;
type AssertErrorPathIsNullable = Expect<
  Equal<(typeof handlerError)["applicationPath"], readonly (string | number)[] | null>
>;
type AssertErrorCauseIsUnknown = Expect<Equal<(typeof handlerError)["cause"], unknown>>;
type AssertErrorIsAnError = Expect<(typeof handlerError) extends Error ? true : false>;

export type {
  AssertHandlerIsMswHandler,
  AssertErrorName,
  AssertErrorCodes,
  AssertErrorPathIsNullable,
  AssertErrorCauseIsUnknown,
  AssertErrorIsAnError,
};
