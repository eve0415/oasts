// Frozen query-key vectors for the tanstack artifact. Authored from the pinned key-factory
// contract BEFORE the emitter existed; the emitter is written to satisfy them, never the reverse.
// Their hashes are pinned in fixtures/tanstack-entry-gate.yaml.
//
// Each vector names the operation, the input the descriptor is called with, and the query key that
// descriptor must produce. Freezing the input alongside the key matters: a vector that froze only
// the key would let a runner pick whatever input made the emitter look right.
//
// HOW THESE ARE COMPARED. By TanStack's own `hashKey`, not by deep equality. `hashKey` is
// `JSON.stringify` with sorted object keys, so it is exactly the function that decides whether two
// keys are the same cache entry — which is the only property these vectors are about. Two
// consequences, both deliberate:
//
//   - field order inside the canonical input object is irrelevant, so a vector cannot accidentally
//     freeze an ordering the contract never promised;
//   - a section whose value is `undefined` compares equal to that section being absent, because
//     `JSON.stringify` drops undefined-valued properties. The emitter omits a section *statically*
//     when the operation declares no parameters in that location; whether a declared-but-unsupplied
//     section renders as `undefined` or is absent is not a cache-identity fact and is not frozen
//     here.
//
// The pair that carries the most weight is `literal segment` against `entity`: the same request
// path text, one reaching a literal path segment and one reaching a parameter whose value happens
// to be that same text. They must hash differently, or a prefix invalidation aimed at one would
// take the other with it.

/** One frozen key vector. `input` is passed to the descriptor verbatim. */
export type KeyVector = {
  readonly name: string;
  /** The generated descriptor function's exported name, minus the `Query` suffix. */
  readonly operation: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly key: readonly unknown[];
};

/**
 * Vectors for the showcase generated in the default (`string`) date/time representation.
 */
export const KEY_VECTORS: readonly KeyVector[] = [
  {
    name: "collection",
    operation: "listPets",
    input: {},
    key: ["api", "pets"],
  },
  {
    name: "literal segment",
    operation: "getMyPet",
    input: {},
    key: ["api", "pets", "mine"],
  },
  {
    name: "entity",
    operation: "getPet",
    input: { path: { petId: "mine" } },
    key: ["api", "pets", { petId: "mine" }],
  },
  {
    name: "nested collection",
    operation: "listToys",
    input: { path: { petId: "7" } },
    key: ["api", "pets", { petId: "7" }, "toys"],
  },
  {
    name: "mixed segment json",
    operation: "getReportJson",
    input: { path: { id: "7" } },
    key: ["api", "reports", [{ id: "7" }, ".json"]],
  },
  {
    name: "mixed segment xml",
    operation: "getReportXml",
    input: { path: { id: "7" } },
    key: ["api", "reports", [{ id: "7" }, ".xml"]],
  },
  {
    name: "zero non-path fields",
    operation: "getPet",
    input: { path: { petId: "7" } },
    key: ["api", "pets", { petId: "7" }],
  },
  {
    name: "one field",
    operation: "search",
    input: { query: { q: "cat" } },
    key: ["api", "search", { query: { q: "cat" } }],
  },
  {
    name: "all optional omitted",
    operation: "search",
    input: { query: {} },
    key: ["api", "search", { query: {} }],
  },
  {
    name: "mixed present and undefined",
    operation: "search",
    input: { query: { q: "cat", limit: undefined } },
    key: ["api", "search", { query: { q: "cat" } }],
  },
  {
    name: "header and cookie sections",
    operation: "search",
    input: { header: { "X-Trace-Id": "t" }, cookie: { session: "s" } },
    key: ["api", "search", { header: { "X-Trace-Id": "t" }, cookie: { session: "s" } }],
  },
  {
    name: "secured read",
    operation: "getSecure",
    input: { path: { id: "9" } },
    key: ["api", "secure", { id: "9" }],
  },
  {
    name: "wire path parameter in string mode",
    operation: "readEvent",
    input: { path: { occurredAt: "2026-08-03T00:00:00.000Z" } },
    key: ["api", "events", { occurredAt: "2026-08-03T00:00:00.000Z" }],
  },
];

/**
 * Vectors for the same showcase generated with `types.dateTime: date`.
 *
 * The runner revives every string listed in `dateFields` into a `Date` before calling the
 * descriptor, so the input reaching the descriptor is an application value while the key stays a
 * wire string. That difference is the whole point: the key must survive a round trip through the
 * transform, or a query and its mutation's invalidation entry would name different cache entries.
 */
export const TRANSFORM_KEY_VECTORS: readonly (KeyVector & {
  readonly dateFields: readonly (readonly string[])[];
})[] = [
  {
    name: "date-time path parameter encodes to wire before keying",
    operation: "readEvent",
    input: { path: { occurredAt: "2026-08-03T00:00:00.000Z" } },
    dateFields: [["path", "occurredAt"]],
    key: ["api", "events", { occurredAt: "2026-08-03T00:00:00.000Z" }],
  },
  {
    name: "date-time query parameter encodes to wire before keying",
    operation: "readEvent",
    input: {
      path: { occurredAt: "2026-08-03T00:00:00.000Z" },
      query: { since: "2026-07-01T12:30:00.000Z" },
    },
    dateFields: [
      ["path", "occurredAt"],
      ["query", "since"],
    ],
    key: [
      "api",
      "events",
      { occurredAt: "2026-08-03T00:00:00.000Z" },
      { query: { since: "2026-07-01T12:30:00.000Z" } },
    ],
  },
];

/**
 * Frozen invalidation lists, broadest entry first.
 *
 * A collection-level mutation yields one entry; an entity mutation yields the parent collection key
 * and then the entity key. The nested case threads both ancestor parameters, which is the shape
 * every field report about generated invalidation metadata gets wrong — a key function called with
 * no arguments when it needs path parameters.
 */
export const AFFECTS_VECTORS: readonly {
  readonly name: string;
  /** The generated export's name, minus the `MutationAffects` suffix. */
  readonly operation: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly affects: readonly (readonly unknown[])[];
}[] = [
  {
    name: "collection mutation",
    operation: "createPet",
    input: { body: { name: "Rex" } },
    affects: [["api", "pets"]],
  },
  {
    name: "entity mutation",
    operation: "updatePet",
    input: { path: { petId: "7" }, body: { name: "Rex" } },
    affects: [
      ["api", "pets"],
      ["api", "pets", { petId: "7" }],
    ],
  },
  {
    name: "bodyless entity mutation",
    operation: "deletePet",
    input: { path: { petId: "7" } },
    affects: [
      ["api", "pets"],
      ["api", "pets", { petId: "7" }],
    ],
  },
  {
    name: "nested entity mutation threads ancestor parameters",
    operation: "deleteToy",
    input: { path: { petId: "7", toyId: "3" } },
    affects: [
      ["api", "pets", { petId: "7" }, "toys"],
      ["api", "pets", { petId: "7" }, "toys", { toyId: "3" }],
    ],
  },
];

/**
 * Invalidation lists for the showcase generated with `types.dateTime: date`.
 *
 * This is the one place a query's stored key and its mutation's invalidation entry can diverge. The
 * query descriptor encodes its input to wire form before keying; if the invalidation list does not
 * do the same, it names an entity key holding an application value that no query ever stored, and
 * the invalidation silently misses. Every other gate stays green when that happens, so it is
 * frozen here.
 *
 * `dateFields` is revived into `Date` values by the runner exactly as in TRANSFORM_KEY_VECTORS.
 */
export const TRANSFORM_AFFECTS_VECTORS: readonly {
  readonly name: string;
  readonly operation: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly dateFields: readonly (readonly string[])[];
  readonly affects: readonly (readonly unknown[])[];
}[] = [
  {
    name: "date-time entity mutation encodes to wire before keying",
    operation: "updateEvent",
    input: {
      path: { occurredAt: "2026-08-03T00:00:00.000Z" },
      body: { occurredAt: "2026-08-03T00:00:00.000Z", note: "moved" },
    },
    dateFields: [
      ["path", "occurredAt"],
      ["body", "occurredAt"],
    ],
    affects: [
      ["api", "events"],
      ["api", "events", { occurredAt: "2026-08-03T00:00:00.000Z" }],
    ],
  },
];
