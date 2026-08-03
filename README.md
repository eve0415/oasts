<div align="center">

# oasts

**Compile OpenAPI 3.0/3.1 into TypeScript types and a zero-dependency typed client — deterministic, fast, Rust-powered.**

[![npm version](https://img.shields.io/npm/v/oasts)](https://www.npmjs.com/package/oasts)
[![npm downloads](https://img.shields.io/npm/dm/oasts)](https://www.npmjs.com/package/oasts)
[![license: MIT](https://img.shields.io/npm/l/oasts)](./LICENSE)

</div>

---

## Why oasts

Most OpenAPI-to-TypeScript tooling is either in maintenance mode, drags a runtime dependency into your bundle, or approximates the parts of the spec that are hard to get right. oasts is a compiler, not a platform:

- **Failure-complete result types.** Every call returns a discriminated union covering documented responses, undocumented HTTP responses, network failures, and decode failures — not just the 2xx happy path. Exhaustive `switch` over an API call is a type error away from correct.
- **Deterministic, byte-identical output.** Same input, same config, same version ⇒ the same bytes on every machine and OS. Generated code is meant to be committed and reviewed; `--check` makes drift a CI failure.
- **The full parameter serialization matrix.** style/explode for path, query, and header parameters (form, spaceDelimited, pipeDelimited, deepObject, label, matrix, simple), multipart encoding with per-part content types — implemented to the letter of the spec, not approximated.
- **Auth the compiler checks.** An operation's security requirements compile into its call signature, so calling one whose auth you never configured is a type error rather than a 401 you find in staging. `client.authEnforcement: runtime` moves the check to call time instead, where an unsatisfied requirement comes back as an `auth` result.
- **Zero-dependency generated client.** The typed fetch client is emitted next to your types. No runtime package to version-match, nothing in your dependency tree.
- **Dates as dates.** `types.dateTime`/`types.date` make a `date-time` or `date` schema a `Date` or a `Temporal` value in your code while the wire keeps its string. Conversion happens before request validation and after response decoding, so validators only ever see wire values, and a value neither side can represent comes back as a `request-transform`/`response-transform` result rather than a throw.
- **Rust-powered.** Cold starts in milliseconds; full specs the size of GitHub's compile in well under a second.

## Features

| Artifact | Status |
| --- | --- |
| TypeScript types | ✅ |
| Typed fetch client | ✅ |
| Zod schemas | ✅ — needs `zod` ^4.4.0 in your project; `zod/mini` supported |
| Standalone validators | ✅ |
| MSW handlers | ✅ — needs `msw` ^2.8.0 in your project |
| TanStack Query hooks | Planned |

## Quick start

```sh
pnpm add -D oasts
```

Node 24 or newer. Drop an `oasts.yaml` next to your spec:

```yaml
schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
```

Generate:

```sh
pnpm exec oasts generate
```

Every schema becomes a plain, readable interface — the declaration from `generated/types/components/pet.ts`, verbatim under its provenance header:

```ts
export interface Pet {
  id: number;
  name: string;
  tag?: string;
}
```

Enable the client artifact and every operation becomes a typed call returning a failure-complete result — documented responses, undocumented statuses, network and decode failures are all in one union keyed by `outcome`, so one `switch` reaches every case and handling them is exhaustiveness-checking, not guesswork:

```ts
import { createTransport } from "./generated/runtime/transport.js";
import { getPetShowcase } from "./generated/client/operations/getpetshowcase.js";

const transport = createTransport({ baseUrl: "https://api.example.com/v1" });

const result = await getPetShowcase(transport, {
  path: { petId: "42" },
  query: { tags: ["indoor"] },
});

switch (result.outcome) {
  case 200:
    // this 200 declares both a JSON and a text body, so contentType selects the payload type
    console.log(result.contentType === "text/plain" ? result.data : result.data.name);
    break;
  case "4XX":
    console.error(result.status, result.error.message); // the documented error schema
    break;
  case "unmatched":
    console.error("undocumented status", result.status);
    break;
  case "timeout":
    break; // retry with backoff
  case "aborted":
    break; // the caller cancelled — never auto-retry
  case "network":
    console.error(result.cause.message); // a value, not a throw
    break;
}
```

An exact declared status is a number literal, a range or `default` key and every failure tag a string literal — the two never overlap, so `case 200:` can never also match `"4XX"`.

Every operation also gets a `getPetShowcaseOrThrow` companion for the call sites where a failure is not worth branching on: it resolves to the matched success arm's `{ data, meta }` and throws `ApiError` otherwise, with the whole failed result preserved on `error.result`. Both forms are re-exported from `generated/client/api.ts` if you would rather import one object than one module per operation.

In CI, fail on drift instead of writing files:

```sh
pnpm exec oasts generate --check
```

## MSW handlers

Enable the artifact and every operation gets a typed handler factory next to your types. Handlers
mock the server side, so they import your generated types and a small local helper — never the
client, its transport, or a validation engine.

```yaml
artifacts:
  types: true
  msw: true
```

```ts
import { setupServer } from "msw/node";
import { getPetHandler } from "./generated/msw/handlers/getpet.js";

const server = setupServer(
  getPetHandler(({ params, respond }) =>
    respond({
      match: 200,
      status: 200,
      contentType: "application/json",
      body: { id: params.petId, name: "Bella" },
    })),
);
```

`respond` is the whole surface, and it is checked against the document: `match` picks a declared
response key, and `status`, `contentType` and `body` have to agree with what that key declares.
Responding `404` from an operation that documents no `4XX`, or handing a `text/plain` arm a JSON
object, is a compile error rather than a mock that quietly lies. A response the document declares
with no content takes `respond({ match, status })` and nothing else — passing even
`body: undefined` is rejected, under `exactOptionalPropertyTypes` either way.

Request values arrive **decoded**, not as the raw strings MSW hands a hand-written handler. A path
parameter documented as an integer is a `number`; an array query parameter is an array, whichever
`style`/`explode` the document declares. That is the same serialization matrix the client encodes
with, run backwards.

**oasts emits no mock data.** There is no faker, no seeded generator, and no placeholder body — you
write the data, or you do not get one. That is a deliberate trade: every generator that synthesizes
bodies does it through faker, where recursive schemas overflow the stack and seeding still does not
make values stable across a faker upgrade. A typed slot you fill is worth more than a plausible
body nobody reviewed.

Everything you already know about MSW keeps working. Returning nothing falls through to the next
handler, `passthrough()` performs the request for real, and a generator resolver answers a
different branch per call:

```ts
server.use(
  getPetHandler(function* ({ respond }) {
    yield respond({ match: 200, status: 200, contentType: "application/json", body: pet });
    yield respond({ match: "4XX", status: 404, contentType: "application/json", body: notFound });
  }),
);
```

Two things worth knowing:

- **Origin is enforced.** The matcher is built from the operation's server URL, so two APIs mocked
  in one suite never answer for each other. Pass `{ baseUrl }` to point a handler somewhere else.
- **MSW resolves first match wins**, and a parameterized path shadows a static sibling — put
  `/pets/mine` ahead of `/pets/{petId}` in your handler array. Registering a handler through
  `server.use()` in a test always wins, because MSW prepends it.

If you would rather write handlers by hand, the artifact also emits a `paths` type that
[openapi-msw](https://github.com/christoph-fricke/openapi-msw) accepts, so both styles work against
the same generated output:

```ts
import { createOpenApiHttp } from "openapi-msw";
import type { paths } from "./generated/msw/paths.js";

const http = createOpenApiHttp<paths>();
const handler = http.get("/pets/{petId}", ({ response }) => response("200").json(pet));
```

Paths that MSW's matcher cannot express are refused at generation time rather than emitted as a
handler that silently never matches — the failure mode that otherwise surfaces as an unrelated
test's unhandled-request warning.

## Comparison

| | oasts | openapi-typescript | orval / hey-api | openapi-generator |
| --- | --- | --- | --- | --- |
| Types | ✅ | ✅ | ✅ | ✅ |
| Typed client | ✅ zero-dependency | — | ✅ needs runtime deps | ✅ heavyweight templates |
| Failure-complete results | ✅ | — | — | — |
| Serialization matrix (style/explode, multipart) | ✅ full | n/a | partial | partial |
| Deterministic committed output | ✅ byte-identical, `--check` gated | — | — | — |
| Toolchain | native binary via npm | Node | Node | Java |

Performance is measured, not promised: the in-repo benchmark harness compiles GitHub's full OpenAPI spec to types in ~80 ms — warm p50 of end-to-end `oasts generate` runs on the reference container — with every run gated on repeatability. Reproduce it with `cargo run -p oasts-bench` — the harness, corpus manifest, and recorded baseline live in [`bench/`](./bench).

## Configuration

`oasts.yaml` (or `.json`) is validated against a published JSON Schema, so typos fail loudly with a rule ID instead of silently doing nothing. A typed TypeScript config is supported too (`oasts.config.ts`).

```yaml
schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  client: true
client:
  authEnforcement: types
  baseUrl:
    source: server
    index: 0
validation:
  engine: off
  unchecked: allow
```

### Date and time representations

`date-time` and `date` schemas are strings on the wire and, by default, strings in your code too.
Set a representation and the client converts at the boundary instead:

```yaml
artifacts:
  types: true
  client: true
types:
  dateTime: date      # string | date | temporal
  date: temporal      # string | temporal
```

`dateTime: date` gives you `Date`, `dateTime: temporal` gives you `Temporal.Instant`, and
`date: temporal` gives you `Temporal.PlainDate`. The wire grammar is RFC 3339 and is checked field
by field rather than handed to `new Date` or `Temporal.Instant.from`, both of which accept more than
the contract does.

Conversion is unconditional and ordered: a request is converted before validation and before
serialization, a response after decoding, so validators only ever observe wire values. A value the
wire cannot represent is a `request-transform` result with nothing sent; one the application cannot
represent is a `response-transform` result. Neither throws.

The representations need the client artifact — the codecs are emitted under it and only run at its
pipeline positions.

### Zod flavor

The zod artifact imports classic `zod` by default. Set `zod.flavor: mini` to import `zod/mini` instead — the tree-shakable entry point, same package, same `^4.4.0` peer range, no extra dependency.

```yaml
artifacts:
  types: true
  zod: true
zod:
  flavor: mini
```

Both flavors share one parsing core and are held to the same conformance vectors, so verdicts and parsed values are identical. What changes is what your bundler can drop. Each row below is one esbuild bundle over the named entry points from the GitHub spec's generated artifact, minified, gzipped:

| bundle | `zod` | `zod/mini` |
| --- | --- | --- |
| `meta-get-octocat` (smallest operation) | 15.9 kB | 2.8 kB |
| `dependabot-list-alerts-for-repo` (largest operation) | 22.3 kB | 8.1 kB |
| the first thirty operations together | 25.5 kB | 11.4 kB |

Zod itself dominates a small bundle and amortizes across a large one, which is why the smallest operation gains the most proportionally.

Pick classic if you hand the emitted schemas to something that expects a classic `ZodType` — under mini they are `ZodMiniType`.

## Determinism

Generated output is a build artifact you can commit: given the same input document, config, and oasts version, output is byte-identical across machines and operating systems. The repo's own gates generate everything twice and diff the bytes; `oasts generate --check` gives your CI the same guarantee.

That also means oasts never reformats your project and you never reformat oasts's output — emitted code has one canonical shape.

## Development

Toolchain pins are picked up automatically (`rust-toolchain.toml`, `devEngines` in `package.json` — pnpm only; npm will refuse to run).

```sh
pnpm install --frozen-lockfile
cargo run -p oasts-gen                  # generate config schema + TS config types
pnpm -C packages/oasts build:napi       # build the native Node binding
pnpm -C packages/oasts build            # bundle the npm package
```

`scripts/*.sh` are the gates. `gate.sh` runs lint and tests; `coverage.sh` / `coverage-ts.sh` hold the coverage floors; `verify-ts.sh` typechecks generated fixture output under `tsc --strict` (run `cargo build` first); `consume-gate.sh` proves generated clients resolve, bundle, tree-shake, and run as consumed artifacts; `allocs-gate.sh` catches drift in the per-stage allocation counters. `auth-gate.sh`, `msw-gate.sh`, `transform-gate.sh`, `validators-gate.sh` and `zod-gate.sh` check the SHA-256 of each artifact's frozen test vectors — those were authored from the contract before the implementation existed, so a mismatch means the freeze was broken. `client-size.sh` reports emitted per-operation client sizes without enforcing a ceiling.

## Roadmap

- TanStack Query hooks
- Streaming request/response bodies (`text/event-stream` is a generation error until then)

## License

[MIT](./LICENSE)
