// Typechecked after the emitter generates the sibling `../generated` tree.
//
// The document declares components named after TypeScript's global generics and after the
// identifiers the client emitter injects. The point of this fixture is that all of it is legal
// OpenAPI and none of it is renamed on the way out: the emitters keep clear of the collision, the
// document keeps its names.

import type { Promise as PromiseComponent } from "../generated/types/components/promise.js";
import type { Record as RecordComponent } from "../generated/types/components/record.js";
import type { RecordHolder } from "../generated/types/components/recordholder.js";
import type { Transport as TransportComponent } from "../generated/types/components/transport.js";
import { probePromise } from "../generated/client/operations/probepromise.js";
import { createTransport } from "../generated/runtime/transport.js";

// The document's names survive. A fix that reserved `Record`/`Promise` and renamed the components
// out of the way would fail here, which is the reason it is pinned rather than assumed.
// Known and deliberately not pinned here: the document also declares a component named `Issue`,
// which the validators artifact exports as `Issue2` while the types artifact still exports it as
// `Issue`. That divergence is `reserve_names` running inside the terminal validators emitter, after
// the types emitter has already written its files — a separate defect from the shadowing this
// fixture guards. What this fixture pins for `Issue` is only that the client operation module no
// longer lands a duplicate declaration (TS2300), not that the two artifacts agree on the name.
export function componentsKeepTheirNames(
  record: RecordComponent,
  promise: PromiseComponent,
  transport: TransportComponent,
): [RecordComponent, PromiseComponent, TransportComponent] {
  return [record, promise, transport];
}

// `RecordHolder` merges declared properties with an index signature. That is the shape the types
// emitter used to render as `... & Record<string, string>`, which resolved to the component above
// instead of the built-in.
export function indexSignatureStillAcceptsExtraKeys(holder: RecordHolder): string | undefined {
  // Reading an undeclared key only typechecks while the index-signature half of the intersection
  // is still an index signature. Had `Record<string, string>` resolved to the `Record` component,
  // the half would be that object type and this would not compile.
  return holder["any-extension-key"];
}

// The operation module names `Promise<...>` in its own signature while importing a component
// called `Promise`. The built-in has to be the one that wins, or `await` here does not typecheck.
export async function operationStillReturnsAPromise(): Promise<string> {
  const result = await probePromise(
    createTransport({ baseUrl: "https://api.example.test/v1" }),
    { query: { mode: "alpha" }, body: { id: "x" } },
  );
  return result.outcome === 200 ? result.data.id : "failed";
}
