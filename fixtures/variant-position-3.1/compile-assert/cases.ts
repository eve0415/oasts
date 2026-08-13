// Typechecked after the emitter generates the sibling `../generated` tree.
//
// A request/response twin is emitted for a position the document actually uses the component at,
// not for every position its shape would split at. All four components below carry `readOnly` and
// `writeOnly`, so shape alone would give each of them both twins; the operations decide.
//
// The `@ts-expect-error` rows are the load-bearing ones. A twin that comes back from the dead is
// not a type error anywhere — the declaration is simply unreferenced — so the only way to assert
// its absence is to import it and require that the import fail.

import type { ReadBack, ReadBackResponse } from "../generated/types/components/readback.js";
// @ts-expect-error a component this document only reads back has no request position to declare for
import type { ReadBackRequest } from "../generated/types/components/readback.js";
import type {
  ReadBackLeaf,
  ReadBackLeafResponse,
} from "../generated/types/components/readbackleaf.js";
// @ts-expect-error response-only reaches the components it references, however deep
import type { ReadBackLeafRequest } from "../generated/types/components/readbackleaf.js";
import type { SendOnly, SendOnlyRequest } from "../generated/types/components/sendonly.js";
// @ts-expect-error the mirror: a component only ever sent has no response position
import type { SendOnlyResponse } from "../generated/types/components/sendonly.js";
import type {
  RoundTrip,
  RoundTripRequest,
  RoundTripResponse,
} from "../generated/types/components/roundtrip.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// The twins that do exist still say what they always said: `readOnly` drops in request position,
// `writeOnly` drops in response position, and the base declaration keeps both.
type AssertReadBackResponse = Expect<
  Equal<ReadBackResponse, { id: string; nested: ReadBackLeafResponse }>
>;
type AssertSendOnlyRequest = Expect<Equal<SendOnlyRequest, { secret: string }>>;
type AssertRoundTripRequest = Expect<Equal<RoundTripRequest, { secret: string }>>;
type AssertRoundTripResponse = Expect<Equal<RoundTripResponse, { id: string }>>;

// The base declaration is the document's own name and is never withheld, whichever positions are
// used — it is what both directional views are derived from. It mirrors the document as declared,
// so it names the neutral leaf even where the only view that survives above it is the response one.
type AssertReadBackBase = Expect<
  Equal<ReadBack, { id: string; secret: string; nested: ReadBackLeaf }>
>;
type AssertSendOnlyBase = Expect<Equal<SendOnly, { id: string; secret: string }>>;
type AssertRoundTripBase = Expect<Equal<RoundTrip, { id: string; secret: string }>>;

export type VariantPositionContracts = [
  AssertReadBackResponse,
  AssertSendOnlyRequest,
  AssertRoundTripRequest,
  AssertRoundTripResponse,
  AssertReadBackBase,
  AssertSendOnlyBase,
  AssertRoundTripBase,
  ReadBackRequest,
  ReadBackLeafRequest,
  SendOnlyResponse,
];
