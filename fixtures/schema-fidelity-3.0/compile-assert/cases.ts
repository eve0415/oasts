// Typechecked after all three configs generate their sibling trees. Positive declarations pin
// the intended surface; every widening regression has a matching negative `@ts-expect-error`.

import type { ClosedEmpty } from "../generated/types/components/closedempty.js";
import type { EmptyEvent } from "../generated/types/components/emptyevent.js";
import type { MaybePlainEmpty } from "../generated/types/components/maybeplainempty.js";
import type { PatternOnly } from "../generated/types/components/patternonly.js";
import type { PlainEmpty } from "../generated/types/components/plainempty.js";
import type { ReadOnlyOnlyRequest } from "../generated/types/components/readonlyonly.js";
import type { RefAndAnonymousEmpty } from "../generated/types/components/refandanonymousempty.js";
import type { CountEvent as TaggedCountEvent } from "../generated-tagged/types/components/countevent.js";
import type { EmptyEvent as TaggedEmptyEvent } from "../generated-tagged/types/components/emptyevent.js";
import type { Event as TaggedEvent } from "../generated-tagged/types/components/event.js";
import type {
  CountEvent as BigintCountEvent,
  CountEventWire as BigintCountEventWire,
} from "../generated-bigint/types/components/countevent.js";
import type {
  PutEventRequest as BigintPutEventRequest,
  PutEventRequestWire as BigintPutEventRequestWire,
} from "../generated-bigint/types/operations/putevent.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type AssertPlainEmpty = Expect<Equal<PlainEmpty, { [key: string]: unknown }>>;
type AssertClosedEmpty = Expect<Equal<ClosedEmpty, { [key: string]: never }>>;
// OpenAPI 3.0 has no patternProperties keyword. OASTS1103 deliberately lowers this schema to
// unknown; the 3.1 twin pins the pattern index signature and its rejecting assignment.
type AssertPatternOnly = Expect<Equal<PatternOnly, unknown>>;
type AssertReadOnlyRequestIsEmpty = Expect<Equal<ReadOnlyOnlyRequest, { [key: string]: unknown }>>;
type AssertNullableEmpty = Expect<Equal<MaybePlainEmpty, PlainEmpty | null>>;
type AssertNullableDiscriminator = Expect<Equal<Extract<TaggedEvent, null>, null>>;

export const plainAcceptsObject: EmptyEvent["plain"] = {};
// @ts-expect-error an OpenAPI object does not admit a number through TypeScript's `{}` hole.
export const plainRejectsNumber: EmptyEvent["plain"] = 42;
// @ts-expect-error an OpenAPI object does not admit a string through TypeScript's `{}` hole.
export const plainRejectsString: EmptyEvent["plain"] = "hello";

export const closedAcceptsEmptyObject: ClosedEmpty = {};
// @ts-expect-error additionalProperties: false rejects every undeclared property.
export const closedRejectsProperty: ClosedEmpty = { a: 1 };

export const patternAcceptsString: PatternOnly = { "x-name": "value" };

export const requestFilteredEmptyAcceptsObject: ReadOnlyOnlyRequest = {};
// @ts-expect-error the request-axis empty object still rejects primitives.
export const requestFilteredEmptyRejectsNumber: ReadOnlyOnlyRequest = 42;

export const allOfAcceptsObject: RefAndAnonymousEmpty = {};
// @ts-expect-error the anonymous empty allOf member must not reopen the ref for primitives.
export const allOfRejectsString: RefAndAnonymousEmpty = "hello";

export function exhaustsTaggedEvent(event: TaggedEvent): "empty" | "count" | "null" {
  if (event === null) {
    return "null";
  }
  switch (event.kind) {
    case "empty": {
      const narrowed: TaggedEmptyEvent = event;
      void narrowed;
      return "empty";
    }
    case "count": {
      const narrowed: TaggedCountEvent = event;
      void narrowed;
      return "count";
    }
    default: {
      const unreachable: never = event;
      return unreachable;
    }
  }
}

export const bigintSequence: BigintCountEvent["sequence"] = 42n;
// @ts-expect-error types.integer: bigint rejects number on the application surface.
export const bigintSequenceRejectsNumber: BigintCountEvent["sequence"] = 42;

export const bigintPath: BigintPutEventRequest["path"]["eventId"] = 42n;
// @ts-expect-error the int64 path parameter is bigint on the application surface.
export const bigintPathRejectsNumber: BigintPutEventRequest["path"]["eventId"] = 42;

export const wireSequenceAcceptsNumber: BigintCountEventWire["sequence"] = 42;
export const wireSequenceAcceptsBigint: BigintCountEventWire["sequence"] = 42n;
export const wireSequenceAcceptsRawJson: BigintCountEventWire["sequence"] = { rawJSON: "42" };
// @ts-expect-error the lossless int64 wire surface does not admit strings.
export const wireSequenceRejectsString: BigintCountEventWire["sequence"] = "42";

type AssertBigintPathWire = Expect<
  Equal<
    BigintPutEventRequestWire["path"]["eventId"],
    number | bigint | { readonly rawJSON: string }
  >
>;

export type SchemaFidelityContracts = [
  AssertPlainEmpty,
  AssertClosedEmpty,
  AssertPatternOnly,
  AssertReadOnlyRequestIsEmpty,
  AssertNullableEmpty,
  AssertNullableDiscriminator,
  AssertBigintPathWire,
];
