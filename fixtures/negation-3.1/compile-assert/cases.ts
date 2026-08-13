// Typechecked after the emitter generates the sibling `../generated` tree.
//
// `not` splits three ways, and the split is what these rows pin. A `not` whose subschema
// admits every instance says "no instance" — the same statement the boolean schema `false`
// makes — so the type is `never`, agreeing with the validator that rejects every value at
// runtime. A `not` of nothing is a no-op and leaves its sibling type alone. Everything in
// between keeps its sibling type and reports the narrowing it could not apply.
//
// The `never` rows are the ones that used to fail: they rendered `unknown`, so the emitted
// type accepted every value the shipped validator rejected.

import type { Holder } from "../generated/types/components/holder.js";
import type { KeyedNames } from "../generated/types/components/keyednames.js";
import type { NamedNot } from "../generated/types/components/namednot.js";
import type { RejectAll } from "../generated/types/components/rejectall.js";
import type { RejectAllAnnotated } from "../generated/types/components/rejectallannotated.js";
import type { RejectAllTrue } from "../generated/types/components/rejectalltrue.js";
import type { RejectNothing } from "../generated/types/components/rejectnothing.js";
import type { RejectSome } from "../generated/types/components/rejectsome.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type Shape<K extends keyof Holder> = Required<Holder>[K];

// A `not` that admits everything: three spellings, one meaning.
type AssertRejectAll = Expect<Equal<RejectAll, never>>;
type AssertRejectAllTrue = Expect<Equal<RejectAllTrue, never>>;
type AssertRejectAllAnnotated = Expect<Equal<RejectAllAnnotated, never>>;

// A `not` of nothing narrows nothing, and an unrepresentable `not` is dropped from the
// type rather than approximated. Both leave the sibling primitive exactly as declared.
type AssertRejectNothing = Expect<Equal<RejectNothing, string>>;
type AssertRejectSome = Expect<Equal<RejectSome, string>>;
type AssertNamedNot = Expect<Equal<NamedNot, { payload?: string }>>;

// `propertyNames` is diagnosed, not applied: the object keeps the value type its
// `additionalProperties` declares, and the key domain is enforced by the validators.
type AssertKeyedNames = Expect<Equal<KeyedNames, { [key: string]: string }>>;

// The reference sites see the same types the declarations do.
type AssertHolderRejectAll = Expect<Equal<Shape<"rejectAll">, never>>;
type AssertHolderRejectSome = Expect<Equal<Shape<"rejectSome">, string>>;

// Assignability, not just structure: nothing is assignable to an empty type. Before the
// fix these declarations were `unknown`, which accepts every value — so the `@ts-expect-error`
// would itself be the error, and this file would stop compiling.
// @ts-expect-error nothing inhabits a schema that rejects every instance
const rejectAllTakesNothing: RejectAll = "anything";
// @ts-expect-error the same, through the reference site rather than the declaration
const holderRejectAllTakesNothing: Shape<"rejectAll"> = 0;

export type NegationContracts = [
  AssertRejectAll,
  AssertRejectAllTrue,
  AssertRejectAllAnnotated,
  AssertRejectNothing,
  AssertRejectSome,
  AssertNamedNot,
  AssertKeyedNames,
  AssertHolderRejectAll,
  AssertHolderRejectSome,
  typeof rejectAllTakesNothing,
  typeof holderRejectAllTakesNothing,
];
