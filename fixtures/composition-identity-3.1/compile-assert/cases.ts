// Typechecked after the emitter generates the sibling `../generated` tree.
//
// One probe component pair in nine composition shapes. Every keyword that can carry a
// `$ref` has to reach emission still naming it; `allOf` is the one that used to inline
// the member's body instead, so these rows are what pin that it no longer does.
//
// `Equal` compares structure, not declaration identity: it reports an interface and a
// structurally identical type literal as the same type. So the single-`$ref` rows below
// (`viaAllOfOne`, `viaAllOfOneDescribed`, `viaAllOfSolo`) hold both before and after the
// change, and are documentation rather than proof — the emitted text is asserted in
// `all_of_preserves_ref_identity`, and the missing import that inlining left behind is
// what the orphan check in scripts/verify-ts.sh catches. The intersection rows are the
// ones `Equal` can decide, and they are the rows that used to fail.

import type { Holder } from "../generated/types/components/holder.js";
import type { OtherMeta } from "../generated/types/components/othermeta.js";
import type { SoloMeta } from "../generated/types/components/solometa.js";
import type { WidgetMeta } from "../generated/types/components/widgetmeta.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type Shape<K extends keyof Holder> = Required<Holder>[K];

// The six shapes that already preserved identity. These must not move.
type AssertRef = Expect<Equal<Shape<"viaRef">, WidgetMeta>>;
type AssertOneOf = Expect<Equal<Shape<"viaOneOf">, WidgetMeta | OtherMeta>>;
type AssertAnyOf = Expect<Equal<Shape<"viaAnyOf">, WidgetMeta | OtherMeta>>;
type AssertAnyOfNull = Expect<Equal<Shape<"viaAnyOfNull">, WidgetMeta | null>>;
type AssertInlineMerge = Expect<Equal<Shape<"viaAllOfInline">, { a: string; b?: string }>>;

// `allOf` over a single `$ref` — the 3.0 quoting idiom, with and without an annotation
// sibling, and over a component nothing else names.
type AssertAllOfOne = Expect<Equal<Shape<"viaAllOfOne">, WidgetMeta>>;
type AssertAllOfOneDescribed = Expect<Equal<Shape<"viaAllOfOneDescribed">, WidgetMeta>>;
type AssertAllOfSolo = Expect<Equal<Shape<"viaAllOfSolo">, SoloMeta>>;

// `allOf` over more than one member. Inlining folded these into one anonymous bag; each
// member now keeps its own identity and they are joined with `&`.
type AssertAllOfTwo = Expect<Equal<Shape<"viaAllOfTwo">, WidgetMeta & OtherMeta>>;
type AssertAllOfMixed = Expect<Equal<Shape<"viaAllOfMixed">, WidgetMeta & { c?: string }>>;

export type CompositionIdentityContracts = [
  AssertRef,
  AssertOneOf,
  AssertAnyOf,
  AssertAnyOfNull,
  AssertInlineMerge,
  AssertAllOfOne,
  AssertAllOfOneDescribed,
  AssertAllOfSolo,
  AssertAllOfTwo,
  AssertAllOfMixed,
];
