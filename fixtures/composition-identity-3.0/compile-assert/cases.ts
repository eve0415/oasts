// Typechecked after the emitter generates the sibling `../generated` tree.
//
// The two rows the 3.1 probe cannot carry, because `nullable` is 3.0-only. Both say the
// same thing about where `null` goes: it wraps whatever the node rendered to, outside the
// intersection. Distributing it into the members instead — `(A | null) & (B | null)` —
// collapses the object half to `never`, which is the shape of the bug typed-openapi has.

import type { Holder } from "../generated/types/components/holder.js";
import type { OtherMeta } from "../generated/types/components/othermeta.js";
import type { WidgetMeta } from "../generated/types/components/widgetmeta.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type Shape<K extends keyof Holder> = Required<Holder>[K];

type AssertNullableRef = Expect<Equal<Shape<"viaNullableRef">, WidgetMeta | null>>;
// Structure alone cannot separate the inlined literal from the name here; the emitted
// text is asserted in `all_of_preserves_ref_identity`. This row pins that `| null`
// survives whichever way the member renders.
type AssertNullableAllOfOne = Expect<Equal<Shape<"viaNullableAllOfOne">, WidgetMeta | null>>;
type AssertNullableAllOfTwo = Expect<
  Equal<Shape<"viaNullableAllOfTwo">, (WidgetMeta & OtherMeta) | null>
>;

export type NullableCompositionContracts = [
  AssertNullableRef,
  AssertNullableAllOfOne,
  AssertNullableAllOfTwo,
];
