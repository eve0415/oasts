// A 3.1-only keyword in a 3.0 document is one conjunct of its schema object. Dropping the whole
// object took every representable sibling with it, so these assertions pin what survives: the
// declared type, the sibling properties, and the union branch that stops being usable the moment
// its tag property widens to `unknown`.

import type { ApiKey } from "../generated/types/components/apikey.js";
import type { Conjoined } from "../generated/types/components/conjoined.js";
import type { JitAccess } from "../generated/types/components/jitaccess.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type AssertJwtTemplate = Expect<
  Equal<ApiKey["jwtTemplate"], { [key: string]: unknown } | null | undefined>
>;
// `prefixItems` and `patternProperties` rescope the sibling that survives them, so that sibling
// widens rather than carrying through: an element type of `string` or an index signature of
// `never` would be narrower than the document, which a dropped keyword may never make it.
type AssertTags = Expect<Equal<ApiKey["tags"], unknown[] | undefined>>;
type AssertLimits = Expect<
  Equal<ApiKey["limits"], { rate?: number; burst?: number } | undefined>
>;
type AssertExtensions = Expect<Equal<ApiKey["extensions"], { [key: string]: unknown } | undefined>>;
// `contains` does not rescope anything — it asserts that some element matches, while `items` still
// governs every index — so its sibling is carried through exactly.
type AssertAuditLog = Expect<Equal<ApiKey["auditLog"], string[] | undefined>>;

// Values this document admits. The emitted types have to accept them: dropping a keyword may only
// widen, and each of these is rejected by the narrower type the sibling would otherwise carry.
export const tuplePrefixValueAssigns: ApiKey["tags"] = [1, "a"];
export const patternedKeyAssigns: ApiKey["extensions"] = { "x-trace": "abc" };
// Nothing representable sits beside the keyword, so the node still widens whole.
type AssertOpaque = Expect<Equal<ApiKey["opaque"], unknown>>;
// A `type` array is the type declaration rather than a droppable conjunct, so this widens whole
// even though `minLength` would otherwise satisfy the sibling guard.
type AssertWidened = Expect<Equal<ApiKey["widened"], unknown>>;

type Unavailable = Extract<JitAccess, { unavailableReason: string }>;
// `const` is dropped rather than reinterpreted: the declared `type: string` is what remains, and
// it is not the literal the document asked for.
type AssertUnavailableState = Expect<Equal<Unavailable["state"], string>>;
// A regression guard rather than a demonstration: the widening never reached this property, and
// this pins that dropping the tag's `const` does not start reaching it.
type AssertUnavailableReason = Expect<
  Equal<Unavailable["unavailableReason"], "postgres_upgrade_required" | "temporarily_unavailable">
>;

// Two applicators and no typed content: the object lowers to a conjunction whose typed half is
// never emitted, and both applicators survive the dropped `const`.
type AssertConjoinedName = Expect<Equal<Conjoined["name"], string>>;
type AssertConjoinedKind = Expect<Equal<Conjoined["kind"], "direct" | "delegated">>;

// Presence-narrowing over the union, which holds either way because only the tag property widened.
// The assertion that separates this branch from a whole-node widening is `AssertUnavailableState`
// above: a tag of `unknown` is a tag no caller can compare, match, or switch on.
export function unavailableReason(access: JitAccess): string | undefined {
  return "unavailableReason" in access ? access.unavailableReason : undefined;
}

export function opaqueDoesNotAssign(key: ApiKey): string {
  // @ts-expect-error a widened node is `unknown`, not `any`: it does not assign without a check.
  return key.opaque;
}
