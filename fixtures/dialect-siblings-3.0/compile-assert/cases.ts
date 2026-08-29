// A 3.1-only keyword in a 3.0 document is one conjunct of its schema object. Dropping the whole
// object took every representable sibling with it, so these assertions pin what survives: the
// declared type, the sibling properties, and the union branch that stops being usable the moment
// its tag property widens to `unknown`.

import type { ApiKey } from "../generated/types/components/apikey.js";
import type { JitAccess } from "../generated/types/components/jitaccess.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type AssertJwtTemplate = Expect<
  Equal<ApiKey["jwtTemplate"], { [key: string]: unknown } | null | undefined>
>;
type AssertTags = Expect<Equal<ApiKey["tags"], string[] | undefined>>;
type AssertLimits = Expect<
  Equal<ApiKey["limits"], { rate?: number; burst?: number } | undefined>
>;
type AssertExtensions = Expect<Equal<ApiKey["extensions"], { [key: string]: unknown } | undefined>>;
type AssertAuditLog = Expect<Equal<ApiKey["auditLog"], string[] | undefined>>;
// Nothing representable sits beside the keyword, so the node still widens whole.
type AssertOpaque = Expect<Equal<ApiKey["opaque"], unknown>>;
// A `type` array is the type declaration rather than a droppable conjunct, so this widens whole
// even though `minLength` would otherwise satisfy the sibling guard.
type AssertWidened = Expect<Equal<ApiKey["widened"], unknown>>;

type Unavailable = Extract<JitAccess, { unavailableReason: string }>;
// `const` is dropped rather than reinterpreted: the declared `type: string` is what remains, and
// it is not the literal the document asked for.
type AssertUnavailableState = Expect<Equal<Unavailable["state"], string>>;
// The sibling the whole-object widening used to erase along with the tag.
type AssertUnavailableReason = Expect<
  Equal<Unavailable["unavailableReason"], "postgres_upgrade_required" | "temporarily_unavailable">
>;

// The branch is a real object type, so the union is still narrowable. Against an `unknown` branch
// this body does not compile.
export function unavailableReason(access: JitAccess): string | undefined {
  return "unavailableReason" in access ? access.unavailableReason : undefined;
}

// @ts-expect-error a widened node is `unknown`, not `any`: it does not assign without a check.
export const opaqueDoesNotAssign: string = ({} as ApiKey).opaque;
