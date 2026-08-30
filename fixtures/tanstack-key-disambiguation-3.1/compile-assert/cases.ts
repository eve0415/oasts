// Type-level assertions for the disambiguated key factory.
//
// The document this compiles against declares every way two path nodes can compete for one name.
// The assertions below pin what disambiguation must preserve: each colliding path keeps a key of
// its own, the key still carries the raw segment text the URL uses, and a repeated path parameter
// is taken exactly once. A run that resolved a collision by dropping one of the competitors, or by
// giving two paths one key, fails here.
//
// Typechecked after the emitter generates the sibling ../generated-tanstack tree.

import {
  apiFooBarAll,
  apiFooBarAll2,
  apiFooBar2All,
  apiPetsAll,
  apiPetsAll2All,
  api20100401AccountsAll,
  apiOrdersByOrderIdLinesByOrderId,
  apiTenantsByUserIdSitesByUserId,
  keys,
} from "../generated-tanstack/tanstack/keys.js";

/** Compiles only when `Actual` and `Expected` are mutually assignable. */
type Exact<Actual, Expected> =
  (<T>() => T extends Actual ? 1 : 2) extends <T>() => T extends Expected ? 1 : 2 ? true : false;

declare function expectExact<Expected>(): <Actual>(
  ...check: Exact<Actual, Expected> extends true ? [] : [never]
) => void;

// --- every competitor keeps a key, and each key carries its own raw text ----------------------

// `/foo/bar`, `/foo-bar` and `/foo_bar` all derive the member `fooBar`. Three distinct keys survive,
// and each one spells the segments the client actually requests.
export const nestedKey = expectExact<readonly ["api", "foo", "bar"]>()<typeof apiFooBarAll>();
export const hyphenKey = expectExact<readonly ["api", "foo-bar"]>()<typeof apiFooBarAll2>();
export const underscoreKey = expectExact<readonly ["api", "foo_bar"]>()<typeof apiFooBar2All>();

// A segment literally named `all` competes with the member the composed object gives a node's own
// key. Both survive, and the collection key is still the prefix of the child's.
export const petsKey = expectExact<readonly ["api", "pets"]>()<typeof apiPetsAll>();
export const petsAllKey = expectExact<readonly ["api", "pets", "all"]>()<typeof apiPetsAll2All>();

// A segment whose text is not an identifier on its own still names a binding and a member.
export const datedKey = expectExact<
  readonly ["api", "2010-04-01", "accounts"]
>()<typeof api20100401AccountsAll>();

// --- the composed object reaches every one of them ---------------------------------------------

export const composedNested: typeof apiFooBarAll = keys.foo.bar.all;
export const composedHyphen: typeof apiFooBarAll2 = keys.fooBar.all;
export const composedUnderscore: typeof apiFooBar2All = keys.fooBar2.all;
export const composedPets: typeof apiPetsAll = keys.pets.all;
export const composedPetsAll: typeof apiPetsAll2All = keys.pets.all2.all;
// A digit-led member is not a bare identifier, so it is reached by index rather than by dot.
export const composedDated: typeof api20100401AccountsAll = keys["20100401"].accounts.all;

// --- path parameters ----------------------------------------------------------------------------

// `/orders/{orderId}/lines/{orderId}` names one parameter twice. The client substitutes the one
// declared value into both occurrences, so the factory takes one argument and repeats it.
export const repeatedParameter = apiOrdersByOrderIdLinesByOrderId("7");

// @ts-expect-error the repeated parameter is one argument, not two.
export const repeatedParameterTakesOne = apiOrdersByOrderIdLinesByOrderId("7", "7");

// `{user_id}` and `{userId}` normalize to one identifier but are two parameters, so they stay two
// arguments and key under their own wire names.
export const twoParameters = apiTenantsByUserIdSitesByUserId("7", "9");

// @ts-expect-error two distinct parameters cannot be satisfied by one argument.
export const twoParametersNeedBoth = apiTenantsByUserIdSitesByUserId("7");
