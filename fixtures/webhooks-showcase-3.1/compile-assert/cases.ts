// Type-level assertions for the generated webhook/callback type surface and the client's typed
// response headers. Every declaration is a compile-time check: the file has no runtime behavior
// and is typechecked only after the emitter generates the sibling `../generated-client` tree
// (which carries both the types artifact and the client), so it does NOT typecheck today.
//
// Imports use `../generated-client/...` with `.js` suffixes because emit.importExtension resolves
// to `.js` over the on-disk `.ts` files.

import type { Webhooks } from "../generated-client/types/webhooks/index.js";
import type {
  CreateSubscriptionCallbacks,
  CreateSubscriptionSubscriptionEvents_1PostCallbacks,
} from "../generated-client/types/callbacks/index.js";
import type { GetPetResult } from "../generated-client/client/operations/getpet.js";
import type { GetPetResponse200Headers } from "../generated-client/types/operations/getpet.js";

// Invariant type equality: true only when A and B are mutually assignable in both variance positions.
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// 1. The Webhooks map narrows to the per-method request type: a valid Pet payload is assignable.
export const validNewPet: Webhooks["newPet"]["post"]["request"] = {
  body: { id: "p1", name: "Rex" },
};

// 2. A wrong-shaped payload is rejected. The only error is the body's type.
export const invalidNewPet: Webhooks["newPet"]["post"]["request"] = {
  // @ts-expect-error body must be a Pet object, not a number.
  body: 42,
};

// 3. A multi-method webhook exposes each method arm; the retraction arm carries no response body.
export const petEventDelete: Webhooks["petEvents"]["delete"]["response"] = null;

// 4. A webhook declaring no operations appears in the map with an empty object type.
type AssertEmptyHookHasNoMethods = Expect<Equal<keyof Webhooks["emptyHook"], never>>;

// 5. Callback access via the verbatim runtime expression as a quoted string key typechecks, and
//    narrows to the callback operation's request type (its body is a Pet).
export const callbackDelivery: CreateSubscriptionCallbacks["subscriptionEvents"]["{$request.body#/callbackUrl}"]["post"]["request"] =
  {
    body: { id: "p2", name: "Milo" },
  };

// 6. The second expression on the same callback is reachable under its own quoted key.
export const callbackFallback: CreateSubscriptionCallbacks["subscriptionEvents"]["{$request.query.fallbackUrl}"]["post"]["response"] =
  null;

// 7. A callback nested inside a callback operation has its own descriptor, keyed identically.
export const nestedAck: CreateSubscriptionSubscriptionEvents_1PostCallbacks["nestedAck"]["{$request.body#/ackUrl}"]["post"]["response"] =
  null;

// 8. On the headered success arm, meta.headers.get is key-checked against the response's declared
//    header set, yet the wide string overload survives so an undeclared key is not an error.
// An exact declared status keys its arm as the number literal `200`, never the string "200".
type GetPet200 = Extract<GetPetResult, { outcome: 200 }>;
export function headerAccess(result: GetPet200): void {
  const declared: string | null = result.meta.headers.get("X-Rate-Limit");
  const undeclared: string | null = result.meta.headers.get("x-typo");
  void declared;
  void undeclared;
}

// 9. Presence of the narrow key set is asserted through `keyof` (the wide overload makes a direct
//    `get("x-typo")` type error impossible, so the narrowing is proven at the type level instead).
type NarrowHeaderKeys = keyof GetPetResponse200Headers & string;
type AssertRateLimitDeclared = Expect<"X-Rate-Limit" extends NarrowHeaderKeys ? true : false>;
type AssertTraceDeclared = Expect<"X-Trace" extends NarrowHeaderKeys ? true : false>;
type AssertRequestIdDeclared = Expect<"X-Request-Id" extends NarrowHeaderKeys ? true : false>;
type AssertContentTypeDropped = Expect<Equal<Extract<"Content-Type", NarrowHeaderKeys>, never>>;
type AssertTypoUndeclared = Expect<Equal<Extract<"x-typo", NarrowHeaderKeys>, never>>;

// Reference every type-only assertion so a broken constraint surfaces as an error on evaluation.
export type WebhookTypeContracts = [
  AssertEmptyHookHasNoMethods,
  AssertRateLimitDeclared,
  AssertTraceDeclared,
  AssertRequestIdDeclared,
  AssertContentTypeDropped,
  AssertTypoUndeclared,
];
