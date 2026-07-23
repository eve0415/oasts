// Type-level enforcement matrix for the generated auth client in authEnforcement: types mode.
//
// Every exported function is a compile-time assertion. A positive call carries no marker and
// must typecheck. A negative call carries a single `@ts-expect-error` whose sole cause is the
// auth-options requirement: the transport type and input argument are always correct, so the
// only thing the compiler can object to is the missing or unsatisfied credential set.
//
// `S` on a transport is the union of scheme names the transport was configured with. An
// operation's generated `CallArgs<S>` makes the trailing options element optional exactly when
// `S` proves one security alternative fully satisfied (every member scheme name assignable to
// `S`), or when the operation admits the anonymous `{}` alternative or is unsecured. Otherwise
// the options element is required and its `auth` property enumerates the minimal missing
// alternatives. A widened `S` (`string extends S`) and an unconstrained type parameter prove
// nothing. Union `S` is read as a set, not distributed, so `'a' | 'b'` proves any alternative
// whose schemes are within `{a, b}`.
//
// Typechecked after the emitter generates the sibling `../generated` tree.

import { AmbientClientCertificate, type Transport } from "../generated/runtime/transport.js";
import {
  inheritedRootOnly,
  inheritedRootOnlyOrThrow,
  type InheritedRootOnlyCallArgs,
  type InheritedRootOnlyInput,
} from "../generated/client/operations/inheritedrootonly.js";
import { orHeaderOauth } from "../generated/client/operations/orheaderoauth.js";
import { andBasicHeader } from "../generated/client/operations/andbasicheader.js";
import { anonymousIncluded } from "../generated/client/operations/anonymousincluded.js";
import { unsecured } from "../generated/client/operations/unsecured.js";
import { sameKindOr } from "../generated/client/operations/samekindor.js";
import { queryKeyOp } from "../generated/client/operations/querykeyop.js";
import { cookieKeyOp } from "../generated/client/operations/cookiekeyop.js";
import { digestAuthOp } from "../generated/client/operations/digestauthop.js";
import { mutualTlsOp } from "../generated/client/operations/mutualtlsop.js";
import { cookieParamOp } from "../generated/client/operations/cookieparamop.js";

// Transports typed by the union of scheme names they were configured with.
declare const tBearer: Transport<"bearerAuth">;
declare const tNever: Transport<never>;
declare const tHeaderKey: Transport<"headerKey">;
declare const tOauth: Transport<"oauthFlow">;
declare const tBasic: Transport<"basicAuth">;
declare const tBasicHeader: Transport<"basicAuth" | "headerKey">;
declare const tBearerAlt: Transport<"bearerAlt">;
declare const tBearerQuery: Transport<"bearerAuth" | "queryKey">;
declare const tWide: Transport<string>;
declare const tCookie: Transport<"cookieKey">;
declare const tDigestAuth: Transport<"digestAuth">;
declare const tMutualTls: Transport<"mutualTls">;

// 1. Inherited root requirement, proven by S: options omitted.
export function inheritedSatisfied(): void {
  inheritedRootOnly(tBearer, {});
}

// 2. Inherited root requirement, unproven by S: options required, then discharged per call.
export function inheritedUnsatisfied(): void {
  // @ts-expect-error S=never proves no alternative, so the options element is required.
  inheritedRootOnly(tNever, {});
  inheritedRootOnly(tNever, {}, { auth: { bearerAuth: "token" } });
}

// 3. OR alternatives: either single-scheme alternative suffices; an unrelated scheme does not.
export function orAlternatives(): void {
  orHeaderOauth(tHeaderKey, {});
  orHeaderOauth(tOauth, {});
  // @ts-expect-error basicAuth belongs to neither alternative, so the options element is required.
  orHeaderOauth(tBasic, {});
}

// 4. AND alternative: one proven member leaves the other required; both proven satisfies.
export function andPartial(): void {
  // @ts-expect-error only basicAuth is proven; the AND still needs headerKey, so options are required.
  andBasicHeader(tBasic, {});
  andBasicHeader(tBasic, {}, { auth: { headerKey: "k" } });
  andBasicHeader(tBasicHeader, {});
}

// 5. Anonymous alternative present: options optional for any S; explicit opt-in also compiles.
export function anonymousAlternative(): void {
  anonymousIncluded(tNever, {});
  anonymousIncluded(tNever, {}, { auth: "anonymous" });
}

// 6. Unsecured operation (security: []): options always optional.
export function unsecuredOperation(): void {
  unsecured(tNever, {});
}

// 7. Same-kind OR (two bearer schemes): the second scheme satisfies; neither proven is required.
export function sameKindAlternatives(): void {
  sameKindOr(tBearerAlt, {});
  // @ts-expect-error neither bearer alternative is proven by S=never, so options are required.
  sameKindOr(tNever, {});
}

// 8. Union-of-literals S proves every alternative whose schemes lie within the union (no distribution).
export function unionLiteralScopes(): void {
  inheritedRootOnly(tBearerQuery, {});
  queryKeyOp(tBearerQuery, {});
}

// 9. Widened S (string extends S) proves nothing; per-call auth discharges the requirement.
export function widenedScheme(): void {
  // @ts-expect-error string extends S proves no scheme, so the options element is required.
  inheritedRootOnly(tWide, {});
  inheritedRootOnly(tWide, {}, { auth: { bearerAuth: "token" } });
}

// 10. Unconstrained generic S proves nothing; per-call auth discharges the requirement.
export function unconstrainedGeneric<S extends string>(t: Transport<S>): void {
  // @ts-expect-error an unconstrained type parameter proves no scheme, so options are required.
  inheritedRootOnly(t, {});
  inheritedRootOnly(t, {}, { auth: { bearerAuth: "token" } });
}

// 11. Generic passthrough preserves S: the wrapper forwards CallArgs<S> without widening the transport.
export function wrap<S extends string>(
  t: Transport<S>,
  input: InheritedRootOnlyInput,
  ...args: InheritedRootOnlyCallArgs<S>
) {
  return inheritedRootOnly(t, input, ...args);
}

// 11 (continued). Enforcement survives the hop through the generic wrapper.
export function enforcementThroughWrapper(): void {
  wrap(tBearer, {});
  // @ts-expect-error the unsatisfied S propagates through the wrapper, so options are required.
  wrap(tNever, {});
}

// 12. Cookie API-key scheme proven by S.
export function cookieOperation(): void {
  cookieKeyOp(tCookie, {});
}

// 13. OrThrow variant enforces identically to the result-returning variant.
export function orThrowParity(): void {
  inheritedRootOnlyOrThrow(tBearer, {});
  // @ts-expect-error S=never proves no alternative for the OrThrow variant either.
  inheritedRootOnlyOrThrow(tNever, {});
}

// 14. Generalized HTTP scheme (any registered `type: http` scheme beyond basic/bearer) proven by
// S; unproven requires a `{ credentials }` object matching the scheme's own grammar.
export function httpSchemeAlternatives(): void {
  digestAuthOp(tDigestAuth, {});
  // @ts-expect-error S=never proves no alternative, so the options element is required.
  digestAuthOp(tNever, {});
  digestAuthOp(tNever, {}, { auth: { digestAuth: { credentials: "proof" } } });
}

// 15. Mutual TLS proven by S; unproven requires the ambient client-certificate credential.
export function mutualTlsAlternatives(): void {
  mutualTlsOp(tMutualTls, {});
  // @ts-expect-error S=never proves no alternative, so the options element is required.
  mutualTlsOp(tNever, {});
  mutualTlsOp(tNever, {}, { auth: { mutualTls: AmbientClientCertificate } });
}

// 16. Cookie-parameter operation: input carries a `cookie` group alongside the auth requirement.
export function cookieParameterInput(): void {
  cookieParamOp(tBearer, { cookie: { consent: "yes" } });
}
