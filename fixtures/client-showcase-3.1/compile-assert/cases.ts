// Type-level assertions for the outcome-keyed result union: that `outcome` alone narrows every
// case, that `contentType` selects the payload type per declared media entry, and that the
// `orThrow` envelope is exactly the success arms and no wider. The file has no runtime behavior and
// is typechecked only after the emitter writes the sibling `../generated` tree, so it does NOT
// typecheck today.
//
// Imports use `.js` suffixes because emit.importExtension resolves to `.js` over the on-disk `.ts`.

import type { SuccessEnvelope } from "../generated/runtime/result.js";
import type {
  GetPetShowcaseInput,
  GetPetShowcaseResult,
  getPetShowcaseOrThrow,
} from "../generated/client/operations/getpetshowcase.js";
import type { GetPetShowcaseRequest } from "../generated/types/operations/getpetshowcase.js";
import type { SelectMediaShowcaseResult } from "../generated/client/operations/selectmediashowcase.js";
import type { Pet } from "../generated/types/components/pet.js";

// Invariant type equality: true only when A and B are mutually assignable in both variance
// positions. One-way assignability would let a too-wide declared type pass silently.
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// 1. An exact declared status keys its arm as a number literal, never the string form. Extracting
//    on the string yields nothing, which is what makes the two literal families disjoint.
type Pet200 = Extract<GetPetShowcaseResult, { outcome: 200 }>;
type AssertStringKeyMatchesNothing = Expect<
  Equal<Extract<GetPetShowcaseResult, { outcome: "200" }>, never>
>;

// 2. `contentType` selects the payload type. The showcase 200 declares an object JSON body beside
//    a text one, so the two arms carry genuinely different `data` types.
type Pet200Json = Extract<Pet200, { contentType: "application/json" }>;
type Pet200Text = Extract<Pet200, { contentType: "text/plain" }>;
type AssertJsonArmIsPet = Expect<Equal<Pet200Json["data"], Pet>>;
type AssertTextArmIsString = Expect<Equal<Pet200Text["data"], string>>;

export function narrowsPayloadByContentType(result: GetPetShowcaseResult): void {
  if (result.outcome === 200 && result.contentType === "application/json") {
    // Reachable only because the json arm's data is Pet, not the status-wide union.
    const name: string = result.data.name;
    void name;
  }
  if (result.outcome === 200 && result.contentType === "text/plain") {
    const raw: string = result.data;
    void raw;
    // @ts-expect-error the text arm's payload is a string, so it has no Pet fields
    void result.data.name;
  }
}

// 3. A sole declared media *range* is discriminated too, and `text/*` types as string.
type Media200 = Extract<SelectMediaShowcaseResult, { outcome: 200 }>;
type AssertRangeArmIsString = Expect<
  Equal<Extract<Media200, { contentType: "text/*" }>["data"], string>
>;

// 4. `ok: true` is carried by exactly the documented success arms — a documented error branch is
//    also `ok: false`, so excluding on `ok` must not sweep it in with the failures.
type AssertSuccessArmsAreTheDeclaredOnes = Expect<
  Equal<Exclude<GetPetShowcaseResult, { ok: false }>, Pet200 | Extract<
    GetPetShowcaseResult,
    { outcome: "default"; ok: true }
  >>
>;

// 5. The emitted `orThrow` return type is exactly what `unwrap` computes over the result union —
//    checked in both directions, because tsc only proves assignability one way and a too-wide
//    declared return would otherwise pass silently.
type DeclaredEnvelope = Awaited<ReturnType<typeof getPetShowcaseOrThrow>>;
type ComputedEnvelope = SuccessEnvelope<GetPetShowcaseResult>;
type AssertEnvelopeIsExact = Expect<Equal<DeclaredEnvelope, ComputedEnvelope>>;

// 6. One switch reaches every case, and dropping one is a compile error rather than a silent gap.
export function exhaustive(result: GetPetShowcaseResult): string {
  switch (result.outcome) {
    case 200:
      return result.contentType === "text/plain" ? result.data : result.data.name;
    case "4XX":
    case "default":
      return result.ok ? "ok" : String(result.status);
    case "unmatched":
      return String(result.status);
    case "auth":
    case "request-encode":
    case "request-validation":
    case "request-transform":
    case "request-middleware":
    case "cookie-params-unsendable":
    case "aborted":
    case "timeout":
      return result.outcome;
    case "network":
      return result.cause.message;
    case "response-aborted":
    case "response-timeout":
    case "response-decode":
    case "response-validation":
    case "response-transform":
    case "response-middleware":
      return `${result.outcome} ${String(result.status)}`;
    default: {
      const unreachable: never = result;
      return unreachable;
    }
  }
}

// 8. The types artifact's `Request` and the client artifact's `Input` describe the same operation
//    input, so every slot the first declares must be a slot the second declares. Assignability
//    alone does not check this: TypeScript's weak-type detection switches off as soon as ONE
//    property matches, so an operation carrying `path` as well as a header stayed silent while the
//    two artifacts spelled the header slot differently. Comparing the key sets is what notices.
//    `getPetShowcase` is the right witness precisely because it has other slots to hide behind.
type RequestSlots = keyof GetPetShowcaseRequest;
type InputSlots = keyof GetPetShowcaseInput;
type AssertRequestSlotsExistOnInput = Expect<
  Equal<Extract<RequestSlots, InputSlots>, RequestSlots>
>;

// And the value itself goes where the client expects one.
declare const requestValue: GetPetShowcaseRequest;
const inputValue: GetPetShowcaseInput = requestValue;
void inputValue;

export type {
  AssertRequestSlotsExistOnInput,
  AssertStringKeyMatchesNothing,
  AssertJsonArmIsPet,
  AssertTextArmIsString,
  AssertRangeArmIsString,
  AssertSuccessArmsAreTheDeclaredOnes,
  AssertEnvelopeIsExact,
};
