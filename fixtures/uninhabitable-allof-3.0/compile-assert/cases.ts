import type { Transport } from "../generated/runtime/transport.js";
import type { Choice } from "../generated/types/components/choice.js";
import type { Cat } from "../generated/types/components/cat.js";
import type { DisjointPrimitive } from "../generated/types/components/disjointprimitive.js";
import type { Dog } from "../generated/types/components/dog.js";
import type { EmptyFinite } from "../generated/types/components/emptyfinite.js";
import type { EmptyInterval } from "../generated/types/components/emptyinterval.js";
import type { NeverDated } from "../generated/types/components/neverdated.js";
import type {
  ExchangeNeverRequest,
  ExchangeNeverResponse200,
} from "../generated/types/operations/exchangenever.js";
import type {
  ExchangeNeverInput,
  ExchangeNeverResult,
} from "../generated/client/operations/exchangenever.js";
import type { StandardSchemaV1 } from "../generated/validators/standard-schema.js";
import { dogValidator } from "../generated/validators/components/dog.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type AssertDogIsNever = Expect<Equal<Dog, never>>;
type AssertPrimitiveProofIsNever = Expect<Equal<DisjointPrimitive, never>>;
type AssertFiniteProofIsNever = Expect<Equal<EmptyFinite, never>>;
type AssertIntervalProofIsNever = Expect<Equal<EmptyInterval, never>>;
type AssertDatedProofIsNever = Expect<Equal<NeverDated, never>>;
type AssertNeverUnionReduces = Expect<Equal<Choice, Cat>>;
type AssertRequestBodyIsNever = Expect<Equal<ExchangeNeverRequest["body"], never>>;
type AssertResponseBodyIsNever = Expect<Equal<ExchangeNeverResponse200, never>>;
type AssertClientInputIsUncallable = Expect<Equal<ExchangeNeverInput["body"], never>>;
type Success = Extract<ExchangeNeverResult, { outcome: 200; ok: true }>;
type AssertClientResponseIsUnmatchable = Expect<Equal<Success["data"], never>>;
type AssertValidatorOutputIsNever = Expect<
  Equal<StandardSchemaV1.InferOutput<typeof dogValidator>, never>
>;

declare const transport: Transport<never>;

export function escapedCallStillHasAValidGeneratedRuntimePath(input: ExchangeNeverInput) {
  return import("../generated/client/operations/exchangenever.js").then(({ exchangeNever }) =>
    exchangeNever(transport, input),
  );
}

export type UninhabitableContracts = [
  AssertDogIsNever,
  AssertPrimitiveProofIsNever,
  AssertFiniteProofIsNever,
  AssertIntervalProofIsNever,
  AssertDatedProofIsNever,
  AssertNeverUnionReduces,
  AssertRequestBodyIsNever,
  AssertResponseBodyIsNever,
  AssertClientInputIsUncallable,
  AssertClientResponseIsUnmatchable,
  AssertValidatorOutputIsNever,
];
