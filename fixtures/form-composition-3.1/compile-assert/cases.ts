import type { ViaAllOfInput } from "../generated/client/operations/viaallof.js";
import type { ViaAnyOfInput } from "../generated/client/operations/viaanyof.js";
import type { ViaNestedInput } from "../generated/client/operations/vianested.js";
import type { ViaOneOfInput } from "../generated/client/operations/viaoneof.js";
import type { ViaSharedEnumAnyOfInput } from "../generated/client/operations/viasharedenumanyof.js";

type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

type FlatAlternatives = {
  name: string;
  applied_tags?: string[];
  invitable?: boolean;
};

type AssertAllOfBody = Expect<Equal<ViaAllOfInput["body"], FlatAlternatives>>;
type AssertOneOfBody = Expect<Equal<ViaOneOfInput["body"], FlatAlternatives>>;
type AssertAnyOfBody = Expect<Equal<ViaAnyOfInput["body"], FlatAlternatives>>;
type AssertSharedEnumAnyOfBody = Expect<
  Equal<ViaSharedEnumAnyOfInput["body"], { kind: "forum" | "text" }>
>;
type AssertNestedBody = Expect<
  Equal<
    ViaNestedInput["body"],
    {
      common: string;
      left?: boolean;
      count?: number;
      right?: string;
    }
  >
>;

export type {
  AssertAllOfBody,
  AssertOneOfBody,
  AssertAnyOfBody,
  AssertSharedEnumAnyOfBody,
  AssertNestedBody,
};
