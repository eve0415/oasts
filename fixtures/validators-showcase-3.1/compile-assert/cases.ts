// Type-level assertions for the generated validators artifact. Every declaration below is a
// compile-time check: the file has no runtime behavior and is typechecked only after the emitter
// generates the sibling `../generated` tree, so it does NOT typecheck today.
//
// It pins four properties of a generated validator's static type:
//   1. the validator is assignable to StandardSchemaV1<T> for its component's structural type T;
//   2. StandardSchemaV1.InferInput and InferOutput both resolve to that structural type (assert-only
//      validation performs no transform, so input equals output);
//   3. the validate result union discriminates on `issues` — the success arm carries `value: T` and
//      the failure arm carries an issues array;
//   4. validate is synchronous: its return type extends the Result union and contains no Promise arm.
//
// Emitter contract these assertions rely on: each generated validator export is declared
// `SyncStandardSchemaV1<T>`, the Promise-free specialization — never a bare `StandardSchemaV1<T>`.
// A bare annotation would widen `validate` back to `Result | Promise<Result>` and erase the typed
// `types` phantom (its runtime value is `undefined`), defeating assertions 2 and 4.
//
// Imports use `../generated/...` with `.js` suffixes because emit.importExtension resolves to `.js`
// over the on-disk `.ts` files; the vendored interface is imported from the emitted
// `validators/standard-schema.js`.

import type {
  StandardSchemaV1,
  SyncStandardSchemaV1,
} from "../generated/validators/standard-schema.js";
import { petValidator } from "../generated/validators/components/pet.js";
import { patternBagValidator } from "../generated/validators/components/patternbag.js";
import { treeNodeValidator } from "../generated/validators/components/treenode.js";
import { createPetResponse200Validator } from "../generated/validators/operations/createpet.js";
import type { ConditionalProfile } from "../generated/types/components/conditionalprofile.js";
import type { Pet } from "../generated/types/components/pet.js";
import type { PatternBag } from "../generated/types/components/patternbag.js";
import type { RequiredOnly } from "../generated/types/components/requiredonly.js";
import type { TreeNode } from "../generated/types/components/treenode.js";
import type { CreatePetResponse200 } from "../generated/types/operations/createpet.js";

// Invariant type equality: true only when A and B are mutually assignable in both variance positions.
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// 0. Each generated validator export is declared as the Promise-free specialization.
export const petIsSync: SyncStandardSchemaV1<Pet> = petValidator;

// 1. Each generated validator is assignable to StandardSchemaV1<T> for its structural type.
export const petIsStandardSchema: StandardSchemaV1<Pet> = petValidator;
export const patternBagIsStandardSchema: StandardSchemaV1<PatternBag> = patternBagValidator;
export const treeIsStandardSchema: StandardSchemaV1<TreeNode> = treeNodeValidator;
export const createPetResponseIsStandardSchema: StandardSchemaV1<CreatePetResponse200> =
  createPetResponse200Validator;

// 2. InferInput and InferOutput both resolve to the structural type.
type AssertInferOutputPet = Expect<Equal<StandardSchemaV1.InferOutput<typeof petValidator>, Pet>>;
type AssertInferInputPet = Expect<Equal<StandardSchemaV1.InferInput<typeof petValidator>, Pet>>;
type AssertInferOutputTree = Expect<
  Equal<StandardSchemaV1.InferOutput<typeof treeNodeValidator>, TreeNode>
>;
type AssertBareRequiredTypeStaysUnknown = Expect<Equal<RequiredOnly, unknown>>;
type AssertConditionalDoesNotWidenDeclaredProperty = Expect<
  Equal<ConditionalProfile["companyName"], string | undefined>
>;

// 3 + 4. The validate result discriminates on `issues` and contains no Promise.
type PetValidateResult = ReturnType<(typeof petValidator)["~standard"]["validate"]>;
type AssertResultIsResultUnion = Expect<
  [PetValidateResult] extends [StandardSchemaV1.Result<Pet>] ? true : false
>;
type AssertResultHasNoPromise = Expect<Equal<Extract<PetValidateResult, Promise<unknown>>, never>>;
type PetSuccess = Extract<PetValidateResult, { readonly issues?: undefined }>;
type PetFailure = Extract<PetValidateResult, { readonly issues: object }>;
type AssertSuccessDiscriminatesToValue = Expect<Equal<PetSuccess["value"], Pet>>;
type AssertFailureDiscriminatesToIssues = Expect<
  [PetFailure["issues"]] extends [ReadonlyArray<StandardSchemaV1.Issue>] ? true : false
>;

// Reference every assertion alias so a broken constraint surfaces as an error on evaluation.
export type ValidatorTypeContracts = [
  AssertInferOutputPet,
  AssertInferInputPet,
  AssertInferOutputTree,
  AssertBareRequiredTypeStaysUnknown,
  AssertConditionalDoesNotWidenDeclaredProperty,
  AssertResultIsResultUnion,
  AssertResultHasNoPromise,
  AssertSuccessDiscriminatesToValue,
  AssertFailureDiscriminatesToIssues,
];
