// Type-level assertions about the scheme type parameter on the emitted `CallArgs` aliases.
//
// An operation with no auth-conditional argument tuple declares a parameter its alias body never
// mentions, which `noUnusedParameters` reports as TS6196. The fix renames it rather than dropping
// it, so what has to keep holding is everything a name change could plausibly break: explicit
// instantiation still resolves, inference from the transport still resolves, the `orThrow`
// companion still accepts the same tuple, and the aggregate still types every member. Assertions
// over the emitted *text* cannot see any of that — only a compile can.
//
// The file has no runtime behavior and is typechecked only after the emitter writes the sibling
// `../generated-client` tree, so it does NOT typecheck today.
//
// Imports use `.js` suffixes because emit.importExtension resolves to `.js` over the on-disk `.ts`.

import type { CallOptions, Transport } from "../generated-client/runtime/transport.js";
import {
  readTree,
  readTreeOrThrow,
  type ReadTreeCallArgs,
  type ReadTreeInput,
} from "../generated-client/client/operations/readtree.js";
import {
  createPet,
  type CreatePetCallArgs,
  type CreatePetInput,
} from "../generated-client/client/operations/createpet.js";
import { api } from "../generated-client/client/api.js";

// Invariant type equality: true only when A and B are mutually assignable in both variance
// positions. One-way assignability would let a too-wide declared type pass silently.
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Expect<T extends true> = T;

// 1. The unsecured operation's tuple is the same whatever the scheme argument is. That is the
//    property that makes the parameter unused, and renaming it must not change it.
export type AssertUnsecuredTupleIgnoresScheme = Expect<
  Equal<ReadTreeCallArgs<"bearerAuth">, [options?: CallOptions]>
>;
export type AssertUnsecuredTupleIgnoresNever = Expect<
  Equal<ReadTreeCallArgs<never>, [options?: CallOptions]>
>;
export type AssertUnsecuredTupleIsPositional = Expect<
  Equal<ReadTreeCallArgs<"bearerAuth">, ReadTreeCallArgs<"headerKey">>
>;

// 2. The secured operation is the contrast: its tuple genuinely reads the parameter, so the same
//    two instantiations differ. Without this row, an alias that silently stopped consuming the
//    parameter everywhere would still satisfy row 1.
export type AssertSecuredTupleReadsScheme = Expect<
  Equal<
    Equal<CreatePetCallArgs<"bearerAuth">, CreatePetCallArgs<never>>,
    false
  >
>;
export type AssertSatisfiedSecuredTupleIsOptionsOnly = Expect<
  Equal<CreatePetCallArgs<"bearerAuth">, [options?: CallOptions]>
>;

// 3. Call sites. Inference from the transport, explicit instantiation, and the `orThrow`
//    companion each reach the alias by a different route.
export async function callsResolveAtEveryRoute(
  inferred: Transport<never>,
  secured: Transport<"bearerAuth">,
  treeInput: ReadTreeInput,
  petInput: CreatePetInput,
): Promise<void> {
  // Inferred, with no explicit instantiation anywhere.
  void (await readTree(inferred, treeInput));
  void (await readTree(inferred, treeInput, {}));
  // Explicitly instantiated at a scheme the operation does not use.
  void (await readTree<"bearerAuth">(secured, treeInput));
  // The orThrow companion shares the alias.
  void (await readTreeOrThrow(inferred, treeInput));
  void (await readTreeOrThrow<"bearerAuth">(secured, treeInput));
  // The secured operation, whose alias does read the parameter: a satisfied scheme takes the
  // options-only tuple, an unsatisfied one requires the credential argument.
  void (await createPet(secured, petInput));
  void (await createPet(inferred, petInput, { auth: { bearerAuth: "t" } }));
  // @ts-expect-error the credential argument is required when the transport declares no scheme
  void (await createPet(inferred, petInput));
  // The aggregate reaches both through one object.
  void (await api.readTree(inferred, treeInput));
  void (await api.createPet(secured, petInput));
}
