// Type-level enforcement matrix for the generated tanstack artifact.
//
// Every exported binding is a compile-time assertion. A positive one carries no marker and must
// typecheck; a negative one carries a single `@ts-expect-error` whose sole cause is the property
// named in the comment above it.
//
// This file deliberately imports no TanStack package. Generated tanstack code imports none either,
// so introducing one here would test the dependency rather than the artifact. What a descriptor
// owes an adapter is structural — a `queryKey` array and a `queryFn` taking the fetch context —
// and that is asserted against the local `QueryOptionsLike` / `MutationOptionsLike` shapes below.
// Whether a real `QueryClient` accepts and drives these objects is proven by the end-to-end suite,
// which uses the real thing rather than a type that resembles it.
//
// Typechecked after the emitter generates the sibling ../generated-tanstack tree.

import type { Transport } from "../generated-tanstack/runtime/transport.js";
import type { ApiError } from "../generated-tanstack/runtime/result.js";
import type { Pet } from "../generated-tanstack/types/components/pet.js";
import type { GetPetResult } from "../generated-tanstack/client/operations/getpet.js";

import {
  getPetQuery,
  type GetPetQueryData,
  type GetPetQueryError,
  type GetPetQueryKey,
} from "../generated-tanstack/tanstack/operations/getpet.js";
import { listPetsQuery } from "../generated-tanstack/tanstack/operations/listpets.js";
import { getSecureQuery } from "../generated-tanstack/tanstack/operations/getsecure.js";
import { searchQuery } from "../generated-tanstack/tanstack/operations/search.js";
import {
  createPetMutation,
  createPetMutationAffects,
} from "../generated-tanstack/tanstack/operations/createpet.js";
import {
  updatePetMutation,
  updatePetMutationAffects,
  type UpdatePetMutationData,
} from "../generated-tanstack/tanstack/operations/updatepet.js";
import {
  deletePetMutation,
  deletePetMutationAffects,
} from "../generated-tanstack/tanstack/operations/deletepet.js";
import { deleteToyMutationAffects } from "../generated-tanstack/tanstack/operations/deletetoy.js";

// A query-ineligible read emits no descriptor at all. These three cover the three ways a read
// fails the rule: a bodyless method, a lone bodyless success branch, and a payload union that
// admits undefined because one of two success branches is bodyless.
// @ts-expect-error headPet is bodyless by method, so no query descriptor exists.
import { headPetQuery } from "../generated-tanstack/tanstack/operations/headpet.js";
// @ts-expect-error getPetStatus's only success branch is bodyless.
import { getPetStatusQuery } from "../generated-tanstack/tanstack/operations/getpetstatus.js";
// @ts-expect-error getPetSummary's success payload union admits undefined.
import { getPetSummaryQuery } from "../generated-tanstack/tanstack/operations/getpetsummary.js";

export type UnusedIneligible = [
  typeof headPetQuery,
  typeof getPetStatusQuery,
  typeof getPetSummaryQuery,
];

// --- the structural contract an adapter's options object needs -----------------------------

type QueryOptionsLike<Data> = {
  queryKey: readonly unknown[];
  queryFn: (context: { signal: AbortSignal }) => Promise<Data>;
};

type MutationOptionsLike<Data, Input> = {
  mutationKey: readonly unknown[];
  mutationFn: (input: Input) => Promise<Data>;
};

/** Compiles only when `Actual` and `Expected` are mutually assignable. */
type Exact<Actual, Expected> =
  (<T>() => T extends Actual ? 1 : 2) extends <T>() => T extends Expected ? 1 : 2 ? true : false;

declare function expectExact<Expected>(): <Actual>(
  ...check: Exact<Actual, Expected> extends true ? [] : [never]
) => void;

// --- transports typed by the scheme names they were configured with -------------------------

declare const anonymous: Transport<never>;
declare const withApiKey: Transport<"apiKey">;

// --- a descriptor is an options object ------------------------------------------------------

export const petOptions: QueryOptionsLike<Pet> = getPetQuery(anonymous, { path: { petId: "7" } });

export const petsOptions: QueryOptionsLike<Pet[]> = listPetsQuery(anonymous, {});

export const searchOptions: QueryOptionsLike<Pet[]> = searchQuery(anonymous, {
  query: { q: "cat" },
});

// --- the payload, never the envelope --------------------------------------------------------

// GetPetQueryData is what the query resolves. If the descriptor resolved the client's envelope
// this would be `{ data: Pet; meta: ResponseMeta }` and both assertions below would fail.
export const dataIsPayload = expectExact<Pet>()<GetPetQueryData>();

// @ts-expect-error the descriptor resolves the payload, so its data is not the client envelope.
export const dataIsNotEnvelope: { data: Pet } = await petOptions.queryFn({
  signal: AbortSignal.abort(),
});

// --- the error type names the operation's documented failures --------------------------------

export const errorIsTyped = expectExact<
  ApiError<Extract<GetPetResult, { ok: false }>>
>()<GetPetQueryError>();

// The key type is the descriptor's own key, so a hand-written invalidation call can be typed by it.
export const keyIsReadonly: GetPetQueryKey = getPetQuery(anonymous, {
  path: { petId: "7" },
}).queryKey;

// @ts-expect-error the emitted key is readonly, so it cannot be assigned to a mutable array.
export const keyIsNotMutable: unknown[] = keyIsReadonly;

// --- the auth proof survives the wrapper -----------------------------------------------------

// A transport proving the operation's scheme needs no options argument.
export const securedWithProof = getSecureQuery(withApiKey, { path: { id: "9" } });

// @ts-expect-error an unproven transport still owes the operation its credential set.
export const securedWithoutProof = getSecureQuery(anonymous, { path: { id: "9" } });

// Supplying the credential set explicitly satisfies an unproven transport, exactly as the
// underlying call does — the descriptor neither adds nor removes a requirement.
export const securedWithOverride = getSecureQuery(
  anonymous,
  { path: { id: "9" } },
  { auth: { apiKey: "secret" } },
);

// --- mutations --------------------------------------------------------------------------------

export const createOptions: MutationOptionsLike<Pet, { body: { name: string } }> =
  createPetMutation(anonymous);

export const updateOptions: MutationOptionsLike<Pet, { path: { petId: string }; body: { name: string } }> =
  updatePetMutation(anonymous);

export const updateDataIsPayload = expectExact<Pet>()<UpdatePetMutationData>();

// A bodyless mutation resolves undefined, which TanStack permits for mutations and forbids for
// queries. That asymmetry is why deletePet has a mutation descriptor and headPet has no query one.
export const deleteOptions: MutationOptionsLike<undefined, { path: { petId: string } }> =
  deletePetMutation(anonymous);

// --- invalidation lists -------------------------------------------------------------------------

// A collection-level mutation yields the collection key alone.
export const createAffects: readonly [readonly unknown[]] = createPetMutationAffects({
  body: { name: "Rex" },
});

// An entity mutation yields the parent collection key and then the entity key, broadest first.
export const updateAffects: readonly [readonly unknown[], readonly unknown[]] =
  updatePetMutationAffects({ path: { petId: "7" }, body: { name: "Rex" } });

export const deleteAffects: readonly [readonly unknown[], readonly unknown[]] =
  deletePetMutationAffects({ path: { petId: "7" } });

// A nested entity mutation threads every ancestor parameter into the parent collection key. An
// implementation that forgot one would not typecheck here, which is the failure this pins.
export const deleteToyAffects: readonly [readonly unknown[], readonly unknown[]] =
  deleteToyMutationAffects({ path: { petId: "7", toyId: "3" } });

// @ts-expect-error the invalidation list needs the input's path parameters, not no arguments.
export const affectsNeedsInput = deleteToyMutationAffects();
