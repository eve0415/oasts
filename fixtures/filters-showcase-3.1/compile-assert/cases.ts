// Type-level enforcement matrix for operation and schema filtering.
//
// Every exported binding is a compile-time assertion. A positive one carries no marker and must
// typecheck; a negative one carries a single `@ts-expect-error` whose sole cause is the module
// named in the comment above it — a module that must not exist because filtering or pruning
// removed what it would have declared.
//
// Typechecked after the emitter generates the sibling ../generated tree under oasts.yaml, whose
// only filter excludes the `/admin/` path prefix.

type Expect<T extends true> = T;
type Equal<X, Y> =
  (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? true : false;

// A component a surviving operation reaches is emitted, with the shape the document declares.
import type { PetSummary } from "../generated/types/components/petsummary.js";
import type { PetInput } from "../generated/types/components/petinput.js";

export type AssertPetSummaryShape = Expect<
  Equal<PetSummary, { id: string; name: string }>
>;
export type AssertPetInputName = Expect<Equal<PetInput["name"], string>>;

// A webhook is a reachability root: a component only its operation reaches survives.
import type { WebhookOnly } from "../generated/types/components/webhookonly.js";

export type AssertWebhookOnlySurvives = Expect<Equal<WebhookOnly["petId"], string>>;

// The callbacks of a surviving operation are roots too.
import type { CallbackOnly } from "../generated/types/components/callbackonly.js";

export type AssertCallbackOnlySurvives = Expect<Equal<CallbackOnly["stored"], boolean>>;

// A component nothing reaches is pruned, so its module is never written.
// @ts-expect-error ../generated/types/components/orphan.js is not emitted
import type { Orphan } from "../generated/types/components/orphan.js";

export type AssertOrphanIsPruned = Orphan;

// `petSummary` is reachable only from the excluded `/admin/pets` operation. Filtering removes
// that operation, pruning removes the schema, and the identifier collision with `PetSummary`
// goes with it — which is why this tree exists at all.
// @ts-expect-error ../generated/types/operations/adminlistpets.js is not emitted
import type { AdminListPetsResponse200 } from "../generated/types/operations/adminlistpets.js";

export type AssertFilteredOperationIsGone = AdminListPetsResponse200;

// Operations the filter admits keep their own modules, including the deprecated one — that axis
// is off by default — and the webhook operation.
import type { ListPetsResponse200 } from "../generated/types/operations/listpets.js";
import type { DeletePetRequest } from "../generated/types/operations/deletepet.js";

export type AssertSurvivingOperation = Expect<Equal<ListPetsResponse200, PetSummary[]>>;
export type AssertDeprecatedOperationSurvivesByDefault = DeletePetRequest;
