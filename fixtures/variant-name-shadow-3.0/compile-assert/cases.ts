// Typechecked after the emitter generates the sibling `../generated` tree.

import type { Pet, PetRequestBody } from "../generated/types/components/pet.js";
import type { PetRequest } from "../generated/types/components/petrequest.js";

// The document's own component keeps its name; `Pet`'s generated request variant moved out of the
// way. These pin that they are two distinct types, not one shadowing the other — a regression that
// let the derived name win would retype `body` to `Pet` minus its readOnly members and still
// compile at the declaration site.
export function componentKeepsItsName(value: PetRequest): PetRequest {
  return value;
}

export function variantIsNotTheComponent(value: PetRequestBody): PetRequest {
  // @ts-expect-error the renamed variant of Pet is a different type from the PetRequest component.
  return value;
}

export function variantDropsReadOnlyMembers(value: PetRequestBody): Omit<Pet, "id"> {
  return value;
}
