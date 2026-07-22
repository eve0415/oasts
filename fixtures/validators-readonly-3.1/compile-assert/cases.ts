// Type-level assertions for the readOnly/writeOnly validator variants. This file has no runtime
// behavior; it is typechecked only after the emitter writes the sibling `../generated` tree, so it
// does NOT typecheck today. Each assignment pins that a validator's declared static type is the
// correct position variant — a mismatch surfaces as a tsc assignability error.
//
// Imports use `.js` suffixes because emit.importExtension resolves to `.js` over the on-disk `.ts`.

import type { SyncStandardSchemaV1 } from "../generated/validators/standard-schema.js";
import type { PetRequest, PetResponse } from "../generated/types/components/pet.js";
import type {
  EnvelopeRequest,
  EnvelopeResponse,
} from "../generated/types/components/envelope.js";
import {
  petRequestValidator,
  petResponseValidator,
} from "../generated/validators/components/pet.js";
import {
  envelopeRequestValidator,
  envelopeResponseValidator,
} from "../generated/validators/components/envelope.js";
import {
  createPetRequestBodyValidator,
  createPetResponse200Validator,
} from "../generated/validators/operations/createpet.js";

// The request body validator's static type is the Request variant (the readOnly `id` is dropped),
// and the response validator's is the Response variant (the writeOnly `secret` is dropped).
export const createPetRequestBodyIsPetRequest: SyncStandardSchemaV1<PetRequest> =
  createPetRequestBodyValidator;
export const createPetResponseIsPetResponse: SyncStandardSchemaV1<PetResponse> =
  createPetResponse200Validator;

// The component variant validators carry their variant types directly.
export const petRequestIsRequest: SyncStandardSchemaV1<PetRequest> = petRequestValidator;
export const petResponseIsResponse: SyncStandardSchemaV1<PetResponse> = petResponseValidator;

// Transitive variance: Envelope carries no marker of its own, yet its variants exist because it
// references Pet, and they are typed to the variant shapes.
export const envelopeRequestIsRequest: SyncStandardSchemaV1<EnvelopeRequest> =
  envelopeRequestValidator;
export const envelopeResponseIsResponse: SyncStandardSchemaV1<EnvelopeResponse> =
  envelopeResponseValidator;
