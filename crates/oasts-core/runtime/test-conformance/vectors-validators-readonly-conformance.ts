// Frozen conformance vectors for the position-variant validators generated from
// fixtures/validators-readonly-3.1. NEVER regenerate these from implementation output: every
// verdict below is derived only from the OAS 3.1 readOnly/writeOnly variance rules plus that
// fixture's schemas, and the engine is written to satisfy these vectors, not the reverse.
//
// These exercise the request/response validator split that the showcase set (whose schemas carry no
// readOnly/writeOnly) never reaches: the request variant drops a readOnly-required member, the
// response variant drops a writeOnly member, and variance flows transitively across a $ref. They
// run under the same runner and contract as the showcase vectors, selected by the
// OASTS_VALIDATORS_CONFORMANCE_FIXTURE=readonly environment variable; the matrix-coverage self-checks
// are showcase-only, so `matrixRow` here names the annotation row each case documents.
import type { ConformanceCase } from "./vectors-validators-conformance.ts";

export const cases: readonly ConformanceCase[] = [
  {
    id: "position-variant/pet-request-accepts-missing-readonly-id",
    matrixRow: "readOnly",
    validator: "petRequestValidator",
    // `id` is readOnly and required on the neutral Pet; the request variant drops it, so a request
    // body without the server-assigned `id` is valid. (This is the reported bug: the request
    // validator must accept the very payload the neutral one rejects.)
    input: { name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "position-variant/pet-neutral-rejects-missing-readonly-id",
    matrixRow: "readOnly",
    validator: "petValidator",
    // The neutral validator keeps `id` required, so the same payload is rejected — proving the
    // request variant is a distinct, laxer validator, not the neutral one reused.
    input: { name: "Rex" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property id", path: [] }],
    },
  },
  {
    id: "position-variant/pet-response-accepts-missing-writeonly-secret",
    matrixRow: "writeOnly",
    validator: "petResponseValidator",
    // `secret` is writeOnly; the response variant drops it, so a response body carrying only the
    // response-side members is valid. `id` is format:uuid and stays required in the response.
    input: { id: "11111111-2222-3333-4444-555555555555", name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "position-variant/envelope-request-accepts-nested-pet-missing-id",
    matrixRow: "readOnly",
    validator: "envelopeRequestValidator",
    // Envelope carries no marker of its own; its request variant exists only because Pet's does and
    // validates the nested pet against the Pet *request* variant, so a nested pet without the
    // readOnly `id` is accepted transitively across the $ref.
    input: { pet: { name: "Rex" } },
    expected: { verdict: "pass" },
  },
];
