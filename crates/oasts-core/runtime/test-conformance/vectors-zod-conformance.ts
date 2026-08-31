// Frozen conformance vectors for the zod artifact. NEVER regenerate these from implementation
// output: every expected verdict and issue path below is derived only from the pinned zod contract
// plus the schemas in fixtures/validators-showcase-3.1/openapi.yaml, and the emitter is written to
// satisfy these vectors, not the reverse. Each case names a generated export (a component schema
// such as `petSchema`) and a keyword row from fixtures/validators-keyword-matrix.yaml — the zod
// engine joins the SAME capability matrix as the generated-validators engine, so no
// second matrix file exists.
//
// What these vectors pin, and what they deliberately do not:
//
//   - Assert-only value contract. On success the parsed value is deep-equal to the
//     input: no unknown-key stripping, no defaults injection, no coercion. Zod reconstructs
//     objects, so the emitted schemas must be built from the value-preserving object modes —
//     `z.looseObject` for the permissive OpenAPI default, `z.strictObject` for
//     `additionalProperties: false`, `.catchall()` for a schema — never the key-stripping
//     `z.object`, never `.default()`, never `z.coerce.*`.
//   - Structural, not referential, identity. The generated-validators engine returns the input by
//     reference; zod returns a reconstructed object whose declared properties come first and whose
//     unknown keys follow. The success value is required to be structurally identical to the
//     input, which key reordering satisfies and which a serialized comparison would not. Every
//     pass case below is therefore checked with deep structural equality.
//   - Issue paths, where a path is the engine-independent part of a failure. Issue *messages* are
//     vendor text and are deliberately NOT pinned: the engines are required to agree on
//     verdicts and success values, not on issue prose. `z.strictObject` reports one
//     `unrecognized_keys` issue at the object's own path with the offending keys named in the
//     message, where the generated engine reports one issue per key at that key's path — a
//     permitted divergence precisely because messages and issue shapes are engine-local.
//   - Constraint semantics that Zod's native methods get differently from this compiler's frozen
//     contract, which is why the emitter routes them through the shared runtime predicates instead:
//     `maxLength` counts Unicode code points, where Zod's native `.max()` counted UTF-16 units through 4.4 and counts code points from 4.5, so an astral emoji measures 1 here and measured 2 under half the supported peer range.
//     `multipleOf` is exact over IEEE-754 (0.3 is not a multiple of 0.1) rather than tolerance-based, on every version in that range.

export type ZodConformanceCase = {
  readonly id: string; // unique, stable, e.g. 'looseObject/unknown-key-preserved'
  readonly matrixRow: string; // matrix keyword row this case covers
  readonly schema: string; // named export in generated showcase output, e.g. 'petSchema'
  readonly input: unknown;
  readonly expected:
    | { readonly verdict: "pass" } // the parsed value must be deep-equal to `input`
    | {
        readonly verdict: "fail";
        // One entry per expected issue, in the order zod reports them. Messages are not pinned.
        readonly issuePaths: readonly (readonly (string | number)[])[];
      };
};

// A syntactically valid UUID reused as the required Pet.id whenever another Pet field is isolated.
const PET_ID = "123e4567-e89b-12d3-a456-426614174000";

export const cases: readonly ZodConformanceCase[] = [
  // --- assert-only value contract: the whole reason the object mode is chosen per schema ---
  {
    // Pet declares no `additionalProperties`, so the OpenAPI permissive default applies and an
    // unknown key must survive validation untouched. This is the case `z.object` would break.
    id: "additionalProperties/unknown-key-preserved",
    matrixRow: "additionalProperties",
    schema: "petSchema",
    input: { id: PET_ID, name: "Rex", extra: 1 },
    expected: { verdict: "pass" },
  },
  {
    // A structured unknown value survives whole, not just a scalar one.
    id: "additionalProperties/nested-unknown-value-preserved",
    matrixRow: "additionalProperties",
    schema: "petSchema",
    input: { id: PET_ID, name: "Rex", extra: { nested: [1, "two"] } },
    expected: { verdict: "pass" },
  },
  {
    // Absent optional properties stay absent: no key may be injected with an undefined value, and
    // no `default` may be materialized. Deep equality over the key set is what proves it.
    id: "default/absent-optionals-are-not-injected",
    matrixRow: "default",
    schema: "petSchema",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    // No coercion: a number is not silently accepted as the declared string.
    id: "type/no-coercion-of-a-wrong-typed-property",
    matrixRow: "type",
    schema: "petSchema",
    input: { id: PET_ID, name: 123 },
    expected: { verdict: "fail", issuePaths: [["name"]] },
  },

  // --- object modes ---
  {
    // Tag sets `additionalProperties: false`, so an unknown key is rejected. Zod reports a single
    // `unrecognized_keys` issue at the object's own path.
    id: "additionalProperties/false-rejects-unknown-key",
    matrixRow: "additionalProperties",
    schema: "tagSchema",
    input: { label: "a", extra: 1 },
    expected: { verdict: "fail", issuePaths: [[]] },
  },
  {
    // Bag's `additionalProperties: {type: integer}` becomes a catchall: the extra key is both
    // validated and preserved.
    id: "additionalProperties/schema-validates-and-preserves-extra",
    matrixRow: "additionalProperties",
    schema: "bagSchema",
    input: { kind: "k", count: 1 },
    expected: { verdict: "pass" },
  },
  {
    id: "additionalProperties/schema-rejects-wrong-typed-extra",
    matrixRow: "additionalProperties",
    schema: "bagSchema",
    input: { kind: "k", count: "no" },
    expected: { verdict: "fail", issuePaths: [["count"]] },
  },

  // --- constraints the emitter must route through the shared runtime, not Zod's natives ---
  {
    // Pet.emoji has maxLength 1.
    // U+1F600 is one code point and two UTF-16 units; the contract counts code points, so this passes.
    // Zod's native `.max(1)` rejected it through 4.4 and accepts it from 4.5, which is why the verdict comes from the runtime predicate rather than from Zod.
    id: "maxLength/astral-code-point-accepted",
    matrixRow: "maxLength",
    schema: "petSchema",
    input: { id: PET_ID, name: "Rex", emoji: "\u{1F600}" },
    expected: { verdict: "pass" },
  },
  {
    // Numeric.tenths has multipleOf 0.1. 0.3's exact f64 value is not an integer multiple of
    // 0.1's exact f64 value, so the exact contract rejects it.
    id: "multipleOf/tenth-inexact-rejected",
    matrixRow: "multipleOf",
    schema: "numericSchema",
    input: { tenths: 0.3 },
    expected: { verdict: "fail", issuePaths: [["tenths"]] },
  },
  {
    id: "multipleOf/quarter-exact-accepted",
    matrixRow: "multipleOf",
    schema: "numericSchema",
    input: { score: 0.75 },
    expected: { verdict: "pass" },
  },

  // --- recursion: emitted with zod's deferred form, and it must still reach depth ---
  {
    id: "$ref/recursive-node-accepted",
    matrixRow: "$ref",
    schema: "treeNodeSchema",
    input: { value: "root", children: [{ value: "outer", children: [{ value: "inner" }] }] },
    expected: { verdict: "pass" },
  },
  {
    // Only the node at depth 2 is invalid. This cannot fail if the recursive reference widens.
    id: "$ref/recursive-node-depth-2-rejected",
    matrixRow: "$ref",
    schema: "treeNodeSchema",
    input: { value: "root", children: [{ value: "outer", children: [{ value: 5 }] }] },
    expected: { verdict: "fail", issuePaths: [["children", 0, "children", 0, "value"]] },
  },

  // --- composition: oneOf is exactly-one, which zod's anyOf-shaped union does not give on its own
  {
    id: "oneOf/single-matching-branch-accepted",
    matrixRow: "oneOf",
    schema: "shapeSchema",
    input: { kind: "circle", radius: 1 },
    expected: { verdict: "pass" },
  },
  {
    id: "oneOf/no-matching-branch-rejected",
    matrixRow: "oneOf",
    schema: "shapeSchema",
    input: { kind: "triangle" },
    expected: { verdict: "fail", issuePaths: [[]] },
  },

  // --- unevaluatedProperties over successful anyOf branches ---
  {
    id: "unevaluatedProperties/successful-branch-annotation-is-visible",
    matrixRow: "unevaluatedProperties",
    schema: "unevaluatedChoiceSchema",
    input: { alpha: "kept" },
    expected: { verdict: "pass" },
  },
  {
    id: "unevaluatedProperties/uncovered-property-rejected",
    matrixRow: "unevaluatedProperties",
    schema: "unevaluatedChoiceSchema",
    input: { alpha: "kept", extra: true },
    expected: { verdict: "fail", issuePaths: [["extra"]] },
  },
  {
    id: "unevaluatedItems/prefix-and-contains-cover-array",
    matrixRow: "unevaluatedItems",
    schema: "unevaluatedSequenceSchema",
    input: ["head", 1, 2],
    expected: { verdict: "pass" },
  },
  {
    id: "unevaluatedItems/uncovered-index-rejected",
    matrixRow: "unevaluatedItems",
    schema: "unevaluatedSequenceSchema",
    input: ["head", 1, "tail"],
    expected: { verdict: "fail", issuePaths: [[2]] },
  },
];
