// Frozen conformance vectors for the generated validators artifact. NEVER regenerate these from
// implementation output: every expected verdict and issue below is derived only from the pinned
// validator semantics plus the schemas in fixtures/validators-showcase-3.1/openapi.yaml, and the
// engine is written to satisfy these vectors, not the reverse. Each case names a generated export
// (a component validator such as `petValidator`, or an operation-response validator such as
// `createPetResponse200Validator`) and a keyword row from fixtures/validators-keyword-matrix.yaml.
//
// Validator contract these vectors pin:
//   - Assert-only. On success `validate` returns `{ value }` where `value` is the input by
//     reference (no coercion, no default injection, no unknown-key stripping) and `issues` is
//     absent. On failure it returns `{ issues }` with no `value`.
//   - Type domain. object = a non-null, non-array `object`; array = `Array.isArray`; string and
//     boolean by `typeof`; number = a finite `number`; integer = a finite number that is also an
//     integer (so a whole-valued number such as 1.0 is an integer). Property presence is own-key
//     presence (`Object.hasOwn`), never the prototype chain, so a present-but-undefined property
//     is validated (and normally fails its type check).
//   - Type gating. An assertion keyword applies only when the instance is of the keyword's target
//     JSON type; otherwise it is inert and only the `type` keyword, if present, reports the
//     mismatch. Asserted formats apply only to strings, `format:int32` only to integers.
//   - Collect-all. No fail-fast. Issue order equals evaluation order equals schema document order:
//     properties in declaration order, array items ascending, allOf branches in order.
//   - Compositions. `allOf` aggregates every branch's issues at their own paths. `anyOf` with zero
//     passing branches, and `oneOf` with zero or more than one passing branch, each emit exactly
//     one issue at the composition's own path; nested branch issues are not surfaced. A
//     `discriminator` is never consulted, so it may not change these verdicts.
//   - Paths are `string | number` segments; the root path is the empty array.
//
// Message grammar (every message is lowercase, bounded, derivable from the schema alone, and never
// embeds the instance value; {name} is a schema-side property or type name, {n} a schema-side
// numeric bound):
//   presence    missing required property {name}   (required, or a dependentRequired dependent;
//                                                    path = the object path, key named in message)
//               unexpected property                (additionalProperties:false unknown key;
//                                                    path = the unknown key's path)
//   type/value  expected type {types}              ({types} = declared type(s) in declaration
//                                                    order joined by ", ", e.g. "string, null")
//               value not in enum
//               value not equal to const
//   string      shorter than minLength {n}
//               longer than maxLength {n}
//               does not match pattern
//   number      less than minimum {n}
//               greater than maximum {n}
//               not greater than exclusiveMinimum {n}
//               not less than exclusiveMaximum {n}
//               not a multiple of {n}
//   array       fewer items than minItems {n}
//               more items than maxItems {n}
//               items not unique
//   object      fewer properties than minProperties {n}
//               more properties than maxProperties {n}
//   composition no anyOf branch matched
//               expected exactly one oneOf branch to match
//               (allOf has no message of its own; its branch issues surface at their paths)
//   applicator   value matches not schema
//               property name does not satisfy propertyNames schema
//   format      invalid date-time format
//               invalid date format
//               invalid time format
//               invalid uuid format
//               out of int32 range

export type ConformanceCase = {
  readonly id: string; // unique, stable, e.g. 'minLength/short-string-rejected'
  readonly matrixRow: string; // matrix keyword row this case covers, e.g. 'minLength' or 'format:date-time'
  readonly validator: string; // named export in generated showcase output, e.g. 'petValidator'
  readonly input: unknown;
  readonly expected:
    | { readonly verdict: "pass" }
    | {
        readonly verdict: "fail";
        readonly issues: readonly {
          readonly message: string;
          readonly path: readonly (string | number)[];
        }[];
      };
};

// A syntactically valid UUID reused as the required Pet.id whenever another Pet field is isolated.
const PET_ID = "123e4567-e89b-12d3-a456-426614174000";

export const cases: readonly ConformanceCase[] = [
  // --- type (petValidator) ---
  {
    id: "type/pet-minimal-valid",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    // Collect-all + property declaration order: id before name, both wrong type. `format: uuid`
    // on id is inert because id is not a string.
    id: "type/two-properties-wrong-type",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: 5, name: 6 },
    expected: {
      verdict: "fail",
      issues: [
        { message: "expected type string", path: ["id"] },
        { message: "expected type string", path: ["name"] },
      ],
    },
  },
  {
    id: "type/nickname-null-accepted",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", nickname: null },
    expected: { verdict: "pass" },
  },
  {
    // The 3.1 type array [string, "null"] yields a joined type list in the message.
    id: "type/nickname-wrong-type",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", nickname: 5 },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type string, null", path: ["nickname"] }],
    },
  },
  {
    // A whole-valued number is an integer; 1 denotes 1.0 (JSON has no separate integer literal).
    id: "type/integer-whole-number-accepted",
    matrixRow: "type",
    validator: "numericValidator",
    input: { age: 1 },
    expected: { verdict: "pass" },
  },
  {
    id: "type/integer-fraction-rejected",
    matrixRow: "type",
    validator: "numericValidator",
    input: { age: 1.5 },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type integer", path: ["age"] }],
    },
  },
  {
    // A non-number fails the number type; multipleOf on score is inert.
    id: "type/number-wrong-type",
    matrixRow: "type",
    validator: "numericValidator",
    input: { score: "x" },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type number", path: ["score"] }],
    },
  },

  // --- enum (petValidator, numericValidator) ---
  {
    id: "enum/status-member-accepted",
    matrixRow: "enum",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", status: "pending" },
    expected: { verdict: "pass" },
  },
  {
    id: "enum/status-not-a-member",
    matrixRow: "enum",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", status: "unknown" },
    expected: {
      verdict: "fail",
      issues: [{ message: "value not in enum", path: ["status"] }],
    },
  },
  {
    // Deep equality compares numbers by ===, so -0 equals the enum member 0.
    id: "enum/negative-zero-equals-zero",
    matrixRow: "enum",
    validator: "numericValidator",
    input: { zero: -0 },
    expected: { verdict: "pass" },
  },
  {
    id: "enum/zero-not-a-member",
    matrixRow: "enum",
    validator: "numericValidator",
    input: { zero: 3 },
    expected: {
      verdict: "fail",
      issues: [{ message: "value not in enum", path: ["zero"] }],
    },
  },

  // --- const (petValidator) ---
  {
    id: "const/species-matches",
    matrixRow: "const",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", species: "canis" },
    expected: { verdict: "pass" },
  },
  {
    id: "const/species-differs",
    matrixRow: "const",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", species: "felis" },
    expected: {
      verdict: "fail",
      issues: [{ message: "value not equal to const", path: ["species"] }],
    },
  },

  // --- properties (petValidator) ---
  {
    id: "properties/all-declared-valid",
    matrixRow: "properties",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", status: "sold", species: "canis" },
    expected: { verdict: "pass" },
  },
  {
    // A declared property value is validated against its schema; pattern on slug is inert here.
    id: "properties/declared-value-wrong-type",
    matrixRow: "properties",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", slug: 5 },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type string", path: ["slug"] }],
    },
  },
  {
    // Present-but-undefined is present (key in obj) and is validated, failing its string type.
    id: "properties/present-undefined-validated",
    matrixRow: "properties",
    validator: "petValidator",
    input: { id: PET_ID, name: undefined },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type string", path: ["name"] }],
    },
  },

  // --- required (petValidator, tagValidator, requiredOnlyValidator) ---
  {
    id: "required/pet-present",
    matrixRow: "required",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "required/pet-missing-name",
    matrixRow: "required",
    validator: "petValidator",
    input: { id: PET_ID },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property name", path: [] }],
    },
  },
  {
    id: "required/tag-missing-label",
    matrixRow: "required",
    validator: "tagValidator",
    input: { color: "red" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property label", path: [] }],
    },
  },
  {
    id: "required/typeless-non-object-is-inert",
    matrixRow: "required",
    validator: "requiredOnlyValidator",
    input: "not an object",
    expected: { verdict: "pass" },
  },
  {
    id: "required/typeless-object-present",
    matrixRow: "required",
    validator: "requiredOnlyValidator",
    input: { id: 1 },
    expected: { verdict: "pass" },
  },
  {
    id: "required/typeless-object-missing",
    matrixRow: "required",
    validator: "requiredOnlyValidator",
    input: {},
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property id", path: [] }],
    },
  },

  // --- additionalProperties (petValidator open, tagValidator closed, bagValidator schema) ---
  {
    // The permissive default passes an unknown key through untouched (no stripping).
    id: "additionalProperties/open-passthrough",
    matrixRow: "additionalProperties",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", extra: 999 },
    expected: { verdict: "pass" },
  },
  {
    id: "additionalProperties/closed-valid",
    matrixRow: "additionalProperties",
    validator: "tagValidator",
    input: { label: "blue" },
    expected: { verdict: "pass" },
  },
  {
    // additionalProperties:false rejects the unknown key at the key's own path.
    id: "additionalProperties/closed-unknown-key",
    matrixRow: "additionalProperties",
    validator: "tagValidator",
    input: { label: "blue", extra: 1 },
    expected: {
      verdict: "fail",
      issues: [{ message: "unexpected property", path: ["extra"] }],
    },
  },
  {
    id: "additionalProperties/schema-valid",
    matrixRow: "additionalProperties",
    validator: "bagValidator",
    input: { kind: "x", count: 5 },
    expected: { verdict: "pass" },
  },
  {
    // A schema-valued additionalProperties validates the unknown key's value.
    id: "additionalProperties/schema-wrong-type",
    matrixRow: "additionalProperties",
    validator: "bagValidator",
    input: { kind: "x", count: "no" },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type integer", path: ["count"] }],
    },
  },

  // --- items (petValidator, getTreeResponse200Validator) ---
  {
    id: "items/tag-elements-valid",
    matrixRow: "items",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: "a" }] },
    expected: { verdict: "pass" },
  },
  {
    // Element validation recurses into the referenced Tag; the failure is at the element path.
    id: "items/tag-element-wrong-type",
    matrixRow: "items",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: 5 }] },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type string", path: ["tags", 0, "label"] }],
    },
  },
  {
    id: "items/tree-response-child-wrong-type",
    matrixRow: "items",
    validator: "getTreeResponse200Validator",
    input: { value: "root", children: [{ value: 5 }] },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type string", path: ["children", 0, "value"] }],
    },
  },

  // --- prefixItems (pairValidator) ---
  {
    id: "prefixItems/tuple-valid",
    matrixRow: "prefixItems",
    validator: "pairValidator",
    input: ["x", 1],
    expected: { verdict: "pass" },
  },
  {
    id: "prefixItems/second-position-wrong-type",
    matrixRow: "prefixItems",
    validator: "pairValidator",
    input: ["x", "y"],
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type integer", path: [1] }],
    },
  },

  // --- minLength / maxLength (petValidator), code-point counting ---
  {
    id: "minLength/name-nonempty",
    matrixRow: "minLength",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "minLength/name-empty",
    matrixRow: "minLength",
    validator: "petValidator",
    input: { id: PET_ID, name: "" },
    expected: {
      verdict: "fail",
      issues: [{ message: "shorter than minLength 1", path: ["name"] }],
    },
  },
  {
    // One astral code point (U+1F600) has code-point length 1 < 2; a UTF-16 count of 2 would
    // wrongly pass, so this pins code-point counting for the lower bound.
    id: "minLength/astral-code-point-rejected",
    matrixRow: "minLength",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", code: "\u{1F600}" },
    expected: {
      verdict: "fail",
      issues: [{ message: "shorter than minLength 2", path: ["code"] }],
    },
  },
  {
    // The same astral code point has code-point length 1 <= 1; a UTF-16 count of 2 would wrongly
    // fail, so this pins code-point counting for the upper bound.
    id: "maxLength/astral-code-point-accepted",
    matrixRow: "maxLength",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", emoji: "\u{1F600}" },
    expected: { verdict: "pass" },
  },
  {
    id: "maxLength/name-too-long",
    matrixRow: "maxLength",
    validator: "petValidator",
    input: { id: PET_ID, name: "abcdefghijklmnopqrstu" },
    expected: {
      verdict: "fail",
      issues: [{ message: "longer than maxLength 20", path: ["name"] }],
    },
  },

  // --- pattern (petValidator), unanchored partial match ---
  {
    id: "pattern/contains-digit",
    matrixRow: "pattern",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", slug: "abc1" },
    expected: { verdict: "pass" },
  },
  {
    id: "pattern/no-digit",
    matrixRow: "pattern",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", slug: "abc" },
    expected: {
      verdict: "fail",
      issues: [{ message: "does not match pattern", path: ["slug"] }],
    },
  },

  // --- minimum / maximum (numericValidator) ---
  {
    id: "minimum/age-in-range",
    matrixRow: "minimum",
    validator: "numericValidator",
    input: { age: 5 },
    expected: { verdict: "pass" },
  },
  {
    id: "minimum/age-below",
    matrixRow: "minimum",
    validator: "numericValidator",
    input: { age: -1 },
    expected: {
      verdict: "fail",
      issues: [{ message: "less than minimum 0", path: ["age"] }],
    },
  },
  {
    id: "maximum/age-in-range",
    matrixRow: "maximum",
    validator: "numericValidator",
    input: { age: 5 },
    expected: { verdict: "pass" },
  },
  {
    id: "maximum/age-above",
    matrixRow: "maximum",
    validator: "numericValidator",
    input: { age: 500 },
    expected: {
      verdict: "fail",
      issues: [{ message: "greater than maximum 200", path: ["age"] }],
    },
  },

  // --- exclusiveMinimum / exclusiveMaximum (numericValidator) ---
  {
    id: "exclusiveMinimum/ratio-inside",
    matrixRow: "exclusiveMinimum",
    validator: "numericValidator",
    input: { ratio: 0.5 },
    expected: { verdict: "pass" },
  },
  {
    id: "exclusiveMinimum/ratio-at-bound",
    matrixRow: "exclusiveMinimum",
    validator: "numericValidator",
    input: { ratio: 0 },
    expected: {
      verdict: "fail",
      issues: [{ message: "not greater than exclusiveMinimum 0", path: ["ratio"] }],
    },
  },
  {
    id: "exclusiveMaximum/ratio-inside",
    matrixRow: "exclusiveMaximum",
    validator: "numericValidator",
    input: { ratio: 0.5 },
    expected: { verdict: "pass" },
  },
  {
    id: "exclusiveMaximum/ratio-at-bound",
    matrixRow: "exclusiveMaximum",
    validator: "numericValidator",
    input: { ratio: 1 },
    expected: {
      verdict: "fail",
      issues: [{ message: "not less than exclusiveMaximum 1", path: ["ratio"] }],
    },
  },

  // --- multipleOf (numericValidator), exact IEEE-754 divisibility anchors ---
  {
    // 0.75 is an exact f64 multiple of 0.25.
    id: "multipleOf/quarter-exact",
    matrixRow: "multipleOf",
    validator: "numericValidator",
    input: { score: 0.75 },
    expected: { verdict: "pass" },
  },
  {
    // 10 is an exact multiple of 5.
    id: "multipleOf/five-exact",
    matrixRow: "multipleOf",
    validator: "numericValidator",
    input: { fives: 10 },
    expected: { verdict: "pass" },
  },
  {
    // 0.3's exact f64 value is not an integer multiple of 0.1's exact f64 value.
    id: "multipleOf/tenth-inexact",
    matrixRow: "multipleOf",
    validator: "numericValidator",
    input: { tenths: 0.3 },
    expected: {
      verdict: "fail",
      issues: [{ message: "not a multiple of 0.1", path: ["tenths"] }],
    },
  },

  // --- minItems / maxItems / uniqueItems (petValidator) ---
  {
    id: "minItems/tags-nonempty",
    matrixRow: "minItems",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: "a" }] },
    expected: { verdict: "pass" },
  },
  {
    id: "minItems/tags-empty",
    matrixRow: "minItems",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [] },
    expected: {
      verdict: "fail",
      issues: [{ message: "fewer items than minItems 1", path: ["tags"] }],
    },
  },
  {
    id: "maxItems/tags-within-bound",
    matrixRow: "maxItems",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: "a" }] },
    expected: { verdict: "pass" },
  },
  {
    id: "maxItems/tags-too-many",
    matrixRow: "maxItems",
    validator: "petValidator",
    input: {
      id: PET_ID,
      name: "Rex",
      tags: [{ label: "a" }, { label: "b" }, { label: "c" }, { label: "d" }],
    },
    expected: {
      verdict: "fail",
      issues: [{ message: "more items than maxItems 3", path: ["tags"] }],
    },
  },
  {
    id: "uniqueItems/tags-distinct",
    matrixRow: "uniqueItems",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: "a" }, { label: "b" }] },
    expected: { verdict: "pass" },
  },
  {
    // Two structurally equal objects are equal under deep JSON equality, so the array is not unique.
    id: "uniqueItems/tags-deep-duplicate",
    matrixRow: "uniqueItems",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: [{ label: "a" }, { label: "a" }] },
    expected: {
      verdict: "fail",
      issues: [{ message: "items not unique", path: ["tags"] }],
    },
  },

  // --- minProperties / maxProperties (bagValidator) ---
  {
    id: "minProperties/bag-one-property",
    matrixRow: "minProperties",
    validator: "bagValidator",
    input: { kind: "x" },
    expected: { verdict: "pass" },
  },
  {
    id: "minProperties/bag-empty",
    matrixRow: "minProperties",
    validator: "bagValidator",
    input: {},
    expected: {
      verdict: "fail",
      issues: [{ message: "fewer properties than minProperties 1", path: [] }],
    },
  },
  {
    id: "maxProperties/bag-within-bound",
    matrixRow: "maxProperties",
    validator: "bagValidator",
    input: { kind: "x" },
    expected: { verdict: "pass" },
  },
  {
    id: "maxProperties/bag-too-many",
    matrixRow: "maxProperties",
    validator: "bagValidator",
    input: { a: 1, b: 2, c: 3, d: 4 },
    expected: {
      verdict: "fail",
      issues: [{ message: "more properties than maxProperties 3", path: [] }],
    },
  },

  // --- dependentRequired (accountValidator) ---
  {
    // No trigger key present, so the dependency is inert.
    id: "dependentRequired/trigger-absent",
    matrixRow: "dependentRequired",
    validator: "accountValidator",
    input: {},
    expected: { verdict: "pass" },
  },
  {
    id: "dependentRequired/dependent-present",
    matrixRow: "dependentRequired",
    validator: "accountValidator",
    input: { creditCard: "x", billingAddress: "y" },
    expected: { verdict: "pass" },
  },
  {
    id: "dependentRequired/dependent-missing",
    matrixRow: "dependentRequired",
    validator: "accountValidator",
    input: { creditCard: "x" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property billingAddress", path: [] }],
    },
  },

  // --- allOf (combinedValidator), aggregation + collect-all + branch order ---
  {
    id: "allOf/both-branches-satisfied",
    matrixRow: "allOf",
    validator: "combinedValidator",
    input: { a: "x", b: 1 },
    expected: { verdict: "pass" },
  },
  {
    // Every branch is evaluated and its issues aggregate; branch 0 (a) precedes branch 1 (b).
    id: "allOf/both-branches-fail",
    matrixRow: "allOf",
    validator: "combinedValidator",
    input: {},
    expected: {
      verdict: "fail",
      issues: [
        { message: "missing required property a", path: [] },
        { message: "missing required property b", path: [] },
      ],
    },
  },

  // --- not (notRequiredValidator, notNumberValidator, notObjectValidator) ---
  {
    id: "not/required-subschema-does-not-match",
    matrixRow: "not",
    validator: "notRequiredValidator",
    input: {},
    expected: { verdict: "pass" },
  },
  {
    id: "not/required-subschema-matches",
    matrixRow: "not",
    validator: "notRequiredValidator",
    input: { id: 1 },
    expected: {
      verdict: "fail",
      issues: [{ message: "value matches not schema", path: [] }],
    },
  },
  {
    id: "not/enum-does-not-match",
    matrixRow: "not",
    validator: "notNumberValidator",
    input: 1,
    expected: { verdict: "pass" },
  },
  {
    id: "not/enum-matches",
    matrixRow: "not",
    validator: "notNumberValidator",
    input: 23456,
    expected: {
      verdict: "fail",
      issues: [{ message: "value matches not schema", path: [] }],
    },
  },
  {
    id: "not/object-properties-required-do-not-match",
    matrixRow: "not",
    validator: "notObjectValidator",
    input: { type: "allowed" },
    expected: { verdict: "pass" },
  },
  {
    id: "not/object-properties-required-match",
    matrixRow: "not",
    validator: "notObjectValidator",
    input: { type: "blocked" },
    expected: {
      verdict: "fail",
      issues: [{ message: "value matches not schema", path: [] }],
    },
  },

  // --- propertyNames (namedObjectValidator) ---
  {
    id: "propertyNames/all-names-match",
    matrixRow: "propertyNames",
    validator: "namedObjectValidator",
    input: { valid: 1 },
    expected: { verdict: "pass" },
  },
  {
    id: "propertyNames/name-does-not-match",
    matrixRow: "propertyNames",
    validator: "namedObjectValidator",
    input: { Invalid: 1 },
    expected: {
      verdict: "fail",
      issues: [
        {
          message: "property name does not satisfy propertyNames schema",
          path: ["Invalid"],
        },
      ],
    },
  },

  // --- anyOf (scalarValidator) ---
  {
    id: "anyOf/string-branch",
    matrixRow: "anyOf",
    validator: "scalarValidator",
    input: "abcd",
    expected: { verdict: "pass" },
  },
  {
    id: "anyOf/integer-branch",
    matrixRow: "anyOf",
    validator: "scalarValidator",
    input: 7,
    expected: { verdict: "pass" },
  },
  {
    // Neither branch matches: exactly one issue at the composition path, no nested branch issues.
    id: "anyOf/no-branch",
    matrixRow: "anyOf",
    validator: "scalarValidator",
    input: true,
    expected: {
      verdict: "fail",
      issues: [{ message: "no anyOf branch matched", path: [] }],
    },
  },

  // --- oneOf (shapeValidator discriminated, tokenValidator plain) ---
  {
    id: "oneOf/shape-single-match",
    matrixRow: "oneOf",
    validator: "shapeValidator",
    input: { kind: "circle", radius: 2 },
    expected: { verdict: "pass" },
  },
  {
    id: "oneOf/token-single-match",
    matrixRow: "oneOf",
    validator: "tokenValidator",
    input: 2,
    expected: { verdict: "pass" },
  },
  {
    // Neither branch matches: exactly one issue at the composition path.
    id: "oneOf/token-zero-match",
    matrixRow: "oneOf",
    validator: "tokenValidator",
    input: 1,
    expected: {
      verdict: "fail",
      issues: [{ message: "expected exactly one oneOf branch to match", path: [] }],
    },
  },
  {
    // Both branches match (6 is a multiple of 2 and of 3): exactly one issue at the composition path.
    id: "oneOf/token-multi-match",
    matrixRow: "oneOf",
    validator: "tokenValidator",
    input: 6,
    expected: {
      verdict: "fail",
      issues: [{ message: "expected exactly one oneOf branch to match", path: [] }],
    },
  },

  // --- discriminator is annotation-only (shapeValidator) ---
  {
    // With a mistyped radius, the circle branch and the square branch both fail, so zero branches
    // match and one oneOf issue is emitted. A discriminator-driven engine would instead route to
    // the circle branch and surface its radius error; the single composition issue proves the
    // discriminator is never consulted.
    id: "discriminator/not-consulted-at-runtime",
    matrixRow: "discriminator",
    validator: "shapeValidator",
    input: { kind: "circle", radius: "no" },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected exactly one oneOf branch to match", path: [] }],
    },
  },

  // --- $ref (treeNodeValidator recursion, createPetResponse200Validator) ---
  {
    id: "$ref/tree-valid-depth-3",
    matrixRow: "$ref",
    validator: "treeNodeValidator",
    input: {
      value: "root",
      children: [
        { value: "a", children: [{ value: "b", children: [{ value: "c", children: [] }] }] },
      ],
    },
    expected: { verdict: "pass" },
  },
  {
    // A self-referential $ref recurses; the failure at depth 3 carries the full nested path.
    id: "$ref/tree-deep-node-wrong-type",
    matrixRow: "$ref",
    validator: "treeNodeValidator",
    input: {
      value: "root",
      children: [
        { value: "a", children: [{ value: "b", children: [{ value: 5, children: [] }] }] },
      ],
    },
    expected: {
      verdict: "fail",
      issues: [
        {
          message: "expected type string",
          path: ["children", 0, "children", 0, "children", 0, "value"],
        },
      ],
    },
  },
  {
    id: "$ref/create-pet-response-valid",
    matrixRow: "$ref",
    validator: "createPetResponse200Validator",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },

  // --- operation-response validators exercise the operations directory ---
  {
    id: "required/create-pet-response-missing-id",
    matrixRow: "required",
    validator: "createPetResponse200Validator",
    input: { name: "Rex" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property id", path: [] }],
    },
  },
  {
    id: "$ref/get-tree-response-valid",
    matrixRow: "$ref",
    validator: "getTreeResponse200Validator",
    input: { value: "root" },
    expected: { verdict: "pass" },
  },

  // --- format:date-time (petValidator) ---
  {
    // Leap second 60 is accepted; the trailing Z is case-insensitive.
    id: "format:date-time/leap-second",
    matrixRow: "format:date-time",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", createdAt: "2024-06-30T23:59:60Z" },
    expected: { verdict: "pass" },
  },
  {
    id: "format:date-time/impossible-month",
    matrixRow: "format:date-time",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", createdAt: "2024-13-01T00:00:00Z" },
    expected: {
      verdict: "fail",
      issues: [{ message: "invalid date-time format", path: ["createdAt"] }],
    },
  },

  // --- format:date (petValidator), real calendar ---
  {
    id: "format:date/leap-day-valid",
    matrixRow: "format:date",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", birthday: "2024-02-29" },
    expected: { verdict: "pass" },
  },
  {
    id: "format:date/non-leap-year-feb-29",
    matrixRow: "format:date",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", birthday: "2023-02-29" },
    expected: {
      verdict: "fail",
      issues: [{ message: "invalid date format", path: ["birthday"] }],
    },
  },

  // --- format:time (petValidator), offset required ---
  {
    id: "format:time/with-offset",
    matrixRow: "format:time",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", checkupTime: "08:30:00+09:00" },
    expected: { verdict: "pass" },
  },
  {
    id: "format:time/missing-offset",
    matrixRow: "format:time",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", checkupTime: "08:30:00" },
    expected: {
      verdict: "fail",
      issues: [{ message: "invalid time format", path: ["checkupTime"] }],
    },
  },

  // --- format:uuid (petValidator) ---
  {
    id: "format:uuid/valid",
    matrixRow: "format:uuid",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex" },
    expected: { verdict: "pass" },
  },
  {
    id: "format:uuid/malformed",
    matrixRow: "format:uuid",
    validator: "petValidator",
    input: { id: "not-a-uuid", name: "Rex" },
    expected: {
      verdict: "fail",
      issues: [{ message: "invalid uuid format", path: ["id"] }],
    },
  },

  // --- format:int32 (numericValidator) ---
  {
    id: "format:int32/max-boundary",
    matrixRow: "format:int32",
    validator: "numericValidator",
    input: { bigId: 2147483647 },
    expected: { verdict: "pass" },
  },
  {
    // One past the signed 32-bit maximum; bigId carries no minimum/maximum, so int32 is the only
    // failing keyword.
    id: "format:int32/over-boundary",
    matrixRow: "format:int32",
    validator: "numericValidator",
    input: { bigId: 2147483648 },
    expected: {
      verdict: "fail",
      issues: [{ message: "out of int32 range", path: ["bigId"] }],
    },
  },

  // --- patternProperties (patternBagValidator) ---
  {
    id: "patternProperties/declared-and-pattern-keys-valid",
    matrixRow: "patternProperties",
    validator: "patternBagValidator",
    input: { fixed: "kept-string", "x-count": 3 },
    expected: { verdict: "pass" },
  },
  {
    // x-count matches both /^x-/u and /count$/u; both schemas apply, so the second maximum fails.
    id: "patternProperties/name-matching-two-patterns",
    matrixRow: "patternProperties",
    validator: "patternBagValidator",
    input: { fixed: "kept-string", "x-count": 6 },
    expected: {
      verdict: "fail",
      issues: [{ message: "greater than maximum 5", path: ["x-count"] }],
    },
  },
  {
    // A key matched by patternProperties is not also processed by additionalProperties:false.
    id: "patternProperties/matched-key-is-not-additional",
    matrixRow: "patternProperties",
    validator: "patternBagValidator",
    input: { "x-extra": 2 },
    expected: { verdict: "pass" },
  },

  // --- contains/minContains/maxContains ---
  {
    id: "contains/one-match",
    matrixRow: "contains",
    validator: "containsDefaultValidator",
    input: ["no", 1],
    expected: { verdict: "pass" },
  },
  {
    id: "contains/no-match",
    matrixRow: "contains",
    validator: "containsDefaultValidator",
    input: ["no", false],
    expected: {
      verdict: "fail",
      issues: [{ message: "no array item matches contains schema", path: [] }],
    },
  },
  {
    id: "minContains/two-matches",
    matrixRow: "minContains",
    validator: "containsRangeValidator",
    input: [1, "no", 2],
    expected: { verdict: "pass" },
  },
  {
    id: "minContains/one-match",
    matrixRow: "minContains",
    validator: "containsRangeValidator",
    input: [1, "no"],
    expected: {
      verdict: "fail",
      issues: [{ message: "fewer matching items than minContains 2", path: [] }],
    },
  },
  {
    id: "maxContains/three-matches",
    matrixRow: "maxContains",
    validator: "containsRangeValidator",
    input: [1, 2, 3],
    expected: { verdict: "pass" },
  },
  {
    id: "maxContains/four-matches",
    matrixRow: "maxContains",
    validator: "containsRangeValidator",
    input: [1, 2, 3, 4],
    expected: {
      verdict: "fail",
      issues: [{ message: "more matching items than maxContains 3", path: [] }],
    },
  },
  {
    // minContains:0 makes contains itself pass even when the empty array has no matching item.
    id: "minContains/zero-allows-no-match",
    matrixRow: "minContains",
    validator: "containsOptionalValidator",
    input: [],
    expected: { verdict: "pass" },
  },
  {
    // maxContains remains active beside minContains:0.
    id: "maxContains/zero-minimum-still-bounded",
    matrixRow: "maxContains",
    validator: "containsOptionalValidator",
    input: ["one", "two"],
    expected: {
      verdict: "fail",
      issues: [{ message: "more matching items than maxContains 1", path: [] }],
    },
  },

  // --- dependentSchemas (dependentAccountValidator) ---
  {
    id: "dependentSchemas/trigger-absent",
    matrixRow: "dependentSchemas",
    validator: "dependentAccountValidator",
    input: { billingAddress: "x" },
    expected: { verdict: "pass" },
  },
  {
    id: "dependentSchemas/trigger-present-and-dependent-schema-fails",
    matrixRow: "dependentSchemas",
    validator: "dependentAccountValidator",
    input: { creditCard: "1234" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property billingAddress", path: [] }],
    },
  },
  {
    // The dependency schema applies to the whole object, so it can inspect billingAddress.
    id: "dependentSchemas/whole-object-schema",
    matrixRow: "dependentSchemas",
    validator: "dependentAccountValidator",
    input: { creditCard: "1234", billingAddress: "x" },
    expected: {
      verdict: "fail",
      issues: [{ message: "shorter than minLength 3", path: ["billingAddress"] }],
    },
  },

  // --- if/then/else (conditionalProfileValidator) ---
  {
    // Failing `if` selects `else`; the failed condition is not itself an assertion failure.
    id: "if/failed-condition-selects-valid-else",
    matrixRow: "if",
    validator: "conditionalProfileValidator",
    input: { kind: "personal", personalName: "Ada" },
    expected: { verdict: "pass" },
  },
  {
    id: "if/matched-condition-selects-failing-then",
    matrixRow: "if",
    validator: "conditionalProfileValidator",
    input: { kind: "business" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property companyName", path: [] }],
    },
  },
  {
    id: "then/active-branch-satisfied",
    matrixRow: "then",
    validator: "conditionalProfileValidator",
    input: { kind: "business", companyName: "Acme" },
    expected: { verdict: "pass" },
  },
  {
    id: "then/active-branch-fails",
    matrixRow: "then",
    validator: "conditionalProfileValidator",
    input: { kind: "business" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property companyName", path: [] }],
    },
  },
  {
    id: "else/active-branch-satisfied",
    matrixRow: "else",
    validator: "conditionalProfileValidator",
    input: { kind: "personal", personalName: "Ada" },
    expected: { verdict: "pass" },
  },
  {
    id: "else/active-branch-fails",
    matrixRow: "else",
    validator: "conditionalProfileValidator",
    input: { kind: "personal" },
    expected: {
      verdict: "fail",
      issues: [{ message: "missing required property personalName", path: [] }],
    },
  },

  // --- unevaluatedProperties / unevaluatedItems ---
  {
    // `alpha` is evaluated only by the successful first anyOf branch.
    id: "unevaluatedProperties/successful-anyof-annotation-is-visible",
    matrixRow: "unevaluatedProperties",
    validator: "unevaluatedChoiceValidator",
    input: { alpha: "kept" },
    expected: { verdict: "pass" },
  },
  {
    id: "unevaluatedProperties/uncovered-property-rejected",
    matrixRow: "unevaluatedProperties",
    validator: "unevaluatedChoiceValidator",
    input: { alpha: "kept", extra: true },
    expected: {
      verdict: "fail",
      issues: [{ message: "value not allowed", path: ["extra"] }],
    },
  },
  {
    // Index 0 is evaluated by prefixItems and indexes 1 and 2 by successful contains matches.
    id: "unevaluatedItems/prefix-and-contains-cover-array",
    matrixRow: "unevaluatedItems",
    validator: "unevaluatedSequenceValidator",
    input: ["head", 1, 2],
    expected: { verdict: "pass" },
  },
  {
    id: "unevaluatedItems/uncovered-index-rejected",
    matrixRow: "unevaluatedItems",
    validator: "unevaluatedSequenceValidator",
    input: ["head", 1, "tail"],
    expected: {
      verdict: "fail",
      issues: [{ message: "value not allowed", path: [2] }],
    },
  },

  // --- coverage additions: boolean type, type-mismatch positions, format casing, deep-equality
  //     key order, and 2020-12 tuple-rest (items after prefixItems) ---
  {
    id: "type/pet-boolean-accepted",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", vaccinated: true },
    expected: { verdict: "pass" },
  },
  {
    id: "type/pet-boolean-wrong-type",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", vaccinated: 1 },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type boolean", path: ["vaccinated"] }],
    },
  },
  {
    // A non-object at the root of an object-typed validator fails the object type at the root path.
    id: "type/pet-not-an-object",
    matrixRow: "type",
    validator: "petValidator",
    input: 5,
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type object", path: [] }],
    },
  },
  {
    // A non-array where an array is declared fails the array type at the property path; the array
    // constraints (items, minItems, ...) are inert on a non-array.
    id: "type/tags-not-an-array",
    matrixRow: "type",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", tags: 5 },
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type array", path: ["tags"] }],
    },
  },
  {
    // The T separator and Z zone are case-insensitive, so lowercase markers still pass.
    id: "format:date-time/lowercase-markers",
    matrixRow: "format:date-time",
    validator: "petValidator",
    input: { id: PET_ID, name: "Rex", createdAt: "2024-06-30t23:59:60z" },
    expected: { verdict: "pass" },
  },
  {
    // The two elements carry the same keys in different declaration order; key-order-insensitive
    // deep equality makes them equal, so the array is not unique.
    id: "uniqueItems/tags-key-order-insensitive",
    matrixRow: "uniqueItems",
    validator: "petValidator",
    input: {
      id: PET_ID,
      name: "Rex",
      tags: [
        { label: "a", color: "b" },
        { color: "b", label: "a" },
      ],
    },
    expected: {
      verdict: "fail",
      issues: [{ message: "items not unique", path: ["tags"] }],
    },
  },
  {
    // 2020-12 semantics: `items` constrains elements past the two prefixItems positions.
    id: "items/pair-rest-valid",
    matrixRow: "items",
    validator: "pairValidator",
    input: ["x", 1, true],
    expected: { verdict: "pass" },
  },
  {
    // A rest element that violates the `items` schema fails at its own index.
    id: "items/pair-rest-wrong-type",
    matrixRow: "items",
    validator: "pairValidator",
    input: ["x", 1, "no"],
    expected: {
      verdict: "fail",
      issues: [{ message: "expected type boolean", path: [2] }],
    },
  },
];
