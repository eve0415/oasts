// Vendored Standard Schema v1 interface (from @standard-schema/spec, MIT). The spec FAQ
// recommends vendoring the declaration rather than depending on the package, so the generated
// validators artifact carries this copy and exposes no third-party runtime dependency. Every
// generated component and operation-response validator is a `StandardSchemaV1`: its assert-only
// `~standard.validate` returns `{ value }` on success (the input by reference) or `{ issues }`
// on failure, never a Promise. This is the minimal typed surface that contract depends on: the
// widely-deployed v1 consumer shape. The current spec package (1.1.0) additionally declares an
// optional `options` parameter on `validate`, a `StandardTypedV1` base, and `StandardJSONSchemaV1`;
// all are deliberately omitted — a fewer-parameter `validate` stays assignable in both directions,
// and the JSON-Schema converter is out of scope for a runtime validator.
//
// The client runtime's `runtime/standard-schema.ts` (minimal Issue/PathSegment only) is a distinct,
// deliberately smaller file and must not be unified with this one.
//
// No relative imports: this declaration is self-contained, so the emit engine copies it verbatim
// with no `.ts` suffix rewriting.

/** The Standard Schema interface. */
export interface StandardSchemaV1<Input = unknown, Output = Input> {
  /** The Standard Schema properties. */
  readonly "~standard": StandardSchemaV1.Props<Input, Output>;
}

export declare namespace StandardSchemaV1 {
  /** The Standard Schema properties interface. */
  export interface Props<Input = unknown, Output = Input> {
    /** The version number of the standard. */
    readonly version: 1;
    /** The vendor name of the schema library. */
    readonly vendor: string;
    /** Validates unknown input values. */
    readonly validate: (value: unknown) => Result<Output> | Promise<Result<Output>>;
    /** Inferred types associated with the schema. */
    readonly types?: Types<Input, Output> | undefined;
  }

  /** The result interface of the validate function. */
  export type Result<Output> = SuccessResult<Output> | FailureResult;

  /** The result interface if validation succeeds. */
  export interface SuccessResult<Output> {
    /** The typed output value. */
    readonly value: Output;
    /** A falsy value for `issues` indicates success. */
    readonly issues?: undefined;
  }

  /** The result interface if validation fails. */
  export interface FailureResult {
    /** The issues of failed validation. */
    readonly issues: ReadonlyArray<Issue>;
  }

  /** The issue interface of the failure output. */
  export interface Issue {
    /** The error message of the issue. */
    readonly message: string;
    /** The path of the issue, if any. */
    readonly path?: ReadonlyArray<PropertyKey | PathSegment> | undefined;
  }

  /** The path segment interface of the issue. */
  export interface PathSegment {
    /** The key representing a path segment. */
    readonly key: PropertyKey;
  }

  /** The Standard Schema types interface. */
  export interface Types<Input = unknown, Output = Input> {
    /** The input type of the schema. */
    readonly input: Input;
    /** The output type of the schema. */
    readonly output: Output;
  }

  /** Infers the input type of a Standard Schema. */
  export type InferInput<Schema extends StandardSchemaV1> = NonNullable<
    Schema["~standard"]["types"]
  >["input"];

  /** Infers the output type of a Standard Schema. */
  export type InferOutput<Schema extends StandardSchemaV1> = NonNullable<
    Schema["~standard"]["types"]
  >["output"];
}

// oasts-specific addition — NOT part of the upstream @standard-schema/spec. Every generated
// oasts validator export is declared as this Promise-free specialization: `validate` returns the
// bare synchronous Result union (assert-only validators never defer to a Promise), and the `types`
// phantom is TYPED as `Types<Input, Output> | undefined` even though its runtime value is always
// `undefined`, so `StandardSchemaV1.InferInput`/`InferOutput` resolve on the export rather than
// collapsing through `NonNullable<undefined>`. `SyncStandardSchemaV1<T>` is assignable to
// `StandardSchemaV1<T>`, so a generated validator still satisfies any Standard Schema consumer while
// preserving the narrower, Promise-free static contract the compile-assert cases depend on. Emitters
// MUST annotate exports as `SyncStandardSchemaV1<T>`; a bare `StandardSchemaV1<T>` annotation would
// widen `validate` back to `Result | Promise<Result>` and erase the typed phantom.
export interface SyncStandardSchemaV1<Input = unknown, Output = Input> {
  readonly "~standard": SyncStandardSchemaV1.SyncProps<Input, Output>;
}

export declare namespace SyncStandardSchemaV1 {
  /** The Promise-free properties interface of a generated oasts validator. */
  export interface SyncProps<Input = unknown, Output = Input> {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (value: unknown) => StandardSchemaV1.Result<Output>;
    readonly types?: StandardSchemaV1.Types<Input, Output> | undefined;
  }
}
