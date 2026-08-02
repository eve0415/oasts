// Frozen declaration snapshot for the MSW handler artifact's malformed-input error.
//
// Authored from the pinned handler contract before the emitter existed; the implementation is
// written to satisfy this file, never the reverse. Its SHA-256 is pinned in
// fixtures/msw-entry-gate.yaml and scripts/msw-gate.sh fails on any edit.
//
// `SourcePointer` and `ApplicationPath` are re-declared here rather than imported. Handlers mock
// the server side and may not import the client result runtime, so the MSW artifact carries its
// own structurally identical copies; a drift test pins the two declarations equal. This file
// therefore states the copies the MSW artifact is expected to emit, not the client's originals.

export type MswSourcePointer = {
  readonly logicalSourceId: string;
  readonly jsonPointer: string;
};

// An empty array is the root value.
export type MswApplicationPath = readonly (string | number)[];

// The malformed-input classes, one per way a real Request can fail to project onto the declared
// operation input. A handler never synthesizes an HTTP response for these: it rejects the
// invocation so the failure surfaces in the test rather than as a plausible-looking mock response.
export type MswHandlerErrorCode =
  | "parameter-decode"
  | "content-type-mismatch"
  | "body-decode"
  | "multipart-decode"
  | "body-missing";

export declare class OastsHandlerError extends Error {
  readonly name: "OastsHandlerError";
  readonly code: MswHandlerErrorCode;
  readonly sourcePointer: MswSourcePointer;
  // Null when no value path exists, as for a content-type mismatch.
  readonly applicationPath: MswApplicationPath | null;
  readonly cause: unknown;
  constructor(fields: {
    code: MswHandlerErrorCode;
    sourcePointer: MswSourcePointer;
    applicationPath: MswApplicationPath | null;
    cause: unknown;
  });
}

// The construction cases every emitted implementation must accept: each code, and both the null
// and non-null application-path forms.
export const handlerErrorConstructionVectors = [
  {
    label: "parameter-decode/non-null-path",
    code: "parameter-decode",
    sourcePointer: {
      logicalSourceId: "$single",
      jsonPointer: "/paths/~1pets~1{petId}/get/parameters/0",
    },
    applicationPath: ["petId"],
  },
  {
    label: "content-type-mismatch/null-path",
    code: "content-type-mismatch",
    sourcePointer: { logicalSourceId: "$single", jsonPointer: "/paths/~1pets/post/requestBody" },
    applicationPath: null,
  },
  {
    label: "body-decode/root-path",
    code: "body-decode",
    sourcePointer: { logicalSourceId: "$single", jsonPointer: "/paths/~1pets/post/requestBody" },
    applicationPath: [],
  },
  {
    label: "multipart-decode/nested-path",
    code: "multipart-decode",
    sourcePointer: { logicalSourceId: "$single", jsonPointer: "/paths/~1uploads/post/requestBody" },
    applicationPath: ["meta", "name"],
  },
  {
    label: "body-missing/null-path",
    code: "body-missing",
    sourcePointer: { logicalSourceId: "$single", jsonPointer: "/paths/~1pets/post/requestBody" },
    applicationPath: null,
  },
] as const satisfies readonly {
  label: string;
  code: MswHandlerErrorCode;
  sourcePointer: MswSourcePointer;
  applicationPath: MswApplicationPath | null;
}[];
